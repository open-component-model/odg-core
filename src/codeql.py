#!/usr/bin/env python3
import collections.abc
import datetime
import functools
import json
import logging
import urllib.parse

import ci.log
import cnudie.retrieve
import ocm.iter

import github_util
import k8s.util
import k8s.logging
import odg.extensions_cfg
import odg.findings
import odg.labels
import odg.model
import odg.util
import odg_client
import paths
import secret_mgmt


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()

# CodeQL uses different language names than GitHub's /languages endpoint.
# This mapping expands CodeQL language identifiers to their GitHub equivalents
# so that config entries like 'javascript' match CodeQL's 'javascript-typescript'.
_CODEQL_LANGUAGE_ALIASES: dict[str, set[str]] = {
    'javascript-typescript': {'javascript', 'typescript'},
    'c-cpp': {'c', 'c++'},
    'java-kotlin': {'java', 'kotlin'},
}


def _parse_github_coords(
    repo_url: str,
) -> tuple[str, str, str] | None:
    if not repo_url.startswith('http'):
        repo_url = f'https://{repo_url}'
    parsed = urllib.parse.urlparse(repo_url)
    if not parsed.hostname:
        logger.warning(f'Cannot determine hostname from {repo_url=}')
        return None
    path_parts = parsed.path.strip('/').split('/')
    if len(path_parts) < 2:
        return None
    org, repo = path_parts[0], path_parts[1]
    api_base = (
        f'https://{parsed.hostname}/api/v3'
        if parsed.hostname != 'github.com'
        else 'https://api.github.com'
    )
    return org, repo, api_base


def fetch_repo_info(
    repo_url: str,
    ref: str | None,
    secret_factory: secret_mgmt.SecretFactory,
) -> tuple[str | None, set[str], set[str], bool]:
    """
    Returns (repo_url, repo_languages, active_codeql_languages, api_success).

    api_success is False when the GitHub API could not be reached (e.g. auth
    failure, network error). Callers must not treat empty language sets as
    "CodeQL disabled" when api_success is False — stale findings should be
    preserved rather than rescored in that case.
    """
    coords = _parse_github_coords(repo_url)
    if not coords:
        logger.warning(f'Cannot parse org/repo from {repo_url=}')
        return repo_url, set(), set(), False

    org, repo, api_base = coords

    languages_raw, _ = github_util.github_api_request(
        url=f'{api_base}/repos/{org}/{repo}/languages',
        secret_factory=secret_factory,
    )
    if languages_raw is None:
        logger.warning(f'Failed to fetch repository languages for {repo_url=}, skipping')
        return repo_url, set(), set(), False

    if not isinstance(languages_raw, dict):
        logger.warning(
            f'Unexpected response type from /languages endpoint for {repo_url=}, skipping',
        )
        return repo_url, set(), set(), False

    repo_languages = {lang.lower() for lang in languages_raw}

    repo_info, _ = github_util.github_api_request(
        url=f'{api_base}/repos/{org}/{repo}',
        secret_factory=secret_factory,
    )

    if ref:
        ref = ref if ref.startswith('refs/') else f'refs/heads/{ref}'
    elif isinstance(repo_info, dict) and (default_branch := repo_info.get('default_branch')):
        ref = f'refs/heads/{default_branch}'
        logger.info(
            f'No ref provided for {repo_url=}, falling back to default branch {default_branch!r}',
        )
    else:
        logger.warning(
            f'No ref provided and could not determine default branch for {repo_url=}, skipping',
        )
        return repo_url, set(), set(), False

    active_languages = set()
    for analysis in github_util.github_api_request_paginated(
        url=f'{api_base}/repos/{org}/{repo}/code-scanning/analyses?tool_name=CodeQL&ref={ref}&per_page=100',
        secret_factory=secret_factory,
    ):
        if not isinstance(analysis, dict):
            continue
        env = analysis.get('environment', {})
        if isinstance(env, str):
            try:
                env = json.loads(env)
            except Exception as e:
                logger.warning(f'Failed to parse environment field {env!r}: {e}')
                continue
        if lang := env.get('language'):
            lang = lang.lower()
            active_languages.update(_CODEQL_LANGUAGE_ALIASES.get(lang, {lang}))

    logger.info(
        f'{repo_url=}: {repo_languages=}, active CodeQL languages={active_languages}',
    )
    return repo_url, repo_languages, active_languages, True


def iter_artefact_metadata(
    artefact: odg.model.ComponentArtefactId,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    codeql_finding_config: odg.findings.Finding,
    codeql_config: odg.extensions_cfg.CodeqlConfig,
    secret_factory: secret_mgmt.SecretFactory,
    existing_findings: list[odg.model.ArtefactMetadata],
    creation_timestamp: datetime.datetime | None = None,
) -> collections.abc.Generator[odg.model.ArtefactMetadata, None, None]:
    if creation_timestamp is None:
        creation_timestamp = datetime.datetime.now(tz=datetime.timezone.utc)
    if not codeql_finding_config.matches(artefact):
        logger.info(f'CodeQL findings are filtered out for {artefact=}, skipping...')
        return

    if not codeql_config.is_supported(artefact_kind=artefact.artefact_kind):
        if codeql_config.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(
                f'{artefact.artefact_kind} is not supported by the CodeQL extension, maybe the '
                'filter configurations have to be adjusted to filter out this artefact kind',
            )
        return

    source_node = k8s.util.get_ocm_node(
        component_descriptor_lookup=component_descriptor_lookup,
        artefact=artefact,
        absent_ok=True,
    )

    if not source_node:
        logger.info(f'did not find source node for {artefact=}, skipping...')
        return

    if not codeql_config.is_supported(access_type=source_node.source.access.type):
        if codeql_config.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(
                f'{source_node.source.access.type} is not supported by the CodeQL extension',
            )
        return

    yield odg.model.ArtefactMetadata(
        artefact=artefact,
        meta=odg.model.Metadata(
            datasource=odg.model.Datasource.CODEQL,
            type=odg.model.Datatype.ARTEFACT_SCAN_INFO,
            creation_date=creation_timestamp,
            last_update=creation_timestamp,
        ),
        data={},
        discovery_date=creation_timestamp.date(),
    )

    if odg.labels.ScanPolicy.SKIP is _find_scan_policy(source_node):
        logger.info(
            f'Skip label found for source {source_node.source.name}. CodeQL check skipped.',
        )
        return

    access = source_node.source.access
    repo_url, repo_languages, active_languages, api_success = fetch_repo_info(
        repo_url=access.repoUrl,
        ref=access.ref,
        secret_factory=secret_factory,
    )

    if not repo_url or not api_success:
        return

    excluded_languages = {lang.lower() for lang in codeql_config.languages}

    new_keys = set()
    for language in repo_languages:
        if language in excluded_languages:
            logger.info(
                f'skipping CodeQL check for {language=}: excluded by config for {repo_url=}',
            )
            continue
        if language not in active_languages:
            finding = _make_finding(
                artefact=artefact,
                codeql_finding_config=codeql_finding_config,
                repo_url=repo_url,
                language=language,
                creation_timestamp=creation_timestamp,
            )
            if finding:
                new_keys.add(finding.data.key)
                yield finding

    for stale in existing_findings:
        if stale.data.key in new_keys:
            continue
        rescoring = odg.model.ArtefactMetadata(
            artefact=stale.artefact,
            meta=odg.model.Metadata(
                datasource=stale.meta.datasource,
                type=odg.model.Datatype.RESCORING,
                creation_date=creation_timestamp,
                last_update=creation_timestamp,
            ),
            data=odg.model.CustomRescoring(
                finding=odg.model.RescoreCodeqlFinding(
                    codeql_status=stale.data.codeql_status,
                    repo_url=stale.data.repo_url,
                    language=stale.data.language,
                ),
                referenced_type=odg.model.Datatype.CODEQL_FINDING,
                severity='accepted',
                user=odg.model.User(
                    username='codeql-extension-auto-rescoring',
                    type='codeql-extension-user',
                ),
                comment='Automatically rescored: CodeQL is now enabled for this language.',
            ),
        )
        yield rescoring


def _make_finding(
    artefact: odg.model.ComponentArtefactId,
    codeql_finding_config: odg.findings.Finding,
    repo_url: str,
    language: str,
    creation_timestamp: datetime.datetime,
) -> odg.model.ArtefactMetadata | None:
    categorisation = odg.findings.categorise_finding(
        finding_cfg=codeql_finding_config,
        finding_property=odg.model.CodeqlStatus.NOT_ENABLED,
    )
    if not categorisation:
        return None
    return odg.model.ArtefactMetadata(
        artefact=artefact,
        meta=odg.model.Metadata(
            datasource=odg.model.Datasource.CODEQL,
            type=odg.model.Datatype.CODEQL_FINDING,
            creation_date=creation_timestamp,
            last_update=creation_timestamp,
        ),
        data=odg.model.CodeqlFinding(
            codeql_status=odg.model.CodeqlStatus.NOT_ENABLED,
            severity=categorisation.id,
            repo_url=repo_url,
            language=language,
        ),
        discovery_date=creation_timestamp.date(),
        allowed_processing_time=categorisation.allowed_processing_time_raw,
    )


def _find_scan_policy(
    snode: ocm.iter.SourceNode,
) -> odg.labels.ScanPolicy | None:
    if label := snode.source.find_label(name=odg.labels.SourceScanLabel.name):
        label_content = odg.labels.deserialise_label(label)
        return label_content.value.policy

    if label := snode.component.find_label(name=odg.labels.SourceScanLabel.name):
        label_content = odg.labels.deserialise_label(label)
        return label_content.value.policy

    return None


def scan(
    artefact: odg.model.ComponentArtefactId,
    extension_cfg: odg.extensions_cfg.CodeqlConfig,
    codeql_finding_config: odg.findings.Finding,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_service_client: odg_client.DeliveryServiceClient,
    secret_factory: secret_mgmt.SecretFactory,
    **kwargs,
):
    existing_findings = [
        odg.model.ArtefactMetadata.from_dict(raw)
        for raw in delivery_service_client.query_metadata(
            artefacts=[artefact],
            type=odg.model.Datatype.CODEQL_FINDING,
        )
    ]

    new_metadata = list(
        iter_artefact_metadata(
            artefact=artefact,
            component_descriptor_lookup=component_descriptor_lookup,
            codeql_finding_config=codeql_finding_config,
            codeql_config=extension_cfg,
            secret_factory=secret_factory,
            existing_findings=existing_findings,
        ),
    )

    delivery_service_client.update_metadata(data=new_metadata)


def main():
    parsed_arguments = odg.util.parse_args()

    if not (findings_cfg_path := parsed_arguments.findings_cfg_path):
        findings_cfg_path = paths.findings_cfg_path()

    codeql_finding_config = odg.findings.Finding.from_file(
        path=findings_cfg_path,
        finding_type=odg.model.Datatype.CODEQL_FINDING,
    )

    if not codeql_finding_config:
        logger.info('CodeQL findings are disabled, exiting...')
        return

    scan_callback = functools.partial(
        scan,
        codeql_finding_config=codeql_finding_config,
    )

    odg.util.process_backlog_items(
        parsed_arguments=parsed_arguments,
        service=odg.extensions_cfg.Services.CODEQL,
        callback=scan_callback,
    )


if __name__ == '__main__':
    main()
