#!/usr/bin/env python3
import collections.abc
import datetime
import functools
import logging
import urllib.parse

import ci.log
import cnudie.retrieve
import ocm
import ocm.iter

import ctx_util
import ghas
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


def _parse_github_coords(
    repo_url: str,
) -> tuple[str, str, str] | None:
    parsed = urllib.parse.urlparse(repo_url)
    path_parts = parsed.path.strip('/').split('/')
    if len(path_parts) < 2:
        return None
    org, repo = path_parts[0], path_parts[1]
    hostname = parsed.hostname or 'github.com'
    api_base = (
        f'https://{hostname}/api/v3' if hostname != 'github.com' else 'https://api.github.com'
    )
    return org, repo, api_base


def fetch_repo_info(
    source_node: ocm.iter.SourceNode,
    secret_factory: secret_mgmt.SecretFactory,
) -> tuple[str | None, str | None, set[str]]:
    """
    Returns (repo_url, settings_url, active_codeql_languages).

    active_codeql_languages is the set of languages CodeQL is currently
    scanning on the default branch, extracted from code-scanning/analyses
    environment field. Empty set means CodeQL is not enabled for any language.
    """
    access = source_node.source.access
    if not isinstance(access, ocm.GithubAccess):
        logger.info(
            f'source access is not GithubAccess for {source_node.source.name}, skipping CodeQL check',
        )
        return None, None, set()

    repo_url = access.repoUrl
    coords = _parse_github_coords(repo_url)
    if not coords:
        logger.warning(f'Cannot parse org/repo from {repo_url=}')
        return repo_url, None, set()

    org, repo, api_base = coords

    repo_info, _ = ghas.github_api_request(
        url=f'{api_base}/repos/{org}/{repo}',
        secret_factory=secret_factory,
    )

    settings_url = None
    if isinstance(repo_info, dict):
        html_url = repo_info.get('html_url', repo_url)
        settings_url = f'{html_url}/settings/security_analysis'

    analyses = list(ghas.github_api_request_paginated(
        url=f'{api_base}/repos/{org}/{repo}/code-scanning/analyses?tool_name=CodeQL&ref=refs/heads/{access.branch or "main"}&per_page=100',
        secret_factory=secret_factory,
    ))

    active_languages = set()
    for analysis in analyses:
        if not isinstance(analysis, dict):
            continue
        env = analysis.get('environment', {})
        if isinstance(env, str):
            import json as _json
            try:
                env = _json.loads(env)
            except Exception:
                continue
        if lang := env.get('language'):
            active_languages.add(lang.lower())

    logger.info(f'{repo_url=}: active CodeQL languages={active_languages}')
    return repo_url, settings_url, active_languages


def iter_artefact_metadata(
    artefact: odg.model.ComponentArtefactId,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    codeql_finding_config: odg.findings.Finding,
    codeql_config: odg.extensions_cfg.CodeqlConfig,
    secret_factory: secret_mgmt.SecretFactory,
    creation_timestamp: datetime.datetime = datetime.datetime.now(datetime.timezone.utc),
) -> collections.abc.Generator[odg.model.ArtefactMetadata, None, None]:
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

    repo_url, settings_url, active_languages = fetch_repo_info(
        source_node=source_node,
        secret_factory=secret_factory,
    )

    if not repo_url:
        return

    languages_to_check = [l.lower() for l in codeql_config.languages] if codeql_config.languages else None

    if languages_to_check is None:
        if not active_languages:
            yield _make_finding(
                artefact=artefact,
                codeql_finding_config=codeql_finding_config,
                repo_url=repo_url,
                settings_url=settings_url,
                language=None,
                creation_timestamp=creation_timestamp,
            )
        return

    for language in languages_to_check:
        if language not in active_languages:
            finding = _make_finding(
                artefact=artefact,
                codeql_finding_config=codeql_finding_config,
                repo_url=repo_url,
                settings_url=settings_url,
                language=language,
                creation_timestamp=creation_timestamp,
            )
            if finding:
                yield finding


def _make_finding(
    artefact: odg.model.ComponentArtefactId,
    codeql_finding_config: odg.findings.Finding,
    repo_url: str,
    settings_url: str | None,
    language: str | None,
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
            settings_url=settings_url,
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
    all_metadata = list(
        iter_artefact_metadata(
            artefact=artefact,
            component_descriptor_lookup=component_descriptor_lookup,
            codeql_finding_config=codeql_finding_config,
            codeql_config=extension_cfg,
            secret_factory=secret_factory,
        ),
    )

    delivery_service_client.update_metadata(data=all_metadata)


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

    secret_factory = ctx_util.secret_factory()

    scan_callback = functools.partial(
        scan,
        codeql_finding_config=codeql_finding_config,
        secret_factory=secret_factory,
    )

    odg.util.process_backlog_items(
        parsed_arguments=parsed_arguments,
        service=odg.extensions_cfg.Services.CODEQL,
        callback=scan_callback,
    )


if __name__ == '__main__':
    main()
