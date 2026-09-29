#!/usr/bin/env python3
"""
Standalone SLA violation report.

Reads SLA_VIOLATION metadata from the ODG delivery-service database for all root components
configured under ``sla_violation_profiler.components``, selects the newest version of each,
and renders a markdown report per component that maps each artefact (sub-component + version)
to the CVEs a team needs to fix.
"""

import collections
import dataclasses
import enum
import logging
import os
import tempfile

import ci.log
import dacite
import git
import github.pullrequest
import github3.pulls
import gitutil
import mako.template
import ocm
import version as version_util

import lookups
import odg.extensions_cfg
import odg.findings
import odg.model
import odg.util
import odg_client
import paths
import util

ci.log.configure_default_logging()
logger = logging.getLogger(__name__)

own_dir = os.path.abspath(os.path.dirname(__file__))
templates_dir = os.path.join(own_dir, 'templates')
sla_report_template_path = os.path.join(templates_dir, 'sla-report.mako')


def _artefact_display(artefact: odg.model.ComponentArtefactId) -> tuple[str, str, str]:
    inner = artefact.artefact
    return (
        artefact.component_name or '(unknown)',
        (inner.artefact_name if inner else None) or '(unknown)',
        (inner.artefact_version if inner else None) or '(unknown)',
    )


def _parse_party(party: list[dict]) -> odg.model.UserIdentity:
    return dacite.from_dict(
        data_class=odg.model.UserIdentity,
        data={'identifiers': party},
        config=dacite.Config(
            cast=[enum.Enum],
        ),
    )


def _party_display(
    user_identity: odg.model.UserIdentity,
    preferred_hostname: str | None = None,
) -> str | None:
    handle = preferred_handle = name = email = None

    for identity in user_identity.identifiers:
        if identity.type is odg.model.UserTypes.GITHUB_USER and identity.username:
            handle = handle or f'@{identity.username}'
            # a person may have accounts on multiple github instances; prefer the handle on the
            # instance the report is published to, since that is the one that @-mentions resolve on
            if preferred_hostname and identity.github_hostname == preferred_hostname:
                preferred_handle = preferred_handle or f'@{identity.username}'

        elif identity.type is odg.model.UserTypes.PERSONAL_NAME:
            full_name = ' '.join(part for part in (identity.first_name, identity.last_name) if part)
            name = name or (full_name or None)

        elif identity.type is odg.model.UserTypes.EMAIL_ADDRESS and identity.email:
            email = email or identity.email

    return preferred_handle or handle or name or email


def _resolve_responsibles(
    delivery_service_client: odg_client.DeliveryServiceClient,
    artefact: odg.model.ComponentArtefactId,
    preferred_hostname: str | None = None,
) -> list[str]:
    inner = artefact.artefact
    responsible_parties, statuses = delivery_service_client.component_responsibles(
        name=artefact.component_name,
        version=artefact.component_version,
        artifact=inner.artefact_name if inner else None,
        absent_ok=True,
    )

    for status in statuses or ():
        if status.type is odg_client.model.StatusType.ERROR:
            logger.warning(f'responsibles lookup for {artefact.component_name}: {status.msg}')

    names = {
        name
        for party in responsible_parties or ()
        if (
            name := _party_display(
                user_identity=_parse_party(party=party),
                preferred_hostname=preferred_hostname,
            )
        )
    }
    return sorted(names)


def _value_to_emoji(value: int | None) -> str:
    if value is None:
        return '⚫'
    if value <= 1:
        return '🟢'
    if value <= 2:
        return '🟡'
    if value <= 4:
        return '🟠'
    return '🔴'


_TRACE_EVENT_EMOJI = {
    odg.model.SlaViolationTraceEventType.FINDING_DISCOVERED: '🔍',
    odg.model.SlaViolationTraceEventType.RESCORING: '🔁',
}


@dataclasses.dataclass
class _TraceEvent:
    emoji: str
    comment: str


@dataclasses.dataclass
class _CveRow:
    emoji: str
    cve: str
    package: str
    severity: str
    summary: str
    events: list[_TraceEvent]


@dataclasses.dataclass
class _ArtefactSection:
    component_name: str
    artefact_name: str
    version: str
    violation_count: int
    cve_rows: list[_CveRow]
    responsibles: list[str]


class _SeverityModel:
    """
    Severity ordering + colours derived from a finding type's configured categorisations, so we make
    no assumptions about which severities exist (they are operator-configurable).
    """

    def __init__(self, finding_cfg: odg.findings.Finding | None):
        # a categorisation's `value` is its severity: higher == more severe
        categorisations = finding_cfg.categorisations if finding_cfg else []
        self._value_by_id = {c.id: c.value for c in categorisations}

    def emoji(self, severity: str) -> str:
        value = self._value_by_id.get(severity)
        return _value_to_emoji(value)

    def sort_key(self, severity: str) -> int:
        # most severe first; unknown severities sort last
        return -self._value_by_id.get(severity, -1)

    def rows(self, counter: collections.Counter) -> list[tuple[str, str, int]]:
        return [
            (self.emoji(sev), sev, counter[sev])
            for sev in sorted(counter, key=self.sort_key)
            if counter.get(sev)
        ]


def _select_version(
    component: odg.extensions_cfg.Component,
    delivery_service_client: odg_client.DeliveryServiceClient,
) -> str | None:
    if resolved_version := component.resolved_version:
        return resolved_version

    time_range = component.time_range
    versions = delivery_service_client.greatest_component_versions(
        component_name=component.component_name,
        max_versions=component.max_versions_limit,
        ocm_repo=component.ocm_repo,
        start_date=time_range.start_date if time_range else None,
        end_date=time_range.end_date if time_range else None,
    )
    return version_util.greatest_version(versions=list(versions), invalid_semver_ok=True)


def _render_report(
    outpath: str,
    component_name: str,
    selected_version: str | None,
    profiled: bool,
    total_violation_count: int,
    artefact_sections: list[_ArtefactSection],
    severity_rows: list[tuple[str, str, int]],
    delivery_service_url: str,
) -> None:
    template = mako.template.Template(
        filename=sla_report_template_path,
        output_encoding='utf-8',
    )

    with open(outpath, 'wb') as f:
        f.write(
            template.render(
                component_name=component_name,
                selected_version=selected_version,
                profiled=profiled,
                total_violation_count=total_violation_count,
                artefact_sections=artefact_sections,
                severity_rows=severity_rows,
                delivery_service_url=delivery_service_url,
            ),
        )


def _generate_report_for_component(
    component_cfg: odg.extensions_cfg.Component,
    severity_model: _SeverityModel,
    delivery_service_client: odg_client.DeliveryServiceClient,
    delivery_service_url: str,
    outpath: str,
    preferred_hostname: str | None = None,
) -> None:
    component_name = component_cfg.component_name

    selected_version = _select_version(
        component=component_cfg,
        delivery_service_client=delivery_service_client,
    )

    if selected_version is None:
        raise RuntimeError(f'could not resolve a version for {component_name}')

    sla_rows = [
        odg.model.ArtefactMetadata.from_dict(raw)
        for raw in delivery_service_client.query_metadata(
            components=(ocm.ComponentIdentity(name=component_name, version=selected_version),),
            type=odg.model.Datatype.SLA_VIOLATION,
        )
    ]

    if len(sla_rows) > 1:
        # the profiler writes exactly one SLA_VIOLATION row per component version
        logger.warning(
            f'expected a single SLA_VIOLATION row for {component_name} {selected_version}, '
            f'found {len(sla_rows)}; using the first',
        )

    selected_row = sla_rows[0] if sla_rows else None

    if selected_row is None:
        _render_report(
            outpath=outpath,
            component_name=component_name,
            selected_version=selected_version,
            profiled=False,
            total_violation_count=0,
            artefact_sections=[],
            severity_rows=[],
            delivery_service_url=delivery_service_url,
        )
        logger.info(
            f'no SLA_VIOLATION row for {component_name} {selected_version} '
            f'(profiler has not run for this version yet); wrote report to {outpath}',
        )
        return

    violations_by_artefact: dict[odg.model.ComponentArtefactId, list[odg.model.SlaViolation]] = (
        collections.defaultdict(list)
    )
    severity_counter: collections.Counter[str] = collections.Counter()

    sla_violations = selected_row.data.sla_violations
    total_violation_count = len(sla_violations)

    for violation in sla_violations:
        violations_by_artefact[violation.artefact].append(violation)
        severity_counter[violation.severity] += 1

    def _cve_rows(
        violations: list[odg.model.SlaViolation],
    ) -> list[_CveRow]:
        rows = []
        for violation in violations:
            events = [
                _TraceEvent(
                    emoji=_TRACE_EVENT_EMOJI.get(event.event_type, '🚨'),
                    comment=event.comment or str(event.event_type),
                )
                for event in violation.trace
            ]
            rows.append(
                _CveRow(
                    emoji=severity_model.emoji(violation.severity),
                    cve=violation.finding.cve or '(unknown)',
                    package=violation.finding.package_name or '(unknown)',
                    severity=violation.severity,
                    # the last trace event is the cause the SLA fired (e.g. released after deadline)
                    summary=events[-1].comment if events else '(no trace)',
                    events=events,
                ),
            )
        return sorted(rows, key=lambda r: (severity_model.sort_key(r.severity), r.cve))

    artefact_sections = []
    for artefact, violations in sorted(
        violations_by_artefact.items(),
        key=lambda item: (-len(item[1]), item[0].key),
    ):
        component_name_, artefact_name_, version_ = _artefact_display(artefact)
        artefact_sections.append(
            _ArtefactSection(
                component_name=component_name_,
                artefact_name=artefact_name_,
                version=version_,
                violation_count=len(violations),
                cve_rows=_cve_rows(violations),
                responsibles=_resolve_responsibles(
                    delivery_service_client=delivery_service_client,
                    artefact=artefact,
                    preferred_hostname=preferred_hostname,
                ),
            ),
        )

    severity_rows = severity_model.rows(severity_counter)

    _render_report(
        outpath=outpath,
        component_name=component_name,
        selected_version=selected_version,
        profiled=True,
        total_violation_count=total_violation_count,
        artefact_sections=artefact_sections,
        severity_rows=severity_rows,
        delivery_service_url=delivery_service_url,
    )
    logger.info(
        f'wrote SLA report for {component_name} {selected_version} '
        f'({total_violation_count} violation(s)) to {outpath}',
    )


def main():
    parsed_arguments = odg.util.parse_args(
        arguments=odg.util.scan_extension_arguments,
    )

    if not (extensions_cfg_path := parsed_arguments.extensions_cfg_path):
        extensions_cfg_path = paths.extensions_cfg_path()

    extensions_cfg = odg.extensions_cfg.ExtensionsConfiguration.from_file(extensions_cfg_path)
    sla_cfg = extensions_cfg.sla_violation_profiler

    if not sla_cfg:
        raise ValueError('sla_violation_profiler is not configured in the extensions config')

    if not (findings_cfg_path := parsed_arguments.findings_cfg_path):
        findings_cfg_path = paths.findings_cfg_path()

    vulnerability_finding_cfg = odg.findings.Finding.from_file(
        path=findings_cfg_path,
        finding_type=odg.model.Datatype.VULNERABILITY_FINDING,
    )
    severity_model = _SeverityModel(vulnerability_finding_cfg)

    if not (delivery_service_url := parsed_arguments.delivery_service_url):
        delivery_service_url = sla_cfg.delivery_service_url

    # a token in the env lets local runs skip the in-cluster secret lookup
    auth_token = os.environ.get('DELIVERY_SERVICE_AUTH_TOKEN')

    if auth_token:
        delivery_service_client = odg_client.DeliveryServiceClient(
            routes=odg_client.DeliveryServiceRoutes(base_url=delivery_service_url),
            auth_token=auth_token,
            api_url=os.environ.get('GITHUB_API_URL'),
        )
    else:
        delivery_service_client = odg_client.DeliveryServiceClient(
            routes=odg_client.DeliveryServiceRoutes(base_url=delivery_service_url),
            auth_token_lookup=lookups.github_auth_token_lookup,
        )

    # prefer responsible handles on the github instance the report is published to
    preferred_hostname = (
        util.urlparse(sla_cfg.github_repository).hostname if sla_cfg.github_repository else None
    )

    def _generate_report_for_components(out_dir: str) -> None:
        for component_cfg in sla_cfg.components:
            _generate_report_for_component(
                component_cfg=component_cfg,
                severity_model=severity_model,
                delivery_service_client=delivery_service_client,
                delivery_service_url=delivery_service_url,
                outpath=os.path.join(out_dir, sla_cfg.filename),
                preferred_hostname=preferred_hostname,
            )

    if not sla_cfg.github_repository:
        _generate_report_for_components(out_dir=os.getcwd())
        return

    repo_url = sla_cfg.github_repository
    parsed_repo_url = util.urlparse(repo_url)

    github_api_lookup = lookups.github_api_lookup()
    github_api = github_api_lookup(repo_url)

    org, repo = parsed_repo_url.path.strip('/').split('/')[:2]
    repository = github_api.repository(org, repo)

    git_cfg = gitutil.GitCfg(
        repo_url=repository.clone_url,
        auth=('x-access-token', github_api.session.auth.token),
        auth_type=gitutil.AuthType.HTTP_TOKEN,
    )

    with tempfile.TemporaryDirectory() as tmp_dir:
        gitutil.GitHelper.clone_into(
            target_directory=tmp_dir,
            git_cfg=git_cfg,
            checkout_branch=sla_cfg.branch,
        )

        _generate_report_for_components(out_dir=tmp_dir)

        message = 'Update SLA violation report'

        # token is only valid for ~30min — refresh before push
        repository = odg.extensions_cfg.github_repository(
            repo=sla_cfg.github_repository,
        )
        github_api = github_api_lookup(repo_url)
        git_helper = gitutil.GitHelper(
            repo=git.Repo(tmp_dir),
            git_cfg=gitutil.GitCfg(
                repo_url=repository.clone_url,
                auth=('x-access-token', github_api.session.auth.token),
                auth_type=gitutil.AuthType.HTTP_TOKEN,
            ),
        )

        with github.pullrequest.commit_and_push_to_tmp_branch(
            repository=repository,
            git_helper=git_helper,
            commit_message=message,
            delete_on_exit=sla_cfg.auto_merge,
        ) as tmp_branch_name:
            pull_request: github3.pulls.PullRequest = repository.create_pull(
                title=message,
                base=sla_cfg.branch,
                head=tmp_branch_name,
            )
            if sla_cfg.auto_merge:
                logger.info(f'Merging PR#{pull_request.number} -> {sla_cfg.branch}')
                pull_request.merge()


if __name__ == '__main__':
    main()
