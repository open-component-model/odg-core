import asyncio
import collections
import collections.abc
import dataclasses
import enum
import functools
import ocm
import ocm.retrieve_async
import sqlalchemy.ext.asyncio as sqlasync
import structlog

import deliverydb.cache_async
import deliverydb.util
import lookups
import odg.findings
import odg.model
import rescore.utility
import util

logger = structlog.get_logger(__name__)


class ComplianceEntryCategorisation(enum.StrEnum):
    UNKNOWN = 'UNKNOWN'
    CLEAN = 'CLEAN'


def categorisation_to_summary_categorisation(
    categorisation: odg.findings.FindingCategorisation,
) -> ComplianceEntryCategorisation | str:
    if categorisation.value == 0:
        # Rather use "CLEAN" instead of the custom none-categorisation for the summary as it either
        # means there are no findings or all findings have been assessed, whereas the
        # none-categorisation should only be used for the latter (e.g. "false-positive").
        return ComplianceEntryCategorisation.CLEAN

    return categorisation.id


def rescored_severity_if_any(
    finding: odg.model.ArtefactMetadata,
    grouped_rescorings: dict[tuple, list[odg.model.ArtefactMetadata]],
) -> str | None:
    rescorings_for_finding = rescore.utility.rescorings_for_finding_by_specificity(
        finding=finding,
        grouped_rescorings=grouped_rescorings,
    )

    if not rescorings_for_finding:
        return None

    # rescorings are already sorted by specificity and creation date
    most_specific_rescoring = rescorings_for_finding[0]

    return most_specific_rescoring.data.severity


class ComplianceScanStatus:
    NO_DATA = 'no_data'
    OK = 'ok'


@dataclasses.dataclass
class ComplianceSummaryEntry:
    """
    :param Datatype type
    :param Datasource source
    :param ComplianceEntryCategorisation | str categorisation:
        The id of the most severe categorisation which was found for the given `source` and `type`.
        Note, if the semantic value of this categorisation is "0", the meta-category `CLEAN` is used,
        and if no scan is found, the meta-category `UNKNOWN` is used.
    :param int value:
        The semantic value of the respective categorisation.
    :param ComplianceScanStatus scanStatus
    """

    type: odg.model.Datatype
    source: odg.model.Datasource
    categorisation: ComplianceEntryCategorisation | str
    value: int
    scanStatus: ComplianceScanStatus


@dataclasses.dataclass
class ArtefactComplianceSummary:
    artefact: odg.model.ComponentArtefactId
    entries: list[ComplianceSummaryEntry]


@dataclasses.dataclass
class ComponentComplianceSummary:
    componentId: ocm.ComponentIdentity
    entries: list[ComplianceSummaryEntry]
    artefacts: list[ArtefactComplianceSummary]


async def severity_for_finding(
    finding: odg.model.ArtefactMetadata,
    grouped_rescorings: dict[tuple, list[odg.model.ArtefactMetadata]],
) -> ComplianceEntryCategorisation | str | None:
    """
    Severity for known `ArtefactMetadata`.
    """
    if grouped_rescorings:
        loop = asyncio.get_running_loop()
        rescored_severity = await loop.run_in_executor(
            None,
            functools.partial(
                rescored_severity_if_any,
                finding=finding,
                grouped_rescorings=grouped_rescorings,
            ),
        )
        if rescored_severity:
            return rescored_severity

    return finding.data.severity


async def calculate_summary_entry(
    finding_cfg: odg.findings.Finding,
    findings: collections.abc.Iterable[odg.model.ArtefactMetadata],
    rescorings: collections.abc.Iterable[odg.model.ArtefactMetadata],
) -> ComplianceSummaryEntry:
    """
    returns most severe (highest semantic value) `ComplianceSummaryEntry`
    `findings` must be of same datatype and not empty!
    """
    most_severe_categorisation = None

    grouped_rescorings = rescore.utility.group_rescorings(rescorings)

    for finding in findings:
        severity_name = await severity_for_finding(
            finding=finding,
            grouped_rescorings=grouped_rescorings,
        )

        categorisation = finding_cfg.categorisation_by_id(severity_name)

        if not most_severe_categorisation or categorisation.value > most_severe_categorisation.value:
            most_severe_categorisation = categorisation

    return ComplianceSummaryEntry(
        type=finding_cfg.type,
        source=finding.meta.datasource,
        categorisation=categorisation_to_summary_categorisation(most_severe_categorisation),
        value=most_severe_categorisation.value,
        scanStatus=ComplianceScanStatus.OK,
    )


async def compliance_summary_entry(
    finding_cfg: odg.findings.Finding,
    datasource: odg.model.Datasource,
    scan_exists: bool,
    findings: collections.abc.Sequence[odg.model.ArtefactMetadata],
    rescorings: collections.abc.Sequence[odg.model.ArtefactMetadata],
) -> ComplianceSummaryEntry:
    if not scan_exists:
        return ComplianceSummaryEntry(
            type=finding_cfg.type,
            source=datasource,
            categorisation=ComplianceEntryCategorisation.UNKNOWN,
            value=-1,
            scanStatus=ComplianceScanStatus.NO_DATA,
        )

    if not findings:
        return ComplianceSummaryEntry(
            type=finding_cfg.type,
            source=datasource,
            categorisation=ComplianceEntryCategorisation.CLEAN,
            value=0,
            scanStatus=ComplianceScanStatus.OK,
        )

    return await calculate_summary_entry(
        finding_cfg=finding_cfg,
        findings=findings,
        rescorings=rescorings,
    )


async def artefact_datatype_summary(
    artefact: odg.model.ComponentArtefactId,
    finding_cfg: odg.findings.Finding,
    datasource: odg.model.Datasource,
    artefact_scan_infos: collections.abc.Sequence[odg.model.ArtefactMetadata],
    findings: collections.abc.Sequence[odg.model.ArtefactMetadata],
    rescorings: collections.abc.Sequence[odg.model.ArtefactMetadata],
) -> ComplianceSummaryEntry:
    normalised_artefact_extra_identity = odg.model.normalise_artefact_extra_id(
        artefact_extra_id=artefact.artefact.artefact_extra_id,
        omit_version=True,
    )

    def matches_if_set(candidate, actual) -> bool:
        return not candidate or candidate == actual

    rescorings_for_artefact = [
        rescoring
        for rescoring in rescorings
        if (
            not rescoring.artefact.artefact
            or all(
                (
                    matches_if_set(
                        candidate=rescoring.artefact.artefact.artefact_name,
                        actual=artefact.artefact.artefact_name,
                    ),
                    matches_if_set(
                        candidate=rescoring.artefact.artefact.artefact_version,
                        actual=artefact.artefact.artefact_version,
                    ),
                    matches_if_set(
                        candidate=odg.model.normalise_artefact_extra_id(
                            artefact_extra_id=rescoring.artefact.artefact.artefact_extra_id,
                            omit_version=True,
                        ),
                        actual=normalised_artefact_extra_identity,
                    ),
                ),
            )
        )
    ]

    for artefact_scan_info in artefact_scan_infos:
        if (
            artefact_scan_info.artefact.artefact_kind is artefact.artefact_kind
            and artefact_scan_info.artefact.artefact == artefact.artefact
        ):
            scan_exists = True
            break
    else:
        scan_exists = False

    return await compliance_summary_entry(
        finding_cfg=finding_cfg,
        datasource=datasource,
        scan_exists=scan_exists,
        findings=findings,
        rescorings=rescorings_for_artefact,
    )


def _effective_severity_for_projection(
    finding: deliverydb.util.FindingProjection,
    grouped_rescorings: dict[str | None, list[deliverydb.util.RescoringProjection]],
    normalised_artefact_extra_id: str,
) -> str | None:
    """
    Mirrors rescore.utility.rescorings_for_finding_by_specificity + severity_for_finding
    but operates on FindingProjection / RescoringProjection — no dacite.
    grouped_rescorings is keyed by group_key_hash (md5 string or None).
    """
    candidates = []
    for rescoring in grouped_rescorings.get(finding.finding_group_key, []):
        if rescoring.component_name and rescoring.component_name != finding.component_name:
            continue

        if (
            rescoring.component_version
            and finding.component_version
            and rescoring.component_version != finding.component_version
        ):
            continue

        if rescoring.artefact_name and rescoring.artefact_name != finding.artefact_name:
            continue

        if (
            rescoring.artefact_version
            and finding.artefact_version
            and rescoring.artefact_version != finding.artefact_version
        ):
            continue

        if (
            rescoring.artefact_extra_id
            and odg.model.normalise_artefact_extra_id(
                artefact_extra_id=rescoring.artefact_extra_id,
                omit_version=True,
            )
            != normalised_artefact_extra_id
        ):
            continue

        candidates.append(rescoring)

    if not candidates:
        return finding.severity

    most_recent = max(candidates, key=lambda r: util.normalise_date(r.creation_date))
    return most_recent.severity


# Note: The cache manager expects this function to use the persistent db-cache annotator. If this
# would be removed in a future change, the cache manager also had to be adjusted to prevent
# unnecessary load.
@deliverydb.cache_async.dbcached_function(
    ttl_seconds=60 * 60 * 24,  # 1 day
    exclude_kwargs=(
        'finding_cfg',
        'component_descriptor_lookup',
        'ocm_repo',
        'artefact_scan_infos',
    ),
    skip_values=([],),
)
async def component_datatype_summaries(
    component: ocm.ComponentIdentity,
    finding_cfg: odg.findings.Finding,
    finding_type: odg.model.Datatype,
    datasource: odg.model.Datasource,
    db_session: sqlasync.session.AsyncSession,
    component_descriptor_lookup: ocm.retrieve_async.ComponentDescriptorLookupById,
    ocm_repo: ocm.OciOcmRepository | None = None,
    shortcut_cache: bool = False,
    artefact_scan_infos: collections.abc.Sequence[odg.model.ArtefactMetadata] | None = None,
) -> list[tuple[odg.model.ComponentArtefactId, ComplianceSummaryEntry]]:
    component = (
        await component_descriptor_lookup(
            component,
            ocm_repository_lookup=lookups.extended_ocm_repository_lookup(ocm_repo),
        )
    ).component

    if artefact_scan_infos is None:
        artefact_scan_infos = await deliverydb.util.findings_for_component(
            component=component,
            finding_type=odg.model.Datatype.ARTEFACT_SCAN_INFO,
            datasource=datasource,
            db_session=db_session,
        )

    # Fast SQL path: for types supported by severity_summary_for_component, let Postgres do the
    # findings→rescorings join and MAX aggregation.  Returns {artefact_key: max_value} with no
    # row-level Python work.  Falls back to the projection path for unsupported types.
    severity_values = {c.id: c.value for c in finding_cfg.categorisations}
    try:
        t_sql = time.monotonic()
        max_value_by_artefact = await deliverydb.util.severity_summary_for_component(
            component=component,
            finding_type=finding_type,
            datasource=datasource,
            db_session=db_session,
            severity_values=severity_values,
        )
        logger.info(
            'component_datatype_summaries(%s): severity_summary (SQL) (%d artefacts) %.2fs',
            finding_type,
            len(max_value_by_artefact),
            time.monotonic() - t_sql,
        )
        sql_path = True
    except NotImplementedError:
        t_findings = time.monotonic()
        findings_by_artefact = await deliverydb.util.projected_findings_for_component(
            component=component,
            finding_type=finding_type,
            datasource=datasource,
            db_session=db_session,
        )
        logger.info(
            'component_datatype_summaries(%s): projected_findings %.2fs',
            finding_type,
            time.monotonic() - t_findings,
        )
        max_value_by_artefact = None
        sql_path = False

    grouped_rescorings: collections.defaultdict | None = None

    summaries = []
    for ocm_artefact in component.resources + component.sources:
        artefact = odg.model.component_artefact_id_from_ocm(
            component=component,
            artefact=ocm_artefact,
        )

        if not finding_cfg.matches(artefact):
            continue

        artefact_key = (
            artefact.artefact_kind,
            artefact.artefact.artefact_name,
            artefact.artefact.artefact_version,
            odg.model.normalise_artefact_extra_id(artefact.artefact.artefact_extra_id),
        )

        scan_exists = any(
            scan_info.artefact.artefact_kind is artefact.artefact_kind
            and scan_info.artefact.artefact == artefact.artefact
            for scan_info in artefact_scan_infos
        )

        if not scan_exists:
            artefact_summary = ComplianceSummaryEntry(
                type=finding_cfg.type,
                source=datasource,
                categorisation=ComplianceEntryCategorisation.UNKNOWN,
                value=-1,
                scanStatus=ComplianceScanStatus.NO_DATA,
            )
        elif sql_path:
            max_value = max_value_by_artefact.get(artefact_key)
            if max_value is None:
                artefact_summary = ComplianceSummaryEntry(
                    type=finding_cfg.type,
                    source=datasource,
                    categorisation=ComplianceEntryCategorisation.CLEAN,
                    value=0,
                    scanStatus=ComplianceScanStatus.OK,
                )
            else:
                categorisation = finding_cfg.categorisation_by_value(max_value)
                artefact_summary = ComplianceSummaryEntry(
                    type=finding_cfg.type,
                    source=datasource,
                    categorisation=categorisation_to_summary_categorisation(categorisation),
                    value=max_value,
                    scanStatus=ComplianceScanStatus.OK,
                )
        else:
            findings = findings_by_artefact.get(artefact_key, [])
            if not findings:
                artefact_summary = ComplianceSummaryEntry(
                    type=finding_cfg.type,
                    source=datasource,
                    categorisation=ComplianceEntryCategorisation.CLEAN,
                    value=0,
                    scanStatus=ComplianceScanStatus.OK,
                )
            else:
                if grouped_rescorings is None:
                    t_resc = time.monotonic()
                    projected_rescorings = await deliverydb.util.projected_rescorings_for_component(
                        component=component,
                        finding_type=finding_type,
                        db_session=db_session,
                    )
                    logger.info(
                        'component_datatype_summaries(%s): projected_rescorings (%d rows) %.2fs',
                        finding_type,
                        len(projected_rescorings),
                        time.monotonic() - t_resc,
                    )
                    grouped_rescorings = collections.defaultdict(list)
                    for rescoring in projected_rescorings:
                        grouped_rescorings[rescoring.group_key_hash].append(rescoring)

                normalised_extra_id = odg.model.normalise_artefact_extra_id(
                    artefact.artefact.artefact_extra_id,
                    omit_version=True,
                )
                most_severe_categorisation = None
                for finding in findings:
                    severity_name = _effective_severity_for_projection(
                        finding=finding,
                        grouped_rescorings=grouped_rescorings,
                        normalised_artefact_extra_id=normalised_extra_id,
                    )
                    categorisation = finding_cfg.categorisation_by_id(severity_name)
                    if (
                        not most_severe_categorisation
                        or categorisation.value > most_severe_categorisation.value
                    ):
                        most_severe_categorisation = categorisation
                artefact_summary = ComplianceSummaryEntry(
                    type=finding_cfg.type,
                    source=datasource,
                    categorisation=categorisation_to_summary_categorisation(
                        most_severe_categorisation,
                    ),
                    value=most_severe_categorisation.value,
                    scanStatus=ComplianceScanStatus.OK,
                )

        summaries.append(
            (
                artefact,
                artefact_summary,
            ),
        )

    if not summaries:
        return summaries

    component_summary = None
    for _, artefact_summary in summaries:
        if not component_summary or artefact_summary.value > component_summary.value:
            component_summary = artefact_summary

    summaries.insert(
        0,
        (
            odg.model.ComponentArtefactId(
                component_name=component.name,
                component_version=component.version,
                artefact=None,
            ),
            component_summary,
        ),
    )

    return summaries


async def component_compliance_summary(
    component: ocm.ComponentIdentity,
    finding_cfgs: collections.abc.Sequence[odg.findings.Finding],
    db_session: sqlasync.session.AsyncSession,
    component_descriptor_lookup: ocm.retrieve_async.ComponentDescriptorLookupById,
    ocm_repo: ocm.OciOcmRepository | None = None,
    shortcut_cache: bool = False,
) -> ComponentComplianceSummary:
    t0 = time.monotonic()
    component_resolved = (
        await component_descriptor_lookup(
            component,
            ocm_repository_lookup=lookups.extended_ocm_repository_lookup(ocm_repo),
        )
    ).component
    logger.info('component_compliance_summary: resolve component %.2fs', time.monotonic() - t0)

    # Fetch artefact_scan_infos once per datasource — shared across all finding_cfgs
    # that map to the same datasource.
    t1 = time.monotonic()
    artefact_scan_infos_by_datasource: dict[
        odg.model.Datasource,
        list[odg.model.ArtefactMetadata],
    ] = {}
    for finding_cfg in finding_cfgs:
        datasource = finding_cfg.type.datasource()
        if datasource not in artefact_scan_infos_by_datasource:
            artefact_scan_infos_by_datasource[
                datasource
            ] = await deliverydb.util.findings_for_component(
                component=component_resolved,
                finding_type=odg.model.Datatype.ARTEFACT_SCAN_INFO,
                datasource=datasource,
                db_session=db_session,
            )
    logger.info('component_compliance_summary: fetch scan_infos %.2fs', time.monotonic() - t1)

    component_entries = []
    artefacts_entries_by_artefact = collections.defaultdict(list)

    t3 = time.monotonic()
    for finding_cfg in finding_cfgs:
        datasource = finding_cfg.type.datasource()
        summary_entries_by_artefact = await component_datatype_summaries(
            component=component,
            finding_cfg=finding_cfg,
            finding_type=finding_cfg.type,
            datasource=datasource,
            db_session=db_session,
            component_descriptor_lookup=component_descriptor_lookup,
            ocm_repo=ocm_repo,
            shortcut_cache=shortcut_cache,
            artefact_scan_infos=artefact_scan_infos_by_datasource[datasource],
        )

        if not summary_entries_by_artefact:
            continue

        # first entry is always the component summary
        component_entries.append(summary_entries_by_artefact[0][1])

        for component_artefact_id, summary_entry in summary_entries_by_artefact[1:]:
            artefacts_entries_by_artefact[component_artefact_id].append(summary_entry)

    logger.info(
        'component_compliance_summary: datatype_summaries loop %.2fs',
        time.monotonic() - t3,
    )
    logger.info('component_compliance_summary: total %.2fs', time.monotonic() - t0)

    return ComponentComplianceSummary(
        componentId=component,
        entries=component_entries,
        artefacts=[
            ArtefactComplianceSummary(
                artefact=artefact,
                entries=entries,
            )
            for artefact, entries in artefacts_entries_by_artefact.items()
        ],
    )
