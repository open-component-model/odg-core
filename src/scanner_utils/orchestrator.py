import dataclasses
import datetime
import json
import logging

import cnudie.retrieve
import oci.client

import k8s.util
import odg.extensions_cfg
import odg.findings
import odg.labels
import odg.model
import odg_client
import scanner_utils.cyclonedx
import scanner_utils.findings
import scanner_utils.model
import scanner_utils.scanner
import secret_mgmt

logger = logging.getLogger(__name__)


def _is_supported_sbom_format(sbom: dict) -> bool:
    if sbom.get('bomFormat') == 'CycloneDX':
        return True
    spdx_version = sbom.get('spdxVersion')
    if isinstance(spdx_version, str) and spdx_version.startswith('SPDX-'):
        return True
    context = sbom.get('@context', '')
    if isinstance(context, str) and 'spdx.org/rdf/' in context:
        return True
    return False


def _fetch_sbom(
    delivery_service_client: odg_client.DeliveryServiceClient,
    artefact: odg.model.ComponentArtefactId,
) -> dict | None:
    entries = delivery_service_client.query_metadata(
        artefacts=[artefact],
        type=odg.model.Datatype.ARTEFACT_SCAN_INFO,
        datasource=odg.model.Datasource.SBOM_GENERATOR,
    )
    for entry in entries:
        digest = entry.get('data', {}).get('digest')
        if not digest:
            continue
        sbom_bytes = delivery_service_client.get_blob(digest=digest)
        try:
            sbom = json.loads(sbom_bytes)
        except json.JSONDecodeError:
            logger.info(f'SBOM for {artefact} is not valid JSON, ignoring')
            continue
        if not isinstance(sbom, dict) or not _is_supported_sbom_format(sbom):
            logger.info(f'SBOM for {artefact} has unsupported format, ignoring')
            continue
        return sbom
    return None


def run_scan(
    artefact: odg.model.ComponentArtefactId,
    extension_cfg: odg.extensions_cfg.BacklogItemMixins,
    vulnerability_cfg: odg.findings.Finding | None,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_service_client: odg_client.DeliveryServiceClient,
    oci_client: oci.client.Client,
    scanner: scanner_utils.scanner.Scanner,
    datasource: odg.model.Datasource,
    secret_factory: secret_mgmt.SecretFactory | None = None,
) -> None:
    """
    Generic orchestration loop for a CycloneDX-based vulnerability scanner.

    Call this from a scanner extension's `__main__.py` instead of re-implementing
    the orchestration steps. Only the `Scanner` subclass (scan hook implementations)
    is scanner-specific; routing logic lives in `scanner_utils.scanner`.

    artefact: The backlog item being processed — identifies the OCM component + resource
    extension_cfg: Scanner-specific configuration (e.g. `TrivyConfig`)
    vulnerability_cfg: Which CVSS score ranges produce findings and label-based exclusion rules
    component_descriptor_lookup: Resolve an OCM `ComponentIdentity` → `ComponentDescriptor`
    delivery_service_client: Client for the ODG delivery service API
    oci_client: Authenticated OCI client (`oci.client.Client`)
    scanner: Implementation of the `Scanner` interface
    datasource: `odg.model.Datasource` enum value for this scanner (e.g. `Datasource.TRIVY`).
        Used as the primary key namespace for all DB records written by this scanner
    """
    if not vulnerability_cfg or not vulnerability_cfg.matches(artefact):
        logger.info(f'[{datasource}] {artefact} skipped: vulnerability_cfg does not match')
        return

    if not extension_cfg.is_supported(artefact_kind=artefact.artefact_kind):
        if extension_cfg.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(
                f'{artefact.artefact_kind} is not supported by {datasource}, '
                'adjust filter configuration to exclude this artefact kind',
            )
        logger.info(
            f'[{datasource}] {artefact} skipped: artefact_kind={artefact.artefact_kind!r} '
            f'not supported',
        )
        return

    resource_node = k8s.util.get_ocm_node(
        component_descriptor_lookup=component_descriptor_lookup,
        artefact=artefact,
    )
    access = resource_node.resource.access

    if odg.labels.is_binary_scan_skipped(resource_node.resource):
        logger.info(f'[{datasource}] {artefact} skipped: binary-scan-policy=skip')
        return

    if not extension_cfg.is_supported(
        access_type=access.type,
        artefact_type=resource_node.resource.type,
    ):
        if extension_cfg.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(
                f'{access.type} is not supported by {datasource}, '
                'adjust filter configuration to exclude this access type',
            )
        logger.info(
            f'[{datasource}] {artefact} skipped: '
            f'access_type={access.type!r} or '
            f'artefact_type={resource_node.resource.type!r} not supported',
        )
        return

    scan_target = extension_cfg.scan_target
    cyclonedx: dict | None = None

    if scan_target in (
        scanner_utils.model.ScanningMode.SBOM,
        scanner_utils.model.ScanningMode.SBOM_WITH_BINARY_FALLBACK,
    ):
        sbom = _fetch_sbom(delivery_service_client=delivery_service_client, artefact=artefact)
        if sbom is not None:
            cyclonedx = scanner.scan_sbom(sbom)

        if sbom is None:
            if scan_target is scanner_utils.model.ScanningMode.SBOM:
                logger.warning(
                    f'[{datasource}] {artefact} no SBOM available, raising SbomNotAvailable',
                )
                raise scanner_utils.model.SbomNotAvailable(artefact)
            logger.info(
                f'[{datasource}] {artefact} no SBOM available, falling back to binary scan',
            )

    if cyclonedx is None:
        cyclonedx = scanner.scan_ocm_resource(
            resource_node=resource_node,
            oci_client=oci_client,
            secret_factory=secret_factory,
        )

    findings = list(
        scanner_utils.cyclonedx.iter_vulnerability_findings(
            cyclonedx=cyclonedx,
            vulnerability_cfg=vulnerability_cfg,
        ),
    )

    logger.info(
        f'[{datasource}] {artefact} '
        f'scan_target={scan_target} '
        f'raw_cves={len(cyclonedx.get("vulnerabilities") or [])} '
        f'findings_after_cfg={len(findings)}',
    )

    finding_artefact_ref = odg.model.component_artefact_id_from_ocm(
        component=resource_node.component,
        artefact=resource_node.resource,
    )
    finding_artefact_ref = dataclasses.replace(finding_artefact_ref, component_version=None)

    existing = {
        ef.data.key: ef
        for ef in scanner_utils.findings.iter_existing_findings(
            delivery_service_client=delivery_service_client,
            resource_node=resource_node,
            finding_type=odg.model.Datatype.VULNERABILITY_FINDING,
            datasource=datasource,
        )
    }

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    artefact_metadatas = [
        odg.model.ArtefactMetadata(
            artefact=finding_artefact_ref,
            meta=odg.model.Metadata(
                datasource=datasource,
                type=odg.model.Datatype.VULNERABILITY_FINDING,
                creation_date=now,
            ),
            data=finding,
            discovery_date=now.date(),
            allowed_processing_time=categorisation.allowed_processing_time_raw,
        )
        for finding, categorisation in findings
    ]

    scan_info = scanner_utils.findings.make_artefact_scan_info(
        resource_node=resource_node,
        datasource=datasource,
    )

    delivery_service_client.update_metadata(data=[scan_info] + artefact_metadatas)
    scanner_utils.findings.delete_stale_findings(
        existing_findings_by_key=existing,
        current_findings=artefact_metadatas,
        delivery_service_client=delivery_service_client,
    )

    logger.debug(f'[{datasource}] {artefact} finished')
