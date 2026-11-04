import ocm.iter
import structlog

import bdba.client
import bdba.model as bm
import odg.findings
import odg.model
import rescore.utility as ru
import scanner_utils.rescore

logger = structlog.get_logger(__name__)


def rescore(
    bdba_client: bdba.client.BDBAApi,
    scan_result: bm.AnalysisResult,
    scanned_element: ocm.iter.ResourceNode,
    vulnerability_cfg: odg.findings.Finding,
) -> bool:
    """
    Rescores bdba-findings for the scanned element of the given components scan result.
    Rescoring is only possible if cve-categorisations are available from categoristion-label
    in either resource or component. Returns a boolean indicating whether a triage was applied
    or not (if yes, a refetching of the scan result may be required).
    """
    if not vulnerability_cfg.rescoring_ruleset:
        return False

    if not (cve_categorisation := ru.find_cve_categorisation(scanned_element)):
        return False

    artefact = odg.model.component_artefact_id_from_ocm(
        component=scanned_element.component,
        artefact=scanned_element.resource,
    )

    if not vulnerability_cfg.matches(artefact):
        return False

    logger.info(f'rescoring {scan_result.display_name} - {scan_result.product_id=}')

    # component.vulnerabilities generator is always truthy; tuple() forces evaluation
    components_with_vulnerabilities = (
        component for component in scan_result.components if tuple(component.vulnerabilities)
    )

    components_with_vulnerabilities = sorted(
        components_with_vulnerabilities,
        key=lambda c: c.name,
    )

    triages_were_applied = False

    for c in components_with_vulnerabilities:
        candidates = [
            scanner_utils.rescore.VulnerabilityCandidate(
                cve=v.cve,
                cvss_score=v.cve_severity(),
                cvss_vector=v.cvss,
                is_skippable=v.okay_to_skip,
                is_already_triaged=v.has_triage,
            )
            for v in c.vulnerabilities
        ]

        auto_triage_cves = scanner_utils.rescore.compute_auto_triage_cves(
            component_name=c.name,
            component_version=c.version,
            vulnerabilities=candidates,
            vulnerability_cfg=vulnerability_cfg,
            cve_categorisation=cve_categorisation,
        )

        if auto_triage_cves:
            bdba_client.add_triage_raw(
                {
                    'component': c.name,
                    'version': c.version,
                    'vulns': auto_triage_cves,
                    'scope': bm.TriageScope.RESULT.value,
                    'reason': 'OT',
                    'description': 'auto-assessed as irrelevant based on cve-categorisation',
                    'product_id': scan_result.product_id,
                },
            )
            triages_were_applied = True

    return triages_were_applied
