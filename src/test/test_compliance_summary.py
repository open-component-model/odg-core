import datetime
import logging

import ci.log
import pytest

import compliance_summary as cs
import odg.findings
import odg.model
import paths


def _make_vuln_finding(
    artefact: odg.model.ComponentArtefactId,
    severity: str,
) -> odg.model.ArtefactMetadata:
    return odg.model.ArtefactMetadata(
        artefact=artefact,
        meta=odg.model.Metadata(
            datasource=odg.model.Datasource.BDBA,
            type=odg.model.Datatype.VULNERABILITY_FINDING,
            creation_date=datetime.datetime.now(tz=datetime.timezone.utc),
        ),
        data=odg.model.VulnerabilityFinding(
            package_name='libfoo',
            package_version='1.0',
            severity=severity,
            cve='CVE-2024-1234',
            cvss_score=9.0,
        ),
    )


def _make_vuln_rescoring(
    artefact: odg.model.ComponentArtefactId,
    severity: str,
) -> odg.model.ArtefactMetadata:
    return odg.model.ArtefactMetadata(
        artefact=artefact,
        meta=odg.model.Metadata(
            datasource=odg.model.Datasource.BDBA,
            type=odg.model.Datatype.VULNERABILITY_FINDING,
            creation_date=datetime.datetime.now(tz=datetime.timezone.utc),
        ),
        data=odg.model.CustomRescoring(
            finding=odg.model.RescoringVulnerabilityFinding(
                package_name='libfoo',
                cve='CVE-2024-1234',
            ),
            referenced_type=odg.model.Datatype.VULNERABILITY_FINDING,
            severity=severity,
            user=odg.model.User(username='testuser'),
        ),
    )


def _artefact_scan_info(artefact: odg.model.ComponentArtefactId) -> odg.model.ArtefactMetadata:
    return odg.model.ArtefactMetadata(
        artefact=artefact,
        meta=odg.model.Metadata(
            datasource=odg.model.Datasource.BDBA,
            type=odg.model.Datatype.ARTEFACT_SCAN_INFO,
        ),
        data={},
    )


# surpress warnings due to unknown os-id
ci.log.configure_default_logging(stdout_level=logging.ERROR)


@pytest.fixture
def component_artefact_id() -> odg.model.ComponentArtefactId:
    return odg.model.ComponentArtefactId(
        component_name=None,
        component_version=None,
        artefact=odg.model.LocalArtefactId(
            artefact_name=None,
            artefact_version=None,
            artefact_type=None,
            artefact_extra_id=dict(),
        ),
    )


@pytest.mark.asyncio
async def test_vulnerability(component_artefact_id):
    meta = odg.model.Metadata(
        datasource=None,
        type=odg.model.Datatype.VULNERABILITY_FINDING,
    )

    finding_cfg = odg.findings.Finding.from_file(
        path=paths.findings_cfg_path(),
        finding_type=odg.model.Datatype.VULNERABILITY_FINDING,
    )

    # Test with base VulnerabilityFinding (no BDBA-specific fields)
    assert (
        await cs.calculate_summary_entry(
            finding_cfg=finding_cfg,
            findings=[
                odg.model.ArtefactMetadata(
                    artefact=component_artefact_id,
                    meta=meta,
                    data=odg.model.VulnerabilityFinding(
                        package_name=None,
                        package_version=None,
                        severity='NONE',
                        cve='CVE-1234',
                        cvss_score=0.0,
                    ),
                ),
            ],
            rescorings=[],
        )
    ).categorisation is cs.ComplianceEntryCategorisation.CLEAN

    assert (
        await cs.calculate_summary_entry(
            finding_cfg=finding_cfg,
            findings=[
                odg.model.ArtefactMetadata(
                    artefact=component_artefact_id,
                    meta=meta,
                    data=odg.model.VulnerabilityFinding(
                        package_name=None,
                        package_version=None,
                        severity='CRITICAL',
                        cve='CVE-123',
                        cvss_score=9.0,
                    ),
                ),
            ],
            rescorings=[],
        )
    ).categorisation == 'CRITICAL'

    # Test with BDBAVulnerabilityFinding (BDBA-specific fields present)
    assert (
        await cs.calculate_summary_entry(
            finding_cfg=finding_cfg,
            findings=[
                odg.model.ArtefactMetadata(
                    artefact=component_artefact_id,
                    meta=meta,
                    data=odg.model.BDBAVulnerabilityFinding(
                        package_name=None,
                        package_version=None,
                        base_url=None,
                        report_url=None,
                        product_id=-1,
                        group_id=-1,
                        severity='NONE',
                        cve='CVE-123',
                        cvss_score=-1,
                        cvss=dict(),
                        summary=None,
                    ),
                ),
            ],
            rescorings=[],
        )
    ).categorisation is cs.ComplianceEntryCategorisation.CLEAN

    assert (
        await cs.calculate_summary_entry(
            finding_cfg=finding_cfg,
            findings=[
                odg.model.ArtefactMetadata(
                    artefact=component_artefact_id,
                    meta=meta,
                    data=odg.model.BDBAVulnerabilityFinding(
                        package_name=None,
                        package_version=None,
                        base_url=None,
                        report_url=None,
                        product_id=-1,
                        group_id=-1,
                        severity='CRITICAL',
                        cve='CVE-123',
                        cvss_score=-1,
                        cvss=dict(),
                        summary=None,
                    ),
                ),
            ],
            rescorings=[],
        )
    ).categorisation == 'CRITICAL'


@pytest.mark.asyncio
async def test_malware(component_artefact_id):
    meta = odg.model.Metadata(
        datasource=None,
        type=odg.model.Datatype.MALWARE_FINDING,
    )

    finding_cfg = odg.findings.Finding.from_file(
        path=paths.findings_cfg_path(),
        finding_type=odg.model.Datatype.MALWARE_FINDING,
    )

    assert (
        await cs.calculate_summary_entry(
            finding_cfg=finding_cfg,
            findings=[
                odg.model.ArtefactMetadata(
                    artefact=component_artefact_id,
                    meta=meta,
                    data=odg.model.ClamAVMalwareFinding(
                        finding=odg.model.MalwareFindingDetails(
                            filename='sha256:xxx|foo/bar',
                            content_digest='sha256:foo',
                            malware='very-bad-virus',
                            context=None,
                        ),
                        octets_count=1024,
                        scan_duration_seconds=1.0,
                        severity='NONE',
                        clamav_version=None,
                        signature_version=None,
                        freshclam_timestamp=None,
                    ),
                ),
            ],
            rescorings=[],
        )
    ).categorisation is cs.ComplianceEntryCategorisation.CLEAN

    assert (
        await cs.calculate_summary_entry(
            finding_cfg=finding_cfg,
            findings=[
                odg.model.ArtefactMetadata(
                    artefact=component_artefact_id,
                    meta=meta,
                    data=odg.model.ClamAVMalwareFinding(
                        finding=odg.model.MalwareFindingDetails(
                            filename='sha256:xxx|foo/bar',
                            content_digest='sha256:foo',
                            malware='very-bad-virus',
                            context=None,
                        ),
                        octets_count=1024,
                        scan_duration_seconds=1.0,
                        severity='BLOCKER',
                        clamav_version=None,
                        signature_version=None,
                        freshclam_timestamp=None,
                    ),
                ),
            ],
            rescorings=[],
        )
    ).categorisation == 'BLOCKER'


@pytest.mark.asyncio
async def test_licenses(component_artefact_id):
    meta = odg.model.Metadata(
        datasource=None,
        type=odg.model.Datatype.LICENSE_FINDING,
    )

    finding_cfg = odg.findings.Finding.from_file(
        path=paths.findings_cfg_path(),
        finding_type=odg.model.Datatype.LICENSE_FINDING,
    )

    assert (
        await cs.calculate_summary_entry(
            finding_cfg=finding_cfg,
            findings=[
                odg.model.ArtefactMetadata(
                    artefact=component_artefact_id,
                    meta=meta,
                    data=odg.model.LicenseFinding(
                        package_name=None,
                        package_version=None,
                        base_url=None,
                        report_url=None,
                        product_id=-1,
                        group_id=-1,
                        severity='NONE',
                        license=None,
                    ),
                ),
            ],
            rescorings=[],
        )
    ).categorisation is cs.ComplianceEntryCategorisation.CLEAN

    assert (
        await cs.calculate_summary_entry(
            finding_cfg=finding_cfg,
            findings=[
                odg.model.ArtefactMetadata(
                    artefact=component_artefact_id,
                    meta=meta,
                    data=odg.model.LicenseFinding(
                        package_name=None,
                        package_version=None,
                        base_url=None,
                        report_url=None,
                        product_id=-1,
                        group_id=-1,
                        severity='BLOCKER',
                        license=None,
                    ),
                ),
            ],
            rescorings=[],
        )
    ).categorisation == 'BLOCKER'


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'scope_artefact',
    [
        # SINGLE scope: all fields are set
        odg.model.ComponentArtefactId(
            component_name='my-component',
            component_version='1.0.0',
            artefact_kind=odg.model.ArtefactKind.RESOURCE,
            artefact=odg.model.LocalArtefactId(
                artefact_name='my-image',
                artefact_version='1.0.0',
                artefact_type='ociImage',
                artefact_extra_id={'os': 'linux', 'version': '1.0.0'},
            ),
        ),
        # ARTEFACT scope: version fields are absent
        odg.model.ComponentArtefactId(
            component_name='my-component',
            artefact_kind=odg.model.ArtefactKind.RESOURCE,
            artefact=odg.model.LocalArtefactId(
                artefact_name='my-image',
                artefact_type='ociImage',
                artefact_extra_id={'os': 'linux'},
            ),
        ),
        # COMPONENT scope: artefact_kind and artefact fields are absent
        odg.model.ComponentArtefactId(
            component_name='my-component',
        ),
        # GLOBAL scope: component_name also absent
        odg.model.ComponentArtefactId(),
    ],
)
async def test_artefact_datatype_summary_rescoring_applied(scope_artefact):
    """
    artefact_datatype_summary must apply COMPONENT/GLOBAL-scoped rescorings and must match
    when the rescoring extra-id version differs from the finding.
    """
    finding_cfg = odg.findings.Finding.from_file(
        path=paths.findings_cfg_path(),
        finding_type=odg.model.Datatype.VULNERABILITY_FINDING,
    )

    artefact = odg.model.ComponentArtefactId(
        component_name='my-component',
        component_version='1.0.0',
        artefact_kind=odg.model.ArtefactKind.RESOURCE,
        artefact=odg.model.LocalArtefactId(
            artefact_name='my-image',
            artefact_version='1.0.0',
            artefact_type='ociImage',
            artefact_extra_id={'os': 'linux', 'version': '1.0.0'},
        ),
    )

    finding = _make_vuln_finding(artefact=artefact, severity='CRITICAL')
    scan_info = _artefact_scan_info(artefact=artefact)
    rescoring = _make_vuln_rescoring(artefact=scope_artefact, severity='NONE')

    result = await cs.artefact_datatype_summary(
        artefact=artefact,
        finding_cfg=finding_cfg,
        datasource=odg.model.Datasource.BDBA,
        artefact_scan_infos=[scan_info],
        findings=[finding],
        rescorings=[rescoring],
    )

    assert result.categorisation is cs.ComplianceEntryCategorisation.CLEAN
