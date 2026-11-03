import ocm
import ocm.iter
import pytest

import consts
import odg.cvss
import odg.findings
import odg.labels
import odg.model
import rescore.utility

_CVE_CATEGORISATION_VALUE = {
    'network_exposure': 'public',
    'authentication_enforced': True,
    'user_interaction': 'operator',
    'confidentiality_requirement': 'high',
    'integrity_requirement': 'high',
    'availability_requirement': 'low',
    'comment': None,
}


def _artefact(
    component_name: str = 'comp',
) -> odg.model.ComponentArtefactId:
    return odg.model.ComponentArtefactId(
        component_name=component_name,
        component_version='1.0.0',
        artefact_kind=odg.model.ArtefactKind.RESOURCE,
        artefact=odg.model.LocalArtefactId(
            artefact_name='art',
            artefact_version='1.0.0',
            artefact_type='ociImage',
            artefact_extra_id={},
        ),
    )


def _meta(
    datatype: str,
    creation_date: str = '2024-01-01T00:00:00',
) -> odg.model.Metadata:
    return odg.model.Metadata(
        datasource='test',
        type=datatype,
        creation_date=creation_date,
    )


def _user() -> odg.model.User:
    return odg.model.User(username='tester')


def _vuln_finding(
    cve: str = 'CVE-2024-1234',
    package: str = 'pkg',
) -> odg.model.ArtefactMetadata:
    return odg.model.ArtefactMetadata(
        artefact=_artefact(),
        meta=_meta(odg.model.Datatype.VULNERABILITY_FINDING),
        data=odg.model.VulnerabilityFinding(
            severity='HIGH',
            package_name=package,
            package_version='1.0',
            cve=cve,
            cvss_score=7.5,
        ),
    )


def _vuln_rescoring(
    cve: str = 'CVE-2024-1234',
    package: str = 'pkg',
) -> odg.model.ArtefactMetadata:
    return odg.model.ArtefactMetadata(
        artefact=_artefact(),
        meta=_meta(odg.model.Datatype.RESCORING),
        data=odg.model.CustomRescoring(
            finding=odg.model.RescoringVulnerabilityFinding(
                package_name=package,
                cve=cve,
            ),
            referenced_type=odg.model.Datatype.VULNERABILITY_FINDING,
            severity='NONE',
            user=_user(),
        ),
    )


def _license_finding(
    license_name: str = 'MIT',
    package: str = 'pkg',
) -> odg.model.ArtefactMetadata:
    return odg.model.ArtefactMetadata(
        artefact=_artefact(),
        meta=_meta(odg.model.Datatype.LICENSE_FINDING),
        data=odg.model.LicenseFinding(
            severity='MEDIUM',
            base_url='http://bdba',
            report_url='http://bdba/report',
            product_id=1,
            group_id=1,
            package_name=package,
            package_version='1.0',
            license=odg.model.License(
                name=license_name,
            ),
        ),
    )


def _license_rescoring(
    license_name: str = 'MIT',
    package: str = 'pkg',
) -> odg.model.ArtefactMetadata:
    return odg.model.ArtefactMetadata(
        artefact=_artefact(),
        meta=_meta(odg.model.Datatype.RESCORING),
        data=odg.model.CustomRescoring(
            finding=odg.model.RescoringLicenseFinding(
                package_name=package,
                license=odg.model.License(
                    name=license_name,
                ),
            ),
            referenced_type=odg.model.Datatype.LICENSE_FINDING,
            severity='NONE',
            user=_user(),
        ),
    )


def _ip_finding(
    package: str = 'pkg',
    labels: list[str] = ('label-a',),
) -> odg.model.ArtefactMetadata:
    return odg.model.ArtefactMetadata(
        artefact=_artefact(),
        meta=_meta(odg.model.Datatype.IP_FINDING),
        data=odg.model.IPFinding(
            severity='HIGH',
            package_name=package,
            package_version='1.0',
            license=odg.model.License(
                name='MIT',
            ),
            policy_violation=odg.model.PolicyViolationRef(
                name='test-policy',
                id=None,
                url=None,
            ),
            labels=list(labels),
            host='host',
            href=None,
        ),
    )


def _ip_rescoring(
    package: str = 'pkg',
    labels: list[str] = ('label-a',),
) -> odg.model.ArtefactMetadata:
    return odg.model.ArtefactMetadata(
        artefact=_artefact(),
        meta=_meta(odg.model.Datatype.RESCORING),
        data=odg.model.CustomRescoring(
            finding=odg.model.RescoringIPFinding(
                package_name=package,
                license=None,
                labels=list(labels),
            ),
            referenced_type=odg.model.Datatype.IP_FINDING,
            severity='NONE',
            user=_user(),
        ),
    )


def _make_artefact_node(
    artefact_labels: list[ocm.Label] = (),
    component_labels: list[ocm.Label] = (),
) -> ocm.iter.ResourceNode:
    resource = ocm.Resource(
        name='test-resource',
        version='1.0.0',
        type='ociImage',
        access=None,
        labels=list(artefact_labels),
    )
    component = ocm.Component(
        name='test-component',
        version='1.0.0',
        repositoryContexts=[],
        provider='test',
        sources=[],
        componentReferences=[],
        resources=[],
        labels=list(component_labels),
    )
    return ocm.iter.ResourceNode(
        path=(ocm.iter.NodePathEntry(component=component),),
        resource=resource,
    )


# ---------------------------------------------------------------------------
# find_cve_categorisation — new label name
# ---------------------------------------------------------------------------


def test_find_cve_categorisation_from_artefact():
    label = ocm.Label(
        name='security.ocm.software/risk-profile',
        value=_CVE_CATEGORISATION_VALUE,
    )
    node = _make_artefact_node(artefact_labels=[label])
    result = rescore.utility.find_cve_categorisation(node)
    assert result is not None
    assert result.authentication_enforced is True


def test_find_cve_categorisation_from_component_fallback():
    label = ocm.Label(
        name='security.ocm.software/risk-profile',
        value=_CVE_CATEGORISATION_VALUE,
    )
    node = _make_artefact_node(component_labels=[label])
    result = rescore.utility.find_cve_categorisation(node)
    assert result is not None
    assert result.authentication_enforced is True


def test_find_cve_categorisation_artefact_label_takes_precedence():
    artefact_label = ocm.Label(
        name='security.ocm.software/risk-profile',
        value={**_CVE_CATEGORISATION_VALUE, 'authentication_enforced': False},
    )
    component_label = ocm.Label(
        name='security.ocm.software/risk-profile',
        value={**_CVE_CATEGORISATION_VALUE, 'authentication_enforced': True},
    )
    node = _make_artefact_node(artefact_labels=[artefact_label], component_labels=[component_label])
    result = rescore.utility.find_cve_categorisation(node)
    assert result.authentication_enforced is False


def test_find_cve_categorisation_not_found():
    node = _make_artefact_node()
    result = rescore.utility.find_cve_categorisation(node)
    assert result is None


# ---------------------------------------------------------------------------
# find_cve_categorisation — legacy label name (backwards compat)
# ---------------------------------------------------------------------------


def test_find_cve_categorisation_from_artefact_legacy():
    label = ocm.Label(
        name='gardener.cloud/cve-categorisation',
        value=_CVE_CATEGORISATION_VALUE,
    )
    node = _make_artefact_node(artefact_labels=[label])
    result = rescore.utility.find_cve_categorisation(node)
    assert result is not None
    assert result.authentication_enforced is True


def test_find_cve_categorisation_from_component_fallback_legacy():
    label = ocm.Label(
        name='gardener.cloud/cve-categorisation',
        value=_CVE_CATEGORISATION_VALUE,
    )
    node = _make_artefact_node(component_labels=[label])
    result = rescore.utility.find_cve_categorisation(node)
    assert result is not None
    assert result.authentication_enforced is True


def test_find_cve_categorisation_legacy_artefact_beats_new_component():
    artefact_label = ocm.Label(
        name='gardener.cloud/cve-categorisation',
        value={**_CVE_CATEGORISATION_VALUE, 'authentication_enforced': False},
    )
    component_label = ocm.Label(
        name='security.ocm.software/risk-profile',
        value={**_CVE_CATEGORISATION_VALUE, 'authentication_enforced': True},
    )
    node = _make_artefact_node(artefact_labels=[artefact_label], component_labels=[component_label])
    result = rescore.utility.find_cve_categorisation(node)
    assert result.authentication_enforced is False


# ---------------------------------------------------------------------------
# matching_rescore_rules + rescore_finding
# ---------------------------------------------------------------------------

_VULNERABILITY_CFG_RAW = [
    {
        'type': odg.model.Datatype.VULNERABILITY_FINDING,
        'categorisations': [
            {'id': 'NONE', 'display_name': 'NONE', 'value': 0},
            {
                'id': 'MEDIUM',
                'display_name': 'MEDIUM',
                'value': 2,
                'allowed_processing_time': 90,
                'rescoring': 'automatic',
                'selector': {'cve_score_range': {'min': 4.0, 'max': 6.9}},
            },
            {
                'id': 'CRITICAL',
                'display_name': 'CRITICAL',
                'value': 8,
                'allowed_processing_time': 30,
                'rescoring': 'automatic',
                'selector': {'cve_score_range': {'min': 9.0, 'max': 10.0}},
            },
        ],
        'rescoring_ruleset': {
            'name': 'test-ruleset',
            'operations': {
                'not-exploitable': f'{consts.RESCORING_OPERATOR_SET_TO_PREFIX}NONE',
                'reduce': {'order': ['CRITICAL', 'MEDIUM', 'NONE']},
            },
            'rules': [
                {
                    'category_value': 'network_exposure:public',
                    'name': 'local-only',
                    'rules': [{'cve_values': ['AV:L'], 'operation': 'not-exploitable'}],
                },
                {
                    'category_value': 'network_exposure:public',
                    'name': 'adjacent-reduces',
                    'rules': [{'cve_values': ['AV:A'], 'operation': 'reduce'}],
                },
            ],
        },
    },
]


@pytest.fixture
def vulnerability_cfg() -> odg.findings.Finding:
    return odg.findings.Finding.from_dict(
        findings_raw=_VULNERABILITY_CFG_RAW,
        finding_type=odg.model.Datatype.VULNERABILITY_FINDING,
    )


@pytest.fixture
def cve_categorisation() -> odg.cvss.CveCategorisation:
    label = ocm.Label(
        name='security.ocm.software/risk-profile',
        value={
            'network_exposure': 'public',
            'authentication_enforced': True,
            'user_interaction': 'operator',
            'confidentiality_requirement': 'high',
            'integrity_requirement': 'high',
            'availability_requirement': 'low',
            'comment': None,
        },
    )
    return odg.labels.deserialise_label(label).value


@pytest.mark.parametrize(
    'cvss_vector,cvss_score,expected_value',
    [
        ('CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 5.0, 0),  # AV:L → not-exploitable → NONE
        ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 5.0, 2),  # AV:N → no rule match → MEDIUM
        ('CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.5, 2),  # AV:A → reduce CRITICAL → MEDIUM
    ],
)
def test_rescore_finding(
    cvss_vector,
    cvss_score,
    expected_value,
    vulnerability_cfg,
    cve_categorisation,
):
    cvss = odg.cvss.CVSSV3.parse(cvss_vector)
    categorisation = odg.findings.categorise_finding(
        finding_cfg=vulnerability_cfg,
        finding_property=cvss_score,
    )
    rules = list(
        rescore.utility.matching_rescore_rules(
            rescoring_rules=vulnerability_cfg.rescoring_ruleset.rules,
            categorisation=cve_categorisation,
            cvss=cvss,
        ),
    )
    result = rescore.utility.rescore_finding(
        finding_cfg=vulnerability_cfg,
        current_categorisation=categorisation,
        rescoring_rules=rules,
        operations=vulnerability_cfg.rescoring_ruleset.operations,
    )
    assert result.value == expected_value


def test_score_outside_all_ranges_has_no_categorisation(vulnerability_cfg):
    # score=1.0 falls below the lowest range (MEDIUM: 4.0–6.9) → None
    assert (
        odg.findings.categorise_finding(
            finding_cfg=vulnerability_cfg,
            finding_property=1.0,
        )
        is None
    )


def test_find_cve_categorisation_new_artefact_beats_legacy_component():
    artefact_label = ocm.Label(
        name='security.ocm.software/risk-profile',
        value={**_CVE_CATEGORISATION_VALUE, 'authentication_enforced': False},
    )
    component_label = ocm.Label(
        name='gardener.cloud/cve-categorisation',
        value={**_CVE_CATEGORISATION_VALUE, 'authentication_enforced': True},
    )
    node = _make_artefact_node(artefact_labels=[artefact_label], component_labels=[component_label])
    result = rescore.utility.find_cve_categorisation(node)
    assert result.authentication_enforced is False


# ---------------------------------------------------------------------------
# _finding_group_key / _rescoring_group_key — keys must match for same finding
# ---------------------------------------------------------------------------


def test_group_key_matches_vulnerability():
    finding = _vuln_finding()
    rescoring = _vuln_rescoring()
    assert rescore.utility._finding_group_key(finding) == rescore.utility._rescoring_group_key(
        rescoring,
    )


def test_group_key_differs_on_cve():
    finding = _vuln_finding(cve='CVE-2024-1111')
    rescoring = _vuln_rescoring(cve='CVE-2024-9999')
    assert rescore.utility._finding_group_key(finding) != rescore.utility._rescoring_group_key(
        rescoring,
    )


def test_group_key_differs_on_package_vulnerability():
    finding = _vuln_finding(package='pkg-a')
    rescoring = _vuln_rescoring(package='pkg-b')
    assert rescore.utility._finding_group_key(finding) != rescore.utility._rescoring_group_key(
        rescoring,
    )


def test_group_key_matches_license():
    finding = _license_finding()
    rescoring = _license_rescoring()
    assert rescore.utility._finding_group_key(finding) == rescore.utility._rescoring_group_key(
        rescoring,
    )


def test_group_key_differs_on_license_name():
    finding = _license_finding(license_name='MIT')
    rescoring = _license_rescoring(license_name='Apache-2.0')
    assert rescore.utility._finding_group_key(finding) != rescore.utility._rescoring_group_key(
        rescoring,
    )


def test_group_key_matches_ip():
    finding = _ip_finding(labels=['b', 'a'])
    rescoring = _ip_rescoring(labels=['a', 'b'])  # order must not matter
    assert rescore.utility._finding_group_key(finding) == rescore.utility._rescoring_group_key(
        rescoring,
    )


def test_group_key_differs_on_ip_labels():
    finding = _ip_finding(labels=['label-x'])
    rescoring = _ip_rescoring(labels=['label-y'])
    assert rescore.utility._finding_group_key(finding) != rescore.utility._rescoring_group_key(
        rescoring,
    )


# ---------------------------------------------------------------------------
# group_rescorings
# ---------------------------------------------------------------------------


def test_group_rescorings_empty():
    assert rescore.utility.group_rescorings([]) == {}


def test_group_rescorings_single():
    rescoring = _vuln_rescoring()
    grouped = rescore.utility.group_rescorings([rescoring])
    assert len(grouped) == 1
    assert grouped[rescore.utility._rescoring_group_key(rescoring)] == [rescoring]


def test_group_rescorings_two_same_key():
    r1 = _vuln_rescoring()
    r2 = _vuln_rescoring()
    grouped = rescore.utility.group_rescorings([r1, r2])
    assert len(grouped) == 1
    assert set(grouped[rescore.utility._rescoring_group_key(r1)]) == {r1, r2}


def test_group_rescorings_different_keys():
    r_vuln = _vuln_rescoring()
    r_license = _license_rescoring()
    grouped = rescore.utility.group_rescorings([r_vuln, r_license])
    assert len(grouped) == 2
    assert grouped[rescore.utility._rescoring_group_key(r_vuln)] == [r_vuln]
    assert grouped[rescore.utility._rescoring_group_key(r_license)] == [r_license]


def test_group_rescorings_lookup_miss_returns_empty():
    grouped = rescore.utility.group_rescorings([_license_rescoring()])
    vuln_key = rescore.utility._rescoring_group_key(_vuln_rescoring())
    assert grouped[vuln_key] == []


# ---------------------------------------------------------------------------
# Regression: rescorings_for_finding_by_specificity via group_rescorings
# ---------------------------------------------------------------------------


def test_rescorings_for_finding_matches_same_vuln():
    finding = _vuln_finding(cve='CVE-2024-1234', package='libfoo')
    rescoring = _vuln_rescoring(cve='CVE-2024-1234', package='libfoo')
    result = rescore.utility.rescorings_for_finding_by_specificity(
        finding=finding,
        grouped_rescorings=rescore.utility.group_rescorings([rescoring]),
    )
    assert rescoring in result


def test_rescorings_for_finding_no_match_different_cve():
    finding = _vuln_finding(cve='CVE-2024-1111')
    rescoring = _vuln_rescoring(cve='CVE-2024-9999')
    result = rescore.utility.rescorings_for_finding_by_specificity(
        finding=finding,
        grouped_rescorings=rescore.utility.group_rescorings([rescoring]),
    )
    assert result == ()


def test_rescorings_for_finding_no_match_different_package():
    finding = _vuln_finding(cve='CVE-2024-1234', package='pkg-a')
    rescoring = _vuln_rescoring(cve='CVE-2024-1234', package='pkg-b')
    result = rescore.utility.rescorings_for_finding_by_specificity(
        finding=finding,
        grouped_rescorings=rescore.utility.group_rescorings([rescoring]),
    )
    assert result == ()


def test_rescorings_for_finding_no_match_wrong_type():
    # a license rescoring must not match a vulnerability finding
    vuln_finding = _vuln_finding()
    license_rescoring = _license_rescoring()
    result = rescore.utility.rescorings_for_finding_by_specificity(
        finding=vuln_finding,
        grouped_rescorings=rescore.utility.group_rescorings([license_rescoring]),
    )
    assert result == ()


def test_rescorings_for_finding_selects_correct_from_mixed_pool():
    # pool contains one matching and one non-matching rescoring
    finding = _vuln_finding(cve='CVE-2024-1234', package='pkg')
    matching = _vuln_rescoring(cve='CVE-2024-1234', package='pkg')
    decoy = _vuln_rescoring(cve='CVE-2024-9999', package='pkg')
    result = rescore.utility.rescorings_for_finding_by_specificity(
        finding=finding,
        grouped_rescorings=rescore.utility.group_rescorings([matching, decoy]),
    )
    assert result == (matching,)


def test_rescorings_for_finding_global_rescoring_matches_any_component():
    # a rescoring with no component set is global and must match any finding
    finding = _vuln_finding()
    global_rescoring = odg.model.ArtefactMetadata(
        artefact=odg.model.ComponentArtefactId(
            component_name=None,
            component_version=None,
            artefact_kind=None,
            artefact=None,
        ),
        meta=_meta(odg.model.Datatype.RESCORING),
        data=odg.model.CustomRescoring(
            finding=odg.model.RescoringVulnerabilityFinding(
                package_name='pkg',
                cve='CVE-2024-1234',
            ),
            referenced_type=odg.model.Datatype.VULNERABILITY_FINDING,
            severity='NONE',
            user=_user(),
        ),
    )
    result = rescore.utility.rescorings_for_finding_by_specificity(
        finding=finding,
        grouped_rescorings=rescore.utility.group_rescorings([global_rescoring]),
    )
    assert global_rescoring in result


def test_rescorings_for_finding_component_scoped_no_match_different_component():
    finding = odg.model.ArtefactMetadata(
        artefact=_artefact(component_name='comp-a'),
        meta=_meta(odg.model.Datatype.VULNERABILITY_FINDING),
        data=odg.model.VulnerabilityFinding(
            severity='HIGH',
            package_name='pkg',
            package_version='1.0',
            cve='CVE-2024-1234',
            cvss_score=7.5,
        ),
    )
    rescoring_other_comp = odg.model.ArtefactMetadata(
        artefact=_artefact(component_name='comp-b'),
        meta=_meta(odg.model.Datatype.RESCORING),
        data=odg.model.CustomRescoring(
            finding=odg.model.RescoringVulnerabilityFinding(
                package_name='pkg',
                cve='CVE-2024-1234',
            ),
            referenced_type=odg.model.Datatype.VULNERABILITY_FINDING,
            severity='NONE',
            user=_user(),
        ),
    )
    result = rescore.utility.rescorings_for_finding_by_specificity(
        finding=finding,
        grouped_rescorings=rescore.utility.group_rescorings([rescoring_other_comp]),
    )
    assert result == ()
