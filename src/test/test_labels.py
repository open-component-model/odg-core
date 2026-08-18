import ocm
import ocm.iter
import pytest

import odg.cvss
import odg.labels

# ---------------------------------------------------------------------------
# get_label_names_with_aliases
# ---------------------------------------------------------------------------


def test_get_label_names_with_aliases():
    names = odg.labels.get_label_names_with_aliases(odg.labels.BinaryScanPolicyLabel)
    assert 'odg.ocm.software/binary-scan-policy' in names
    assert 'cloud.gardener.cnudie/dso/scanning-hints/binary_id/v1' in names


# ---------------------------------------------------------------------------
# BinaryScanPolicyLabel
# ---------------------------------------------------------------------------


def test_binary_scan_policy_label_scan():
    label = ocm.Label(
        name='odg.ocm.software/binary-scan-policy',
        value={'policy': 'scan'},
    )
    result = odg.labels.deserialise_label(label)
    assert isinstance(result, odg.labels.BinaryScanPolicyLabel)
    assert isinstance(result.value, odg.labels.BinaryScanPolicy)
    assert result.value.policy is odg.labels.ScanPolicy.SCAN
    assert result.value.comment is None


def test_binary_scan_policy_label_skip_with_comment():
    label = ocm.Label(
        name='odg.ocm.software/binary-scan-policy',
        value={'policy': 'skip', 'comment': 'do not scan'},
    )
    result = odg.labels.deserialise_label(label)
    assert isinstance(result, odg.labels.BinaryScanPolicyLabel)
    assert result.value.policy is odg.labels.ScanPolicy.SKIP
    assert result.value.comment == 'do not scan'


# ---------------------------------------------------------------------------
# BinaryScanPolicyLabel — legacy name (backwards compat)
# ---------------------------------------------------------------------------


def test_binary_scan_policy_label_legacy_name_scan():
    label = ocm.Label(
        name='cloud.gardener.cnudie/dso/scanning-hints/binary_id/v1',
        value={'policy': 'scan'},
    )
    result = odg.labels.deserialise_label(label)
    assert isinstance(result, odg.labels.BinaryScanPolicyLabel)
    assert result.name == 'cloud.gardener.cnudie/dso/scanning-hints/binary_id/v1'
    assert result.value.policy is odg.labels.ScanPolicy.SCAN
    assert result.value.comment is None


def test_binary_scan_policy_label_legacy_name_skip_with_comment():
    label = ocm.Label(
        name='cloud.gardener.cnudie/dso/scanning-hints/binary_id/v1',
        value={'policy': 'skip', 'comment': 'do not scan'},
    )
    result = odg.labels.deserialise_label(label)
    assert isinstance(result, odg.labels.BinaryScanPolicyLabel)
    assert result.name == 'cloud.gardener.cnudie/dso/scanning-hints/binary_id/v1'
    assert result.value.policy is odg.labels.ScanPolicy.SKIP
    assert result.value.comment == 'do not scan'


def test_binary_scan_policy_label_legacy_name_with_path_config():
    # Old payloads may carry path_config; it should be silently ignored
    label = ocm.Label(
        name='cloud.gardener.cnudie/dso/scanning-hints/binary_id/v1',
        value={
            'policy': 'scan',
            'path_config': {
                'include_paths': ['src/.*'],
                'exclude_paths': ['test/.*'],
            },
            'comment': None,
        },
    )
    result = odg.labels.deserialise_label(label)
    assert isinstance(result, odg.labels.BinaryScanPolicyLabel)
    assert result.value.policy is odg.labels.ScanPolicy.SCAN


# ---------------------------------------------------------------------------
# SourceScanPolicyLabel
# ---------------------------------------------------------------------------


def test_source_scan_policy_label_scan():
    label = ocm.Label(
        name='odg.ocm.software/source-scan-policy',
        value={'policy': 'scan'},
    )
    result = odg.labels.deserialise_label(label)
    assert isinstance(result, odg.labels.SourceScanPolicyLabel)
    assert isinstance(result.value, odg.labels.SourceScanPolicy)
    assert result.value.policy is odg.labels.ScanPolicy.SCAN
    assert result.value.comment is None


def test_source_scan_policy_label_skip_with_comment():
    label = ocm.Label(
        name='odg.ocm.software/source-scan-policy',
        value={'policy': 'skip', 'comment': 'do not scan'},
    )
    result = odg.labels.deserialise_label(label)
    assert isinstance(result, odg.labels.SourceScanPolicyLabel)
    assert result.value.policy is odg.labels.ScanPolicy.SKIP
    assert result.value.comment == 'do not scan'


# ---------------------------------------------------------------------------
# SourceScanPolicyLabel — legacy name (backwards compat)
# ---------------------------------------------------------------------------


def test_source_scan_policy_label_legacy_name_scan():
    label = ocm.Label(
        name='cloud.gardener.cnudie/dso/scanning-hints/source_analysis/v1',
        value={'policy': 'scan'},
    )
    result = odg.labels.deserialise_label(label)
    assert isinstance(result, odg.labels.SourceScanPolicyLabel)
    assert result.name == 'cloud.gardener.cnudie/dso/scanning-hints/source_analysis/v1'
    assert result.value.policy is odg.labels.ScanPolicy.SCAN


def test_source_scan_policy_label_legacy_name_with_path_config():
    label = ocm.Label(
        name='cloud.gardener.cnudie/dso/scanning-hints/source_analysis/v1',
        value={
            'policy': 'scan',
            'path_config': {
                'include_paths': ['src/.*'],
                'exclude_paths': ['test/.*'],
            },
            'comment': None,
        },
    )
    result = odg.labels.deserialise_label(label)
    assert isinstance(result, odg.labels.SourceScanPolicyLabel)
    assert result.name == 'cloud.gardener.cnudie/dso/scanning-hints/source_analysis/v1'
    assert result.value.policy is odg.labels.ScanPolicy.SCAN


# ---------------------------------------------------------------------------
# PurposeLabel
# ---------------------------------------------------------------------------


def test_deserialise_purpose_label():
    label = ocm.Label(
        name='odg.ocm.software/purposes',
        value=['lint', 'sast'],
    )
    result = odg.labels.deserialise_label(label)
    assert isinstance(result, odg.labels.PurposeLabel)
    assert result.name == 'odg.ocm.software/purposes'
    assert isinstance(result.value, tuple)
    assert 'lint' in result.value
    assert 'sast' in result.value


def test_deserialise_purpose_label_legacy_name():
    label = ocm.Label(
        name='gardener.cloud/purposes',
        value=['lint', 'pybandit'],
    )
    result = odg.labels.deserialise_label(label)
    assert isinstance(result, odg.labels.PurposeLabel)
    assert result.name == 'gardener.cloud/purposes'
    assert 'lint' in result.value
    assert 'pybandit' in result.value


# ---------------------------------------------------------------------------
# PackageVersionHintLabel
# ---------------------------------------------------------------------------


def test_deserialise_package_version_hint_label():
    label = ocm.Label(
        name='cloud.gardener.cnudie/dso/scanning-hints/package-versions',
        value=[
            {'name': 'openssl', 'version': '3.0.1'},
            {'name': 'zlib', 'version': '1.2.11'},
        ],
    )
    result = odg.labels.deserialise_label(label)
    assert isinstance(result, odg.labels.PackageVersionHintLabel)
    assert isinstance(result.value, tuple)
    assert len(result.value) == 2
    hint = result.value[0]
    assert isinstance(hint, odg.labels.PackageVersionHint)
    assert hint.name == 'openssl'
    assert hint.version == '3.0.1'


# ---------------------------------------------------------------------------
# RiskProfileLabel
# ---------------------------------------------------------------------------


def test_deserialise_risk_profile_label():
    label = ocm.Label(
        name='security.ocm.software/risk-profile',
        value={
            'network_exposure': 'public',
            'authentication_enforced': True,
            'user_interaction': 'operator',
            'confidentiality_requirement': 'high',
            'integrity_requirement': 'high',
            'availability_requirement': 'low',
            'comment': 'internet-facing service',
        },
    )
    result = odg.labels.deserialise_label(label)
    assert isinstance(result, odg.labels.RiskProfileLabel)
    categorisation = result.value
    assert isinstance(categorisation, odg.cvss.CveCategorisation)
    assert categorisation.authentication_enforced is True
    assert categorisation.availability_requirement is odg.cvss.CVENoneLowHigh.LOW
    assert categorisation.confidentiality_requirement is odg.cvss.CVENoneLowHigh.HIGH
    assert categorisation.comment == 'internet-facing service'
    assert categorisation.user_interaction is odg.cvss.InteractingUserCategory.OPERATOR


def test_deserialise_risk_profile_label_legacy_user_interaction():
    label = ocm.Label(
        name='security.ocm.software/risk-profile',
        value={
            'network_exposure': 'public',
            'authentication_enforced': True,
            'user_interaction': 'gardener-operator',
            'confidentiality_requirement': 'high',
            'integrity_requirement': 'high',
            'availability_requirement': 'low',
            'comment': None,
        },
    )
    result = odg.labels.deserialise_label(label)
    assert result.value.user_interaction is odg.cvss.InteractingUserCategory.OPERATOR


# ---------------------------------------------------------------------------
# RiskProfileLabel — legacy label name (backwards compat)
# ---------------------------------------------------------------------------


def test_deserialise_cve_categorisation_label():
    label = ocm.Label(
        name='gardener.cloud/cve-categorisation',
        value={
            'network_exposure': 'public',
            'authentication_enforced': True,
            'user_interaction': 'operator',
            'confidentiality_requirement': 'high',
            'integrity_requirement': 'high',
            'availability_requirement': 'low',
            'comment': 'internet-facing service',
        },
    )
    result = odg.labels.deserialise_label(label)
    assert isinstance(result, odg.labels.RiskProfileLabel)
    assert result.name == 'gardener.cloud/cve-categorisation'
    categorisation = result.value
    assert isinstance(categorisation, odg.cvss.CveCategorisation)
    assert categorisation.authentication_enforced is True
    assert categorisation.availability_requirement is odg.cvss.CVENoneLowHigh.LOW
    assert categorisation.confidentiality_requirement is odg.cvss.CVENoneLowHigh.HIGH
    assert categorisation.user_interaction is odg.cvss.InteractingUserCategory.OPERATOR
    assert categorisation.comment == 'internet-facing service'


# ---------------------------------------------------------------------------
# Unknown label
# ---------------------------------------------------------------------------


def test_deserialise_unknown_label_raises():
    label = ocm.Label(name='unknown.label/does-not-exist', value={})
    with pytest.raises(ValueError, match='unknown'):
        odg.labels.deserialise_label(label)


def test_deserialise_accepts_dict():
    data = {
        'name': 'odg.ocm.software/purposes',
        'value': ['sast'],
    }
    result = odg.labels.deserialise_label(data)
    assert isinstance(result, odg.labels.PurposeLabel)
    assert 'sast' in result.value


# ---------------------------------------------------------------------------
# find_source_scan_policy
# ---------------------------------------------------------------------------


def _make_source_node(
    source_labels: list[ocm.Label] = (),
    component_labels: list[ocm.Label] = (),
) -> ocm.iter.SourceNode:
    source = ocm.Source(name='test-source', access=None, labels=list(source_labels))
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
    return ocm.iter.SourceNode(
        path=(ocm.iter.NodePathEntry(component=component),),
        source=source,
    )


def test_find_source_scan_policy_from_source():
    label = ocm.Label(name='odg.ocm.software/source-scan-policy', value={'policy': 'skip'})
    node = _make_source_node(source_labels=[label])
    assert odg.labels.find_source_scan_policy(node) is odg.labels.ScanPolicy.SKIP


def test_find_source_scan_policy_from_component_fallback():
    label = ocm.Label(name='odg.ocm.software/source-scan-policy', value={'policy': 'scan'})
    node = _make_source_node(component_labels=[label])
    assert odg.labels.find_source_scan_policy(node) is odg.labels.ScanPolicy.SCAN


def test_find_source_scan_policy_source_takes_precedence():
    source_label = ocm.Label(name='odg.ocm.software/source-scan-policy', value={'policy': 'skip'})
    component_label = ocm.Label(name='odg.ocm.software/source-scan-policy', value={'policy': 'scan'})
    node = _make_source_node(source_labels=[source_label], component_labels=[component_label])
    assert odg.labels.find_source_scan_policy(node) is odg.labels.ScanPolicy.SKIP


def test_find_source_scan_policy_not_found():
    node = _make_source_node()
    assert odg.labels.find_source_scan_policy(node) is None


# ---------------------------------------------------------------------------
# find_source_scan_policy — legacy name (backwards compat)
# ---------------------------------------------------------------------------


def test_find_source_scan_policy_from_source_legacy():
    label = ocm.Label(
        name='cloud.gardener.cnudie/dso/scanning-hints/source_analysis/v1',
        value={'policy': 'skip'},
    )
    node = _make_source_node(source_labels=[label])
    assert odg.labels.find_source_scan_policy(node) is odg.labels.ScanPolicy.SKIP


def test_find_source_scan_policy_from_component_fallback_legacy():
    label = ocm.Label(
        name='cloud.gardener.cnudie/dso/scanning-hints/source_analysis/v1',
        value={'policy': 'scan'},
    )
    node = _make_source_node(component_labels=[label])
    assert odg.labels.find_source_scan_policy(node) is odg.labels.ScanPolicy.SCAN


def test_find_source_scan_policy_legacy_source_beats_new_component():
    source_label = ocm.Label(
        name='cloud.gardener.cnudie/dso/scanning-hints/source_analysis/v1',
        value={'policy': 'skip'},
    )
    component_label = ocm.Label(name='odg.ocm.software/source-scan-policy', value={'policy': 'scan'})
    node = _make_source_node(source_labels=[source_label], component_labels=[component_label])
    assert odg.labels.find_source_scan_policy(node) is odg.labels.ScanPolicy.SKIP


def test_find_source_scan_policy_new_source_beats_legacy_component():
    source_label = ocm.Label(name='odg.ocm.software/source-scan-policy', value={'policy': 'skip'})
    component_label = ocm.Label(
        name='cloud.gardener.cnudie/dso/scanning-hints/source_analysis/v1',
        value={'policy': 'scan'},
    )
    node = _make_source_node(source_labels=[source_label], component_labels=[component_label])
    assert odg.labels.find_source_scan_policy(node) is odg.labels.ScanPolicy.SKIP
