import unittest.mock

import pytest

import ocm

import odg.cvss
import odg.labels


# ---------------------------------------------------------------------------
# BinaryIdScanLabel
# ---------------------------------------------------------------------------


def test_deserialise_binary_id_scan_label_scan_policy():
    label = ocm.Label(
        name='cloud.gardener.cnudie/dso/scanning-hints/binary_id/v1',
        value={'policy': 'scan'},
    )
    result = odg.labels.deserialise_label(label)
    assert isinstance(result, odg.labels.BinaryIdScanLabel)
    assert result.value.policy is odg.labels.ScanPolicy.SCAN
    assert result.value.path_config is None
    assert result.value.comment is None


def test_deserialise_binary_id_scan_label_skip_policy():
    label = ocm.Label(
        name='cloud.gardener.cnudie/dso/scanning-hints/binary_id/v1',
        value={'policy': 'skip', 'comment': 'do not scan'},
    )
    result = odg.labels.deserialise_label(label)
    assert isinstance(result, odg.labels.BinaryIdScanLabel)
    assert result.value.policy is odg.labels.ScanPolicy.SKIP
    assert result.value.comment == 'do not scan'


def test_deserialise_binary_id_scan_label_with_path_config():
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
    assert result.value.path_config.include_paths == ['src/.*']
    assert result.value.path_config.exclude_paths == ['test/.*']


# ---------------------------------------------------------------------------
# PurposeLabel
# ---------------------------------------------------------------------------


def test_deserialise_purpose_label():
    label = ocm.Label(
        name='gardener.cloud/purposes',
        value=['lint', 'sast'],
    )
    result = odg.labels.deserialise_label(label)
    assert isinstance(result, odg.labels.PurposeLabel)
    assert isinstance(result.value, tuple)
    assert 'lint' in result.value
    assert 'sast' in result.value


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
# CveCategorisationLabel
# ---------------------------------------------------------------------------


def test_deserialise_cve_categorisation_label():
    label = ocm.Label(
        name='gardener.cloud/cve-categorisation',
        value={
            'network_exposure': 'public',
            'authentication_enforced': True,
            'user_interaction': 'gardener-operator',
            'confidentiality_requirement': 'high',
            'integrity_requirement': 'high',
            'availability_requirement': 'low',
            'comment': 'internet-facing service',
        },
    )
    result = odg.labels.deserialise_label(label)
    assert isinstance(result, odg.labels.CveCategorisationLabel)
    categorisation = result.value
    assert isinstance(categorisation, odg.cvss.CveCategorisation)
    assert categorisation.authentication_enforced is True
    assert categorisation.availability_requirement is odg.cvss.CVENoneLowHigh.LOW
    assert categorisation.confidentiality_requirement is odg.cvss.CVENoneLowHigh.HIGH
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
        'name': 'gardener.cloud/purposes',
        'value': ['sast'],
    }
    result = odg.labels.deserialise_label(data)
    assert isinstance(result, odg.labels.PurposeLabel)
    assert 'sast' in result.value


# ---------------------------------------------------------------------------
# find_source_scan_policy
# ---------------------------------------------------------------------------


def _make_source_node(
    source_label: ocm.Label | None,
    component_label: ocm.Label | None,
) -> unittest.mock.Mock:
    source = unittest.mock.Mock(spec=ocm.Source)
    source.find_label.return_value = source_label
    component = unittest.mock.Mock(spec=ocm.Component)
    component.find_label.return_value = component_label
    node = unittest.mock.Mock()
    node.source = source
    node.component = component
    return node


def test_find_source_scan_policy_from_source():
    label = ocm.Label(
        name='cloud.gardener.cnudie/dso/scanning-hints/source_analysis/v1',
        value={'policy': 'skip'},
    )
    node = _make_source_node(source_label=label, component_label=None)
    assert odg.labels.find_source_scan_policy(node) is odg.labels.ScanPolicy.SKIP


def test_find_source_scan_policy_from_component_fallback():
    label = ocm.Label(
        name='cloud.gardener.cnudie/dso/scanning-hints/source_analysis/v1',
        value={'policy': 'scan'},
    )
    node = _make_source_node(source_label=None, component_label=label)
    assert odg.labels.find_source_scan_policy(node) is odg.labels.ScanPolicy.SCAN


def test_find_source_scan_policy_source_takes_precedence():
    source_label = ocm.Label(
        name='cloud.gardener.cnudie/dso/scanning-hints/source_analysis/v1',
        value={'policy': 'skip'},
    )
    component_label = ocm.Label(
        name='cloud.gardener.cnudie/dso/scanning-hints/source_analysis/v1',
        value={'policy': 'scan'},
    )
    node = _make_source_node(source_label=source_label, component_label=component_label)
    assert odg.labels.find_source_scan_policy(node) is odg.labels.ScanPolicy.SKIP


def test_find_source_scan_policy_not_found():
    node = _make_source_node(source_label=None, component_label=None)
    assert odg.labels.find_source_scan_policy(node) is None
