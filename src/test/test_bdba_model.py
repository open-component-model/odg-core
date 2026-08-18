import ocm

import bdba_utils.model


def _make_artefact(label: ocm.Label | None) -> ocm.Resource:
    return ocm.Resource(
        name='test-artefact',
        version='1.0.0',
        type='ociImage',
        access=None,
        labels=[label] if label else [],
    )


def _make_scan_request(artefact: ocm.Resource) -> bdba_utils.model.ScanRequest:
    component = ocm.Component(
        name='test-component',
        version='1.0.0',
        repositoryContexts=[],
        provider='test',
        sources=[],
        componentReferences=[],
        resources=[],
    )
    return bdba_utils.model.ScanRequest(
        component=component,
        artefact=artefact,
        scan_content=iter([]),
        display_name='test-artefact',
        target_product_id=None,
        custom_metadata={},
    )


def test_skip_vulnerability_scan_no_label():
    artefact = _make_artefact(label=None)
    req = _make_scan_request(artefact)
    assert req.skip_vulnerability_scan is False


def test_skip_vulnerability_scan_policy_skip():
    label = ocm.Label(
        name='odg.ocm.software/binary-scan-policy',
        value={'policy': 'skip'},
    )
    artefact = _make_artefact(label=label)
    req = _make_scan_request(artefact)
    assert req.skip_vulnerability_scan is True


def test_skip_vulnerability_scan_policy_scan():
    label = ocm.Label(
        name='odg.ocm.software/binary-scan-policy',
        value={'policy': 'scan'},
    )
    artefact = _make_artefact(label=label)
    req = _make_scan_request(artefact)
    assert req.skip_vulnerability_scan is False


def test_skip_vulnerability_scan_policy_skip_legacy_label():
    label = ocm.Label(
        name='cloud.gardener.cnudie/dso/scanning-hints/binary_id/v1',
        value={'policy': 'skip'},
    )
    artefact = _make_artefact(label=label)
    req = _make_scan_request(artefact)
    assert req.skip_vulnerability_scan is True


def test_skip_vulnerability_scan_policy_scan_legacy_label():
    label = ocm.Label(
        name='cloud.gardener.cnudie/dso/scanning-hints/binary_id/v1',
        value={'policy': 'scan'},
    )
    artefact = _make_artefact(label=label)
    req = _make_scan_request(artefact)
    assert req.skip_vulnerability_scan is False
