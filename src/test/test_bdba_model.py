import ocm

import bdba_utils.model


def _make_scan_request(label: ocm.Label | None) -> bdba_utils.model.ScanRequest:
    artefact = ocm.Resource(
        name='test-artefact',
        version='1.0.0',
        type='ociImage',
        access=None,
        labels=[label] if label else [],
    )
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
    assert _make_scan_request(None).skip_vulnerability_scan is False


def test_skip_vulnerability_scan_policy_skip():
    label = ocm.Label(name='odg.ocm.software/binary-scan-policy', value={'policy': 'skip'})
    assert _make_scan_request(label).skip_vulnerability_scan is True


def test_skip_vulnerability_scan_policy_scan():
    label = ocm.Label(name='odg.ocm.software/binary-scan-policy', value={'policy': 'scan'})
    assert _make_scan_request(label).skip_vulnerability_scan is False
