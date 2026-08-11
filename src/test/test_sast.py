import ocm

import sast


def _make_resource(label: ocm.Label | None) -> ocm.Resource:
    return ocm.Resource(
        name='test-resource',
        version='1.0.0',
        type='ociImage',
        access=None,
        labels=[label] if label else [],
    )


def test_has_local_linter_no_resources():
    assert sast.has_local_linter([]) is False


def test_has_local_linter_resource_no_label():
    resource = _make_resource(label=None)
    assert sast.has_local_linter([resource]) is False


def test_has_local_linter_resource_with_sast_purpose():
    label = ocm.Label(name='odg.ocm.software/purposes', value=['lint', 'sast'])
    resource = _make_resource(label=label)
    assert sast.has_local_linter([resource]) is True


def test_has_local_linter_resource_without_sast_purpose():
    label = ocm.Label(name='odg.ocm.software/purposes', value=['lint'])
    resource = _make_resource(label=label)
    assert sast.has_local_linter([resource]) is False


def test_has_local_linter_first_resource_matches():
    label_sast = ocm.Label(name='odg.ocm.software/purposes', value=['sast'])
    label_other = ocm.Label(name='odg.ocm.software/purposes', value=['lint'])
    resources = [_make_resource(label_sast), _make_resource(label_other)]
    assert sast.has_local_linter(resources) is True


def test_has_local_linter_second_resource_matches():
    label_other = ocm.Label(name='odg.ocm.software/purposes', value=['lint'])
    label_sast = ocm.Label(name='odg.ocm.software/purposes', value=['sast'])
    resources = [_make_resource(label_other), _make_resource(label_sast)]
    assert sast.has_local_linter(resources) is True


# ---------------------------------------------------------------------------
# legacy: gardener.cloud/purposes
# ---------------------------------------------------------------------------

def test_has_local_linter_resource_with_sast_purpose_legacy_name():
    label = ocm.Label(name='gardener.cloud/purposes', value=['sast', 'lint'])
    resource = _make_resource(label=label)
    assert sast.has_local_linter([resource]) is True


def test_has_local_linter_resource_without_sast_purpose_legacy_name():
    label = ocm.Label(name='gardener.cloud/purposes', value=['lint'])
    resource = _make_resource(label=label)
    assert sast.has_local_linter([resource]) is False
