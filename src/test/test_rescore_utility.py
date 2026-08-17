import ocm
import ocm.iter

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
