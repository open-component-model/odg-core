import unittest.mock

import ocm

import rescore.utility


_CVE_CATEGORISATION_VALUE = {
    'network_exposure': 'public',
    'authentication_enforced': True,
    'user_interaction': 'gardener-operator',
    'confidentiality_requirement': 'high',
    'integrity_requirement': 'high',
    'availability_requirement': 'low',
    'comment': None,
}


def _make_artefact_node(
    artefact_label: ocm.Label | None,
    component_label: ocm.Label | None,
) -> unittest.mock.Mock:
    artefact = unittest.mock.Mock(spec=ocm.Resource)
    artefact.find_label.return_value = artefact_label

    component = unittest.mock.Mock(spec=ocm.Component)
    component.find_label.return_value = component_label

    node = unittest.mock.Mock()
    node.artefact = artefact
    node.component = component
    return node


def test_find_cve_categorisation_from_artefact():
    label = ocm.Label(
        name='gardener.cloud/cve-categorisation',
        value=_CVE_CATEGORISATION_VALUE,
    )
    node = _make_artefact_node(artefact_label=label, component_label=None)
    result = rescore.utility.find_cve_categorisation(node)
    assert result is not None
    assert result.authentication_enforced is True


def test_find_cve_categorisation_from_component_fallback():
    label = ocm.Label(
        name='gardener.cloud/cve-categorisation',
        value=_CVE_CATEGORISATION_VALUE,
    )
    node = _make_artefact_node(artefact_label=None, component_label=label)
    result = rescore.utility.find_cve_categorisation(node)
    assert result is not None
    assert result.authentication_enforced is True


def test_find_cve_categorisation_artefact_label_takes_precedence():
    artefact_label = ocm.Label(
        name='gardener.cloud/cve-categorisation',
        value={**_CVE_CATEGORISATION_VALUE, 'authentication_enforced': False},
    )
    component_label = ocm.Label(
        name='gardener.cloud/cve-categorisation',
        value={**_CVE_CATEGORISATION_VALUE, 'authentication_enforced': True},
    )
    node = _make_artefact_node(artefact_label=artefact_label, component_label=component_label)
    result = rescore.utility.find_cve_categorisation(node)
    assert result.authentication_enforced is False


def test_find_cve_categorisation_not_found():
    node = _make_artefact_node(artefact_label=None, component_label=None)
    result = rescore.utility.find_cve_categorisation(node)
    assert result is None
