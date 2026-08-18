import unittest.mock

import ocm

import bdba_utils.assessments


def _make_component_and_resource(
    resource_label: ocm.Label | None,
    component_label: ocm.Label | None,
):
    resource = ocm.Resource(
        name='test-resource',
        version='1.0.0',
        type='ociImage',
        access=None,
        labels=[resource_label] if resource_label else [],
    )
    component = ocm.Component(
        name='test-component',
        version='1.0.0',
        repositoryContexts=[],
        provider='test',
        sources=[],
        componentReferences=[],
        resources=[resource],
        labels=[component_label] if component_label else [],
    )
    return component, resource


def _collect_package_version_overwrites(component, resource):
    delivery_service_client = unittest.mock.Mock()
    delivery_service_client  # not under test — mock away

    with (
        unittest.mock.patch('odg.model.component_artefact_id_from_ocm'),
        unittest.mock.patch('odg.util.iter_scanner_writebacks', return_value=iter([])),
    ):
        return list(
            bdba_utils.assessments.iter_package_version_overwrites(
                component=component,
                resource=resource,
                delivery_service_client=delivery_service_client,
            ),
        )


def test_iter_package_version_overwrites_from_resource():
    label = ocm.Label(
        name='cloud.gardener.cnudie/dso/scanning-hints/package-versions',
        value=[{'name': 'openssl', 'version': '3.0.1'}],
    )
    component, resource = _make_component_and_resource(
        resource_label=label,
        component_label=None,
    )
    results = _collect_package_version_overwrites(component, resource)
    assert len(results) == 1
    assert results[0].package_name == 'openssl'
    assert results[0].package_version_to == '3.0.1'


def test_iter_package_version_overwrites_from_component_fallback():
    label = ocm.Label(
        name='cloud.gardener.cnudie/dso/scanning-hints/package-versions',
        value=[{'name': 'zlib', 'version': '1.2.11'}],
    )
    component, resource = _make_component_and_resource(
        resource_label=None,
        component_label=label,
    )
    results = _collect_package_version_overwrites(component, resource)
    assert len(results) == 1
    assert results[0].package_name == 'zlib'
    assert results[0].package_version_to == '1.2.11'


def test_iter_package_version_overwrites_resource_takes_precedence():
    resource_label = ocm.Label(
        name='cloud.gardener.cnudie/dso/scanning-hints/package-versions',
        value=[{'name': 'openssl', 'version': '3.0.1'}],
    )
    component_label = ocm.Label(
        name='cloud.gardener.cnudie/dso/scanning-hints/package-versions',
        value=[{'name': 'zlib', 'version': '1.2.11'}],
    )
    component, resource = _make_component_and_resource(
        resource_label=resource_label,
        component_label=component_label,
    )
    results = _collect_package_version_overwrites(component, resource)
    assert len(results) == 1
    assert results[0].package_name == 'openssl'


def test_iter_package_version_overwrites_no_label():
    component, resource = _make_component_and_resource(
        resource_label=None,
        component_label=None,
    )
    results = _collect_package_version_overwrites(component, resource)
    assert results == []
