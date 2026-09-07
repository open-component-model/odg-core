import json
import unittest.mock

import pytest

import ocm
import odg.extensions_cfg
import odg.labels
import odg.model

import sbom_generator


def _make_resource(
    name='my-image',
    version='1.0.0',
    extra_identity=None,
    labels=None,
    access_type=ocm.AccessType.OCI_REGISTRY,
    image_reference='registry.example.com/my-image:1.0.0',
):
    if extra_identity is None:
        extra_identity = {}
    if labels is None:
        labels = []

    if access_type == ocm.AccessType.OCI_REGISTRY:
        access = ocm.OciAccess(imageReference=image_reference)
    else:
        access = unittest.mock.MagicMock()
        access.type = access_type

    return ocm.Resource(
        name=name,
        version=version,
        type='ociImage',
        access=access,
        extraIdentity=extra_identity,
        labels=labels,
    )


def _make_sbom_resource(
    name='my-image-sbom',
    version='1.0.0',
    label_value=None,
    label_version='v1alpha1',
    extra_identity=None,
    image_reference='registry.example.com/my-image-sbom:1.0.0',
):
    if extra_identity is None:
        extra_identity = {}
    if label_value is None:
        label_value = [{'identity': {'name': 'my-image'}}]

    labels = [ocm.Label(
        name=odg.labels.ArtefactReferencesLabel.name,
        value=label_value,
        version=label_version,
    )]

    return ocm.Resource(
        name=name,
        version=version,
        type='sbom',
        access=ocm.OciAccess(imageReference=image_reference),
        extraIdentity=extra_identity,
        labels=labels,
    )


def _make_component(resources):
    component = unittest.mock.MagicMock(spec=ocm.Component)
    component.resources = resources
    return component


# --- _identity_matches ---

class TestIdentityMatches:
    def test_name_mismatch(self):
        resource = _make_resource(name='my-image')
        assert not sbom_generator._identity_matches({'name': 'other-image'}, resource)

    def test_name_match_no_version(self):
        resource = _make_resource(name='my-image', version='1.0.0')
        assert sbom_generator._identity_matches({'name': 'my-image'}, resource)

    def test_version_match(self):
        resource = _make_resource(name='my-image', version='1.0.0')
        assert sbom_generator._identity_matches({'name': 'my-image', 'version': '1.0.0'}, resource)

    def test_version_mismatch(self):
        resource = _make_resource(name='my-image', version='1.0.0')
        assert not sbom_generator._identity_matches(
            {'name': 'my-image', 'version': '2.0.0'}, resource,
        )

    def test_extra_identity_exact_match(self):
        resource = _make_resource(name='my-image', extra_identity={'arch': 'amd64'})
        assert sbom_generator._identity_matches(
            {'name': 'my-image', 'arch': 'amd64'}, resource,
        )

    def test_extra_identity_key_missing_in_resource(self):
        resource = _make_resource(name='my-image', extra_identity={})
        assert not sbom_generator._identity_matches(
            {'name': 'my-image', 'arch': 'amd64'}, resource,
        )

    def test_extra_identity_extra_key_in_resource(self):
        resource = _make_resource(name='my-image', extra_identity={'arch': 'amd64', 'os': 'linux'})
        assert not sbom_generator._identity_matches(
            {'name': 'my-image', 'arch': 'amd64'}, resource,
        )

    def test_extra_identity_value_mismatch(self):
        resource = _make_resource(name='my-image', extra_identity={'arch': 'amd64'})
        assert not sbom_generator._identity_matches(
            {'name': 'my-image', 'arch': 'arm64'}, resource,
        )


# --- find_ocm_sbom_resource ---

class TestFindOcmSbomResource:
    def test_no_resources(self):
        component = _make_component([])
        resource = _make_resource()
        assert sbom_generator.find_ocm_sbom_resource(component, resource) is None

    def test_resource_without_label(self):
        subject = _make_resource(name='my-image')
        candidate = _make_resource(name='other', labels=[])
        component = _make_component([subject, candidate])
        assert sbom_generator.find_ocm_sbom_resource(component, subject) is None

    def test_label_wrong_version(self):
        subject = _make_resource(name='my-image')
        sbom = _make_sbom_resource(label_value=[{'identity': {'name': 'my-image'}}], label_version='v1')
        component = _make_component([subject, sbom])
        assert sbom_generator.find_ocm_sbom_resource(component, subject) is None

    def test_label_matches(self):
        subject = _make_resource(name='my-image')
        sbom = _make_sbom_resource(label_value=[{'identity': {'name': 'my-image'}}])
        component = _make_component([subject, sbom])
        result = sbom_generator.find_ocm_sbom_resource(component, subject)
        assert result is sbom

    def test_label_matches_with_version(self):
        subject = _make_resource(name='my-image', version='1.2.3')
        sbom = _make_sbom_resource(label_value=[{'identity': {'name': 'my-image', 'version': '1.2.3'}}])
        component = _make_component([subject, sbom])
        result = sbom_generator.find_ocm_sbom_resource(component, subject)
        assert result is sbom

    def test_label_version_mismatch_skipped(self):
        subject = _make_resource(name='my-image', version='1.0.0')
        sbom = _make_sbom_resource(label_value=[{'identity': {'name': 'my-image', 'version': '2.0.0'}}])
        component = _make_component([subject, sbom])
        assert sbom_generator.find_ocm_sbom_resource(component, subject) is None

    def test_multiple_candidates_returns_first_match(self):
        subject = _make_resource(name='my-image', extra_identity={'arch': 'amd64'})
        sbom_amd64 = _make_sbom_resource(
            name='sbom-amd64',
            label_value=[{'identity': {'name': 'my-image', 'arch': 'amd64'}}],
        )
        sbom_arm64 = _make_sbom_resource(
            name='sbom-arm64',
            label_value=[{'identity': {'name': 'my-image', 'arch': 'arm64'}}],
        )
        component = _make_component([subject, sbom_amd64, sbom_arm64])
        result = sbom_generator.find_ocm_sbom_resource(component, subject)
        assert result is sbom_amd64

    def test_label_no_match_for_extra_identity(self):
        subject = _make_resource(name='my-image', extra_identity={'arch': 'amd64'})
        sbom = _make_sbom_resource(label_value=[{'identity': {'name': 'my-image'}}])
        component = _make_component([subject, sbom])
        assert sbom_generator.find_ocm_sbom_resource(component, subject) is None


# --- _detect_sbom_format ---

class TestDetectSbomFormat:
    def test_cyclonedx(self):
        raw = {'bomFormat': 'CycloneDX', 'components': []}
        assert sbom_generator._detect_sbom_format(raw) is odg.extensions_cfg.SbomFormat.CYCLONEDX

    def test_spdx(self):
        raw = {'spdxVersion': 'SPDX-2.3', 'packages': []}
        assert sbom_generator._detect_sbom_format(raw) is odg.extensions_cfg.SbomFormat.SPDX

    def test_unknown_falls_back_to_cyclonedx(self):
        raw = {'something': 'else'}
        assert sbom_generator._detect_sbom_format(raw) is odg.extensions_cfg.SbomFormat.CYCLONEDX


# --- fetch_ocm_sbom ---

class TestFetchOcmSbom:
    def _cyclonedx_payload(self):
        return {'bomFormat': 'CycloneDX', 'components': []}

    def test_oci_registry_access(self):
        sbom_resource = _make_sbom_resource(image_reference='registry.example.com/sbom:1.0.0')
        component = unittest.mock.MagicMock()

        layer = unittest.mock.MagicMock()
        layer.digest = 'sha256:abc'
        manifest = unittest.mock.MagicMock(spec=['layers'])
        manifest.layers = [layer]

        blob_response = unittest.mock.MagicMock()
        blob_response.content = json.dumps(self._cyclonedx_payload()).encode()

        oci_client = unittest.mock.MagicMock()
        oci_client.manifest.return_value = manifest
        oci_client.blob.return_value = blob_response

        result = sbom_generator.fetch_ocm_sbom(sbom_resource, oci_client, component)

        oci_client.manifest.assert_called_once_with('registry.example.com/sbom:1.0.0')
        oci_client.blob.assert_called_once_with(
            'registry.example.com/sbom:1.0.0', 'sha256:abc', stream=False,
        )
        assert result.sbom_raw == self._cyclonedx_payload()
        assert result.sbom_format is odg.extensions_cfg.SbomFormat.CYCLONEDX

    def test_unsupported_access_type_raises(self):
        sbom_resource = _make_sbom_resource()
        sbom_resource = unittest.mock.MagicMock(spec=ocm.Resource)
        sbom_resource.access = unittest.mock.MagicMock()
        sbom_resource.access.type = ocm.AccessType.S3
        sbom_resource.name = 'my-sbom'

        oci_client = unittest.mock.MagicMock()
        component = unittest.mock.MagicMock()

        with pytest.raises(ValueError, match='Unsupported access type'):
            sbom_generator.fetch_ocm_sbom(sbom_resource, oci_client, component)


# --- generate_sbom_for_artefact (integration-level with mocks) ---

class TestGenerateSbomForArtefact:
    def _make_extension_cfg(self, generation_mode=odg.model.SbomGenerationMode.SYFT):
        cfg = unittest.mock.MagicMock(spec=odg.extensions_cfg.SBOMGeneratorConfig)
        cfg.is_supported.return_value = True
        cfg.on_exist = odg.model.OnExist.OVERWRITE
        cfg.on_unsupported = odg.extensions_cfg.WarningVerbosities.WARNING
        cfg.generation_mode = generation_mode
        cfg.output_format = odg.extensions_cfg.SbomFormat.CYCLONEDX
        cfg.create_new_scan_if_missing = False
        cfg.processing_mode = unittest.mock.MagicMock()
        mapping = unittest.mock.MagicMock()
        mapping.aws_secret_name = None
        cfg.mapping.return_value = mapping
        return cfg

    def _make_artefact(self):
        return odg.model.ComponentArtefactId(
            component_name='my.component',
            component_version='1.0.0',
            artefact_kind=odg.model.ArtefactKind.RESOURCE,
            artefact=odg.model.LocalArtefactId(
                artefact_name='my-image',
                artefact_version='1.0.0',
                artefact_type='ociImage',
            ),
        )

    def _make_resource_node(self, component_resources=None):
        if component_resources is None:
            component_resources = []
        resource = _make_resource()
        component = _make_component(component_resources)
        node = unittest.mock.MagicMock()
        node.resource = resource
        node.component = component
        return node

    def test_ocm_sbom_found_skips_generation(self):
        sbom_payload = {'bomFormat': 'CycloneDX', 'components': []}
        sbom_res = _make_sbom_resource(label_value=[{'identity': {'name': 'my-image'}}])
        resource_node = self._make_resource_node(component_resources=[
            _make_resource(name='my-image'),
            sbom_res,
        ])

        layer = unittest.mock.MagicMock()
        layer.digest = 'sha256:abc'
        manifest = unittest.mock.MagicMock(spec=['layers'])
        manifest.layers = [layer]

        blob_response = unittest.mock.MagicMock()
        blob_response.content = json.dumps(sbom_payload).encode()

        oci_client = unittest.mock.MagicMock()
        oci_client.manifest.return_value = manifest
        oci_client.blob.return_value = blob_response

        delivery_client = unittest.mock.MagicMock()
        delivery_client.query_metadata.return_value = []
        delivery_client.upload_blob = unittest.mock.MagicMock()
        delivery_client.update_metadata = unittest.mock.MagicMock()

        with (
            unittest.mock.patch(
                'k8s.util.get_ocm_node', return_value=resource_node,
            ),
            unittest.mock.patch(
                'sbom_generator.generate_sbom_with_syft',
            ) as mock_syft,
        ):
            sbom_generator.generate_sbom_for_artefact(
                artefact=self._make_artefact(),
                extension_cfg=self._make_extension_cfg(),
                component_descriptor_lookup=unittest.mock.MagicMock(),
                delivery_service_client=delivery_client,
                oci_client=oci_client,
                secret_factory=unittest.mock.MagicMock(),
            )

        mock_syft.assert_not_called()
        delivery_client.upload_blob.assert_called_once()

    def test_no_ocm_sbom_falls_through_to_syft(self):
        resource_node = self._make_resource_node(component_resources=[
            _make_resource(name='my-image'),
        ])

        syft_result = sbom_generator.SBOM(
            sbom_raw={'bomFormat': 'CycloneDX'},
            sbom_format=odg.extensions_cfg.SbomFormat.CYCLONEDX,
        )

        delivery_client = unittest.mock.MagicMock()
        delivery_client.query_metadata.return_value = []
        delivery_client.upload_blob = unittest.mock.MagicMock()
        delivery_client.update_metadata = unittest.mock.MagicMock()

        with (
            unittest.mock.patch('k8s.util.get_ocm_node', return_value=resource_node),
            unittest.mock.patch(
                'sbom_generator.generate_sbom_with_syft', return_value=syft_result,
            ) as mock_syft,
        ):
            sbom_generator.generate_sbom_for_artefact(
                artefact=self._make_artefact(),
                extension_cfg=self._make_extension_cfg(),
                component_descriptor_lookup=unittest.mock.MagicMock(),
                delivery_service_client=delivery_client,
                oci_client=unittest.mock.MagicMock(),
                secret_factory=unittest.mock.MagicMock(),
            )

        mock_syft.assert_called_once()

    def test_ocm_sbom_fetch_failure_falls_back_to_syft(self):
        sbom_res = _make_sbom_resource(label_value=[{'identity': {'name': 'my-image'}}])
        resource_node = self._make_resource_node(component_resources=[
            _make_resource(name='my-image'),
            sbom_res,
        ])

        syft_result = sbom_generator.SBOM(
            sbom_raw={'bomFormat': 'CycloneDX'},
            sbom_format=odg.extensions_cfg.SbomFormat.CYCLONEDX,
        )

        delivery_client = unittest.mock.MagicMock()
        delivery_client.query_metadata.return_value = []
        delivery_client.upload_blob = unittest.mock.MagicMock()
        delivery_client.update_metadata = unittest.mock.MagicMock()

        with (
            unittest.mock.patch('k8s.util.get_ocm_node', return_value=resource_node),
            unittest.mock.patch(
                'sbom_generator.fetch_ocm_sbom', side_effect=RuntimeError('fetch failed'),
            ),
            unittest.mock.patch(
                'sbom_generator.generate_sbom_with_syft', return_value=syft_result,
            ) as mock_syft,
        ):
            sbom_generator.generate_sbom_for_artefact(
                artefact=self._make_artefact(),
                extension_cfg=self._make_extension_cfg(),
                component_descriptor_lookup=unittest.mock.MagicMock(),
                delivery_service_client=delivery_client,
                oci_client=unittest.mock.MagicMock(),
                secret_factory=unittest.mock.MagicMock(),
            )

        mock_syft.assert_called_once()


# --- smoke tests: real OCM component descriptor from YAML, only I/O mocked ---

import pathlib
import sys

_RESOURCES = pathlib.Path(__file__).parent / 'resources'
sys.path.insert(0, str(pathlib.Path(__file__).parent))

import resources.lookup_mocks as _lookup_mocks


def _make_sync_lookup(path):
    async_lookup = _lookup_mocks.component_descriptor_lookup_mockup_factory(str(path))

    def sync_lookup(component_id, *_, **kwargs):
        import asyncio
        kwargs.pop('absent_ok', None)
        return asyncio.run(async_lookup(component_id, **kwargs))

    return sync_lookup


def _make_oci_client_for_sbom(sbom_payload: dict) -> unittest.mock.MagicMock:
    layer = unittest.mock.MagicMock()
    layer.digest = 'sha256:deadbeef'
    manifest = unittest.mock.MagicMock(spec=['layers'])
    manifest.layers = [layer]

    blob_response = unittest.mock.MagicMock()
    blob_response.content = json.dumps(sbom_payload).encode()

    oci_client = unittest.mock.MagicMock()
    oci_client.manifest.return_value = manifest
    oci_client.blob.return_value = blob_response
    return oci_client


def _make_delivery_client() -> unittest.mock.MagicMock:
    client = unittest.mock.MagicMock()
    client.query_metadata.return_value = []
    client.upload_blob = unittest.mock.MagicMock()
    client.update_metadata = unittest.mock.MagicMock()
    return client


class TestSmoke:
    _FIXTURE = _RESOURCES / 'component_descriptor_ocm_sbom.yaml'

    def _extension_cfg(self, generation_mode=odg.model.SbomGenerationMode.SYFT):
        cfg = unittest.mock.MagicMock(spec=odg.extensions_cfg.SBOMGeneratorConfig)
        cfg.is_supported.return_value = True
        cfg.on_exist = odg.model.OnExist.OVERWRITE
        cfg.on_unsupported = odg.extensions_cfg.WarningVerbosities.WARNING
        cfg.generation_mode = generation_mode
        cfg.output_format = odg.extensions_cfg.SbomFormat.CYCLONEDX
        cfg.create_new_scan_if_missing = False
        mapping = unittest.mock.MagicMock()
        mapping.aws_secret_name = None
        cfg.mapping.return_value = mapping
        return cfg

    def test_ocm_sbom_preferred_over_syft(self):
        """OCM-shipped SBoM is used; Syft is never invoked."""
        sbom_payload = {'bomFormat': 'CycloneDX', 'components': [{'name': 'libfoo', 'version': '1.0'}]}

        artefact = odg.model.ComponentArtefactId(
            component_name='my.org/my-component',
            component_version='1.0.0',
            artefact_kind=odg.model.ArtefactKind.RESOURCE,
            artefact=odg.model.LocalArtefactId(
                artefact_name='my-image',
                artefact_version='1.0.0',
                artefact_type='ociImage',
            ),
        )

        oci_client = _make_oci_client_for_sbom(sbom_payload)
        delivery_client = _make_delivery_client()

        with unittest.mock.patch('sbom_generator.generate_sbom_with_syft') as mock_syft:
            sbom_generator.generate_sbom_for_artefact(
                artefact=artefact,
                extension_cfg=self._extension_cfg(),
                component_descriptor_lookup=_make_sync_lookup(self._FIXTURE),
                delivery_service_client=delivery_client,
                oci_client=oci_client,
                secret_factory=unittest.mock.MagicMock(),
            )

        mock_syft.assert_not_called()
        oci_client.manifest.assert_called_with('registry.example.com/my-image-sbom:1.0.0')
        delivery_client.upload_blob.assert_called_once()

        meta_data = delivery_client.update_metadata.call_args.kwargs['data'][0].data
        assert meta_data['sbom_format'] == 'cyclonedx'

    def test_extra_identity_match_picks_correct_sbom(self):
        """For a multi-arch image, only the matching SBoM resource is used."""
        sbom_payload = {'bomFormat': 'CycloneDX', 'components': []}

        artefact = odg.model.ComponentArtefactId(
            component_name='my.org/my-component',
            component_version='2.0.0',
            artefact_kind=odg.model.ArtefactKind.RESOURCE,
            artefact=odg.model.LocalArtefactId(
                artefact_name='my-image',
                artefact_version='2.0.0',
                artefact_type='ociImage',
                artefact_extra_id={'arch': 'amd64'},
            ),
        )

        oci_client = _make_oci_client_for_sbom(sbom_payload)
        delivery_client = _make_delivery_client()

        with unittest.mock.patch('sbom_generator.generate_sbom_with_syft') as mock_syft:
            sbom_generator.generate_sbom_for_artefact(
                artefact=artefact,
                extension_cfg=self._extension_cfg(),
                component_descriptor_lookup=_make_sync_lookup(self._FIXTURE),
                delivery_service_client=delivery_client,
                oci_client=oci_client,
                secret_factory=unittest.mock.MagicMock(),
            )

        mock_syft.assert_not_called()
        oci_client.manifest.assert_called_with('registry.example.com/my-image-sbom-amd64:2.0.0')

    def test_no_ocm_sbom_falls_back_to_syft(self):
        """Component without an SBoM resource falls through to Syft."""
        syft_result = sbom_generator.SBOM(
            sbom_raw={'bomFormat': 'CycloneDX'},
            sbom_format=odg.extensions_cfg.SbomFormat.CYCLONEDX,
        )

        artefact = odg.model.ComponentArtefactId(
            component_name='my.org/my-component-no-sbom',
            component_version='1.0.0',
            artefact_kind=odg.model.ArtefactKind.RESOURCE,
            artefact=odg.model.LocalArtefactId(
                artefact_name='my-image',
                artefact_version='1.0.0',
                artefact_type='ociImage',
            ),
        )

        delivery_client = _make_delivery_client()

        with unittest.mock.patch(
            'sbom_generator.generate_sbom_with_syft', return_value=syft_result,
        ) as mock_syft:
            sbom_generator.generate_sbom_for_artefact(
                artefact=artefact,
                extension_cfg=self._extension_cfg(),
                component_descriptor_lookup=_make_sync_lookup(self._FIXTURE),
                delivery_service_client=delivery_client,
                oci_client=unittest.mock.MagicMock(),
                secret_factory=unittest.mock.MagicMock(),
            )

        mock_syft.assert_called_once()

