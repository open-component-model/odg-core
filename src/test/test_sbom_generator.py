import json
import pathlib
import unittest.mock

import pytest

import oci.model
import ocm
import odg.extensions_cfg
import odg.labels
import odg.model

import ocm_util
import sbom_generator
import test.resources.lookup_mocks as _lookup_mocks

_RESOURCES = pathlib.Path(__file__).parent / 'resources'
_SMOKE_FIXTURE = _RESOURCES / 'component_descriptor_ocm_sbom.yaml'


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

    labels = [
        ocm.Label(
            name=odg.labels.ArtifactReferencesLabel.name,
            value=label_value,
            version=label_version,
        ),
    ]

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


def _make_extension_cfg(generation_mode=odg.model.SbomGenerationMode.SYFT):
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


def _make_artifact():
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


def _make_resource_node(component_resources=None):
    if component_resources is None:
        component_resources = []
    resource = _make_resource()
    component = _make_component(component_resources)
    node = unittest.mock.MagicMock()
    node.resource = resource
    node.component = component
    return node


def _patch_blob_descriptors(chunks: list[bytes]):
    descriptor = ocm_util.BlobDescriptor(content=iter(chunks), size=sum(len(c) for c in chunks))
    return unittest.mock.patch(
        'ocm_util.iter_blob_descriptors',
        return_value=iter([descriptor]),
    )


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
    blob_response.iter_content.return_value = [json.dumps(sbom_payload).encode()]

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


# --- find_ocm_sbom_resource ---


def test_find_ocm_sbom_resource_no_resources():
    component = _make_component([])
    resource = _make_resource()
    assert sbom_generator.find_ocm_sbom_resource(component, resource) is None


def test_find_ocm_sbom_resource_without_label():
    subject = _make_resource(name='my-image')
    candidate = _make_resource(name='other', labels=[])
    component = _make_component([subject, candidate])
    assert sbom_generator.find_ocm_sbom_resource(component, subject) is None


def test_find_ocm_sbom_resource_wrong_label_version():
    subject = _make_resource(name='my-image')
    sbom = _make_sbom_resource(
        label_value=[{'identity': {'name': 'my-image'}}],
        label_version='v1',
    )
    component = _make_component([subject, sbom])
    assert sbom_generator.find_ocm_sbom_resource(component, subject) is None


def test_find_ocm_sbom_resource_label_matches():
    subject = _make_resource(name='my-image')
    sbom = _make_sbom_resource(label_value=[{'identity': {'name': 'my-image'}}])
    component = _make_component([subject, sbom])
    result = sbom_generator.find_ocm_sbom_resource(component, subject)
    assert result is sbom


def test_find_ocm_sbom_resource_label_matches_with_version():
    subject = _make_resource(name='my-image', version='1.2.3')
    sbom = _make_sbom_resource(
        label_value=[{'identity': {'name': 'my-image', 'version': '1.2.3'}}],
    )
    component = _make_component([subject, sbom])
    result = sbom_generator.find_ocm_sbom_resource(component, subject)
    assert result is sbom


def test_find_ocm_sbom_resource_version_mismatch_skipped():
    subject = _make_resource(name='my-image', version='1.0.0')
    sbom = _make_sbom_resource(
        label_value=[{'identity': {'name': 'my-image', 'version': '2.0.0'}}],
    )
    component = _make_component([subject, sbom])
    assert sbom_generator.find_ocm_sbom_resource(component, subject) is None


def test_find_ocm_sbom_resource_multiple_candidates_returns_first_match():
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


def test_find_ocm_sbom_resource_no_match_for_extra_identity():
    subject = _make_resource(name='my-image', extra_identity={'arch': 'amd64'})
    sbom = _make_sbom_resource(label_value=[{'identity': {'name': 'my-image'}}])
    component = _make_component([subject, sbom])
    assert sbom_generator.find_ocm_sbom_resource(component, subject) is None


def test_find_ocm_sbom_resource_non_sbom_type_excluded():
    subject = _make_resource(name='my-image')
    attestation = ocm.Resource(
        name='my-attestation',
        version='1.0.0',
        type='attestation',
        access=ocm.OciAccess(imageReference='registry.example.com/attestation:1.0.0'),
        extraIdentity={},
        labels=[
            ocm.Label(
                name=odg.labels.ArtifactReferencesLabel.name,
                value=[{'identity': {'name': 'my-image'}}],
                version='v1alpha1',
            ),
        ],
    )
    component = _make_component([subject, attestation])
    assert sbom_generator.find_ocm_sbom_resource(component, subject) is None


# --- _detect_sbom_format ---


def test_detect_sbom_format_cyclonedx():
    raw = {'bomFormat': 'CycloneDX', 'components': []}
    assert sbom_generator._detect_sbom_format(raw) is odg.extensions_cfg.SbomFormat.CYCLONEDX


def test_detect_sbom_format_spdx():
    raw = {'spdxVersion': 'SPDX-2.3', 'packages': []}
    assert sbom_generator._detect_sbom_format(raw) is odg.extensions_cfg.SbomFormat.SPDX


def test_detect_sbom_format_unknown_raises():
    raw = {'something': 'else'}
    with pytest.raises(ValueError, match='unable to detect SBOM format'):
        sbom_generator._detect_sbom_format(raw)


# --- fetch_ocm_sbom ---


def test_fetch_ocm_sbom_joins_blob_content_and_detects_cyclonedx():
    sbom_resource = _make_sbom_resource(image_reference='registry.example.com/sbom:1.0.0')
    component = unittest.mock.MagicMock()
    oci_client = unittest.mock.MagicMock()
    secret_factory = unittest.mock.MagicMock()

    cyclonedx_payload = {'bomFormat': 'CycloneDX', 'components': []}
    payload = json.dumps(cyclonedx_payload).encode()
    with _patch_blob_descriptors([payload[:5], payload[5:]]) as mock_iter:
        result = sbom_generator.fetch_ocm_sbom(
            sbom_resource=sbom_resource,
            oci_client=oci_client,
            component=component,
            secret_factory=secret_factory,
        )

    mock_iter.assert_called_once_with(
        component=component,
        access=sbom_resource.access,
        oci_client=oci_client,
        secret_factory=secret_factory,
    )
    assert result.sbom_raw == cyclonedx_payload
    assert result.sbom_format is odg.extensions_cfg.SbomFormat.CYCLONEDX


def test_fetch_ocm_sbom_detects_spdx():
    payload = json.dumps({'spdxVersion': 'SPDX-2.3', 'packages': []}).encode()
    with _patch_blob_descriptors([payload]):
        result = sbom_generator.fetch_ocm_sbom(
            sbom_resource=_make_sbom_resource(),
            oci_client=unittest.mock.MagicMock(),
            component=unittest.mock.MagicMock(),
            secret_factory=unittest.mock.MagicMock(),
        )

    assert result.sbom_format is odg.extensions_cfg.SbomFormat.SPDX


def test_fetch_ocm_sbom_propagates_iter_errors():
    with unittest.mock.patch(
        'ocm_util.iter_blob_descriptors',
        side_effect=RuntimeError('Unsupported access type: s3'),
    ):
        with pytest.raises(RuntimeError, match='Unsupported access type'):
            sbom_generator.fetch_ocm_sbom(
                sbom_resource=_make_sbom_resource(),
                oci_client=unittest.mock.MagicMock(),
                component=unittest.mock.MagicMock(),
                secret_factory=unittest.mock.MagicMock(),
            )


# --- generate_sbom_for_artifact (integration-level with mocks) ---


def test_generate_sbom_ocm_sbom_found_skips_generation():
    sbom_payload = {'bomFormat': 'CycloneDX', 'components': []}
    sbom_res = _make_sbom_resource(label_value=[{'identity': {'name': 'my-image'}}])
    resource_node = _make_resource_node(
        component_resources=[
            _make_resource(name='my-image'),
            sbom_res,
        ],
    )

    layer = unittest.mock.MagicMock()
    layer.digest = 'sha256:abc'
    manifest = unittest.mock.MagicMock(spec=['layers'])
    manifest.layers = [layer]

    blob_response = unittest.mock.MagicMock()
    blob_response.iter_content.return_value = [json.dumps(sbom_payload).encode()]

    oci_client = unittest.mock.MagicMock()
    oci_client.manifest.return_value = manifest
    oci_client.blob.return_value = blob_response

    delivery_client = _make_delivery_client()

    with (
        unittest.mock.patch('k8s.util.get_ocm_node', return_value=resource_node),
        unittest.mock.patch('sbom_generator.generate_sbom_with_syft') as mock_syft,
    ):
        sbom_generator.generate_sbom_for_artefact(
            artefact=_make_artifact(),
            extension_cfg=_make_extension_cfg(),
            component_descriptor_lookup=unittest.mock.MagicMock(),
            delivery_service_client=delivery_client,
            oci_client=oci_client,
            secret_factory=unittest.mock.MagicMock(),
        )

    mock_syft.assert_not_called()
    delivery_client.upload_blob.assert_called_once()


def test_generate_sbom_no_ocm_sbom_falls_through_to_syft():
    resource_node = _make_resource_node(
        component_resources=[
            _make_resource(name='my-image'),
        ],
    )

    syft_result = sbom_generator.SBOM(
        sbom_raw={'bomFormat': 'CycloneDX'},
        sbom_format=odg.extensions_cfg.SbomFormat.CYCLONEDX,
    )

    delivery_client = _make_delivery_client()

    with (
        unittest.mock.patch('k8s.util.get_ocm_node', return_value=resource_node),
        unittest.mock.patch(
            'sbom_generator.generate_sbom_with_syft',
            return_value=syft_result,
        ) as mock_syft,
    ):
        sbom_generator.generate_sbom_for_artefact(
            artefact=_make_artifact(),
            extension_cfg=_make_extension_cfg(),
            component_descriptor_lookup=unittest.mock.MagicMock(),
            delivery_service_client=delivery_client,
            oci_client=unittest.mock.MagicMock(),
            secret_factory=unittest.mock.MagicMock(),
        )

    mock_syft.assert_called_once()


def test_generate_sbom_fetch_failure_falls_back_to_syft():
    sbom_res = _make_sbom_resource(label_value=[{'identity': {'name': 'my-image'}}])
    resource_node = _make_resource_node(
        component_resources=[
            _make_resource(name='my-image'),
            sbom_res,
        ],
    )

    syft_result = sbom_generator.SBOM(
        sbom_raw={'bomFormat': 'CycloneDX'},
        sbom_format=odg.extensions_cfg.SbomFormat.CYCLONEDX,
    )

    delivery_client = _make_delivery_client()

    with (
        unittest.mock.patch('k8s.util.get_ocm_node', return_value=resource_node),
        unittest.mock.patch(
            'sbom_generator.fetch_ocm_sbom',
            side_effect=RuntimeError('fetch failed'),
        ),
        unittest.mock.patch(
            'sbom_generator.generate_sbom_with_syft',
            return_value=syft_result,
        ) as mock_syft,
    ):
        sbom_generator.generate_sbom_for_artefact(
            artefact=_make_artifact(),
            extension_cfg=_make_extension_cfg(),
            component_descriptor_lookup=unittest.mock.MagicMock(),
            delivery_service_client=delivery_client,
            oci_client=unittest.mock.MagicMock(),
            secret_factory=unittest.mock.MagicMock(),
        )

    mock_syft.assert_called_once()


# --- smoke tests: real OCM component descriptor from YAML, only I/O mocked ---


def test_smoke_ocm_sbom_preferred_over_syft():
    sbom_payload = {
        'bomFormat': 'CycloneDX',
        'components': [{'name': 'libfoo', 'version': '1.0'}],
    }

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
            extension_cfg=_make_extension_cfg(),
            component_descriptor_lookup=_make_sync_lookup(_SMOKE_FIXTURE),
            delivery_service_client=delivery_client,
            oci_client=oci_client,
            secret_factory=unittest.mock.MagicMock(),
        )

    mock_syft.assert_not_called()
    oci_client.manifest.assert_called_with(
        image_reference='registry.example.com/my-image-sbom:1.0.0',
        accept=oci.model.MimeTypes.prefer_multiarch,
    )
    delivery_client.upload_blob.assert_called_once()

    meta_data = delivery_client.update_metadata.call_args.kwargs['data'][0].data
    assert meta_data['sbom_format'] == 'cyclonedx'


def test_smoke_extra_identity_match_picks_correct_sbom():
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
            extension_cfg=_make_extension_cfg(),
            component_descriptor_lookup=_make_sync_lookup(_SMOKE_FIXTURE),
            delivery_service_client=delivery_client,
            oci_client=oci_client,
            secret_factory=unittest.mock.MagicMock(),
        )

    mock_syft.assert_not_called()
    oci_client.manifest.assert_called_with(
        image_reference='registry.example.com/my-image-sbom-amd64:2.0.0',
        accept=oci.model.MimeTypes.prefer_multiarch,
    )


def test_smoke_no_ocm_sbom_falls_back_to_syft():
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
        'sbom_generator.generate_sbom_with_syft',
        return_value=syft_result,
    ) as mock_syft:
        sbom_generator.generate_sbom_for_artefact(
            artefact=artefact,
            extension_cfg=_make_extension_cfg(),
            component_descriptor_lookup=_make_sync_lookup(_SMOKE_FIXTURE),
            delivery_service_client=delivery_client,
            oci_client=unittest.mock.MagicMock(),
            secret_factory=unittest.mock.MagicMock(),
        )

    mock_syft.assert_called_once()
