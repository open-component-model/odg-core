import unittest.mock

import ocm
import pytest

import ocm_util
import odg.labels


def _make_resource(
    name='my-image',
    version='1.0.0',
    extra_identity=None,
    resource_type='ociImage',
):
    return ocm.Resource(
        name=name,
        version=version,
        type=resource_type,
        access=ocm.OciAccess(imageReference=f'registry.example.com/{name}:{version}'),
        extraIdentity=extra_identity or {},
        labels=[],
    )


def _make_referencing_resource(
    name='my-image-sbom',
    version='1.0.0',
    resource_type='sbom',
    label_value=None,
    label_version='v1alpha1',
):
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
        type=resource_type,
        access=ocm.OciAccess(imageReference=f'registry.example.com/{name}:{version}'),
        extraIdentity={},
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
        assert not ocm_util._identity_matches({'name': 'other-image'}, resource)

    def test_name_match_no_version(self):
        resource = _make_resource(name='my-image', version='1.0.0')
        assert ocm_util._identity_matches({'name': 'my-image'}, resource)

    def test_version_match(self):
        resource = _make_resource(name='my-image', version='1.0.0')
        assert ocm_util._identity_matches({'name': 'my-image', 'version': '1.0.0'}, resource)

    def test_version_mismatch(self):
        resource = _make_resource(name='my-image', version='1.0.0')
        assert not ocm_util._identity_matches(
            {'name': 'my-image', 'version': '2.0.0'},
            resource,
        )

    def test_extra_identity_exact_match(self):
        resource = _make_resource(name='my-image', extra_identity={'arch': 'amd64'})
        assert ocm_util._identity_matches(
            {'name': 'my-image', 'arch': 'amd64'},
            resource,
        )

    def test_extra_identity_key_missing_in_resource(self):
        resource = _make_resource(name='my-image', extra_identity={})
        assert not ocm_util._identity_matches(
            {'name': 'my-image', 'arch': 'amd64'},
            resource,
        )

    def test_extra_identity_extra_key_in_resource(self):
        resource = _make_resource(name='my-image', extra_identity={'arch': 'amd64', 'os': 'linux'})
        assert not ocm_util._identity_matches(
            {'name': 'my-image', 'arch': 'amd64'},
            resource,
        )

    def test_extra_identity_value_mismatch(self):
        resource = _make_resource(name='my-image', extra_identity={'arch': 'amd64'})
        assert not ocm_util._identity_matches(
            {'name': 'my-image', 'arch': 'arm64'},
            resource,
        )


# --- iter_resources_referencing ---


class TestIterResourcesReferencing:
    def test_no_resources(self):
        component = _make_component([])
        resource = _make_resource()
        assert list(ocm_util.iter_resources_referencing(component, resource)) == []

    def test_resource_without_label(self):
        subject = _make_resource(name='my-image')
        candidate = _make_resource(name='other')
        component = _make_component([subject, candidate])
        assert list(ocm_util.iter_resources_referencing(component, subject)) == []

    def test_label_wrong_version(self):
        subject = _make_resource(name='my-image')
        ref = _make_referencing_resource(
            label_value=[{'identity': {'name': 'my-image'}}],
            label_version='v1',
        )
        component = _make_component([subject, ref])
        assert list(ocm_util.iter_resources_referencing(component, subject)) == []

    def test_label_matches(self):
        subject = _make_resource(name='my-image')
        ref = _make_referencing_resource(label_value=[{'identity': {'name': 'my-image'}}])
        component = _make_component([subject, ref])
        assert list(ocm_util.iter_resources_referencing(component, subject)) == [ref]

    def test_yields_any_resource_type_without_filter(self):
        subject = _make_resource(name='my-image')
        attestation = _make_referencing_resource(
            name='my-attestation',
            resource_type='attestation',
            label_value=[{'identity': {'name': 'my-image'}}],
        )
        component = _make_component([subject, attestation])
        assert list(ocm_util.iter_resources_referencing(component, subject)) == [attestation]

    def test_resource_type_filter(self):
        subject = _make_resource(name='my-image')
        sbom = _make_referencing_resource(
            name='my-sbom',
            resource_type='sbom',
            label_value=[{'identity': {'name': 'my-image'}}],
        )
        attestation = _make_referencing_resource(
            name='my-attestation',
            resource_type='attestation',
            label_value=[{'identity': {'name': 'my-image'}}],
        )
        component = _make_component([subject, sbom, attestation])
        result = list(
            ocm_util.iter_resources_referencing(
                component,
                subject,
                resource_type='sbom',
            ),
        )
        assert result == [sbom]

    def test_identity_no_match(self):
        subject = _make_resource(name='my-image')
        ref = _make_referencing_resource(label_value=[{'identity': {'name': 'other-image'}}])
        component = _make_component([subject, ref])
        assert list(ocm_util.iter_resources_referencing(component, subject)) == []

    def test_multiple_entries_in_label(self):
        subject = _make_resource(name='my-image')
        ref = _make_referencing_resource(
            label_value=[
                {'identity': {'name': 'other-image'}},
                {'identity': {'name': 'my-image'}},
            ],
        )
        component = _make_component([subject, ref])
        assert list(ocm_util.iter_resources_referencing(component, subject)) == [ref]


# --- iter_blob_descriptors allowlist enforcement ---


class TestIterBlobDescriptorsAllowlist:
    def _component(self):
        component = unittest.mock.MagicMock(spec=ocm.Component)
        component.name = 'example.org/test'
        component.version = '1.0.0'
        return component

    def test_non_allowlisted_oci_image_raises(self):
        access = ocm.OciAccess(imageReference='evil.example.com/bad/image:latest')
        with (
            unittest.mock.patch('lookups.is_allowlisted_ocm_repo', return_value=False),
            unittest.mock.patch('odg.audit.emit') as mock_emit,
        ):
            with pytest.raises(PermissionError, match='not in allowlist'):
                # function body runs eagerly (returns a generator, does not yield), so the
                # allowlist check fires on call
                ocm_util.iter_blob_descriptors(
                    component=self._component(),
                    access=access,
                    oci_client=unittest.mock.MagicMock(),
                    secret_factory=unittest.mock.MagicMock(),
                )
        mock_emit.assert_called_once()
        assert mock_emit.call_args.kwargs['odg_audit_outcome'] == 'denied'

    def test_allowlisted_oci_image_proceeds(self):
        access = ocm.OciAccess(imageReference='ghcr.io/org/image:latest')
        with (
            unittest.mock.patch('lookups.is_allowlisted_ocm_repo', return_value=True),
            unittest.mock.patch(
                'ocm_util._iter_blob_descriptors_for_manifest',
                return_value=iter([]),
            ) as mock_manifest,
        ):
            result = ocm_util.iter_blob_descriptors(
                component=self._component(),
                access=access,
                oci_client=unittest.mock.MagicMock(),
                secret_factory=unittest.mock.MagicMock(),
            )
            assert list(result) == []
        mock_manifest.assert_called_once()

    def test_non_oci_access_skips_check(self):
        access = ocm.LocalBlobAccess(
            localReference='sha256:abc123',
            mediaType='application/octet-stream',
        )
        with (
            unittest.mock.patch('lookups.is_allowlisted_ocm_repo') as mock_check,
            unittest.mock.patch(
                'ocm_util._iter_blob_descriptors_for_blob',
                return_value=iter([]),
            ),
        ):
            list(
                ocm_util.iter_blob_descriptors(
                    component=self._component(),
                    access=access,
                    oci_client=unittest.mock.MagicMock(),
                    secret_factory=unittest.mock.MagicMock(),
                ),
            )
        mock_check.assert_not_called()
