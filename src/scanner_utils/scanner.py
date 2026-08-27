import abc
import collections.abc
import json
import logging
import os
import tempfile

import oci.client
import oci.model
import ocm
import ocm.iter

import ocm_util
import scanner_utils.model
import secret_mgmt

logger = logging.getLogger(__name__)

_OCI_IMAGE_ARCHIVE_MEDIA_TYPES = frozenset(
    {
        'application/vnd.oci.image.manifest.v1+tar',
        'application/vnd.oci.image.manifest.v1+tar+gzip',
        'application/vnd.oci.image.index.v1+tar.gzip',
        'application/vnd.ocm.software.oci.layout.v1+tar',
    },
)

# LOCAL_BLOB access_media_type values that indicate the blob is an OCI image layout
# (the blob_media_type will be an individual layer, not the archive container format)
_OCI_IMAGE_ACCESS_MEDIA_TYPES = frozenset(
    {
        oci.model.OCI_IMAGE_INDEX_MIME,  # 'application/vnd.oci.image.index.v1+json'
        oci.model.OCI_MANIFEST_SCHEMA_V2_MIME,  # 'application/vnd.oci.image.manifest.v1+json'
    },
)


class Scanner(abc.ABC):
    """
    Interface that a scanner extension must implement.

    Override `decide_route` to customise routing; override the scan hooks to implement
    the actual scanning logic. Never overwrite `scan_ocm_resource` itself.

    The `*_stream` hooks have default implementations that write the blob to a temp file
    and call the corresponding `*_archive` / `scan_file` hook. Scanners that support streaming
    input can override the `*_stream` hooks directly to avoid writing to disk.
    """

    def decide_route(
        self,
        evidence: scanner_utils.model.RouteEvidence,
    ) -> scanner_utils.model.ScanTarget:
        """
        Decide which scan hook to invoke based on gathered evidence.

        Override to customise routing for a specific scanner.
        """
        if evidence.artefact_type == ocm.ArtefactType.SBOM:
            return scanner_utils.model.ScanTarget.SBOM
        if evidence.manifest_class_type is not None:
            if evidence.manifest_class_type is oci.model.OciImageManifestList or (
                evidence.manifest_class_type is oci.model.OciImageManifest
                and evidence.manifest_artifact_type is None
            ):
                return scanner_utils.model.ScanTarget.OCI_IMAGE
        if evidence.blob_media_type in _OCI_IMAGE_ARCHIVE_MEDIA_TYPES:
            return scanner_utils.model.ScanTarget.OCI_IMAGE_ARCHIVE
        if evidence.access_media_type in _OCI_IMAGE_ACCESS_MEDIA_TYPES:
            return scanner_utils.model.ScanTarget.OCI_IMAGE_ARCHIVE
        return scanner_utils.model.ScanTarget.FILE

    def scan_ocm_resource(
        self,
        resource_node: ocm.iter.ResourceNode,
        oci_client: oci.client.Client,
        secret_factory: secret_mgmt.SecretFactory | None = None,
        aws_secret_name: str | None = None,
    ) -> dict:
        """
        Gather routing evidence, call `decide_route`, log the decision, then dispatch.
        See `decide_route` for the default routing rules.
        """
        access = resource_node.resource.access
        evidence = scanner_utils.model.RouteEvidence(
            access_type=access.type,
            access_media_type=getattr(access, 'mediaType', None),
            artefact_type=resource_node.resource.type,
        )

        if access.type == ocm.AccessType.OCI_REGISTRY:
            manifest = oci_client.manifest(
                image_reference=access.imageReference,
                accept=oci.model.MimeTypes.prefer_multiarch,
            )
            evidence.manifest_class_type = type(manifest)
            evidence.manifest_media_type = getattr(manifest, 'mediaType', None)
            evidence.manifest_artifact_type = getattr(manifest, 'artifactType', None)

        target = self.decide_route(evidence)

        if target is scanner_utils.model.ScanTarget.SBOM:
            logger.info(f'scan route: target={target.value!r} evidence={evidence}')
            sbom = _fetch_oci_sbom(resource_node=resource_node, oci_client=oci_client)
            if sbom is not None:
                return self.scan_sbom(sbom)

        if target is scanner_utils.model.ScanTarget.OCI_IMAGE:
            logger.info(f'scan route: target={target.value!r} evidence={evidence}')
            return self.scan_oci_image(access.imageReference, secret_factory=secret_factory)

        try:
            blob_descriptors = ocm_util.iter_blob_descriptors(
                component=resource_node.component,
                access=access,
                oci_client=oci_client,
                secret_factory=secret_factory,
                aws_secret_name=aws_secret_name,
            )
        except RuntimeError as e:
            logger.error(
                f'unsupported access type in scan_ocm_resource, evidence={evidence}',
            )
            raise ValueError(
                f'unsupported access type {access.type!r} in scan_ocm_resource; '
                'check extension_cfg.is_supported() configuration',
            ) from e

        for blob_descriptor in blob_descriptors:
            evidence.blob_media_type = blob_descriptor.media_type or ''
            evidence.is_tar = ocm_util.is_tar_archive(blob_descriptor, resource_node.resource)
            target = self.decide_route(evidence)
            logger.info(f'scan route: target={target.value!r} evidence={evidence}')
            if target is scanner_utils.model.ScanTarget.OCI_IMAGE_ARCHIVE:
                return self.scan_oci_image_archive_stream(blob_descriptor, is_tar=evidence.is_tar)
            if target is scanner_utils.model.ScanTarget.FILE:
                return self.scan_file_stream(blob_descriptor, is_tar=evidence.is_tar)
            logger.error(f'unexpected scan target {target!r} from decide_route, evidence={evidence}')
            raise ValueError(f'unexpected scan target {target!r} returned by decide_route')

        logger.error(
            f'no blob descriptors yielded for access type {access.type!r}, evidence={evidence}',
        )
        raise ValueError(
            f'unsupported access type {access.type!r} in scan_ocm_resource; '
            'check extension_cfg.is_supported() configuration',
        )

    def scan_oci_image(
        self,
        image_reference: str,
        secret_factory: secret_mgmt.SecretFactory | None = None,
    ) -> dict:
        """
        Scan an OCI image by registry reference.
        secret_factory: optional SecretFactory for private registry auth.
        Returns a list of vulnerabilities in CycloneDX format as dict
        """
        raise NotImplementedError(f'{type(self).__name__} does not support OCI image scanning')

    def scan_oci_image_archive_stream(self, blob: ocm_util.BlobDescriptor, is_tar: bool) -> dict:
        """
        Scan an OCI image archive (ASAF tar) from a blob stream.
        Returns a list of vulnerabilities in CycloneDX format as dict

        Default: writes blob content to a temp file, calls scan_oci_image_archive(path, blob).
        If there are errors, it recovers by calling scan_file on the data file
        Override to consume the stream directly (e.g. pipe to scanner stdin).
        """
        media_type = blob.media_type or ''
        suffix = (
            '.tar.gz' if media_type.endswith('+gzip') or media_type.endswith('.gzip') else '.tar'
        )
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
            tmp_path = f.name
        try:
            _chunks_to_file(blob.content, tmp_path)
            logger.debug(f'scanning OCI image archive {tmp_path!r} (mediaType={media_type!r})')
            return self.scan_oci_image_archive(tmp_path, blob)
        except scanner_utils.model.ScanError as e:
            if not e.fallback_to_file_scan:
                raise
            logger.info('scan_oci_image_archive failed, falling back to file scan')
            return self.scan_file(tmp_path, blob, is_tar=is_tar)
        finally:
            os.unlink(tmp_path)

    def scan_oci_image_archive(self, path: str, blob: ocm_util.BlobDescriptor) -> dict:
        """
        Scan an OCI image archive (ASAF tar) from a local file path.
        blob.media_type has the mediaType.
        Returns a list of vulnerabilities in CycloneDX format as dict
        """
        raise NotImplementedError(
            f'{type(self).__name__} does not support OCI image archive scanning',
        )

    def scan_file_stream(self, blob: ocm_util.BlobDescriptor, is_tar: bool) -> dict:
        """
        Scans an arbitrary file (binary, filesystem tar, s3, oci blob, etc.) from a blob stream.
        is_tar pre-computed by base class via ocm_util.is_tar_archive.
        blob.media_type, blob.name, blob.digest available if needed.
        Returns a list of vulnerabilities in CycloneDX format as dict

        Default: writes blob content to a temp file, calls scan_file(path, blob, is_tar).
        Override to consume the stream directly (e.g. pipe to scanner stdin).
        """
        with tempfile.NamedTemporaryFile(delete=False) as f:
            tmp_path = f.name
        try:
            _chunks_to_file(blob.content, tmp_path)
            logger.debug(f'scanning file {tmp_path!r} (mediaType={blob.media_type!r}, {is_tar=})')
            return self.scan_file(tmp_path, blob, is_tar=is_tar)
        finally:
            os.unlink(tmp_path)

    def scan_file(self, path: str, blob: ocm_util.BlobDescriptor, is_tar: bool) -> dict:
        """
        Scans an arbitrary file (binary, filesystem tar, s3, oci blob, etc.) from a local file path.
        Returns a list of vulnerabilities in CycloneDX format as dict
        """
        raise NotImplementedError(f'{type(self).__name__} does not support file scanning')

    def scan_sbom(self, data: dict) -> dict:
        """
        Scan an existing SBOM (CycloneDX or SPDX) and return a new CycloneDX document
        with a list of found vulnerabilities as dict.

        Called when `decide_route` returns `scanner_utils.model.ScanTarget.SBOM`
        (resource type is SBOM artefact),
        or directly by `run_scan` when an SBOM is available from the delivery service.
        """
        raise NotImplementedError(f'{type(self).__name__} does not support SBOM scanning')


def _chunks_to_file(chunks: collections.abc.Iterable[bytes], path: str) -> None:
    with open(path, 'wb') as f:
        for chunk in chunks:
            f.write(chunk)


def _fetch_oci_sbom(
    resource_node: ocm.iter.ResourceNode,
    oci_client: oci.client.Client,
) -> dict | None:
    access = resource_node.resource.access
    try:
        manifest = oci_client.manifest(image_reference=access.imageReference)
    except Exception as e:
        logger.warning(f'failed to fetch OCI SBOM manifest for {access.imageReference!r}: {e}')
        return None
    if not manifest.layers:
        return None
    layer = manifest.layers[0]
    blob = oci_client.blob(
        image_reference=access.imageReference,
        digest=layer.digest,
        stream=True,
    )
    return json.loads(b''.join(blob.iter_content(chunk_size=4096)))
