"""
Generic scan orchestration for CycloneDX-based vulnerability scanners.

New scanner extensions call `run_scan()` from their `__main__.py` instead of
re-implementing the orchestration steps themselves. Only the subprocess invocation
(the Scanner object) is scanner-specific.
"""

import abc
import dataclasses
import datetime
import json
import logging
import os
import tempfile

import ocm
import ocm.iter

import k8s.util
import ocm_util
import odg.extensions_cfg
import odg.findings
import odg.model
import odg_client
import scanner_utils.cyclonedx
import scanner_utils.findings
import scanner_utils.model

logger = logging.getLogger(__name__)

_OCI_IMAGE_MEDIA_TYPES = frozenset(
    {
        'application/vnd.oci.image.manifest.v1+tar',
        'application/vnd.oci.image.manifest.v1+tar+gzip',
        'application/vnd.oci.image.index.v1+tar.gzip',
    },
)


class SbomNotAvailable(Exception):
    """
    Raised when the scanner requires an SBOM (scan_target=SBOM or SBOM_WITH_BINARY_FALLBACK)
    but none has been generated yet for this artefact.

    Callers should requeue the backlog item with a delay to allow the sbom_generator job
    to complete before retrying.
    """


class Scanner(abc.ABC):
    """
    Interface that a scanner extension must implement.

    `scan_ocm_resource` is a concrete dispatch method that handles all OCM/OCI access-type
    branching and blob-fetching. Subclasses implement the content-typed hooks below.
    Never overwrite this function.

    The `*_stream` hooks have default implementations that write the blob to a temp file
    and call the corresponding `*_archive` / `scan_file` hook. Scanners that support streaming
    input can override the `*_stream` hooks directly to avoid writing to disk.
    """

    def scan_ocm_resource(
        self,
        resource_node: ocm.iter.ResourceNode,
        oci_client: object,
        secret_factory=None,
        aws_secret_name: str | None = None,
    ) -> dict:
        """
        Dispatch to the appropriate scan hook based on OCM resource type, access type, and mediaType.

        ArtefactType.SBOM + OCI_REGISTRY → fetch SBOM blob from OCI manifest → scan_sbom
        OCI_REGISTRY → scan_oci_image (by reference, no blob fetch)
        LOCAL_BLOB / OCI_BLOB / S3 with OCI image mediaType → scan_oci_image_archive_stream
        LOCAL_BLOB / OCI_BLOB / S3 with everything else → scan_file_stream
        """
        access = resource_node.resource.access

        # SBOM stored as an OCI artifact: fetch the blob from the first manifest layer
        if resource_node.resource.type == ocm.ArtefactType.SBOM:
            sbom = _fetch_oci_sbom(resource_node=resource_node, oci_client=oci_client)
            if sbom is not None:
                logger.debug('found OCI SBOM artifact, routing to scan_sbom')
                return self.scan_sbom(sbom)

        if access.type == ocm.AccessType.OCI_REGISTRY:
            logger.debug(f'scanning OCI image {access.imageReference!r}')
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
            raise ValueError(
                f'unsupported access type {access.type!r} in scan_ocm_resource; '
                'check extension_cfg.is_supported() configuration',
            ) from e

        for blob_descriptor in blob_descriptors:
            media_type = blob_descriptor.media_type or ''
            logger.debug(
                f'blob digest={blob_descriptor.digest!r} '
                f'mediaType={media_type!r} name={blob_descriptor.name!r}',
            )
            if media_type in _OCI_IMAGE_MEDIA_TYPES:
                return self.scan_oci_image_archive_stream(blob_descriptor)
            is_tar = ocm_util.is_tar_archive(blob_descriptor, resource_node.resource)
            return self.scan_file_stream(blob_descriptor, is_tar=is_tar)

        raise ValueError(
            f'unsupported access type {access.type!r} in scan_ocm_resource; '
            'check extension_cfg.is_supported() configuration',
        )

    def scan_oci_image(self, image_reference: str, secret_factory=None) -> dict:
        """
        Scan an OCI image by registry reference.
        secret_factory: optional SecretFactory for private registry auth.
        Returns a list of vulnerabilities in CycloneDX format as dict
        """
        raise NotImplementedError(f'{type(self).__name__} does not support OCI image scanning')

    def scan_oci_image_archive_stream(self, blob: ocm_util.BlobDescriptor) -> dict:
        """
        Scan an OCI image archive (ASAF tar) from a blob stream.
        Returns a list of vulnerabilities in CycloneDX format as dict

        Default: writes blob content to a temp file, calls scan_oci_image_archive(path, blob).
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

        Called when scan_target is SBOM or SBOM_WITH_BINARY_FALLBACK (primary path),
        or when the resource itself is an SBOM OCI artefact.
        """
        raise NotImplementedError(f'{type(self).__name__} does not support SBOM scanning')


def run_scan(
    artefact: odg.model.ComponentArtefactId,
    extension_cfg,
    vulnerability_cfg: odg.findings.Finding | None,
    component_descriptor_lookup,
    delivery_service_client: odg_client.DeliveryServiceClient,
    oci_client,
    scanner: Scanner,
    datasource: odg.model.Datasource,
) -> None:
    """
    Generic orchestration loop for a CycloneDX-based vulnerability scanner.

    artefact: The backlog item being processed — identifies the OCM component + resource
    extension_cfg: Scanner-specific configuration (e.g. `TrivyConfig`)
    vulnerability_cfg: Which CVSS score ranges produce findings and label-based exclusion rules
    component_descriptor_lookup: Resolve an OCM `ComponentIdentity` → `ComponentDescriptor`
    delivery_service_client: Client for the ODG delivery service API
    oci_client: Authenticated OCI client (`oci.client.Client`)
    scanner: Implementation of the `Scanner` interface
    datasource: `odg.model.Datasource` enum value for this scanner (e.g. `Datasource.TRIVY`).
        Used as the primary key namespace for all DB records written by this scanner
    """
    if not vulnerability_cfg or not vulnerability_cfg.matches(artefact):
        logger.info(
            f'[{datasource}] {artefact.component_name}:{artefact.component_version} '
            f'resource={artefact.artefact.artefact_name!r} '
            f'skipped: vulnerability_cfg does not match',
        )
        return

    if not extension_cfg.is_supported(artefact_kind=artefact.artefact_kind):
        if extension_cfg.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(
                f'{artefact.artefact_kind} is not supported by {datasource}, '
                'adjust filter configuration to exclude this artefact kind',
            )
        logger.info(
            f'[{datasource}] {artefact.component_name}:{artefact.component_version} '
            f'resource={artefact.artefact.artefact_name!r} '
            f'skipped: artefact_kind={artefact.artefact_kind!r} not supported',
        )
        return

    resource_node = k8s.util.get_ocm_node(
        component_descriptor_lookup=component_descriptor_lookup,
        artefact=artefact,
    )
    access = resource_node.resource.access

    if not extension_cfg.is_supported(
        access_type=access.type,
        artefact_type=resource_node.resource.type,
    ):
        if extension_cfg.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(
                f'{access.type} is not supported by {datasource}, '
                'adjust filter configuration to exclude this access type',
            )
        resource = resource_node.resource
        logger.info(
            f'[{datasource}] {artefact.component_name}:{artefact.component_version} '
            f'resource={resource.name!r} type={resource.type!r} '
            f'access_type={access.type!r} skipped: not supported',
        )
        return

    scan_target = extension_cfg.scan_target
    cyclonedx: dict | None = None

    if scan_target in (
        scanner_utils.model.ScanningMode.SBOM,
        scanner_utils.model.ScanningMode.SBOM_WITH_BINARY_FALLBACK,
    ):
        sbom = _fetch_sbom(delivery_service_client=delivery_service_client, artefact=artefact)
        if sbom is not None:
            cyclonedx = scanner.scan_sbom(sbom)

        if sbom is None:
            if scan_target is scanner_utils.model.ScanningMode.SBOM:
                logger.warning(
                    f'[{datasource}] {artefact.component_name}:{artefact.component_version} '
                    f'resource={artefact.artefact.artefact_name!r} '
                    f'no SBOM available, raising SbomNotAvailable',
                )
                raise SbomNotAvailable(artefact)
            logger.info(
                f'[{datasource}] {artefact.component_name}:{artefact.component_version} '
                f'resource={artefact.artefact.artefact_name!r} '
                f'no SBOM available, falling back to binary scan',
            )

    if cyclonedx is None:
        cyclonedx = scanner.scan_ocm_resource(
            resource_node=resource_node,
            oci_client=oci_client,
        )

    findings = list(
        scanner_utils.cyclonedx.iter_vulnerability_findings(
            cyclonedx=cyclonedx,
            vulnerability_cfg=vulnerability_cfg,
        ),
    )

    resource = resource_node.resource
    logger.info(
        f'[{datasource}] {artefact.component_name}:{artefact.component_version} '
        f'resource={resource.name!r} type={resource.type!r} '
        f'scan_target={scan_target} '
        f'raw_cves={len(cyclonedx.get("vulnerabilities") or [])} '
        f'findings_after_cfg={len(findings)}',
    )

    finding_artefact_ref = odg.model.component_artefact_id_from_ocm(
        component=resource_node.component,
        artefact=resource_node.resource,
    )
    finding_artefact_ref = dataclasses.replace(finding_artefact_ref, component_version=None)

    existing = {
        ef.data.key: ef
        for ef in scanner_utils.findings.iter_existing_findings(
            delivery_service_client=delivery_service_client,
            resource_node=resource_node,
            finding_type=odg.model.Datatype.VULNERABILITY_FINDING,
            datasource=datasource,
        )
    }

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    ams = [
        odg.model.ArtefactMetadata(
            artefact=finding_artefact_ref,
            meta=odg.model.Metadata(
                datasource=datasource,
                type=odg.model.Datatype.VULNERABILITY_FINDING,
                creation_date=now,
            ),
            data=f,
            discovery_date=now.date(),
        )
        for f in findings
    ]

    scan_info = scanner_utils.findings.make_artefact_scan_info(
        resource_node=resource_node,
        datasource=datasource,
    )

    delivery_service_client.update_metadata(data=[scan_info] + ams)
    scanner_utils.findings.delete_stale_findings(
        existing_findings_by_key=existing,
        current_findings=ams,
        delivery_service_client=delivery_service_client,
    )

    logger.debug(f'[{datasource}] {artefact.component_name}:{artefact.component_version} finished')


def _chunks_to_file(chunks, path: str) -> None:
    with open(path, 'wb') as f:
        for chunk in chunks:
            f.write(chunk)


def _fetch_sbom(
    delivery_service_client: odg_client.DeliveryServiceClient,
    artefact: odg.model.ComponentArtefactId,
) -> dict | None:
    entries = delivery_service_client.query_metadata(
        artefacts=[artefact],
        type=odg.model.Datatype.ARTEFACT_SCAN_INFO,
        datasource=odg.model.Datasource.SBOM_GENERATOR,
    )
    if not entries:
        return None
    digest = entries[0].get('data', {}).get('digest')
    if not digest:
        return None
    sbom_bytes = delivery_service_client.get_blob(digest=digest)
    return json.loads(sbom_bytes)


def _fetch_oci_sbom(
    resource_node: ocm.iter.ResourceNode,
    oci_client,
) -> dict | None:
    access = resource_node.resource.access
    if access.type != ocm.AccessType.OCI_REGISTRY:
        return None
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
