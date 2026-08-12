import enum
import logging
import os
import subprocess
import tarfile

import oci.client
import oci.model
import ocm

import dockerutil
import secret_mgmt.aws
import secret_mgmt.oci_registry
import util


logger = logging.getLogger(__name__)
own_dir = os.path.abspath(os.path.dirname(__file__))


class SyftSbomFormat(enum.StrEnum):
    CYCLONEDX = 'cyclonedx-json'
    SPDX = 'spdx-json'


def run_syft(
    source: str,
    output_format: SyftSbomFormat = SyftSbomFormat.CYCLONEDX,
) -> str:
    """
    Runs `syft` (https://github.com/anchore/syft) to create a SBOM for the provided `source`.
    `source` might be any of the accepted inputs for `syft`, e.g. an image reference or a path
    to a directory, file, archive.

    Returns the raw SBOM output as a string.
    """
    sbom_cmd = (
        'syft',
        source,
        '--scope',
        'all-layers',
        '--output',
        output_format,
    )
    logger.info(f'run cmd "{" ".join(sbom_cmd)}"')
    try:
        sbom_raw = subprocess.run(sbom_cmd, check=True, capture_output=True, text=True).stdout
    except subprocess.CalledProcessError as e:
        e.add_note(f'{e.stdout=}')
        e.add_note(f'{e.stderr=}')
        raise

    return sbom_raw


def _sbom_for_oci_artefact(
    access: ocm.OciAccess,
    secret_factory: secret_mgmt.SecretFactory,
    sbom_output_format: SyftSbomFormat = SyftSbomFormat.CYCLONEDX,
) -> str:
    oci_secret = secret_mgmt.oci_registry.find_cfg(
        secret_factory=secret_factory,
        image_reference=access.imageReference,
    )

    if oci_secret:
        dockerutil.prepare_docker_cfg(
            image_reference=access.imageReference,
            username=oci_secret.username,
            password=oci_secret.password,
        )

    return run_syft(
        source=access.imageReference,
        output_format=sbom_output_format,
    )


def _sbom_for_s3(
    access: ocm.S3Access | ocm.LegacyS3Access,
    secret_factory: secret_mgmt.SecretFactory,
    file_path: str,
    aws_secret_name: str | None = None,
    sbom_output_format: SyftSbomFormat = SyftSbomFormat.CYCLONEDX,
) -> str:
    if hasattr(access, 'mediaType') and access.mediaType:
        if not util.media_type_supports(access.mediaType, 'tar'):
            raise ValueError(f"Don't know how to handle {access.mediaType=} for s3 access")
    else:
        logger.warning(f'No mediaType found in {access=}, will assume it is a tar archive')

    aws_secret = secret_mgmt.aws.find_cfg(
        secret_factory=secret_factory,
        secret_name=aws_secret_name,
    )
    s3_client = aws_secret.session.client('s3')

    if isinstance(access, ocm.LegacyS3Access):
        bucket = access.bucketName
        key = access.objectKey
    else:
        bucket = access.bucket
        key = access.key

    fileobj = s3_client.get_object(Bucket=bucket, Key=key)['Body']

    def tar_filter(member: tarfile.TarInfo, dest_path: str) -> tarfile.TarInfo | None:
        if member.islnk() or member.issym():
            if os.path.isabs(member.linkname):
                return None
        return member

    with tarfile.open(fileobj=fileobj, mode='r|*') as tar:
        tar.extractall(
            path=file_path,
            filter=tar_filter,
        )

    return run_syft(
        source=file_path,
        output_format=sbom_output_format,
    )


def _sbom_for_blob(
    access: ocm.LocalBlobAccess | ocm.OciBlobAccess,
    component: ocm.Component,
    oci_client: oci.client.Client,
    secret_factory: secret_mgmt.SecretFactory,
    file_path: str,
    sbom_output_format: SyftSbomFormat = SyftSbomFormat.CYCLONEDX,
) -> str:
    image_reference = component.current_ocm_repo.component_version_oci_ref(
        name=component.name,
        version=component.version,
    )

    if access.type is ocm.AccessType.LOCAL_BLOB:
        digest = access.localReference.lower()
    else:
        digest = access.digest.lower()

    if access.mediaType in (
        oci.model.OCI_IMAGE_INDEX_MIME,
        oci.model.OCI_MANIFEST_SCHEMA_V2_MIME,
        oci.model.DOCKER_MANIFEST_LIST_MIME,
        oci.model.DOCKER_MANIFEST_SCHEMA_V2_MIME,
    ):
        image_reference = oci.model.OciImageReference(image_reference).with_tag(digest)

        return _sbom_for_oci_artefact(
            access=ocm.OciAccess(imageReference=str(image_reference)),
            secret_factory=secret_factory,
            sbom_output_format=sbom_output_format,
        )

    if access.type is ocm.AccessType.LOCAL_BLOB and access.globalAccess:
        image_reference = access.globalAccess.ref
        digest = access.globalAccess.digest.lower()

    blob = oci_client.blob(
        image_reference=image_reference,
        digest=digest,
        stream=True,
    )

    with open(file_path, 'wb') as file:
        for chunk in blob.iter_content(chunk_size=4096):
            file.write(chunk)

    return run_syft(
        source=file_path,
        output_format=sbom_output_format,
    )


def generate_raw_sbom_for_artefact(
    component: ocm.Component,
    access: ocm.Access,
    secret_factory: secret_mgmt.SecretFactory,
    oci_client: oci.client.Client | None = None,
    file_path: str | None = None,
    aws_secret_name: str | None = None,
    sbom_output_format: SyftSbomFormat = SyftSbomFormat.CYCLONEDX,
) -> str:
    if (
        access.type
        in (
            ocm.AccessType.LOCAL_BLOB,
            ocm.AccessType.OCI_BLOB,
        )
        and not oci_client
    ):
        raise ValueError(f'oci_client must not be empty for {access.type=}')

    if (
        access.type
        in (
            ocm.AccessType.LOCAL_BLOB,
            ocm.AccessType.OCI_BLOB,
            ocm.AccessType.S3,
        )
        and not file_path
    ):
        raise ValueError(f'file_path must not be empty for {access.type=}')

    if access.type is ocm.AccessType.OCI_REGISTRY:
        return _sbom_for_oci_artefact(
            access=access,
            secret_factory=secret_factory,
            sbom_output_format=sbom_output_format,
        )

    elif access.type is ocm.AccessType.S3:
        return _sbom_for_s3(
            access=access,
            secret_factory=secret_factory,
            aws_secret_name=aws_secret_name,
            file_path=file_path,
            sbom_output_format=sbom_output_format,
        )

    elif access.type in (
        ocm.AccessType.LOCAL_BLOB,
        ocm.AccessType.OCI_BLOB,
    ):
        return _sbom_for_blob(
            access=access,
            component=component,
            oci_client=oci_client,
            secret_factory=secret_factory,
            file_path=file_path,
            sbom_output_format=sbom_output_format,
        )

    else:
        raise ValueError(f'dont know how to handle {access.type=}')
