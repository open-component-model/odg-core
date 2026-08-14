import collections.abc
import dataclasses
import io
import logging
import os
import tarfile

import dacite

import cnudie.retrieve_async
import oci.client
import oci.client_async
import oci.model
import ocm
import ocm.iter
import ocm.oci
import tarutil

import odg.model
import secret_mgmt
import secret_mgmt.aws
import util


logger = logging.getLogger(__name__)


@dataclasses.dataclass
class BlobDescriptor:
    content: collections.abc.Generator[bytes, None, None]
    size: int
    digest: str | None = None
    media_type: str | None = None
    name: str | None = None


def _iter_blob_descriptors_for_manifest(
    image_reference: str | oci.model.OciImageReference,
    oci_client: oci.client.Client,
    chunk_size=tarfile.RECORDSIZE,
    include_config_blob=True,
    fallback_to_first_subimage_if_index=False,
) -> collections.abc.Generator[BlobDescriptor, None, None]:
    manifest = oci_client.manifest(
        image_reference=image_reference,
        accept=oci.model.MimeTypes.prefer_multiarch,
    )

    image_reference = oci.model.OciImageReference.to_image_ref(image_reference)

    if fallback_to_first_subimage_if_index and isinstance(manifest, oci.model.OciImageManifestList):
        logger.warning(
            f'image-index handling not fully implemented - will only scan first image, '
            f'{image_reference=}, {manifest.mediaType=}',
        )
        manifest_ref = manifest.manifests[0]
        manifest = oci_client.manifest(
            image_reference=f'{image_reference.ref_without_tag}@{manifest_ref.digest}',
        )

    blob_refs = manifest.blobs() if include_config_blob else manifest.layers

    if not include_config_blob:
        logger.debug('skipping config blob')

    for blob_ref in blob_refs:
        content = oci_client.blob(
            image_reference=image_reference,
            digest=blob_ref.digest,
            stream=True,
        ).iter_content(chunk_size=chunk_size)

        yield BlobDescriptor(
            content=content,
            size=blob_ref.size,
            digest=blob_ref.digest,
            media_type=blob_ref.mediaType,
            name=f'{blob_ref.digest}.tar',
        )


def _iter_blob_descriptors_for_local_blob(
    access: ocm.LocalBlobAccess,
    oci_client: oci.client.Client,
    image_reference: str = None,
) -> collections.abc.Generator[BlobDescriptor, None, None]:
    if access.globalAccess:
        image_reference = access.globalAccess.ref
        digest = access.globalAccess.digest
        size = access.globalAccess.size

    else:
        if not image_reference:
            raise ValueError('`image_reference` must not be empty to resolve local blob')

        digest = access.localReference.lower()
        size = access.size

    blob = oci_client.blob(
        image_reference=image_reference,
        digest=digest,
        stream=True,
    )

    if not size:
        manifest = oci_client.manifest(
            image_reference=image_reference,
            accept=oci.model.MimeTypes.prefer_multiarch,
        )

        if isinstance(manifest, oci.model.OciImageManifestList):
            component_descriptor_manifest_digest = ocm.oci.find_component_descriptor_manifest_digest(
                index_manifest=manifest,
            )

            manifest = oci_client.manifest(
                image_reference=oci.model.OciImageReference(image_reference).with_tag(
                    tag=component_descriptor_manifest_digest,
                ),
            )

        for layer in manifest.layers:
            if layer.digest == digest:
                size = layer.size
                break
        else:
            raise ValueError('`size` must not be empty to stream local blob')

    yield BlobDescriptor(
        content=blob.iter_content(chunk_size=4096),
        size=size,
        digest=digest,
        media_type=access.mediaType,
        name=access.referenceName,
    )


def _iter_blob_descriptors_for_oci_blob(
    access: ocm.OciBlobAccess,
    oci_client: oci.client.Client,
    image_reference: str,
) -> collections.abc.Generator[BlobDescriptor, None, None]:
    digest = access.digest.lower()
    size = access.size

    blob = oci_client.blob(
        image_reference=image_reference,
        digest=digest,
        stream=True,
    )

    yield BlobDescriptor(
        content=blob.iter_content(chunk_size=4096),
        size=size,
        digest=digest,
        media_type=access.mediaType,
        name=f'{digest}.tar',
    )


def _iter_blob_descriptors_for_blob(
    access: ocm.LocalBlobAccess | ocm.OciBlobAccess,
    component: ocm.Component,
    oci_client: oci.client.Client,
) -> collections.abc.Generator[BlobDescriptor, None, None]:
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

        return _iter_blob_descriptors_for_manifest(
            image_reference=image_reference,
            oci_client=oci_client,
            include_config_blob=False,
            fallback_to_first_subimage_if_index=True,
        )

    if access.type is ocm.AccessType.LOCAL_BLOB:
        return _iter_blob_descriptors_for_local_blob(
            access=access,
            oci_client=oci_client,
            image_reference=image_reference,
        )
    else:
        return _iter_blob_descriptors_for_oci_blob(
            access=access,
            oci_client=oci_client,
            image_reference=image_reference,
        )


def _iter_blob_descriptors_for_s3(
    s3_access: ocm.S3Access | ocm.LegacyS3Access,
    secret_factory: secret_mgmt.SecretFactory,
    aws_secret_name: str | None = None,
    chunk_size: int = 8192,
) -> collections.abc.Generator[BlobDescriptor, None, None]:
    aws_secret = secret_mgmt.aws.find_cfg(
        secret_factory=secret_factory,
        secret_name=aws_secret_name,
    )
    s3_client = aws_secret.session.client('s3')

    if isinstance(s3_access, ocm.LegacyS3Access):
        bucket = s3_access.bucketName
        key = s3_access.objectKey
    else:
        bucket = s3_access.bucket
        key = s3_access.key

    blob = s3_client.get_object(Bucket=bucket, Key=key)

    size = blob['ContentLength']
    body = blob['Body']

    yield BlobDescriptor(
        content=body.iter_chunks(chunk_size=chunk_size),
        size=size,
        media_type=s3_access.mediaType,
        name=f's3://{bucket}/{key}',
    )


def iter_blob_descriptors(
    component: ocm.Component,
    access: ocm.Access,
    oci_client: oci.client.Client,
    secret_factory: secret_mgmt.SecretFactory,
    aws_secret_name: str | None = None,
) -> collections.abc.Generator[BlobDescriptor, None, None]:
    if access.type is ocm.AccessType.OCI_REGISTRY:
        access: ocm.OciAccess

        return _iter_blob_descriptors_for_manifest(
            image_reference=access.imageReference,
            oci_client=oci_client,
            include_config_blob=False,
            fallback_to_first_subimage_if_index=True,
        )

    elif access.type in (
        ocm.AccessType.S3,
        ocm.AccessType.S3_V2,
    ):
        return _iter_blob_descriptors_for_s3(
            s3_access=access,
            secret_factory=secret_factory,
            aws_secret_name=aws_secret_name,
        )

    elif access.type in (
        ocm.AccessType.LOCAL_BLOB,
        ocm.AccessType.OCI_BLOB,
    ):
        return _iter_blob_descriptors_for_blob(
            access=access,
            component=component,
            oci_client=oci_client,
        )

    else:
        raise RuntimeError(f'Unsupported access type: {access.type}')


def is_tar_archive(
    blob_descriptor: BlobDescriptor,
    resource: ocm.Resource,
) -> bool:
    """
    Returns True if the blob should be treated as a tar archive, based on the media type of the blob
    descriptor (preferred) or the resource type (fallback).
    """
    if (media_type := blob_descriptor.media_type) and not util.media_type_supports(
        media_type=media_type,
        type='tar',
    ):
        return False

    if not media_type and not util.media_type_supports(resource.type, 'tar'):
        return False

    return True


def iter_tar_archive_contents(
    data: collections.abc.Iterator[bytes],
    tar_filter: collections.abc.Callable[[tarfile.TarInfo], tarfile.TarInfo | None] | None = None,
) -> collections.abc.Generator[tuple[str, io.BytesIO], None, None]:
    """
    Yields (name, fileobj) for each regular file in the tar archive read from `data`.

    `data` is consumed as a streaming iterator — it does not need to be seekable. Non-regular
    entries (directories, symlinks, hardlinks) are skipped. The optional `tar_filter` callback
    receives a TarInfo and should return it to include the entry or None to skip it.

    The yielded fileobj is only valid until the next iteration. Callers must fully read it
    before advancing the loop.
    """
    with tarfile.open(fileobj=tarutil.FilelikeProxy(data), mode='r|*') as tar_file:
        tar_file: tarfile.TarFile

        for tar_info in tar_file:
            if not tar_info.isfile():
                continue  # always filter out non regular files

            if tar_filter and not tar_filter(tar_info):
                continue

            yield tar_info.name, tar_file.extractfile(tar_info)


def extract_tar_archive_contents(
    data: collections.abc.Iterator[bytes],
    file_path: str,
    tar_filter: collections.abc.Callable[[tarfile.TarInfo], tarfile.TarInfo | None] | None = None,
    chunk_size: int = 65536,
):
    root = os.path.realpath(file_path)
    os.makedirs(root, exist_ok=True)

    for fname, file in iter_tar_archive_contents(
        data=data,
        tar_filter=tar_filter,
    ):
        dest = os.path.realpath(os.path.join(root, fname))

        if os.path.commonpath((root, dest)) != root:
            logger.warning(f'skipping tar member outside of destination: {fname=}')
            continue

        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, 'wb') as f:
            while chunk := file.read(chunk_size):
                f.write(chunk)


async def find_artefact_node_async(
    component_descriptor_lookup: cnudie.retrieve_async.ComponentDescriptorLookupById,
    artefact: odg.model.ComponentArtefactId,
    absent_ok: bool = False,
) -> ocm.iter.ResourceNode | ocm.iter.SourceNode | None:
    if not odg.model.is_ocm_artefact(artefact.artefact_kind):
        return None

    component = (
        await component_descriptor_lookup(
            ocm.ComponentIdentity(
                name=artefact.component_name,
                version=artefact.component_version,
            ),
            absent_ok=absent_ok,
        )
    ).component

    if not component:
        return None

    if artefact.artefact_kind is odg.model.ArtefactKind.RESOURCE:
        artefacts = component.resources
    elif artefact.artefact_kind is odg.model.ArtefactKind.SOURCE:
        artefacts = component.sources
    else:
        raise RuntimeError('this line should never be reached')

    for a in artefacts:
        if (a.name or artefact.artefact.artefact_name) and a.name != artefact.artefact.artefact_name:
            continue
        if (
            a.version or artefact.artefact.artefact_version
        ) and a.version != artefact.artefact.artefact_version:
            continue
        if (a.type or artefact.artefact.artefact_type) and a.type != artefact.artefact.artefact_type:
            continue
        if (
            odg.model.normalise_artefact_extra_id(a.extraIdentity)
            != artefact.artefact.normalised_artefact_extra_id
        ):
            continue

        # found artefact in component's artefacts
        if artefact.artefact_kind is odg.model.ArtefactKind.RESOURCE:
            return ocm.iter.ResourceNode(
                path=(ocm.iter.NodePathEntry(component),),
                resource=a,
            )
        elif artefact.artefact_kind is odg.model.ArtefactKind.SOURCE:
            return ocm.iter.SourceNode(
                path=(ocm.iter.NodePathEntry(component),),
                source=a,
            )
        else:
            raise RuntimeError('this line should never be reached')

    if not absent_ok:
        raise ValueError(f'could not find OCM node for {artefact=}')


def find_artefact_node(
    artefact_nodes: collections.abc.Sequence[ocm.iter.ArtefactNode],
    artefact_name: str = None,
    artefact_version: str = None,
    artefact_type: str = None,
    artefact_extra_id: dict = None,
    absent_ok: bool = False,
) -> ocm.iter.ArtefactNode | None:
    for artefact_node in artefact_nodes:
        if artefact_name is not None and artefact_node.artefact.name != artefact_name:
            continue

        if artefact_version is not None and artefact_node.artefact.version != artefact_version:
            continue

        if artefact_type is not None and artefact_node.artefact.type != artefact_type:
            continue

        if (
            artefact_extra_id is not None
            and odg.model.normalise_artefact_extra_id(artefact_node.artefact.extraIdentity)
            != odg.model.normalise_artefact_extra_id(artefact_extra_id)  # noqa: E501
        ):
            continue

        return artefact_node

    else:
        if absent_ok:
            return None

        raise ValueError(
            f'no ocm node found for {artefact_name=} {artefact_version=} \
                         {artefact_type=} {artefact_extra_id=}',
        )


async def raw_component_descriptor_from_oci_async(
    component_id: ocm.ComponentIdentity,
    ocm_repos: collections.abc.Iterable[ocm.OciOcmRepository | str],
    oci_client: oci.client_async.Client,
    absent_ok: bool = False,
) -> str | None:
    for ocm_repo in ocm_repos:
        if isinstance(ocm_repo, str):
            ocm_repo = ocm.OciOcmRepository(
                baseUrl=ocm_repo,
            )

        if not isinstance(ocm_repo, ocm.OciOcmRepository):
            raise NotImplementedError(ocm_repo)

        target_ref = ocm_repo.component_version_oci_ref(component_id)

        manifest = await oci_client.manifest(
            image_reference=target_ref,
            absent_ok=True,
            accept=f'{oci.model.OCI_MANIFEST_SCHEMA_V2_MIME}, {oci.model.OCI_IMAGE_INDEX_MIME}',
        )

        if not manifest:
            continue

        if manifest.mediaType == oci.model.OCI_IMAGE_INDEX_MIME:
            digest = ocm.oci.find_component_descriptor_manifest_digest(manifest)

            manifest = await oci_client.manifest(
                image_reference=oci.model.OciImageReference(target_ref).with_tag(digest),
                accept=oci.model.OCI_MANIFEST_SCHEMA_V2_MIME,
            )

        break
    else:
        if absent_ok:
            return None
        raise oci.model.OciImageNotFoundException

    try:
        cfg_blob = await oci_client.blob(
            image_reference=target_ref,
            digest=manifest.config.digest,
        )
        cfg_dict = await cfg_blob.json(content_type='application/octet-stream')
        cfg = dacite.from_dict(
            data_class=ocm.oci.ComponentDescriptorOciCfg,
            data=cfg_dict,
        )
        layer_digest = cfg.componentDescriptorLayer.digest
        layer_mimetype = cfg.componentDescriptorLayer.mediaType
    except Exception as e:
        logger.warning(
            f'Failed to parse or retrieve component-descriptor-cfg: {e=}. '
            'falling back to single-layer',
        )

        # by contract, there must be exactly one layer (tar w/ component-descriptor)
        if (layers_count := len(manifest.layers)) != 1:
            logger.warning(f'XXX unexpected amount of {layers_count=}')

        layer_digest = manifest.layers[0].digest
        layer_mimetype = manifest.layers[0].mediaType

    blob = await oci_client.blob(
        image_reference=target_ref,
        digest=layer_digest,
    )
    component_descriptor_blob = await blob.content.read()

    if '+tar' in layer_mimetype:
        try:
            with tarfile.open(fileobj=io.BytesIO(component_descriptor_blob), mode='r') as tf:
                component_descriptor_info = tf.getmember(ocm.oci.component_descriptor_fname)
                component_descriptor_blob = tf.extractfile(component_descriptor_info).read()
        except tarfile.ReadError as tre:
            tre.add_note(f'{component_id=}')
            raise tre

    return component_descriptor_blob.decode()
