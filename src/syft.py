import enum
import logging
import os
import subprocess

import oci.client
import ocm
import tarutil

import ocm_util
import secret_mgmt


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


def generate_raw_sbom_for_artefact(
    component: ocm.Component,
    resource: ocm.Resource,
    secret_factory: secret_mgmt.SecretFactory,
    oci_client: oci.client.Client,
    file_path: str,
    aws_secret_name: str | None = None,
    sbom_output_format: SyftSbomFormat = SyftSbomFormat.CYCLONEDX,
) -> str:
    blob_descriptors_iterator = ocm_util.iter_blob_descriptors(
        component=component,
        access=resource.access,
        oci_client=oci_client,
        secret_factory=secret_factory,
        aws_secret_name=aws_secret_name,
    )

    root = os.path.realpath(file_path)
    os.makedirs(root, exist_ok=True)

    for idx, blob_descriptor in enumerate(blob_descriptors_iterator):
        if ocm_util.is_tar_archive(
            blob_descriptor=blob_descriptor,
            resource=resource,
        ):
            ocm_util.extract_tar_archive_contents(
                data=blob_descriptor.content,
                file_path=file_path,
                tar_filter=tarutil.tar_filter,
            )

        else:
            blob_name = os.path.basename(blob_descriptor.digest or blob_descriptor.name or str(idx))
            with open(os.path.join(file_path, blob_name), 'wb') as file:
                for chunk in blob_descriptor.content:
                    file.write(chunk)

    return run_syft(
        source=file_path,
        output_format=sbom_output_format,
    )
