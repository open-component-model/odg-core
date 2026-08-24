import dataclasses
import json
import logging
import os
import subprocess
import tarfile
import tempfile

import ocm_util
import scanner_utils.orchestrator

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class TrivyScanner(scanner_utils.orchestrator.Scanner):
    def scan_oci_image(self, image_reference: str) -> dict:
        logger.debug(f'trivy image {image_reference!r}')
        return _run_trivy('image', [image_reference])

    def scan_oci_image_archive(self, path: str, blob: ocm_util.BlobDescriptor) -> dict:
        logger.debug(f'trivy image --input {path!r}')
        return _run_trivy('image', ['--input', path])

    def scan_file(self, path: str, blob: ocm_util.BlobDescriptor, is_tar: bool) -> dict:
        media_type = blob.media_type or ''
        if is_tar:
            with tempfile.TemporaryDirectory() as tmp_dir:
                logger.debug(f'extracting {path!r} (mediaType={media_type!r}) to {tmp_dir!r}')
                with tarfile.open(path) as tf:
                    tf.extractall(tmp_dir, filter='data')
                return _run_trivy('fs', [tmp_dir])
        logger.debug(f'trivy fs {path!r} (mediaType={media_type!r})')
        return _run_trivy('fs', [path])

    def scan_sbom(self, data: dict) -> dict:
        with tempfile.NamedTemporaryFile(suffix='.json', mode='w', delete=False) as f:
            json.dump(data, f)
            tmp_path = f.name
        logger.debug(f'scanning SBOM from {tmp_path!r}')
        try:
            return _run_trivy('sbom', [tmp_path])
        finally:
            os.unlink(tmp_path)


def _run_trivy(subcommand: str, args: list[str], timeout: int = 600) -> dict:
    result = subprocess.run(
        ['trivy', subcommand, '--format', 'cyclonedx', '--scanners', 'vuln', '--quiet'] + args,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    if result.returncode != 0:
        logger.error(
            f'trivy {subcommand} failed (exit {result.returncode}):\n{result.stderr.decode()}'
        )
        result.check_returncode()
    cyclonedx = json.loads(result.stdout)
    logger.debug(
        f'trivy {subcommand} returned {len(cyclonedx.get("vulnerabilities") or [])} CVE(s) '
        f'across {len(cyclonedx.get("components") or [])} component(s)',
    )
    return cyclonedx
