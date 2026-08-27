import dataclasses
import json
import logging
import os
import subprocess
import tarfile
import tempfile

import ocm_util
import scanner_utils.scanner
import secret_mgmt.oci_registry

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class TrivyScanner(scanner_utils.scanner.Scanner):
    def scan_oci_image(self, image_reference: str, secret_factory=None) -> dict:
        logger.debug(f'Preparing OCI image scan {image_reference!r}')
        extra_args = []
        extra_env = None
        if secret_factory is not None:
            oci_cfg = secret_mgmt.oci_registry.find_cfg(
                secret_factory=secret_factory,
                image_reference=image_reference,
            )
            if oci_cfg is not None:
                extra_args = ['--username', oci_cfg.username]
                extra_env = {'TRIVY_PASSWORD': oci_cfg.password}
        return _run_trivy('image', [*extra_args, image_reference], extra_env=extra_env)

    def scan_oci_image_archive(self, path: str, blob: ocm_util.BlobDescriptor) -> dict:
        try:
            return _run_trivy('image', ['--input', path])
        except scanner_utils.model.ScanError as e:
            if 'unable to initialize archive image' in e.details:
                e.fallback_to_file_scan = True
            raise

    def scan_file(self, path: str, blob: ocm_util.BlobDescriptor, is_tar: bool) -> dict:
        logger.debug(f'Preparing file scan {path!r} (is_tar={is_tar})')
        media_type = blob.media_type or ''
        if is_tar:
            with tempfile.TemporaryDirectory() as tmp_dir:
                logger.debug(f'extracting {path!r} (mediaType={media_type!r}) to {tmp_dir!r}')
                with tarfile.open(path) as tf:
                    tf.extractall(tmp_dir, filter=_data_filter_skip_links)
                return _run_trivy('rootfs', [tmp_dir])
        logger.debug(f'trivy rootfs {path!r} (mediaType={media_type!r})')
        return _run_trivy('rootfs', [path])

    def scan_sbom(self, data: dict) -> dict:
        logger.debug('Preparing SBOM scan')
        with tempfile.NamedTemporaryFile(suffix='.json', mode='w', delete=False) as f:
            json.dump(data, f)
            tmp_path = f.name
        logger.debug(f'scanning SBOM from {tmp_path!r}')
        try:
            return _run_trivy('sbom', [tmp_path])
        finally:
            os.unlink(tmp_path)


def _data_filter_skip_links(member, dest_path):
    """Like tarfile.data_filter but skips absolute/escaping symlinks instead of raising.

    Container image layers commonly contain absolute symlinks (e.g. bin/pidof -> /bin/pidof)
    which are harmless in context but rejected by the strict 'data' filter.
    """
    try:
        return tarfile.data_filter(member, dest_path)
    except tarfile.AbsoluteLinkError, tarfile.LinkOutsideDestinationError:
        return None


def _run_trivy(
    subcommand: str,
    args: list[str],
    timeout: int = 600,
    extra_env: dict | None = None,
) -> dict:
    env = {**os.environ, **extra_env} if extra_env else None
    cmd = ['trivy', subcommand, '--format', 'cyclonedx', '--scanners', 'vuln'] + args
    logger.info(f'Running {" ".join(cmd)!r}')
    result = subprocess.run(
        cmd,
        capture_output=True,
        check=False,
        timeout=timeout,
        env=env,
    )
    stderr = result.stderr.decode()
    if result.returncode != 0:
        logger.error(f'trivy {subcommand} failed (exit {result.returncode}):\n{stderr}')
        raise scanner_utils.model.ScanError(
            f'trivy {subcommand} failed (exit {result.returncode})',
            details=stderr,
        )
    logger.debug(f'trivy {subcommand} RC {result.returncode}')
    for line in stderr.splitlines():
        if '[vulndb]' in line.lower():
            logger.info(line.strip())
        else:
            logger.debug(line.strip())
    cyclonedx = json.loads(result.stdout)
    logger.debug(
        f'trivy {subcommand} returned {len(cyclonedx.get("vulnerabilities") or [])} CVE(s) '
        f'across {len(cyclonedx.get("components") or [])} component(s)',
    )
    return cyclonedx
