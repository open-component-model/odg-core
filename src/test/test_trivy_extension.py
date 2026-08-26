"""
Unit tests for TrivyScanner.

Mock mode (default, TRIVY_USE_MOCK=true): _run_trivy and tarfile.open are patched, so no
trivy binary or real files are needed. Pre-recorded CycloneDX output is returned from
_MOCK_STDOUT. Fast.

Real mode (TRIVY_USE_MOCK=false): calls the actual trivy binary against real fixtures cached
under /tmp/trivy-test-fixtures/ (downloaded/created on first run). Use this to verify scanner
behaviour, to refresh _MOCK_STDOUT after a scanner upgrade or when implementing/updating CLI params.
"""

import json
import os
import subprocess
import tarfile
import unittest.mock
import urllib.request

import pytest

import ocm_util
import secret_mgmt.oci_registry
import trivy_extension.scanner

_FIXTURE_DIR = '/tmp/trivy-test-fixtures'
_USE_MOCK = os.environ.get('TRIVY_USE_MOCK', 'true').lower() != 'false'

# Pre-recorded CycloneDX output per trivy subcommand (minimal: empty components, 1 vuln).
# To regenerate: run with TRIVY_USE_MOCK=false and paste trimmed output here.
_MOCK_STDOUT: dict[str, bytes] = {
    'sbom': (
        b'{"bomFormat":"CycloneDX","components":[],'  # this was trimmed, all components removed
        b'"vulnerabilities":[{"id":"CVE-2020-28500"}]}'  # this was trimmed, CVEs + details removed
    ),
    'rootfs': (
        b'{"bomFormat":"CycloneDX","components":[],"vulnerabilities":[{"id":"CVE-2022-1705"}]}'
    ),
    'image': (
        b'{"bomFormat":"CycloneDX","components":[],"vulnerabilities":[{"id":"CVE-2005-2541"}]}'
    ),
}


def _mock_run_trivy(subcommand: str, args: list[str], **kwargs) -> dict:
    if subcommand not in _MOCK_STDOUT:
        pytest.skip(f'no mock data for trivy {subcommand} — run with TRIVY_USE_MOCK=false')
    return json.loads(_MOCK_STDOUT[subcommand])


@pytest.fixture
def mock_scanner():
    if not _USE_MOCK:
        yield
        return
    mock_tar = unittest.mock.MagicMock()
    mock_tar.__enter__ = unittest.mock.Mock(return_value=mock_tar)
    mock_tar.__exit__ = unittest.mock.Mock(return_value=False)
    with (
        unittest.mock.patch('trivy_extension.scanner._run_trivy', side_effect=_mock_run_trivy),
        unittest.mock.patch('trivy_extension.scanner.tarfile.open', return_value=mock_tar),
    ):
        yield


@pytest.fixture
def scanner():
    return trivy_extension.scanner.TrivyScanner()


def _blob(media_type: str | None = None) -> ocm_util.BlobDescriptor:
    return ocm_util.BlobDescriptor(content=iter([]), size=0, media_type=media_type)


@pytest.mark.usefixtures('mock_scanner')
class TestScanSbom:
    """Passes a minimal CycloneDX SBOM with a known-CVE purl (lodash 4.17.20) to scan_sbom."""

    _SBOM = {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.4',
        'components': [
            {
                'bom-ref': 'pkg:npm/lodash@4.17.20',
                'type': 'library',
                'name': 'lodash',
                'version': '4.17.20',
                'purl': 'pkg:npm/lodash@4.17.20',
            },
        ],
    }

    def test_finds_vulnerabilities(self, scanner):
        result = scanner.scan_sbom(self._SBOM)
        assert result.get('bomFormat') == 'CycloneDX'
        assert len(result.get('vulnerabilities') or []) >= 1, 'expected CVE for lodash 4.17.20'


@pytest.mark.usefixtures('mock_scanner')
class TestScanFile:
    """Scans kubectl v1.24.0 (Go binary with known CVEs) as a plain file and as a .tar archive."""

    _KUBECTL_PATH = os.path.join(_FIXTURE_DIR, 'kubectl')
    _KUBECTL_TAR_PATH = os.path.join(_FIXTURE_DIR, 'kubectl.tar')

    @pytest.fixture(scope='session')
    def kubectl_binary(self):
        if not _USE_MOCK:
            os.makedirs(_FIXTURE_DIR, exist_ok=True)
            if not os.path.exists(self._KUBECTL_PATH):
                urllib.request.urlretrieve(
                    'https://dl.k8s.io/release/v1.24.0/bin/linux/amd64/kubectl',
                    self._KUBECTL_PATH,
                )
                os.chmod(self._KUBECTL_PATH, 0o755)
        return self._KUBECTL_PATH

    @pytest.fixture(scope='session')
    def kubectl_tar(self, kubectl_binary):
        if not _USE_MOCK:
            if not os.path.exists(self._KUBECTL_TAR_PATH):
                with tarfile.open(self._KUBECTL_TAR_PATH, 'w') as tf:
                    tf.add(kubectl_binary, arcname='kubectl')
        return self._KUBECTL_TAR_PATH

    def test_binary_plain_file_finds_vulnerabilities(self, scanner, kubectl_binary):
        result = scanner.scan_file(kubectl_binary, _blob('application/octet-stream'), is_tar=False)
        assert result.get('bomFormat') == 'CycloneDX'
        assert len(result.get('vulnerabilities') or []) >= 1, 'expected CVE in kubectl v1.24.0'

    def test_binary_in_tar_finds_vulnerabilities(self, scanner, kubectl_tar):
        result = scanner.scan_file(kubectl_tar, _blob('application/x-tar'), is_tar=True)
        assert result.get('bomFormat') == 'CycloneDX'
        assert len(result.get('vulnerabilities') or []) >= 1, 'expected CVE in kubectl v1.24.0 (tar)'

    def test_nonexistent_path_raises(self, scanner):
        with unittest.mock.patch(
            'trivy_extension.scanner._run_trivy',
            side_effect=subprocess.CalledProcessError(1, 'trivy'),
        ):
            with pytest.raises(subprocess.CalledProcessError):
                scanner.scan_file('/nonexistent/binary', _blob(), is_tar=False)


@pytest.mark.usefixtures('mock_scanner')
class TestScanOciImage:
    """Scans docker.io/library/python:3.9-slim by registry reference."""

    _IMAGE = 'docker.io/library/python:3.9-slim'

    def test_finds_vulnerabilities(self, scanner):
        result = scanner.scan_oci_image(self._IMAGE)
        assert result.get('bomFormat') == 'CycloneDX'
        assert len(result.get('vulnerabilities') or []) >= 1

    def test_nonexistent_image_raises(self, scanner):
        with unittest.mock.patch(
            'trivy_extension.scanner._run_trivy',
            side_effect=subprocess.CalledProcessError(1, 'trivy'),
        ):
            with pytest.raises(subprocess.CalledProcessError):
                scanner.scan_oci_image('localhost/nonexistent:doesnotexist')


class TestScanOciImagePrivateRegistry:
    """Verifies that scan_oci_image passes --username and TRIVY_PASSWORD to the trivy subprocess."""

    def test_private_registry_passes_credentials(self, scanner):
        oci_cfg = secret_mgmt.oci_registry.OciRegistry(
            username='myuser',
            password='mypass',
            image_reference_prefixes=['private.registry.example.com'],
        )
        mock_secret_factory = unittest.mock.MagicMock()
        fake_result = unittest.mock.MagicMock()
        fake_result.returncode = 0
        fake_result.stdout = _MOCK_STDOUT['image']

        with (
            unittest.mock.patch(
                'trivy_extension.scanner.subprocess.run',
                return_value=fake_result,
            ) as mock_run,
            unittest.mock.patch(
                'secret_mgmt.oci_registry.find_cfg',
                return_value=oci_cfg,
            ),
        ):
            scanner.scan_oci_image(
                'private.registry.example.com/myimage:latest',
                secret_factory=mock_secret_factory,
            )

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        env = mock_run.call_args[1].get('env') or mock_run.call_args.kwargs.get('env')
        assert '--username' in cmd
        assert cmd[cmd.index('--username') + 1] == 'myuser'
        assert env is not None and env.get('TRIVY_PASSWORD') == 'mypass'


@pytest.mark.usefixtures('mock_scanner')
class TestScanOciImageArchive:
    """Scans python:3.9-slim pulled as an OCI layout dir via oras copy --to-oci-layout."""

    _IMAGE = 'docker.io/library/python:3.9-slim'
    _OCI_LAYOUT = os.path.join(_FIXTURE_DIR, 'python-3.9-slim-oci-layout')

    @pytest.fixture(scope='session')
    def oci_layout(self):
        if not _USE_MOCK:
            os.makedirs(_FIXTURE_DIR, exist_ok=True)
            if not os.path.exists(self._OCI_LAYOUT):
                subprocess.run(
                    ['oras', 'copy', '--to-oci-layout', self._IMAGE, f'{self._OCI_LAYOUT}:latest'],
                    check=True,
                )
        return self._OCI_LAYOUT

    def test_finds_vulnerabilities(self, scanner, oci_layout):
        result = scanner.scan_oci_image_archive(
            oci_layout,
            _blob('application/vnd.oci.image.manifest.v1+tar'),
        )
        assert result.get('bomFormat') == 'CycloneDX'
        assert len(result.get('vulnerabilities') or []) >= 1
