"""
Testcontainers-based ODG delivery-service container for perf/integration test scripts.

Starts the delivery-service image wired to an already-running PostgresContainer,
with secrets and config mounted from the local repo tree.

Usage:
    with PostgresContainer() as pg:
        with OdgCoreContainer(db_url=pg.url) as odg:
            odg.wait_ready()
            # run tests against odg.base_url
"""

import logging
import os
import pathlib
import subprocess
import tempfile
import threading
import time

import requests

logger = logging.getLogger(__name__)

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
_SECRETS_DIR = os.path.join(_REPO_ROOT, 'src', 'secrets')
_CFG_DIR = os.path.join(_REPO_ROOT, 'src', 'odg')


def _default_image() -> str:
    version = open(os.path.join(_REPO_ROOT, 'VERSION')).read().strip().split('-')[0]
    return f'odg-core:{version}-debug'


_CFG_FILES = {
    'extensions_cfg': ('EXTENSIONS_CFG_PATH', 'extensions_cfg.yaml'),
    'findings_cfg': ('FINDINGS_CFG_PATH', 'findings_cfg.yaml'),
    'ocm_repo_mappings': ('OCM_REPO_MAPPINGS_PATH', 'ocm_repo_mappings.yaml'),
    'profiles': ('PROFILES_PATH', 'profiles.yaml'),
}


class OdgCoreContainer:
    def __init__(
        self,
        db_url: str,
        image: str | None = None,
        secrets_dir: str = _SECRETS_DIR,
        shortcut_auth: bool = True,
        memory_limit: str = '6g',
        memray: bool = False,
    ):
        self._image = image or _default_image()
        self._db_url = db_url
        self._secrets_dir = secrets_dir
        self._shortcut_auth = shortcut_auth
        self._memory_limit = memory_limit
        self._memray = memray
        self._container: object | None = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        self.stop()

    @property
    def base_url(self) -> str:
        port = self._container.get_exposed_port(5000) if self._container else None
        return f'http://localhost:{port}'

    @property
    def container_name(self) -> str:
        return self._container.get_wrapped_container().name if self._container else None

    def start(self):
        from testcontainers.core.container import DockerContainer

        container = DockerContainer(self._image)
        container.with_bind_ports(5000, None)
        container.with_kwargs(
            mem_limit=self._memory_limit,
            extra_hosts={'host.docker.internal': 'host-gateway'},
        )

        # db_url uses localhost from the host's perspective; rewrite for in-container use
        db_url = self._db_url.replace('localhost', 'host.docker.internal')

        container.with_volume_mapping(self._secrets_dir, '/secrets', 'ro')
        container.with_env('SECRET_FACTORY_PATH', '/secrets')

        for key, (env_var, filename) in _CFG_FILES.items():
            src = os.path.join(_CFG_DIR, filename)
            if os.path.isfile(src):
                container.with_volume_mapping(src, f'/cfg/{key}', 'ro')
                container.with_env(env_var, f'/cfg/{key}')

        cmd = ['python3', '-m', 'app', '--productive', '--delivery-db-url', db_url]
        if self._shortcut_auth:
            cmd.append('--shortcut-auth')
        if self._memray:
            # wrap the entire app under memray; attach is not supported on Alpine/musl
            cmd = [
                'python3',
                '-m',
                'memray',
                'run',
                '--output',
                '/tmp/memray.bin',
                '--force',
                '-m',
            ] + cmd[2:]
        container.with_command(' '.join(cmd))

        container.start()
        self._container = container
        logger.info(f'ODG delivery-service started at {self.base_url}')

    def stop(self):
        if self._container:
            self._container.stop()
            self._container = None
            logger.info('ODG delivery-service container stopped')

    def wait_ready(self, timeout: int = 60):
        """Poll /ready until the service responds 200."""
        url = f'{self.base_url}/ready'
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            try:
                if requests.get(url, timeout=2).ok:
                    logger.info(f'ODG /ready OK at {self.base_url}')
                    return
            except requests.RequestException:
                pass
            time.sleep(2)

        path = self.dump_logs_to_file(pathlib.Path(tempfile.mkdtemp()) / 'odg-container.log')
        logger.info(f'container log → {path}')
        raise TimeoutError(f'ODG delivery-service not ready after {timeout}s')

    # ── logs ──────────────────────────────────────────────────────────────────

    def dump_logs_to_file(self, path: pathlib.Path, tail: int = 500) -> pathlib.Path:
        """Write the last *tail* lines of the container log to *path*. Returns path."""
        if not self._container:
            return path
        result = subprocess.run(
            ['docker', 'logs', '--tail', str(tail), self.container_name],
            capture_output=True,
            text=True,
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text((result.stdout + result.stderr).strip())
        print(f'Wrote container log to {path}')
        return path

    # ── memray ────────────────────────────────────────────────────────────────
    # memray wraps the entire process from start (pass memray=True to __init__).
    # collect_memray() copies the capture out at any point during the run.

    def collect_memray(
        self, out_dir: pathlib.Path, filename: str = 'memray.bin',
    ) -> pathlib.Path | None:
        """Copy the whole-run memray capture to *out_dir*/*filename*. Returns local path or None."""
        if not self._memray:
            logger.warning('collect_memray() called but container was not started with memray=True')
            return None
        dest = out_dir / filename
        result = subprocess.run(
            ['docker', 'cp', f'{self.container_name}:/tmp/memray.bin', str(dest)],
            capture_output=True,
        )
        if result.returncode != 0:
            logger.warning(f'collect_memray failed: {result.stderr.decode().strip()}')
            return None
        logger.info(f'memray capture → {dest}')
        return dest

    # ── py-spy ────────────────────────────────────────────────────────────────
    # py-spy is on-demand: start_pyspy() begins sampling, stop_pyspy() stops and
    # collects. Can be called multiple times to bracket specific phases.

    def start_pyspy(self, rate: int = 100) -> None:
        """Start py-spy sampling PID 1 in a background thread."""

        def _record():
            try:
                self._exec(
                    'py-spy',
                    'record',
                    '--pid',
                    '1',
                    '--output',
                    '/tmp/pyspy.json',
                    '--rate',
                    str(rate),
                    '--nonblocking',
                    '--format',
                    'speedscope',
                )
            except subprocess.CalledProcessError as exc:
                if exc.returncode != 130:  # 130 = SIGINT, expected on stop_pyspy
                    logger.warning(f'py-spy record exited unexpectedly: {exc}')

        self._pyspy_thread = threading.Thread(target=_record, daemon=True)
        self._pyspy_thread.start()
        logger.info('py-spy started')

    def stop_pyspy(self, out_dir: pathlib.Path, filename: str = 'pyspy.json') -> pathlib.Path | None:
        """Stop py-spy and copy the capture to *out_dir*/*filename*. Returns local path or None."""
        try:
            self._exec('sh', '-c', 'kill -INT $(pgrep -f "py-spy record") 2>/dev/null || true')
        except subprocess.CalledProcessError as exc:
            logger.warning(f'py-spy stop signal failed: {exc}')
        if hasattr(self, '_pyspy_thread'):
            self._pyspy_thread.join(timeout=30)
        dest = out_dir / filename
        result = subprocess.run(
            ['docker', 'cp', f'{self.container_name}:/tmp/pyspy.json', str(dest)],
            capture_output=True,
        )
        if result.returncode != 0:
            logger.warning(f'stop_pyspy failed: {result.stderr.decode().strip()}')
            return None
        logger.info(f'py-spy capture → {dest}')
        return dest

    # ── internals ─────────────────────────────────────────────────────────────

    def _exec(self, *args: str) -> str:
        result = subprocess.run(
            ['docker', 'exec', self.container_name, *args],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout
