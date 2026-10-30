"""
Testcontainers-based ODG delivery-service container for perf/integration test scripts.

Starts the delivery-service image wired to an already-running PostgresContainer,
with secrets and config mounted from the local repo tree.

Usage:
    with PostgresContainer() as pg:
        with OdgCoreContainer(db_url=pg.url) as odg:
            odg.wait_ready()
            # run tests against odg.base_url

    # with profiling (pass the --profile pytest flag value directly):
    with OdgCoreContainer(db_url=pg.url, profile=request.config.getoption('--profile')) as odg:
        ...
"""

import logging
import pathlib
import re
import subprocess
import tempfile
import time

import requests
from testcontainers.core.container import DockerContainer

logger = logging.getLogger(__name__)
logging.getLogger('testcontainers.core.waiting_utils').setLevel(logging.WARNING)


class OdgCoreContainer:
    def __init__(
        self,
        image: str,
        db_url: str,
        secrets_dir: pathlib.Path | None = None,
        shortcut_auth: bool = True,
        memory_limit: str = '6g',
        cpu_limit: float = 1.0,
        profile: str | None = None,
        logs_dir: pathlib.Path | None = None,
    ):
        self.image = image
        self.db_url = db_url
        self.secrets_dir = secrets_dir
        self.shortcut_auth = shortcut_auth
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.enable_memray = profile in ('memray', 'all')
        self.enable_pyspy = profile in ('pyspy', 'all')
        self.logs_dir = logs_dir or pathlib.Path(tempfile.mkdtemp())
        self._container: DockerContainer | None = None
        self._port: int | None = None
        self._pyspy_proc: subprocess.Popen | None = None
        self._tmp_secrets: tempfile.TemporaryDirectory | None = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        self.stop()

    @property
    def base_url(self) -> str:
        if self._port is None:
            return 'http://localhost:0'
        return f'http://localhost:{self._port}'

    @property
    def container_name(self) -> str:
        return self._container.get_wrapped_container().name if self._container else None

    def start(self):
        secrets_dir = self.secrets_dir
        if secrets_dir is None:
            self._tmp_secrets = tempfile.TemporaryDirectory()
            secrets_dir = pathlib.Path(self._tmp_secrets.name)

        container = DockerContainer(self.image)
        container.with_bind_ports(5000, None)
        cap_add = ['SYS_PTRACE'] if self.enable_pyspy else []
        container.with_kwargs(
            mem_limit=self.memory_limit,
            nano_cpus=int(self.cpu_limit * 1e9),
            extra_hosts={'host.docker.internal': 'host-gateway'},
            cap_add=cap_add,
        )

        db_url = self.db_url.replace('localhost', 'host.docker.internal')

        container.with_volume_mapping(str(secrets_dir), '/secrets', 'ro')
        container.with_env('SECRET_FACTORY_PATH', '/secrets')
        container.with_volume_mapping(str(self.logs_dir), '/results', 'rw')

        cmd = ['python3', '-m', 'app', '--productive', '--delivery-db-url', db_url]
        if self.shortcut_auth:
            cmd.append('--shortcut-auth')
        if self.enable_memray:
            cmd = [
                'python3',
                '-m',
                'memray',
                'run',
                '--output',
                '/results/memray.bin',
                '--force',
                '-m',
            ] + cmd[2:]
        container.with_command(cmd)

        container.start()
        self._container = container
        self._port = int(container.get_exposed_port(5000))
        logger.info(f'ODG delivery-service started at {self.base_url}')
        if self.enable_pyspy:
            self.start_pyspy()

    def stop(self):
        if self.enable_pyspy:
            self.stop_pyspy()
        self.write_logs_to_file(self.logs_dir / 'odg.log')
        if self.enable_pyspy:
            logger.info(f'py-spy capture → {self.logs_dir / "pyspy.json"}')
        if self.enable_memray:
            logger.info(f'memray capture → {self.logs_dir / "memray.bin"}')
        if self._container:
            # SIGTERM + wait before remove(force=True) so PID 1 can flush output files
            self._container.get_wrapped_container().stop()
            self._container.stop()
            self._container = None
            self._port = None
            logger.info('ODG delivery-service container stopped')
        if self._tmp_secrets:
            self._tmp_secrets.cleanup()
            self._tmp_secrets = None

    def wait_ready(self, timeout: int = 30):
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
            time.sleep(1)

        log_path = self.write_logs_to_file(self.logs_dir / 'odg.log')
        raise TimeoutError(f'ODG delivery-service not ready after {timeout}s — see {log_path}')

    def write_logs_to_file(self, path: pathlib.Path, tail: int = 500) -> pathlib.Path:
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
        logger.info(f'container log → {path}')
        return path

    def start_pyspy(self, rate: int = 100) -> None:
        """Start py-spy sampling PID 1 in a background thread."""
        self._pyspy_proc = subprocess.Popen(
            [
                'docker',
                'exec',
                self.container_name,
                'py-spy',
                'record',
                '--pid',
                '1',
                '--output',
                '/results/pyspy.json',
                '--rate',
                str(rate),
                '--nonblocking',
                '--format',
                'speedscope',
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        logger.info('py-spy started')

    def stop_pyspy(self) -> None:
        """Stop py-spy by signalling it inside the container, then wait for docker exec to exit."""
        if self._pyspy_proc is None:
            return
        # Send SIGINT to py-spy inside the container so it flushes the speedscope JSON.
        # Signalling the host-side `docker exec` PID is not reliable — the signal may not
        # propagate to the process running inside the container namespace.
        try:
            self._exec('sh', '-c', 'kill -INT $(pgrep -f "py-spy record") 2>/dev/null || true')
        except subprocess.CalledProcessError:
            pass
        try:
            self._pyspy_proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self._pyspy_proc.kill()
            self._pyspy_proc.wait()
        stderr = (self._pyspy_proc.stderr.read() or b'').decode().strip()
        if self._pyspy_proc.returncode not in (0, -2, -15) and stderr:
            log_path = self.logs_dir / 'odg.log'
            logger.warning(
                f'py-spy exited with {self._pyspy_proc.returncode}: {stderr} — see {log_path}',
            )

    def read_rss(self) -> dict[str, int]:
        try:
            out = self._exec(
                'sh',
                '-c',
                'grep -E "VmRSS|VmPeak|VmHWM" /proc/1/status; cat /proc/1/smaps_rollup',
            )
            result = {}
            for line in out.splitlines():
                m = re.match(r'(\w+):\s+(\d+)\s+kB', line)
                if m:
                    result[m.group(1)] = int(m.group(2))
            return result
        except subprocess.CalledProcessError as exc:
            logger.warning(f'RSS read failed: {exc}')
            return {}

    def _exec(self, *args: str) -> str:
        result = subprocess.run(
            ['docker', 'exec', self.container_name, *args],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout
