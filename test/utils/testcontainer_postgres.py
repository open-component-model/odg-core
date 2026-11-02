"""
Testcontainers-based PostgreSQL setup for test scripts.

Starts a postgres:16 container, waits for it to be ready, and optionally
restores/saves pg_dump snapshots by path.

Usage:
    with PostgresContainer() as pg:
        pg.restore(pathlib.Path('test/backups/baseline'))
        # use pg.url ...
        pg.backup(pathlib.Path('test/backups/after_seed'))
"""

import logging
import pathlib
import os
import subprocess
import time
import urllib.parse
from urllib.parse import quote_plus

import psycopg
from testcontainers.postgres import PostgresContainer as _TC

logger = logging.getLogger(__name__)


class PostgresContainer:
    def __init__(
        self,
        image: str,
        logs_dir: pathlib.Path | None = None,
    ):
        self.image = image
        self.username = os.getenv('ODG_TEST_DB_USER', 'odg-user')
        self.password = os.getenv('ODG_TEST_DB_PASSWORD', 'changeme')
        self.dbname = os.getenv('ODG_TEST_DB_NAME', 'odg-db')
        self.logs_dir = logs_dir
        self._container: _TC | None = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        self.stop()

    @property
    def url(self) -> str:
        port = self._container.get_exposed_port(5432) if self._container else None
        return (
            'postgresql+psycopg://'
            + quote_plus(self.username)
            + ':'
            + quote_plus(self.password)
            + '@localhost:'
            + str(port)
            + '/'
            + quote_plus(self.dbname)
        )

    @property
    def container_name(self) -> str | None:
        return self._container.get_wrapped_container().name if self._container else None

    def wait_ready(self, timeout: int = 30):
        if not self._container:
            raise RuntimeError('container is not running')
        container_id = self._container.get_wrapped_container().id
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = subprocess.run(
                ['docker', 'exec', container_id, 'pg_isready', '-U', self.username],
                capture_output=True,
            )
            if result.returncode == 0:
                return
            time.sleep(0.5)
        raise TimeoutError(f'PostgreSQL not ready after {timeout}s')

    def start(self):
        self._container = _TC(
            image=self.image,
            username=self.username,
            password=self.password,
            dbname=self.dbname,
            # postgres needs ≥256 MB of /dev/shm for shared_buffers; the Docker default
            # of 64 MB causes OOM kill (exit 137) when the server restarts under load.
            shm_size='256m',
        )
        self._container.start()
        self.wait_ready()
        logger.info(f'PostgreSQL ready at {self.url}')

    def stop(self):
        if self.logs_dir:
            self.write_logs_to_file(self.logs_dir / 'postgres.log')
        if self._container:
            self._container.stop()
            self._container = None
            logger.info('PostgreSQL container stopped')

    def exec(self, *args: str) -> str:
        result = subprocess.run(
            ['docker', 'exec', self.container_name, *args],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout

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

    def get_dead_tuples_stats(self, table: str = 'artefact_metadata') -> int:
        """Return n_dead_tup for *table* from pg_stat_user_tables."""
        parsed = urllib.parse.urlparse(self.url)
        with (
            psycopg.connect(
                host=parsed.hostname,
                port=parsed.port,
                user=parsed.username,
                password=parsed.password,
                dbname=parsed.path.lstrip('/'),
            ) as conn,
            conn.cursor() as cur,
        ):
            cur.execute(
                'SELECT n_dead_tup FROM pg_stat_user_tables WHERE relname = %s',
                (table,),
            )
            row = cur.fetchone()
        return row[0] if row else 0
