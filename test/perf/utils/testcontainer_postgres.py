"""
Testcontainers-based PostgreSQL setup for test scripts.

Starts a postgres:16 container, waits for it to be ready, and optionally
restores a pg_dump file (custom format) into it.

Usage:
    pg = PostgresContainer()
    pg.start()                          # plain empty DB
    pg.restore('test/dev_backup.dump')  # optional: restore a dump
    print(pg.url)                       # sqlalchemy URL for delivery-service
    pg.stop()

    # or as a context manager:
    with PostgresContainer() as pg:
        pg.restore('test/dev_backup.dump')
        ...
"""

import logging
import subprocess
import time

logger = logging.getLogger(__name__)

_IMAGE = 'postgres:16'
_DB_USER = 'postgres'
_DB_PASSWORD = 'postgres'
_DB_NAME = 'postgres'


class PostgresContainer:
    def __init__(self):
        self._container: object | None = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        self.stop()

    @property
    def url(self) -> str:
        port = self._container.get_exposed_port(5432) if self._container else None
        return f'postgresql+psycopg://{_DB_USER}:{_DB_PASSWORD}@localhost:{port}/{_DB_NAME}'

    def start(self):
        from testcontainers.community.postgres import PostgresContainer as TC

        self._container = TC(
            image=_IMAGE,
            username=_DB_USER,
            password=_DB_PASSWORD,
            dbname=_DB_NAME,
        )
        self._container.start()
        self._wait_ready()
        logger.info(f'PostgreSQL ready at {self.url}')

    def stop(self):
        if self._container:
            self._container.stop()
            self._container = None
            logger.info('PostgreSQL container stopped')

    def restore(self, dump_path: str):
        """Restore a pg_dump custom-format file into the running container."""
        if not self._container:
            raise RuntimeError('container is not running')

        container_id = self._container.get_wrapped_container().id

        logger.info(f'Copying {dump_path} into container...')
        subprocess.run(
            ['docker', 'cp', dump_path, f'{container_id}:/tmp/restore.dump'],
            check=True,
        )

        logger.info('Restoring dump...')
        subprocess.run(
            [
                'docker',
                'exec',
                container_id,
                'pg_restore',
                '--username',
                _DB_USER,
                '--dbname',
                _DB_NAME,
                '--no-owner',
                '--no-privileges',
                '--exit-on-error',
                '/tmp/restore.dump',
            ],
            check=True,
        )
        logger.info('Restore complete')

    def _wait_ready(self, timeout: int = 30):
        if not self._container:
            raise RuntimeError('container is not running')

        container_id = self._container.get_wrapped_container().id
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            result = subprocess.run(
                ['docker', 'exec', container_id, 'pg_isready', '-U', _DB_USER],
                capture_output=True,
            )
            if result.returncode == 0:
                return
            time.sleep(1)

        raise TimeoutError(f'PostgreSQL not ready after {timeout}s')
