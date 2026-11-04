import itertools
import logging
import os
import uuid
from collections.abc import Generator

import pytest
import sqlalchemy

import migrations


logger = logging.getLogger(__name__)

# deliverydb's session factories cache engines by (pool_size, max_overflow, pool_timeout)
# only, NOT by URL — per-test databases need distinct pool sizes or tests share an engine
# pointing at the first test's (by-then-dropped) database
_pool_size_counter = itertools.count(start=100)

POSTGRES_IMAGE = os.environ.get('ODG_TEST_POSTGRES_IMAGE', 'postgres:16')
POSTGRES_USER = os.environ.get('ODG_TEST_DB_USER', 'odg-user')
POSTGRES_PASSWORD = os.environ.get('ODG_TEST_DB_PASSWORD', 'changeme')
POSTGRES_DB = os.environ.get('ODG_TEST_DB_NAME', 'postgres')

# any connectable DSN works (the server is throwaway); alembic reads it from `-x db_url=`,
# see migrations/env.py. `_db_dsn`/`db_dsn` hand out one database per fixture consumer.
BOOTSTRAP_DB_DSN = 'postgresql+psycopg://localhost/postgres'


def _plain_dsn(dsn: str, dbname: str | None = None) -> str:
    """SQLAlchemy-URL DSN -> libpq DSN (`postgresql://...`) as psycopg expects."""
    return (
        sqlalchemy.engine.make_url(dsn)
        .set(
            drivername='postgresql',
            **({'database': dbname} if dbname else {}),
        )
        .render_as_string(hide_password=False)
    )


def _admin_connection(admin_dsn: str):
    # autocommit: CREATE/DROP DATABASE cannot run inside a transaction
    import psycopg

    return psycopg.connect(admin_dsn, autocommit=True)


@pytest.fixture(scope='session')
def postgres_container_dsn() -> Generator[str, None, None]:
    """
    Session-scoped throwaway PostgreSQL (testcontainers). Yields the server-level
    SQLAlchemy DSN (`postgresql+psycopg://.../postgres`). One container per test
    session; databases are created per test via `db_dsn`.
    """
    from testcontainers.community.postgres import PostgresContainer

    container = PostgresContainer(
        image=POSTGRES_IMAGE,
        username=POSTGRES_USER,
        password=POSTGRES_PASSWORD,
        dbname=POSTGRES_DB,
        # postgres needs ≥256 MB of /dev/shm for shared_buffers; the Docker default
        # of 64 MB can OOM-kill (exit 137) the server under load
        shm_size='256m',
    ).start()

    # testcontainers' get_connection_url emits a psycopg2 driver URL; the project
    # pins psycopg v3
    dsn = (
        sqlalchemy.engine.make_url(container.get_connection_url())
        .set(
            drivername='postgresql+psycopg',
        )
        .render_as_string(hide_password=False)
    )

    engine = sqlalchemy.create_engine(dsn)
    with engine.connect() as connection:
        connection.execute(sqlalchemy.text('select 1'))
    engine.dispose()

    try:
        yield dsn
    finally:
        container.stop()


@pytest.fixture
def _db_dsn(postgres_container_dsn: str) -> Generator[str, None, None]:
    """
    Per-test fresh, empty database on the session's container. Yields its
    SQLAlchemy DSN; no schema is created (see `db_dsn` for a migrated one).
    """
    admin_url = sqlalchemy.engine.make_url(postgres_container_dsn)
    dbname = f'test_{uuid.uuid4().hex}'

    with _admin_connection(_plain_dsn(postgres_container_dsn)) as connection:
        connection.execute(f'create database {dbname}')

    try:
        yield admin_url.set(database=dbname).render_as_string(hide_password=False)
    finally:
        with _admin_connection(_plain_dsn(postgres_container_dsn)) as connection:
            # force: leftover connections from a failed test would block the drop
            connection.execute(f'drop database {dbname} with (force)')


@pytest.fixture
def db_dsn(_db_dsn: str) -> str:
    """
    Per-test database with the full ODG schema: yields the DSN after running
    `alembic upgrade head` (migrations/env.py). Use for tests against
    `deliverydb` queries that expect the productive schema.
    """
    from alembic.config import main as alembic_main

    logger.info('running migrations for %s', _db_dsn)
    alembic_main(argv=['-c', migrations.ini_path, '-x', f'db_url={_db_dsn}', 'upgrade', 'head'])

    return _db_dsn


@pytest.fixture
def db_session(db_dsn: str) -> Generator[sqlalchemy.orm.Session, None, None]:
    """
    Productive `sqlalchemy.orm.Session` against the per-test migrated database.
    Handles session close + engine disposal; the engine cache (see above) is
    sidestepped with a unique per-test pool size.
    """
    import deliverydb

    session = deliverydb.sqlalchemy_session(
        db_url=db_dsn,
        pool_size=next(_pool_size_counter),
        max_overflow=0,
    )
    try:
        yield session
    finally:
        session.close()
        session.get_bind().dispose()
