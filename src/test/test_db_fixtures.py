"""
Smoke tests for the testcontainers fixtures in src/test/conftest.py
(`postgres_container_dsn`, `_db_dsn`, `db_dsn`).
"""

import alembic.migration
import psycopg
import sqlalchemy

import deliverydb.model


def _table_names(dsn: str) -> set[str]:
    engine = sqlalchemy.create_engine(dsn)
    with engine.connect() as connection:
        return set(sqlalchemy.inspect(connection).get_table_names())


def test_db_dsn(postgres_container_dsn: str):
    """server-level DSN must be connectable via sqlalchemy and plain psycopg"""
    engine = sqlalchemy.create_engine(postgres_container_dsn)
    with engine.connect() as connection:
        assert connection.execute(sqlalchemy.text('select 1')).scalar() == 1
    engine.dispose()

    plain = (
        sqlalchemy.engine.make_url(postgres_container_dsn)
        .set(
            drivername='postgresql',
        )
        .render_as_string(hide_password=False)
    )
    with psycopg.connect(plain) as connection:
        assert connection.execute('select 1').fetchone()[0] == 1


def test__db_dsn(_db_dsn: str):
    """fresh database: exists, is connectable, and has no tables"""
    assert _table_names(_db_dsn) == set()


def test_db_dsn_migrated(db_dsn: str):
    """migrated database: all model tables exist and alembic sits at head"""
    table_names = _table_names(db_dsn)
    model_tables = set(deliverydb.model.Base.metadata.tables)

    missing = model_tables - table_names
    assert not missing, f'missing tables after migration: {sorted(missing)}'

    engine = sqlalchemy.create_engine(db_dsn)
    with engine.connect() as connection:
        revision = alembic.migration.MigrationContext.configure(
            connection=connection,
        ).get_current_revision()
    engine.dispose()

    assert revision is not None
