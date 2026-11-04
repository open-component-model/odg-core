"""
Tests for `migrations.bootstrap.main`. The third test reproduces the bug from
PR review: a follow-up revision exists on disk but was never applied to the
legacy database, and bootstrap must stamp at the base revision and upgrade
instead of stamping at head.
"""

import os
import pathlib
import sys
import textwrap
from collections.abc import Generator

import pytest
import sqlalchemy

import deliverydb.model
import migrations.bootstrap


@pytest.fixture
def bootstrap_db(
    _db_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[sqlalchemy.Engine, None, None]:
    monkeypatch.setattr(migrations.bootstrap, '_db_url', lambda: _db_dsn)
    # bootstrap must not depend on the env var; a wrong value proves the -x arg wins
    monkeypatch.setenv('DELIVERY_DB_URL', 'postgresql+psycopg://invalid:invalid@invalid:1/invalid')
    engine = sqlalchemy.create_engine(_db_dsn)
    yield engine
    engine.dispose()


def _head(engine: sqlalchemy.Engine) -> str | None:
    return migrations.bootstrap._current_revision(engine)


def test_fresh_database(bootstrap_db: sqlalchemy.Engine):
    assert migrations.bootstrap.main() == 0
    assert _head(bootstrap_db) == migrations.bootstrap._head_revision()


def test_alembic_managed_database_is_idempotent(bootstrap_db: sqlalchemy.Engine):
    assert migrations.bootstrap.main() == 0
    assert migrations.bootstrap.main() == 0
    assert _head(bootstrap_db) == migrations.bootstrap._head_revision()


TEST_REVISION_ID = 'b00t5trap0test'
TEST_MARKER_COLUMN = 'bootstrap_test_marker'

FOLLOWUP_REVISION = textwrap.dedent(f"""
from alembic import op
import sqlalchemy as sa

revision: str = {TEST_REVISION_ID!r}
down_revision: str | None = {'cc90ad81441c'!r}

def schema_upgrade() -> None:
    op.add_column('cache', sa.Column({TEST_MARKER_COLUMN!r}, sa.Integer, nullable=True))

def data_upgrade() -> None:
    pass

def schema_downgrade() -> None:
    op.drop_column('cache', {TEST_MARKER_COLUMN!r})

def data_downgrade() -> None:
    pass

def upgrade() -> None:
    schema_upgrade()
    data_upgrade()

def downgrade() -> None:
    data_downgrade()
    schema_downgrade()
""")


def _run_bootstrap_in_subprocess(dsn: str) -> str:
    """Run bootstrap in a subprocess with a fresh import of the model and a
    fresh scan of `migrations/versions/`."""
    import subprocess  # late import: not needed for the happy-path tests

    result = subprocess.run(
        [
            sys.executable,
            '-c',
            textwrap.dedent(f"""
                import migrations.bootstrap
                migrations.bootstrap._db_url = lambda: {dsn!r}
                assert migrations.bootstrap.main() == 0
            """),
        ],
        capture_output=True,
        text=True,
        env={**os.environ, 'PYTHONPATH': str(pathlib.Path(migrations.__file__).parent.parent)},
    )
    assert result.returncode == 0, result.stderr
    return result.stderr


def test_legacy_database_picks_up_followup_revision(
    bootstrap_db: sqlalchemy.Engine,
):
    """
    A follow-up revision exists; the database was created before it was
    written. Bootstrap must stamp the base revision, upgrade to the new head,
    and the post-check must pass.
    """
    engine = bootstrap_db
    deliverydb.model.Base.metadata.create_all(engine)

    versions_dir = pathlib.Path(migrations.bootstrap.migrations.__file__).parent / 'versions'
    revision_file = versions_dir / f'{TEST_REVISION_ID}_bootstrap_followup.py'
    revision_file.write_text(FOLLOWUP_REVISION)
    try:
        _run_bootstrap_in_subprocess(engine.url.render_as_string(hide_password=False))
    finally:
        if revision_file.exists():
            revision_file.unlink()

    with engine.connect() as connection:
        columns = {c['name'] for c in sqlalchemy.inspect(connection).get_columns('cache')}

    assert TEST_MARKER_COLUMN in columns
    assert _head(engine) == TEST_REVISION_ID
