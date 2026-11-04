import logging
import os
import pathlib
import sys
import urllib.parse
from collections.abc import Generator

_TEST_DIR = pathlib.Path(__file__).parent.parent

sys.path.insert(0, str(_TEST_DIR))

import psycopg  # noqa: E402
import pytest  # noqa: E402

import odg_client as _odg_client  # noqa: E402
from targets import (  # noqa: E402
    WriteTargets,
    query_compliance_targets,
    query_components,
    query_write_targets,
)
from utils.snapshot import Snapshot  # noqa: E402
from utils.testcontainer_odg import OdgCoreContainer  # noqa: E402
from utils.testcontainer_postgres import PostgresContainer  # noqa: E402

_PATCH_INDEXES_DDL = """
    DROP INDEX IF EXISTS ix_artefact_metadata_component_name;
    CREATE INDEX IF NOT EXISTS ix_artefact_metadata_findings_lookup
        ON artefact_metadata (component_name, component_version, type, datasource);
    CREATE INDEX IF NOT EXISTS ix_artefact_metadata_rescorings_lookup
        ON artefact_metadata (type, referenced_type, component_name);
    CREATE INDEX IF NOT EXISTS ix_artefact_metadata_global_scope
        ON artefact_metadata (component_name, artefact_name, type, datasource)
        WHERE component_version IS NULL;
    ALTER TABLE artefact_metadata
        ALTER COLUMN data TYPE JSONB USING data::jsonb,
        ALTER COLUMN meta TYPE JSONB USING meta::jsonb,
        ALTER COLUMN artefact_extra_id TYPE JSONB USING artefact_extra_id::jsonb;
    CREATE INDEX IF NOT EXISTS ix_artefact_metadata_severity
        ON artefact_metadata
        (component_name, component_version, type, datasource, (data->>'severity'));
    ANALYZE artefact_metadata;
"""

logger = logging.getLogger(__name__)

# suppress per-request anonymous-auth noise from the ODG client
logging.getLogger('odg_client').setLevel(logging.WARNING)

ODG_VERSION = (_TEST_DIR.parent / 'VERSION').read_text().strip().split('-')[0]
ODG_DB_IMAGE = os.getenv('ODG_DB_IMAGE', 'odg-test-db:latest')
ODG_CORE_IMAGE = os.getenv('ODG_CORE_IMAGE', f'odg-core:{ODG_VERSION}-debug')


def pytest_addoption(parser):
    parser.addoption(
        '--profile',
        nargs='?',
        const='all',
        default=None,
        choices=['pyspy', 'memray', 'all'],
        help='Enable profiling: --profile (both), --profile pyspy, --profile memray',
    )
    parser.addoption(
        '--patch-indexes',
        action='store_true',
        default=False,
        help='Migrate JSON→JSONB, targeted indexes + severity expression index before each test.',
    )


def _apply_index_patch(pg: PostgresContainer) -> None:
    parsed = urllib.parse.urlparse(pg.url)
    with psycopg.connect(
        host=parsed.hostname,
        port=parsed.port,
        user=parsed.username,
        password=parsed.password,
        dbname=parsed.path.lstrip('/'),
        autocommit=True,
    ) as conn:
        conn.execute(_PATCH_INDEXES_DDL)
    logger.info('index patch applied')


def make_odg_container(pg, profile: str | None, **kwargs) -> OdgCoreContainer:
    """Return a configured OdgCoreContainer (not yet started)."""
    return OdgCoreContainer(image=ODG_CORE_IMAGE, db_url=pg.url, profile=profile, **kwargs)


def make_odg_client(base_url: str) -> _odg_client.DeliveryServiceClient:
    """Return an anonymous ODG client for *base_url*."""
    routes = _odg_client.DeliveryServiceRoutes(base_url=base_url)
    return _odg_client.DeliveryServiceClient.for_github(routes=routes)


@pytest.fixture
def odg_stack(request):
    """Fresh OdgCoreContainer per test, sharing the session-scoped Postgres."""
    profile = request.config.getoption('--profile')
    patch_indexes = request.config.getoption('--patch-indexes')
    with PostgresContainer(image=ODG_DB_IMAGE) as pg:
        if patch_indexes:
            _apply_index_patch(pg)
        with make_odg_container(pg, profile) as odg:
            odg.wait_ready()
            yield odg, pg


@pytest.fixture
def odg_client(odg_stack):
    odg, _ = odg_stack
    return make_odg_client(odg.base_url)


@pytest.fixture
def write_targets(odg_stack) -> WriteTargets:
    """Heaviest artefact_metadata row at each scope level, queried live from the DB."""
    _, pg = odg_stack
    return query_write_targets(pg)


@pytest.fixture
def compliance_targets(odg_stack):
    """(gardenlinux, gardener) ComponentArtefactIds with latest version from DB."""
    _, pg = odg_stack
    return query_compliance_targets(pg)


@pytest.fixture
def components(odg_stack):
    """Top components by global-scope row count, queried live from DB."""
    _, pg = odg_stack
    return query_components(pg)


@pytest.fixture
def snapshot(request) -> Generator[callable, None, None]:
    fixtures_dir = pathlib.Path(request.fspath).parent / 'snapshots'

    def _snapshot(name: str) -> Snapshot:
        return Snapshot(fixtures_dir / name)

    yield _snapshot
