"""
Canary integration test: start odg-core against an empty DB and hit basic endpoints.

Verifies the whole container setup is healthy — no data seeding required.

Run (from test/perf/):
    uv run pytest canary/ -v
"""

import pathlib

import pytest
import requests

import odg_client

from utils.testcontainer_postgres import PostgresContainer
from utils.testcontainer_odg import OdgCoreContainer
from utils.perf_profiler import PerfProfiler

COMPONENT_NAME = 'github.com/gardener/cc-utils'
_DIR = pathlib.Path(__file__).parent


@pytest.fixture(scope='session')
def odg(request):
    keep = request.config.getoption('--keep-containers')
    if keep:
        import os

        os.environ['TESTCONTAINERS_RYUK_DISABLED'] = 'true'

    with PostgresContainer() as pg:
        with OdgCoreContainer(db_url=pg.url) as odg:
            odg.wait_ready()
            routes = odg_client.DeliveryServiceRoutes(base_url=odg.base_url)
            client = odg_client.DeliveryServiceClient(routes=routes)
            prof = PerfProfiler(odg, results_dir=_DIR / 'results')
            with prof:
                prof.set_test('canary')
                prof.phase('ready')
                yield client
                prof.phase('done')

            if keep:
                import logging

                logging.getLogger(__name__).info(
                    f'--keep-containers set: leaving containers running\n'
                    f'  ODG:      docker exec -it {odg.container_name} sh\n'
                    f'  Postgres: docker exec -it {pg._container.get_wrapped_container().name} sh',
                )


def test_ready(odg):
    res = requests.get(f'{odg._routes._base_url}/ready', timeout=5)
    assert res.ok


def test_openapi_spec(odg):
    res = requests.get(f'{odg._routes._base_url}/api/v1/doc/swagger.json', timeout=5)
    assert res.ok
    assert 'openapi' in res.json()
