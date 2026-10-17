"""
Fires the compliance-summary endpoint in BURSTS x CONCURRENCY concurrent requests

Run (from test/perf/):
    uv run pytest compliance_summary/ -v
"""

import concurrent.futures
import logging
import os
import pathlib
import time

import pytest
import requests

import odg_client

from utils.testcontainer_postgres import PostgresContainer
from utils.testcontainer_odg import OdgCoreContainer
from utils.perf_profiler import PerfProfiler
from utils.snapshots import assert_snapshot
from compliance_summary.seed_db import dump, seed

_DIR = pathlib.Path(__file__).parent
DUMP_FILE = _DIR / 'seed_db.dump'
SNAPSHOT_FILE = _DIR / 'expected-summary.json'
RESULTS_DIR = _DIR / 'results'

COMPONENT_NAME = 'github.com/gardenlinux/gardenlinux'
COMPONENT_VERSION = '2150.10.0'
OCM_REPO_URL = 'europe-docker.pkg.dev/gardener-project/releases'
PROFILE = 'OCM'
CONCURRENCY = 3
BURSTS = 2

logger = logging.getLogger(__name__)


@pytest.fixture(scope='module')
def odg_container(request):
    keep = request.config.getoption('--keep-containers')
    if keep:
        os.environ['TESTCONTAINERS_RYUK_DISABLED'] = 'true'

    pg = PostgresContainer()
    pg.__enter__()
    if DUMP_FILE.exists():
        pg.restore(str(DUMP_FILE))
    else:
        logger.info(f'no dump found at {DUMP_FILE}, seeding — this may take a few minutes')
        with OdgCoreContainer(db_url=pg.url) as odg_seed:
            odg_seed.wait_ready()
            seed(base_url=odg_seed.base_url)
        dump(pg, str(DUMP_FILE))
    odg = OdgCoreContainer(db_url=pg.url, memray=True)
    odg.__enter__()
    odg.wait_ready()

    routes = odg_client.DeliveryServiceRoutes(base_url=odg.base_url)
    client = odg_client.DeliveryServiceClient(routes=routes)
    prof = PerfProfiler(odg, results_dir=RESULTS_DIR)
    prof.__enter__()

    yield client, prof, odg, pg

    prof.__exit__(None, None, None)
    if keep:
        logger.info(
            f'--keep-containers set: leaving containers running\n'
            f'  ODG:      docker exec -it {odg.container_name} sh\n'
            f'  Postgres: docker exec -it {pg._container.get_wrapped_container().name} sh',
        )
    else:
        odg.__exit__(None, None, None)
        pg.__exit__(None, None, None)


def _fetch_compliance_summary(
    client: odg_client.DeliveryServiceClient,
    worker_id: int,
) -> tuple[int, int, float, dict]:
    t0 = time.monotonic()
    res = client.request(
        url=client._routes._base_url.rstrip('/') + '/components/compliance-summary',
        params={
            'component_name': COMPONENT_NAME,
            'version': COMPONENT_VERSION,
            'ocm_repo_url': OCM_REPO_URL,
            'recursion_depth': '0',
            'profile': PROFILE,
        },
        # shortcut-cache: true bypasses the DB cache read, forcing a full recomputation
        # on every request — mirrors the exact prod call that exhibited the issue.
        headers={'shortcut-cache': 'true'},
        timeout=(4, 600),
        remaining_retries=0,
    )
    elapsed = time.monotonic() - t0
    logger.info(f'  worker {worker_id}: {res.status_code} {len(res.content):,}B in {elapsed:.1f}s')
    return worker_id, res.status_code, elapsed, res.json()


def test_ready(odg_container):
    client, _, _, _ = odg_container
    res = requests.get(f'{client._routes._base_url}/ready', timeout=5)
    assert res.ok


def test_warm_cache(odg_container):
    """Fetch the component descriptor once to populate the server-side in-memory cache."""
    client, _, _, _ = odg_container
    client.component_descriptor(
        name=COMPONENT_NAME,
        version=COMPONENT_VERSION,
        ocm_repo_url=OCM_REPO_URL,
    )
    logger.info(f'component descriptor cached: {COMPONENT_NAME} {COMPONENT_VERSION}')


def test_compliance_summary_concurrent(odg_container):
    """Fire BURSTS x CONCURRENCY compliance-summary requests, assert output and RSS growth."""
    client, prof, _, _ = odg_container
    prof.set_test('test_compliance_summary_concurrent')

    first_response = None
    prof.start_pyspy()
    for burst in range(BURSTS):
        prof.phase(f'pre-burst-{burst + 1}')
        logger.info(
            f'burst {burst + 1}/{BURSTS}: firing {CONCURRENCY} concurrent requests '
            f'({COMPONENT_NAME} {COMPONENT_VERSION} profile={PROFILE})',
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
            futs = [
                pool.submit(_fetch_compliance_summary, client, burst * CONCURRENCY + i)
                for i in range(CONCURRENCY)
            ]
            for fut in concurrent.futures.as_completed(futs):
                _, status, _, body = fut.result()
                assert status == 200, f'unexpected status {status}'
                if first_response is None:
                    first_response = body

    prof.stop_pyspy()
    assert first_response is not None
    assert_snapshot(first_response, SNAPSHOT_FILE)
