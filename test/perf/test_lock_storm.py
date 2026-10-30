"""
Perf test: two-replica write storm — readiness, query latency, and compliance-summary under load

Catches regressions when two service instances share one database under simultaneous write and
read pressure.

Mechanics:
  Starts two OdgCoreContainer instances against a shared module-scoped Postgres.
  Write workers upload real findings from the DB backup against both replicas.
  Three reader shapes are measured in separate tests:

  (1) test_readiness_under_write_storm      — /ready p95 on both replicas
  (2) test_query_latency_under_write_storm  — POST /artefacts/metadata/query reader p95;
                                              NULL-version (global_scope) write target
  (3) test_compliance_summary_under_write_storm — GET /components/compliance-summary reader p95
                                              for gardener; writers target the same versioned
                                              gardener findings — directly exercises cache
                                              invalidation scope (#5)

Run (from test/perf/):
    uv run pytest test_lock_storm.py -v
    uv run pytest test_lock_storm.py -v --profile all
"""

import itertools
import logging
import pathlib
import tempfile

import pytest
import requests

from conftest import ODG_DB_IMAGE, make_odg_client, make_odg_container
from targets import query_compliance_targets, query_write_targets
from utils.fixtures import (  # noqa: E402
    apply_mutations,
    load_findings,
    log_dead_tuples,
    request_compliance_summary,
)
from utils.load_generator import gen_concurrent_requests
from utils.testcontainer_postgres import PostgresContainer

logger = logging.getLogger(__name__)

_WRITE_WORKERS = 8
_READ_WORKERS = 5
_DURATION_S = 60


# ---------------------------------------------------------------------------
# Module-scoped infrastructure fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope='module')
def pg_stack():
    with PostgresContainer(image=ODG_DB_IMAGE) as pg:
        yield pg


@pytest.fixture(scope='module')
def odg_stack_pair(request, pg_stack):
    profile = request.config.getoption('--profile')
    logs_root = pathlib.Path(tempfile.mkdtemp())
    with (
        make_odg_container(
            pg_stack,
            profile,
            logs_dir=logs_root / 'odg1',
            cpu_limit=1.0,
            memory_limit='6g',
        ) as odg1,
        make_odg_container(
            pg_stack,
            profile,
            logs_dir=logs_root / 'odg2',
            cpu_limit=1.0,
            memory_limit='6g',
        ) as odg2,
    ):
        odg1.wait_ready()
        odg2.wait_ready()
        yield odg1, odg2


@pytest.fixture(scope='module')
def _write_batch_global(pg_stack):
    """NULL-version findings — bottleneck for readiness + query tests."""
    targets = query_write_targets(pg_stack)
    findings = load_findings(pg_stack, targets.global_scope, max_rows=10_000)
    return apply_mutations(findings[:1_000])


@pytest.fixture(scope='module')
def _gardener(pg_stack):
    _, gardener = query_compliance_targets(pg_stack)
    return gardener


@pytest.fixture(scope='module')
def _write_batch_gardener(pg_stack, _gardener):
    """Versioned gardener findings — same component the compliance-summary reader queries."""
    findings = load_findings(pg_stack, _gardener, max_rows=500)
    if not findings:
        pytest.skip('no versioned gardener findings in DB image')
    return apply_mutations(findings)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_readiness_under_write_storm(odg_stack_pair, _write_batch_global):
    """Readiness probe latency on both replicas while writers are in flight."""
    odg1, odg2 = odg_stack_pair
    urls = itertools.cycle([odg1.base_url, odg2.base_url])

    def _write():
        make_odg_client(next(urls)).update_metadata(data=_write_batch_global)

    def _probe():
        requests.get(f'{next(urls)}/ready', timeout=5).raise_for_status()

    gen_concurrent_requests(_write, workers=_WRITE_WORKERS, duration_s=_DURATION_S)
    gen_concurrent_requests(_probe, workers=2, duration_s=_DURATION_S, pace_s=0.5)


def test_query_latency_under_write_storm(odg_stack_pair, pg_stack, _write_batch_global):
    """POST /artefacts/metadata/query latency under write pressure; dead-tuple count logged."""
    odg1, odg2 = odg_stack_pair
    urls = itertools.cycle([odg1.base_url, odg2.base_url])
    query_body = {
        'criteria': [{'type': 'fulltext', 'value': 'CVE-2024'}],
        'limit': 50,
    }

    def _write():
        make_odg_client(next(urls)).update_metadata(data=_write_batch_global)

    def _query():
        requests.post(
            f'{odg2.base_url}/artefacts/metadata/query',
            json=query_body,
            timeout=(4, 120),
        ).raise_for_status()

    gen_concurrent_requests(_write, workers=_WRITE_WORKERS, duration_s=_DURATION_S)
    gen_concurrent_requests(_query, workers=_READ_WORKERS, duration_s=_DURATION_S)
    log_dead_tuples(pg_stack, logger, 'write storm')


def test_compliance_summary_under_write_storm(
    odg_stack_pair,
    pg_stack,
    _write_batch_gardener,
    _gardener,
):
    """GET /components/compliance-summary latency under concurrent writes to the same component.

    Writers and readers both target gardener — directly stresses cache invalidation scope (#5).
    After the storm, one correctness check: summary must be non-empty.
    """
    odg1, odg2 = odg_stack_pair
    urls = itertools.cycle([odg1.base_url, odg2.base_url])

    def _write():
        make_odg_client(next(urls)).update_metadata(data=_write_batch_gardener)

    def _read():
        request_compliance_summary(
            odg2.base_url,
            _gardener.component_name,
            _gardener.component_version,
        )

    gen_concurrent_requests(_write, workers=_WRITE_WORKERS, duration_s=_DURATION_S)
    gen_concurrent_requests(_read, workers=_READ_WORKERS, duration_s=_DURATION_S)
    log_dead_tuples(pg_stack, logger, 'compliance storm')

    result = request_compliance_summary(
        odg1.base_url,
        _gardener.component_name,
        _gardener.component_version,
    )
    assert result, 'compliance-summary returned empty result after write storm'
