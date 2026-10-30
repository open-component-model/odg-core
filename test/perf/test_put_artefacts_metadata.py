"""
Perf test: PUT /artefacts/metadata — write throughput and lock contention

Measures write throughput for three PUT scopes:
  global_scope:    component_version=NULL (BDBA path — full sequential scan bottleneck).
  component_scope: versioned component, all artefacts.
  artefact_scope:  versioned component + specific artefact (tightest index path).

Tests:
  1. test_bulk_put_baseline  — single baseline_size-row PUT per scope; regression guard.
  2. test_bulk_put_scaling   — same pool in chunks of increasing size; exposes fixed-overhead
     vs per-row cost. The global_scope path shows super-linear degradation at large chunks.
  3. test_concurrent_puts    — sustained concurrent PUT workers per scope; p95 latency
     exposes lock contention under realistic write pressure.

Run (from test/perf/):
    uv run pytest test_put_artefacts_metadata.py -v
    uv run pytest test_put_artefacts_metadata.py -v --profile all   # with py-spy and memray
"""

import logging

from conftest import make_odg_client
from utils.fixtures import apply_mutations, load_findings
from utils.load_generator import gen_concurrent_requests
from utils.timer import timed

logger = logging.getLogger(__name__)

_BASELINE_SIZE = 10
_SCALING_SIZES = [5, 10, 25]
_CONCURRENT_WORKERS = 3
_CONCURRENT_DURATION_S = 30


def test_bulk_put_baseline(odg_stack, odg_client, write_targets):
    """Single baseline_size-row PUT for each scope — regression guard."""
    _odg, pg = odg_stack
    for label, target in write_targets.items():
        findings = load_findings(pg, target, max_rows=_BASELINE_SIZE)
        batch = apply_mutations(findings[:_BASELINE_SIZE])
        with timed(f'bulk_put_baseline[{label}]', logger) as t:
            odg_client.update_metadata(data=batch)
        logger.info(
            'bulk_put_baseline[%s]: rows/s=%.0f  ms/row=%.1f',
            label,
            len(batch) / t.elapsed,
            t.elapsed * 1000 / len(batch),
        )


def test_bulk_put_scaling(odg_stack, odg_client, write_targets):
    """Increasing chunk sizes per scope — exposes fixed-overhead vs per-row cost."""
    _odg, pg = odg_stack
    for label, target in write_targets.items():
        findings = load_findings(pg, target, max_rows=max(_SCALING_SIZES))
        first_elapsed = last_elapsed = 0.0
        for size in _SCALING_SIZES:
            chunk = apply_mutations(findings[:size])
            with timed(f'bulk_put_scaling[{label}] size={size}', logger) as t:
                odg_client.update_metadata(data=chunk)
            logger.info(
                'bulk_put_scaling[%s]: size=%-5d  rows/s=%-6.0f  ms/row=%-6.1f',
                label,
                size,
                size / t.elapsed,
                t.elapsed * 1000 / size,
            )
            if first_elapsed == 0.0:
                first_elapsed = t.elapsed
            last_elapsed = t.elapsed
        logger.info(
            'bulk_put_scaling[%s]: speedup small(%d)→large(%d)=%.1fx',
            label,
            _SCALING_SIZES[0],
            _SCALING_SIZES[-1],
            (first_elapsed / _SCALING_SIZES[0]) / (last_elapsed / _SCALING_SIZES[-1]),
        )


def test_concurrent_puts(odg_stack, odg_client, write_targets):
    """Sustained concurrent PUT workers per scope — p95 exposes lock contention."""
    odg, pg = odg_stack
    for label, target in write_targets.items():
        findings = load_findings(pg, target, max_rows=_BASELINE_SIZE)
        batch = apply_mutations(findings[:_BASELINE_SIZE])
        logger.info(
            'concurrent_puts[%s]: component=%s version=%s workers=%d chunk=%d',
            label,
            target.component_name,
            target.component_version,
            _CONCURRENT_WORKERS,
            len(batch),
        )
        gen_concurrent_requests(
            lambda b=batch: make_odg_client(odg.base_url).update_metadata(data=b),
            workers=_CONCURRENT_WORKERS,
            duration_s=_CONCURRENT_DURATION_S,
            raise_on_error=False,
        )
