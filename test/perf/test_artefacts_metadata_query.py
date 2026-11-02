"""
Perf test: POST /artefacts/metadata/query — extension read patterns

Mimics the query shapes used by extensions, using odg_client exactly as extensions do.
One request per shape; log what was queried, how many entries came back, and elapsed.

Tests:
  test_scanner_utils_read       — 1 artefact + type=VULNERABILITY
                                  (scanner_utils reads existing findings before writing)
  test_issue_replicator_read    — N artefacts + type=[ARTEFACT_SCAN_INFO, VULNERABILITY]
                                  (issue_replicator bulk-fetches findings + scan info)
  test_sla_profiler_read        — components (no artefact) + type=VULNERABILITY
                                  (sla_violation_profiler fetches all findings for a component)
  test_rescorings_read          — one request per component, type=RESCORING
                                  (rescoring fetch used by issue_replicator + sla_profiler)
  test_responsibles_license_read — components, type=RESPONSIBLES + referenced_type=LICENSE_FINDING
                                  (issue_replicator reads responsibles for license findings)
  test_responsibles_malware_read — components, type=RESPONSIBLES + referenced_type=MALWARE_FINDING
                                  (issue_replicator reads responsibles for malware findings)

Run (from test/perf/):
    uv run pytest test_artefacts_metadata_query.py -v
    uv run pytest test_artefacts_metadata_query.py -v --profile all
"""

import logging

import pytest

import odg.model
from utils.fixtures import load_artefact_entries
from utils.timer import timed

logger = logging.getLogger(__name__)

_LICENSE = odg.model.Datatype.LICENSE_FINDING
_MALWARE = odg.model.Datatype.MALWARE_FINDING
_RESPONSIBLES = odg.model.Datatype.RESPONSIBLES
_VULNERABILITY = odg.model.Datatype.VULNERABILITY_FINDING
_ARTEFACT_SCAN_INFO = odg.model.Datatype.ARTEFACT_SCAN_INFO
_RESCORING = odg.model.Datatype.RESCORING


@pytest.fixture
def _artefacts(odg_stack, components):
    """Distinct artefact dicts (ODG client format) sampled from components."""
    _odg, pg = odg_stack
    return load_artefact_entries(pg, components)


def test_scanner_utils_read(odg_stack, odg_client, _artefacts, snapshot):
    """scanner_utils: read existing findings for one artefact before writing."""
    artefact = _artefacts[0]
    with timed('scanner_utils_read', logger) as t:
        result = odg_client.query_metadata(artefacts=[artefact], type=_VULNERABILITY)
        t.info(entries=len(result), component=artefact['component_name'].rsplit('/', 1)[-1])
    assert result == snapshot('artefacts-query-scanner-utils.json')


def test_issue_replicator_read(odg_stack, odg_client, _artefacts, snapshot):
    """issue_replicator: fetch findings + scan info for a chunk of artefacts."""
    with timed('issue_replicator_read', logger) as t:
        result = odg_client.query_metadata(
            artefacts=_artefacts,
            type=[_ARTEFACT_SCAN_INFO, _VULNERABILITY],
        )
        components = sorted({a['component_name'].rsplit('/', 1)[-1] for a in _artefacts})
        t.info(artefacts=len(_artefacts), components=components, entries=len(result))
    assert result == snapshot('artefacts-query-issue-replicator.json')


def test_sla_profiler_read(odg_stack, odg_client, components, snapshot):
    """sla_violation_profiler: fetch all findings for components (no artefact filter)."""
    entries = [
        {'component_name': c.component_name, 'component_version': c.component_version}
        for c in components
    ]
    with timed('sla_profiler_read', logger) as t:
        result = odg_client.query_metadata(artefacts=entries, type=_VULNERABILITY)
        names = [c.component_name.rsplit('/', 1)[-1] for c in components]
        t.info(components=names, entries=len(result))
    assert result == snapshot('artefacts-query-sla-profiler.json')


@pytest.mark.skip(reason='sequential scan on full table — ~10 min, deferred')
def test_sla_profiler_read_no_type(odg_stack, odg_client, components, snapshot):
    """sla_violation_profiler without type filter — triggers none_ok=True + full sequential scan."""
    entries = [
        {'component_name': c.component_name, 'component_version': c.component_version}
        for c in components
    ]
    with timed('sla_profiler_read_no_type', logger) as t:
        result = odg_client.query_metadata(artefacts=entries)
        names = [c.component_name.rsplit('/', 1)[-1] for c in components]
        t.info(components=names, entries=len(result))
    assert result == snapshot('artefacts-query-sla-profiler-no-type.json')


def test_rescorings_read(odg_stack, odg_client, components, snapshot):
    """issue_replicator + sla_profiler: fetch rescorings, one request per component."""
    any_results = False
    for component in components:
        entry = [
            {
                'component_name': component.component_name,
                'component_version': component.component_version,
            },
        ]
        version_slug = (component.component_version or 'null').replace('/', '-')
        snap_name = (
            'rescorings-' + component.component_name.replace('/', '-') + '-' + version_slug + '.json'
        )
        with timed('rescorings_read', logger) as t:
            result = odg_client.query_metadata(
                artefacts=entry,
                type=_RESCORING,
                referenced_type=_VULNERABILITY,
            )
            t.info(entries=len(result), component=component.component_name)
        if result:
            any_results = True
            assert result == snapshot(snap_name)

    if not any_results:
        pytest.skip('no rescorings in DB backup')


def test_responsibles_license_read(odg_stack, odg_client, components, snapshot):
    """issue_replicator: fetch responsibles for license findings, one request per component"""
    any_results = False
    for component in components:
        entry = [
            {
                'component_name': component.component_name,
                'component_version': component.component_version,
            },
        ]
        version_slug = (component.component_version or 'null').replace('/', '-')
        snap_name = (
            'responsibles-license-'
            + component.component_name.replace('/', '-')
            + '-'
            + version_slug
            + '.json'
        )
        with timed('responsibles_license_read', logger) as t:
            result = odg_client.query_metadata(
                artefacts=entry,
                type=_RESPONSIBLES,
                referenced_type=_LICENSE,
            )
            t.info(entries=len(result), component=component.component_name)
        if result:
            any_results = True
            assert result == snapshot(snap_name)

    if not any_results:
        pytest.skip('no meta/responsibles rows for finding/license in DB backup')


def test_responsibles_malware_read(odg_stack, odg_client, components, snapshot):
    """issue_replicator: fetch responsibles for malware findings, one request per component"""
    any_results = False
    for component in components:
        entry = [
            {
                'component_name': component.component_name,
                'component_version': component.component_version,
            },
        ]
        version_slug = (component.component_version or 'null').replace('/', '-')
        snap_name = (
            'responsibles-malware-'
            + component.component_name.replace('/', '-')
            + '-'
            + version_slug
            + '.json'
        )
        with timed('responsibles_malware_read', logger) as t:
            result = odg_client.query_metadata(
                artefacts=entry,
                type=_RESPONSIBLES,
                referenced_type=_MALWARE,
            )
            t.info(entries=len(result), component=component.component_name)
        if result:
            any_results = True
            assert result == snapshot(snap_name)

    if not any_results:
        pytest.skip('no meta/responsibles rows for finding/malware in DB backup')
