"""
Shared test fixture helpers — DB access, payload mutation, HTTP requests.
"""

import copy
import dataclasses
import datetime
import logging
import random
import urllib.parse

import psycopg
import pytest
import requests

import odg.model


def pg_connect(pg):
    """Return an open psycopg connection to *pg* (PostgresContainer)."""
    parsed = urllib.parse.urlparse(pg.url)
    return psycopg.connect(
        host=parsed.hostname,
        port=parsed.port,
        user=parsed.username,
        password=parsed.password,
        dbname=parsed.path.lstrip('/'),
    )


def load_findings(
    pg,
    target: odg.model.ComponentArtefactId,
    max_rows: int,
) -> list[odg.model.ArtefactMetadata]:
    """Load up to max_rows artefact_metadata rows for *target* directly from Postgres.

    Bypasses the ODG client (and its HTTP cache) intentionally.
    """
    component_name = target.component_name
    component_version = target.component_version
    artefact_name = target.artefact.artefact_name if target.artefact else None

    with pg_connect(pg) as conn, conn.cursor() as cur:
        if artefact_name is not None:
            cur.execute(
                """
                SELECT
                    type, component_name, component_version,
                    artefact_kind, artefact_name, artefact_version, artefact_type,
                    artefact_extra_id, meta, data, datasource, discovery_date
                FROM artefact_metadata
                WHERE component_name = %s
                  AND component_version IS NOT DISTINCT FROM %s
                  AND artefact_name = %s
                LIMIT %s
                """,
                (component_name, component_version, artefact_name, max_rows),
            )
        else:
            cur.execute(
                """
                SELECT
                    type, component_name, component_version,
                    artefact_kind, artefact_name, artefact_version, artefact_type,
                    artefact_extra_id, meta, data, datasource, discovery_date
                FROM artefact_metadata
                WHERE component_name = %s
                  AND component_version IS NOT DISTINCT FROM %s
                LIMIT %s
                """,
                (component_name, component_version, max_rows),
            )
        rows = cur.fetchall()

    if not rows:
        pytest.skip(f'no rows for {component_name}@{component_version} artefact={artefact_name}')

    findings = []
    skipped = 0
    for (
        type_,
        comp_name,
        comp_ver,
        art_kind,
        art_name,
        art_ver,
        art_type,
        art_extra_id,
        meta,
        data,
        datasource,
        discovery_date,
    ) in rows:
        try:
            ds = odg.model.Datasource(datasource)
            dt = odg.model.Datatype(type_)
        except ValueError:
            skipped += 1
            continue
        findings.append(
            odg.model.ArtefactMetadata(
                artefact=odg.model.ComponentArtefactId(
                    component_name=comp_name,
                    component_version=comp_ver,
                    artefact=odg.model.LocalArtefactId(
                        artefact_name=art_name,
                        artefact_version=art_ver,
                        artefact_type=art_type,
                        artefact_extra_id=art_extra_id,
                    ),
                    artefact_kind=odg.model.ArtefactKind(art_kind),
                ),
                meta=odg.model.Metadata(
                    datasource=ds,
                    type=dt,
                    creation_date=datetime.datetime.now(tz=datetime.timezone.utc),
                ),
                data=data,
                discovery_date=discovery_date,
            ),
        )
    if skipped:
        logging.getLogger(__name__).warning(
            'load_findings: skipped %d rows with unrecognised datasource/type values',
            skipped,
        )
    if not findings:
        pytest.skip(
            f'no usable rows for {component_name}@{component_version} artefact={artefact_name}'
            f' (all {skipped} rows had unknown datasource/type)',
        )
    # Deduplicate by PK — the DB can return rows whose key() hashes collide within a batch,
    # causing UniqueViolation in the server's autoflush when we PUT them together.
    return list({f.id: f for f in findings}.values())


def mutate_finding_id(
    finding: odg.model.ArtefactMetadata,
    rng: random.Random,
) -> odg.model.ArtefactMetadata:
    """Return a copy with a mutated finding ID so ODG treats it as a new row."""
    mutated = copy.deepcopy(finding)
    data = dataclasses.asdict(mutated)['data']
    if 'cve' in data:
        data['cve'] = f'CVE-PERF-{rng.randint(100000, 999999)}'
    elif 'package_name' in data:
        data['package_name'] = f'perf-pkg-{rng.randint(10000, 99999)}'
    mutated.data = data
    return mutated


def apply_mutations(
    findings: list[odg.model.ArtefactMetadata],
    rng: random.Random | None = None,
    fraction: float = 0.1,
) -> list[odg.model.ArtefactMetadata]:
    """Return a copy with ~fraction of entries having mutated IDs (insert+delete path)."""
    if rng is None:
        rng = random.Random(42)
    batch = findings[:]
    n_mutated = max(1, int(len(batch) * fraction))
    for i in rng.sample(range(len(batch)), n_mutated):
        batch[i] = mutate_finding_id(findings[i], rng)
    return batch


def log_dead_tuples(pg, logger, context: str = '') -> None:
    """Log dead-tuple count for artefact_metadata — vacuum-stall indicator."""
    dead = pg.get_dead_tuples_stats()
    suffix = f' after {context}' if context else ''
    logger.info('artefact_metadata n_dead_tup=%d%s', dead, suffix)


def load_artefact_entries(
    pg,
    components: list[odg.model.ComponentArtefactId],
    limit: int = 20,
) -> list[dict]:
    """Return up to *limit* distinct artefact dicts (ODG client format) for *components*.

    Used by query tests to build artefact filter lists without hardcoding component names.
    """
    clauses = ' OR '.join(
        '(component_name = %s AND component_version IS NOT DISTINCT FROM %s)' for _ in components
    )
    params: list = []
    for component in components:
        params.extend([component.component_name, component.component_version])

    with pg_connect(pg) as conn, conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT DISTINCT component_name, component_version,
                artefact_kind, artefact_name, artefact_version, artefact_type
            FROM artefact_metadata
            WHERE ({clauses})
              AND artefact_kind IS NOT NULL
              AND artefact_name IS NOT NULL
            LIMIT %s
            """,
            params + [limit],
        )
        rows = cur.fetchall()

    if not rows:
        pytest.skip('no artefact entries found for components')

    return [
        {
            'component_name': comp_name,
            'component_version': comp_ver,
            'artefact_kind': art_kind,
            'artefact': {
                'artefact_name': art_name,
                'artefact_version': art_ver,
                'artefact_type': art_type,
            },
        }
        for comp_name, comp_ver, art_kind, art_name, art_ver, art_type in rows
    ]


def request_compliance_summary(base_url: str, component_name: str, version: str) -> dict:
    """GET /components/compliance-summary with cold-cache and full recursion."""
    res = requests.get(
        f'{base_url}/components/compliance-summary',
        params={
            'component_name': component_name,
            'version': version,
            'recursion_depth': '-1',
        },
        headers={'shortcut-cache': 'false'},
        timeout=(4, 600),
    )
    res.raise_for_status()
    return res.json()
