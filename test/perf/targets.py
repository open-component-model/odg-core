"""
Static component names for perf test targets based read from DB.
"""

import dataclasses

import pytest

import odg.model
from utils.fixtures import pg_connect

# Compliance-summary targets: chosen for structural properties:
# GARDENLINUX: many artefacts, no component refs (flat fan-out).
# GARDENER:    many artefacts + component refs (recursive fan-out).
GARDENLINUX = 'github.com/gardenlinux/gardenlinux'
GARDENER = 'github.com/gardener/gardener'


def query_compliance_targets(
    pg,
) -> tuple[
    odg.model.ComponentArtefactId,
    odg.model.ComponentArtefactId,
]:
    """Return (gardenlinux, gardener) ComponentArtefactIds with latest version from DB."""
    with pg_connect(pg) as conn, conn.cursor() as cur:
        results = []
        for name in (GARDENLINUX, GARDENER):
            cur.execute(
                """
                SELECT component_version
                FROM artefact_metadata
                WHERE component_name = %s
                  AND component_version IS NOT NULL
                GROUP BY component_version
                ORDER BY count(*) DESC
                LIMIT 1
                """,
                (name,),
            )
            row = cur.fetchone()
            if row is None:
                pytest.skip(f'no versioned rows for {name} in DB')
            results.append(
                odg.model.ComponentArtefactId(
                    component_name=name,
                    component_version=row[0],
                ),
            )
    return results[0], results[1]


def query_components(
    pg,
    global_limit: int = 10,
    versioned_limit: int = 5,
) -> list[odg.model.ComponentArtefactId]:
    """Return a mix of global-scope and versioned components ordered by row count.

    Mixes both so downstream queries exercise the NULL-version and versioned code paths.
    """
    with pg_connect(pg) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT component_name, NULL AS component_version
            FROM artefact_metadata
            WHERE component_version IS NULL
            GROUP BY component_name
            ORDER BY count(*) DESC
            LIMIT %s
            """,
            (global_limit,),
        )
        global_rows = cur.fetchall()

        cur.execute(
            """
            SELECT component_name, component_version
            FROM artefact_metadata
            WHERE component_version IS NOT NULL
            GROUP BY component_name, component_version
            ORDER BY count(*) DESC
            LIMIT %s
            """,
            (versioned_limit,),
        )
        versioned_rows = cur.fetchall()

    rows = global_rows + versioned_rows
    if not rows:
        pytest.skip('no artefact_metadata rows in DB')
    return [
        odg.model.ComponentArtefactId(component_name=row[0], component_version=row[1])
        for row in rows
    ]


@dataclasses.dataclass(frozen=True)
class WriteTargets:
    global_scope: odg.model.ComponentArtefactId  # component_version=NULL (BDBA path)
    component_scope: odg.model.ComponentArtefactId  # heaviest versioned component
    artefact_scope: odg.model.ComponentArtefactId  # heaviest versioned artefact

    def items(self) -> list[tuple[str, odg.model.ComponentArtefactId]]:
        return [
            ('artefact_scope', self.artefact_scope),
            ('component_scope', self.component_scope),
            ('global_scope', self.global_scope),
        ]


def query_write_targets(pg) -> WriteTargets:
    """Query the heaviest artefact_metadata row at each scope level from *pg*."""
    with pg_connect(pg) as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT component_name, artefact_name
            FROM artefact_metadata
            WHERE component_version IS NULL
            GROUP BY component_name, artefact_name
            ORDER BY count(*) DESC
            LIMIT 1
        """)
        row = cur.fetchone()
        if row is None:
            pytest.skip('no global-scope (NULL component_version) rows in DB')
        global_scope = odg.model.ComponentArtefactId(
            component_name=row[0],
            component_version=None,
            artefact=odg.model.LocalArtefactId(artefact_name=row[1]),
        )

        cur.execute("""
            SELECT component_name, component_version
            FROM artefact_metadata
            WHERE component_version IS NOT NULL
            GROUP BY component_name, component_version
            ORDER BY count(*) DESC
            LIMIT 1
        """)
        row = cur.fetchone()
        if row is None:
            pytest.skip('no versioned rows in DB')
        component_scope = odg.model.ComponentArtefactId(
            component_name=row[0],
            component_version=row[1],
        )

        cur.execute("""
            SELECT component_name, component_version, artefact_name
            FROM artefact_metadata
            WHERE component_version IS NOT NULL
              AND artefact_name IS NOT NULL
            GROUP BY component_name, component_version, artefact_name
            ORDER BY count(*) DESC
            LIMIT 1
        """)
        row = cur.fetchone()
        if row is None:
            pytest.skip('no versioned artefact rows in DB')
        artefact_scope = odg.model.ComponentArtefactId(
            component_name=row[0],
            component_version=row[1],
            artefact=odg.model.LocalArtefactId(artefact_name=row[2]),
        )

    return WriteTargets(
        global_scope=global_scope,
        component_scope=component_scope,
        artefact_scope=artefact_scope,
    )
