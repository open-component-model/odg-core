import collections
import collections.abc
import dataclasses
import hashlib

import oci.model
import ocm
import ocm.iter
import ocm.iter_async
import ocm.retrieve_async
import sqlalchemy as sa
import sqlalchemy.ext.asyncio as sqlasync
import sqlalchemy.sql.elements as sqle

import deliverydb.model as dm
import odg.model
import util


def to_db_artefact_metadata(
    artefact_metadata: odg.model.ArtefactMetadata,
) -> dm.ArtefactMetaData:
    artefact_ref = artefact_metadata.artefact
    artefact = artefact_ref.artefact

    meta = artefact_metadata.meta
    data = artefact_metadata.data

    if dataclasses.is_dataclass(data):
        data_raw = util.dict_serialisation(data)
    else:
        data_raw = data

    if hasattr(data, 'key'):
        data_key = hashlib.sha1(data.key.encode('utf-8'), usedforsecurity=False).hexdigest()
    else:
        data_key = None

    referenced_type = data.referenced_type if hasattr(data, 'referenced_type') else None

    meta_raw = util.dict_serialisation(meta)

    return dm.ArtefactMetaData(
        id=artefact_metadata.id,
        type=meta.type,
        component_name=artefact_ref.component_name,
        component_version=artefact_ref.component_version,
        artefact_kind=artefact_ref.artefact_kind,
        artefact_name=artefact.artefact_name,
        artefact_type=artefact.artefact_type,
        artefact_version=artefact.artefact_version,
        artefact_extra_id=artefact.artefact_extra_id,
        artefact_extra_id_normalised=artefact.normalised_artefact_extra_id,
        data=data_raw,
        data_key=data_key,
        meta=meta_raw,
        datasource=meta.datasource,
        referenced_type=referenced_type,
        creation_date=meta.creation_date,
        discovery_date=artefact_metadata.discovery_date,
        allowed_processing_time=artefact_metadata.allowed_processing_time,
    )


def db_artefact_metadata_to_dict(
    artefact_metadata: dm.ArtefactMetaData,
) -> dict:
    return {
        'artefact': {
            'component_name': artefact_metadata.component_name,
            'component_version': artefact_metadata.component_version,
            'artefact_kind': artefact_metadata.artefact_kind,
            'artefact': {
                'artefact_name': artefact_metadata.artefact_name,
                'artefact_version': artefact_metadata.artefact_version,
                'artefact_type': artefact_metadata.artefact_type,
                'artefact_extra_id': artefact_metadata.artefact_extra_id,
            },
        },
        'meta': artefact_metadata.meta,
        'data': artefact_metadata.data,
        'discovery_date': (
            artefact_metadata.discovery_date.isoformat()
            if artefact_metadata.discovery_date
            else None
        ),
        'allowed_processing_time': artefact_metadata.allowed_processing_time,
    }


def db_artefact_metadata_row_to_dso(
    artefact_metadata_row: sa.Row[dm.ArtefactMetaData],
) -> odg.model.ArtefactMetadata:
    artefact_metadata = artefact_metadata_row[0]

    artefact_metadata_dict = db_artefact_metadata_to_dict(
        artefact_metadata=artefact_metadata,
    )

    return odg.model.ArtefactMetadata.from_dict(
        raw=artefact_metadata_dict,
    )


class ArtefactMetadataFilters:
    @staticmethod
    def by_name_and_type(
        artefact_metadata: dm.ArtefactMetaData,
    ):
        return sa.and_(
            dm.ArtefactMetaData.component_name == artefact_metadata.component_name,
            dm.ArtefactMetaData.artefact_name == artefact_metadata.artefact_name,
            dm.ArtefactMetaData.type == artefact_metadata.type,
            dm.ArtefactMetaData.datasource == artefact_metadata.datasource,
        )

    @staticmethod
    def filter_for_rescoring_type(
        type_filter: list[str] = None,
    ):
        if not type_filter:
            return True

        return sa.and_(
            dm.ArtefactMetaData.type == odg.model.Datatype.RESCORING,
            dm.ArtefactMetaData.referenced_type.in_(type_filter),
        )


class ArtefactMetadataQueries:
    @staticmethod
    async def artefact_queries(
        artefacts: collections.abc.Iterable[ocm.Resource | ocm.Source] = None,
        component: ocm.Component | ocm.ComponentIdentity = None,
        component_descriptor_lookup: ocm.retrieve_async.ComponentDescriptorLookupById = None,
        ocm_repository_lookup: ocm.OcmRepositoryLookup | None = None,
        none_ok: bool = False,
    ) -> collections.abc.AsyncGenerator[sqle.BooleanClauseList, None, None]:
        """
        Generates single SQL expressions which check for equality with one artefact of `artefacts`.
        If `artefacts` is not specified, `component` _must_ be specified to retrieve all artefacts
        of the given `component`.

        Intended to be concatenated using an `OR` expression which semantically checks a database
        entry to be one of `artefacts`.

        If a property mismatches but the value stored in the database is `None` and `none_ok` is set
        to `True`, the predecate evaluates to `True` anyways.
        """
        if not (artefacts or component):
            raise ValueError('either `artefacts` or `component` must be specified')

        if not artefacts:
            if component.version:
                if isinstance(component, ocm.ComponentIdentity):
                    try:
                        component_descriptor = await component_descriptor_lookup(
                            component,
                            ocm_repository_lookup=ocm_repository_lookup,
                        )
                    except oci.model.OciImageNotFoundException:
                        yield False
                        return

                    component: ocm.Component = component_descriptor.component

                artefacts = [
                    artefact_node.artefact
                    async for artefact_node in ocm.iter_async.iter(
                        component=component,
                        node_filter=ocm.iter.Filter.artefacts,
                        recursion_depth=0,
                    )
                    if artefact_node.artefact.type
                    not in (
                        'application/vnd.cyclonedx+json',
                        'application/spdx+json',
                    )
                ]
            else:
                # if no component version is specified, artefact specific querying must be
                # taken care of by the caller
                yield True
                return

        for artefact in artefacts:
            yield sa.and_(
                # if name or version is missing and `none_ok` is set, set predicate to `True`
                sa.or_(
                    sa.and_(
                        none_ok,
                        dm.ArtefactMetaData.artefact_name.is_(None),
                    ),
                    dm.ArtefactMetaData.artefact_name == artefact.name,
                ),
                sa.or_(
                    sa.and_(
                        none_ok,
                        dm.ArtefactMetaData.artefact_version.is_(None),
                    ),
                    dm.ArtefactMetaData.artefact_version == artefact.version,
                ),
                sa.or_(
                    sa.and_(
                        none_ok,
                        dm.ArtefactMetaData.artefact_type.is_(None),
                    ),
                    dm.ArtefactMetaData.artefact_type == artefact.type,
                ),
                sa.or_(
                    sa.and_(
                        none_ok,
                        dm.ArtefactMetaData.artefact_extra_id_normalised == '',
                    ),
                    dm.ArtefactMetaData.artefact_extra_id_normalised
                    == odg.model.normalise_artefact_extra_id(
                        artefact_extra_id=artefact.extraIdentity,
                    ),
                ),
            )

    @staticmethod
    async def component_queries(
        components: tuple[ocm.Component | ocm.ComponentIdentity],
        none_ok: bool = False,
        component_descriptor_lookup: ocm.retrieve_async.ComponentDescriptorLookupById = None,
        ocm_repository_lookup: ocm.OcmRepositoryLookup | None = None,
    ) -> collections.abc.AsyncGenerator[sqle.BooleanClauseList, None, None]:
        """
        Generates single SQL expressions which check for equality with one component of `components`
        by name and version.

        Intended to be concatenated using an `OR` expression which semantically checks a database
        entry to be one of `components`.

        If a property mismatches but the value stored in the database is `None` and `none_ok` is set
        to `True`, the predecate evaluates to `True` anyways.

        If the component version of a database entry is not specified and `none_ok` is not `True`,
        it is checked whether the component in question contains an artefact version which matches
        the database entry. This is especially useful for retrieving BDBA scan results which don't
        contain a component version (for deduplication), to only query scan results for artefact
        versions which are included in the specified component versions.
        """
        for component in components:
            yield sa.and_(
                # if name or version is missing and `none_ok` is set, set predicate to `True`
                sa.or_(
                    sa.and_(
                        none_ok,
                        dm.ArtefactMetaData.component_name.is_(None),
                    ),
                    dm.ArtefactMetaData.component_name == component.name,
                ),
                sa.or_(
                    component.version is None,
                    dm.ArtefactMetaData.component_version == component.version,
                    sa.and_(
                        none_ok,
                        dm.ArtefactMetaData.component_version.is_(None),
                    ),
                    sa.and_(
                        dm.ArtefactMetaData.component_version.is_(None),
                        sa.or_(
                            *[
                                query
                                async for query in ArtefactMetadataQueries.artefact_queries(
                                    component=component,
                                    component_descriptor_lookup=component_descriptor_lookup,
                                    ocm_repository_lookup=ocm_repository_lookup,
                                )
                            ],
                        ),
                    ),
                ),
            )


async def severity_counts_for_component(
    component: ocm.Component,
    finding_type: odg.model.Datatype,
    datasource: odg.model.Datasource,
    db_session: sqlasync.session.AsyncSession,
) -> dict[tuple, dict[str, int]]:
    """
    Returns per-artefact severity counts via a single GROUP BY query.

    Key: (artefact_kind, artefact_name, artefact_version, artefact_extra_id_normalised)
    Value: {severity_string: row_count}

    Only artefacts with at least one finding appear in the result.
    """
    severity_col = sa.text("data->>'severity'").label('severity')
    rows = await db_session.execute(
        sa.select(
            dm.ArtefactMetaData.artefact_kind,
            dm.ArtefactMetaData.artefact_name,
            dm.ArtefactMetaData.artefact_version,
            dm.ArtefactMetaData.artefact_extra_id_normalised,
            severity_col,
            sa.func.count().label('cnt'),
        )
        .where(
            dm.ArtefactMetaData.component_name == component.name,
            sa.or_(
                dm.ArtefactMetaData.component_version == component.version,
                sa.and_(
                    dm.ArtefactMetaData.component_version.is_(None),
                    sa.or_(
                        *[
                            query
                            async for query in ArtefactMetadataQueries.artefact_queries(
                                component=component,
                            )
                        ],
                    ),
                ),
            ),
            dm.ArtefactMetaData.type == finding_type,
            dm.ArtefactMetaData.datasource == datasource,
        )
        .group_by(
            dm.ArtefactMetaData.artefact_kind,
            dm.ArtefactMetaData.artefact_name,
            dm.ArtefactMetaData.artefact_version,
            dm.ArtefactMetaData.artefact_extra_id_normalised,
            severity_col,
        ),
    )

    result: dict[tuple, dict[str, int]] = {}
    for row in rows:
        key = (
            row.artefact_kind,
            row.artefact_name,
            row.artefact_version,
            row.artefact_extra_id_normalised,
        )
        result.setdefault(key, {})[row.severity] = row.cnt
    return result


async def findings_for_component_grouped(
    component: ocm.Component,
    finding_type: odg.model.Datatype,
    datasource: odg.model.Datasource,
    db_session: sqlasync.session.AsyncSession,
    chunk_size: int = 50,
) -> dict[tuple, list[odg.model.ArtefactMetadata]]:
    """
    Fetches all findings for a component+type in one query, grouped by artefact identity.

    Key: (artefact_kind, artefact_name, artefact_version, artefact_extra_id_normalised)
    """
    query = await db_session.stream(
        sa.select(dm.ArtefactMetaData).where(
            dm.ArtefactMetaData.component_name == component.name,
            sa.or_(
                dm.ArtefactMetaData.component_version == component.version,
                sa.and_(
                    dm.ArtefactMetaData.component_version.is_(None),
                    sa.or_(
                        *[
                            q
                            async for q in ArtefactMetadataQueries.artefact_queries(
                                component=component,
                            )
                        ],
                    ),
                ),
            ),
            dm.ArtefactMetaData.type == finding_type,
            dm.ArtefactMetaData.datasource == datasource,
        ),
    )

    grouped: dict[tuple, list[odg.model.ArtefactMetadata]] = collections.defaultdict(list)
    async for partition in query.partitions(size=chunk_size):
        for row in partition:
            key = (
                row.ArtefactMetaData.artefact_kind,
                row.ArtefactMetaData.artefact_name,
                row.ArtefactMetaData.artefact_version,
                row.ArtefactMetaData.artefact_extra_id_normalised,
            )
            grouped[key].append(db_artefact_metadata_row_to_dso(row))

    return grouped


async def findings_for_component(
    component: ocm.Component,
    finding_type: odg.model.Datatype,
    datasource: odg.model.Datasource,
    db_session: sqlasync.session.AsyncSession,
    chunk_size: int = 50,
) -> list[odg.model.ArtefactMetadata]:
    query = await db_session.stream(
        sa.select(dm.ArtefactMetaData).where(
            dm.ArtefactMetaData.component_name == component.name,
            sa.or_(
                dm.ArtefactMetaData.component_version == component.version,
                sa.and_(
                    dm.ArtefactMetaData.component_version.is_(None),
                    sa.or_(
                        *[  # check if component versions contains the referenced artefact version
                            query
                            async for query in ArtefactMetadataQueries.artefact_queries(
                                component=component,
                            )
                        ],
                    ),
                ),
            ),
            dm.ArtefactMetaData.type == finding_type,
            dm.ArtefactMetaData.datasource == datasource,
        ),
    )

    return [
        db_artefact_metadata_row_to_dso(row)
        async for partition in query.partitions(size=chunk_size)
        for row in partition
    ]


async def findings_for_artefact(
    component: ocm.Component,
    artefact: ocm.Resource | ocm.Source,
    finding_type: odg.model.Datatype,
    datasource: odg.model.Datasource,
    db_session: sqlasync.session.AsyncSession,
    chunk_size: int = 50,
) -> list[odg.model.ArtefactMetadata]:
    artefact_filter = [
        query
        async for query in ArtefactMetadataQueries.artefact_queries(
            artefacts=[artefact],
        )
    ]

    if isinstance(artefact, ocm.Resource):
        artefact_kind = odg.model.ArtefactKind.RESOURCE
    else:
        artefact_kind = odg.model.ArtefactKind.SOURCE

    query = await db_session.stream(
        sa.select(dm.ArtefactMetaData).where(
            dm.ArtefactMetaData.component_name == component.name,
            sa.or_(
                dm.ArtefactMetaData.component_version == component.version,
                dm.ArtefactMetaData.component_version.is_(None),
            ),
            sa.or_(*artefact_filter),
            dm.ArtefactMetaData.artefact_kind == artefact_kind,
            dm.ArtefactMetaData.type == finding_type,
            dm.ArtefactMetaData.datasource == datasource,
        ),
    )

    return [
        db_artefact_metadata_row_to_dso(row)
        async for partition in query.partitions(size=chunk_size)
        for row in partition
    ]


async def severity_summary_for_component(
    component: ocm.Component,
    finding_type: odg.model.Datatype,
    datasource: odg.model.Datasource,
    db_session: sqlasync.session.AsyncSession,
    severity_values: dict[str, int],
) -> dict[tuple, int]:
    """
    Returns the effective max severity value per artefact via a single SQL query.

    Uses finding_group_key (stored generated column) as the equi-join key between findings and
    rescorings — avoids JSONB path comparisons and allows full index usage on both sides.

    Key: (artefact_kind, artefact_name, artefact_version, artefact_extra_id_normalised)
    Value: max effective severity value (integer from finding_cfg categorisations)

    Only artefacts with at least one finding appear in the result. Findings whose effective
    severity is not in severity_values are treated as value 0 (same behaviour as CLEAN).

    Raises NotImplementedError for finding types with no finding_group_key (e.g. CRYPTO).
    """
    _supported = (
        odg.model.Datatype.CODEQL_FINDING,
        odg.model.Datatype.DIKI_FINDING,
        odg.model.Datatype.FALCO_FINDING,
        odg.model.Datatype.GHAS_FINDING,
        odg.model.Datatype.IP_FINDING,
        odg.model.Datatype.KYVERNO_FINDING,
        odg.model.Datatype.LICENSE_FINDING,
        odg.model.Datatype.MALWARE_FINDING,
        odg.model.Datatype.OSID_FINDING,
        odg.model.Datatype.SAST_FINDING,
        odg.model.Datatype.VULNERABILITY_FINDING,
    )
    if finding_type not in _supported:
        raise NotImplementedError(finding_type)

    if not severity_values:
        return {}

    # CTE rows: trusted config values, not user input.  Safe to inline as SQL literals.
    cte_rows = ', '.join(
        f"('{severity_id}', {value})" for severity_id, value in severity_values.items()
    )

    from sqlalchemy.dialects import postgresql as pg_dialect  # noqa: PLC0415

    # Build the component_version IS NULL artefact sub-filter.
    artefact_sub_queries_compiled = [
        q async for q in ArtefactMetadataQueries.artefact_queries(component=component)
    ]
    compiled_artefact_parts = []
    for q in artefact_sub_queries_compiled:
        if q is True:
            compiled_artefact_parts.append('TRUE')
            break
        c = q.compile(dialect=pg_dialect.dialect(), compile_kwargs={'literal_binds': True})
        compiled_artefact_parts.append(
            str(c).replace('artefact_metadata.', 'f.'),
        )

    if compiled_artefact_parts:
        artefact_or_sql = ' OR '.join(f'({p})' for p in compiled_artefact_parts)
        version_filter_sql = (
            f'(f.component_version = :component_version'
            f' OR (f.component_version IS NULL AND ({artefact_or_sql})))'
        )
    else:
        version_filter_sql = 'f.component_version = :component_version'

    # Normalise artefact_extra_id_normalised for comparison: the stored column includes a
    # 'version' key, but rescoring matching uses omit_version=True.  Strip 'version:...'
    # segments from both sides.
    extra_id_match_sql = (
        'r.artefact_extra_id_normalised IS NULL'
        " OR r.artefact_extra_id_normalised = ''"
        ' OR ltrim(regexp_replace('
        "       r.artefact_extra_id_normalised, '_?version:[^_]*', '', 'g'), '_')"
        '   = ltrim(regexp_replace('
        "       f.artefact_extra_id_normalised, '_?version:[^_]*', '', 'g'), '_')"
    )

    # Join on finding_group_key (indexed equi-join) instead of JSONB path comparisons.
    # Both findings and rescorings now have the same hash in this column.
    # cte_rows, version_filter_sql: built from trusted config and ORM literals — no user
    # input is interpolated.  nosec B608.
    full_sql = sa.text(f"""
        WITH sev_value(id, val) AS (
            VALUES {cte_rows}
        )
        SELECT
            f.artefact_kind,
            f.artefact_name,
            f.artefact_version,
            f.artefact_extra_id_normalised,
            MAX(COALESCE(sv.val, 0)) AS max_value
        FROM artefact_metadata f
        LEFT JOIN LATERAL (
            SELECT r.severity AS sev
            FROM artefact_metadata r
            WHERE r.type = :rescoring_type
              AND r.referenced_type = :finding_type
              AND r.finding_group_key = f.finding_group_key
              AND (r.component_name    IS NULL OR r.component_name    = f.component_name)
              AND (r.component_version IS NULL OR r.component_version = f.component_version)
              AND (r.artefact_name     IS NULL OR r.artefact_name     = f.artefact_name)
              AND (r.artefact_version  IS NULL OR r.artefact_version  = f.artefact_version)
              AND ({extra_id_match_sql})
            ORDER BY r.creation_date DESC
            LIMIT 1
        ) resc ON TRUE
        LEFT JOIN sev_value sv ON sv.id = COALESCE(resc.sev, f.severity)
        WHERE f.component_name = :component_name
          AND f.type = :finding_type
          AND f.datasource = :datasource
          AND {version_filter_sql}
          AND f.finding_group_key IS NOT NULL
        GROUP BY
            f.artefact_kind,
            f.artefact_name,
            f.artefact_version,
            f.artefact_extra_id_normalised
    """)  # nosec B608

    rows = await db_session.execute(
        full_sql,
        {
            'component_name': component.name,
            'component_version': component.version,
            'finding_type': str(finding_type),
            'datasource': str(datasource),
            'rescoring_type': str(odg.model.Datatype.RESCORING),
        },
    )

    return {
        (
            row.artefact_kind,
            row.artefact_name,
            row.artefact_version,
            row.artefact_extra_id_normalised,
        ): row.max_value
        for row in rows
    }


@dataclasses.dataclass(frozen=True, slots=True)
class FindingProjection:
    type: str
    datasource: str
    severity: str | None
    artefact_kind: str
    artefact_name: str
    artefact_version: str | None
    artefact_extra_id: dict  # raw dict from JSONB column
    component_name: str
    component_version: str | None
    finding_group_key: str | None  # md5 of type-specific key string; None for CRYPTO and unknown


async def projected_findings_for_component(
    component: ocm.Component,
    finding_type: odg.model.Datatype,
    datasource: odg.model.Datasource,
    db_session: sqlasync.session.AsyncSession,
    chunk_size: int = 50,
) -> dict[tuple, list[FindingProjection]]:
    """
    Fetches only the columns needed by the compliance-summary hot path, grouped by artefact identity.

    Key: (artefact_kind, artefact_name, artefact_version, artefact_extra_id_normalised)

    Eliminates dacite deserialization — rows are mapped directly to FindingProjection.
    """
    query = await db_session.stream(
        sa.select(
            dm.ArtefactMetaData.type,
            dm.ArtefactMetaData.datasource,
            dm.ArtefactMetaData.artefact_kind,
            dm.ArtefactMetaData.artefact_name,
            dm.ArtefactMetaData.artefact_version,
            dm.ArtefactMetaData.artefact_extra_id,
            dm.ArtefactMetaData.artefact_extra_id_normalised,
            dm.ArtefactMetaData.component_name,
            dm.ArtefactMetaData.component_version,
            dm.ArtefactMetaData.severity,
            dm.ArtefactMetaData.finding_group_key,
        ).where(
            dm.ArtefactMetaData.component_name == component.name,
            sa.or_(
                dm.ArtefactMetaData.component_version == component.version,
                sa.and_(
                    dm.ArtefactMetaData.component_version.is_(None),
                    sa.or_(
                        *[
                            q
                            async for q in ArtefactMetadataQueries.artefact_queries(
                                component=component,
                            )
                        ],
                    ),
                ),
            ),
            dm.ArtefactMetaData.type == finding_type,
            dm.ArtefactMetaData.datasource == datasource,
        ),
    )

    grouped: dict[tuple, list[FindingProjection]] = collections.defaultdict(list)
    async for partition in query.partitions(size=chunk_size):
        for row in partition:
            key = (
                row.artefact_kind,
                row.artefact_name,
                row.artefact_version,
                row.artefact_extra_id_normalised,
            )
            grouped[key].append(
                FindingProjection(
                    type=row.type,
                    datasource=row.datasource,
                    severity=row.severity,
                    artefact_kind=row.artefact_kind,
                    artefact_name=row.artefact_name,
                    artefact_version=row.artefact_version,
                    artefact_extra_id=row.artefact_extra_id or {},
                    component_name=row.component_name,
                    component_version=row.component_version,
                    finding_group_key=row.finding_group_key,
                ),
            )

    return grouped


async def rescorings_for_component(
    component: ocm.Component | ocm.ComponentIdentity,
    finding_type: odg.model.Datatype,
    db_session: sqlasync.session.AsyncSession,
    chunk_size: int = 50,
) -> list[odg.model.ArtefactMetadata]:
    rescorings_query = await db_session.stream(
        sa.select(dm.ArtefactMetaData).where(
            sa.or_(
                dm.ArtefactMetaData.component_name.is_(None),
                dm.ArtefactMetaData.component_name == component.name,
            ),
            sa.or_(
                dm.ArtefactMetaData.component_version.is_(None),
                dm.ArtefactMetaData.component_version == component.version,
            ),
            dm.ArtefactMetaData.type == odg.model.Datatype.RESCORING,
            dm.ArtefactMetaData.referenced_type == finding_type,
        ),
    )

    return [
        db_artefact_metadata_row_to_dso(row)
        async for partition in rescorings_query.partitions(size=chunk_size)
        for row in partition
    ]


@dataclasses.dataclass(frozen=True, slots=True)
class RescoringProjection:
    """Lightweight rescoring row — no dacite, only fields needed by compliance-summary."""

    group_key_hash: str | None  # precomputed hash matching finding_group_key
    severity: str | None
    component_name: str | None
    component_version: str | None
    artefact_name: str | None
    artefact_version: str | None
    artefact_extra_id: dict | None
    creation_date: str | None  # ISO string from meta->>'creation_date'


def _rescoring_projection_group_key_hash(
    referenced_type: str,
    data: dict,
) -> str | None:
    import hashlib

    finding = data.get('finding') or {}

    if referenced_type == odg.model.Datatype.VULNERABILITY_FINDING:
        key_str = (finding.get('cve') or 'None') + '|' + (finding.get('package_name') or 'None')
    elif referenced_type == odg.model.Datatype.LICENSE_FINDING:
        license_name = (finding.get('license') or {}).get('name')
        key_str = (license_name or 'None') + '|' + (finding.get('package_name') or 'None')
    elif referenced_type == odg.model.Datatype.IP_FINDING:
        key_str = finding.get('package_name') or 'None'
    elif referenced_type == odg.model.Datatype.SAST_FINDING:
        key_str = (finding.get('sast_status') or 'None') + '|' + (finding.get('sub_type') or 'None')
    elif referenced_type == odg.model.Datatype.CODEQL_FINDING:
        key_str = (
            (finding.get('codeql_status') or 'None')
            + '|'
            + (finding.get('repo_url') or 'None')
            + '|'
            + (finding.get('language') or 'None')
        )
    elif referenced_type == odg.model.Datatype.OSID_FINDING:
        osid = finding.get('osid') or {}
        key_str = osid.get('ID') or 'None'
    elif referenced_type == odg.model.Datatype.MALWARE_FINDING:
        # CustomRescoring.finding is MalwareFindingDetails directly (no extra nesting)
        key_str = (
            (finding.get('content_digest') or 'None')
            + '|'
            + (finding.get('filename') or 'None')
            + '|'
            + (finding.get('malware') or 'None')
        )
    elif referenced_type == odg.model.Datatype.DIKI_FINDING:
        key_str = (
            (finding.get('provider_id') or 'None')
            + '|'
            + (finding.get('ruleset_id') or 'None')
            + '|'
            + (finding.get('rule_id') or 'None')
        )
    elif referenced_type == odg.model.Datatype.GHAS_FINDING:
        key_str = finding.get('html_url') or 'None'
    elif referenced_type in (
        odg.model.Datatype.FALCO_FINDING,
        odg.model.Datatype.KYVERNO_FINDING,
    ):
        # CustomRescoring.finding is RescoringFalcoFinding/KyvernoFinding: {'group_hash': ...}
        key_str = finding.get('group_hash') or 'None'
    else:
        return None

    return hashlib.md5(key_str.encode(), usedforsecurity=False).hexdigest()  # nosec B324


async def projected_rescorings_for_component(
    component: ocm.Component | ocm.ComponentIdentity,
    finding_type: odg.model.Datatype,
    db_session: sqlasync.session.AsyncSession,
    chunk_size: int = 50,
) -> list[RescoringProjection]:
    """Fetch rescorings without dacite — projects only fields needed by compliance-summary."""
    rescorings_query = await db_session.stream(
        sa.select(
            dm.ArtefactMetaData.component_name,
            dm.ArtefactMetaData.component_version,
            dm.ArtefactMetaData.artefact_name,
            dm.ArtefactMetaData.artefact_version,
            dm.ArtefactMetaData.artefact_extra_id,
            dm.ArtefactMetaData.data,
            dm.ArtefactMetaData.meta,
        ).where(
            sa.or_(
                dm.ArtefactMetaData.component_name.is_(None),
                dm.ArtefactMetaData.component_name == component.name,
            ),
            sa.or_(
                dm.ArtefactMetaData.component_version.is_(None),
                dm.ArtefactMetaData.component_version == component.version,
            ),
            dm.ArtefactMetaData.type == odg.model.Datatype.RESCORING,
            dm.ArtefactMetaData.referenced_type == finding_type,
        ),
    )

    result = []
    async for partition in rescorings_query.partitions(size=chunk_size):
        for row in partition:
            data = row.data or {}
            meta = row.meta or {}
            result.append(
                RescoringProjection(
                    group_key_hash=_rescoring_projection_group_key_hash(finding_type, data),
                    severity=data.get('severity'),
                    component_name=row.component_name,
                    component_version=row.component_version,
                    artefact_name=row.artefact_name,
                    artefact_version=row.artefact_version,
                    artefact_extra_id=row.artefact_extra_id,
                    creation_date=meta.get('creation_date'),
                ),
            )
    return result
