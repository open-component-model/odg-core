"""perf: add finding_group_key and severity generated columns + indexes

Revision ID: 33862894185c
Revises: cc90ad81441c
Create Date: 2026-11-04 00:00:00.000000+00:00

"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = '33862894185c'
down_revision: str | None = 'cc90ad81441c'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_FINDING_GROUP_KEY_EXPR = (
    'md5(CASE'
    " WHEN type = 'finding/vulnerability' THEN"
    "  coalesce(data->>'cve','None')||'|'||coalesce(data->>'package_name','None')"
    " WHEN type = 'finding/license' THEN"
    "  coalesce(data->'license'->>'name','None')||'|'||coalesce(data->>'package_name','None')"
    " WHEN type = 'finding/ip' THEN"
    "  coalesce(data->>'package_name','None')"
    " WHEN type = 'finding/sast' THEN"
    "  coalesce(data->>'sast_status','None')||'|'||coalesce(data->>'sub_type','None')"
    " WHEN type = 'finding/codeql' THEN"
    "  coalesce(data->>'codeql_status','None')||'|'||coalesce(data->>'repo_url','None')"
    "  ||'|'||coalesce(data->>'language','None')"
    " WHEN type = 'finding/osid' THEN"
    "  coalesce(data->'osid'->>'ID','None')"
    " WHEN type = 'finding/malware' THEN"
    "  coalesce(data->'finding'->>'content_digest','None')"
    "  ||'|'||coalesce(data->'finding'->>'filename','None')"
    "  ||'|'||coalesce(data->'finding'->>'malware','None')"
    " WHEN type = 'finding/diki' THEN"
    "  coalesce(data->>'provider_id','None')||'|'||coalesce(data->>'ruleset_id','None')"
    "  ||'|'||coalesce(data->>'rule_id','None')"
    " WHEN type = 'finding/ghas' THEN"
    "  coalesce(data->>'html_url','None')"
    " WHEN type IN ('finding/falco','finding/kyverno') THEN"
    "  coalesce(data->'finding'->>'group_hash','None')"
    " WHEN type = 'rescorings' AND referenced_type = 'finding/vulnerability' THEN"
    "  coalesce(data->'finding'->>'cve','None')"
    "  ||'|'||coalesce(data->'finding'->>'package_name','None')"
    " WHEN type = 'rescorings' AND referenced_type = 'finding/license' THEN"
    "  coalesce(data->'finding'->'license'->>'name','None')"
    "  ||'|'||coalesce(data->'finding'->>'package_name','None')"
    " WHEN type = 'rescorings' AND referenced_type = 'finding/ip' THEN"
    "  coalesce(data->'finding'->>'package_name','None')"
    " WHEN type = 'rescorings' AND referenced_type = 'finding/sast' THEN"
    "  coalesce(data->'finding'->>'sast_status','None')"
    "  ||'|'||coalesce(data->'finding'->>'sub_type','None')"
    " WHEN type = 'rescorings' AND referenced_type = 'finding/codeql' THEN"
    "  coalesce(data->'finding'->>'codeql_status','None')"
    "  ||'|'||coalesce(data->'finding'->>'repo_url','None')"
    "  ||'|'||coalesce(data->'finding'->>'language','None')"
    " WHEN type = 'rescorings' AND referenced_type = 'finding/osid' THEN"
    "  coalesce(data->'finding'->'osid'->>'ID','None')"
    " WHEN type = 'rescorings' AND referenced_type = 'finding/malware' THEN"
    "  coalesce(data->'finding'->>'content_digest','None')"
    "  ||'|'||coalesce(data->'finding'->>'filename','None')"
    "  ||'|'||coalesce(data->'finding'->>'malware','None')"
    " WHEN type = 'rescorings' AND referenced_type = 'finding/diki' THEN"
    "  coalesce(data->'finding'->>'provider_id','None')"
    "  ||'|'||coalesce(data->'finding'->>'ruleset_id','None')"
    "  ||'|'||coalesce(data->'finding'->>'rule_id','None')"
    " WHEN type = 'rescorings' AND referenced_type = 'finding/ghas' THEN"
    "  coalesce(data->'finding'->>'html_url','None')"
    " WHEN type = 'rescorings' AND referenced_type IN ('finding/falco','finding/kyverno') THEN"
    "  coalesce(data->'finding'->>'group_hash','None')"
    ' ELSE NULL END)'
)


def upgrade() -> None:
    # IF NOT EXISTS guards are needed for legacy databases created with create_all
    # against the current model (which already includes these generated columns).
    op.execute(
        sa.text(
            f'ALTER TABLE artefact_metadata'
            f' ADD COLUMN IF NOT EXISTS finding_group_key VARCHAR(32)'
            f' GENERATED ALWAYS AS ({_FINDING_GROUP_KEY_EXPR}) STORED',
        ),
    )
    op.execute(
        sa.text(
            'ALTER TABLE artefact_metadata'
            ' ADD COLUMN IF NOT EXISTS severity VARCHAR'
            " GENERATED ALWAYS AS (data->>'severity') STORED",
        ),
    )

    op.execute(
        sa.text(
            'CREATE INDEX IF NOT EXISTS ix_artefact_metadata_findings_lookup'
            ' ON artefact_metadata (component_name, component_version, type, datasource)',
        ),
    )
    op.execute(
        sa.text(
            'CREATE INDEX IF NOT EXISTS ix_artefact_metadata_rescorings_lookup'
            ' ON artefact_metadata (type, referenced_type, component_name)',
        ),
    )
    op.execute(
        sa.text(
            'CREATE INDEX IF NOT EXISTS ix_artefact_metadata_global_scope'
            ' ON artefact_metadata'
            ' (component_name, artefact_name, artefact_version, type, datasource)'
            ' WHERE component_version IS NULL',
        ),
    )
    op.execute(
        sa.text(
            'CREATE INDEX IF NOT EXISTS ix_artefact_metadata_severity'
            ' ON artefact_metadata (component_name, component_version, type, datasource, severity)',
        ),
    )
    op.execute(
        sa.text(
            'CREATE INDEX IF NOT EXISTS ix_artefact_metadata_rescoring_vuln_key'
            ' ON artefact_metadata'
            " ((data->'finding'->>'cve'), (data->'finding'->>'package_name'))"
            " WHERE type = 'rescoring'",
        ),
    )
    op.execute(
        sa.text(
            'CREATE INDEX IF NOT EXISTS ix_artefact_metadata_rescoring_license_key'
            ' ON artefact_metadata'
            " ((data->'finding'->'license'->>'name'), (data->'finding'->>'package_name'))"
            " WHERE type = 'rescoring'",
        ),
    )


def downgrade() -> None:
    op.drop_index('ix_artefact_metadata_rescoring_license_key', table_name='artefact_metadata')
    op.drop_index('ix_artefact_metadata_rescoring_vuln_key', table_name='artefact_metadata')
    op.drop_index('ix_artefact_metadata_severity', table_name='artefact_metadata')
    op.drop_index('ix_artefact_metadata_global_scope', table_name='artefact_metadata')
    op.drop_index('ix_artefact_metadata_rescorings_lookup', table_name='artefact_metadata')
    op.drop_index('ix_artefact_metadata_findings_lookup', table_name='artefact_metadata')
    op.drop_column('artefact_metadata', 'severity')
    op.drop_column('artefact_metadata', 'finding_group_key')
