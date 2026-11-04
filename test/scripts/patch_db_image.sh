#!/usr/bin/env bash
# Apply schema patches to an existing DB image and commit as a new tag.
#
# Usage (from repo root):
#
#   test/scripts/patch_db_image.sh --patch <patch-name>
#
# Available patches: jsonb, rescoring-indexes, group-key-hash
#
# Optional flags:
#   --src-tag  <tag>   source image  (default: odg-test-db:latest)
#   --dst-tag  <tag>   output image  (default: odg-test-db:<patch-name>)

set -euo pipefail

PATCH_NAME=""
SRC_TAG="odg-test-db:latest"
DST_TAG=""
PG_USER="${ODG_TEST_DB_USER:-odg-user}"
PG_PASSWORD="${ODG_TEST_DB_PASSWORD:-changeme}"
PG_DB="${ODG_TEST_DB_NAME:-odg-db}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --patch)   PATCH_NAME="$2";  shift 2 ;;
        --src-tag) SRC_TAG="$2";     shift 2 ;;
        --dst-tag) DST_TAG="$2";     shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$PATCH_NAME" ]]; then
    echo "error: --patch <name> is required" >&2; exit 1
fi
if [[ -z "$DST_TAG" ]]; then
    DST_TAG="odg-test-db:${PATCH_NAME}"
fi

echo "Source  : $SRC_TAG"
echo "Dest    : $DST_TAG"
echo "Patch   : $PATCH_NAME"
echo ""

# ---------------------------------------------------------------------------
# Start Postgres from the source image.
# PGDATA=/pgdata keeps data outside the declared VOLUME so docker commit
# captures it.
# ---------------------------------------------------------------------------

echo "Starting container from $SRC_TAG..."
CONTAINER=$(docker run -d \
    --shm-size=256m \
    --stop-timeout=120 \
    -e POSTGRES_USER="$PG_USER" \
    -e POSTGRES_PASSWORD="$PG_PASSWORD" \
    -e POSTGRES_DB="$PG_DB" \
    -e PGDATA=/pgdata \
    "$SRC_TAG")

cleanup() {
    echo "Removing container $CONTAINER..." >&2
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Waiting for Postgres to be ready..."
for i in $(seq 1 120); do
    if docker exec "$CONTAINER" pg_isready -U "$PG_USER" -d "$PG_DB" 2>/dev/null | grep -q 'accepting connections'; then break; fi
    if [[ $i -eq 120 ]]; then echo "error: Postgres not ready after 60s" >&2; exit 1; fi
    sleep 0.5
done
sleep 2
echo "Postgres ready."

# ---------------------------------------------------------------------------
# Apply patch
# ---------------------------------------------------------------------------

case "$PATCH_NAME" in
    jsonb)
        echo "Applying patch: JSONB migration + targeted indexes..."
        docker exec -i -e PGPASSWORD="$PG_PASSWORD" "$CONTAINER" \
            psql --host localhost --username "$PG_USER" --dbname "$PG_DB" << 'SQL'
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
SQL
        echo "Patch applied."
        ;;
    rescoring-indexes)
        echo "Applying patch: rescoring expression indexes..."
        docker exec -i -e PGPASSWORD="$PG_PASSWORD" "$CONTAINER" \
            psql --host localhost --username "$PG_USER" --dbname "$PG_DB" << 'SQL'
CREATE INDEX IF NOT EXISTS ix_artefact_metadata_rescoring_vuln_key
    ON artefact_metadata ((data->'finding'->>'cve'), (data->'finding'->>'package_name'))
    WHERE type = 'rescoring';

CREATE INDEX IF NOT EXISTS ix_artefact_metadata_rescoring_license_key
    ON artefact_metadata ((data->'finding'->'license'->>'name'), (data->'finding'->>'package_name'))
    WHERE type = 'rescoring';

ANALYZE artefact_metadata;
SQL
        echo "Patch applied."
        ;;
    group-key-hash)
        echo "Applying patch: finding_group_key generated column (findings + rescorings)..."
        docker exec -i -e PGPASSWORD="$PG_PASSWORD" "$CONTAINER" \
            psql --host localhost --username "$PG_USER" --dbname "$PG_DB" << 'SQL'
-- Drop and recreate to pick up the extended CASE that covers rescoring rows too.
ALTER TABLE artefact_metadata DROP COLUMN IF EXISTS finding_group_key;

ALTER TABLE artefact_metadata
    ADD COLUMN finding_group_key text GENERATED ALWAYS AS (
        md5(CASE
            -- finding rows: identity fields stored flat in data
            WHEN type = 'finding/vulnerability' THEN
                coalesce(data->>'cve', 'None') || '|' || coalesce(data->>'package_name', 'None')
            WHEN type = 'finding/license' THEN
                coalesce(data->'license'->>'name', 'None') || '|' || coalesce(data->>'package_name', 'None')
            WHEN type = 'finding/ip' THEN
                coalesce(data->>'package_name', 'None')
            WHEN type = 'finding/sast' THEN
                coalesce(data->>'sast_status', 'None') || '|' || coalesce(data->>'sub_type', 'None')
            WHEN type = 'finding/codeql' THEN
                coalesce(data->>'codeql_status', 'None') || '|' || coalesce(data->>'repo_url', 'None') || '|' || coalesce(data->>'language', 'None')
            WHEN type = 'finding/osid' THEN
                coalesce(data->'osid'->>'ID', 'None')
            WHEN type = 'finding/malware' THEN
                coalesce(data->'finding'->>'content_digest', 'None') || '|' || coalesce(data->'finding'->>'filename', 'None') || '|' || coalesce(data->'finding'->>'malware', 'None')
            WHEN type = 'finding/diki' THEN
                coalesce(data->>'provider_id', 'None') || '|' || coalesce(data->>'ruleset_id', 'None') || '|' || coalesce(data->>'rule_id', 'None')
            WHEN type = 'finding/ghas' THEN
                coalesce(data->>'html_url', 'None')
            WHEN type IN ('finding/falco', 'finding/kyverno') THEN
                coalesce(data->'finding'->>'group_hash', 'None')
            -- rescoring rows: identity fields nested under data->'finding'
            WHEN type = 'rescorings' AND referenced_type = 'finding/vulnerability' THEN
                coalesce(data->'finding'->>'cve', 'None') || '|' || coalesce(data->'finding'->>'package_name', 'None')
            WHEN type = 'rescorings' AND referenced_type = 'finding/license' THEN
                coalesce(data->'finding'->'license'->>'name', 'None') || '|' || coalesce(data->'finding'->>'package_name', 'None')
            WHEN type = 'rescorings' AND referenced_type = 'finding/ip' THEN
                coalesce(data->'finding'->>'package_name', 'None')
            WHEN type = 'rescorings' AND referenced_type = 'finding/sast' THEN
                coalesce(data->'finding'->>'sast_status', 'None') || '|' || coalesce(data->'finding'->>'sub_type', 'None')
            WHEN type = 'rescorings' AND referenced_type = 'finding/codeql' THEN
                coalesce(data->'finding'->>'codeql_status', 'None') || '|' || coalesce(data->'finding'->>'repo_url', 'None') || '|' || coalesce(data->'finding'->>'language', 'None')
            WHEN type = 'rescorings' AND referenced_type = 'finding/osid' THEN
                coalesce(data->'finding'->'osid'->>'ID', 'None')
            WHEN type = 'rescorings' AND referenced_type = 'finding/malware' THEN
                coalesce(data->'finding'->>'content_digest', 'None') || '|' || coalesce(data->'finding'->>'filename', 'None') || '|' || coalesce(data->'finding'->>'malware', 'None')
            WHEN type = 'rescorings' AND referenced_type = 'finding/diki' THEN
                coalesce(data->'finding'->>'provider_id', 'None') || '|' || coalesce(data->'finding'->>'ruleset_id', 'None') || '|' || coalesce(data->'finding'->>'rule_id', 'None')
            WHEN type = 'rescorings' AND referenced_type = 'finding/ghas' THEN
                coalesce(data->'finding'->>'html_url', 'None')
            WHEN type = 'rescorings' AND referenced_type IN ('finding/falco', 'finding/kyverno') THEN
                coalesce(data->'finding'->>'group_hash', 'None')
            ELSE NULL
        END)
    ) STORED;

-- Index for finding lookups (unchanged)
CREATE INDEX IF NOT EXISTS ix_artefact_metadata_finding_group_key
    ON artefact_metadata (finding_group_key)
    WHERE finding_group_key IS NOT NULL;

-- Index for the rescoring side of the LATERAL join:
-- WHERE type='rescorings' AND referenced_type=? AND finding_group_key=?
CREATE INDEX IF NOT EXISTS ix_artefact_metadata_rescoring_group_key
    ON artefact_metadata (finding_group_key, referenced_type, component_name)
    WHERE type = 'rescorings' AND finding_group_key IS NOT NULL;

-- Stored column for severity (avoids JSONB extraction in the query hot path)
ALTER TABLE artefact_metadata
    ADD COLUMN IF NOT EXISTS severity text GENERATED ALWAYS AS (data->>'severity') STORED;

-- Extended global_scope index: add artefact_version so gardenlinux-style global-version
-- findings can be narrowed to a specific version without scanning all global-scope rows.
DROP INDEX IF EXISTS ix_artefact_metadata_global_scope;
CREATE INDEX ix_artefact_metadata_global_scope
    ON artefact_metadata (component_name, artefact_name, artefact_version, type, datasource)
    WHERE component_version IS NULL;

-- Update severity index to use the stored column instead of an expression
DROP INDEX IF EXISTS ix_artefact_metadata_severity;
CREATE INDEX ix_artefact_metadata_severity
    ON artefact_metadata (component_name, component_version, type, datasource, severity);

ANALYZE artefact_metadata;
SQL
        echo "Patch applied."
        ;;
    *)
        echo "error: unknown patch '$PATCH_NAME' (available: jsonb, rescoring-indexes, group-key-hash)" >&2; exit 1 ;;
esac

# ---------------------------------------------------------------------------
# Stop Postgres cleanly — pg_ctl fast-stop runs a checkpoint first, so all
# dirty pages are flushed before the process exits. Poll until Postgres stops
# accepting connections, then wait for pg_ctl to exit cleanly.
# ---------------------------------------------------------------------------

echo "Stopping Postgres cleanly (checkpoint may take a moment)..."
docker exec -u postgres "$CONTAINER" \
    pg_ctl stop -D /pgdata -m fast -t 120 -w &
PG_CTL_PID=$!
for i in $(seq 1 240); do
    if ! docker exec "$CONTAINER" pg_isready -U "$PG_USER" -d "$PG_DB" 2>/dev/null | grep -q 'accepting connections'; then
        echo "Postgres stopped."
        break
    fi
    if [[ $i -eq 240 ]]; then echo "error: Postgres did not stop after 120s" >&2; exit 1; fi
    sleep 0.5
done
wait "$PG_CTL_PID" || true

echo "Committing image as $DST_TAG..."
IMAGE_ID=$(docker commit \
    --change "ENV POSTGRES_USER=${PG_USER}" \
    --change "ENV POSTGRES_PASSWORD=${PG_PASSWORD}" \
    --change "ENV POSTGRES_DB=${PG_DB}" \
    --change "ENV PGDATA=/pgdata" \
    "$CONTAINER" \
    "$DST_TAG")

echo ""
echo "Done.  $DST_TAG  ($IMAGE_ID)"
echo "Run the perf tests with:"
echo "  ODG_DB_IMAGE=$DST_TAG uv run pytest test/perf/"
