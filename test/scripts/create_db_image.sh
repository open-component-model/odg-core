#!/usr/bin/env bash
# Create a local Docker image from a DB backup for fast perf-test startup.
#
# Usage (from repo root):
#
#   test/scripts/create_db_image.sh --db data/delivery-db-backup/2026-10-26
#
# The image tag defaults to odg-test-db:latest, override with --tag.
# Override credentials with ODG_TEST_DB_USER / ODG_TEST_DB_PASSWORD / ODG_TEST_DB_NAME.

set -euo pipefail

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------

DB_PATH=""
PG_IMAGE="postgres:17"
TAG="odg-test-db:latest"
PG_USER="${ODG_TEST_DB_USER:-odg-user}"
PG_PASSWORD="${ODG_TEST_DB_PASSWORD:-changeme}"
PG_DB="${ODG_TEST_DB_NAME:-odg-db}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --db)   DB_PATH="$(cd "$2" && pwd)"; shift 2 ;;
        --tag)  TAG="$2";                    shift 2 ;;
        *)      echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$DB_PATH" ]]; then
    echo "error: --db <backup-path> is required" >&2
    exit 1
fi
if [[ ! -d "$DB_PATH" ]]; then
    echo "error: backup not found: $DB_PATH" >&2
    exit 1
fi

echo "DB backup : $DB_PATH"
echo "Image tag : $TAG"
echo "Credentials: user=$PG_USER db=$PG_DB"
echo ""

# ---------------------------------------------------------------------------
# Start Postgres with PGDATA=/pgdata so the data directory is outside the
# declared VOLUME (/var/lib/postgresql/data) and survives docker commit.
# ---------------------------------------------------------------------------

echo "Starting Postgres container..."
CONTAINER=$(docker run -d \
    --shm-size=256m \
    --stop-timeout=120 \
    -p 5432 \
    -v "${DB_PATH}:/backup:ro" \
    -e POSTGRES_USER="$PG_USER" \
    -e POSTGRES_PASSWORD="$PG_PASSWORD" \
    -e POSTGRES_DB="$PG_DB" \
    -e PGDATA=/pgdata \
    "$PG_IMAGE" \
    postgres \
        -c max_wal_size=2GB \
        -c checkpoint_completion_target=0.9 \
        -c synchronous_commit=off)

cleanup() {
    echo "Removing container $CONTAINER..." >&2
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Waiting for Postgres to be ready..."
for i in $(seq 1 60); do
    if docker exec "$CONTAINER" pg_isready -U "$PG_USER" -d "$PG_DB" 2>/dev/null | grep -q 'accepting connections'; then break; fi
    if [[ $i -eq 60 ]]; then echo "error: Postgres not ready after 30s" >&2; exit 1; fi
    sleep 0.5
done
# Brief extra wait for pg_hba.conf and WAL to settle after pg_isready reports ready
sleep 2
echo "Postgres ready."

# ---------------------------------------------------------------------------
# Restore (pg_restore runs inside the container against the mounted backup)
# ---------------------------------------------------------------------------

echo "Running pg_restore inside container (parallel, -j4)..."
docker exec -e PGPASSWORD="$PG_PASSWORD" "$CONTAINER" \
    pg_restore \
        --host localhost \
        --username "$PG_USER" \
        --dbname "$PG_DB" \
        --no-owner \
        --no-privileges \
        -j 4 \
        /backup
echo "Restore complete."

# ---------------------------------------------------------------------------
# Prepare data for perf tests:
#   1. Clear the cache — entries contain internal OCI registry URLs; tests
#      resolve descriptors from public OCI at runtime, so a cold cache is needed.
#   2. Rewrite component names
# ---------------------------------------------------------------------------

echo "Preparing DB for perf tests..."
docker exec -i -e PGPASSWORD="$PG_PASSWORD" "$CONTAINER" \
    psql --host localhost --username "$PG_USER" --dbname "$PG_DB" <<'SQL'
TRUNCATE cache;

-- Rewrite gardenlinux component names
UPDATE artefact_metadata
    SET component_name = 'github.com/gardenlinux/gardenlinux'
    WHERE component_name LIKE '%gardenlinux%'
      AND component_name NOT LIKE 'github.com/%';
SQL
echo "DB prepared."

# ---------------------------------------------------------------------------
# Stop Postgres cleanly, commit image
# ---------------------------------------------------------------------------

echo "Stopping Postgres cleanly (may take a minute to flush dirty pages)..."
# Run pg_ctl in the background and poll from the host so memory pressure
# cannot SIGKILL this script while the checkpoint is running.
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

echo "Committing image as $TAG..."
IMAGE_ID=$(docker commit \
    --change "ENV POSTGRES_USER=${PG_USER}" \
    --change "ENV POSTGRES_PASSWORD=${PG_PASSWORD}" \
    --change "ENV POSTGRES_DB=${PG_DB}" \
    --change "ENV PGDATA=/pgdata" \
    "$CONTAINER" \
    "$TAG")

echo ""
echo "Done.  $TAG  ($IMAGE_ID)"
echo "Run the perf tests with:  uv run pytest test/perf/ ..."
