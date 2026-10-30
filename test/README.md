# Test suite

Tests in `test/perf/` reproduce and validate ODG performance characteristics against a
containerised ODG stack and a pre-built DB image (`odg-test-db:latest`) is required.

## Structure

```
test/
  utils/
    testcontainer_odg.py      # OdgCoreContainer — container lifecycle + profiling
    testcontainer_postgres.py # PostgresContainer — testcontainers wrapper
    snapshot.py               # Snapshot — JSON golden-file assertions (auto-write on first run)
    timer.py                  # timed() — single-shot timing context manager
    load_generator.py         # gen_concurrent_requests() — threaded load driver
    fixtures.py               # pg_connect, load_findings, apply_mutations, request_compliance_summary
  perf/
    conftest.py               # fixtures: odg_stack, write_targets, compliance_targets, components, odg_client, snapshot
    targets.py                # DB query helpers for test targets (write, compliance, query components)
    pytest.ini                # log_cli config
    test_canary.py            # smoke: /ready snapshot, /metrics reachability
    test_compliance_summary.py        # GET /components/compliance-summary — timed + snapshot
    test_artefacts_metadata_query.py  # POST /artefacts/metadata/query — extension read patterns
    test_put_artefacts_metadata.py    # PUT /artefacts/metadata — write throughput + lock-storm
  scripts/
    create_db_image.sh   # build odg-test-db image from a DB backup
```

## Prerequisites

Docker must be running. The debug ODG image must exist locally:

```bash
# From repo root — build once, or after code changes:
make build-core
make build-docker-local ODG_CORE_LIBS_VERSION=$(cat VERSION | cut -d- -f1)
make build-docker-debug-local ODG_CORE_LIBS_VERSION=$(cat VERSION | cut -d- -f1)
```

## One-time setup: build the DB image

Download a DB backup, then run `create_db_image.sh` once to bake it into a local Docker image
to shorten start times of the DB to ~2 seconds:

```bash
ocm download resources \
  -O data/delivery-db-backup/2026-10-26 \
  oci::${REGISTRY}//${NAME}:${VERSION} \
  delivery-db-backup

test/scripts/create_db_image.sh --db data/delivery-db-backup/2026-10-26
```

What the script does:
1. Starts a `postgres:17` container with `PGDATA=/pgdata`
2. Runs `pg_restore -j4` inside the container
3. Truncates the cache table and rewrites internal component names to their public OSS equivalents
4. Stops Postgres cleanly, `docker commit`s the container as `odg-test-db:latest`.

```bash
test/scripts/create_db_image.sh --db data/delivery-db-backup/2026-10-26 --tag odg-test-db:2026-10-26
```

## Run the tests

```bash
cd test/perf
uv run pytest -v
```

Override the DB image or the ODG image:

```bash
cd test/perf
ODG_DB_IMAGE=odg-test-db:2026-10-26 uv run pytest test/perf/ -v
ODG_CORE_IMAGE=odg-core:1.2.3-debug  uv run pytest test/perf/ -v
```

### Profiling

```bash
cd test/perf
uv run pytest test_canary.py -v --profile          # py-spy + memray
uv run pytest test_canary.py -v --profile pyspy    # py-spy only
uv run pytest test_canary.py -v --profile memray   # memray only
```

Output files (py-spy speedscope JSON, memray binary, container log) are written to a
temporary directory logged at the end of the run.

### Snapshots

`Snapshot` auto-writes on first run and asserts equality on subsequent runs.
Delete the file under `perf/snapshots/` to regenerate (e.g. after a DB image rebuild or a code change that affects output).
