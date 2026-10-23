# Performance test suite

Tests in `test/perf/` reproduce and validate ODG performance characteristics against a
containerised ODG stack. Each performance topic lives in its own subdirectory with a focused
test and an `expected-*.json` golden snapshot.

## Structure

```
test/perf/
  conftest.py              # pytest options (--keep-containers) + results/ cleanup
  pytest.ini
  utils/
    testcontainer_odg.py   # OdgCoreContainer testcontainers wrapper
    testcontainer_postgres.py
    perf_profiler.py       # PerfProfiler — RSS + Prometheus + tracemalloc
    mock_data.py           # deterministic mock artefacts, CVEs, packages
    snapshots.py           # save/load/diff JSON snapshots
  canary/
    test_canary.py         # smoke test, no data seeding
  <issue-name>/
    seed_db.py             # one-time DB seeding (if needed, auto-invoked)
    test_<issue>.py        # perf test for this issue
    expected-*.json        # golden snapshot (committed)
```

## Prerequisites

```bash
# Build the local image (from repo root)
make build-core
VERSION=$(cat VERSION | sed 's/-dev//')
make build-docker-local ODG_VERSION=$VERSION ODG_CORE_LIBS_VERSION=$VERSION
```

You need Docker running for TestContainers.

## Run the tests

```bash
cd test/perf
uv run pytest <issue-name>/ -v -s
```

For some tests: The first run auto-seeds the database and writes a dump file.
Subsequent runs start a fresh empty container and restore from that cached dump.

## Debugging

```bash
# Leave containers running after the test for manual inspection
uv run pytest <issue-name>/ -v -s --keep-containers
```

---

## Writing a new perf test

### 1. Create the directory

```
test/perf/<issue-name>/
  __init__.py
  seed_db.py
  test_<issue>.py
```

### 2. If needed: Write `seed_db.py`

Seeding populates the database with realistic data via the real ODG API — the same path
production writers use. Use `utils/mock_data.py` for deterministic, reproducible data.
Only use this function if a big dataset needs to be seeded, to speed up repeat runs.

```python
from utils.mock_data import ...
from utils.testcontainer_postgres import PostgresContainer
import odg_client
import random

def seed(base_url: str, ...) -> None:
    rng = random.Random(42)           # fixed seed → reproducible dump
    # ...

def dump(pg: PostgresContainer, dump_path: str) -> None:
    # ...
```

See `compliance_summary/seed_db.py` for a full example.

### 3. Write `test_<issue>.py`

All tests follow this shape:

```python
import pathlib, pytest
from utils.testcontainer_odg import OdgCoreContainer
from utils.testcontainer_postgres import PostgresContainer
from utils.perf_profiler import PerfProfiler
from utils.snapshots import assert_snapshot
import odg_client

DUMP_FILE = pathlib.Path(__file__).parent / 'seed_db.dump'
SNAPSHOT_FILE = pathlib.Path(__file__).parent / 'expected-output.json'
RESULTS_DIR = pathlib.Path(__file__).parent / 'results'


@pytest.fixture(scope='module')
def odg_container(request):
    # 1. Start Postgres
    # 2. If DUMP_FILE exists: start fresh container, restore dump
    #    Otherwise: seed via ODG API, write dump (DB already populated — no restore)
    # 3. Start OdgCoreContainer, wait_ready()
    # 4. Build odg_client, create PerfProfiler, enter it
    # 5. yield (client, prof, odg, pg)
    # 6. Teardown: exit profiler; skip container stop if --keep-containers
    ...


def test_ready(odg_container):
    # GET /ready → 2xx
    ...


def test_my_endpoint(odg_container):
    client, prof, odg, pg = odg_container
    prof.set_test('test_my_endpoint')

    prof.phase('before-load')
    response = ...  # call the endpoint under test
    prof.phase('after-load')

    assert response.status_code == 200
    assert_snapshot(response.json(), SNAPSHOT_FILE)
```

See `canary/test_canary.py` for a lightweight and `compliance_summary/test_compliance_summary.py`
for a full implementation.


### 4. Golden snapshots

`assert_snapshot(actual, path)` writes `path` on the first run (no assertion). On subsequent
runs it diffs the actual output against the stored JSON. Delete `expected-output.json`
deliberately to reset the baseline after a fix that legitimately changes the output.

This is checked into Git.

### 5. Key utilities reference

**`PerfProfiler(container, results_dir)`**

| Method | When to call |
|---|---|
| `set_test(name)` | Once per test function; resets phase counter |
| `phase(label)` | At each measurement point. If py-spy is active, automatically stops+collects the closing phase and restarts for the opening phase. |
| `start_pyspy(rate=100)` | Begin CPU sampling before the phases you want to profile |
| `stop_pyspy()` | Stop sampling and collect the final phase recording |

memray is collected automatically on profiler exit (no call needed) when the container
was started with `memray=True`. py-spy produces one
`results/<image-name>-pyspy-<test>-<seq>-<label>.json` per phase boundary while active.

**`OdgCoreContainer(db_url, ..., memray=False)`**

| Method / param | Purpose |
|---|---|
| `memray=True` | Wrap the process with `memray run` from start; records the entire run to `/tmp/memray.bin` |
| `wait_ready(timeout=60)` | Poll `/ready`; raises `TimeoutError` on timeout |
| `base_url` | `http://localhost:<port>` after `start()` |
| `container_name` | Docker container name |
| `collect_memray(out_dir, filename)` | Copy whole-run capture out (called automatically by profiler) |
| `start_pyspy(rate=100)` | Start py-spy sampling PID 1 in a background thread |
| `stop_pyspy(out_dir, filename)` | Stop py-spy and copy capture out (called automatically by profiler) |

**`PostgresContainer()`**

| Method | Purpose |
|---|---|
| `url` | SQLAlchemy URL for this container |
| `restore(dump_path)` | Restore a `pg_dump` custom-format file |

**`mock_data` helpers**

| Function | Returns |
|---|---|
| `build_variants()` | 36 deterministic artefact variant dicts |
| `make_cve_pool(rng, n)` | `n` unique `BDBAVulnerabilityFinding` objects |
| `make_pkg_pool(rng, n)` | `n` unique `StructureInfo` objects |
| `make_rescorings(cve_pool, pkg_pool, variant, now)` | 9 `ArtefactMetadata` rescoring entries (6 match, 3 don't) |

Always pass `random.Random(42)` as `rng` for a reproducible, committable dump.
