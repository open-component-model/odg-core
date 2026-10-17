---
name: odg-implement-perf-test
description: Write a new ODG performance test for a given issue.
model: sonnet
---

# ODG perf test implementation

You are implementing a perf test for a given issue. Read `test/perf/README.md` for the
test structure, utilities API, and code patterns.

Read `test/perf/<test-suite>/results/TASK.md` for the issue name, symptom, and the endpoint/operation under test.

Write the tests to `test/perf/<test-suite>/test_*.py`

The test suite must reproduce the issue.
It should also cover business logic that might break, with snapshot-tests of API endpoints (input->output)

---

## Seed dump lifecycle

The database is initialized automatically. If a large dataset is needed, we can cache the seed
locally to speed up performance. The dump is generated once and cached as `seed_db.dump`.
To force a fresh seed (e.g. when the seed/sample data changes):

```bash
rm test/perf/<test-suite>/seed_db.dump
```

Re-run — the fixture re-seeds automatically. If the DB schema changed, run migration
tests first.

---

## Done

Once the test is written (or updated), spawn **`odg-run-perf-test`** with the test suite name.

Investigate if the test reproduced the issue from TASK.md

If the run fails (fixture error, import error, container startup), fix the test and retry. Return to the orchestrator if the fix fails.

Report back to the orchestrator:

```markdown
Test Suite: test/perf/<test-suite>
Seeded DB: <yes | no>
Snapshot: <written | already existed>
Changes: <one line summary of what was written or changed>

<!-- one block per test_... function -->
## <test-name>
Status: <pass | fail>
Duration: <seconds>
Memory: VmRSS <start> MiB → <end> MiB  (Δ <+/- diff> MiB)
Captures: memray.bin <present | absent>  pyspy.json <present | absent>
Observation: <optional, one sentence on what is noteworthy>
```
