# Alembic migrations for the delivery-db

Alembic owns the delivery-db schema defined in `src/deliverydb/model.py`.
For a hands-on walkthrough, see `TUTORIAL.md`.

## How migrations run in production

The delivery-service Deployment has the init container `delivery-service-migrate`
(`charts/delivery-service/templates/deployment.yaml`). It runs
`python3 -m migrations.bootstrap` before every pod start. `bootstrap.py` detects the
database state:

| DB state                                          | Action                                 |
| ------------------------------------------------- | -------------------------------------- |
| has `alembic_version`                             | `upgrade head`                         |
| has model tables, no `alembic_version` (legacy)   | `stamp cc90ad81441c` (the schema `create_all` produced), then `upgrade head` |
| empty                                             | `upgrade head`                         |

Afterwards, bootstrap verifies that the database is at head.

Re-running is safe: `upgrade head` on a database at head is a no-op.

Concurrent init containers are serialised by a session-scoped Postgres advisory lock
in `env.py`. A crashed migration releases the lock when its connection drops.

## Long-running migrations

`env.py` sets `lock_timeout = '5min'` on the migration connection. This bounds only
**waits for locks** (the advisory lock and table locks taken by DDL). It does **not**
bound statement execution: no `statement_timeout` and no init container deadline exist.

If a backfill holds the advisory lock past 5 minutes, a concurrent init container fails
with a lock-timeout error and restarts (`Init:CrashLoopBackOff`). It never runs its
own migration in parallel; the rollout just stalls until the first container releases
the lock. Run such backfills manually against the live database, outside of alembic,
during a maintenance window.

## Schema change workflow

1. Edit `src/deliverydb/model.py`.
2. Port-forward a database that is at head:
   `kubectl port-forward -n odg svc/delivery-db 55434:5432`
3. Generate the revision (from `src/`):

   ```bash
   uv run --project .. alembic -c migrations/alembic.ini \
       -x db_url=postgresql+psycopg://postgres:password-123@localhost:55434/postgres \
       revision --autogenerate -m "short description"
   ```

4. Review the file. Autogenerate does not detect renames (rewrite drop/add as
   `op.rename_table` / `op.alter_column(..., new_column_name=...)`) or data migrations.
5. Commit the model change and the revision together. The next pod start applies it.

## Useful commands

Run from `src/`. Pass the DB URL via `-x db_url=...` or `DELIVERY_DB_URL`.

- Current revision: `alembic -c migrations/alembic.ini -x db_url=... current`
- History: `alembic -c migrations/alembic.ini history`
- Roll back one step: `alembic -c migrations/alembic.ini -x db_url=... downgrade -1`
- Drift check: `alembic -c migrations/alembic.ini -x db_url=... revision --autogenerate -m check`
  must produce an empty revision. Delete it afterwards.

## Rules

- **Never edit applied revisions.** Alembic tracks revision ids, not file content.
  Create a new revision instead.
- **Name every index.** Unnamed indexes are excluded from autogenerate
  (`migrations.include_object`) because their auto-generated names differ between runs.
- **Do not reintroduce `create_all`.** It masks schema drift.
- **Failed migrations** show as `Init:CrashLoopBackOff`. Inspect with
  `kubectl logs <pod> -c delivery-service-migrate`, fix the cause; Kubernetes retries.
- **Advisory lock key**: other tools that use advisory locks on the delivery-db must
  pick a different key than `ADVISORY_LOCK_KEY` in `env.py`.
