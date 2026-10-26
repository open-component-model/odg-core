# Alembic migrations for the delivery-db

This directory contains the Alembic migration environment for the delivery-db
schema owned by `src/deliverydb/model.py`.

## How migrations are applied in production

`charts/delivery-service/templates/migration-job.yaml` defines a Helm
pre-install/pre-upgrade hook that runs `python3 -m migrations.bootstrap` on
every `helm install` / `helm upgrade`.

`bootstrap.py` auto-detects the database state:

| DB state                                    | Action          |
| ------------------------------------------- | --------------- |
| has `alembic_version` table                 | `upgrade head`  |
| has tables but no `alembic_version` (legacy `create_all` era) | `stamp head` |
| empty                                       | `upgrade head`  |

If the job fails, the Helm release fails and the failed Job stays in the
cluster for `kubectl logs`. This is intentional — do not add
`hook-delete-policy`.

## Running migrations repeatedly is safe

Like `create_all` before it, alembic is idempotent at the level that matters:

- `alembic upgrade head` on a database that is already at head is a no-op
  (alembic compares the `alembic_version` table against the target revision
  and runs nothing).
- `src/migrations/bootstrap.py` is itself state-aware and may be re-run any
  number of times; it stamps or upgrades once and then keeps no-oping.
- Because every `helm upgrade` runs the hook Job again, schema changes
  ordered after a release are picked up on the next rollout automatically.
  There is no harm in redeploying the same chart version many times.

Compared to `create_all`, the differences are in *what* changes are
idempotent: `create_all` only creates missing tables (column changes on
existing tables were silently skipped), while alembic replays each revision
exactly once and never re-applies it.

## Day-to-day schema changes

1. Edit `src/deliverydb/model.py` (add/change/remove columns or tables).
2. Point alembic at any database that currently is at `head` (e.g. the local
   kind cluster via port-forward):

   ```bash
   kubectl port-forward -n odg svc/delivery-db 55434:5432
   ```

3. Autogenerate the revision:

   ```bash
   cd src
   uv run --project .. alembic -c migrations/alembic.ini \
       -x db_url=postgresql+psycopg://postgres:password-123@localhost:55434/postgres \
       revision --autogenerate -m "short description"
   ```

4. Read the generated file. Autogenerate catches column add/drop and type
   changes; it does **not** catch table or column renames (you must rewrite
   the generated drop/add into `op.rename_table`/`op.alter_column(...,
   new_column_name=...)`), nor data migrations.

5. Commit model change and revision file together. The migration is applied
   automatically the next time the delivery-service chart is installed or
   upgraded.

## Local checks

`alembic` needs to know where the ini is and gets the DB URL via `-x` (or
`DELIVERY_DB_URL` env var). All commands run from `src/`:

- Current revision of a DB: `alembic -c migrations/alembic.ini -x db_url=... current`
- History: `alembic -c migrations/alembic.ini history`
- Roll back one step: `alembic -c migrations/alembic.ini -x db_url=... downgrade -1`
- Drift check (model vs. DB): `alembic -c migrations/alembic.ini -x db_url=... revision --autogenerate -m check`
  — must produce an empty revision. Delete it afterwards.

For comparing an existing deployment's schema to the baseline, use
`src/test/get-schema.sql` via `psql`.

## Gotchas worth knowing

- **File naming**: the `file_template` in `alembic.ini` prefixes files with a
  second-precision UTC timestamp (`YYYYMMDD_HHMMSS-<rev>_<slug>.py`), so
  `ls versions/` is chronological.  Alembic only needs the revision hash, the
  rest of the filename is for humans.
- **Never edit old revisions that have been applied anywhere.** Alembic
  tracks state by revision id, not by file content — changing the file after
  it was applied does not re-run it. Make a new revision instead.
- **Renames**: autogenerate produces `drop_column` + `add_column` for
  renames. If you need the data preserved, rewrite by hand as `op.alter_column()`.
- **Index with `name=None`**: `ArtefactMetaData` has an index declared with
  `sa.Index(None, ...)`. SQLAlchemy auto-names it `ix_artefact_metadata_component_name`
  (after the first column).  `env.py` excludes unnamed indexes from
  autogenerate to avoid perpetual drop/re-add churn.  If you add indexes,
  give them explicit names.
- **Don't bring back `create_all`**: the two calls were removed from
  `src/deliverydb/__init__.py`. The schema is owned by Alembic alone. Adding
  a `create_all` back would mask drift risk again (works in dev, burns you in
  prod).
- **Failed Helm hook Jobs stay around**: `helm upgrade` will refuse to run
  again until the failed Job is deleted
  (`kubectl delete job delivery-service-migrate -n odg`). This is by design,
  so failures are visible in `helm` and `kubectl` output — there is no
  `hook-delete-policy` annotation.
- **NetworkPolicies**: the Job reuses the `app: delivery-service` pod label
  so it is covered by the existing `allow-egress-from-delivery-service`
  NetworkPolicy.  Renaming the label requires adjusting the chart
  accordingly.
- **Secret rotation**: the Job mounts `secret-factory-delivery-db`. If the
  bootstrap reports secret-related errors, verify the Secret exists and has
  exactly one element (`kubectl get secret secret-factory-delivery-db -o yaml`).
