"""
Entry script for the delivery-service migration job.

Legacy databases (schema previously managed by `create_all`) are stamped at the
baseline revision, then every database is upgraded to head. Afterwards the
revision is verified against the checked-out head.

Usage:
    python3 -m migrations.bootstrap
"""

import logging
import os

import sqlalchemy

from alembic.config import main as alembic_main
import alembic.migration

import migrations
import deliverydb.model
import odg.logging_cfg


logger = logging.getLogger('odg.migrations')


def _db_url() -> str:
    """
    Simplified variant of the URL resolution in migrations/env.py, sufficient for
    in-cluster runs: read the mounted delivery-db secret.
    """
    import secret_mgmt
    import secret_mgmt.delivery_db

    secret_factory_path = os.environ.get('SECRET_FACTORY_PATH', '/secrets')
    secret_factory = secret_mgmt.SecretFactory.from_dir(secrets_dir=secret_factory_path)

    delivery_db_cfgs = secret_factory.delivery_db()
    if len(delivery_db_cfgs) != 1:
        raise ValueError(f'expected exactly one delivery-db secret, found {len(delivery_db_cfgs)}')
    delivery_db_cfg: secret_mgmt.delivery_db.DeliveryDB = delivery_db_cfgs[0]

    namespace = (
        os.environ.get('K8S_TARGET_NAMESPACE')
        # fallback: namespace of the pod this job runs in
        or open(
            '/var/run/secrets/kubernetes.io/serviceaccount/namespace',
        )
        .read()
        .strip()
    )

    return delivery_db_cfg.connection_url(namespace=namespace)


def _current_revision(engine) -> str | None:
    with engine.connect() as connection:
        ctx = alembic.migration.MigrationContext.configure(connection)
        return ctx.get_current_revision()


def _revision_scripts() -> dict[str, str]:
    """Return {revision_id: down_revision_id} of all checked-in alembic revisions."""
    from alembic.script import ScriptDirectory
    from alembic.config import Config

    cfg = Config()
    cfg.set_main_option('script_location', os.path.dirname(migrations.ini_path))
    script = ScriptDirectory.from_config(cfg)
    return {r.revision: r.down_revision for r in script.walk_revisions()}


def _head_revision() -> str:
    """Resolve the head revision from checked-in files."""
    scripts = _revision_scripts()
    parents = set(scripts.values()) - {None}
    heads = set(scripts) - parents
    if len(heads) != 1:
        raise RuntimeError(f'expected exactly 1 head, found: {heads}')
    return next(iter(heads))


def main() -> int:
    db_url = _db_url()
    engine = sqlalchemy.create_engine(db_url)

    with engine.connect() as connection:
        existing_tables = set(sqlalchemy.inspect(connection).get_table_names())

    model_tables = set(deliverydb.model.Base.metadata.tables)
    alembic_managed = 'alembic_version' in existing_tables

    # in-process argv (not visible in the process list); `-x db_url` has the highest
    # precedence in env.py, so alembic targets exactly the database inspected here
    argv = ['-c', migrations.ini_path, '-x', f'db_url={db_url}']

    if alembic_managed:
        logger.info('database is alembic-managed')
    elif model_tables & existing_tables:
        # legacy schema equals the baseline revision; later revisions must still run
        base_revision = 'cc90ad81441c'
        logger.info(
            'schema exists but is not alembic-managed (create_all-era), stamping %s',
            base_revision,
        )
        alembic_main(argv=[*argv, 'stamp', base_revision])
    else:
        logger.info('fresh database')

    logger.info('running upgrade to head')
    alembic_main(argv=[*argv, 'upgrade', 'head'])

    # post-condition: the database must now reflect checked-in head.
    # This catches silent failures, in particular cases where an open pre-existing
    # transaction caused alembic's begin_transaction() to silently issue no COMMIT.
    logger.info('running post-check: comparing database revision to checked-in head')
    applied = _current_revision(engine)
    expected = _head_revision()
    if applied != expected:
        logger.error(
            'post-check failed: database is at %s, expected %s; the migration was not committed.',
            applied,
            expected,
        )
        raise RuntimeError(
            f'database is at {applied}, expected {expected}; the migration was not committed.',
        )

    logger.info('post-check passed: database is at %s (head)', applied)
    return 0


if __name__ == '__main__':
    odg.logging_cfg.configure_logging(service_name='delivery-db-migration')
    raise SystemExit(main())
