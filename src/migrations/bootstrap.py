"""
Entry script for the delivery-service migration job.

Decides between `alembic stamp head` (existing database whose schema was
previously managed by `create_all`) and `alembic upgrade head` (fresh
database). Afterwards the schema is always at alembic head.

Usage:
    python3 -m migrations.bootstrap
"""

import logging

import sqlalchemy

from alembic.config import main as alembic_main

import migrations
import deliverydb.model


logging.basicConfig(level=logging.INFO, format='%(levelname)-5.5s %(name)s %(message)s')
logger = logging.getLogger(__name__)


def _db_url() -> str:
    """
    Simplified variant of the URL resolution in migrations/env.py, sufficient for
    in-cluster runs: read the mounted delivery-db secret.
    """
    import os

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


def main() -> int:
    engine = sqlalchemy.create_engine(_db_url())

    with engine.connect() as connection:
        existing_tables = set(sqlalchemy.inspect(connection).get_table_names())

    model_tables = set(deliverydb.model.Base.metadata.tables)
    alembic_managed = 'alembic_version' in existing_tables

    argv = ['-c', migrations.ini_path]

    if alembic_managed:
        logger.info('database is alembic-managed, running upgrade to head')
        alembic_main(argv=[*argv, 'upgrade', 'head'])
    elif model_tables & existing_tables:
        logger.info(
            'schema exists but is not alembic-managed (create_all-era), stamping head',
        )
        alembic_main(argv=[*argv, 'stamp', 'head'])
    else:
        logger.info('fresh database, running full upgrade to head')
        alembic_main(argv=[*argv, 'upgrade', 'head'])

    logger.info('done')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
