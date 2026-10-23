import os
from logging.config import fileConfig

from alembic import context
import sqlalchemy

from deliverydb.model import Base


config = context.config
target_metadata = Base.metadata

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _include_object(obj, name, type_, reflected, compare_to) -> bool:
    # exclude unnamed indexes (SQLAlchemy auto-naming differs between
    # create_all and alembic runs and would cause endless drop/re-add diffs)
    if type_ == 'index' and not name:
        return False
    return True


def _db_url() -> str:
    # 1. -x db_url=... passed to the alembic CLI
    db_url = context.get_x_argument(as_dictionary=True).get('db_url')
    if db_url:
        return db_url

    # 2. explicit env var (useful for local runs and debugging)
    if db_url := os.environ.get('DELIVERY_DB_URL'):
        return db_url

    # 3. delivery-db secret mounted into the pod (same as the app uses)
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
        # fallback: current namespace when running inside a pod
        or open(
            '/var/run/secrets/kubernetes.io/serviceaccount/namespace',
        )
        .read()
        .strip()
    )

    return delivery_db_cfg.connection_url(namespace=namespace)


def run_migrations_offline() -> None:
    context.configure(
        url=_db_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        include_object=_include_object,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = sqlalchemy.create_engine(
        _db_url(),
        poolclass=sqlalchemy.pool.NullPool,
    )

    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_object=_include_object,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
