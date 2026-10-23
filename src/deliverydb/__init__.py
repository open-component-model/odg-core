import orjson
import sqlalchemy
import sqlalchemy.dialects.postgresql as sap
import sqlalchemy.ext.asyncio as sqlasync
import sqlalchemy.orm.session
from psycopg.types.json import set_json_dumps, set_json_loads

import deliverydb.model as dm

set_json_loads(orjson.loads)
set_json_dumps(orjson.dumps)


def do_raise(self):
    raise RuntimeError('JSONB is not allowed, use JSON instead')


# prevent usage of postgresql exclusive `JSONB`
sap.JSONB.__init__ = do_raise

# pool configuration for low-priority sessions (small pool, long timeout)
DB_POOL_LOW_PRIO_SIZE = 2
DB_POOL_LOW_PRIO_MAX_OVERFLOW = 1
DB_POOL_LOW_PRIO_TIMEOUT = 300

sessionmakers_async: dict[
    tuple[int, int, int],
    sqlasync.async_sessionmaker[sqlasync.session.AsyncSession],
] = {}

sessionmakers: dict[
    tuple[int, int, int],
    sqlalchemy.orm.sessionmaker[sqlalchemy.orm.session.Session],
] = {}


async def _sqlalchemy_sessionmaker_async(
    db_url: str,
    pool_size: int = 5,
    max_overflow: int = 10,
    pool_timeout: int = 30,
) -> sqlasync.async_sessionmaker[sqlasync.session.AsyncSession]:
    # don't use regular caching here to prevent issues with coroutines as return type
    if sessionmaker := sessionmakers_async.get((pool_size, max_overflow, pool_timeout)):
        return sessionmaker

    engine = sqlasync.create_async_engine(
        db_url,
        echo=False,
        future=True,
        pool_pre_ping=True,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout=pool_timeout,
        connect_args={
            # Kill sessions left idle-in-transaction after 30 min to prevent lock storms.
            'options': '-c idle_in_transaction_session_timeout=1800000',
        },
    )

    async with engine.begin() as conn:
        await conn.run_sync(dm.Base.metadata.create_all)

    sessionmaker = sqlasync.async_sessionmaker(bind=engine)
    sessionmakers_async[(pool_size, max_overflow, pool_timeout)] = sessionmaker

    return sessionmaker


async def sqlalchemy_session_async(
    db_url: str,
    pool_size: int = 5,
    max_overflow: int = 10,
    pool_timeout: int = 30,
) -> sqlasync.session.AsyncSession:
    """
    Caller must close database-session.

    Using session object managed by `middleware.db_session_middleware` middleware is the preferred
    way to obtain a database-session.
    """
    sessionmaker = await _sqlalchemy_sessionmaker_async(
        db_url=db_url,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout=pool_timeout,
    )

    return sessionmaker()


def _sqlalchemy_sessionmaker(
    db_url: str,
    pool_size: int = 5,
    max_overflow: int = 10,
    pool_timeout: int = 30,
) -> sqlalchemy.orm.sessionmaker[sqlalchemy.orm.session.Session]:
    if sessionmaker := sessionmakers.get((pool_size, max_overflow, pool_timeout)):
        return sessionmaker

    engine = sqlalchemy.create_engine(
        db_url,
        echo=False,
        future=True,
        pool_pre_ping=True,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout=pool_timeout,
        connect_args={
            'options': '-c idle_in_transaction_session_timeout=1800000',
        },
    )

    dm.Base.metadata.create_all(engine)

    sessionmaker = sqlalchemy.orm.sessionmaker(bind=engine)
    sessionmakers[(pool_size, max_overflow, pool_timeout)] = sessionmaker

    return sessionmaker


def sqlalchemy_session(
    db_url: str,
    pool_size: int = 5,
    max_overflow: int = 10,
    pool_timeout: int = 30,
) -> sqlalchemy.orm.session.Session:
    """
    Caller must close database-session.
    """
    sessionmaker = _sqlalchemy_sessionmaker(
        db_url=db_url,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout=pool_timeout,
    )

    return sessionmaker()
