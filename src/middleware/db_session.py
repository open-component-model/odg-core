import aiohttp.typedefs
import aiohttp.web
import cachetools
import sqlalchemy.exc

import consts
import ctx_util
import deliverydb
import features
import secret_mgmt
import secret_mgmt.delivery_db


@cachetools.cached(cachetools.TTLCache(maxsize=1, ttl=60))
def incluster_db_url() -> str:
    cluster_access_feature = features.get_feature(features.FeatureClusterAccess)

    if (
        not cluster_access_feature
        or cluster_access_feature.state is not features.FeatureStates.AVAILABLE
        or cluster_access_feature.namespace is None
    ):
        return None

    secret_factory = ctx_util.secret_factory()

    try:
        delivery_db_cfgs = secret_factory.delivery_db()
    except secret_mgmt.SecretTypeNotFound:
        return None

    if len(delivery_db_cfgs) != 1:
        raise ValueError(
            f'There must be exactly one delivery-db secret, found {len(delivery_db_cfgs)}',
        )

    delivery_db_cfg: secret_mgmt.delivery_db.DeliveryDB = delivery_db_cfgs[0]
    return delivery_db_cfg.connection_url(
        namespace=cluster_access_feature.namespace,
    )


def db_session_middleware(
    db_url: str | None = None,
) -> aiohttp.typedefs.Middleware:
    """
    Used to centrally manage database-session lifecycle.

    Create session object stored in request-context after request routing, available for all routes.
    Close session object at response post-processing.

    Using database-session from request-context is the preferred way.
    Consumers must still commit / rollback transactions.
    """

    @aiohttp.web.middleware
    async def middleware(
        request: aiohttp.web.Request,
        handler: aiohttp.typedefs.Handler,
    ) -> aiohttp.web.StreamResponse:
        _db_url = db_url or incluster_db_url()

        if not _db_url:
            return await handler(request)

        request[consts.REQUEST_DB_SESSION] = await deliverydb.sqlalchemy_session_async(
            db_url=_db_url,
            pool_timeout=5,
        )
        request[consts.REQUEST_DB_SESSION_LOW_PRIO] = await deliverydb.sqlalchemy_session_async(
            db_url=_db_url,
            pool_size=2,
            max_overflow=1,
            pool_timeout=300,
        )

        try:
            response = await handler(request)
        except sqlalchemy.exc.TimeoutError:
            # 503 error can be reacted upon by a load balancer to forward req to next pod
            raise aiohttp.web.HTTPServiceUnavailable
        except Exception:
            raise
        finally:
            if db_session := request.get(consts.REQUEST_DB_SESSION):
                await db_session.close()
            if db_session_low_prio := request.get(consts.REQUEST_DB_SESSION_LOW_PRIO):
                await db_session_low_prio.close()

        return response

    return middleware
