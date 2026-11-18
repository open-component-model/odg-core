"""
Audit middleware for the delivery service: emits one audit event for every mutating HTTP
request (POST/PUT/PATCH/DELETE), regardless of whether handlers add more detailed events.

The middleware must be registered *before* the auth middleware in the middleware chain, so
that requests rejected by the auth middleware (401/403) are still audited. Those requests
simply carry no `user_id` (the auth middleware never ran far enough to set it).

Read-only requests (GET/HEAD/OPTIONS and read-by-POST query routes) are skipped: they make
up the bulk of traffic and carry no audit value.
"""

import aiohttp.typedefs
import aiohttp.web

import consts
import odg.audit

# methods that never mutate delivery-db state; audit-relevant events are write-side only
IMMUTABLE_METHODS = frozenset({'get', 'head', 'options'})

# POST routes that are read-only queries (batched queries use request bodies -> POST); they
# are excluded from request-level audit events
READ_ONLY_POST_ROUTE_PARTS = ('query', 'diff')

_DENIED_STATUSES = frozenset({401, 403})


def audit_middleware() -> aiohttp.typedefs.Middleware:

    @aiohttp.web.middleware
    async def middleware(
        request: aiohttp.web.Request,
        handler: aiohttp.typedefs.Handler,
    ) -> aiohttp.web.StreamResponse:
        if request.method.lower() in IMMUTABLE_METHODS:
            return await handler(request)

        # may be None for unmatched routes (404); use the template to bound field cardinality
        resource = request.match_info.route.resource
        route = resource.canonical if resource else request.path

        if request.method.lower() == 'post' and any(
            part.lower() in route.lower() for part in READ_ONLY_POST_ROUTE_PARTS
        ):
            return await handler(request)

        status: int | None = None

        try:
            response = await handler(request)
            status = response.status
            return response
        except aiohttp.web.HTTPException as e:
            status = e.status
            raise
        finally:
            if status is None or status >= 500:
                outcome = odg.audit.Outcome.ERROR
            elif status in _DENIED_STATUSES:
                outcome = odg.audit.Outcome.DENIED
            elif status >= 400:
                outcome = odg.audit.Outcome.ERROR
            else:
                outcome = odg.audit.Outcome.ALLOWED

            odg.audit.emit(
                action='request_write',
                msg=f'audit {request.method} {route}',
                # the inner auth middleware sets the user id; absent for rejected/anonymous requests
                user_id=request.get(consts.REQUEST_USER_ID),
                url_full=route,
                odg_audit_target=f'{request.method.upper()} {route}',
                odg_audit_outcome=outcome,
                odg_audit_detail={'http_status': status},
            )

    return middleware
