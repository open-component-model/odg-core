import aiohttp.typedefs
import aiohttp.web

import consts


def cors_headers(
    request: aiohttp.web.Request,
) -> dict:
    # origin is only sent by browsers on cross-origin requests; server-to-server
    # callers (e.g. extension pods via internal DNS) omit it -> no CORS headers
    # Vary: Origin must be set unconditionally so that caches populated by a
    # no-Origin request don't serve that entry to a cross-origin request
    headers = {'Vary': 'Origin'}

    if not (origin := request.headers.get('Origin')):
        return headers

    allow_origins = request.app[consts.APP_ALLOW_ORIGINS]
    if origin not in allow_origins:
        return headers

    if not request.headers.get('Access-Control-Allow-Origin'):
        # every allowed origin is a credentialed origin: the dashboard always
        # sends `credentials: include`, so echo the origin (never '*', which
        # browsers reject for credentialed requests)
        headers['Access-Control-Allow-Origin'] = origin
        headers['Access-Control-Allow-Credentials'] = 'true'

    if request.method == 'OPTIONS' and 'Access-Control-Request-Method' in request.headers:
        allow_methods = request.headers.get('Access-Control-Request-Method')
        allow_headers = request.headers.get('Access-Control-Request-Headers', default='*')

        headers['Access-Control-Allow-Headers'] = allow_headers
        headers['Access-Control-Allow-Methods'] = allow_methods

    return headers


def cors_middleware() -> aiohttp.typedefs.Middleware:

    @aiohttp.web.middleware
    async def middleware(
        request: aiohttp.web.Request,
        handler: aiohttp.typedefs.Handler,
    ) -> aiohttp.web.StreamResponse:
        try:
            response = await handler(request)
        except Exception as e:
            response = e

        response.headers.extend(cors_headers(request=request))

        if request.method == 'OPTIONS':
            # this is a preflight request -> skip processing of this request in other middlewares
            raise aiohttp.web.HTTPOk(headers=response.headers)

        return response

    return middleware


async def _on_response_prepare_handler(
    request: aiohttp.web.Request,
    response: aiohttp.web.StreamResponse,
):
    """
    Signal handler for on_response_prepare to add CORS headers before response is sent.
    This is necessary for StreamResponse where headers must be set before prepare() is called.
    """
    response.headers.update(cors_headers(request=request))
