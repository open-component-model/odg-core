"""
HTTP server metrics for aiohttp, emitted via the OpenTelemetry Metrics SDK.

Replaces the former prometheus_client implementation (middleware/prometheus.py).
Metric names follow the OTel HTTP semantic conventions, so the collector's
Prometheus exporter converts them into the standard shape:

    OTEL                                     → Prometheus exposition
    http.server.duration (Histogram, s)      → http_server_duration_seconds_bucket/_sum/_count
    http.server.active_requests (UpDown)     → http_server_active_requests
    http.server.request.count (Counter)      → http_server_request_count_total

This module's `add_http_metrics_middleware()` is independent of the telemetry
setup: when `OTEL_EXPORTER_OTLP_ENDPOINT` is unset (local dev, tests) the
MeterProvider has no exporter attached and all instruments are silent no-ops.
Instrument creation is therefore safe to run always; only shipping needs
`configure_telemetry()` to have set up a MeterProvider.
"""

import asyncio
import datetime

import aiohttp.typedefs
import aiohttp.web
import aiohttp.web_exceptions
import structlog
from opentelemetry import metrics
from opentelemetry.metrics import Counter
from opentelemetry.metrics import Histogram
from opentelemetry.metrics import UpDownCounter


logger = structlog.get_logger(__name__)

# aiohttp app storage keys
APP_HTTP_SERVER_ACTIVE_REQUESTS: aiohttp.web.AppKey[UpDownCounter] = aiohttp.web.AppKey(
    'http.server.active_requests',
    UpDownCounter,
)
APP_HTTP_SERVER_DURATION: aiohttp.web.AppKey[Histogram] = aiohttp.web.AppKey(
    'http.server.duration',
    Histogram,
)
APP_HTTP_SERVER_QUEUE_DURATION: aiohttp.web.AppKey[Histogram] = aiohttp.web.AppKey(
    'http.server.request.queue_duration',
    Histogram,
)
APP_HTTP_SERVER_REQUEST_COUNT: aiohttp.web.AppKey[Counter] = aiohttp.web.AppKey(
    'http.server.request.count',
    Counter,
)
SLOW_REQUEST_THRESHOLD_SECONDS = 30.0

# endpoint attribute used for requests that did not match any registered route
UNMATCHED_ENDPOINT = 'unmatched'


def endpoint_label(request: aiohttp.web.Request) -> str:
    """
    Return the matched route's canonical pattern (e.g. `/os/{os_id}/branches`) as endpoint
    attribute. Using the raw request path would create a persistent metric series per
    distinct path (cardinality explosion).
    """
    if (resource := request.match_info.route.resource) is not None:
        return resource.canonical
    return UNMATCHED_ENDPOINT


def add_http_metrics_middleware(
    app: aiohttp.web.Application,
) -> aiohttp.web.Application:
    """
    Record OTel HTTP server metrics per request (duration histogram,
    in-flight gauge, request counter) and store the instruments on the aiohttp
    app. Safe with or without a configured MeterProvider.

    Must run before `aiohttp.web` starts serving; typically called once with
    the populated application, like the auth/prometheus middlewares.
    """

    # depth of the per-route in-flight stack when a new request arrives.
    # aiohttp is single-threaded; no locking needed.
    inflight_depths: dict[tuple[str, str], int] = {}

    @aiohttp.web.middleware
    async def middleware(
        request: aiohttp.web.Request,
        handler: aiohttp.typedefs.Handler,
    ) -> aiohttp.web.StreamResponse:
        start_time = datetime.datetime.now()
        endpoint = endpoint_label(request)
        method = request.method
        request_key = (endpoint, method)
        attrs = {'http.route': endpoint, 'http.request.method': method}

        # queue-wait heuristic: time spent behind this many already in-flight
        # requests for the same route. Real scheduling time is aiohttp-internal
        # and not observable; this depth-relative proxy is what the old
        # prometheus gauge approximated too. depth 0 = no wait.
        depth = inflight_depths.get(request_key, 0)
        inflight_depth = inflight_depths[request_key] = depth + 1
        request.app[APP_HTTP_SERVER_ACTIVE_REQUESTS].add(1, attrs)
        if depth > 0:
            request.app[APP_HTTP_SERVER_QUEUE_DURATION].record(float(depth), attrs)

        status = None
        response = None
        try:
            response = await handler(request)
            # handler may return None if the client disconnected mid-flight
            status = response.status if response is not None else 'disconnected'
        except aiohttp.web_exceptions.HTTPException as e:
            status = e.status
            raise
        except asyncio.CancelledError, GeneratorExit:
            status = 'cancelled'
            raise
        except BaseException:
            status = 'error'
            raise
        finally:
            inflight_depths[request_key] = inflight_depth - 1
            latency_seconds = (datetime.datetime.now() - start_time).total_seconds()

            request.app[APP_HTTP_SERVER_ACTIVE_REQUESTS].add(-1, attrs)
            request.app[APP_HTTP_SERVER_DURATION].record(latency_seconds, attrs)

            if status is not None:
                request.app[APP_HTTP_SERVER_REQUEST_COUNT].add(
                    1,
                    {**attrs, 'http.response.status_code': str(status)},
                )

            if latency_seconds > SLOW_REQUEST_THRESHOLD_SECONDS:
                logger.warning(
                    # %r keeps client-controlled control characters (e.g. CR/LF) escaped
                    f'slow request: {method!r} {request.path!r} took '
                    f'{latency_seconds:.1f}s ({status=})',
                )

        return response

    meter = metrics.get_meter('odg.http')

    app[APP_HTTP_SERVER_DURATION] = meter.create_histogram(
        name='http.server.duration',
        unit='s',
        description='HTTP server request duration, in seconds',
    )
    app[APP_HTTP_SERVER_ACTIVE_REQUESTS] = meter.create_up_down_counter(
        name='http.server.active_requests',
        description='Number of in-flight HTTP server requests',
    )
    app[APP_HTTP_SERVER_REQUEST_COUNT] = meter.create_counter(
        name='http.server.request.count',
        description='Total number of HTTP server requests',
    )
    app[APP_HTTP_SERVER_QUEUE_DURATION] = meter.create_histogram(
        name='http.server.request.queue_duration',
        description=(
            'Per-route in-flight depth when a request started (proxy for time '
            'spent waiting for a free handler slot)'
        ),
    )

    app.middlewares.insert(0, middleware)

    return app
