"""
HTTP server metrics for aiohttp, emitted via the OpenTelemetry Metrics SDK.

Replaces the former prometheus_client implementation (middleware/prometheus.py).
Metric names follow the OTel HTTP semantic conventions, so the collector's
Prometheus exporter converts them into the standard shape:

    OTEL                                     → Prometheus exposition
    http.server.request.count (Counter)      → http_server_request_count_total
    http.server.request.queue_depth (Histogram) → http_server_request_queue_depth

Only instruments NOT provided by the aiohttp-server instrumentor are created
here — it already emits `http.server.duration` and
`http.server.active_requests` with broader attributes, so duplicates under the
same instrument name would corrupt aggregations (mixed units for the duration
histogram) after the otel-collector drops the `_source` scope attribute.

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


logger = structlog.get_logger(__name__)

# aiohttp app storage keys
APP_HTTP_SERVER_REQUEST_COUNT: aiohttp.web.AppKey[Counter] = aiohttp.web.AppKey(
    'http.server.request.count',
    Counter,
)
APP_HTTP_SERVER_QUEUE_DEPTH: aiohttp.web.AppKey[Histogram] = aiohttp.web.AppKey(
    'http.server.request.queue_depth',
    Histogram,
)

SLOW_REQUEST_THRESHOLD_SECONDS = 30.0

# endpoint attribute used for requests that did not match any registered route
UNMATCHED_ENDPOINT = 'unmatched'

# route canonicals (leading `/` stripped) with no observability value,
# mirroring odg.telemetry's excluded_urls
EXCLUDED_ENDPOINTS = frozenset({'healthz', 'ready', 'favicon.ico'})


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
    Record OTel HTTP server request count + queue depth per request and store
    the instruments on the aiohttp app (duration + active-request metrics come
    from the aiohttp-server instrumentor). Safe with or without a configured
    MeterProvider.

    Must run before `aiohttp.web` starts serving; typically called once with
    the populated application, like the other middlewares.
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
        if endpoint.lstrip('/') in EXCLUDED_ENDPOINTS:
            return await handler(request)
        method = request.method
        request_key = (endpoint, method)
        attrs = {'http.route': endpoint, 'http.request.method': method}

        # queue-depth heuristic: how many requests for this route were already
        # in-flight when this one arrived. Unlike the old prometheus gauge
        # (which exported the oldest in-flight request's start timestamp — the
        # same info derivable from latency), this is a depth *count* (0 = no
        # wait). Real scheduling time is aiohttp-internal and not observable.
        depth = inflight_depths.get(request_key, 0)
        inflight_depths[request_key] = depth + 1
        if depth > 0:
            request.app[APP_HTTP_SERVER_QUEUE_DEPTH].record(
                float(depth),
                attrs,
            )

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
            # decrement the live value: overlapping requests finish in any order
            inflight_depths[request_key] -= 1
            latency_seconds = (datetime.datetime.now() - start_time).total_seconds()

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

    app[APP_HTTP_SERVER_REQUEST_COUNT] = meter.create_counter(
        name='http.server.request.count',
        description='Total number of HTTP server requests',
    )
    app[APP_HTTP_SERVER_QUEUE_DEPTH] = meter.create_histogram(
        name='http.server.request.queue_depth',
        unit='{request}',
        description='Number of requests already in-flight on this route when this one arrived',
        explicit_bucket_boundaries_advisory=(1.0, 2.0, 4.0, 8.0, 16.0, 32.0),
    )

    app.middlewares.insert(0, middleware)

    return app
