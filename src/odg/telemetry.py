"""
Central OpenTelemetry trace configuration for ODG processes.

Usage (entry points, e.g. src/app.py or an extension's __main__.py):

    import odg.telemetry
    odg.telemetry.configure_telemetry()

Mirrors `odg.logging_cfg.configure_logging()`: call once per process at
startup. Configures both tracing and metrics — the old Prometheus `/metrics`
endpoint was removed in favour of OTLP metrics; logs stay on structlog.

Configuration is entirely via standard OTel env vars (read by the SDK):
- `OTEL_EXPORTER_OTLP_ENDPOINT` — collector URL, e.g.
  `http://telemetry-opentelemetry-collector.odg-system:4317`. **Unset or empty
  means no instrumentation**: `configure_telemetry()` is a no-op, so local
  dev/tests and clusters without a collector run unmodified.
- `OTEL_SERVICE_NAME` — overrides `service_name`; injected by helm per
  extension, matches the name passed to `configure_logging()`.

Instrumented libraries:
- aiohttp server (delivery-service): one span per request, route-templated
  span names (`/components/{name}`), plus `http.server.duration` /
  `http.server.active_requests` metrics via the built-in meter —
  middleware.metrics therefore only adds `http.server.request.count` and
  `http.server.request.queue_depth`
- aiohttp client: one span per outgoing request; W3C `traceparent` header
  propagation enables cross-extension traces (extensions call the
  delivery-service via odg_client, which uses aiohttp)
- aiohttp and the propagators run on contextvars, so manual spans created via
  `opentelemetry.trace.get_tracer(...)` nest under the request span
  automatically
- SQLAlchemy: one span per statement; instrumenting here (once) wraps
  `sqlalchemy.create_engine`/`create_async_engine`, so engines created later
  by deliverydb are instrumented without touching engine construction

Probe endpoints (`/healthz`, `/ready`) are excluded via
`OTEL_PYTHON_AIOHTTP_SERVER_EXCLUDED_URLS` — anchored regexes; `ExcludeList`
uses `re.search`, so bare `metrics` would also match real routes like
`/dora/dora-metrics`.

Not instrumented on purpose:
- logging/trace-correlation: requires a logging handler that formats the
  whole record JSON; ODG's structlog pipeline does that itself, so add a
  processor injecting `trace_id`/`span_id` from `trace.get_current_span()`
  when that integration is wanted
"""

import os

import structlog

logger = structlog.get_logger(__name__)

# probe endpoints excluded from server spans (self-observation noise); consumed
# in configure_telemetry() when setting OTEL_PYTHON_AIOHTTP_SERVER_EXCLUDED_URLS
# (instrument() snapshots that into OTEL_PYTHON_EXCLUDED_URLS while the env
# parses instrumentation config). Anchored: ExcludeList runs `re.search`, so an
# unanchored `metrics` would also exclude real routes like `/dora/dora-metrics`
excluded_urls = '^/healthz$,^/ready$,^/favicon.ico$'

# explicit seconds buckets: the OTel SDK default histogram aggregation spans
# 0 … 10000 (assumes ms scale), so without a View virtually every request
# lands in one bucket and quantiles become meaningless. One View per unit
# catches both the instrumentor's (ms) and our own (s) duration histograms
duration_histogram_buckets_seconds = (
    0.005,
    0.025,
    0.1,
    0.5,
    2.5,
    10.0,
    30.0,
    60.0,
    120.0,
    300.0,
    900.0,
)
duration_histogram_buckets_ms = tuple(s * 1000.0 for s in duration_histogram_buckets_seconds)


def configure_telemetry(
    instrument_aiohttp: bool = True,
) -> None:
    """
    Configure OTel tracing for this process if `OTEL_EXPORTER_OTLP_ENDPOINT`
    is set (non-empty); no-op otherwise.

    Must be called BEFORE any `aiohttp.web.Application` is instantiated
    (aiohttp-server instrumentation patches `Application.__init__`) and after
    `odg.logging_cfg.configure_logging()` (so the disabled/enabled log entry
    is formatted).

    `instrument_aiohttp`: disable for non-HTTP batch processes to save the
    monkey-patching overhead (harmless to leave on; spans only appear once
    the process serves or calls HTTP).
    """
    if not (endpoint := os.environ.get('OTEL_EXPORTER_OTLP_ENDPOINT')):
        logger.info('OTEL_EXPORTER_OTLP_ENDPOINT unset or empty; OTel tracing disabled')
        return

    # `instrument()` snapshots this into OTEL_PYTHON_EXCLUDED_URLS while
    # reading instrumentation config from the env
    os.environ.setdefault('OTEL_PYTHON_AIOHTTP_SERVER_EXCLUDED_URLS', excluded_urls)

    from opentelemetry import metrics
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    # env var (set by helm) wins so one chart helper serves every extension
    service_name = os.environ.get('OTEL_SERVICE_NAME', 'odg')
    resource = Resource.create(attributes={'service.name': service_name})

    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(tracer_provider)

    from opentelemetry.sdk.metrics import Histogram
    from opentelemetry.sdk.metrics._internal.aggregation import (
        ExplicitBucketHistogramAggregation,
    )
    from opentelemetry.sdk.metrics.view import View

    # scope-matched View for all seconds-unit histograms: own `odg.http` meter
    # and the aiohttp-server semconv-new meter (schema url pins the scope)
    views = [
        View(
            instrument_type=Histogram,
            instrument_unit=unit,
            aggregation=ExplicitBucketHistogramAggregation(
                boundaries=bucket_boundaries,
            ),
        )
        for unit, bucket_boundaries in (
            ('s', duration_histogram_buckets_seconds),
            ('ms', duration_histogram_buckets_ms),
        )
    ]

    # default cadence matches the traces batch processor (~30s flush)
    metric_reader = PeriodicExportingMetricReader(OTLPMetricExporter())
    metrics.set_meter_provider(
        MeterProvider(
            resource=resource,
            metric_readers=[metric_reader],
            views=views,
        ),
    )

    from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

    # with no `engine=` argument this only wraps create_engine/
    # create_async_engine (per-engine spans attach when engines are built);
    # must run here, not where engines are built — the instrumentor is a
    # singleton and a second `instrument()` short-circuits with a warning
    SQLAlchemyInstrumentor().instrument()

    if instrument_aiohttp:
        from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor
        from opentelemetry.instrumentation.aiohttp_server import AioHttpServerInstrumentor

        AioHttpServerInstrumentor().instrument()
        AioHttpClientInstrumentor().instrument()

    logger.info(
        'OpenTelemetry tracing enabled',
        **{'otel.exporter.otlp.endpoint': endpoint, 'service.name': service_name},
    )
