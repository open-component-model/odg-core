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
- `OTEL_SERVICE_NAME` — service identity for traces AND logs; injected by
  helm per extension (`.Chart.Name`). `configure_logging()` falls back to it
  when no `service_name` is passed, so logs and traces report the same name.

Instrumented libraries:
- aiohttp server (delivery-service): one span per request, route-templated
  span names (`/components/{name}`), plus `http.server.duration` /
  `http.server.active_requests` metrics via the built-in meter —
  middleware.metrics therefore only adds `http.server.request.count` and
  `http.server.request.queue_depth`
- aiohttp client: one span per outgoing request; W3C `traceparent` header
  propagation
- requests: same for the sync client; extensions call the delivery-service
  via odg_client (requests-based), so this links extension and
  delivery-service spans into one trace
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

Span attributes are scrubbed via `odg.logging_cfg.scrub_string` (same
credential patterns as logs): instrumentors record full URLs incl. query
strings, e.g. `/auth?code=…&access_token=…` (server) or the GitHub token
exchange with `client_secret=…` (client); OTel's built-in redaction only
covers a few cloud-signature params.

Not instrumented on purpose:
- logging/trace-correlation: requires a logging handler that formats the
  whole record JSON; ODG's structlog pipeline does that itself, so add a
  processor injecting `trace_id`/`span_id` from `trace.get_current_span()`
  when that integration is wanted
"""

import os
import typing

import structlog

import odg.logging_cfg

# annotations only — the OTel SDK stays lazily imported inside the functions
# below so importing this module never pulls it in when telemetry is disabled
if typing.TYPE_CHECKING:
    import opentelemetry.context
    import opentelemetry.sdk.trace

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


def _scrubbing_span_processor() -> 'opentelemetry.sdk.trace.SpanProcessor':
    import opentelemetry.sdk.trace

    class ScrubbingSpanProcessor(opentelemetry.sdk.trace.SpanProcessor):
        """
        Scrub credentials from string attributes set at span start (where
        instrumentors put URL/query attributes); attributes are immutable
        once the span ended, so `on_end` cannot rewrite them.
        """

        def on_start(
            self,
            span: 'opentelemetry.sdk.trace.Span',
            parent_context: 'opentelemetry.context.Context | None' = None,
        ) -> None:
            for key, value in (span.attributes or {}).items():
                if (
                    isinstance(value, str)
                    and (scrubbed := odg.logging_cfg.scrub_string(value)) != value
                ):
                    span.set_attribute(key, scrubbed)

    return ScrubbingSpanProcessor()


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

    import opentelemetry.exporter.otlp.proto.grpc.metric_exporter as metric_exporter
    import opentelemetry.exporter.otlp.proto.grpc.trace_exporter as trace_exporter
    import opentelemetry.metrics
    import opentelemetry.sdk.metrics
    import opentelemetry.sdk.metrics.export
    import opentelemetry.sdk.resources
    import opentelemetry.sdk.trace
    import opentelemetry.sdk.trace.export
    import opentelemetry.trace

    # env var (set by helm) wins so one chart helper serves every extension
    service_name = os.environ.get('OTEL_SERVICE_NAME', 'odg')
    resource = opentelemetry.sdk.resources.Resource.create(
        attributes={'service.name': service_name},
    )

    tracer_provider = opentelemetry.sdk.trace.TracerProvider(resource=resource)
    # processors run in registration order: scrub before anything can export
    tracer_provider.add_span_processor(_scrubbing_span_processor())
    batch_processor = opentelemetry.sdk.trace.export.BatchSpanProcessor(
        trace_exporter.OTLPSpanExporter(),
    )
    tracer_provider.add_span_processor(batch_processor)
    opentelemetry.trace.set_tracer_provider(tracer_provider)

    import opentelemetry.sdk.metrics._internal.aggregation as metrics_aggregation
    import opentelemetry.sdk.metrics.view

    # scope-matched View for all seconds-unit histograms: own `odg.http` meter
    # and the aiohttp-server semconv-new meter (schema url pins the scope)
    views = [
        opentelemetry.sdk.metrics.view.View(
            instrument_type=opentelemetry.sdk.metrics.Histogram,
            instrument_unit=unit,
            aggregation=metrics_aggregation.ExplicitBucketHistogramAggregation(
                boundaries=bucket_boundaries,
            ),
        )
        for unit, bucket_boundaries in (
            ('s', duration_histogram_buckets_seconds),
            ('ms', duration_histogram_buckets_ms),
        )
    ]

    # default cadence matches the traces batch processor (~30s flush)
    metric_reader = opentelemetry.sdk.metrics.export.PeriodicExportingMetricReader(
        metric_exporter.OTLPMetricExporter(),
    )
    opentelemetry.metrics.set_meter_provider(
        opentelemetry.sdk.metrics.MeterProvider(
            resource=resource,
            metric_readers=[metric_reader],
            views=views,
        ),
    )

    import opentelemetry.instrumentation.sqlalchemy

    # with no `engine=` argument this only wraps create_engine/
    # create_async_engine (per-engine spans attach when engines are built);
    # must run here, not where engines are built — the instrumentor is a
    # singleton and a second `instrument()` short-circuits with a warning
    opentelemetry.instrumentation.sqlalchemy.SQLAlchemyInstrumentor().instrument()

    import opentelemetry.instrumentation.requests

    # independent of `instrument_aiohttp`: batch processes call the
    # delivery-service via the requests-based odg_client
    opentelemetry.instrumentation.requests.RequestsInstrumentor().instrument()

    if instrument_aiohttp:
        import opentelemetry.instrumentation.aiohttp_client as aiohttp_client
        import opentelemetry.instrumentation.aiohttp_server as aiohttp_server

        aiohttp_server.AioHttpServerInstrumentor().instrument()
        aiohttp_client.AioHttpClientInstrumentor().instrument()

    logger.info(
        'OpenTelemetry tracing enabled',
        **{'otel.exporter.otlp.endpoint': endpoint, 'service.name': service_name},
    )
