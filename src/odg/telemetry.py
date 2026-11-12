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
  span names (`/components/{name}`); instrumented BEFORE
  `aiohttp.web.Application` is created (the instrumentor patches
  `Application.__init__`)
- aiohttp client: one span per outgoing request; W3C `traceparent` header
  propagation enables cross-extension traces (extensions call the
  delivery-service via odg_client, which uses aiohttp)
- aiohttp and the propagators run on contextvars, so manual spans created via
  `opentelemetry.trace.get_tracer(...)` nest under the request span
  automatically

Probe/scrape endpoints (`/healthz`, `/ready`, `/metrics`) are excluded via
`OTEL_PYTHON_AIOHTTP_SERVER_EXCLUDED_URLS` — the SDK exports this package's
`excluded_urls` list as `OTEL_PYTHON_EXCLUDED_URLS` before initialising the
instrumentation env-var parsing.

Not instrumented on purpose:
- SQLAlchemy: engine registry lives in deliverydb.cli/entry points; add
  `SqlalchemyInstrumentor` where the engine is created if DB spans are wanted
- logging/trace-correlation: requires a logging handler that formats the
  whole record JSON; ODG's structlog pipeline does that itself, so add a
  processor injecting `trace_id`/`span_id` from `trace.get_current_span()`
  when that integration is wanted
"""

import os

import structlog

logger = structlog.get_logger(__name__)

# probe/scrape endpoints excluded from server spans (self-observation noise);
# consumed by OTEL_PYTHON_AIOHTTP_SERVER_EXCLUDED_URLS (set below at import
# time because `configure()` snapshots it into OTEL_PYTHON_EXCLUDED_URLS when
# the env parses instrumentation config)
excluded_urls = 'healthz,ready,metrics'


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

    # default cadence matches the traces batch processor (~30s flush)
    metric_reader = PeriodicExportingMetricReader(OTLPMetricExporter())
    metrics.set_meter_provider(
        MeterProvider(resource=resource, metric_readers=[metric_reader]),
    )

    if instrument_aiohttp:
        from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor
        from opentelemetry.instrumentation.aiohttp_server import AioHttpServerInstrumentor

        AioHttpServerInstrumentor().instrument()
        AioHttpClientInstrumentor().instrument()

    logger.info(
        'OTel tracing enabled',
        **{'otel.exporter.otlp.endpoint': endpoint, 'service.name': service_name},
    )
