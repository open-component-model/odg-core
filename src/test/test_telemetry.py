"""
Tests for odg.telemetry: the no-op when the exporter endpoint is unset, the
excluded-URL list (matched by the aiohttp-server instrumentor with
`re.search`), and the histogram-bucket View setup.
"""

import importlib
import os

import pytest


import odg.telemetry

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
def unset_otel(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv('OTEL_EXPORTER_OTLP_ENDPOINT', raising=False)
    monkeypatch.delenv('OTEL_PYTHON_AIOHTTP_SERVER_EXCLUDED_URLS', raising=False)
    importlib.reload(odg.telemetry)
    yield odg.telemetry
    # prevent batch exporters started by configure runs from retrying against
    # real collectors after the test
    monkeypatch.undo()


async def test_no_endpoint_is_noop(unset_otel, caplog, capfd):
    # the structlog log lands via logging (captured by caplog) when the pytest
    # logging plugin grabbed the root handler first (test-file order), or via
    # console writes (captured by capfd) — accept either
    unset_otel.configure_telemetry()

    output = caplog.text + capfd.readouterr().out
    assert 'tracing disabled' in output
    assert 'OpenTelemetry tracing enabled' not in output

    # the aiohttp instrumentor reads the env var only during instrument(),
    # which must not have run
    assert 'OTEL_PYTHON_AIOHTTP_SERVER_EXCLUDED_URLS' not in os.environ


async def test_excluded_urls_match_probes_but_not_dora(unset_otel):
    """`ExcludeList` uses re.search — unanchored tokens like `metrics` would
    also exclude real endpoints (`/dora/dora-metrics`)."""
    import opentelemetry.util.http

    excluded = opentelemetry.util.http.ExcludeList(unset_otel.excluded_urls.split(','))

    assert excluded.url_disabled('/healthz')
    assert excluded.url_disabled('/ready')
    assert excluded.url_disabled('/favicon.ico')
    assert not excluded.url_disabled('/dora/dora-metrics')
    assert not excluded.url_disabled('/already-ready')
    assert not excluded.url_disabled('/components')


async def test_noop_configure_sets_no_env(unset_otel):
    # even a no-op run must not leak the env var (a later process-side
    # auto-instrumentation run would pick it up)
    unset_otel.configure_telemetry()
    assert 'OTEL_PYTHON_AIOHTTP_SERVER_EXCLUDED_URLS' not in os.environ


async def test_bucket_views_cover_seconds_and_ms(unset_otel):
    seconds = unset_otel.duration_histogram_buckets_seconds
    millis = unset_otel.duration_histogram_buckets_ms

    assert len(seconds) == len(millis)
    for s, m in zip(seconds, millis, strict=True):
        assert m == s * 1000.0

    # spans the full request-durations range (5ms probes … 15min SBOM/dora exports)
    assert seconds[0] <= 0.005
    assert seconds[-1] >= 900.0


async def test_configure_with_endpoint_sets_providers(unset_otel, monkeypatch):
    """With an endpoint, tracer + meter providers and instrumentations are
    configured. Providers are global singletons (`Once`); as soon as one test
    in this process set a provider the assertion relies on that global state."""
    import opentelemetry.instrumentation.aiohttp_client
    import opentelemetry.instrumentation.aiohttp_server
    import opentelemetry.instrumentation.requests
    import opentelemetry.metrics
    import opentelemetry.metrics._internal as metrics_internal
    import opentelemetry.sdk.metrics
    import opentelemetry.sdk.trace
    import opentelemetry.trace
    import opentelemetry.util._once

    monkeypatch.setenv('OTEL_EXPORTER_OTLP_ENDPOINT', 'http://localhost:4317')
    monkeypatch.setenv('OTEL_SERVICE_NAME', 'test-svc')

    try:
        unset_otel.configure_telemetry()

        assert isinstance(
            opentelemetry.trace.get_tracer_provider(),
            opentelemetry.sdk.trace.TracerProvider,
        )
        assert isinstance(
            opentelemetry.metrics.get_meter_provider(),
            opentelemetry.sdk.metrics.MeterProvider,
        )
    finally:
        # restore global state for other tests in the same process
        providers = []
        try:
            providers.append(trace.get_tracer_provider())
            providers.append(metrics.get_meter_provider())
        except Exception:
            pass
        for provider in providers:
            try:
                provider.shutdown()
            except Exception:
                pass
        opentelemetry.trace._TRACER_PROVIDER = None
        opentelemetry.trace._TRACER_PROVIDER_SET_ONCE = opentelemetry.util._once.Once()
        metrics_internal._METER_PROVIDER = None
        metrics_internal._METER_PROVIDER_SET_ONCE = opentelemetry.util._once.Once()

        # both instrumentors attach middlewares/meters sharing the global
        # providers — reset them so no scope leaks into metrics tests
        for instrumentor in (
            opentelemetry.instrumentation.aiohttp_server.AioHttpServerInstrumentor,
            opentelemetry.instrumentation.aiohttp_client.AioHttpClientInstrumentor,
            opentelemetry.instrumentation.requests.RequestsInstrumentor,
        ):
            instrumentor._is_instrumented_by_opentelemetry = False
            instrumentor().uninstrument()


def test_scrubbing_span_processor_redacts_credential_attributes():
    import opentelemetry.sdk.trace
    import opentelemetry.sdk.trace.export
    import opentelemetry.sdk.trace.export.in_memory_span_exporter as in_memory_span_exporter

    exporter = in_memory_span_exporter.InMemorySpanExporter()
    tracer_provider = opentelemetry.sdk.trace.TracerProvider()
    tracer_provider.add_span_processor(odg.telemetry._scrubbing_span_processor())
    exporter_processor = opentelemetry.sdk.trace.export.SimpleSpanProcessor(exporter)
    tracer_provider.add_span_processor(exporter_processor)

    tracer_provider.get_tracer(__name__).start_span(
        'POST',
        attributes={
            'http.status_code': 200,
            'http.target': '/auth?code=abc&client_id=xyz',
            'url.full': 'https://github.com/login/oauth/access_token?client_secret=s3cr3t&code=abc',
        },
    ).end()

    (span,) = exporter.get_finished_spans()
    assert span.attributes['http.status_code'] == 200
    assert span.attributes['http.target'] == '/auth?code=***&client_id=xyz'
    assert span.attributes['url.full'] == (
        'https://github.com/login/oauth/access_token?client_secret=***&code=***'
    )
