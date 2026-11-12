"""
Tests for middleware.metrics: in-memory OTEL MetricsReader is attached, the
middleware is installed on a test app, requests run through aiohttp's test
client, and the exported metrics are asserted directly off the reader.
"""

import aiohttp.test_utils
import aiohttp.web
import pytest

import middleware.metrics

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
async def otel_reader():
    from opentelemetry import metrics as otel_metrics
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import InMemoryMetricReader
    from opentelemetry.util._once import Once

    reader = InMemoryMetricReader()
    provider = MeterProvider(metric_readers=[reader])
    otel_metrics._internal._METER_PROVIDER = provider
    yield reader
    provider.shutdown()
    otel_metrics._internal._METER_PROVIDER = None
    otel_metrics._internal._METER_PROVIDER_SET_ONCE = Once()


@pytest.fixture
async def metrics_app(otel_reader):
    async def hello(request: aiohttp.web.Request) -> aiohttp.web.Response:
        return aiohttp.web.Response(text='ok')

    async def boom(request: aiohttp.web.Request) -> aiohttp.web.Response:
        raise ValueError('kaboom')

    async def ready(request: aiohttp.web.Request) -> aiohttp.web.Response:
        return aiohttp.web.Response(text='ready')

    app = aiohttp.web.Application()
    app.router.add_get('/hello', hello)
    app.router.add_get('/boom', boom)
    app.router.add_get('/ready', ready)
    app = middleware.metrics.add_http_metrics_middleware(app=app)
    return app


@pytest.fixture
async def metrics_client(metrics_app):
    async with aiohttp.test_utils.TestClient(
        aiohttp.test_utils.TestServer(metrics_app),
    ) as client:
        yield client


def _series(reader, name: str) -> list:
    out = []
    result = reader.get_metrics_data()
    for rms in result.resource_metrics:
        for scope_metrics in rms.scope_metrics:
            for m in scope_metrics.metrics:
                if m.name == name:
                    out.append((m, rms, scope_metrics))
    return out


async def test_records_request_count_and_duration(metrics_client, otel_reader):
    resp = await metrics_client.get('/hello')
    assert resp.status == 200

    call_data = otel_reader.get_metrics_data()

    duration = None
    count = None
    active = None
    for rms in call_data.resource_metrics:
        for sm in rms.scope_metrics:
            assert sm.scope.name == 'odg.http'
            for m in sm.metrics:
                if m.name == 'http.server.duration':
                    duration = m
                elif m.name == 'http.server.request.count':
                    count = m
                elif m.name == 'http.server.active_requests':
                    active = m

    assert duration is not None, 'http.server.duration metric not exported'
    assert count is not None, 'http.server.request.count metric not exported'
    assert active is not None, 'http.server.active_requests metric not exported'

    assert duration.data.data_points[0].count == 1
    assert duration.data.data_points[0].sum > 0
    assert duration.data.data_points[0].attributes['http.route'] == '/hello'
    assert duration.data.data_points[0].attributes['http.request.method'] == 'GET'

    counter_point = list(count.data.data_points)[0]
    assert counter_point.value == 1
    assert counter_point.attributes['http.route'] == '/hello'
    assert counter_point.attributes['http.response.status_code'] == '200'

    # up-down counter nets back to zero after the request finished
    assert sum(p.value for p in active.data.data_points) == 0


async def test_excluded_route_is_not_recorded(metrics_client, otel_reader):
    resp = await metrics_client.get('/ready')
    assert resp.status == 200

    call_data = otel_reader.get_metrics_data()
    # no collection runnable when nothing was recorded -> None
    assert call_data is None or not list(call_data.resource_metrics), (
        f'unexpected metrics for /ready: {call_data!r}'
    )


async def test_error_status_label(metrics_client, otel_reader):
    await metrics_client.get('/boom')

    call_data = otel_reader.get_metrics_data()
    points = [
        dp
        for rms in call_data.resource_metrics
        for sm in rms.scope_metrics
        for m in sm.metrics
        if m.name == 'http.server.request.count'
        for dp in m.data.data_points
    ]
    assert points[0].attributes['http.response.status_code'] == 'error'


async def test_unmatched_route_uses_canonical_unmatched_label(otel_reader):
    async def known(request: aiohttp.web.Request) -> aiohttp.web.Response:
        return aiohttp.web.Response(text='ok')

    app = aiohttp.web.Application()
    app.router.add_get('/known', known)
    app = middleware.metrics.add_http_metrics_middleware(app=app)

    async with aiohttp.test_utils.TestClient(aiohttp.test_utils.TestServer(app)) as client:
        resp = await client.get('/nope')
        assert resp.status == 404

    points = [
        (m, dp)
        for rms in otel_reader.get_metrics_data().resource_metrics
        for sm in rms.scope_metrics
        for m in sm.metrics
        if m.name == 'http.server.request.count'
        for dp in m.data.data_points
    ]
    assert points[0][1].attributes['http.route'] == middleware.metrics.UNMATCHED_ENDPOINT
    assert points[0][1].attributes['http.response.status_code'] == '404'
