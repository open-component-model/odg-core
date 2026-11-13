"""
Tests for middleware.metrics: in-memory OTEL MetricsReader is attached, the
middleware is installed on a test app, requests run through aiohttp's test
client, and the exported metrics are asserted directly off the reader.
"""

import asyncio

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
    import opentelemetry.metrics._internal as metrics_internal
    import opentelemetry.sdk.metrics
    import opentelemetry.sdk.metrics.export
    import opentelemetry.util._once

    reader = opentelemetry.sdk.metrics.export.InMemoryMetricReader()
    provider = opentelemetry.sdk.metrics.MeterProvider(metric_readers=[reader])
    metrics_internal._METER_PROVIDER = provider
    yield reader
    provider.shutdown()
    metrics_internal._METER_PROVIDER = None
    metrics_internal._METER_PROVIDER_SET_ONCE = opentelemetry.util._once.Once()


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


async def test_records_request_count(metrics_client, otel_reader):
    resp = await metrics_client.get('/hello')
    assert resp.status == 200

    call_data = otel_reader.get_metrics_data()

    count = None
    queue_depth = None
    for rms in call_data.resource_metrics:
        for sm in rms.scope_metrics:
            assert sm.scope.name == 'odg.http'
            for m in sm.metrics:
                if m.name == 'http.server.request.count':
                    count = m
                elif m.name == 'http.server.request.queue_depth':
                    queue_depth = m

    assert count is not None, 'http.server.request.count metric not exported'
    # no concurrent requests: queue depth observations may exist with depth-1
    # values depending on request interleave, or not at all
    if queue_depth is not None:
        assert all(dp.sum >= 0 for dp in queue_depth.data.data_points)

    counter_point = list(count.data.data_points)[0]
    assert counter_point.value == 1
    assert counter_point.attributes['http.route'] == '/hello'
    assert counter_point.attributes['http.request.method'] == 'GET'
    assert counter_point.attributes['http.response.status_code'] == '200'


async def test_queue_depth_recorded_for_concurrent_requests(otel_reader):
    slow_running = asyncio.Event()
    slow_inflight = asyncio.Event()
    second_in_middleware = asyncio.Event()

    async def slow(request: aiohttp.web.Request) -> aiohttp.web.Response:
        slow_running.set()
        await slow_inflight.wait()
        return aiohttp.web.Response(text='ok')

    app = aiohttp.web.Application()
    app.router.add_get('/slow', slow)
    app = middleware.metrics.add_http_metrics_middleware(app=app)

    # wrap the histogram's record to know exactly when the second request is in
    # the middleware — asyncio scheduling between two aiohttp test requests is
    # not stable enough for sleep(0) ticks
    observed_depths: list[float] = []
    histogram = app[middleware.metrics.APP_HTTP_SERVER_QUEUE_DEPTH]
    queue_record = histogram.record

    def wrapped_record(value, attrs=None):
        observed_depths.append(value)
        second_in_middleware.set()
        return queue_record(value, attrs)

    histogram.record = wrapped_record

    async with aiohttp.test_utils.TestClient(aiohttp.test_utils.TestServer(app)) as client:
        first = asyncio.create_task(client.get('/slow'))
        await slow_running.wait()
        second = asyncio.create_task(client.get('/slow'))
        # wait for the second request to hit record (depth 1) before releasing
        # the first one
        await asyncio.wait_for(second_in_middleware.wait(), timeout=5)
        slow_inflight.set()
        await first
        await second

    assert observed_depths == [1.0]

    points = [
        dp
        for rms in otel_reader.get_metrics_data().resource_metrics
        for sm in rms.scope_metrics
        for m in sm.metrics
        if m.name == 'http.server.request.queue_depth'
        for dp in m.data.data_points
    ]
    assert len(points) == 1
    assert points[0].attributes['http.route'] == '/slow'
    assert points[0].sum == 1  # one observation of depth 1


async def test_queue_depth_resets_after_out_of_order_completion(otel_reader):
    """first-in request finishing first must not leave a stale in-flight count"""
    release_first = asyncio.Event()
    release_second = asyncio.Event()
    first_running = asyncio.Event()
    second_running = asyncio.Event()

    async def slow(request: aiohttp.web.Request) -> aiohttp.web.Response:
        if not first_running.is_set():
            first_running.set()
            await release_first.wait()
        else:
            second_running.set()
            await release_second.wait()
        return aiohttp.web.Response(text='ok')

    app = aiohttp.web.Application()
    app.router.add_get('/slow', slow)
    app = middleware.metrics.add_http_metrics_middleware(app=app)

    observed_depths: list[float] = []
    histogram = app[middleware.metrics.APP_HTTP_SERVER_QUEUE_DEPTH]
    queue_record = histogram.record

    def wrapped_record(value, attrs=None):
        observed_depths.append(value)
        return queue_record(value, attrs)

    histogram.record = wrapped_record

    async with aiohttp.test_utils.TestClient(aiohttp.test_utils.TestServer(app)) as client:
        first = asyncio.create_task(client.get('/slow'))
        await asyncio.wait_for(first_running.wait(), timeout=5)
        second = asyncio.create_task(client.get('/slow'))
        await asyncio.wait_for(second_running.wait(), timeout=5)

        release_first.set()
        await first
        release_second.set()
        await second

        # sequential request after both finished: no in-flight requests remain
        first_running.clear()
        release_first.set()
        await client.get('/slow')

    assert observed_depths == [1.0]


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
