"""
Tests for odg.audit and middleware.audit: the audit helper emits structlog events with the
fixed schema (event name, action, fields); the audit middleware emits one event per mutating
request (skipping reads) with the outcome derived from the HTTP status.
"""

import types

import aiohttp.test_utils
import aiohttp.web
import ocm
import pytest
import structlog.testing

import middleware.audit
import odg.audit
import scanner_utils.scanner

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return 'asyncio'


def test_emit_creates_audit_event():
    with structlog.testing.capture_logs() as logs:
        odg.audit.emit(
            action='findings_write',
            user_id='user-1',
            odg_audit_outcome=odg.audit.Outcome.ALLOWED,
        )

    (log,) = logs
    assert log['event_name'] == 'odg.audit.findings_write'
    assert log['odg_audit_action'] == 'findings_write'
    assert log['user_id'] == 'user-1'
    assert log['odg_audit_outcome'] == odg.audit.Outcome.ALLOWED


def test_capped_truncates_long_lists():
    result = odg.audit.capped(
        (f'key-{idx}' for idx in range(odg.audit.MAX_DETAIL_ITEMS + 5)),
        limit=odg.audit.MAX_DETAIL_ITEMS,
    )

    assert result['total'] == odg.audit.MAX_DETAIL_ITEMS + 5
    assert len(result['items']) == odg.audit.MAX_DETAIL_ITEMS


def test_stringify_truncates_long_values():
    result = odg.audit.stringify({'data': 'x' * odg.audit.MAX_DETAIL_LENGTH})

    assert len(result) <= odg.audit.MAX_DETAIL_LENGTH + len('...<truncated>')
    assert result.endswith('...<truncated>')


@pytest.fixture
async def audit_app():
    async def ok(request: aiohttp.web.Request) -> aiohttp.web.Response:
        return aiohttp.web.Response(text='ok')

    async def forbidden(request: aiohttp.web.Request) -> aiohttp.web.Response:
        raise aiohttp.web.HTTPForbidden()

    async def boom(request: aiohttp.web.Request) -> aiohttp.web.Response:
        raise ValueError('kaboom')

    app = aiohttp.web.Application()
    app.router.add_put('/items', ok)
    app.router.add_get('/items', ok)
    app.router.add_post('/things/query', ok)
    app.router.add_delete('/protected', forbidden)
    app.router.add_post('/boom', boom)
    app.middlewares.append(middleware.audit.audit_middleware())
    return app


@pytest.fixture
async def audit_client(audit_app):
    async with aiohttp.test_utils.TestClient(
        aiohttp.test_utils.TestServer(audit_app),
    ) as client:
        yield client


async def request_and_capture(client, method: str, path: str) -> list[dict]:
    with structlog.testing.capture_logs() as logs:
        await client.request(method, path)
    return logs


async def test_middleware_audits_mutating_request(audit_client):
    (log,) = await request_and_capture(audit_client, 'PUT', '/items')

    assert log['event_name'] == 'odg.audit.request_write'
    assert log['odg_audit_action'] == 'request_write'
    assert log['odg_audit_target'] == 'PUT /items'
    assert log['url_full'] == '/items'
    assert log['user_id'] is None  # no auth middleware in test app
    assert log['odg_audit_outcome'] == odg.audit.Outcome.ALLOWED
    assert log['odg_audit_detail'] == {'http_status': 200}


async def test_middleware_skips_read_requests(audit_client):
    assert await request_and_capture(audit_client, 'GET', '/items') == []


async def test_middleware_skips_read_only_post_queries(audit_client):
    assert await request_and_capture(audit_client, 'POST', '/things/query') == []


async def test_middleware_audits_denied_request(audit_client):
    (log,) = await request_and_capture(audit_client, 'DELETE', '/protected')

    assert log['odg_audit_outcome'] == odg.audit.Outcome.DENIED
    assert log['odg_audit_detail'] == {'http_status': 403}


def test_access_reference_prefers_image_reference():
    access = types.SimpleNamespace(
        imageReference='registry.example.org/ocm/component:1.0.0',
        type=ocm.AccessType.OCI_REGISTRY,
    )

    assert (
        scanner_utils.scanner._access_reference(access) == 'registry.example.org/ocm/component:1.0.0'
    )


def test_access_reference_falls_back_to_repo_url():
    access = types.SimpleNamespace(
        repoUrl='github.com/sap/ocm-repo',
        type=ocm.AccessType.GITHUB,
    )

    assert scanner_utils.scanner._access_reference(access) == 'github.com/sap/ocm-repo'


def test_access_reference_falls_back_to_access_type():
    access = types.SimpleNamespace(type=ocm.AccessType.LOCAL_BLOB)

    assert scanner_utils.scanner._access_reference(access) == ocm.AccessType.LOCAL_BLOB.value


async def test_middleware_audits_failing_request(audit_client):
    (log,) = await request_and_capture(audit_client, 'POST', '/boom')

    assert log['odg_audit_outcome'] == odg.audit.Outcome.ERROR
    assert log['odg_audit_detail'] == {'http_status': None}
