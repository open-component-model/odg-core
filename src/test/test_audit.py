"""
Tests for odg.audit and middleware.audit: the audit helper emits structlog events with the
fixed schema (event name, action, fields); the audit middleware emits one event per mutating
request (skipping reads) with the outcome derived from the HTTP status.
"""

import datetime
import types
import unittest.mock

import aiohttp.test_utils
import aiohttp.web
import ocm
import pytest
import structlog.testing

import consts
import middleware.audit
import middleware.auth
import odg.audit
import odg_client.jwt
import scanner_utils.scanner
import secret_mgmt
import secret_mgmt.oauth_cfg

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
    assert log['network_peer_address'] == '127.0.0.1'
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


@pytest.fixture
def mock_db_session():
    session = unittest.mock.MagicMock()  # `add` is sync in sqlalchemy
    session.get = unittest.mock.AsyncMock(
        return_value=types.SimpleNamespace(user_id='user-1'),
    )
    session.commit = unittest.mock.AsyncMock()
    session.rollback = unittest.mock.AsyncMock()
    return session


@pytest.fixture
async def auth_app(mock_db_session):
    app = aiohttp.web.Application()
    app[consts.APP_BASE_URL] = 'http://localhost:5000'

    @aiohttp.web.middleware
    async def db_session(request: aiohttp.web.Request, handler):
        request[consts.REQUEST_DB_SESSION] = mock_db_session
        return await handler(request)

    app.middlewares.append(db_session)
    app.router.add_post('/auth', middleware.auth.OAuthLogin)
    app.router.add_post('/auth/refresh', middleware.auth.OAuthRefresh)
    app.router.add_get('/auth/logout', middleware.auth.OAuthLogout)
    return app


@pytest.fixture
async def auth_client(auth_app):
    async with aiohttp.test_utils.TestClient(
        aiohttp.test_utils.TestServer(auth_app),
    ) as client:
        yield client


async def test_auth_login_denied_without_credentials(auth_client):
    with structlog.testing.capture_logs() as logs:
        response = await auth_client.post('/auth', json={})

    assert response.status == 401

    (log,) = logs
    assert log['event_name'] == 'odg.audit.auth_login'
    assert log['odg_audit_outcome'] == odg.audit.Outcome.DENIED
    assert log['network_peer_address'] == '127.0.0.1'
    assert log['odg_audit_detail']['http_status'] == 401


async def test_auth_login_denied_unknown_provider(auth_client, monkeypatch):
    secret_factory = unittest.mock.Mock()
    secret_factory.oauth_cfg.side_effect = secret_mgmt.SecretTypeNotFound('no cfgs')
    monkeypatch.setattr(middleware.auth.ctx_util, 'secret_factory', lambda: secret_factory)

    with structlog.testing.capture_logs() as logs:
        response = await auth_client.post('/auth', json={'code': 'x', 'client_id': 'y'})

    assert response.status == 401

    (log,) = logs
    assert log['odg_audit_action'] == 'auth_login'
    assert log['odg_audit_outcome'] == odg.audit.Outcome.DENIED
    assert 'No OAuth providers configured' in log['odg_audit_detail']['reason']


async def test_auth_login_success(auth_client, monkeypatch):
    secret_factory = unittest.mock.Mock()
    secret_factory.oauth_cfg.return_value = [object()]
    monkeypatch.setattr(middleware.auth.ctx_util, 'secret_factory', lambda: secret_factory)
    monkeypatch.setattr(
        middleware.auth,
        'find_oauth_cfg',
        lambda **kwargs: types.SimpleNamespace(type=secret_mgmt.oauth_cfg.OAuthCfgTypes.GITHUB),
    )
    monkeypatch.setattr(
        middleware.auth,
        'find_github_identifier',
        unittest.mock.AsyncMock(
            return_value=types.SimpleNamespace(normalised_digest='digest'),
        ),
    )
    monkeypatch.setattr(
        middleware.auth,
        'set_session_and_refresh_token',
        unittest.mock.AsyncMock(return_value=aiohttp.web.Response(text='ok')),
    )

    with structlog.testing.capture_logs() as logs:
        response = await auth_client.post('/auth', json={'code': 'c', 'client_id': 'y'})

    assert response.status == 200

    (log,) = logs
    assert log['odg_audit_action'] == 'auth_login'
    assert log['odg_audit_outcome'] == odg.audit.Outcome.ALLOWED
    assert log['user_id'] == 'user-1'
    assert log['network_peer_address'] == '127.0.0.1'
    assert log['odg_audit_detail']['idp_type'] == 'github'


async def test_auth_token_refresh_success(auth_client, monkeypatch):
    monkeypatch.setattr(middleware.auth.ctx_util, 'secret_factory', unittest.mock.Mock())
    monkeypatch.setattr(
        middleware.auth,
        'decode_jwt',
        lambda **kwargs: {'sub': 'user-1', 'identifier': 'rid', 'key_id': 'k'},
    )
    monkeypatch.setattr(middleware.auth, 'get_signing_cfg_for_key', lambda **kwargs: object())
    monkeypatch.setattr(
        middleware.auth,
        'set_session_and_refresh_token',
        unittest.mock.AsyncMock(return_value=aiohttp.web.Response(text='ok')),
    )

    with structlog.testing.capture_logs() as logs:
        response = await auth_client.post(
            '/auth/refresh',
            cookies={odg_client.jwt.REFRESH_TOKEN_KEY: 'token'},
        )

    assert response.status == 200

    (log,) = logs
    assert log['odg_audit_action'] == 'auth_token_refresh'
    assert log['odg_audit_outcome'] == odg.audit.Outcome.ALLOWED
    assert log['user_id'] == 'user-1'


async def test_auth_token_refresh_denied_without_cookie(auth_client):
    with structlog.testing.capture_logs() as logs:
        response = await auth_client.post('/auth/refresh')

    assert response.status == 401

    (log,) = logs
    assert log['odg_audit_action'] == 'auth_token_refresh'
    assert log['odg_audit_outcome'] == odg.audit.Outcome.DENIED


async def test_auth_logout_without_token(auth_client):
    with structlog.testing.capture_logs() as logs:
        response = await auth_client.get('/auth/logout')

    assert response.status == 200

    (log,) = logs
    assert log['odg_audit_action'] == 'auth_logout'
    assert log['odg_audit_outcome'] == odg.audit.Outcome.ALLOWED
    assert log['user_id'] is None
    assert log['odg_audit_detail'] == {'refresh_token_revoked': False}


async def test_auth_logout_revokes_refresh_token(
    auth_client,
    mock_db_session,
    monkeypatch,
):
    identifier_hash = middleware.auth.hash_refresh_token_identifier('rid')
    user = types.SimpleNamespace(
        refresh_tokens=[
            {
                'identifier': identifier_hash,
                'exp': int(
                    (
                        datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=1)
                    ).timestamp(),
                ),
            },
        ],
    )
    mock_db_session.get.return_value = user
    monkeypatch.setattr(
        middleware.auth,
        'decode_jwt',
        lambda **kwargs: {'sub': 'user-1', 'identifier': 'rid'},
    )

    with structlog.testing.capture_logs() as logs:
        response = await auth_client.get(
            '/auth/logout',
            cookies={odg_client.jwt.REFRESH_TOKEN_KEY: 'token'},
        )

    assert response.status == 200
    assert user.refresh_tokens == []

    (log,) = logs
    assert log['odg_audit_action'] == 'auth_logout'
    assert log['user_id'] == 'user-1'
    assert log['odg_audit_detail'] == {'refresh_token_revoked': True}
