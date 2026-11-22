import datetime
import json
import traceback
import unittest.mock
import uuid

import aiohttp.web
import Crypto.PublicKey.RSA
import jwt
import pytest
import yarl

import deliverydb.model as dm
import middleware.auth
import odg_client.jwt
import secret_mgmt.oauth_cfg
import secret_mgmt.signing_cfg

ISSUER = 'https://delivery-service.example.com'
USER_ID = str(uuid.uuid4())
KEY_ID = str(uuid.uuid4())
KEY_ALGORITHM = 'RS256'

_rsa_key = Crypto.PublicKey.RSA.generate(2048)
_PRIVATE_KEY_PEM = _rsa_key.export_key(format='PEM').decode()
_PUBLIC_KEY_PEM = _rsa_key.public_key().export_key(format='PEM').decode()


@pytest.fixture()
def signing_cfg():
    return secret_mgmt.signing_cfg.SigningCfg(
        id=KEY_ID,
        private_key=_PRIVATE_KEY_PEM,
        public_key=_PUBLIC_KEY_PEM,
        algorithm=KEY_ALGORITHM,
    )


def _make_user(
    refresh_tokens: list | None = None,
) -> dm.User:
    user = dm.User()

    user.id = USER_ID
    user.role_bindings = [{'name': 'reader'}]
    user.refresh_tokens = refresh_tokens if refresh_tokens is not None else []

    return user


def _make_db_session(
    user: dm.User | None = None,
) -> unittest.mock.AsyncMock:
    db_session = unittest.mock.AsyncMock()

    db_session.get = unittest.mock.AsyncMock(return_value=user)
    db_session.add = unittest.mock.MagicMock()
    db_session.commit = unittest.mock.AsyncMock()

    return db_session


def _make_request(
    token: str | None = None,
    user: dm.User | None = None,
) -> tuple:
    db_session = _make_db_session(user)

    app = unittest.mock.MagicMock()
    app.__getitem__ = lambda self, key: ISSUER

    request = unittest.mock.MagicMock()
    request.app = app
    request.cookies = {odg_client.jwt.REFRESH_TOKEN_KEY: token} if token else {}
    request.__getitem__ = lambda self, key: db_session
    request.__setitem__ = unittest.mock.MagicMock()

    return request, db_session


def _make_refresh_jwt(
    identifier: str,
    expired: bool = False,
) -> str:
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    exp = (
        int((now - datetime.timedelta(seconds=1)).timestamp())
        if expired
        else int((now + datetime.timedelta(days=30)).timestamp())
    )
    payload = {
        'iss': ISSUER,
        'exp': exp,
        'key_id': KEY_ID,
        'sub': USER_ID,
        'identifier': identifier,
    }
    return jwt.encode(
        payload=payload,
        key=_PRIVATE_KEY_PEM,
        algorithm=KEY_ALGORITHM,
    )


# ---------------------------------------------------------------------------
# set_session_and_refresh_token
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_set_session_creates_bearer_and_refresh_cookies(signing_cfg):
    user = _make_user()
    db_session = _make_db_session(user)

    response = await middleware.auth.set_session_and_refresh_token(
        user_id=USER_ID,
        issuer=ISSUER,
        db_session=db_session,
        signing_cfg=signing_cfg,
    )

    assert odg_client.jwt.JWT_KEY in response.cookies
    assert odg_client.jwt.REFRESH_TOKEN_KEY in response.cookies
    db_session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_set_session_without_refresh_token_only_sets_bearer_cookie(signing_cfg):
    user = _make_user()
    db_session = _make_db_session(user)

    response = await middleware.auth.set_session_and_refresh_token(
        user_id=USER_ID,
        issuer=ISSUER,
        db_session=db_session,
        signing_cfg=signing_cfg,
        use_refresh_token=False,
    )

    assert odg_client.jwt.JWT_KEY in response.cookies
    assert odg_client.jwt.REFRESH_TOKEN_KEY not in response.cookies


@pytest.mark.asyncio
async def test_set_session_raises_401_for_missing_user(signing_cfg):
    db_session = _make_db_session(user=None)

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        await middleware.auth.set_session_and_refresh_token(
            user_id=USER_ID,
            issuer=ISSUER,
            db_session=db_session,
            signing_cfg=signing_cfg,
        )


@pytest.mark.asyncio
async def test_set_session_raises_401_for_user_without_role_bindings(signing_cfg):
    user = _make_user()
    user.role_bindings = []
    db_session = _make_db_session(user)

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        await middleware.auth.set_session_and_refresh_token(
            user_id=USER_ID,
            issuer=ISSUER,
            db_session=db_session,
            signing_cfg=signing_cfg,
        )


@pytest.mark.asyncio
async def test_set_session_rotates_refresh_token(signing_cfg):
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    identifier = str(uuid.uuid4())
    identifier_hash = middleware.auth.hash_refresh_token_identifier(identifier)
    valid_exp = int((now + datetime.timedelta(days=30)).timestamp())

    user = _make_user(refresh_tokens=[{'identifier': identifier_hash, 'exp': valid_exp}])
    db_session = _make_db_session(user)

    response = await middleware.auth.set_session_and_refresh_token(
        user_id=USER_ID,
        issuer=ISSUER,
        db_session=db_session,
        signing_cfg=signing_cfg,
        existing_refresh_token_identifier=identifier,
    )

    assert odg_client.jwt.REFRESH_TOKEN_KEY in response.cookies
    assert len(user.refresh_tokens) == 1
    assert user.refresh_tokens[0]['identifier'] != identifier_hash


@pytest.mark.asyncio
async def test_set_session_rejects_unknown_refresh_token_identifier(signing_cfg):
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    known_identifier = str(uuid.uuid4())
    known_hash = middleware.auth.hash_refresh_token_identifier(known_identifier)
    valid_exp = int((now + datetime.timedelta(days=30)).timestamp())

    user = _make_user(refresh_tokens=[{'identifier': known_hash, 'exp': valid_exp}])
    db_session = _make_db_session(user)

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        await middleware.auth.set_session_and_refresh_token(
            user_id=USER_ID,
            issuer=ISSUER,
            db_session=db_session,
            signing_cfg=signing_cfg,
            existing_refresh_token_identifier=str(uuid.uuid4()),
        )


@pytest.mark.asyncio
async def test_set_session_rejects_expired_refresh_token_identifier(signing_cfg):
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    identifier = str(uuid.uuid4())
    identifier_hash = middleware.auth.hash_refresh_token_identifier(identifier)
    expired_exp = int((now - datetime.timedelta(seconds=1)).timestamp())

    user = _make_user(refresh_tokens=[{'identifier': identifier_hash, 'exp': expired_exp}])
    db_session = _make_db_session(user)

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        await middleware.auth.set_session_and_refresh_token(
            user_id=USER_ID,
            issuer=ISSUER,
            db_session=db_session,
            signing_cfg=signing_cfg,
            existing_refresh_token_identifier=identifier,
        )


@pytest.mark.asyncio
async def test_set_session_prunes_expired_tokens_from_db(signing_cfg):
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    expired_hash = middleware.auth.hash_refresh_token_identifier(str(uuid.uuid4()))
    expired_exp = int((now - datetime.timedelta(days=1)).timestamp())

    user = _make_user(refresh_tokens=[{'identifier': expired_hash, 'exp': expired_exp}])
    db_session = _make_db_session(user)

    await middleware.auth.set_session_and_refresh_token(
        user_id=USER_ID,
        issuer=ISSUER,
        db_session=db_session,
        signing_cfg=signing_cfg,
    )

    assert all(
        datetime.datetime.fromtimestamp(t['exp'], tz=datetime.timezone.utc) > now
        for t in user.refresh_tokens
    )


# ---------------------------------------------------------------------------
# OAuthRefresh POST
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_post_no_cookie_raises_401():
    request, _ = _make_request(token=None, user=None)

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        await middleware.auth.OAuthRefresh(request).post()


@pytest.mark.asyncio
async def test_refresh_post_expired_token_raises_401(signing_cfg):
    identifier = str(uuid.uuid4())
    token = _make_refresh_jwt(identifier, expired=True)

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    identifier_hash = middleware.auth.hash_refresh_token_identifier(identifier)
    valid_exp = int((now + datetime.timedelta(days=30)).timestamp())

    user = _make_user(refresh_tokens=[{'identifier': identifier_hash, 'exp': valid_exp}])
    request, _ = _make_request(token=token, user=user)

    secret_factory_mock = unittest.mock.MagicMock()
    secret_factory_mock.signing_cfg.return_value = [signing_cfg]

    with unittest.mock.patch('ctx_util.secret_factory', return_value=secret_factory_mock):
        with pytest.raises(aiohttp.web.HTTPUnauthorized):
            await middleware.auth.OAuthRefresh(request).post()


@pytest.mark.asyncio
async def test_refresh_post_valid_token_issues_new_cookies(signing_cfg):
    identifier = str(uuid.uuid4())
    token = _make_refresh_jwt(identifier)

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    identifier_hash = middleware.auth.hash_refresh_token_identifier(identifier)
    valid_exp = int((now + datetime.timedelta(days=30)).timestamp())

    user = _make_user(refresh_tokens=[{'identifier': identifier_hash, 'exp': valid_exp}])
    request, _ = _make_request(token=token, user=user)

    secret_factory_mock = unittest.mock.MagicMock()
    secret_factory_mock.signing_cfg.return_value = [signing_cfg]

    with unittest.mock.patch('ctx_util.secret_factory', return_value=secret_factory_mock):
        response = await middleware.auth.OAuthRefresh(request).post()

    assert odg_client.jwt.JWT_KEY in response.cookies
    assert odg_client.jwt.REFRESH_TOKEN_KEY in response.cookies


# ---------------------------------------------------------------------------
# OAuthLogout GET
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_logout_no_cookie_clears_cookies_without_touching_db():
    request, db_session = _make_request(token=None, user=None)

    response = await middleware.auth.OAuthLogout(request).get()

    assert response.status == 200
    assert response.cookies[odg_client.jwt.JWT_KEY]['max-age'] == '0'
    assert response.cookies[odg_client.jwt.REFRESH_TOKEN_KEY]['max-age'] == '0'
    db_session.get.assert_not_awaited()
    db_session.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_logout_valid_cookie_removes_only_matching_hash():
    identifier = str(uuid.uuid4())
    identifier_hash = middleware.auth.hash_refresh_token_identifier(identifier)

    other_identifier = str(uuid.uuid4())
    other_hash = middleware.auth.hash_refresh_token_identifier(other_identifier)

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    valid_exp = int((now + datetime.timedelta(days=30)).timestamp())

    user = _make_user(
        refresh_tokens=[
            {'identifier': identifier_hash, 'exp': valid_exp},
            {'identifier': other_hash, 'exp': valid_exp},
        ],
    )
    token = _make_refresh_jwt(identifier)
    request, db_session = _make_request(token=token, user=user)

    response = await middleware.auth.OAuthLogout(request).get()

    assert response.status == 200
    assert len(user.refresh_tokens) == 1
    assert user.refresh_tokens[0]['identifier'] == other_hash
    db_session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_logout_garbage_cookie_still_clears_cookies():
    request, db_session = _make_request(token='not.a.valid.jwt', user=None)

    response = await middleware.auth.OAuthLogout(request).get()

    assert response.status == 200
    assert response.cookies[odg_client.jwt.JWT_KEY]['max-age'] == '0'
    assert response.cookies[odg_client.jwt.REFRESH_TOKEN_KEY]['max-age'] == '0'
    db_session.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_logout_missing_identifier_claim_still_logs_out():
    """Cookie without 'identifier' claim (old format) — user is still logged out."""
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    payload = {
        'iss': ISSUER,
        'exp': int((now + datetime.timedelta(days=30)).timestamp()),
        'key_id': KEY_ID,
        'sub': USER_ID,
    }
    token = jwt.encode(payload=payload, key=_PRIVATE_KEY_PEM, algorithm='RS256')

    request, db_session = _make_request(token=token, user=_make_user())

    response = await middleware.auth.OAuthLogout(request).get()

    assert response.status == 200
    assert response.cookies[odg_client.jwt.JWT_KEY]['max-age'] == '0'
    assert response.cookies[odg_client.jwt.REFRESH_TOKEN_KEY]['max-age'] == '0'
    db_session.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_logout_user_missing_from_db_still_clears_cookies():
    """Deleted user's browser must not be stuck with an active bearer_token cookie."""
    token = _make_refresh_jwt(str(uuid.uuid4()))
    request, db_session = _make_request(token=token, user=None)

    response = await middleware.auth.OAuthLogout(request).get()

    assert response.status == 200
    assert response.cookies[odg_client.jwt.JWT_KEY]['max-age'] == '0'
    assert response.cookies[odg_client.jwt.REFRESH_TOKEN_KEY]['max-age'] == '0'
    db_session.commit.assert_not_awaited()


# ---------------------------------------------------------------------------
# OAuthLogin (POST /auth)
# ---------------------------------------------------------------------------


def _make_login_view(
    body: bytes = b'{}',
    content_type: str = 'application/json',
    query: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    user: dm.UserIdentifiers | None = None,
) -> middleware.auth.OAuthLogin:
    db_session = _make_db_session(user)

    app = unittest.mock.MagicMock()
    app.__getitem__ = lambda self, key: ISSUER

    request = unittest.mock.MagicMock()
    request.app = app
    request.content_type = content_type
    request.content_length = len(body)

    # aiohttp exposes the body via request.content.iter_any(); mock the same semantics
    async def iter_body(chunks: list[bytes] | None = None):
        for chunk in chunks or [body]:
            yield chunk

    request.content = unittest.mock.MagicMock()
    request.content.iter_any = iter_body
    request.iter_body = iter_body
    request.rel_url = yarl.URL.build(query=query or {})
    request.headers = headers or {}
    request.__getitem__ = lambda self, key: db_session

    view = middleware.auth.OAuthLogin(request)

    return view


def _make_user_idp() -> dm.UserIdentifiers:
    user_idp = dm.UserIdentifiers()
    user_idp.user_id = USER_ID

    return user_idp


@pytest.mark.asyncio
async def test_login_rejects_non_json_content_type():
    view = _make_login_view(content_type='text/plain')

    with pytest.raises(aiohttp.web.HTTPUnsupportedMediaType):
        await view.post()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'body',
    (
        b'',
        b'{invalid',
        b'"plain string"',
        b'[1, 2]',
        b'\xff',  # invalid UTF-8
        b'{"accessToken": "token"}',  # unknown field
        b'{"use_refresh_token": "true"}',  # wrong type
    ),
)
async def test_login_rejects_invalid_or_non_object_body(body):
    view = _make_login_view(body=body)

    with pytest.raises(aiohttp.web.HTTPBadRequest):
        await view.post()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'chunks',
    (
        # oversized body announced via Content-Length
        None,
        # oversized chunked body (no Content-Length; enforced while streaming)
        [b'{"code": "', b'x' * middleware.auth.POST_AUTH_BODY_MAX_SIZE],
    ),
)
async def test_login_rejects_oversized_body(chunks):
    view = _make_login_view(body=b'x' * (middleware.auth.POST_AUTH_BODY_MAX_SIZE + 1))

    if chunks is not None:
        view.request.content_length = None
        view.request.content.iter_any = lambda: view.request.iter_body(chunks)

    with pytest.raises(aiohttp.web.HTTPRequestEntityTooLarge):
        await view.post()


@pytest.mark.asyncio
async def test_login_bad_field_type_does_not_leak_value_in_traceback():
    token = 'ghp_example_secret'
    view = _make_login_view(body=json.dumps({'access_token': [token]}).encode())

    with pytest.raises(aiohttp.web.HTTPBadRequest) as excinfo:
        await view.post()

    # dacite's error contains the offending value; it must not be retained as exception context
    # (errors_middleware logs the full traceback, including chained exceptions)
    assert token not in ''.join(traceback.format_exception(excinfo.value))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'query',
    (
        {},
        {'access_token': 'token', 'api_url': 'https://github.example.com/api'},
        {'code': 'code', 'client_id': 'id'},
    ),
)
async def test_login_get_is_gone(query):
    # credentials in the URL end up in access logs and browser history -> GET login is removed
    view = _make_login_view(query=query)

    with pytest.raises(aiohttp.web.HTTPGone):
        await view.get()


class _GithubTokenResponse:
    status = 200

    def raise_for_status(self):
        pass

    async def text(self):
        return 'access_token=gho_example'

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None


@pytest.mark.asyncio
async def test_find_github_identifier_sends_client_secret_in_body():
    oauth_cfg = unittest.mock.MagicMock()
    oauth_cfg.token_url = 'https://github.example.com/login/oauth/access_token'
    oauth_cfg.client_id = 'client-id'
    oauth_cfg.client_secret = 'client-secret'

    session = unittest.mock.MagicMock()
    session.post = unittest.mock.MagicMock(return_value=_GithubTokenResponse())
    session.__aenter__ = unittest.mock.AsyncMock(return_value=session)
    session.__aexit__ = unittest.mock.AsyncMock(return_value=None)

    with (
        unittest.mock.patch('aiohttp.ClientSession', return_value=session),
        # stop after the token exchange, the GitHub user lookup is not of interest here
        unittest.mock.patch.object(middleware.auth, 'GithubApi', side_effect=RuntimeError),
        pytest.raises(RuntimeError),
    ):
        await middleware.auth.find_github_identifier(
            oauth_cfg=oauth_cfg,
            github_code='oauth-code',
        )

    session.post.assert_called_once()
    _, kwargs = session.post.call_args

    # no credentials in the URL (access logs of proxies/gateways), only in the POST body
    assert kwargs['url'] == oauth_cfg.token_url
    assert kwargs['data'] == {
        'client_id': 'client-id',
        'client_secret': 'client-secret',
        'code': 'oauth-code',
    }


@pytest.mark.asyncio
async def test_github_login_via_code_and_client_id(signing_cfg):
    view = _make_login_view(
        body=b'{"code": "code", "client_id": "id"}',
        user=_make_user_idp(),
    )

    with (
        unittest.mock.patch('ctx_util.secret_factory'),
        unittest.mock.patch.object(
            middleware.auth,
            'find_github_oauth_cfg',
            return_value=unittest.mock.MagicMock(),
        ),
        unittest.mock.patch.object(
            middleware.auth,
            'find_github_identifier',
            new=unittest.mock.AsyncMock(),
        ),
        unittest.mock.patch.object(
            middleware.auth,
            'find_role_bindings',
            return_value={'reader'},
        ),
        unittest.mock.patch.object(
            middleware.auth,
            'set_session_and_refresh_token',
            new=unittest.mock.AsyncMock(return_value=aiohttp.web.json_response()),
        ),
    ):
        response = await view.post()

    assert response.status == 200


@pytest.mark.asyncio
async def test_github_login_via_access_token_and_api_url(signing_cfg):
    view = _make_login_view(
        body=b'{"access_token": "token", "api_url": "https://github.example.com/api"}',
        user=_make_user_idp(),
    )

    with (
        unittest.mock.patch('ctx_util.secret_factory'),
        unittest.mock.patch.object(
            middleware.auth,
            'find_github_oauth_cfg',
            return_value=unittest.mock.MagicMock(),
        ),
        unittest.mock.patch.object(
            middleware.auth,
            'find_github_identifier',
            new=unittest.mock.AsyncMock(),
        ),
        unittest.mock.patch.object(
            middleware.auth,
            'set_session_and_refresh_token',
            new=unittest.mock.AsyncMock(return_value=aiohttp.web.json_response()),
        ),
    ):
        response = await view.post()

    assert response.status == 200


@pytest.mark.asyncio
async def test_oidc_login_via_authorization_header():
    view = _make_login_view(
        headers={'Authorization': 'Bearer oidc-token'},
        user=_make_user_idp(),
    )

    with (
        unittest.mock.patch('ctx_util.secret_factory'),
        unittest.mock.patch.object(
            middleware.auth,
            'find_oidc_cfg',
        ),
        unittest.mock.patch.object(
            middleware.auth,
            'verify_oidc_token',
            new=unittest.mock.AsyncMock(),
        ),
        unittest.mock.patch.object(
            middleware.auth,
            'set_session_and_refresh_token',
            new=unittest.mock.AsyncMock(return_value=aiohttp.web.json_response()),
        ),
    ):
        response = await view.post()

    assert response.status == 200


@pytest.mark.asyncio
async def test_oidc_login_via_access_token_in_body():
    view = _make_login_view(
        body=b'{"access_token": "oidc-token"}',
        user=_make_user_idp(),
    )

    with (
        unittest.mock.patch('ctx_util.secret_factory'),
        unittest.mock.patch.object(
            middleware.auth,
            'find_oidc_cfg',
        ),
        unittest.mock.patch.object(
            middleware.auth,
            'verify_oidc_token',
            new=unittest.mock.AsyncMock(),
        ),
        unittest.mock.patch.object(
            middleware.auth,
            'set_session_and_refresh_token',
            new=unittest.mock.AsyncMock(return_value=aiohttp.web.json_response()),
        ),
    ):
        response = await view.post()

    assert response.status == 200


@pytest.mark.asyncio
async def test_login_without_credentials_raises_401():
    view = _make_login_view(body=b'{}')

    with pytest.raises(aiohttp.web.HTTPUnauthorized) as excinfo:
        await view.post()

    assert 'WWW-Authenticate' in excinfo.value.headers


@pytest.mark.parametrize(
    'lookup_kwargs',
    [
        {'api_url': 'https://unknown.example.com'},
        {'client_id': 'unknown-client-id'},
    ],
)
def test_find_github_oauth_cfg_does_not_leak_configured_values(lookup_kwargs):
    oauth_cfg = secret_mgmt.oauth_cfg.OAuthCfg(
        name='internal',
        type=secret_mgmt.oauth_cfg.OAuthCfgTypes.GITHUB,
        api_url='https://github.internal.example.com',
        client_id='internal-client-id',
        client_secret='internal-client-secret',
    )

    with pytest.raises(aiohttp.web.HTTPUnauthorized) as excinfo:
        middleware.auth.find_github_oauth_cfg(
            oauth_cfgs=[oauth_cfg],
            **lookup_kwargs,
        )

    header = excinfo.value.headers['WWW-Authenticate']
    assert header == 'invalid api_url or client_id'
    assert oauth_cfg.api_url not in header
    assert oauth_cfg.client_id not in header
