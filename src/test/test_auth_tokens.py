import datetime
import unittest.mock
import uuid

import aiohttp.web
import Crypto.PublicKey.RSA
import jwt
import pytest

import deliverydb.model as dm
import middleware.auth
import odg_client.jwt
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
