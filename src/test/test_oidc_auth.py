import datetime
import unittest.mock

import aiohttp.web
import cryptography.hazmat.backends
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.serialization
import jwt
import pytest

import deliverydb.model as dm
import middleware.auth
import secret_mgmt.oauth_cfg


ISSUER = 'https://example.com/issuer'
JWKS_URI = 'https://example.com/issuer/jwks'
AUDIENCE = 'delivery-service'
SUB = 'system:serviceaccount:default:ocm-mcp'
ALGORITHM = 'RS256'


@pytest.fixture(autouse=True)
def clear_jwks_clients():
    yield
    middleware.auth._jwks_clients.clear()


@pytest.fixture()
def rsa_key_pair():
    private_key = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=cryptography.hazmat.backends.default_backend(),
    )
    return private_key, private_key.public_key()


@pytest.fixture()
def oidc_cfg():
    return secret_mgmt.oauth_cfg.OidcCfg(
        name='test',
        issuer=ISSUER,
        audiences=[AUDIENCE],
        role_bindings=[
            secret_mgmt.oauth_cfg.RoleBinding(
                subjects=[
                    secret_mgmt.oauth_cfg.Subject(
                        type=secret_mgmt.oauth_cfg.SubjectType.OIDC_SUB,
                        name=SUB,
                    ),
                ],
                roles=['reader'],
            ),
        ],
    )


@pytest.fixture()
def jwks_client_mock(rsa_key_pair):
    _, public_key = rsa_key_pair
    signing_key_mock = unittest.mock.MagicMock()
    signing_key_mock.key = public_key
    client_mock = unittest.mock.MagicMock()
    client_mock.get_signing_key_from_jwt.return_value = signing_key_mock
    return client_mock


def make_token(
    private_key,
    issuer: str = ISSUER,
    audience: str | list[str] = AUDIENCE,
    sub: str = SUB,
    expired: bool = False,
):
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    exp = now - datetime.timedelta(minutes=1) if expired else now + datetime.timedelta(hours=1)
    payload = {
        'iss': issuer,
        'sub': sub,
        'aud': audience,
        'iat': int(now.timestamp()),
        'exp': int(exp.timestamp()),
    }
    private_pem = private_key.private_bytes(
        cryptography.hazmat.primitives.serialization.Encoding.PEM,
        cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8,
        cryptography.hazmat.primitives.serialization.NoEncryption(),
    )
    return jwt.encode(payload, private_pem, algorithm=ALGORITHM)


@pytest.mark.asyncio
async def test_get_jwks_client_rejects_redirect(oidc_cfg):
    redirect_response = unittest.mock.AsyncMock()
    redirect_response.raise_for_status = unittest.mock.MagicMock(
        side_effect=aiohttp.ClientResponseError(
            request_info=unittest.mock.MagicMock(),
            history=(),
            status=301,
        ),
    )
    redirect_response.__aenter__ = unittest.mock.AsyncMock(return_value=redirect_response)
    redirect_response.__aexit__ = unittest.mock.AsyncMock(return_value=False)

    session_mock = unittest.mock.MagicMock()
    session_mock.get.return_value = redirect_response
    session_mock.__aenter__ = unittest.mock.AsyncMock(return_value=session_mock)
    session_mock.__aexit__ = unittest.mock.AsyncMock(return_value=False)

    with unittest.mock.patch('aiohttp.ClientSession', return_value=session_mock):
        with pytest.raises(aiohttp.web.HTTPUnauthorized):
            await middleware.auth._get_jwks_client(oidc_cfg=oidc_cfg)


@pytest.mark.asyncio
async def test_get_jwks_client_rejects_http_issuer():
    cfg = secret_mgmt.oauth_cfg.OidcCfg(
        name='test',
        issuer='http://example.com/issuer',
        audiences=[AUDIENCE],
    )
    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        await middleware.auth._get_jwks_client(oidc_cfg=cfg)


@pytest.mark.asyncio
async def test_get_jwks_client_rejects_http_jwks_uri(oidc_cfg):
    discovery_response = unittest.mock.AsyncMock()
    discovery_response.raise_for_status = unittest.mock.MagicMock()
    discovery_response.json = unittest.mock.AsyncMock(
        return_value={'jwks_uri': 'http://example.com/jwks'},
    )
    discovery_response.__aenter__ = unittest.mock.AsyncMock(return_value=discovery_response)
    discovery_response.__aexit__ = unittest.mock.AsyncMock(return_value=False)

    session_mock = unittest.mock.MagicMock()
    session_mock.get.return_value = discovery_response
    session_mock.__aenter__ = unittest.mock.AsyncMock(return_value=session_mock)
    session_mock.__aexit__ = unittest.mock.AsyncMock(return_value=False)

    with unittest.mock.patch('aiohttp.ClientSession', return_value=session_mock):
        with pytest.raises(aiohttp.web.HTTPUnauthorized):
            await middleware.auth._get_jwks_client(oidc_cfg=oidc_cfg)


@pytest.mark.asyncio
async def test_get_jwks_client_fetches_discovery_and_jwks_uri(oidc_cfg):
    discovery_response = unittest.mock.AsyncMock()
    discovery_response.raise_for_status = unittest.mock.MagicMock()
    discovery_response.json = unittest.mock.AsyncMock(return_value={'jwks_uri': JWKS_URI})
    discovery_response.__aenter__ = unittest.mock.AsyncMock(return_value=discovery_response)
    discovery_response.__aexit__ = unittest.mock.AsyncMock(return_value=False)

    session_mock = unittest.mock.MagicMock()
    session_mock.get.return_value = discovery_response
    session_mock.__aenter__ = unittest.mock.AsyncMock(return_value=session_mock)
    session_mock.__aexit__ = unittest.mock.AsyncMock(return_value=False)

    with unittest.mock.patch('aiohttp.ClientSession', return_value=session_mock):
        with unittest.mock.patch('jwt.PyJWKClient') as jwks_client_cls:
            await middleware.auth._get_jwks_client(oidc_cfg=oidc_cfg)

    session_mock.get.assert_called_once_with(
        oidc_cfg.oidc_cfg_url,
        timeout=unittest.mock.ANY,
        allow_redirects=False,
    )
    jwks_client_cls.assert_called_once_with(JWKS_URI, cache_keys=True)


@pytest.mark.asyncio
async def test_get_jwks_client_missing_jwks_uri(oidc_cfg):
    discovery_response = unittest.mock.AsyncMock()
    discovery_response.raise_for_status = unittest.mock.MagicMock()
    discovery_response.json = unittest.mock.AsyncMock(return_value={})
    discovery_response.__aenter__ = unittest.mock.AsyncMock(return_value=discovery_response)
    discovery_response.__aexit__ = unittest.mock.AsyncMock(return_value=False)

    session_mock = unittest.mock.MagicMock()
    session_mock.get.return_value = discovery_response
    session_mock.__aenter__ = unittest.mock.AsyncMock(return_value=session_mock)
    session_mock.__aexit__ = unittest.mock.AsyncMock(return_value=False)

    with unittest.mock.patch('aiohttp.ClientSession', return_value=session_mock):
        with pytest.raises(aiohttp.web.HTTPUnauthorized):
            await middleware.auth._get_jwks_client(oidc_cfg=oidc_cfg)


@pytest.mark.asyncio
async def test_get_jwks_client_reuses_cached_client(oidc_cfg, jwks_client_mock):
    middleware.auth._jwks_clients[oidc_cfg.issuer] = jwks_client_mock

    with unittest.mock.patch('aiohttp.ClientSession') as session_cls:
        result = await middleware.auth._get_jwks_client(oidc_cfg=oidc_cfg)

    session_cls.assert_not_called()
    assert result is jwks_client_mock


@pytest.mark.asyncio
async def test_verify_oidc_token_valid(rsa_key_pair, oidc_cfg, jwks_client_mock):
    private_key, _ = rsa_key_pair
    token = make_token(private_key)

    with unittest.mock.patch(
        'middleware.auth._get_jwks_client',
        return_value=jwks_client_mock,
    ):
        result = await middleware.auth.verify_oidc_token(
            token=token,
            oidc_cfg=oidc_cfg,
        )

    assert isinstance(result, dm.OidcIdentifier)
    assert result.sub == SUB
    assert result.issuer == ISSUER


@pytest.mark.asyncio
async def test_verify_oidc_token_wrong_audience(rsa_key_pair, oidc_cfg, jwks_client_mock):
    private_key, _ = rsa_key_pair
    token = make_token(private_key, audience='wrong-audience')

    with unittest.mock.patch(
        'middleware.auth._get_jwks_client',
        return_value=jwks_client_mock,
    ):
        with pytest.raises(aiohttp.web.HTTPUnauthorized):
            await middleware.auth.verify_oidc_token(
                token=token,
                oidc_cfg=oidc_cfg,
            )


@pytest.mark.asyncio
async def test_verify_oidc_token_wrong_issuer(rsa_key_pair, oidc_cfg, jwks_client_mock):
    private_key, _ = rsa_key_pair
    token = make_token(private_key, issuer='https://other-issuer.com')

    with unittest.mock.patch(
        'middleware.auth._get_jwks_client',
        return_value=jwks_client_mock,
    ):
        with pytest.raises(aiohttp.web.HTTPUnauthorized):
            await middleware.auth.verify_oidc_token(
                token=token,
                oidc_cfg=oidc_cfg,
            )


@pytest.mark.asyncio
async def test_verify_oidc_token_missing_sub(rsa_key_pair, oidc_cfg, jwks_client_mock):
    private_key, _ = rsa_key_pair
    token = make_token(private_key, sub='')

    with unittest.mock.patch(
        'middleware.auth._get_jwks_client',
        return_value=jwks_client_mock,
    ):
        with unittest.mock.patch('jwt.decode', return_value={'iss': ISSUER}):
            with pytest.raises(aiohttp.web.HTTPUnauthorized):
                await middleware.auth.verify_oidc_token(
                    token=token,
                    oidc_cfg=oidc_cfg,
                )


@pytest.mark.asyncio
async def test_verify_oidc_token_jwks_failure(rsa_key_pair, oidc_cfg):
    private_key, _ = rsa_key_pair
    token = make_token(private_key)

    jwks_client_mock = unittest.mock.MagicMock()
    jwks_client_mock.get_signing_key_from_jwt.side_effect = Exception('JWKS fetch failed')

    with unittest.mock.patch(
        'middleware.auth._get_jwks_client',
        return_value=jwks_client_mock,
    ):
        with pytest.raises(aiohttp.web.HTTPUnauthorized):
            await middleware.auth.verify_oidc_token(
                token=token,
                oidc_cfg=oidc_cfg,
            )


def test_find_oidc_role_bindings_match(oidc_cfg):
    identifier = dm.OidcIdentifier(sub=SUB, issuer=ISSUER)
    role_bindings = list(middleware.auth.find_oidc_role_bindings(oidc_cfg, identifier))

    assert len(role_bindings) == 1
    assert role_bindings[0].name == 'reader'


def test_find_oidc_role_bindings_no_match(oidc_cfg):
    identifier = dm.OidcIdentifier(
        sub='system:serviceaccount:other:other-sa',
        issuer=ISSUER,
    )
    role_bindings = list(middleware.auth.find_oidc_role_bindings(oidc_cfg, identifier))

    assert role_bindings == []


def test_find_oidc_role_bindings_regex_match():
    cfg = secret_mgmt.oauth_cfg.OidcCfg(
        name='test',
        issuer=ISSUER,
        audiences=[AUDIENCE],
        role_bindings=[
            secret_mgmt.oauth_cfg.RoleBinding(
                subjects=[
                    secret_mgmt.oauth_cfg.Subject(
                        type=secret_mgmt.oauth_cfg.SubjectType.OIDC_SUB,
                        name='system:serviceaccount:default:.*',
                    ),
                ],
                roles=['reader'],
            ),
        ],
    )
    identifier = dm.OidcIdentifier(sub=SUB, issuer=ISSUER)
    role_bindings = list(middleware.auth.find_oidc_role_bindings(cfg, identifier))

    assert len(role_bindings) == 1


@pytest.mark.asyncio
async def test_verify_oidc_token_missing_exp(rsa_key_pair, oidc_cfg, jwks_client_mock):
    private_key, _ = rsa_key_pair
    # token without exp claim
    private_pem = private_key.private_bytes(
        cryptography.hazmat.primitives.serialization.Encoding.PEM,
        cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8,
        cryptography.hazmat.primitives.serialization.NoEncryption(),
    )
    token = jwt.encode(
        {'iss': ISSUER, 'sub': SUB, 'aud': AUDIENCE,
         'iat': int(datetime.datetime.now(tz=datetime.timezone.utc).timestamp())},
        private_pem,
        algorithm=ALGORITHM,
    )

    with unittest.mock.patch(
        'middleware.auth._get_jwks_client',
        return_value=jwks_client_mock,
    ):
        with pytest.raises(aiohttp.web.HTTPUnauthorized):
            await middleware.auth.verify_oidc_token(
                token=token,
                oidc_cfg=oidc_cfg,
            )


@pytest.mark.asyncio
async def test_verify_oidc_token_wrong_algorithm(oidc_cfg, jwks_client_mock):
    # HS256 token — not RS256, should be rejected
    token = jwt.encode(
        {'iss': ISSUER, 'sub': SUB, 'aud': AUDIENCE,
         'iat': int(datetime.datetime.now(tz=datetime.timezone.utc).timestamp()),
         'exp': int((datetime.datetime.now(tz=datetime.timezone.utc)
                     + datetime.timedelta(hours=1)).timestamp())},
        'secret',
        algorithm='HS256',
    )

    with unittest.mock.patch(
        'middleware.auth._get_jwks_client',
        return_value=jwks_client_mock,
    ):
        with pytest.raises(aiohttp.web.HTTPUnauthorized):
            await middleware.auth.verify_oidc_token(
                token=token,
                oidc_cfg=oidc_cfg,
            )


def test_oidc_issuer_lookup_found(oidc_cfg):
    token = jwt.encode(
        {'iss': ISSUER, 'sub': SUB, 'aud': AUDIENCE},
        'secret',
        algorithm='HS256',
    )
    result = middleware.auth.find_oidc_cfg(token=token, oidc_cfgs=[oidc_cfg])
    assert result is oidc_cfg


def test_oidc_issuer_lookup_not_found(oidc_cfg):
    token = jwt.encode(
        {'iss': 'https://unknown-issuer.com', 'sub': SUB, 'aud': AUDIENCE},
        'secret',
        algorithm='HS256',
    )
    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        middleware.auth.find_oidc_cfg(token=token, oidc_cfgs=[oidc_cfg])


def test_oidc_issuer_lookup_malformed_token(oidc_cfg):
    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        middleware.auth.find_oidc_cfg(token='not.a.jwt', oidc_cfgs=[oidc_cfg])


def test_deserialised_identifier_oidc():
    user_identifiers = dm.UserIdentifiers()
    user_identifiers.type = secret_mgmt.oauth_cfg.OAuthCfgTypes.OIDC
    user_identifiers.identifier = {'sub': SUB, 'issuer': ISSUER}

    result = user_identifiers.deserialised_identifier

    assert isinstance(result, dm.OidcIdentifier)
    assert result.sub == SUB
    assert result.issuer == ISSUER
