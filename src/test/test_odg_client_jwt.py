import datetime
import unittest.mock

import Crypto.PublicKey.RSA
import jwt
import pytest
import requests.cookies

import odg_client
import odg_client.jwt


ISSUER = 'test-issuer'
private_key = Crypto.PublicKey.RSA.generate(4096)
public_key = private_key.public_key()


@pytest.fixture
def json_web_key() -> odg_client.jwt.JSONWebKey:
    return odg_client.jwt.JSONWebKey.from_dict(
        data={
            'use': odg_client.jwt.Use.SIGNATURE,
            'kid': 'foo',
            'alg': odg_client.jwt.Algorithm.RS256,
            'n': odg_client.jwt.encodeBase64urlUInt(public_key.n),
            'e': odg_client.jwt.encodeBase64urlUInt(private_key.e),
        },
    )


@pytest.fixture
def token() -> str:
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    time_delta = datetime.timedelta(days=730)  # 2 years

    token = {
        'version': 'v1',
        'sub': 'test-user',
        'iss': ISSUER,
        'iat': int(now.timestamp()),
        'github_oAuth': {
            'host': 'github',
            'team_names': [],
            'email_address': 'test-user@email.com',
        },
        'exp': int((now + time_delta).timestamp()),
        'key_id': '0',
    }

    return jwt.encode(
        payload=token,
        key=private_key.export_key(format='PEM'),
        algorithm=odg_client.jwt.Algorithm.RS256,
    )


def test_jwt(json_web_key, token):
    # token was just created and thus is not expired yet
    assert not odg_client.jwt.is_jwt_token_expired(
        token=token,
    )

    # this is a correct token validation
    odg_client.jwt.decode_jwt(
        token=token,
        verify_signature=True,
        json_web_key=json_web_key,
        issuer=ISSUER,
    )

    # no key supplied but token validation requested
    with pytest.raises(ValueError):
        odg_client.jwt.decode_jwt(
            token=token,
            verify_signature=True,
            json_web_key=None,
            issuer=ISSUER,
        )

    # token validation but with wrong issuer
    with pytest.raises(jwt.exceptions.InvalidIssuerError):
        odg_client.jwt.decode_jwt(
            token=token,
            verify_signature=True,
            json_web_key=json_web_key,
            issuer='wrong-issuer',
        )


def _make_client(**kwargs) -> odg_client.DeliveryServiceClient:
    routes = odg_client.DeliveryServiceRoutes(base_url='https://delivery-service.example.com')
    return odg_client.DeliveryServiceClient(routes=routes, **kwargs)


def _make_oidc_client(**kwargs) -> odg_client.DeliveryServiceClient:
    routes = odg_client.DeliveryServiceRoutes(base_url='https://delivery-service.example.com')
    return odg_client.DeliveryServiceClient.for_oidc(routes=routes, **kwargs)


def _mock_auth_response(bearer_token: str) -> unittest.mock.Mock:
    res = unittest.mock.Mock()
    res.ok = True
    res.cookies = requests.cookies.RequestsCookieJar()
    res.cookies.set(odg_client.jwt.JWT_KEY, bearer_token)
    return res


def test_oidc_token_calls_auth_with_bearer_header():
    client = _make_oidc_client(token='sa-token-123')
    mock_response = _mock_auth_response('session-jwt')

    with unittest.mock.patch.object(client._session, 'get', return_value=mock_response) as mock_get:
        client._authenticate()

    mock_get.assert_called_once()
    _, kwargs = mock_get.call_args
    assert kwargs['headers']['Authorization'] == 'Bearer sa-token-123'
    assert client._bearer_token == 'session-jwt'


def test_oidc_token_lookup_calls_lookup_on_each_auth():
    call_count = 0

    def fresh_token():
        nonlocal call_count
        call_count += 1
        return f'sa-token-{call_count}'

    client = _make_oidc_client(token_lookup=fresh_token)
    mock_response = _mock_auth_response('session-jwt')

    with unittest.mock.patch.object(client._session, 'get', return_value=mock_response):
        client._authenticate()
        client._bearer_token = None  # force re-auth
        client._authenticate()

    assert call_count == 2


def test_oidc_token_and_lookup_are_mutually_exclusive():
    with pytest.raises(ValueError):
        _make_oidc_client(token='tok', token_lookup=lambda: 'tok')


def test_for_oidc_requires_token_or_lookup():
    with pytest.raises(ValueError):
        _make_oidc_client()


def test_oidc_and_github_auth_are_mutually_exclusive():
    # The API enforces this by having separate factory methods — verify
    # the deprecated __init__ still validates the old-style combinations.
    with pytest.warns(DeprecationWarning), pytest.raises(ValueError):
        _make_client(auth_token='gh-tok', auth_token_lookup=lambda api_url: 'gh-tok')
