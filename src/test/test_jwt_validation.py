import datetime
import unittest.mock

import aiohttp.web
import Crypto.PublicKey.RSA
import jwt
import pytest

import middleware.auth
import odg_client.jwt

ISSUER = 'delivery_service'
KEY_ID = 'foobar'
JWT_ALGORITHM = 'RS256'
_rsa_key = Crypto.PublicKey.RSA.generate(2048)
JWT_PRIVATE_KEY = _rsa_key.export_key().decode()
JWT_PUBLIC_KEY = _rsa_key.public_key().export_key().decode()


def gen_jwt_payload():
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    return {
        'version': 'v2',
        'sub': 'service_user',
        'iss': ISSUER,
        'iat': int((now - datetime.timedelta(minutes=10)).timestamp()),
        'exp': int((now + datetime.timedelta(minutes=5)).timestamp()),
        'key_id': '1',
        'roles': [],
    }


def gen_jwt_token(
    payload: dict,
    key: str = JWT_PRIVATE_KEY,
    algorithm: str = JWT_ALGORITHM,
):
    return jwt.encode(
        payload=payload,
        key=key,
        algorithm=algorithm,
    )


@pytest.fixture()
def signing_cfg():
    signing_cfg_mock = unittest.mock.Mock()
    signing_cfg_mock.id = KEY_ID
    signing_cfg_mock.private_key = JWT_PRIVATE_KEY
    signing_cfg_mock.public_key = JWT_PUBLIC_KEY
    signing_cfg_mock.algorithm = JWT_ALGORITHM

    return signing_cfg_mock


def test_valid_token():
    payload = gen_jwt_payload()
    middleware.auth.validate_jwt_payload(decoded_jwt=payload)


def test_no_exp():
    payload = gen_jwt_payload()
    payload.pop('exp')
    middleware.auth.validate_jwt_payload(decoded_jwt=payload)


def test_wrong_exp_format():
    payload = gen_jwt_payload()
    # will return float
    payload['exp'] = datetime.datetime.now(tz=datetime.timezone.utc).timestamp()

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        middleware.auth.validate_jwt_payload(payload)


def test_no_iss():
    payload = gen_jwt_payload()
    payload.pop('iss')

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        middleware.auth.validate_jwt_payload(payload)


def test_wrong_iss(signing_cfg):
    payload = gen_jwt_payload()
    payload['iss'] = 'foo_bar'

    token = gen_jwt_token(payload=payload)

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        middleware.auth.decode_jwt(
            token=token,
            issuer=ISSUER,
            signing_cfg=signing_cfg,
            verify_signature=True,
        )


def test_no_iat():
    payload = gen_jwt_payload()
    payload.pop('iat')

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        middleware.auth.validate_jwt_payload(payload)


def test_future_iat(signing_cfg):
    payload = gen_jwt_payload()
    payload['iat'] = int(
        (
            datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(minutes=100)
        ).timestamp(),
    )

    token = gen_jwt_token(payload=payload)

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        middleware.auth.decode_jwt(
            token=token,
            issuer=ISSUER,
            signing_cfg=signing_cfg,
            verify_signature=True,
        )


def test_no_sub():
    payload = gen_jwt_payload()
    payload.pop('sub')

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        middleware.auth.validate_jwt_payload(payload)


def test_wrong_version():
    payload = gen_jwt_payload()
    payload['version'] = 'versionNotSet5000'

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        middleware.auth.validate_jwt_payload(payload)


def test_no_version():
    payload = gen_jwt_payload()
    payload.pop('version')

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        middleware.auth.validate_jwt_payload(payload)


def test_nbf_in_past():
    payload = gen_jwt_payload()
    payload['nbf'] = int(
        (
            datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(minutes=100)
        ).timestamp(),
    )

    middleware.auth.validate_jwt_payload(payload)


def test_nbf_in_future(signing_cfg):
    payload = gen_jwt_payload()
    payload['nbf'] = int(
        (
            datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(minutes=100)
        ).timestamp(),
    )

    token = gen_jwt_token(payload=payload)

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        middleware.auth.decode_jwt(
            token=token,
            issuer=ISSUER,
            signing_cfg=signing_cfg,
            verify_signature=True,
        )


def test_no_roles():
    payload = gen_jwt_payload()
    payload.pop('roles')

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        middleware.auth.validate_jwt_payload(payload)


def test_jwt_from_signing_cfg(signing_cfg):
    jwt = middleware.auth.jwt_from_signing_cfg(signing_cfg)
    jwt.use is odg_client.jwt.Use.SIGNATURE
    jwt.kid is KEY_ID
    jwt.key == JWT_PUBLIC_KEY.encode()

    invalid_signing_cfg_mock = unittest.mock.MagicMock()
    invalid_signing_cfg_mock.algorithm = 'HS256'

    with pytest.raises(ValueError):
        middleware.auth.jwt_from_signing_cfg(invalid_signing_cfg_mock)
