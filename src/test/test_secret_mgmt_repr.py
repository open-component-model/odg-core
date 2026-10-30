"""
Regression tests for credential leakage via dataclass __repr__ into logs.

Background: every secret-holding class in `secret_mgmt` uses @dataclass, whose
auto-generated __repr__ serializes every field — including credentials — into
strings. If any such object gets interpolated into an exception message
(f"connect failed with {cfg}"), the secret is baked into the traceback and our
JSON log output ships it verbatim.

The defence is at the model level: `dataclasses.field(repr=False)` on every
credential field. These tests pin that contract for each class in the package.
If a new class or credential field is added without repr=False, extend the
parameter list below (test author: this file appearing in your diff is the
reminder).
"""

import dataclasses

import pytest

import secret_mgmt.aws
import secret_mgmt.bdba
import secret_mgmt.blackduck
import secret_mgmt.delivery_db
import secret_mgmt.github
import secret_mgmt.oauth_cfg
import secret_mgmt.oci_registry
import secret_mgmt.ppms
import secret_mgmt.signing_cfg


SECRET = 's3cr3t-value-not-matching-any-scrubber'


def _init_with_secret(cls, secret_field: str):
    """instantiate a dataclass with dummy values, `secret_field` set to SECRET"""
    field_values = {}
    for field in dataclasses.fields(cls):
        if not field.init:
            continue
        if field.name == secret_field:
            field_values[field.name] = SECRET
        elif field.type is str or field.type == 'str':
            field_values[field.name] = 'dummy'
        elif field.type is int or field.type == 'int':
            field_values[field.name] = 1
        elif field.type is bool or field.type == 'bool':
            field_values[field.name] = True
        elif hasattr(field.type, '__origin__') or field.type in ('list', list):
            field_values[field.name] = []
        else:
            field_values[field.name] = None

    return cls(**field_values)


@pytest.mark.parametrize(
    'cls,secret_field',
    [
        (secret_mgmt.aws.AWS, 'secret_access_key'),
        (secret_mgmt.bdba.BDBA, 'token'),
        (secret_mgmt.blackduck.BlackDuck, 'token'),
        (secret_mgmt.delivery_db.DeliveryDB, 'password'),
        (secret_mgmt.github.GitHubApp, 'private_key'),
        (secret_mgmt.github.GitHub, 'auth_token'),
        (secret_mgmt.oauth_cfg.OAuthCfg, 'client_secret'),
        (secret_mgmt.oci_registry.OciRegistry, 'password'),
        (secret_mgmt.ppms.PPMS, 'password'),
        (secret_mgmt.signing_cfg.SigningCfg, 'private_key'),
    ],
)
def test_secret_field_not_in_repr(cls, secret_field: str):
    instance = _init_with_secret(cls, secret_field)
    assert SECRET not in repr(instance), (
        f'{cls.__name__}.{secret_field} is exposed via __repr__; use dataclasses.field(repr=False)'
    )
    assert SECRET not in str(instance)


@pytest.mark.parametrize(
    'cls,secret_field',
    [
        (secret_mgmt.aws.AWS, 'secret_access_key'),
        (secret_mgmt.delivery_db.DeliveryDB, 'password'),
        (secret_mgmt.github.GitHubApp, 'private_key'),
        (secret_mgmt.oci_registry.OciRegistry, 'password'),
    ],
)
def test_secret_not_in_exception_message(cls, secret_field: str):
    """the exact article scenario: object lands in f-string inside raise"""
    instance = _init_with_secret(cls, secret_field)

    try:
        raise ValueError(f'operation failed with {instance}')
    except ValueError as e:
        assert SECRET not in str(e), (
            f'{cls.__name__} leaks {secret_field} when embedded in an exception '
            'message; fix belongs on the model (repr=False)'
        )
