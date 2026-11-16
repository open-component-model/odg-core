import requests.adapters
import pytest

import delivery.client
import odg_client

BASE_URL = 'https://delivery-service.example.com'


@pytest.fixture(name='routes')
def _routes():
    return odg_client.DeliveryServiceRoutes(base_url=BASE_URL)


def _expected_retry(max_retries: int | None):
    return requests.adapters.HTTPAdapter(max_retries=max_retries).max_retries


@pytest.mark.parametrize('max_retries', (None, 0, 5))
def test_odg_client_auth_route_retries_post(routes, max_retries):
    client = odg_client.DeliveryServiceClient.for_oidc(
        routes=routes,
        token='token',
        max_retries=max_retries,
    )

    expected_retry = _expected_retry(max_retries)

    auth_retry = client._session.get_adapter(routes.auth()).max_retries
    assert 'POST' in auth_retry.allowed_methods
    assert auth_retry.total == expected_retry.total
    assert auth_retry.read == expected_retry.read

    other_retry = client._session.get_adapter(f'{BASE_URL}/other').max_retries
    assert 'POST' not in other_retry.allowed_methods


@pytest.mark.parametrize('max_retries', (None, 0, 5))
def test_delivery_client_auth_route_retries_post(max_retries):
    routes = delivery.client.DeliveryServiceRoutes(base_url=BASE_URL)
    client = delivery.client.DeliveryServiceClient(
        routes=routes,
        auth_token='token',
        max_retries=max_retries,
    )

    expected_retry = _expected_retry(max_retries)

    auth_retry = client._session.get_adapter(routes.auth()).max_retries
    assert 'POST' in auth_retry.allowed_methods
    assert auth_retry.total == expected_retry.total
    assert auth_retry.read == expected_retry.read

    other_retry = client._session.get_adapter(f'{BASE_URL}/other').max_retries
    assert 'POST' not in other_retry.allowed_methods
