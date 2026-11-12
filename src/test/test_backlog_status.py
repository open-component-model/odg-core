import datetime
import unittest.mock

import k8s.backlog


def _make_api():
    api = unittest.mock.MagicMock()
    api.custom_kubernetes_api.replace_namespaced_custom_object.return_value = {}
    return api


def _make_backlog_crd(
    name: str = 'item-abc',
    spec: dict | None = None,
    status: dict | None = None,
) -> dict:
    return {
        'metadata': {
            'name': name,
        },
        'spec': spec or {},
        'status': status or {},
    }


def test_set_status_calls_replace_with_correct_body():
    api = _make_api()
    backlog_crd = _make_backlog_crd()

    k8s.backlog.set_backlog_item_status(
        namespace='delivery',
        kubernetes_api=api,
        backlog_crd=backlog_crd,
        phase=k8s.backlog.BacklogItemPhase.PROCESSING,
        claimed_by='worker-pod-1',
        claimed_at=datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc),
    )

    call = api.custom_kubernetes_api.replace_namespaced_custom_object.call_args
    body = call.kwargs['body']
    assert body['status']['phase'] == k8s.backlog.BacklogItemPhase.PROCESSING
    assert body['status']['claimed_by'] == 'worker-pod-1'
    assert body['status']['error'] is None


def test_set_status_clears_fields_when_none():
    api = _make_api()
    backlog_crd = _make_backlog_crd(
        status={
            'claimed_by': 'worker-pod-1',
            'claimed_at': datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc),
            'error': {
                'message': 'foo',
                'traceback': 'bar',
            },
        },
    )

    k8s.backlog.set_backlog_item_status(
        namespace='delivery',
        kubernetes_api=api,
        backlog_crd=backlog_crd,
        phase=k8s.backlog.BacklogItemPhase.PENDING,
    )

    call = api.custom_kubernetes_api.replace_namespaced_custom_object.call_args
    body = call.kwargs['body']
    assert body['status']['claimed_by'] is None
    assert body['status']['claimed_at'] is None
    assert body['status']['error'] is None


def test_set_status_stores_error_dict():
    api = _make_api()
    backlog_crd = _make_backlog_crd()

    k8s.backlog.set_backlog_item_status(
        namespace='delivery',
        kubernetes_api=api,
        backlog_crd=backlog_crd,
        phase=k8s.backlog.BacklogItemPhase.FAILED,
        claimed_by='worker-pod-1',
        claimed_at=None,
        error={'message': 'boom', 'traceback': 'Traceback...'},
    )

    call = api.custom_kubernetes_api.replace_namespaced_custom_object.call_args
    body = call.kwargs['body']
    assert body['status']['phase'] == k8s.backlog.BacklogItemPhase.FAILED
    assert body['status']['error']['message'] == 'boom'
