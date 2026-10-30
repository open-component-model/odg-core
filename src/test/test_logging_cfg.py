import dataclasses
import io
import json
import logging
import sys
import threading

import pytest

import aiohttp.web_log

import odg.logging_cfg as lc


@pytest.fixture
def preserve_excepthooks():
    """configure_logging replaces sys.excepthook and threading.excepthook
    globally; restore them so later tests run with the original hooks."""
    sys_hook = sys.excepthook
    threading_hook = threading.excepthook
    yield
    sys.excepthook = sys_hook
    threading.excepthook = threading_hook


def _configured_logging(**kwargs) -> io.StringIO:
    """configure structlog to render JSON into a captured stdout stream"""
    defaults = {'json_logs': True, 'service_name': 'test-service', 'stream': None}
    defaults.update(kwargs)

    captured = io.StringIO()
    defaults['stream'] = captured

    # structlog/ loggers cache; reset between configure calls
    lc.configure_logging(**defaults)

    return captured


def _log_lines(captured: io.StringIO) -> list[dict]:
    captured.seek(0)
    return [json.loads(line) for line in captured if line.strip()]


def test_unhandled_main_thread_exception_goes_through_structlog(preserve_excepthooks):
    captured = _configured_logging()

    try:
        raise RuntimeError('boom main')
    except RuntimeError as e:
        sys.excepthook(type(e), e, e.__traceback__)

    (entry,) = _log_lines(captured)
    assert entry['event'] == 'unhandled exception in main thread; process will exit'
    assert 'boom main' in entry['exception']
    assert 'RuntimeError' in entry['exception']
    assert entry['service.name'] == 'test-service'
    assert entry['level'] == 'critical'


def test_unhandled_daemon_thread_exception_goes_through_structlog(preserve_excepthooks):
    captured = _configured_logging()

    class FakeThread:
        name = 'worker-7'

    try:
        raise ValueError('boom thread')
    except ValueError:
        exc_type, exc_value, exc_tb = sys.exc_info()
        args = threading.ExceptHookArgs((exc_type, exc_value, exc_tb, FakeThread()))
        threading.excepthook(args)

    (entry,) = _log_lines(captured)
    assert entry['event'] == 'unhandled exception in worker-7; process will exit'
    assert 'boom thread' in entry['exception']
    assert 'ValueError' in entry['exception']


def test_keyboardinterrupt_and_systemexit_pass_through_to_previous_hook(preserve_excepthooks):
    """Ctrl+C and sys.exit must NOT be rerouted to JSON, otherwise interactive
    Ctrl+C would print a structured traceback instead of silently exiting, and
    sys.exit() would look like a crash."""
    passthrough = []

    def sentinel_prev(exc_type, exc_value, exc_tb):
        passthrough.append(exc_type)

    sys.excepthook = sentinel_prev  # becomes 'previous' once configure swaps it
    _configured_logging()

    for exc in (KeyboardInterrupt(), SystemExit(0)):
        sys.excepthook(type(exc), exc, exc.__traceback__)

    assert passthrough == [KeyboardInterrupt, SystemExit]


def test_stdlib_logger_emits_json_with_service_name():
    captured = _configured_logging()

    logging.getLogger('some.module').info('hello world')

    (entry,) = _log_lines(captured)
    assert entry['event'] == 'hello world'
    assert entry['service.name'] == 'test-service'
    assert entry['logger'] == 'some.module'
    assert entry['level'] == 'info'
    assert 'timestamp' in entry


def test_structlog_logger_emits_json():
    import structlog

    captured = _configured_logging()

    structlog.get_logger('native').info('native event', **{'artefact.name': 'my-artefact'})

    (entry,) = _log_lines(captured)
    assert entry['event'] == 'native event'
    assert entry['artefact.name'] == 'my-artefact'
    assert entry['service.name'] == 'test-service'


def test_sensitive_key_in_extra_is_scrubbed():
    captured = _configured_logging()

    logging.getLogger('leaky.lib').warning(
        'request sent',
        extra={'Authorization': 'Bearer topsecretvalue1234', 'harmless': 'kept'},
    )

    (entry,) = _log_lines(captured)
    assert entry['Authorization'] == '***'
    assert entry['harmless'] == 'kept'


def test_sensitive_value_in_message_string_is_scrubbed():
    captured = _configured_logging()

    token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig'
    logging.getLogger('leaky.lib').warning(f'sending Authorization: Bearer {token}')

    (entry,) = _log_lines(captured)
    assert token not in entry['event']
    assert '***' in entry['event']


def test_sensitive_query_param_in_url_is_scrubbed():
    captured = _configured_logging()

    logging.getLogger('access').info(
        'GET /reset?token=abc123secret&locale=en -> 200',
        extra={lc.URL_QUERY: 'token=abc123secret&locale=en'},
    )

    (entry,) = _log_lines(captured)
    assert 'abc123secret' not in json.dumps(entry)
    assert 'locale=en' in entry[lc.URL_QUERY]


def test_urllib3_prefix_filter_applied_to_preexisting_file_handler(tmp_path):
    """urllib3 DEBUG chatter must not spam LogCollection CRD files"""
    import k8s.logging

    log_file = tmp_path / 'crd.log'
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(k8s.logging.LogCollectionFormatter())
    file_handler.setLevel(logging.DEBUG)
    logging.root.addHandler(file_handler)
    try:
        _configured_logging()

        logging.getLogger('urllib3.connectionpool').warning('connectionpool noise')
        logging.getLogger('something.else').warning('kept')

        content = log_file.read_text()
        assert 'connectionpool noise' not in content
        assert 'kept' in content
    finally:
        logging.root.removeHandler(file_handler)
        file_handler.close()


def test_suppressed_logger_is_dropped():
    captured = _configured_logging()

    oci_logger = logging.getLogger('oci.client.request_logger')
    oci_logger.setLevel(logging.DEBUG)
    oci_logger.debug('oci request sent', extra={'Authorization': 'Bearer abc123def456ghi789'})

    logging.getLogger('other').info('visible')

    entries = _log_lines(captured)
    assert [entry['event'] for entry in entries] == ['visible']


def test_http_access_log_extra_uses_otel_semconv_keys():
    extra = lc.http_access_log_extra(
        request_method='GET',
        url_path='/components',
        url_query='name=x',
        response_status_code=200,
        response_body_size=42,
        duration_seconds=0.01,
        user_agent='ua',
        client_address='127.0.0.1',
    )

    assert extra[lc.HTTP_REQUEST_METHOD] == 'GET'
    assert extra[lc.URL_PATH] == '/components'
    assert extra[lc.URL_QUERY] == 'name=x'
    assert extra[lc.HTTP_RESPONSE_STATUS_CODE] == 200
    assert extra[lc.HTTP_RESPONSE_BODY_SIZE] == 42
    assert extra[lc.HTTP_SERVER_REQUEST_DURATION] == 0.01
    assert extra[lc.USER_AGENT_ORIGINAL] == 'ua'
    assert extra[lc.CLIENT_ADDRESS] == '127.0.0.1'


def test_aiohttp_access_logger_quiets_probe_paths_but_not_errors():
    captured = _configured_logging()

    logger_class = lc.aiohttp_access_logger_class(quiet_path_prefixes=('/ready', '/healthz'))
    logger = logger_class(
        logger=logging.getLogger('aiohttp.access'),
        log_format=aiohttp.web_log.AccessLogger.LOG_FORMAT,
    )

    class FakeRequest:
        path = '/ready'
        query_string = None
        method = 'GET'
        remote = '10.0.0.1'
        headers = {}

    class FakeResponse:
        body_length = 10
        status = 200

    logger.log(FakeRequest(), FakeResponse(), 0.001)
    assert _log_lines(captured) == []

    FakeResponse.status = 500
    logger.log(FakeRequest(), FakeResponse(), 0.001)

    (entry,) = _log_lines(captured)
    assert entry[lc.URL_PATH] == '/ready'
    assert entry[lc.HTTP_RESPONSE_STATUS_CODE] == 500


def test_dataclass_with_secret_field_does_not_leak_via_exception_message():
    """
    The article-lab leak vector: `@dataclasses.dataclass` generates a field-
    level __repr__ that includes everything. If such an object lands in an
    exception message (e.g. f"connect failed with {cfg}"), the exception's
    __str__ bakes the secret into the traceback, which our JSON renderer
    ships verbatim. Our scrubbers catch only known credential formats, not
    arbitrary secret values.

    This test constructs the minimal case and asserts the secret does NOT
    appear in the logged exception. It must FAIL if the dataclass has
    `repr=True` (the default) and no explicit safe __repr__, and PASS after
    fixing either side.
    """
    captured = _configured_logging()

    # use a field name and value that none of our regex scrubbers match:
    # 'supersecret' is not in SENSITIVE_QUERY_PARAMS, and 'mysecret' is too
    # short for the Bearer/Basic patterns.
    secret = 'mysecret'

    @dataclasses.dataclass
    class FakeDbCreds:
        username: str
        supersecret: str

    creds = FakeDbCreds(username='admin', supersecret=secret)

    try:
        raise ValueError(f'connect failed with {creds}')
    except ValueError:
        logging.getLogger('db').exception('something failed')

    (entry,) = _log_lines(captured)
    # if the dataclass has a safe repr (repr=False on the field, or explicit
    # __repr__), the secret never entered the exception message and hence not
    # the serialized traceback. Scrubbers do NOT catch arbitrary values.
    serialized = json.dumps(entry)
    assert secret not in serialized, (
        'secret leaked via dataclass __repr__ into exception message; '
        'the fix belongs on the model (repr=False or explicit __repr__); '
        'see structlog article on tenant secrets'
    )


def test_aiohttp_access_logger_masks_query_for_sensitive_paths():
    captured = _configured_logging()

    logger_class = lc.aiohttp_access_logger_class(masked_query_path_prefixes=('/auth',))
    logger = logger_class(
        logger=logging.getLogger('aiohttp.access'),
        log_format=aiohttp.web_log.AccessLogger.LOG_FORMAT,
    )

    class FakeRequest:
        path = '/auth/callback'
        query_string = 'code=s3cret'
        method = 'GET'
        remote = '10.0.0.1'
        headers = {}

    class FakeResponse:
        body_length = 10
        status = 200

    logger.log(FakeRequest(), FakeResponse(), 0.001)

    (entry,) = _log_lines(captured)
    assert 's3cret' not in json.dumps(entry)
    assert lc.URL_QUERY not in entry
