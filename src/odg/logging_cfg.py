"""
Central logging configuration for ODG processes, based on structlog.

Name of this module is `logging_cfg` (not `logging`) to avoid shadowing/confusion
with the stdlib `logging` module in imports.

Usage (entry points, e.g. src/malware/__main__.py):

    import odg.logging_cfg
    odg.logging_cfg.configure_logging()

Works alongside existing infrastructure:
- stdlib `logging.getLogger(...)` call sites keep working unchanged (structlog
  only re-formats the stdlib pipeline via ProcessorFormatter)
- third-party stdlib loggers (uvicorn, aiohttp, kubernetes, ...) are routed into
  the same pipeline, see `route_foreign_loggers()`
- `k8s.logging.configure_kubernetes_logging()` may be called BEFORE
  `configure_logging()` to keep its FileHandlers attached for the LogCollection
  CRD pipeline; pod stdout logs then use the structlog format, the CRD content
  the legacy frontend format.

Field naming follows OpenTelemetry semantic conventions
(https://opentelemetry.io/docs/specs/semconv/general/naming/):
- lowercase, dot-separated namespaces, snake_case within components
- e.g. `service.name`, `log.iostream`, `k8s.namespace.name`
- for custom ODG fields use e.g. `ocm.component.name`, `artefact.name`

Since dotted names are not valid kwarg names, pass them via dict expansion:

    logger.info('scan finished', **{'artefact.name': artefact_name})

CAUTION: keyword arguments only work with `structlog.get_logger()`. Stdlib
loggers (`logging.getLogger(...)`) raise TypeError on unknown kwargs.

Standard structlog output keys (`timestamp`, `level`, `event`) map to OTel's
`Timestamp`, `SeverityText` and `Body` respectively; keeping the structlog
names as most log pipelines (Loki, Fluent Bit, Splunk HEC) recognise them.
"""

import collections.abc
import logging
import re
import sys
import threading
import typing

import structlog


# well-known field names (OpenTelemetry semantic conventions)
SERVICE_NAME = 'service.name'
SERVICE_VERSION = 'service.version'
LOG_IOSTREAM = 'log.iostream'

# OTel semantic-convention field names used for HTTP access logs
HTTP_REQUEST_METHOD = 'http.request.method'
URL_PATH = 'url.path'
URL_QUERY = 'url.query'
HTTP_RESPONSE_STATUS_CODE = 'http.response.status_code'
HTTP_RESPONSE_BODY_SIZE = 'http.response.body.size'
HTTP_SERVER_REQUEST_DURATION = 'http.server.request.duration'
USER_AGENT_ORIGINAL = 'user_agent.original'
CLIENT_ADDRESS = 'client.address'
NETWORK_PEER_ADDRESS = 'network.peer.address'
EXCEPTION_TYPE = 'exception.type'
EXCEPTION_MESSAGE = 'exception.message'
EXCEPTION_STACKTRACE = 'exception.stacktrace'

# keys whose values must never appear in logs (third-party loggers sometimes
# pass them via `extra=`; e.g. oci.client.request_logger sends Authorization
# headers including bearer tokens)
SENSITIVE_KEYS = frozenset(
    {
        'authorization',
        'proxy-authorization',
        'x-api-key',
        'x-auth-token',
        'cookie',
        'set-cookie',
    },
)
# query params whose values are scrubbed from logged URLs (e.g. access logs)
SENSITIVE_QUERY_PARAMS = ('token', 'secret', 'password', 'key', 'code', 'credential')
SENSITIVE_QUERY_PARAMS_RE = re.compile(
    rf'(?P<name>{"|".join(SENSITIVE_QUERY_PARAMS)})=(?P<value>[^&\s]+)',
    re.IGNORECASE,
)

# credentials embedded in plain message strings, e.g. some loggers format an
# `Authorization: Bearer ...` header into the message itself
BEARER_TOKEN_RE = re.compile(r'(?<=Bearer )[A-Za-z0-9\-\._~+/]{16,}={0,2}')
BASIC_CREDENTIALS_RE = re.compile(r'(?<=Basic )[A-Za-z0-9+/]{16,}={0,2}')

SENSITIVE_REPLACEMENT = '***'


def merge_extra_fields(logger, method_name: str, event_dict: dict) -> dict:
    """
    Copy ``extra={...}`` fields from a stdlib LogRecord into the event dict.

    structlog's ``ProcessorFormatter`` only forwards a fixed set of LogRecord
    attributes; anything a third party passes via ``logging.Logger.info(msg,
    extra={'key': value})`` would otherwise be lost. aiohttp's AccessLogger
    uses this mechanism (see ``aiohttp.web_log.AccessLogger.log``).

    Keys are mapped to OpenTelemetry semantic-convention names where known.
    """
    record = event_dict.get('_record')

    if record is None:
        return event_dict

    extras = getattr(record, '__extra_fields__', None)

    if extras is None:
        # fall back to scanning record.__dict__ for non-standard attributes
        # standard LogRecord attributes (see logging.LogRecord)
        standard_attrs = {
            'name',
            'msg',
            'args',
            'levelname',
            'levelno',
            'pathname',
            'filename',
            'module',
            'exc_info',
            'exc_text',
            'stack_info',
            'lineno',
            'funcName',
            'created',
            'msecs',
            'relativeCreated',
            'thread',
            'threadName',
            'processName',
            'process',
            'message',
            'asctime',
            'taskName',
        }
        extras = {
            key: value
            for key, value in record.__dict__.items()
            if key not in standard_attrs and not key.startswith('_')
        }

    # map to OTel semantic conventions where applicable
    otel_key_map = {
        'remote_address': NETWORK_PEER_ADDRESS,
        'user_agent': USER_AGENT_ORIGINAL,
    }

    for key, value in extras.items():
        # do not overwrite event_dict if already set explicitly
        if key in event_dict:
            continue

        if key.lower() in SENSITIVE_KEYS:
            event_dict[key] = _replace_sensitive(value)
            continue

        otel_key = otel_key_map.get(key, key)

        if isinstance(value, str):
            value = _scrub_string(value)

        # unpack nested dicts (e.g. from aiohttp) one level deep
        if isinstance(value, dict):
            for inner_key, inner_value in value.items():
                if inner_key.lower() in SENSITIVE_KEYS:
                    event_dict[inner_key] = _replace_sensitive(inner_value)
                    continue
                inner_otel_key = otel_key_map.get(inner_key, inner_key)
                if inner_otel_key not in event_dict:
                    event_dict[inner_otel_key] = inner_value
        else:
            event_dict[otel_key] = value

    return event_dict


class SuppressLoggerPrefixesFilter(logging.Filter):
    """Drop records whose logger name starts with one of the given prefixes."""

    def __init__(self, logger_prefixes: collections.abc.Iterable[str]):
        super().__init__()
        self.logger_prefixes = tuple(logger_prefixes)

    def filter(self, record: logging.LogRecord) -> bool:
        return not record.name.startswith(self.logger_prefixes)


class SuppressLoggerNamesFilter(logging.Filter):
    """Drop records from given logger names entirely."""

    def __init__(self, logger_names: collections.abc.Iterable[str]):
        super().__init__()
        self.logger_names = frozenset(logger_names)

    def filter(self, record: logging.LogRecord) -> bool:
        return record.name not in self.logger_names


# OCI request logs ship in cc-utils at DEBUG level and leak
# "Authorization"/"User-Agent" headers via record extras. Cc-utils is in
# control, and scrubbing the fields would remove the diagnostic value the
# request logger is supposed to add in the first place — so drop them.
DEFAULT_SUPPRESSED_LOGGERS = ('oci.client.request_logger',)


def _replace_sensitive(value):
    if isinstance(value, str):
        return SENSITIVE_REPLACEMENT
    if isinstance(value, dict):
        return {key: _replace_sensitive(v) for key, v in value.items()}

    return value


def scrub_sensitive_fields(logger, method_name: str, event_dict: dict) -> dict:
    """
    Replace values of well-known credential keys. Only string values are
    replaced outright (a key coincidentally named e.g. `token_count` with an
    int value is kept); dicts are scrubbed recursively so that e.g.
    extra={'headers': {'Authorization': ...}} is fully stripped.
    """
    for key in list(event_dict.keys()):
        if key.lower() in SENSITIVE_KEYS:
            event_dict[key] = _replace_sensitive(event_dict[key])

    return event_dict


def _scrub_string(value: str) -> str:
    value = SENSITIVE_QUERY_PARAMS_RE.sub(lambda m: f'{m["name"]}={SENSITIVE_REPLACEMENT}', value)
    value = BEARER_TOKEN_RE.sub(SENSITIVE_REPLACEMENT, value)
    value = BASIC_CREDENTIALS_RE.sub(SENSITIVE_REPLACEMENT, value)

    return value


def scrub_string_values(logger, method_name: str, event_dict: dict) -> dict:
    """
    Scrub credential patterns from string values (and the event message
    itself), regardless of key name. Catch-all for loggers that format
    credentials into plain strings; format-based, not semantic — it misses
    non-standard formats and may replace lookalikes.
    """
    for key, value in event_dict.items():
        if isinstance(value, str):
            event_dict[key] = _scrub_string(value)

    return event_dict


_shared_processors: list = [
    structlog.contextvars.merge_contextvars,
    structlog.stdlib.add_logger_name,
    structlog.stdlib.add_log_level,
    structlog.processors.TimeStamper(fmt='iso', utc=True),
    structlog.processors.StackInfoRenderer(),
    structlog.processors.format_exc_info,
    scrub_sensitive_fields,
]


def _install_excepthook(logger_name: str = 'unhandled') -> None:
    """
    Route unhandled exceptions (main thread and daemon threads) through the
    configured structlog pipeline so the process's final crash record is JSON.

    KeyboardInterrupt and SystemExit are delegated to the previous hook to keep
    Ctrl+C and sys.exit() semantics.
    """
    previous_sys_hook = sys.excepthook
    previous_threading_hook = threading.excepthook

    def _log_unhandled(exc_type, exc_value, exc_tb, thread_name: str | None) -> None:
        logging.getLogger(logger_name).critical(
            f'unhandled exception in {thread_name or "main thread"}; process will exit',
            exc_info=(exc_type, exc_value, exc_tb),
        )

    def sys_hook(exc_type, exc_value, exc_tb):
        if issubclass(exc_type, (KeyboardInterrupt, SystemExit)):
            previous_sys_hook(exc_type, exc_value, exc_tb)
            return
        _log_unhandled(exc_type, exc_value, exc_tb, thread_name=None)

    def threading_hook(args: threading.ExceptHookArgs):
        if issubclass(args.exc_type, (KeyboardInterrupt, SystemExit)):
            previous_threading_hook(args)
            return
        _log_unhandled(
            args.exc_type,
            args.exc_value,
            args.exc_traceback,
            thread_name=args.thread.name if args.thread else None,
        )

    sys.excepthook = sys_hook
    threading.excepthook = threading_hook


def configure_logging(
    log_level: int = logging.INFO,
    json_logs: bool = True,
    service_name: str | None = None,
    stream: typing.TextIO | None = None,
) -> None:
    """
    Configure root stdlib logger + structlog for this process.

    Set `json_logs=False` for local development (human-readable console output).
    `service_name`, if given, is added to every log entry as `service.name`
    (OTel semantic convention; use the extension/service name, e.g. 'malware').

    Also installs a `sys.excepthook`/`threading.excepthook` that routes
    otherwise-silent unhandled exceptions through the structlog pipeline.
    """
    processors = list(_shared_processors)

    if service_name:
        service_context = {SERVICE_NAME: service_name}

        def add_service_name(logger, method_name: str, event_dict: dict) -> dict:
            event_dict.update(service_context)
            return event_dict

        processors.insert(0, add_service_name)

        # also set on foreign (stdlib) log records that bypass the structlog
        # processor chain; without this, ProcessorFormatter renders them with a
        # null service.name.
        old_factory = logging.getLogRecordFactory()

        def record_factory(*args, **kwargs) -> logging.LogRecord:
            record = old_factory(*args, **kwargs)

            for key, value in service_context.items():
                if not hasattr(record, key):
                    setattr(record, key, value)

            return record

        logging.setLogRecordFactory(record_factory)

    if json_logs:
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    # route warnings.warn() calls from any library into the logging pipeline;
    # they surface as records from the `py.warnings` logger (before the handler
    # is installed, so they get the same structlog JSON/console rendering)
    logging.captureWarnings(True)

    formatter = structlog.stdlib.ProcessorFormatter(
        # stdlib log records from third-party libs (uvicorn, aiohttp, kubernetes)
        # pass through the same processors before rendering. merge_extra_fields
        # additionally forwards LogRecord extras (e.g. aiohttp access-log
        # fields) into the event dict.
        # merge_extra_fields must run before scrub_string_values so extras
        # merged into the event dict get string-scrubbed as well
        foreign_pre_chain=[*processors, merge_extra_fields, scrub_string_values],
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    stream_handler = logging.StreamHandler(stream=stream or sys.stdout)
    stream_handler.setFormatter(fmt=formatter)
    stream_handler.addFilter(SuppressLoggerNamesFilter(logger_names=DEFAULT_SUPPRESSED_LOGGERS))

    root_logger = logging.getLogger()
    # drop pre-configured stream handlers (e.g. from basicConfig) to avoid
    # duplicate/unstructured output; FileHandlers attached before this call
    # (k8s CRD pipeline, see k8s.logging.configure_kubernetes_logging) are kept
    for handler in root_logger.handlers[:]:
        if isinstance(handler, logging.StreamHandler) and not isinstance(
            handler,
            logging.FileHandler,
        ):
            root_logger.removeHandler(handler)
        elif isinstance(handler, logging.FileHandler):
            # FileHandlers (LogCollection CRD pipeline, attached before this call) do
            # not get the SuppressLoggerNamesFilter the stdout handler gets: the CRD
            # keeps DEBUG-level records of suppressed loggers for troubleshooting.
            handler.addFilter(SuppressLoggerPrefixesFilter(logger_prefixes=('urllib3',)))
    root_logger.addHandler(hdlr=stream_handler)
    root_logger.setLevel(level=log_level)

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            *processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    _install_excepthook()


def http_access_log_extra(
    request_method: str,
    url_path: str,
    response_status_code: int,
    url_query: str | None = None,
    response_body_size: int | None = None,
    duration_seconds: float | None = None,
    user_agent: str | None = None,
    client_address: str | None = None,
) -> dict:
    """
    Extra fields for an HTTP server access log entry, named per OpenTelemetry
    semantic conventions. Pass as ``extra=`` to a stdlib logger call;
    `merge_extra_fields` picks them up into the structured event.
    """
    extra = {
        HTTP_REQUEST_METHOD: request_method,
        URL_PATH: url_path,
        HTTP_RESPONSE_STATUS_CODE: response_status_code,
    }

    if url_query:
        extra[URL_QUERY] = url_query
    if response_body_size is not None:
        extra[HTTP_RESPONSE_BODY_SIZE] = response_body_size
    if duration_seconds is not None:
        extra[HTTP_SERVER_REQUEST_DURATION] = duration_seconds
    if user_agent:
        extra[USER_AGENT_ORIGINAL] = user_agent
    if client_address:
        extra[CLIENT_ADDRESS] = client_address

    return extra


def aiohttp_access_logger_class(
    masked_query_path_prefixes: tuple[str, ...] = (),
    quiet_path_prefixes: tuple[str, ...] = (),
) -> type:
    """
    AccessLogger subclass emitting structured (field-based) access logs.
    Pass the returned class to `aiohttp.web.TCPSite(..., access_log_class=...)`.

    `masked_query_path_prefixes`: for paths starting with one of these,
    `url.query` is omitted from the log entry (e.g. ('/auth',) to avoid
    logging secrets in authentication-endpoint query parameters).

    `quiet_path_prefixes`: access log entries for 2xx responses to these
    paths are dropped entirely. Use for high-frequency probe endpoints:
    ('/healthz', '/ready'). Errors (4xx/5xx) are still logged.
    """
    import aiohttp.web_log

    class ODGAccessLogger(aiohttp.web_log.AccessLogger):
        def log(self, request, response, time: float) -> None:
            try:
                path = request.path
                query = request.query_string or None

                if (
                    quiet_path_prefixes
                    and path.startswith(quiet_path_prefixes)
                    and response.status < 400
                ):
                    return

                if masked_query_path_prefixes and path.startswith(masked_query_path_prefixes):
                    query = None

                self.logger.info(
                    f'{request.method} {path} -> {response.status}',
                    extra=http_access_log_extra(
                        request_method=request.method,
                        url_path=path,
                        url_query=query,
                        response_status_code=response.status,
                        response_body_size=getattr(response, 'body_length', None),
                        duration_seconds=time,
                        user_agent=request.headers.get('User-Agent'),
                        client_address=request.remote,
                    ),
                )
            except Exception:
                self.logger.exception('error in access logging')

    return ODGAccessLogger


def quiet_uvicorn_access_log(
    logger_name: str = 'uvicorn.access',
    path_prefixes: tuple[str, ...] = ('/readiness', '/healthz', '/ready'),
) -> None:
    """
    Drop access-log records on `logger_name` whose message looks like a
    uvicorn access line for a 2xx/3xx probe to one of `path_prefixes`.
    Non-probe methods (POST/PUT/etc.), 4xx/5xx responses, and other paths
    are unaffected.

    Use for uvicorn-based services (aiohttp users get this via
    `aiohttp_access_logger_class(quiet_path_prefixes=...)` instead).
    """
    import re

    methods = '|'.join(('GET', 'HEAD', 'OPTIONS'))
    paths_re = '|'.join(re.escape(p) for p in path_prefixes)
    pattern = re.compile(
        rf'"(?:{methods}) (?:{paths_re})(?:[ ?][^"]*)? HTTP/[^"]+" [23]\d{{2}}\b',
    )

    class QuietProbeFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            return pattern.search(record.getMessage() or '') is None

    logging.getLogger(logger_name).addFilter(QuietProbeFilter())


def route_foreign_loggers(*logger_names: str) -> None:
    """
    Route third-party stdlib loggers into the root (structlog) pipeline by
    removing their own handlers and enabling propagation.

    Typical use (freshclam extension, which runs uvicorn):

        route_foreign_loggers('uvicorn', 'uvicorn.access', 'uvicorn.error')

    Alternatively, pass ``log_config=None`` to `uvicorn.Config`/`uvicorn.run`
    so uvicorn does not install its own logging setup at all; propagation to
    the root logger then handles formatting (preferred).

    aiohttp (delivery-service) needs no routing: its loggers already propagate
    to root by default.
    """
    for logger_name in logger_names:
        foreign_logger = logging.getLogger(logger_name)
        foreign_logger.handlers.clear()
        foreign_logger.propagate = True
