"""
Guard the odg-ui LogTab CRD contract: k8s.logging must keep emitting exactly
these fields — `timestamp`, `name`, `logLevel`, `thread`, `message` — so that
odg-ui's `LogTab` (src/extensions/monitoring.js::Logs) keeps rendering.

If the format ever changes on purpose also update odg-ui and these tests.
"""

import logging
import os

import k8s.logging as kl


def _setup_crd_handlers(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for h in list(logging.root.handlers):
        logging.root.removeHandler(h)
    kl.configure_kubernetes_logging()


def _read_crds_entries(filename):
    import json

    with open(filename) as f:
        content = f.read()
    return json.loads(f'[{content.rstrip().removesuffix(",")}]')


EXPECTED_KEYS = frozenset({'timestamp', 'name', 'logLevel', 'thread', 'message'})


def test_every_level_writes_frontend_shaped_entries(tmp_path, monkeypatch):
    _setup_crd_handlers(tmp_path, monkeypatch)

    logging.getLogger('__main__').debug('dropped debug')
    logging.getLogger('__main__').info('info msg')
    logging.getLogger('ctx_util').warning('warn msg')
    try:
        raise ValueError('boom')
    except ValueError:
        logging.getLogger('__main__').exception('exception msg')

    info_entries = _read_crds_entries(kl.log_filename_for_level(logging.INFO))
    warning_entries = _read_crds_entries(kl.log_filename_for_level(logging.WARNING))
    error_entries = _read_crds_entries(kl.log_filename_for_level(logging.ERROR))

    assert 'dropped debug' not in [e['message'] for e in info_entries]
    assert 'info msg' in [e['message'] for e in info_entries]
    assert 'warn msg' in [e['message'] for e in warning_entries]
    assert any('exception msg' in e['message'] for e in error_entries)

    for entries in (info_entries, warning_entries, error_entries):
        for entry in entries:
            assert set(entry.keys()) == EXPECTED_KEYS, entry


def test_crd_timestamp_is_frontend_parseable(tmp_path, monkeypatch):
    _setup_crd_handlers(tmp_path, monkeypatch)

    logging.getLogger('__main__').warning('parse me')

    (entry,) = _read_crds_entries(kl.log_filename_for_level(logging.WARNING))
    ts = entry['timestamp']

    import datetime

    parsed = datetime.datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S.%fZ')
    assert parsed is not None


def test_exception_appends_traceback_to_message(tmp_path, monkeypatch):
    _setup_crd_handlers(tmp_path, monkeypatch)

    try:
        raise ValueError('kaboom')
    except ValueError:
        logging.getLogger('__main__').exception('outer message')

    (entry,) = _read_crds_entries(kl.log_filename_for_level(logging.ERROR))
    assert 'outer message' in entry['message']
    assert 'kaboom' in entry['message']
    assert 'Traceback' in entry['message']


def test_message_over_10k_is_capped(tmp_path, monkeypatch):
    _setup_crd_handlers(tmp_path, monkeypatch)

    big = 'x' * 40000
    logging.getLogger('__main__').warning(big)

    (entry,) = _read_crds_entries(kl.log_filename_for_level(logging.WARNING))
    assert entry['message'] != big
    assert 'too large' in entry['message'].lower()


def test_special_chars_never_break_file_parsing(tmp_path, monkeypatch):
    """Regression: values were f-string-interpolated unescaped into JSON, so a
    quote or backslash in any field corrupted the whole log file (all entries
    discarded by read_logs_and_remove's JSONDecodeError branch)."""
    _setup_crd_handlers(tmp_path, monkeypatch)

    logger = logging.getLogger('weird"name\\with\nspecials')
    logger.error('quote " backslash \\ newline \n tab \t unicode äöü €')

    (entry,) = kl.read_logs_and_remove(logging.ERROR)
    assert entry['name'] == 'weird"name\\with\nspecials'
    assert 'quote " backslash \\ newline' in entry['message']


def test_read_logs_and_remove_roundtrip_still_parses(tmp_path, monkeypatch):
    _setup_crd_handlers(tmp_path, monkeypatch)

    logging.getLogger('__main__').error('one')
    logging.getLogger('__main__').error('two')

    assert os.path.exists(kl.log_filename_for_level(logging.ERROR))
    entries = kl.read_logs_and_remove(logging.ERROR)
    assert [e['message'] for e in entries] == ['one', 'two']
    # file truncated
    with open(kl.log_filename_for_level(logging.ERROR)) as f:
        assert f.read() == ''
