import hashlib
import importlib.util
import os
import socket
import struct
import tempfile
import threading
import time
import unittest.mock

import pytest

import malware.clamav as clamav
import odg.findings
import odg.model

# clamav_entrypoint.py lives at src/malware/clamav_entrypoint.py but is not a
# package member — load it directly so we can test its private helpers.
_spec = importlib.util.spec_from_file_location(
    'clamav_entrypoint',
    os.path.join(os.path.dirname(__file__), '..', 'malware', 'clamav_entrypoint.py'),
)
_entrypoint = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_entrypoint)


def _make_clamd_server(
    sock_path: str,
    ready: threading.Event,
    response: bytes,
) -> tuple[threading.Thread, list[bytes]]:
    """Minimal clamd stub: reads INSTREAM chunks, sends response, closes connection."""
    received: list[bytes] = []

    def _serve():
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(sock_path)
        srv.listen(1)
        srv.settimeout(5.0)
        ready.set()
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            return
        try:
            buf = b''
            while not buf.endswith(b'\x00'):
                buf += conn.recv(1)
            while True:
                raw = b''
                while len(raw) < 4:
                    raw += conn.recv(4 - len(raw))
                (length,) = struct.unpack('!L', raw)
                if length == 0:
                    break
                chunk = b''
                while len(chunk) < length:
                    data = conn.recv(min(length - len(chunk), 65536))
                    if not data:
                        return
                    chunk += data
                received.append(chunk)
            conn.sendall(response)
            conn.close()  # EOF so scan()'s f.read() unblocks
        finally:
            srv.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return t, received


def _file_chunks(path: str, chunk_size: int = 65536):
    with open(path, 'rb') as f:
        while chunk := f.read(chunk_size):
            yield chunk


def _run_scan(response: bytes, path: str, malware_cfg=None):
    with tempfile.TemporaryDirectory() as tmp:
        sock_path = f'{tmp}/clamd.sock'
        ready = threading.Event()
        server, received = _make_clamd_server(sock_path, ready, response)
        ready.wait(timeout=3)
        clamav._lookup_clamd_socket.cache_clear()
        with unittest.mock.patch.object(clamav, '_lookup_clamd_socket', return_value=sock_path):
            result = clamav.scan(
                malware_cfg=malware_cfg,
                data=_file_chunks(path),
                filename=path,
            )
        server.join(timeout=3)
        return result, received


def _make_malware_cfg(malware_names: list[str] = ('.*',)):
    cat = odg.findings.FindingCategorisation(
        id='malware',
        display_name='Malware',
        value=100,
        allowed_processing_time=None,
        rescoring=None,
        selector=odg.findings.MalwareFindingSelector(malware_names=list(malware_names)),
    )
    finding = unittest.mock.MagicMock(spec=odg.findings.Finding)
    finding.categorisations = [cat]
    return finding


def _write_tmpfile(content: bytes) -> str:
    """Write content to a new temp file and return its path."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(content)
        return f.name


def test_scan_returns_none_when_no_malware_found():
    path = _write_tmpfile(b'clean file content')
    result, received = _run_scan(response=b'stream: OK\x00', path=path)
    assert result is None
    assert b''.join(received) == b'clean file content'


def test_scan_returns_finding_when_malware_detected():
    path = _write_tmpfile(b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR')
    malware_cfg = _make_malware_cfg()
    with unittest.mock.patch.object(
        clamav,
        'clamscan_version',
        return_value=('ClamAV 1.0', 1, '2024-01-01'),
    ):
        result, received = _run_scan(
            response=b'stream: Eicar-Signature FOUND\x00',
            path=path,
            malware_cfg=malware_cfg,
        )
    assert isinstance(result, odg.model.ClamAVMalwareFinding)
    assert result.finding.malware == 'Eicar-Signature'
    assert result.finding.filename == path
    assert result.octets_count == len(b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR')
    expected_digest = 'sha256:' + hashlib.sha256(b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR').hexdigest()
    assert result.finding.content_digest == expected_digest


def test_scan_returns_none_when_malware_not_categorised():
    path = _write_tmpfile(b'some payload')
    malware_cfg = _make_malware_cfg(malware_names=['KnownMalware'])
    result, _ = _run_scan(
        response=b'stream: UnknownMalware FOUND\x00',
        path=path,
        malware_cfg=malware_cfg,
    )
    assert result is None


def test_scan_raises_on_socket_connect_failure():
    path = _write_tmpfile(b'data')
    clamav._lookup_clamd_socket.cache_clear()
    with unittest.mock.patch.object(
        clamav,
        '_lookup_clamd_socket',
        return_value='/nonexistent/clamd.sock',
    ):
        with pytest.raises(OSError):
            clamav.scan(malware_cfg=None, data=_file_chunks(path), filename=path)


def test_scan_raises_on_clamd_disconnect():
    def _serve_then_disconnect(sock_path, ready):
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(sock_path)
        srv.listen(1)
        srv.settimeout(5.0)
        ready.set()
        try:
            conn, _ = srv.accept()
            buf = b''
            while not buf.endswith(b'\x00'):
                buf += conn.recv(1)
            conn.close()  # close without reading data or sending response
        except socket.timeout:
            pass
        finally:
            srv.close()

    path = _write_tmpfile(b'data')
    with tempfile.TemporaryDirectory() as tmp:
        sock_path = f'{tmp}/clamd.sock'
        ready = threading.Event()
        server = threading.Thread(
            target=_serve_then_disconnect,
            args=(sock_path, ready),
            daemon=True,
        )
        server.start()
        ready.wait(timeout=3)
        clamav._lookup_clamd_socket.cache_clear()
        with unittest.mock.patch.object(clamav, '_lookup_clamd_socket', return_value=sock_path):
            with pytest.raises(OSError):
                clamav.scan(malware_cfg=None, data=_file_chunks(path), filename=path)
        server.join(timeout=3)


def test_wait_for_clamd_socket_success():
    with tempfile.TemporaryDirectory() as tmp:
        sock_path = f'{tmp}/clamd.sock'
        # create the socket file after a short delay

        def _create():
            time.sleep(0.1)
            open(sock_path, 'w').close()

        threading.Thread(target=_create, daemon=True).start()
        _entrypoint._wait_for_clamd_socket(sock_path, timeout=5)
        assert os.path.exists(sock_path)


def test_wait_for_clamd_socket_timeout():
    with pytest.raises(TimeoutError, match='clamd socket'):
        _entrypoint._wait_for_clamd_socket('/nonexistent/clamd.sock', timeout=0.1)


def test_wait_for_virus_db_success():
    with tempfile.TemporaryDirectory() as tmp:
        # write db files after a short delay
        def _create():
            time.sleep(0.1)
            open(f'{tmp}/main.cvd', 'w').close()
            open(f'{tmp}/daily.cld', 'w').close()

        threading.Thread(target=_create, daemon=True).start()
        _entrypoint._wait_for_virus_db(db_dir=tmp, timeout=5)


def test_wait_for_virus_db_timeout():
    with tempfile.TemporaryDirectory() as tmp:
        with pytest.raises(TimeoutError, match='virus definitions'):
            _entrypoint._wait_for_virus_db(db_dir=tmp, timeout=0.1)


def test_wait_for_virus_db_requires_both_main_and_daily():
    with tempfile.TemporaryDirectory() as tmp:
        open(f'{tmp}/main.cvd', 'w').close()
        # daily is missing — should time out
        with pytest.raises(TimeoutError):
            _entrypoint._wait_for_virus_db(db_dir=tmp, timeout=0.1)


def test_wait_for_virus_db_accepts_cld_suffix():
    with tempfile.TemporaryDirectory() as tmp:
        open(f'{tmp}/main.cld', 'w').close()
        open(f'{tmp}/daily.cld', 'w').close()
        _entrypoint._wait_for_virus_db(db_dir=tmp, timeout=1)
