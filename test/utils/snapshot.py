"""
Snapshot assertions for tests.

Usage (via the `snapshot` fixture defined in conftest.py):

    def test_foo(snapshot):
        assert result == snapshot('expected.json')   # dict or list → sorted JSON
        assert result == snapshot('expected.txt')    # str → plain text

On first run (no file): writes *actual* as the new snapshot and passes.
On subsequent runs: fails with a pytest diff when the output differs.
To regenerate: delete the snapshot file and re-run.
"""

import hashlib
import json
import logging
import pathlib

logger = logging.getLogger(__name__)


class Snapshot:
    def __init__(self, path: pathlib.Path):
        self._path = pathlib.Path(path)
        self._is_json = self._path.suffix == '.json'

    def _serialise(self, actual: dict | list | str) -> str:
        if not self._is_json:
            return actual
        if isinstance(actual, list):
            return (
                json.dumps(
                    sorted(actual, key=lambda e: json.dumps(e, sort_keys=True)),
                    indent=2,
                    sort_keys=True,
                )
                + '\n'
            )
        return json.dumps(actual, indent=2, sort_keys=True) + '\n'

    def __eq__(self, actual: dict | list | str) -> bool:
        serialised = self._serialise(actual)
        if not self._path.exists():
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(serialised)
            sha = hashlib.sha256(serialised.encode()).hexdigest()[:12]
            logger.info('snapshot written: %s  sha256=%s', self._path.name, sha)
            return True
        stored = self._path.read_text()
        if self._is_json:
            return serialised == stored
        return actual == stored

    def __repr__(self) -> str:
        if not self._path.exists():
            return '<no snapshot>'
        return self._path.read_text()
