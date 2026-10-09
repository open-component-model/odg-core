"""
Snapshot helpers for perf tests: load and compare committed JSON expected-output files.

The snapshot file is committed alongside the test and is the source of truth.
To update a snapshot, delete the file and re-run — the test will write a new one.

Usage:
    assert_snapshot(actual_dict, pathlib.Path(__file__).parent / 'expected-compliance-summary.json')
"""

import difflib
import json
import logging
import pathlib

logger = logging.getLogger(__name__)


def load_snapshot(path: pathlib.Path) -> dict:
    return json.loads(path.read_text())


def save_snapshot(data: dict, path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')
    logger.info(f'snapshot written to {path}')


def assert_snapshot(
    actual: dict,
    path: pathlib.Path,
    *,
    diff_context: int = 3,
    max_diff_lines: int = 60,
) -> None:
    """Assert *actual* matches the committed snapshot at *path*.

    On first call (no snapshot file): saves *actual* as the new snapshot and passes.
    On subsequent calls: fails with a unified diff when the output differs.
    """
    if not path.exists():
        save_snapshot(actual, path)
        logger.info(f'no snapshot at {path} — wrote initial snapshot, test passes')
        return

    expected = load_snapshot(path)
    if actual == expected:
        return

    a_lines = json.dumps(expected, indent=2, sort_keys=True).splitlines()
    b_lines = json.dumps(actual, indent=2, sort_keys=True).splitlines()
    diff = list(
        difflib.unified_diff(
            a_lines,
            b_lines,
            fromfile='expected',
            tofile='actual',
            lineterm='',
            n=diff_context,
        ),
    )
    truncated = diff[:max_diff_lines]
    extra = len(diff) - max_diff_lines
    trailer = f'\n  ... ({extra} more lines)' if len(diff) > max_diff_lines else ''
    raise AssertionError(f'output differs from snapshot {path}:\n' + '\n'.join(truncated) + trailer)
