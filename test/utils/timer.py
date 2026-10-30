"""
Lightweight single-shot timing context manager for perf tests.

Usage:
    with timed('my_label', logger) as t:
        result = do_something()
        t.info(entries=len(result), component='foo')
    # logs: my_label: 0.42s  entries=137  component=foo
    # t.elapsed holds the wall time in seconds
"""

import contextlib
import logging
import time


class _Timing:
    elapsed: float = 0.0

    def __init__(self) -> None:
        self._context: dict = {}

    def info(self, **kw) -> None:
        self._context = kw


@contextlib.contextmanager
def timed(label: str, logger: logging.Logger):
    """Measure elapsed wall time and log it (with any context from t.info()) on exit."""
    t = _Timing()
    t0 = time.monotonic()
    try:
        yield t
    finally:
        t.elapsed = time.monotonic() - t0
        suffix = ''.join(f'  {k}={v}' for k, v in t._context.items())
        logger.info('%s: %.2fs%s', label, t.elapsed, suffix)
