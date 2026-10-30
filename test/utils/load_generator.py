"""
Concurrent load generator for perf tests.
"""

import concurrent.futures
import logging
import threading
import time

logger = logging.getLogger(__name__)


def gen_concurrent_requests(
    fn,
    *,
    workers: int = 10,
    duration_s: float = 30.0,
    pace_s: float = 0.0,
    raise_on_error: bool = True,
) -> None:
    """Call fn() from `workers` threads repeatedly for `duration_s` seconds.

    Logs total calls, throughput, and any errors on completion.
    If raise_on_error is True (default), re-raises the first exception after all workers finish.
    Set raise_on_error=False to log errors without failing — useful when server crashes are
    themselves the observation (e.g. comparing stable vs. unstable versions).
    """
    calls = 0
    errors: list[BaseException] = []
    deadline = time.monotonic() + duration_s
    _lock = threading.Lock()

    def _worker() -> None:
        nonlocal calls
        while time.monotonic() < deadline:
            try:
                fn()
            except Exception as exc:
                with _lock:
                    errors.append(exc)
                return
            with _lock:
                calls += 1
            if pace_s > 0:
                time.sleep(pace_s)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_worker) for _ in range(workers)]
        concurrent.futures.wait(futures)

    if calls:
        logger.info(
            'gen_concurrent_requests: calls=%d workers=%d duration=%.0fs throughput=%.1f/s',
            calls,
            workers,
            duration_s,
            calls / duration_s,
        )

    if errors:
        logger.warning(
            'gen_concurrent_requests: %d/%d workers failed; first error: %s',
            len(errors),
            workers,
            errors[0],
        )
        if raise_on_error:
            raise errors[0]
