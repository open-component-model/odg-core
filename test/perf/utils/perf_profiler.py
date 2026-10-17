"""
PerfProfiler: unified memory + metrics profiler for ODG perf tests.

Wraps RSS collection and ODG Prometheus metrics into a phase-based context
manager. After each phase, prints a compact RSS trend. On exit, prints a
key-indicator summary across all phases.

All raw data is written to results/ as one .log file per phase.
The container log is written to results/<image-name>.log on exit.

Profiling captures are opt-in:
  - memray: start OdgCoreContainer with memray=True. The profiler collects
    results/<image-name>-memray.bin automatically on exit — no manual call needed.
  - py-spy: call start_pyspy() before the phases you want to CPU-profile.
    phase() stops+collects the current recording and immediately starts a new one,
    producing one results/<image-name>-pyspy-<test>-<seq>-<label>.json per phase.
    Call stop_pyspy() after the last phase you care about.

Usage:
    results_dir = pathlib.Path(__file__).parent / 'results'
    with PerfProfiler(odg_container, results_dir=results_dir) as prof:
        prof.set_test('my_test')
        prof.start_pyspy()
        prof.phase('pre-load')
        # ... burst load ...
        prof.phase('post-load')
        prof.stop_pyspy()
    # on exit: memray.bin collected, summary printed, all data in results/
"""

import logging
import pathlib
import re
import subprocess

import requests as _requests

logger = logging.getLogger(__name__)

_RSS_KEYS = ('VmRSS', 'VmHWM', 'VmPeak', 'Rss', 'Private_Dirty', 'Pss')

_METRIC_PATTERNS = {
    'latency_p99': re.compile(r'request_latency_seconds{[^}]*quantile="0\.99"[^}]*}\s+(\S+)'),
    'latency_sum': re.compile(r'request_latency_seconds_sum{[^}]*}\s+(\S+)'),
    'latency_count': re.compile(r'request_latency_seconds_count{[^}]*}\s+(\S+)'),
    'requests_total': re.compile(r'requests_total{[^}]*}\s+(\S+)'),
}


def _parse_rss(raw: str) -> dict[str, int]:
    result = {}
    for line in raw.splitlines():
        m = re.match(r'(\w+):\s+(\d+)\s+kB', line)
        if m:
            result[m.group(1)] = int(m.group(2))
    return result


def _parse_metrics(text: str) -> dict[str, float]:
    result: dict[str, float] = {}
    for key, pattern in _METRIC_PATTERNS.items():
        totals = [float(m.group(1)) for m in pattern.finditer(text) if m.group(1) != 'NaN']
        if totals:
            result[key] = sum(totals)
    return result


def _format_trend(
    label_from: str,
    label_to: str,
    before: dict[str, int],
    after: dict[str, int],
) -> str:
    lines = [f'  [{label_from} → {label_to}]']
    for key in _RSS_KEYS:
        if key in before and key in after:
            delta = after[key] - before[key]
            sign = '+' if delta >= 0 else ''
            before_mib = before[key] / 1024
            after_mib = after[key] / 1024
            delta_mib = delta / 1024
            lines.append(
                f'    {key:<16}{before_mib:.1f} → {after_mib:.1f} MiB  ({sign}{delta_mib:.1f} MiB)',
            )
    return '\n'.join(lines)


class PerfProfiler:
    def __init__(self, container, results_dir: pathlib.Path):
        """
        container: OdgCoreContainer instance (must already be running)
        results_dir: directory where result files are written
        """
        self._container = container
        self._results_dir = results_dir

        self._phase_seq = 0
        self._current_phase = 'start'
        self._test_name: str = 'unknown'
        self._snapshots: list[tuple[str, dict[str, int], dict[str, float]]] = []
        self._pyspy_active: bool = False

    def __enter__(self):
        self._results_dir.mkdir(parents=True, exist_ok=True)
        return self

    def __exit__(self, *_):
        self._record(self._current_phase)
        self._print_summary()

        image_name = self._image_name()
        log_path = self._results_dir / f'{image_name}.log'
        self._container.dump_logs_to_file(log_path)
        logger.info(f'container log → {log_path}')

        if self._container._memray:
            self._collect_memray()
            self._print_memray_stats()

    def set_test(self, name: str):
        """Call at the start of each test function to prefix phase log filenames."""
        self._test_name = name
        self._phase_seq = 0
        self._record('start')

    def phase(self, label: str):
        """Close the current phase, open a new one, and print the RSS trend.

        If py-spy is active, stops+collects the recording for the closing phase,
        then immediately starts a new recording for the opening phase.
        """
        prev_label, prev_rss, _ = self._snapshots[-1] if self._snapshots else ('start', {}, {})

        if self._pyspy_active:
            self._stop_collect_pyspy(self._current_phase)
            self._container.start_pyspy()

        self._record(label)
        _, curr_rss, _ = self._snapshots[-1]

        if prev_rss and curr_rss:
            logger.info('\n' + _format_trend(prev_label, label, prev_rss, curr_rss))

        self._current_phase = label

    # ── py-spy ────────────────────────────────────────────────────────────────

    def start_pyspy(self, rate: int = 100) -> None:
        """Begin CPU sampling. phase() will stop+collect+restart automatically."""
        self._container.start_pyspy(rate=rate)
        self._pyspy_active = True

    def stop_pyspy(self) -> None:
        """Stop py-spy and collect the final phase recording."""
        if not self._pyspy_active:
            return
        self._stop_collect_pyspy(self._current_phase)
        self._pyspy_active = False

    # ── internals ─────────────────────────────────────────────────────────────

    def _image_name(self) -> str:
        return re.split(r'[:\.@]', self._container._image)[0]

    def _collect_memray(self) -> None:
        dest = self._results_dir / f'{self._image_name()}-memray.bin'
        self._container.collect_memray(dest.parent, dest.name)

    def _print_memray_stats(self) -> None:
        try:
            out = self._container._exec('python', '-m', 'memray', 'stats', '/tmp/memray.bin')
            logger.info(f'\n  === memray stats ===\n{out}')
        except subprocess.CalledProcessError as exc:
            logger.warning(f'memray stats failed: {exc}')

    def _stop_collect_pyspy(self, phase_label: str) -> None:
        filename = (
            f'{self._image_name()}-pyspy-{self._test_name}-{self._phase_seq:02d}-{phase_label}.json'
        )
        self._container.stop_pyspy(self._results_dir, filename)

    def _record(self, label: str):
        rss = self._read_rss()
        metrics, metrics_raw = self._read_metrics()
        self._snapshots.append((label, rss, metrics))
        self._phase_seq += 1
        self._write_phase_log(label, rss, metrics, metrics_raw)

    def _read_rss(self) -> dict[str, int]:
        try:
            out = self._container._exec(
                'sh',
                '-c',
                """
                grep -E "VmRSS|VmPeak|VmHWM|VmSwap" /proc/1/status
                echo "--- smaps_rollup ---"
                cat /proc/1/smaps_rollup
            """,
            )
            return _parse_rss(out)
        except subprocess.CalledProcessError as exc:
            logger.warning(f'RSS read failed: {exc}')
            return {}

    def _read_metrics(self) -> tuple[dict[str, float], str]:
        try:
            resp = _requests.get(f'{self._container.base_url}/metrics', timeout=5)
            resp.raise_for_status()
            return _parse_metrics(resp.text), resp.text
        except Exception as exc:
            logger.warning(f'metrics fetch failed: {exc}')
            return {}, ''

    def _write_phase_log(
        self,
        label: str,
        rss: dict[str, int],
        metrics: dict[str, float],
        metrics_raw: str,
    ):
        image_name = re.split(r'[:\.@]', self._container._image)[0]
        path = self._results_dir / f'{image_name}-metrics.log'
        delimiter = f'=== {self._test_name}-{self._phase_seq:02d}-{label} ===\n\n'
        lines = [delimiter, '--- RSS ---\n']
        for key in _RSS_KEYS:
            if key in rss:
                lines.append(f'{key}: {rss[key] / 1024:.1f} MiB\n')
        if metrics_raw:
            lines.append(f'\n--- metrics (raw) ---\n{metrics_raw}\n')
        elif metrics:
            lines.append('\n--- metrics ---\n')
            for key, val in sorted(metrics.items()):
                lines.append(f'{key}: {val}\n')
        with path.open('a') as f:
            f.write(''.join(lines))
        print(f'Wrote metrics to {path}')

    def _print_summary(self):
        if len(self._snapshots) < 2:
            return

        first_label, first_rss, _ = self._snapshots[0]
        last_label, last_rss, last_metrics = self._snapshots[-1]

        lines = [f'\n  === run summary ({first_label} → {last_label}) ===']
        for key in ('VmRSS', 'VmHWM', 'Private_Dirty'):
            if key in first_rss and key in last_rss:
                delta = last_rss[key] - first_rss[key]
                sign = '+' if delta >= 0 else ''
                first_mib = first_rss[key] / 1024
                last_mib = last_rss[key] / 1024
                delta_mib = delta / 1024
                lines.append(
                    f'    {key:<16}{first_mib:.1f} → {last_mib:.1f} MiB'
                    f'  ({sign}{delta_mib:.1f} MiB)',
                )
        if last_metrics.get('latency_count', 0) > 0:
            avg_ms = (last_metrics['latency_sum'] / last_metrics['latency_count']) * 1000
            count = int(last_metrics['latency_count'])
            lines.append(f'    avg latency:    {avg_ms:.1f} ms  ({count} requests)')
        if 'latency_p99' in last_metrics:
            lines.append(f'    p99 latency:    {last_metrics["latency_p99"] * 1000:.1f} ms')
        if 'requests_total' in last_metrics:
            lines.append(f'    requests total: {int(last_metrics["requests_total"])}')

        logger.info('\n'.join(lines))
