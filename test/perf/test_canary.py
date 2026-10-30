"""
Perf test: canary — verify the stack starts and serves basic endpoints.

Run (from repo root):
    uv run pytest test/perf/test_canary.py -v
"""

import requests


def test_ready(odg_stack, snapshot):
    odg, _pg = odg_stack
    res = requests.get(f'{odg.base_url}/ready', timeout=5)
    res.raise_for_status()
    assert res.text == snapshot('ready-response.txt')


def test_metrics(odg_stack):
    odg, _pg = odg_stack
    requests.get(f'{odg.base_url}/metrics', timeout=5).raise_for_status()
