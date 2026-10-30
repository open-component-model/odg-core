"""
Perf test: GET /components/compliance-summary

Cold-cache latency of the compliance-summary endpoint for two representative
components:
  - gardenlinux  (many artefacts, no component refs — flat fan-out)
  - gardener     (many artefacts + component refs — recursive fan-out)

Run (from test/perf/):
    uv run pytest test_compliance_summary.py -v
    uv run pytest test_compliance_summary.py -v --profile all
"""

import logging

from utils.fixtures import request_compliance_summary
from utils.timer import timed

logger = logging.getLogger(__name__)


def test_compliance_summary_gardenlinux(odg_stack, compliance_targets, snapshot):
    odg, _pg = odg_stack
    gardenlinux, _ = compliance_targets
    with timed('GET /components/compliance-summary gardenlinux', logger):
        result = request_compliance_summary(
            odg.base_url,
            gardenlinux.component_name,
            gardenlinux.component_version,
        )
    assert result == snapshot('compliance-summary-gardenlinux.json')


def test_compliance_summary_gardener(odg_stack, compliance_targets, snapshot):
    odg, _pg = odg_stack
    _, gardener = compliance_targets
    with timed('GET /components/compliance-summary gardener', logger):
        result = request_compliance_summary(
            odg.base_url,
            gardener.component_name,
            gardener.component_version,
        )
    assert result == snapshot('compliance-summary-gardener.json')
