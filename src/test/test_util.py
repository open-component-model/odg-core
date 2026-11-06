import aiohttp.web
import pytest

import util

# ---------------------------------------------------------------------------
# util.param
# ---------------------------------------------------------------------------


def test_param_no_validator_passes():
    assert util.param({'key': 'allowed'}, 'key') == 'allowed'


def test_param_validator_passes():
    assert util.param({'key': 'allowed'}, 'key', validator=lambda v: v == 'allowed') == 'allowed'


def test_param_validator_rejects():
    with pytest.raises(aiohttp.web.HTTPBadRequest):
        util.param({'key': 'bad'}, 'key', validator=lambda v: False)


def test_param_validator_skipped_when_absent():
    called = []
    result = util.param({}, 'key', default='x', validator=lambda v: called.append(v) or True)
    assert result == 'x'
    assert not called  # validator must not run on missing params
