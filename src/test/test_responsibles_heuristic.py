import calendar
import time

import pytest
import yaml
from unittest.mock import patch

import paths
import responsibles.github_statistics as rg

# global_stats() weights commits by age relative to time.time(). The test
# fixtures contain historical contributor data (2020-2022). As real time
# advances, the sigmoid re-fit shifts which authors fall into the percentile
# brackets, making the assertion unstable. Freeze to a fixed epoch so the
# test is deterministic regardless of when it runs.
# See: test_responsibles_heuristic_time_sensitivity.md
_FROZEN_EPOCH = calendar.timegm(time.strptime('2023-06-01', '%Y-%m-%d'))


@pytest.fixture()
def negative_list():
    with open(paths.responsibles_username_negative_list_path, 'r') as f:
        return yaml.load(f, Loader=yaml.SafeLoader)['usernames']


@pytest.fixture()
def positive_list():
    with open(paths.test_resources_gardener_org_members, 'r') as f:
        return yaml.load(f, Loader=yaml.SafeLoader)['usernames']


@pytest.fixture(autouse=True)
def freeze_time():
    with patch(
        'responsibles.github_statistics.time.time',
        return_value=_FROZEN_EPOCH,
    ):
        yield


def _is_candidate_stat(
    stat: dict,
    positive_list: list[str],
    negative_list: list[str],
) -> bool:
    """
    checks given username from stat against positive and negative list.
    """
    username = stat['author']['login']
    if username in negative_list:
        return False

    if username not in positive_list:
        return False

    return True


def _load_yaml(path: str) -> dict:
    with open(path, 'r') as f:
        return yaml.load(f, Loader=yaml.SafeLoader)


def test_apiserver(
    negative_list: list[str],
    positive_list: list[str],
):
    repo_stats = _load_yaml(path=paths.test_resources_apiserver_proxy)
    repo_stats = list(
        filter(
            lambda stat: _is_candidate_stat(
                stat=stat,
                positive_list=positive_list,
                negative_list=negative_list,
            ),
            repo_stats,
        ),
    )
    processed_stats = rg.global_stats(
        repo_stats=repo_stats,
        weight_function_identifier='sigmoid',
        max_responsibles=3,
        percentile_min=85,
    )
    determined_responsibles, _ = rg.heuristically_determine_responsibles(
        stats=processed_stats,
        max_responsibles=3,
    )
    # compare as set to ignore index
    assert set(determined_responsibles) == {
        'vpnachev',
        'ScheererJ',
    }


def test_mcm(
    negative_list: list[str],
    positive_list: list[str],
):
    repo_stats = _load_yaml(path=paths.test_resources_mcm)
    repo_stats = list(
        filter(
            lambda stat: _is_candidate_stat(
                stat=stat,
                positive_list=positive_list,
                negative_list=negative_list,
            ),
            repo_stats,
        ),
    )
    processed_stats = rg.global_stats(
        repo_stats=repo_stats,
        weight_function_identifier='sigmoid',
        max_responsibles=3,
        percentile_min=85,
    )
    determined_responsibles, _ = rg.heuristically_determine_responsibles(
        stats=processed_stats,
        max_responsibles=3,
    )
    # compare as set to ignore index
    assert set(determined_responsibles) == {
        'himanshu-kun',
        'ialidzhikov',
    }
