import collections.abc
import datetime
import functools
import logging
import time

import github3
import github3.issues
import github3.repos
import requests
import requests.adapters
import urllib3.util.retry

import github.retry
import secret_mgmt
import secret_mgmt.github
import util


logger = logging.getLogger(__name__)


def is_remaining_quota_too_low(
    gh_api: github3.GitHub,
    relative_gh_quota_minimum: float = 0.2,
) -> bool:
    rate_limit = gh_api.rate_limit().get('resources', dict()).get('core', dict()).get('limit', -1)
    rate_limit_remaining = gh_api.ratelimit_remaining

    logger.info(f'{rate_limit_remaining=} {rate_limit=}')

    return rate_limit_remaining < relative_gh_quota_minimum * rate_limit


def wait_for_quota_if_required(
    gh_api: github3.GitHub,
    relative_gh_quota_minimum: float = 0.2,
):
    if not is_remaining_quota_too_low(
        gh_api=gh_api,
        relative_gh_quota_minimum=relative_gh_quota_minimum,
    ):
        return

    reset_timestamp = gh_api.rate_limit().get('resources', dict()).get('core', dict()).get('reset')
    if not reset_timestamp:
        return

    reset_datetime = datetime.datetime.fromtimestamp(
        timestamp=reset_timestamp,
        tz=datetime.timezone.utc,
    )
    time_until_reset = reset_datetime - datetime.datetime.now(tz=datetime.timezone.utc)

    logger.warning(f'github quota too low, will sleep {time_until_reset} until {reset_datetime}')
    time.sleep(time_until_reset.total_seconds())


@functools.cache
@github.retry.retry_and_throttle
def all_issues(
    repository: github3.repos.Repository,
    state: str = 'all',
    number: int = -1,  # -1 means all issues
):
    return set(
        repository.issues(
            state=state,
            number=number,
        ),
    )


def filter_issues_for_labels(
    issues: collections.abc.Iterable[github3.issues.ShortIssue],
    labels: collections.abc.Iterable[str],
) -> tuple[github3.issues.ShortIssue, ...]:
    labels = set(labels)

    def filter_issue(
        issue: github3.issues.ShortIssue,
    ) -> bool:
        issue_labels = {label.name for label in issue.original_labels}

        return labels.issubset(issue_labels)

    return tuple(issue for issue in issues if filter_issue(issue))


@functools.cache
def find_token_for_repo_url(
    secret_factory: secret_mgmt.SecretFactory,
    repo_url: str,
) -> str | None:
    github_api = secret_mgmt.github.github_api(
        secret_factory=secret_factory,
        repo_url=repo_url,
        absent_ok=True,
    )

    if not github_api:
        logger.error(f'No GitHub token found for {repo_url=}')
        return None

    return github_api.session.auth.token


@functools.cache
def find_token_for_api_url(
    secret_factory: secret_mgmt.SecretFactory,
    api_url: str,
) -> str | None:
    parsed = util.urlparse(api_url)
    hostname = parsed.hostname
    path_parts = parsed.path.strip('/').split('/')

    if len(path_parts) < 2:
        logger.error(f'Cannot determine repo/org from {api_url=}')
        return None

    # github.com: https://api.github.com/repos/{org}/...  -> path_parts[1]
    # github enterprise: https://host/api/v3/repos/{org}/... -> path_parts[3]
    if hostname == 'api.github.com':
        org_index = 1
    else:
        org_index = 3

    if len(path_parts) <= org_index:
        logger.error(f'Cannot determine org from {api_url=}')
        return None

    org = path_parts[org_index]
    repo_url = f'github.com/{org}' if hostname == 'api.github.com' else f'{hostname}/{org}'

    return find_token_for_repo_url(
        secret_factory=secret_factory,
        repo_url=repo_url,
    )


def github_api_request(
    url: str,
    secret_factory: secret_mgmt.SecretFactory,
    token: str | None = None,
) -> tuple[list | dict | None, str | None]:
    """
    Perform a single authenticated GET request to the GitHub API.

    Returns a tuple of (response_body, next_url), where response_body is the
    parsed JSON (list or dict) and next_url is the URL of the next page taken
    from the Link header, or None if there are no further pages. Both values
    are None if the request fails.
    """
    if not token:
        token = find_token_for_api_url(
            secret_factory=secret_factory,
            api_url=url,
        )

    if not token:
        return None, None

    session = requests.Session()
    retries = urllib3.util.retry.Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=['GET'],
    )
    session.mount('https://', requests.adapters.HTTPAdapter(max_retries=retries))

    try:
        response = session.get(
            url,
            headers={
                'Authorization': f'token {token}',
                'Accept': 'application/vnd.github+json',
            },
            timeout=30,
        )
        response.raise_for_status()
        next_url = response.links.get('next', {}).get('url')
        return response.json(), next_url
    except Exception as e:
        logger.error(f'GitHub API request failed for {url}: {e}')
        return None, None


def github_api_request_paginated(
    url: str,
    secret_factory: secret_mgmt.SecretFactory,
) -> collections.abc.Iterable[dict]:
    next_url = url

    while next_url:
        token = find_token_for_api_url(
            secret_factory=secret_factory,
            api_url=url,
        )

        page_items, next_url = github_api_request(
            url=next_url,
            secret_factory=secret_factory,
            token=token,
        )

        if page_items:
            yield from page_items
