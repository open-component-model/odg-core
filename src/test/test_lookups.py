import unittest.mock

import pytest

import lookups


@pytest.fixture
def ocm_repository_cfgs() -> list[lookups.VirtualOcmRepositoryCfg | lookups.OciOcmRepositoryCfg]:
    ocm_repository_cfgs_raw = [
        {
            'name': '<auto>',
            'type': 'virtual',
            'selectors': {
                'required_labels': 'releases',
            },
        },
        {
            'name': '<releases>',
            'type': 'virtual',
            'selectors': [
                {
                    'required_labels': 'releases',
                },
            ],
        },
        {
            'name': '<auto-all>',
            'type': 'virtual',
        },
        {
            'repository': 'europe-docker.pkg.dev/gardener-project/releases',
            'prefixes': [
                'ocm.software/open-delivery-gear',
                'github.com/gardener',
            ],
            'labels': 'releases',
        },
        {
            'repository': 'europe-docker.pkg.dev/gardener-project/releases/odg',
            'prefix': 'ocm.software/open-delivery-gear',
            'labels': 'releases',
        },
        {
            'repository': 'europe-docker.pkg.dev/gardener-project/snapshots',
            'prefixes': [
                'ocm.software/open-delivery-gear',
                'github.com/gardener',
            ],
            'labels': 'snapshots',
        },
        {
            'repository': 'europe-docker.pkg.dev/gardener-project/snapshots/odg',
            'prefixes': [
                'ocm.software/open-delivery-gear',
            ],
            'labels': [
                'snapshots',
            ],
        },
        {
            'repository': 'europe-docker.pkg.dev/gardener-project/fallback',
        },
    ]

    return [
        lookups.OcmRepositoryCfgBase.from_dict(ocm_repository_cfg_raw)
        for ocm_repository_cfg_raw in ocm_repository_cfgs_raw
    ]


def test_ocm_repository_cfgs(
    ocm_repository_cfgs: list[lookups.VirtualOcmRepositoryCfg | lookups.OciOcmRepositoryCfg],
):
    # test `<auto>` virtual repository
    ocm_repository_lookup = lookups.init_ocm_repository_lookup(
        ocm_repo=None,
        ocm_repository_cfgs=ocm_repository_cfgs,
    )

    assert len(list(ocm_repository_lookup('ocm.software/open-delivery-gear/core'))) == 2
    assert len(list(ocm_repository_lookup('github.com/gardener/gardener'))) == 1

    # test `<auto-all>` virtual repository
    ocm_repository_lookup = lookups.init_ocm_repository_lookup(
        ocm_repo='<auto-all>',
        ocm_repository_cfgs=ocm_repository_cfgs,
    )

    assert len(list(ocm_repository_lookup('ocm.software/open-delivery-gear/core'))) == 5
    assert len(list(ocm_repository_lookup('github.com/gardener/gardener'))) == 3

    # test existing standard repository
    ocm_repository_lookup = lookups.init_ocm_repository_lookup(
        ocm_repo='europe-docker.pkg.dev/gardener-project/releases/odg',
        ocm_repository_cfgs=ocm_repository_cfgs,
    )

    assert len(list(ocm_repository_lookup('ocm.software/open-delivery-gear/core'))) == 1
    assert len(list(ocm_repository_lookup('github.com/gardener/gardener'))) == 0

    # test not existing repository
    ocm_repository_lookup = lookups.init_ocm_repository_lookup(
        ocm_repo='foo',
        ocm_repository_cfgs=ocm_repository_cfgs,
    )

    assert len(list(ocm_repository_lookup('ocm.software/open-delivery-gear/core'))) == 1
    assert len(list(ocm_repository_lookup('github.com/gardener/gardener'))) == 1

    # test explicitly _added_ repository
    ocm_repository_lookup = lookups.extended_ocm_repository_lookup(
        ocm_repo='foo',
        ocm_repository_lookup=lookups.init_ocm_repository_lookup(
            ocm_repository_cfgs=ocm_repository_cfgs,
        ),
    )

    assert list(ocm_repository_lookup('ocm.software/open-delivery-gear/core')) == [
        'foo',
        'europe-docker.pkg.dev/gardener-project/releases',
        'europe-docker.pkg.dev/gardener-project/releases/odg',
    ]
    assert list(ocm_repository_lookup('github.com/gardener/gardener')) == [
        'foo',
        'europe-docker.pkg.dev/gardener-project/releases',
    ]


# ---------------------------------------------------------------------------
# is_allowlisted_ocm_repo
# ---------------------------------------------------------------------------


def _patched_allowlist(*extra_netlocs: str):
    """
    Patch _iter_allowlisted_ocm_repo_netlocs so tests don't touch ctx_util / the
    filesystem, but still exercise the real is_allowlisted_ocm_repo logic.
    """
    return unittest.mock.patch(
        'lookups._iter_allowlisted_ocm_repo_netlocs',
        side_effect=lambda: iter(lookups._ALLOWLISTED_OCM_REPO_NETLOCS + extra_netlocs),
    )


@pytest.mark.parametrize(
    'url',
    [
        'ghcr.io/org/image:latest',
        'quay.io/org/image',
        'registry-1.docker.io/library/alpine',
        'https://docker.io/library/ubuntu:22.04',
        'index.docker.io/library/debian',
        'public.ecr.aws/my-org/image',
        'mcr.microsoft.com/dotnet/runtime',
        'cgr.dev/chainguard/static',
        'registry.k8s.io/pause:3.9',
    ],
)
def test_is_allowlisted_ocm_repo_static(url):
    with _patched_allowlist():
        assert lookups.is_allowlisted_ocm_repo(url) is True


@pytest.mark.parametrize(
    'url',
    [
        'us-east-1.ecr.amazonaws.com/my-repo',
        'myaccount.dkr.ecr.eu-west-1.amazonaws.com/app',
        'europe-docker.pkg.dev/gardener-project/releases',
        'https://us-docker.pkg.dev/my-project/my-repo',
        'eu.gcr.io/my-project/image',
        'myregistry.azurecr.io/image',
    ],
)
def test_is_allowlisted_ocm_repo_wildcard(url):
    with _patched_allowlist():
        assert lookups.is_allowlisted_ocm_repo(url) is True


@pytest.mark.parametrize(
    'url',
    [
        'evil.example.com/bad/image',
        'notghcr.io/org/image',
        'ghcr.io.attacker.com/org/image',
        'fakequay.io/image',
        'pkg.dev/my-project/image',  # bare root does not match *.pkg.dev
        'evil.com\\.pkg.dev/x',  # backslash bypass attempt
    ],
)
def test_is_allowlisted_ocm_repo_rejected(url):
    with _patched_allowlist():
        assert lookups.is_allowlisted_ocm_repo(url) is False


def test_is_allowlisted_ocm_repo_dynamic_netloc():
    # netlocs from OCI registry secrets / OCM repo cfgs are also honoured
    with _patched_allowlist('custom.internal.registry.example.com'):
        assert (
            lookups.is_allowlisted_ocm_repo(
                'custom.internal.registry.example.com/org/image',
            )
            is True
        )


def test_is_allowlisted_ocm_repo_virtual():
    # virtual OCM repo names (e.g. '<auto>') are matched by exact string, not as a URL
    virtual_repos = ['<auto>', 'my-virtual-repo']
    with unittest.mock.patch(
        'lookups._iter_allowlisted_virtual_ocm_repos',
        side_effect=lambda: iter(virtual_repos),
    ):
        assert lookups.is_allowlisted_ocm_repo('<auto>') is True
        assert lookups.is_allowlisted_ocm_repo('my-virtual-repo') is True
        assert lookups.is_allowlisted_ocm_repo('other-virtual-repo') is False
