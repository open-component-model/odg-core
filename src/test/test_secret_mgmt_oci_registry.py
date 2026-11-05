import oci.auth

import secret_mgmt.oci_registry


def _make_cfg(
    prefixes: list[str],
    privileges=oci.auth.Privileges.READONLY,
):
    return secret_mgmt.oci_registry.OciRegistry(
        username='user',
        password='pass',
        image_reference_prefixes=prefixes,
        privileges=privileges,
    )


def test_prefix_multiple_entries_all_normalised():
    cfg = _make_cfg(['ghcr.io/a/', 'quay.io/b/'])
    assert cfg.image_reference_prefixes == ['ghcr.io/a/', 'quay.io/b/']


def test_empty_prefixes_never_match():
    cfg = _make_cfg([])
    assert cfg.image_reference_matches('ghcr.io/anything/image:tag') is False


def test_matching_prefix_grants_access():
    cfg = _make_cfg(['ghcr.io/org/'])
    assert cfg.image_reference_matches('ghcr.io/org/image:latest') is True


def test_non_matching_prefix_denies_access():
    cfg = _make_cfg(['ghcr.io/org/'])
    assert cfg.image_reference_matches('quay.io/org/image:latest') is False


def test_privileges_gate_is_independent_of_prefix_match():
    cfg = _make_cfg(['ghcr.io/org/'], privileges=oci.auth.Privileges.READONLY)
    assert (
        cfg.image_reference_matches(
            'ghcr.io/org/image',
            privileges=oci.auth.Privileges.READWRITE,
        )
        is False
    )
    assert (
        cfg.image_reference_matches(
            'ghcr.io/org/image',
            privileges=oci.auth.Privileges.READONLY,
        )
        is True
    )
