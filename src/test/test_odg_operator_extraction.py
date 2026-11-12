import io
import os
import tarfile
import types

import ocm
import pytest

import odg_operator.__main__ as odgc
import odg_operator.odg_model as odgm


def _tar_gz(*members: tarfile.TarInfo | tuple[tarfile.TarInfo, bytes]) -> list[bytes]:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as tf:
        for member in members:
            if isinstance(member, tuple):
                info, data = member
                tf.addfile(info, io.BytesIO(data))
            else:
                tf.addfile(member)
    return [buffer.getvalue()]


def _file(name: str, data: bytes = b'foo: bar\n') -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    return info, data


def _symlink(name: str, target: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.SYMTYPE
    info.linkname = target
    return info


def test_extract_regular_chart(tmp_path):
    odgc._extract_tar_gz(
        content=_tar_gz(_file('chart/values.yaml')),
        path=str(tmp_path),
    )

    assert (tmp_path / 'chart' / 'values.yaml').read_text() == 'foo: bar\n'


def test_extract_allows_symlink_inside_archive(tmp_path):
    odgc._extract_tar_gz(
        content=_tar_gz(
            _file('chart/values.yaml'),
            _symlink('chart/alias.yaml', 'values.yaml'),
        ),
        path=str(tmp_path),
    )

    assert (tmp_path / 'chart' / 'alias.yaml').read_text() == 'foo: bar\n'


@pytest.mark.parametrize(
    'target',
    (
        '/etc/passwd',
        '/var/run/secrets/kubernetes.io/serviceaccount/token',
        '../../outside',
    ),
)
def test_extract_rejects_escaping_symlink(tmp_path, target):
    with pytest.raises(tarfile.TarError):
        odgc._extract_tar_gz(
            content=_tar_gz(_symlink('chart/values.yaml', target)),
            path=str(tmp_path),
        )

    assert not os.path.lexists(tmp_path / 'chart' / 'values.yaml')


def test_extract_rejects_path_traversal_member(tmp_path):
    extract_path = tmp_path / 'extract'
    extract_path.mkdir()

    with pytest.raises(tarfile.TarError):
        odgc._extract_tar_gz(
            content=_tar_gz(_file('../outside.yaml')),
            path=str(extract_path),
        )

    assert not (tmp_path / 'outside.yaml').exists()


def test_resolve_chart_path_valid(tmp_path):
    (tmp_path / 'chart').mkdir()

    assert odgc._resolve_chart_path(
        base_path=str(tmp_path),
        chart_name='chart',
    ) == os.path.realpath(tmp_path / 'chart')


@pytest.mark.parametrize('chart_name', ('..', '../other', '/etc', 'chart/../../other'))
def test_resolve_chart_path_rejects_escaping_name(tmp_path, chart_name):
    (tmp_path / 'chart').mkdir()

    assert odgc._resolve_chart_path(base_path=str(tmp_path), chart_name=chart_name) is None


def test_resolve_chart_path_rejects_symlink_escape(tmp_path):
    base_path = tmp_path / 'base'
    base_path.mkdir()
    (tmp_path / 'outside').mkdir()
    (base_path / 'chart').symlink_to(tmp_path / 'outside')

    assert odgc._resolve_chart_path(base_path=str(base_path), chart_name='chart') is None


def test_create_or_update_odg_reports_invalid_archive(monkeypatch):
    artefact = types.SimpleNamespace(
        name='broken-chart',
        access=types.SimpleNamespace(type=ocm.AccessType.LOCAL_BLOB),
    )
    extension_instance = odgm.ExtensionInstance(
        name='broken-extension',
        installation_artefacts=[
            odgm.ExtensionInstallationArtefact(
                helm_chart_name='chart',
                artefact=artefact,
                component=None,
            ),
        ],
        values=[],
    )
    extension_definition = types.SimpleNamespace(
        name='broken-extension',
        templated_outputs=lambda context: [],
        installation=types.SimpleNamespace(value_templates=[]),
    )

    monkeypatch.setattr(
        odgm.ExtensionInstance,
        'from_definition',
        lambda **kwargs: extension_instance,
    )
    monkeypatch.setattr(
        odgc.ocm_util,
        'iter_blob_descriptors',
        lambda **kwargs: iter(
            (
                types.SimpleNamespace(
                    content=_tar_gz(_symlink('chart/values.yaml', '/etc/passwd')),
                ),
            ),
        ),
    )

    status_for_extension, encountered_error = odgc.create_or_update_odg(
        odg=odgm.ODG(
            name='odg',
            namespace='odg',
            context={},
            extensions=['broken-extension'],
            uid='uid',
            generation=1,
            annotations={},
            status={},
        ),
        extension_definitions=[extension_definition],
        cluster_identity='cluster',
        component_descriptor_lookup=None,
        oci_client=None,
        kubernetes_api=None,
    )

    assert encountered_error
    assert status_for_extension['broken-extension'][-1].startswith(
        'invalid helm chart archive broken-chart',
    )
