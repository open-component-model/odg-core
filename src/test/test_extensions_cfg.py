import pytest

import odg.extensions_cfg


@pytest.fixture
def extensions_cfg() -> odg.extensions_cfg.ExtensionsConfiguration:
    raw = {
        'defaults': {
            'delivery_service_url': 'foo',
        },
        'sast': {
            'enabled': True,
        },
        'bdba': {
            'enabled': False,
            'mappings': [],
        },
        'clamav': {'mappings': []},
    }
    return odg.extensions_cfg.ExtensionsConfiguration.from_dict(raw)


def test_enabled_defaults(extensions_cfg: odg.extensions_cfg.ExtensionsConfiguration):
    assert extensions_cfg.sast.enabled is True
    assert extensions_cfg.bdba.enabled is False
    assert extensions_cfg.clamav.enabled is True


def test_sla_violation_profiler_publish_fields():
    raw = {
        'defaults': {'delivery_service_url': 'foo'},
        'sla_violation_profiler': {
            'components': [],
            'github_repository': 'github.com/org/repo',
            'branch': 'main',
            'filename': 'sla.md',
            'auto_merge': True,
        },
    }
    cfg = odg.extensions_cfg.ExtensionsConfiguration.from_dict(raw).sla_violation_profiler
    assert cfg.github_repository == 'github.com/org/repo'
    assert cfg.branch == 'main'
    assert cfg.filename == 'sla.md'
    assert cfg.auto_merge is True


def test_sla_violation_profiler_publish_defaults():
    raw = {
        'defaults': {'delivery_service_url': 'foo'},
        'sla_violation_profiler': {'components': []},
    }
    cfg = odg.extensions_cfg.ExtensionsConfiguration.from_dict(raw).sla_violation_profiler
    assert cfg.github_repository is None
    assert cfg.branch == 'master'
    assert cfg.filename == 'report.md'
    assert cfg.auto_merge is False
