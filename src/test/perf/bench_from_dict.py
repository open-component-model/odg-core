"""
Benchmark: ArtefactMetadata.from_dict on the issue_replicator HTTP-path shape.

The HTTP path (delivery_service_client.query_metadata -> res.json()) is the dominant
call site. Dicts include 'references': [] in artefact and nullable meta fields because
the server serialises via dataclasses.asdict().

Run with:  make test_perf
           make test          (benchmarks disabled, runs as plain pass/fail)
"""

import copy

import pytest

import odg.model

_ARTEFACT = {
    'component_name': 'example.org/my-component',
    'component_version': '1.2.3',
    'artefact_kind': 'resource',
    'artefact': {
        'artefact_name': 'my-image',
        'artefact_type': 'ociImage',
        'artefact_version': '1.2.3',
        'artefact_extra_id': {},
    },
    'references': [],
}

_META = {
    'datasource': 'bdba',
    'creation_date': '2025-06-01T12:00:00+00:00',
    'last_update': '2025-06-02T08:00:00+00:00',
    'responsibles': None,
    'assignee_mode': None,
}


def _envelope(meta_type: str, data: dict) -> dict:
    return {
        'artefact': _ARTEFACT,
        'meta': {**_META, 'type': meta_type},
        'data': data,
        'discovery_date': '2025-06-01' if meta_type.startswith('finding/') else None,
        'allowed_processing_time': '30d' if meta_type.startswith('finding/') else None,
    }


_BDBA_VULN = _envelope(
    'finding/vulnerability',
    {
        'package_name': 'openssl',
        'package_version': '3.0.7',
        'base_url': 'https://bdba.example.com',
        'report_url': 'https://bdba.example.com/products/42/',
        'product_id': 42,
        'group_id': 7,
        'severity': 'HIGH',
        'cve': 'CVE-2023-0286',
        'cvss_score': 7.4,
        'cvss': {
            'access_vector': 'N',
            'attack_complexity': 'H',
            'user_interaction': 'N',
            'privileges_required': 'N',
            'scope': 'U',
            'confidentiality': 'H',
            'integrity': 'N',
            'availability': 'H',
        },
        'summary': 'Type confusion vulnerability in X.400 address processing.',
        'urls': ['https://nvd.nist.gov/vuln/detail/CVE-2023-0286'],
    },
)

_RESCORING = _envelope(
    'rescorings',
    {
        'finding': {'package_name': 'openssl', 'cve': 'CVE-2023-0286'},
        'referenced_type': 'finding/vulnerability',
        'severity': 'LOW',
        'user': {
            'username': 'jdoe',
            'type': 'bdba-user',
            'email': 'jdoe@example.com',
            'firstname': 'Jane',
            'lastname': 'Doe',
        },
        'comment': 'Mitigated by network policy.',
        'allowed_processing_time': None,
        'due_date': None,
    },
)

_SCAN_INFO = _envelope(
    'meta/artefact_scan_info',
    {
        'referenced_type': 'finding/vulnerability',
        'newest_processed_artifact_version': '1.2.3',
    },
)


def _warmup():
    for raw in (_BDBA_VULN, _RESCORING, _SCAN_INFO):
        odg.model.ArtefactMetadata.from_dict(copy.deepcopy(raw))


_warmup()


@pytest.fixture
def bdba_vuln():
    return copy.deepcopy(_BDBA_VULN)


@pytest.fixture
def rescoring():
    return copy.deepcopy(_RESCORING)


@pytest.fixture
def scan_info():
    return copy.deepcopy(_SCAN_INFO)


def test_bench_bdba_vuln(benchmark, bdba_vuln):
    benchmark(odg.model.ArtefactMetadata.from_dict, bdba_vuln)


def test_bench_rescoring(benchmark, rescoring):
    benchmark(odg.model.ArtefactMetadata.from_dict, rescoring)


def test_bench_scan_info(benchmark, scan_info):
    benchmark(odg.model.ArtefactMetadata.from_dict, scan_info)
