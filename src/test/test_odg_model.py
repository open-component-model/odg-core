import dataclasses
import datetime
import enum

import dacite
import pytest

import odg.model
from odg.model import ArtefactMetadata, MatchCondition


def _from_dict_dacite(raw: dict) -> ArtefactMetadata:
    return dacite.from_dict(
        data_class=ArtefactMetadata,
        data=raw,
        config=dacite.Config(
            type_hooks={
                datetime.datetime: datetime.datetime.fromisoformat,
                datetime.date: lambda date: datetime.datetime.fromisoformat(date).date(),
            },
            cast=[
                enum.StrEnum,
                MatchCondition,
            ],
            strict=True,
        ),
    )


def _normalize(value):
    """Recursively convert dataclasses and enums to plain dicts/primitives for comparison."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: _normalize(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    return value


def _artefact_envelope(meta_type: str, data: dict) -> dict:
    return {
        'artefact': {
            'component_name': 'example.org/component',
            'component_version': '1.0.0',
            'artefact_kind': 'resource',
            'artefact': {
                'artefact_name': 'my-image',
                'artefact_type': 'ociImage',
                'artefact_version': '1.0.0',
                'artefact_extra_id': {},
            },
        },
        'meta': {
            'datasource': 'bdba',
            'type': meta_type,
            'creation_date': '2025-01-01T00:00:00+00:00',
        },
        'data': data,
        'discovery_date': '2025-01-01',
        'allowed_processing_time': '30d',
    }


def test_artefact_metadata_id():
    artefact_metadatum_1 = odg.model.ArtefactMetadata(
        artefact=odg.model.ComponentArtefactId(
            component_name='my-component',
            component_version=None,
            artefact_kind=odg.model.ArtefactKind.RESOURCE,
            artefact=odg.model.LocalArtefactId(
                artefact_name='my-artefact',
                artefact_version='0.1.0',
                artefact_type='my-artefact-type',
                artefact_extra_id={
                    'extra-identity-key-1': 'extra-identity-value-1',
                    'extra-identity-key-2': 'extra-identity-value-2',
                },
            ),
        ),
        meta=odg.model.Metadata(
            datasource='my-datasource',
            type='my-type',
        ),
        data={},
    )

    artefact_metadatum_2 = odg.model.ArtefactMetadata(
        artefact=odg.model.ComponentArtefactId(
            component_name='my-component',
            component_version='0.1.0',
            artefact=odg.model.LocalArtefactId(
                artefact_name='my-artefact',
                artefact_version='0.1.0',
                artefact_type='my-artefact-type',
            ),
            references=[artefact_metadatum_1.artefact],
        ),
        meta=odg.model.Metadata(
            datasource='my-datasource',
            type='my-type',
        ),
        data={},
    )

    assert artefact_metadatum_1.id == 'de25c7bf37c6031b6d38ef14288b0e2b'
    assert artefact_metadatum_2.id == 'e7645c972e93cdf01526df135253584d'


@pytest.mark.parametrize(
    'raw',
    [
        _artefact_envelope(
            odg.model.Datatype.VULNERABILITY_FINDING,
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
                'summary': 'Type confusion in X.400 address processing.',
                'urls': ['https://nvd.nist.gov/vuln/detail/CVE-2023-0286'],
            },
        ),
        _artefact_envelope(
            odg.model.Datatype.VULNERABILITY_FINDING,
            {
                'package_name': 'curl',
                'package_version': '8.0.0',
                'severity': 'MEDIUM',
                'cve': 'CVE-2025-9999',
                'cvss_score': 5.3,
            },
        ),
        _artefact_envelope(
            odg.model.Datatype.RESCORING,
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
            },
        ),
        _artefact_envelope(
            odg.model.Datatype.RESPONSIBLES,
            {'referenced_type': 'finding/vulnerability'},
        ),
        _artefact_envelope(
            odg.model.Datatype.COMPLIANCE_SNAPSHOTS,
            {'state': []},
        ),
    ],
)
def test_mashumaro_matches_dacite(raw):
    dacite_result = _from_dict_dacite(raw)
    mashumaro_result = ArtefactMetadata.from_dict(raw)
    assert _normalize(dacite_result) == _normalize(mashumaro_result)


def test_mashumaro_matches_dacite_with_responsibles():
    raw = _artefact_envelope(
        odg.model.Datatype.VULNERABILITY_FINDING,
        {
            'package_name': 'curl',
            'package_version': '8.0.0',
            'severity': 'MEDIUM',
            'cve': 'CVE-2025-9999',
            'cvss_score': 5.3,
        },
    )
    raw['meta']['responsibles'] = [
        {
            'identifiers': [
                {
                    'source': 'codeowners',
                    'type': 'githubUser',
                    'username': 'jdoe',
                    'github_hostname': 'github.com',
                },
            ],
        },
    ]
    dacite_result = _from_dict_dacite(raw)
    mashumaro_result = ArtefactMetadata.from_dict(raw)
    assert _normalize(dacite_result) == _normalize(mashumaro_result)


def test_mashumaro_matches_dacite_full_meta():
    raw = _artefact_envelope(
        odg.model.Datatype.VULNERABILITY_FINDING,
        {
            'package_name': 'openssl',
            'package_version': '3.0.7',
            'severity': 'HIGH',
            'cve': 'CVE-2023-0286',
            'cvss_score': 7.4,
        },
    )
    raw['meta']['last_update'] = '2025-06-02T08:00:00+00:00'
    raw['meta']['assignee_mode'] = 'extend'
    dacite_result = _from_dict_dacite(raw)
    mashumaro_result = ArtefactMetadata.from_dict(raw)
    assert _normalize(dacite_result) == _normalize(mashumaro_result)
