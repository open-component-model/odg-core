import dataclasses
import datetime
import enum

import dacite

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


class TestArtefactMetadataId:
    def test_without_version(self):
        am = odg.model.ArtefactMetadata(
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
            meta=odg.model.Metadata(datasource='my-datasource', type='my-type'),
            data={},
        )
        assert am.id == 'de25c7bf37c6031b6d38ef14288b0e2b'

    def test_with_references(self):
        ref = odg.model.ComponentArtefactId(
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
        )
        am = odg.model.ArtefactMetadata(
            artefact=odg.model.ComponentArtefactId(
                component_name='my-component',
                component_version='0.1.0',
                artefact=odg.model.LocalArtefactId(
                    artefact_name='my-artefact',
                    artefact_version='0.1.0',
                    artefact_type='my-artefact-type',
                ),
                references=[ref],
            ),
            meta=odg.model.Metadata(datasource='my-datasource', type='my-type'),
            data={},
        )
        assert am.id == 'e7645c972e93cdf01526df135253584d'


class TestFromDictMatchesDacite:
    """Verify mashumaro from_dict produces identical output to the original dacite implementation."""

    def _assert_matches(self, raw: dict):
        assert _normalize(_from_dict_dacite(raw)) == _normalize(ArtefactMetadata.from_dict(raw))

    def test_bdba_vulnerability_with_cvss(self):
        # Dominant shape in production: BDBAVulnerabilityFinding with full CVSS struct.
        self._assert_matches(
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
        )

    def test_generic_vulnerability(self):
        self._assert_matches(
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
        )

    def test_rescoring_bdba_user(self):
        self._assert_matches(
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
        )

    def test_rescoring_github_user(self):
        self._assert_matches(
            _artefact_envelope(
                odg.model.Datatype.RESCORING,
                {
                    'finding': {'package_name': 'linux_kernel', 'cve': 'CVE-2024-1234'},
                    'referenced_type': 'finding/vulnerability',
                    'severity': 'NONE',
                    'user': {
                        'username': 'd046309',
                        'type': 'github-user',
                        'github_hostname': 'github.wdf.sap.corp',
                    },
                },
            ),
        )

    def test_responsibles(self):
        self._assert_matches(
            _artefact_envelope(
                odg.model.Datatype.RESPONSIBLES,
                {'referenced_type': 'finding/vulnerability'},
            ),
        )

    def test_compliance_snapshot(self):
        self._assert_matches(
            _artefact_envelope(
                odg.model.Datatype.COMPLIANCE_SNAPSHOTS,
                {'state': []},
            ),
        )

    def test_artefact_scan_info(self):
        self._assert_matches(
            _artefact_envelope(
                odg.model.Datatype.ARTEFACT_SCAN_INFO,
                {'referenced_type': 'finding/vulnerability'},
            ),
        )

    def test_meta_optional_fields(self):
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
        self._assert_matches(raw)

    def test_meta_responsibles(self):
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
        self._assert_matches(raw)


class TestRescoringUserFallback:
    """Unknown user types (e.g. bdba-extension-user) must decode to User, preserving type string."""

    def test_bdba_extension_user_decodes_to_user(self):
        raw = _artefact_envelope(
            odg.model.Datatype.RESCORING,
            {
                'finding': {'package_name': 'openssl', 'cve': 'CVE-2023-0286'},
                'referenced_type': 'finding/vulnerability',
                'severity': 'LOW',
                'user': {'username': 'bdba-extension-auto-rescoring', 'type': 'bdba-extension-user'},
                'matching_rules': ['finding-update'],
            },
        )
        result = ArtefactMetadata.from_dict(raw)
        assert type(result.data.user) is odg.model.User
        assert result.data.user.username == 'bdba-extension-auto-rescoring'
        assert result.data.user.type == 'bdba-extension-user'

    def test_known_user_types_decode_to_subclass(self):
        cases = [
            (
                {
                    'username': 'jdoe',
                    'type': 'bdba-user',
                    'email': 'j@x.com',
                    'firstname': 'J',
                    'lastname': 'D',
                },
                odg.model.BDBAUser,
            ),
            (
                {'username': 'd046309', 'type': 'github-user', 'github_hostname': 'github.com'},
                odg.model.GitHubUser,
            ),
            (
                {'username': 'alice', 'type': 'oidc-user', 'issuer': 'https://accounts.example.com'},
                odg.model.OidcUser,
            ),
        ]
        for user_raw, expected_type in cases:
            raw = _artefact_envelope(
                odg.model.Datatype.RESCORING,
                {
                    'finding': {'package_name': 'pkg', 'cve': 'CVE-1'},
                    'referenced_type': 'finding/vulnerability',
                    'severity': 'LOW',
                    'user': user_raw,
                },
            )
            result = ArtefactMetadata.from_dict(raw)
            assert type(result.data.user) is expected_type, (
                f'expected {expected_type.__name__} for type={user_raw["type"]!r}'
            )
