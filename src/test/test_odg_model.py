import copy
import dataclasses
import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import sqlalchemy.dialects.sqlite

import consts
import deliverydb.util as du
import metadata
import odg.cvss
import odg.model


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


def _rescoring_envelope(
    finding: dict,
    user: dict,
    referenced_type: str = 'finding/vulnerability',
    **kwargs,
) -> dict:
    return _artefact_envelope(
        odg.model.Datatype.RESCORING,
        {
            'finding': finding,
            'referenced_type': referenced_type,
            'severity': 'LOW',
            'user': user,
            **kwargs,
        },
    )


_GITHUB_USER = {'username': 'jdoe', 'type': 'github-user', 'github_hostname': 'github.com'}
_OIDC_USER = {'username': 'alice', 'type': 'oidc-user', 'issuer': 'https://idp.example.com'}
_RESCORING_VULN = {'package_name': 'openssl', 'cve': 'CVE-2023-0286'}
_UTC = datetime.timezone.utc


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


class TestFromDictDataTypeResolution:
    """
    Parametrized sweep over all datatypes. Expected types match convention (legacy dacite).
    """

    @pytest.mark.parametrize(
        'meta_type,data,expected_data_type',
        [
            (
                odg.model.Datatype.VULNERABILITY_FINDING,
                {
                    'package_name': 'openssl',
                    'package_version': '3.0.7',
                    'severity': 'HIGH',
                    'cve': 'CVE-2023-0286',
                    'cvss_score': 7.4,
                },
                odg.model.VulnerabilityFinding,
            ),
            (
                odg.model.Datatype.LICENSE_FINDING,
                {
                    'package_name': 'openssl',
                    'package_version': '3.0',
                    'license': {'name': 'OpenSSL'},
                    'severity': 'MEDIUM',
                },
                dict,  # LicenseFinding requires BDBAMixin fields; matches convention (legacy dacite)
            ),
            (
                odg.model.Datatype.IP_FINDING,
                {
                    'package_name': 'openssl',
                    'package_version': '3.0',
                    'license': {'name': 'OpenSSL'},
                    'policy_violation': {'name': 'restricted-license', 'id': None, 'url': None},
                    'labels': [],
                    'host': 'bdba.example.com',
                    'href': None,
                    'severity': 'MEDIUM',
                },
                odg.model.IPFinding,
            ),
            (
                odg.model.Datatype.MALWARE_FINDING,
                {
                    'finding': {
                        'filename': 'eicar.txt',
                        'content_digest': 'sha256:abc',
                        'malware': 'Eicar-Test-Signature',
                        'context': None,
                    },
                    'octets_count': 68,
                    'scan_duration_seconds': 0.1,
                    'clamav_version': '1.0.0',
                    'signature_version': 27417,
                    'freshclam_timestamp': '2025-01-01T00:00:00+00:00',
                    'severity': 'BLOCKER',
                },
                odg.model.ClamAVMalwareFinding,
            ),
            (
                odg.model.Datatype.SAST_FINDING,
                {'sast_status': 'no-linter', 'sub_type': 'local-linting', 'severity': 'LOW'},
                odg.model.SastFinding,
            ),
            (
                odg.model.Datatype.CODEQL_FINDING,
                {
                    'codeql_status': 'not-enabled',
                    'repo_url': 'https://github.com/example/repo',
                    'language': 'python',
                    'severity': 'MEDIUM',
                },
                odg.model.CodeqlFinding,
            ),
            (
                odg.model.Datatype.OSID_FINDING,
                {
                    'osid': {'ID': 'debian', 'VERSION_ID': '12'},
                    'os_status': 'branchReachedEol',
                    'greatest_version': None,
                    'eol_date': None,
                    'severity': 'HIGH',
                },
                odg.model.OsIdFinding,
            ),
            (
                odg.model.Datatype.RESPONSIBLES,
                {'referenced_type': 'finding/vulnerability'},
                odg.model.ResponsibleInfo,
            ),
            (
                odg.model.Datatype.COMPLIANCE_SNAPSHOTS,
                {'state': []},
                odg.model.ComplianceSnapshot,
            ),
            (
                odg.model.Datatype.ARTEFACT_SCAN_INFO,
                {'referenced_type': 'finding/vulnerability'},
                odg.model.ResponsibleInfo,
            ),
            (
                odg.model.Datatype.RESCORING,
                {
                    'finding': _RESCORING_VULN,
                    'referenced_type': 'finding/vulnerability',
                    'severity': 'LOW',
                    'user': _GITHUB_USER,
                },
                odg.model.CustomRescoring,
            ),
            (
                odg.model.Datatype.SLA_VIOLATION,
                {
                    'sla_violations': [
                        {
                            'finding': {'package_name': 'curl', 'cve': 'CVE-2025-1'},
                            'referenced_type': 'finding/vulnerability',
                            'severity': 'HIGH',
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
                        },
                    ],
                },
                odg.model.SlaViolations,
            ),
        ],
    )
    def test_data_type_resolution(self, meta_type, data, expected_data_type):
        result = odg.model.ArtefactMetadata.from_dict(_artefact_envelope(meta_type, data))
        assert type(result.data) is expected_data_type


class TestFromDictVulnerabilityFinding:
    def test_bdba_finding_with_cvss(self):
        result = odg.model.ArtefactMetadata.from_dict(
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
        assert isinstance(result.data, odg.model.BDBAVulnerabilityFinding)
        assert result.data.package_name == 'openssl'
        assert result.data.package_version == '3.0.7'
        assert result.data.cve == 'CVE-2023-0286'
        assert result.data.cvss_score == 7.4
        assert result.data.base_url == 'https://bdba.example.com'
        assert result.data.product_id == 42
        assert result.data.group_id == 7
        assert result.data.summary == 'Type confusion in X.400 address processing.'
        assert result.data.cvss['access_vector'] == 'N'  # stays a dict, see test below

    def test_generic_vulnerability_without_bdba_fields(self):
        result = odg.model.ArtefactMetadata.from_dict(
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
        assert isinstance(result.data, odg.model.VulnerabilityFinding)
        assert not isinstance(result.data, odg.model.BDBAVulnerabilityFinding)
        assert result.data.package_name == 'curl'
        assert result.data.cve == 'CVE-2025-9999'
        assert result.data.cvss_score == 5.3
        assert 'https://nvd.nist.gov/vuln/detail/CVE-2025-9999' in result.data.urls


class TestFromDictRescoring:
    @pytest.mark.parametrize(
        'user_raw,expected_type,expected_key',
        [
            (
                {'username': 'alice', 'type': 'github-user', 'github_hostname': 'github.com'},
                odg.model.GitHubUser,
                'alice|github-user',
            ),
            (
                {
                    'username': 'alice',
                    'type': 'bdba-user',
                    'email': 'a@b.com',
                    'firstname': 'A',
                    'lastname': 'B',
                },
                odg.model.BDBAUser,
                'alice|bdba-user',
            ),
            (
                {'username': 'alice', 'type': 'oidc-user', 'issuer': 'https://example.com'},
                odg.model.OidcUser,
                'alice|oidc-user|https://example.com',
            ),
            (
                # unknown type + issuer: issuer presence drives OidcUser; type value is ignored
                {'username': 'alice', 'type': 'extension-user', 'issuer': 'https://example.com'},
                odg.model.OidcUser,
                'alice|extension-user|https://example.com',
            ),
            (
                {'username': 'alice', 'type': 'extension-user'},
                odg.model.User,
                'alice|extension-user',
            ),
            (
                # oidc-user without issuer: OidcUser construction fails, falls back to User
                {'username': 'alice', 'type': 'oidc-user'},
                odg.model.User,
                'alice|oidc-user',
            ),
            (
                # shape beats tag: BDBA fields + wrong type tag → BDBAUser (first in union)
                {
                    'username': 'alice',
                    'type': 'github-user',
                    'email': 'a@b.com',
                    'firstname': 'A',
                    'lastname': 'B',
                },
                odg.model.BDBAUser,
                'alice|github-user',
            ),
            (
                # shape beats tag: only username + bdba-user tag → User (BDBA required fields absent)
                {'username': 'alice', 'type': 'bdba-user'},
                odg.model.User,
                'alice|bdba-user',
            ),
        ],
    )
    def test_user_type_and_key(self, user_raw, expected_type, expected_key):
        result = odg.model.ArtefactMetadata.from_dict(
            _rescoring_envelope(finding=_RESCORING_VULN, user=user_raw),
        )
        assert type(result.data.user) is expected_type
        assert result.data.user.key == expected_key

    @pytest.mark.parametrize(
        'referenced_type,finding_data,expected_finding_type',
        [
            (
                'finding/vulnerability',
                {'package_name': 'openssl', 'cve': 'CVE-2023-0286'},
                odg.model.RescoringVulnerabilityFinding,
            ),
            (
                'finding/license',
                {'package_name': 'openssl', 'license': {'name': 'MIT'}},
                odg.model.RescoringLicenseFinding,
            ),
            (
                'finding/ip',
                {'package_name': 'openssl', 'license': {'name': 'MIT'}, 'labels': ['a', 'b']},
                odg.model.RescoringIPFinding,
            ),
            (
                'finding/malware',
                {
                    'filename': 'test.exe',
                    'content_digest': 'sha256:abc',
                    'malware': 'Eicar',
                    'context': None,
                },
                odg.model.MalwareFindingDetails,
            ),
        ],
    )
    def test_finding_type(self, referenced_type, finding_data, expected_finding_type):
        result = odg.model.ArtefactMetadata.from_dict(
            _rescoring_envelope(
                finding=finding_data,
                user=_GITHUB_USER,
                referenced_type=referenced_type,
            ),
        )
        assert isinstance(result.data, odg.model.CustomRescoring)
        assert type(result.data.finding) is expected_finding_type

    def test_dispatch_table_matches_finding_union(self):
        # Adding a finding class to _RescoringFindingField without a dispatch-table entry would
        # silently decode its rescorings as raw dict — guard against that drift.
        assert len(odg.model._decode_rescoring_finding_by_type) == len(
            odg.model._RescoringFindingField.__args__,
        )

    @pytest.mark.parametrize(
        'raw',
        [
            # missing required finding field (cve) → MissingField
            _rescoring_envelope(finding={'package_name': 'openssl'}, user=_GITHUB_USER),
            # required field missing (labels) → falls back to dict instead of raising mid-stream
            _rescoring_envelope(
                finding={'package_name': 'openssl', 'license': {'name': 'MIT'}},
                user=_GITHUB_USER,
                referenced_type='finding/ip',
            ),
        ],
    )
    def test_falls_back_to_dict(self, raw):
        assert isinstance(odg.model.ArtefactMetadata.from_dict(raw).data, dict)

    @pytest.mark.parametrize(
        'raw',
        [
            _rescoring_envelope(
                finding={'package_name': 'openssl', 'license': {'name': 'OpenSSL'}},
                user=_GITHUB_USER,
                referenced_type='finding/license',
            ),
            _rescoring_envelope(finding=_RESCORING_VULN, user=_OIDC_USER),
        ],
    )
    def test_id_stable_after_db_roundtrip(self, raw):
        original = odg.model.ArtefactMetadata.from_dict(raw)
        db_row = du.to_db_artefact_metadata(original)
        assert db_row.id == original.id
        readback = odg.model.ArtefactMetadata.from_dict(du.db_artefact_metadata_to_dict(db_row))
        assert readback.id == db_row.id


class TestDeletePath:
    @pytest.mark.asyncio
    async def test_delete_unknown_type_with_issuer_uses_oidc_user_id(self):
        # An unknown user type with an `issuer` field is decoded as OidcUser (issuer presence
        # drives the selection). The old dacite strict=True decoder raised UnionMatchError on
        # this payload on both read and write — so no row was ever stored under a legacy dict
        # ID via the HTTP path. Extension write paths used live OidcUser objects directly,
        # so the stored ID already matches OidcUser.key. The delete path must use the
        # OidcUser-based ID only.
        raw = _rescoring_envelope(
            finding=_RESCORING_VULN,
            user={'username': 'alice', 'type': 'extension-user', 'issuer': 'https://example.com'},
        )
        decoded = odg.model.ArtefactMetadata.from_dict(raw)
        assert type(decoded.data.user) is odg.model.OidcUser

        dict_fallback_id = dataclasses.replace(decoded, data=raw['data']).id
        assert dict_fallback_id != decoded.id

        session = AsyncMock()
        request = MagicMock()
        request.json = AsyncMock(return_value={'entries': [copy.deepcopy(raw)]})
        request.__getitem__ = MagicMock(
            side_effect=lambda k: (
                session if k == consts.REQUEST_DB_SESSION else (_ for _ in ()).throw(KeyError(k))
            ),
        )

        with patch.object(metadata, '_collect_compliance_summary_cache_ids'):
            await metadata.ArtefactMetadata(request).delete()

        dialect = sqlalchemy.dialects.sqlite.dialect()
        delete_ids = [
            value
            for call in session.execute.await_args_list
            if call.args[0].__visit_name__ == 'delete'
            for value in call.args[0].compile(dialect=dialect).params.values()
        ]
        assert decoded.id in delete_ids
        assert dict_fallback_id not in delete_ids


class TestFromDictMetaFields:
    def test_optional_meta_fields(self):
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
        result = odg.model.ArtefactMetadata.from_dict(raw)
        assert result.meta.last_update == datetime.datetime(2025, 6, 2, 8, 0, tzinfo=_UTC)
        assert result.meta.assignee_mode is odg.model.ResponsibleAssigneeModes.EXTEND

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
        result = odg.model.ArtefactMetadata.from_dict(raw)
        assert len(result.meta.responsibles) == 1

    def test_meta_responsibles_bare_identifier_falls_back_to_base(self):
        # A stored identifier with only source+type (subtype fields absent) must not raise —
        # one legacy row in responsibles would abort a streaming metadata query.
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
            {'identifiers': [{'source': 'codeowners', 'type': 'githubUser'}]},
        ]
        result = odg.model.ArtefactMetadata.from_dict(raw)
        assert len(result.meta.responsibles) == 1
        assert isinstance(result.meta.responsibles[0].identifiers[0], odg.model.UserIdentifierBase)

    def test_unknown_meta_type_preserves_data_as_dict(self):
        result = odg.model.ArtefactMetadata.from_dict(
            _artefact_envelope('custom/unknown-type', {'key': 'my-key', 'extra': 'value'}),
        )
        assert result.data == {'key': 'my-key', 'extra': 'value'}

    def test_unknown_nested_artefact_key_does_not_raise(self):
        # dacite strict=True rejected unknown keys at every nested level; mashumaro
        # forbid_extra_keys only fires at the ArtefactMetadata envelope level — nested
        # structs (ComponentArtefactId, Metadata, finding types, etc.) silently ignore them.
        raw = _artefact_envelope(
            odg.model.Datatype.VULNERABILITY_FINDING,
            {
                'package_name': 'curl',
                'package_version': '8.0.0',
                'severity': 'LOW',
                'cve': 'CVE-2025-0001',
                'cvss_score': 5.0,
            },
        )
        raw['artefact']['bogus_nested_key'] = 'ignored'
        result = odg.model.ArtefactMetadata.from_dict(raw)
        assert result.artefact.component_name == 'example.org/component'

    def test_unknown_nested_meta_key_does_not_raise(self):
        # Same as above but for the Metadata nested struct.
        raw = _artefact_envelope(
            odg.model.Datatype.VULNERABILITY_FINDING,
            {
                'package_name': 'curl',
                'package_version': '8.0.0',
                'severity': 'LOW',
                'cve': 'CVE-2025-0001',
                'cvss_score': 5.0,
            },
        )
        raw['meta']['bogus_nested_key'] = 'ignored'
        result = odg.model.ArtefactMetadata.from_dict(raw)
        assert result.meta.datasource == 'bdba'

    def test_unknown_envelope_key_raises(self):
        # Matches dacite strict=True: unknown keys at the ArtefactMetadata envelope level raise.
        raw = _artefact_envelope(
            odg.model.Datatype.VULNERABILITY_FINDING,
            {
                'package_name': 'curl',
                'package_version': '8.0.0',
                'severity': 'LOW',
                'cve': 'CVE-2025-0001',
                'cvss_score': 5.0,
            },
        )
        raw['unexpected'] = 'bad'
        with pytest.raises(Exception):
            odg.model.ArtefactMetadata.from_dict(raw)

    def test_unknown_data_keys_do_not_raise(self):
        # Extra keys inside `data` must be silently ignored — structural union resolution
        # relies on extra fields being present to pick the more-specific BDBA subtype.
        raw = _artefact_envelope(
            odg.model.Datatype.VULNERABILITY_FINDING,
            {
                'package_name': 'curl',
                'package_version': '8.0.0',
                'severity': 'LOW',
                'cve': 'CVE-2025-0001',
                'cvss_score': 5.0,
                'base_url': 'https://bdba.example.com',
                'report_url': 'https://bdba.example.com/products/1/',
                'product_id': 1,
                'group_id': 1,
                'extra_unknown_field': 'ignored',
            },
        )
        result = odg.model.ArtefactMetadata.from_dict(raw)
        assert type(result.data) is odg.model.BDBAVulnerabilityFinding


class TestDateDecoding:
    def test_discovery_date_plain_string(self):
        result = odg.model.ArtefactMetadata.from_dict(
            _artefact_envelope(
                odg.model.Datatype.VULNERABILITY_FINDING,
                {
                    'package_name': 'curl',
                    'package_version': '8.0.0',
                    'severity': 'LOW',
                    'cve': 'CVE-1',
                    'cvss_score': 1.0,
                },
            ),
        )
        assert result.discovery_date == datetime.date(2025, 1, 1)
        assert type(result.discovery_date) is datetime.date

    @pytest.mark.parametrize(
        'raw_date',
        ('2025-01-01', '2025-01-01T10:30:00', '2025-01-01T10:30:00+00:00'),
    )
    def test_discovery_date_accepts_datetime_strings(self, raw_date):
        raw = _artefact_envelope(
            odg.model.Datatype.VULNERABILITY_FINDING,
            {
                'package_name': 'curl',
                'package_version': '8.0.0',
                'severity': 'LOW',
                'cve': 'CVE-1',
                'cvss_score': 1.0,
            },
        )
        raw['discovery_date'] = raw_date
        result = odg.model.ArtefactMetadata.from_dict(raw)
        assert result.discovery_date == datetime.date(2025, 1, 1)
        assert type(result.discovery_date) is datetime.date

    def test_rescoring_due_date(self):
        result = odg.model.ArtefactMetadata.from_dict(
            _rescoring_envelope(
                finding=_RESCORING_VULN,
                user=_GITHUB_USER,
                due_date='2024-01-15',
            ),
        )
        assert result.data.due_date == datetime.date(2024, 1, 15)
        assert type(result.data.due_date) is datetime.date


class TestEncoder:
    _UTC = datetime.timezone.utc
    _AM = odg.model.ArtefactMetadata(
        artefact=odg.model.ComponentArtefactId(
            component_name='example.org/comp',
            component_version='1.0.0',
            artefact_kind=odg.model.ArtefactKind.RESOURCE,
            artefact=odg.model.LocalArtefactId(
                artefact_name='img',
                artefact_type='ociImage',
                artefact_version='1.0.0',
                artefact_extra_id={},
            ),
        ),
        meta=odg.model.Metadata(
            datasource='bdba',
            type=odg.model.Datatype.VULNERABILITY_FINDING,
            creation_date=datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc),
        ),
        data=odg.model.VulnerabilityFinding(
            severity='HIGH',
            package_name='curl',
            package_version='8.0.0',
            cve='CVE-2025-1234',
            cvss_score=7.5,
        ),
        discovery_date=datetime.date(2025, 1, 15),
    )

    def test_basic_encoder_wire_format(self):
        # BasicEncoder is used by ArtefactMetadataQueryBySearchExpression (json_response path).
        # StrEnum values must serialise as strings (StrEnum IS str, so json.dumps handles it);
        # datetime fields must serialise as ISO strings compatible with from_dict.
        import json

        wire = json.loads(json.dumps(odg.model.artefact_metadata_basic_encoder.encode(self._AM)))
        assert wire['meta']['type'] == 'finding/vulnerability'
        assert wire['meta']['datasource'] == 'bdba'
        assert wire['artefact']['artefact_kind'] == 'resource'
        assert wire['meta']['creation_date'] == '2025-01-01T00:00:00+00:00'
        assert wire['discovery_date'] == '2025-01-15'

    def test_orjson_encoder_wire_format(self):
        # ORJSONEncoder is used by ArtefactMetadataQuery (streaming write path, returns bytes).
        import json

        wire = json.loads(odg.model.artefact_metadata_encoder.encode(self._AM))
        assert wire['meta']['type'] == 'finding/vulnerability'
        assert wire['meta']['datasource'] == 'bdba'
        assert wire['artefact']['artefact_kind'] == 'resource'
        assert wire['meta']['creation_date'] == '2025-01-01T00:00:00+00:00'
        assert wire['discovery_date'] == '2025-01-15'

    def test_encoder_decode_roundtrip(self):
        # A value encoded by BasicEncoder must decode back to an identical object via from_dict.
        import json

        wire = json.loads(json.dumps(odg.model.artefact_metadata_basic_encoder.encode(self._AM)))
        result = odg.model.ArtefactMetadata.from_dict(wire)
        assert result.meta.type == odg.model.Datatype.VULNERABILITY_FINDING
        assert result.discovery_date == datetime.date(2025, 1, 15)
        assert result.artefact.artefact_kind is odg.model.ArtefactKind.RESOURCE
        assert result.id == self._AM.id


_DIKI_ROW_WITHOUT_OPTIONALS = {
    # shape of older prod rows: `ruleset_name` and `rule_name` keys are absent
    'severity': 'HIGH',
    'provider_id': 'gardener',
    'ruleset_id': 'disa-kubernetes-stig',
    'ruleset_version': 'v1r11',
    'rule_id': '242415',
    'checks': [
        {
            'message': 'Pod uses environment to inject secret.',
            'targets': {'gcp': [{'cluster': 'seed', 'kind': 'pod', 'name': 'etcd-main-0'}]},
        },
    ],
}
_GHAS_ROW_WITHOUT_OPTIONALS = {
    # shape of older prod rows: `locations` is absent, deprecated `path`/`line` are set
    'severity': 'secret-found',
    'html_url': 'https://github.example.org/org/repo/security/secret-scanning/18',
    'secret': 'redacted',
    'secret_type': 'github_oauth_access_token',
    'secret_type_display_name': 'GitHub OAuth Access Token',
    'resolution': None,
    'path': 'github.yaml',
    'line': 28,
    'location_type': 'commit',
    'url': 'https://github.example.org/api/v3/repos/org/repo/secret-scanning/alerts/18',
}


class TestMissingOptionalKeys:
    """
    `dacite` treated an absent key of an `X | None` field as `None`; `mashumaro` only does so if the
    field has a default. Older prod rows lack such keys and must still decode to their class.
    """

    @pytest.mark.parametrize(
        ('meta_type', 'data', 'expected_type', 'none_fields'),
        [
            (
                odg.model.Datatype.DIKI_FINDING,
                _DIKI_ROW_WITHOUT_OPTIONALS,
                odg.model.DikiFinding,
                ('ruleset_name', 'rule_name'),
            ),
            (
                odg.model.Datatype.GHAS_FINDING,
                _GHAS_ROW_WITHOUT_OPTIONALS,
                odg.model.GitHubSecretFinding,
                ('locations',),
            ),
        ],
    )
    def test_prod_row_shapes_decode_to_class(self, meta_type, data, expected_type, none_fields):
        result = odg.model.ArtefactMetadata.from_dict(_artefact_envelope(meta_type, data))
        assert type(result.data) is expected_type
        for field_name in none_fields:
            assert getattr(result.data, field_name) is None


def test_vulnerability_cvss_stays_dict_when_decoded():
    # rescore.artefacts calls CVSSV3.from_dict(am.data.cvss), which needs a dict, not a CVSSV3
    cvss = {
        'access_vector': 'L',
        'attack_complexity': 'L',
        'user_interaction': 'N',
        'privileges_required': 'L',
        'scope': 'U',
        'confidentiality': 'N',
        'integrity': 'N',
        'availability': 'H',
    }
    result = odg.model.ArtefactMetadata.from_dict(
        _artefact_envelope(
            odg.model.Datatype.VULNERABILITY_FINDING,
            {
                'package_name': 'curl',
                'package_version': '8.0.0',
                'severity': 'LOW',
                'cve': 'CVE-1',
                'cvss_score': 1.0,
                'cvss': cvss,
            },
        ),
    )
    assert result.data.cvss == cvss
    assert (
        odg.cvss.CVSSV3.from_dict(cvss=result.data.cvss).access_vector is odg.cvss.AccessVector.LOCAL
    )


class TestStrictStr:
    """
    mashumaro would coerce e.g. `None` to `'None'` for `str` fields (dacite rejected it). Such rows
    must stay on the dict fallback: their stored row id is derived from the dict-fallback key.
    """

    def test_null_for_required_str_falls_back_to_dict(self):
        raw = _rescoring_envelope(
            finding={'html_url': 'https://github.example.org/org/repo/alerts/1', 'resolution': None},
            user={'username': 'ghas-extension-auto-rescoring', 'type': 'ghas-extension-user'},
            referenced_type='finding/ghas',
            severity='secret-found',
        )
        result = odg.model.ArtefactMetadata.from_dict(raw)
        assert isinstance(result.data, dict)
        assert result.data['finding']['resolution'] is None

    def test_id_of_dict_fallback_rescoring_is_stable(self):
        # id as stored in the db for such rows == id derived from the dict-fallback key
        raw = _rescoring_envelope(
            finding={'html_url': 'https://github.example.org/org/repo/alerts/1', 'resolution': None},
            user={'username': 'ghas-extension-auto-rescoring', 'type': 'ghas-extension-user'},
            referenced_type='finding/ghas',
            severity='secret-found',
        )
        decoded = odg.model.ArtefactMetadata.from_dict(raw)
        assert decoded.key.endswith('|rescorings|None')

    def test_non_str_value_for_required_str_is_rejected(self):
        raw = _artefact_envelope(
            odg.model.Datatype.VULNERABILITY_FINDING,
            {
                'package_name': 12345,
                'package_version': '1.0',
                'severity': 'LOW',
                'cve': 'CVE-1',
                'cvss_score': 1.0,
            },
        )
        assert isinstance(odg.model.ArtefactMetadata.from_dict(raw).data, dict)

    def test_null_for_optional_str_still_decodes(self):
        raw = _artefact_envelope(
            odg.model.Datatype.VULNERABILITY_FINDING,
            {
                'package_name': 'curl',
                'package_version': None,
                'severity': 'LOW',
                'cve': 'CVE-1',
                'cvss_score': 1.0,
            },
        )
        result = odg.model.ArtefactMetadata.from_dict(raw)
        assert isinstance(result.data, odg.model.VulnerabilityFinding)
        assert result.data.package_version is None
