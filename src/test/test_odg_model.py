import datetime

import mashumaro.codecs
import pytest

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


def _rescoring_envelope(finding: dict, user: dict, **kwargs) -> dict:
    return _artefact_envelope(
        odg.model.Datatype.RESCORING,
        {
            'finding': finding,
            'referenced_type': 'finding/vulnerability',
            'severity': 'LOW',
            'user': user,
            **kwargs,
        },
    )


_GITHUB_USER = {'username': 'jdoe', 'type': 'github-user', 'github_hostname': 'github.com'}
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
        assert isinstance(result.data.cvss, odg.cvss.CVSSV3)
        assert result.data.cvss.access_vector is odg.cvss.AccessVector.NETWORK

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
    def test_bdba_user(self):
        result = odg.model.ArtefactMetadata.from_dict(
            _rescoring_envelope(
                finding=_RESCORING_VULN,
                user={
                    'username': 'jdoe',
                    'type': 'bdba-user',
                    'email': 'jdoe@example.com',
                    'firstname': 'Jane',
                    'lastname': 'Doe',
                },
            ),
        )
        assert isinstance(result.data, odg.model.CustomRescoring)
        assert result.data.severity == 'LOW'
        assert isinstance(result.data.finding, odg.model.RescoringVulnerabilityFinding)
        assert result.data.finding.package_name == 'openssl'
        assert result.data.finding.cve == 'CVE-2023-0286'
        assert type(result.data.user) is odg.model.BDBAUser
        assert result.data.user.username == 'jdoe'
        assert result.data.user.email == 'jdoe@example.com'

    def test_github_user(self):
        result = odg.model.ArtefactMetadata.from_dict(
            _rescoring_envelope(
                finding={'package_name': 'linux_kernel', 'cve': 'CVE-2024-1234'},
                user={
                    'username': 'd046309',
                    'type': 'github-user',
                    'github_hostname': 'github.wdf.sap.corp',
                },
                severity='NONE',
            ),
        )
        assert isinstance(result.data, odg.model.CustomRescoring)
        assert result.data.severity == 'NONE'
        assert type(result.data.user) is odg.model.GitHubUser
        assert result.data.user.username == 'd046309'
        assert result.data.user.github_hostname == 'github.wdf.sap.corp'

    def test_unknown_user_type_falls_back_to_user(self):
        result = odg.model.ArtefactMetadata.from_dict(
            _rescoring_envelope(
                finding=_RESCORING_VULN,
                user={'username': 'bdba-extension-auto-rescoring', 'type': 'bdba-extension-user'},
                matching_rules=['finding-update'],
            ),
        )
        assert type(result.data.user) is odg.model.User
        assert result.data.user.username == 'bdba-extension-auto-rescoring'
        assert result.data.user.type == 'bdba-extension-user'

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
        ],
    )
    def test_user_type_and_key(self, user_raw, expected_type, expected_key):
        result = odg.model.ArtefactMetadata.from_dict(
            _rescoring_envelope(finding=_RESCORING_VULN, user=user_raw),
        )
        assert type(result.data.user) is expected_type
        assert result.data.user.key == expected_key

    @pytest.mark.parametrize(
        'finding_data,expected_finding_type',
        [
            (
                {'package_name': 'openssl', 'cve': 'CVE-2023-0286'},
                odg.model.RescoringVulnerabilityFinding,
            ),
            (
                {'package_name': 'openssl', 'license': {'name': 'MIT'}, 'labels': ['a', 'b']},
                odg.model.RescoringIPFinding,
            ),
            (
                # RescoringIPFinding.labels defaults to [] so it matches even without labels;
                # matches convention (legacy dacite)
                {'package_name': 'openssl', 'license': {'name': 'MIT'}},
                odg.model.RescoringIPFinding,
            ),
            (
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
    def test_finding_type(self, finding_data, expected_finding_type):
        result = odg.model.ArtefactMetadata.from_dict(
            _rescoring_envelope(finding=finding_data, user=_GITHUB_USER),
        )
        assert isinstance(result.data, odg.model.CustomRescoring)
        assert type(result.data.finding) is expected_finding_type

    def test_ip_finding_preserves_labels(self):
        result = odg.model.ArtefactMetadata.from_dict(
            _rescoring_envelope(
                finding={
                    'package_name': 'openssl',
                    'license': {'name': 'OpenSSL'},
                    'labels': ['label-a', 'label-b'],
                },
                user=_GITHUB_USER,
            ),
        )
        assert isinstance(result.data.finding, odg.model.RescoringIPFinding)
        assert result.data.finding.labels == ['label-a', 'label-b']
        assert result.data.finding.license.name == 'OpenSSL'

    def test_generic_decoder_resolves_correctly(self):
        # BasicDecoder (no RESCORING branch) must also resolve to CustomRescoring,
        # because MetaModels lists CustomRescoring before InformationalModels.
        generic = mashumaro.codecs.BasicDecoder(odg.model.ArtefactMetadata)
        result = generic.decode(_rescoring_envelope(finding=_RESCORING_VULN, user=_GITHUB_USER))
        assert isinstance(result.data, odg.model.CustomRescoring)


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
        identity = result.meta.responsibles[0]
        assert isinstance(identity, odg.model.UserIdentity)
        assert len(identity.identifiers) == 1
        assert isinstance(identity.identifiers[0], odg.model.GithubUser)
        assert identity.identifiers[0].username == 'jdoe'

    def test_all_meta_fields_vulnerability(self):
        raw = _artefact_envelope(
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
            },
        )
        raw['meta']['last_update'] = '2025-06-01T10:00:00+00:00'
        raw['meta']['assignee_mode'] = 'extend'
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
        assert isinstance(result.data, odg.model.BDBAVulnerabilityFinding)
        assert result.data.cve == 'CVE-2023-0286'
        assert result.meta.last_update == datetime.datetime(2025, 6, 1, 10, 0, tzinfo=_UTC)
        assert result.meta.assignee_mode is odg.model.ResponsibleAssigneeModes.EXTEND
        assert len(result.meta.responsibles) == 1

    def test_all_meta_fields_rescoring(self):
        raw = _rescoring_envelope(finding=_RESCORING_VULN, user=_GITHUB_USER)
        raw['meta']['last_update'] = '2025-07-01T12:00:00+00:00'
        raw['meta']['assignee_mode'] = 'extend'
        result = odg.model.ArtefactMetadata.from_dict(raw)
        assert isinstance(result.data, odg.model.CustomRescoring)
        assert result.meta.last_update == datetime.datetime(2025, 7, 1, 12, 0, tzinfo=_UTC)
        assert result.meta.assignee_mode is odg.model.ResponsibleAssigneeModes.EXTEND

    def test_unknown_meta_type_preserves_data_as_dict(self):
        result = odg.model.ArtefactMetadata.from_dict(
            _artefact_envelope('custom/unknown-type', {'key': 'my-key', 'extra': 'value'}),
        )
        assert result.data == {'key': 'my-key', 'extra': 'value'}


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
        'date_str,expected',
        [
            ('2024-01-15', datetime.date(2024, 1, 15)),
            ('2024-01-15T00:00:00+00:00', datetime.date(2024, 1, 15)),
        ],
    )
    def test_rescoring_due_date(self, date_str, expected):
        result = odg.model.ArtefactMetadata.from_dict(
            _rescoring_envelope(finding=_RESCORING_VULN, user=_GITHUB_USER, due_date=date_str),
        )
        assert result.data.due_date == expected
        assert type(result.data.due_date) is datetime.date
