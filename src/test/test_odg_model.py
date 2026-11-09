import datetime
import enum

import dacite

import odg.model
import util


def _from_dict_dacite(raw: dict) -> odg.model.ArtefactMetadata:
    return dacite.from_dict(
        data_class=odg.model.ArtefactMetadata,
        data=raw,
        config=dacite.Config(
            type_hooks={
                datetime.datetime: datetime.datetime.fromisoformat,
                datetime.date: lambda date: datetime.datetime.fromisoformat(date).date(),
            },
            cast=[
                enum.StrEnum,
                odg.model.MatchCondition,
            ],
            strict=True,
        ),
    )


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
        dacite_result = util.dict_serialisation(_from_dict_dacite(raw))
        mashumaro_result = util.dict_serialisation(odg.model.ArtefactMetadata.from_dict(raw))
        assert dacite_result == mashumaro_result

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


class TestFromDictSinglePath:
    """
    Hot-path types (VULNERABILITY_FINDING, RESCORING) must decode all Metadata and
    ArtefactMetadata fields identically to the generic decoder. A separate hand-written
    path that constructs Metadata by hand will miss newly-added fields.
    """

    def _assert_matches(self, raw: dict):
        dacite_result = util.dict_serialisation(_from_dict_dacite(raw))
        mashumaro_result = util.dict_serialisation(odg.model.ArtefactMetadata.from_dict(raw))
        assert dacite_result == mashumaro_result

    def test_vulnerability_finding_all_meta_fields(self):
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
        self._assert_matches(raw)

    def test_rescoring_all_meta_fields(self):
        raw = _artefact_envelope(
            odg.model.Datatype.RESCORING,
            {
                'finding': {'package_name': 'openssl', 'cve': 'CVE-2023-0286'},
                'referenced_type': 'finding/vulnerability',
                'severity': 'LOW',
                'user': {
                    'username': 'jdoe',
                    'type': 'github-user',
                    'github_hostname': 'github.com',
                },
            },
        )
        raw['meta']['last_update'] = '2025-07-01T12:00:00+00:00'
        raw['meta']['assignee_mode'] = 'extend'
        self._assert_matches(raw)

    def test_rescoring_generic_decoder_alone_wrong_type(self):
        """Without the RESCORING branch, the generic decoder mis-resolves to ResponsibleInfo."""
        raw = _artefact_envelope(
            odg.model.Datatype.RESCORING,
            {
                'finding': {'package_name': 'openssl', 'cve': 'CVE-2023-0286'},
                'referenced_type': 'finding/vulnerability',
                'severity': 'LOW',
                'user': {'username': 'jdoe', 'type': 'github-user', 'github_hostname': 'github.com'},
            },
        )
        import mashumaro.codecs

        generic = mashumaro.codecs.BasicDecoder(odg.model.ArtefactMetadata)
        result = generic.decode(raw)
        # The generic path hits ResponsibleInfo before CustomRescoring in the union — the
        # RESCORING branch in from_dict exists specifically to correct this.
        assert not isinstance(result.data, odg.model.CustomRescoring), (
            'If this fails, the RESCORING branch in from_dict can be removed'
        )


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
        result = odg.model.ArtefactMetadata.from_dict(raw)
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
            result = odg.model.ArtefactMetadata.from_dict(raw)
            assert type(result.data.user) is expected_type, (
                f'expected {expected_type.__name__} for type={user_raw["type"]!r}'
            )


class TestDiscoveryDateDecoding:
    def test_plain_date_string_decoded_to_date(self):
        raw = _artefact_envelope(
            odg.model.Datatype.VULNERABILITY_FINDING,
            {'package_name': 'curl', 'package_version': '8.0.0', 'severity': 'LOW', 'cve': 'CVE-1'},
        )
        result = odg.model.ArtefactMetadata.from_dict(raw)
        assert result.discovery_date == datetime.date(2025, 1, 1)
        assert isinstance(result.discovery_date, datetime.date)


class TestRescoringIPFindingDecoding:
    def test_ip_finding_with_license_preserves_labels(self):
        # IP findings with a license must decode to RescoringIPFinding, not RescoringLicenseFinding.
        raw = _artefact_envelope(
            odg.model.Datatype.RESCORING,
            {
                'finding': {
                    'package_name': 'openssl',
                    'license': {'name': 'OpenSSL'},
                    'labels': ['label-a', 'label-b'],
                },
                'referenced_type': 'finding/ip',
                'severity': 'LOW',
                'user': {'username': 'jdoe', 'type': 'github-user', 'github_hostname': 'github.com'},
            },
        )
        result = odg.model.ArtefactMetadata.from_dict(raw)
        assert isinstance(result.data, odg.model.CustomRescoring)
        assert isinstance(result.data.finding, odg.model.RescoringIPFinding)
        assert result.data.finding.labels == ['label-a', 'label-b']
        assert result.data.finding.license is not None
        assert result.data.finding.license.name == 'OpenSSL'


class TestRescoringUserUnionResolution:
    """Mashumaro and dacite must agree on user union resolution regardless of type field value."""

    def _rescoring_raw(self, user_raw: dict) -> dict:
        return _artefact_envelope(
            odg.model.Datatype.RESCORING,
            {
                'finding': {'package_name': 'openssl', 'cve': 'CVE-2023-0286'},
                'referenced_type': 'finding/vulnerability',
                'severity': 'LOW',
                'user': user_raw,
            },
        )

    def test_unknown_type_with_issuer_resolves_to_oidc_user(self):
        # issuer presence drives OidcUser selection; type value is irrelevant to both libraries.
        raw = self._rescoring_raw(
            {'username': 'alice', 'type': 'extension-user', 'issuer': 'https://example.com'},
        )
        dacite_result = _from_dict_dacite(raw)
        mashumaro_result = odg.model.ArtefactMetadata.from_dict(raw)
        assert isinstance(dacite_result.data.user, odg.model.OidcUser)
        assert isinstance(mashumaro_result.data.user, odg.model.OidcUser)
        assert dacite_result.data.user.key == mashumaro_result.data.user.key

    def test_oidc_type_without_issuer_falls_back_to_user(self):
        # Without issuer, OidcUser construction fails; both libraries fall through to User.
        raw = self._rescoring_raw({'username': 'alice', 'type': 'oidc-user'})
        dacite_result = _from_dict_dacite(raw)
        mashumaro_result = odg.model.ArtefactMetadata.from_dict(raw)
        assert type(dacite_result.data.user) is odg.model.User
        assert type(mashumaro_result.data.user) is odg.model.User
        assert dacite_result.data.user.key == mashumaro_result.data.user.key
