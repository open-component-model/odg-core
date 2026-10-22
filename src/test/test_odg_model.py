import pytest
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
    'meta_type,data,expected_type',
    [
        (
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
            odg.model.BDBAVulnerabilityFinding,
        ),
        (
            odg.model.Datatype.VULNERABILITY_FINDING,
            {
                'package_name': 'curl',
                'package_version': '8.0.0',
                'severity': 'MEDIUM',
                'cve': 'CVE-2025-9999',
                'cvss_score': 5.3,
            },
            odg.model.VulnerabilityFinding,
        ),
        (
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
            odg.model.CustomRescoring,
        ),
        (
            odg.model.Datatype.ARTEFACT_SCAN_INFO,
            {'referenced_type': 'finding/vulnerability'},
            dict,
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
    ],
)
def test_from_dict_dispatch(meta_type, data, expected_type):
    am = odg.model.ArtefactMetadata.from_dict(_artefact_envelope(meta_type, data))
    assert type(am.data) is expected_type


def test_from_dict_hot_path_with_responsibles():
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
    am = odg.model.ArtefactMetadata.from_dict(raw)
    assert len(am.meta.responsibles) == 1
    assert isinstance(am.meta.responsibles[0], odg.model.UserIdentity)
    assert isinstance(am.meta.responsibles[0].identifiers[0], odg.model.GithubUser)
