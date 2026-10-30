import copy

import pytest

import crypto_extension.config
import crypto_extension.model
import crypto_extension.validate
import odg.extensions_cfg
import odg.findings
import odg.model
import odg.shared_cfg
import paths


@pytest.fixture
def crypto_mapping() -> odg.extensions_cfg.CryptoMapping:
    return odg.extensions_cfg.CryptoMapping(
        prefix='',
        standards=[
            odg.extensions_cfg.StandardRef(
                name='FIPS',
                version='140-3',
                ref=odg.shared_cfg.SharedCfgLocalReference(path='odg/crypto_defaults.yaml'),
            ),
            odg.extensions_cfg.StandardRef(
                name='NCS',
                version='1.0',
                ref=odg.shared_cfg.SharedCfgLocalReference(path='odg/crypto_defaults.yaml'),
            ),
        ],
        libraries=[
            odg.extensions_cfg.LibrariesRef(
                ref=odg.shared_cfg.SharedCfgLocalReference(path='odg/crypto_defaults.yaml'),
            ),
        ],
        included_asset_types=None,
        aws_secret_name=None,
    )


@pytest.fixture
def crypto_finding_cfg() -> odg.findings.Finding:
    findings_cfg_path = paths.findings_cfg_path()

    return odg.findings.Finding.from_file(
        path=findings_cfg_path,
        finding_type=odg.model.Datatype.CRYPTO_FINDING,
    )


@pytest.fixture
def cbom() -> dict:
    return {
        'specVersion': '1.6',
        'components': [
            {
                'type': 'library',
                'name': 'no-crypto-library',
                'version': '0.1.0',
            },
            {
                'type': 'library',
                'name': 'golang.org/x/crypto',
                'version': 'v0.27.0',
                'properties': [
                    {
                        'name': 'syft:location:0:path',
                        'value': '/opt/docker/dockerd',
                    },
                ],
            },
            {
                'bom-ref': 'f8394d4343ecaefa',
                'type': 'cryptographic-asset',
                'name': 'ECDSA',
                'evidence': {
                    'occurrences': [
                        {
                            'location': '/opt/app/tls.crt',
                        },
                    ],
                },
                'cryptoProperties': {
                    'assetType': 'algorithm',
                    'algorithmProperties': {
                        'primitive': 'pke',
                    },
                },
            },
            {
                'bom-ref': '01ae17be396c0524',
                'type': 'cryptographic-asset',
                'name': 'ECDSA-SHA384',
                'evidence': {
                    'occurrences': [
                        {
                            'location': '/opt/app/tls.crt',
                        },
                    ],
                },
                'cryptoProperties': {
                    'assetType': 'algorithm',
                    'algorithmProperties': {
                        'primitive': 'signature',
                        'parameterSetIdentifier': '384',
                    },
                },
            },
            {
                'bom-ref': '6ca0151091803ee4',
                'type': 'cryptographic-asset',
                'name': 'ECDSA',
                'description': 'Curve: P-384',
                'evidence': {
                    'occurrences': [
                        {
                            'location': '/opt/app/tls.crt',
                        },
                    ],
                },
                'cryptoProperties': {
                    'assetType': 'related-crypto-material',
                    'relatedCryptoMaterialProperties': {
                        'type': 'public-key',
                        'algorithmRef': 'f8394d4343ecaefa',
                    },
                },
            },
            {
                'type': 'cryptographic-asset',
                'name': 'arbitrary-certificate-name',
                'evidence': {
                    'occurrences': [
                        {
                            'location': '/opt/app/tls.crt',
                        },
                    ],
                },
                'cryptoProperties': {
                    'assetType': 'certificate',
                    'certificateProperties': {
                        'subjectName': 'arbitrary-certificate-name',
                        'issuerName': 'arbitrary-certificate-name',
                        'notValidBefore': '2020-08-25T07:48:20Z',
                        'notValidAfter': '2045-08-25T23:59:59Z',
                        'signatureAlgorithmRef': '01ae17be396c0524',
                        'subjectPublicKeyRef': '6ca0151091803ee4',
                    },
                },
            },
        ],
    }


def test_crypto_validation(
    cbom: dict,
    crypto_mapping: odg.extensions_cfg.CryptoMapping,
    crypto_finding_cfg: odg.findings.Finding,
):
    crypto_assets = crypto_extension.model.iter_crypto_assets(
        cbom=cbom,
        crypto_libraries=crypto_mapping.libraries,
        included_asset_types=crypto_mapping.included_asset_types,
    )

    assert (
        len(
            [
                crypto_asset
                for crypto_asset in crypto_assets
                if crypto_asset.asset_type is odg.model.CryptoAssetTypes.LIBRARY
            ],
        )
        == 1
    )

    assert (
        len(
            [
                crypto_asset
                for crypto_asset in crypto_assets
                if crypto_asset.asset_type is odg.model.CryptoAssetTypes.ALGORITHM
            ],
        )
        == 2
    )

    assert (
        len(
            [
                crypto_asset
                for crypto_asset in crypto_assets
                if crypto_asset.asset_type is odg.model.CryptoAssetTypes.RELATED_CRYPTO_MATERIAL
            ],
        )
        == 1
    )

    assert (
        len(
            [
                crypto_asset
                for crypto_asset in crypto_assets
                if crypto_asset.asset_type is odg.model.CryptoAssetTypes.CERTIFICATE
            ],
        )
        == 1
    )

    assert (
        len(
            [
                crypto_asset
                for crypto_asset in crypto_assets
                if crypto_asset.asset_type is odg.model.CryptoAssetTypes.PROTOCOL
            ],
        )
        == 0
    )

    findings = list(
        crypto_extension.validate.iter_findings_for_standards(
            crypto_assets=crypto_assets,
            standards=crypto_mapping.standards,
            crypto_finding_cfg=crypto_finding_cfg,
        ),
    )

    assert len([finding for finding in findings if finding.standard == 'FIPS']) == 2

    assert len([finding for finding in findings if finding.standard == 'NCS']) == 3


@pytest.mark.parametrize(
    ('subject_name', 'issuer_name', 'expected'),
    [
        pytest.param(
            'COMODO ECC Certification Authority',
            'COMODO ECC Certification Authority',
            odg.model.CertificateKind.ROOT_CA,
            id='self-signed-without-root-phrase',
        ),
        pytest.param(
            'GlobalSign',
            'GlobalSign',
            odg.model.CertificateKind.ROOT_CA,
            id='self-signed-without-any-phrase',
        ),
        pytest.param(
            'R11',
            'ISRG Root X1',
            odg.model.CertificateKind.END_USER,
            id='issued-by-root',
        ),
        pytest.param(
            'Example Intermediate',
            'ISRG Root X1',
            odg.model.CertificateKind.INTERMEDIATE_CA,
            id='issued-intermediate',
        ),
        pytest.param('', '', odg.model.CertificateKind.END_USER, id='missing-subject'),
    ],
)
def test_guess_certificate_kind(
    subject_name: str,
    issuer_name: str,
    expected: odg.model.CertificateKind,
):
    assert (
        crypto_extension.model.guess_certificate_kind(
            subject_name=subject_name,
            issuer_name=issuer_name,
        )
        is expected
    )


@pytest.mark.parametrize(
    'location',
    [
        'etc/ssl/certs/ca-certificates.crt',
        '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem',
        '/usr/lib/jvm/java-21/lib/security/cacerts',
    ],
)
def test_trust_anchors_are_validated_by_public_key_only(
    cbom: dict,
    crypto_mapping: odg.extensions_cfg.CryptoMapping,
    crypto_finding_cfg: odg.findings.Finding,
    location: str,
):
    """
    The fixture certificate is valid for 25 years (NCS root CA maximum: 20) and has a P-384 key
    (allowed for NCS root CAs). Its self-signature is changed to SHA-256 (not allowed in NCS).
    """
    for component in cbom['components']:
        if evidence := component.get('evidence'):
            evidence['occurrences'] = [{'location': location}]
        if component['name'] == 'ECDSA-SHA384':
            component['name'] = 'ECDSA-SHA256'

    def iter_findings(curve: str) -> list[odg.model.CryptoFinding]:
        for component in cbom['components']:
            if component.get('description', '').startswith('Curve:'):
                component['description'] = f'Curve: {curve}'

        crypto_assets = crypto_extension.model.iter_crypto_assets(
            cbom=cbom,
            crypto_libraries=[],
            included_asset_types=None,
        )
        certificate = next(
            crypto_asset
            for crypto_asset in crypto_assets
            if crypto_asset.asset_type is odg.model.CryptoAssetTypes.CERTIFICATE
        )
        assert certificate.properties.kind is odg.model.CertificateKind.TRUST_ANCHOR

        return list(
            crypto_extension.validate.iter_findings_for_standards(
                crypto_assets=crypto_assets,
                standards=crypto_mapping.standards,
                crypto_finding_cfg=crypto_finding_cfg,
            ),
        )

    # neither the self-signature nor the validity are rated, and the algorithms (only found in the
    # trust store) are not rated standalone
    assert iter_findings(curve='P-384') == []

    # P-256 is not allowed for NCS root CAs
    findings = iter_findings(curve='P-256')
    assert [(finding.standard, finding.asset.asset_type) for finding in findings] == [
        ('NCS', odg.model.CryptoAssetTypes.CERTIFICATE),
    ]
    reasoning, _, unmet_requirements = findings[0].summary.partition('\n')
    assert reasoning == crypto_extension.validate.TRUST_ANCHOR_REASONING.replace('\n', ' ')
    assert 'validity' not in unmet_requirements
    assert 'hash' not in unmet_requirements


def test_trust_anchors_are_validated_with_rules(
    cbom: dict,
    crypto_mapping: odg.extensions_cfg.CryptoMapping,
    crypto_finding_cfg: odg.findings.Finding,
):
    for component in cbom['components']:
        if evidence := component.get('evidence'):
            evidence['occurrences'] = [{'location': 'etc/ssl/cert.pem'}]

    crypto_assets = crypto_extension.model.iter_crypto_assets(
        cbom=cbom,
        crypto_libraries=[],
        included_asset_types=None,
    )
    ncs = copy.deepcopy(
        next(standard for standard in crypto_mapping.standards if standard.name == 'NCS'),
    )
    ncs.public_key_infrastructure.certificates[0].properties.append(
        crypto_extension.config.CertificateProperties(
            kind=odg.model.CertificateKind.TRUST_ANCHOR,
            curves=None,
            key_length=None,
            validity_years=crypto_extension.config.MinMaxEnumProperties(max=5),
        ),
    )

    findings = crypto_extension.validate.iter_findings_for_standards(
        crypto_assets=crypto_assets,
        standards=[ncs],
        crypto_finding_cfg=crypto_finding_cfg,
    )

    assert [finding.asset.asset_type for finding in findings] == [
        odg.model.CryptoAssetTypes.CERTIFICATE,
    ]
