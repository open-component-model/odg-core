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
                'evidence': {
                    'occurrences': [
                        {
                            'location': '/opt/app/tls.crt',
                        },
                    ],
                },
                'cryptoProperties': {
                    'assetType': 'related-crypto-material',
                    # current cbomkit-theia only reports the key itself (here: P-384, taken from
                    # "Amazon Root CA 4"), no curve or size
                    'relatedCryptoMaterialProperties': {
                        'type': 'public-key',
                        'algorithmRef': 'f8394d4343ecaefa',
                        'value': (
                            'MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE0quKN0+jUw3+wYp7S6h7RktjsGL2LRvbCHEh0gDo'
                            'Y72aJ/vwOW5d6j2lyYGqo1sgmEVdFtv96BBt45zg471fhGLzcGQzoMskL3C6iKEqoHX4ga5i'
                            'BsSB2zluKbAe+i5c'
                        ),
                        'format': 'PEM',
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

    # the certificate's key algorithm (ECDSA) is validated as part of the certificate only, as it
    # carries neither hash function nor curve by itself
    assert sorted(
        (finding.standard, finding.asset.asset_type, finding.asset.names[0]) for finding in findings
    ) == [
        ('FIPS', odg.model.CryptoAssetTypes.LIBRARY, 'golang.org/x/crypto'),
        ('NCS', odg.model.CryptoAssetTypes.CERTIFICATE, 'arbitrary-certificate-name'),
        ('NCS', odg.model.CryptoAssetTypes.LIBRARY, 'golang.org/x/crypto'),
    ]


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
    ('value', 'expected'),
    [
        pytest.param(
            'MFIwEAYHKoZIzj0CAQYFK4EEABoDPgAEAJozj2lWe9hsDAC+8VGA3oG/+Qh8Y7tkvR0oAIcoAMoVqft5KQaaIiOE'
            '1hgJkwXu9sqX8ANNGKypoWwR',
            ('K-233', 233),
            id='binary-curve-unsupported-by-cryptography',
        ),
        pytest.param(
            '-----BEGIN PUBLIC KEY-----\n'
            'MIGnMBAGByqGSM49AgEGBSuBBAAnA4GSAAQGQuhzWJV564Vj3U2mY+oKwvUd0CLh\n'
            'H0PtWgX3ODg52cQaigO27qiiAQ3CHrkzyZvekPsGgv4fjZVCKpAbkecJFeRjsKkS\n'
            'mN8D9ESF2sqhNciIjvkolPHRpLFA63eOoRR61Pisa5wuQGCyZ1v7VKvuCc9UfA+1\n'
            '5YVjd8rz8q5mfsmxz9O2OTvO6lfbV9EyixA=\n'
            '-----END PUBLIC KEY-----\n',
            ('B-571', 571),
            id='pem-long-form-length',
        ),
        pytest.param(
            'MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAvlsW2HTNBHEyWqBTLySTIOO8he3UOe3zxSgsF+xRCzsP'
            's4lyR6ghgBBoQV4O/U8DzYB+FDSPsZ+nsXCUt3yLu02x/ZNFDaDyz+yIwODacCkepxZ9l9j7jR8ECAcyWDW+fQun'
            'Afq2VVlxidde9tnS4NfHFlOLqTIhdXjt5REAjv5fkCbcwUxlvL2Z+j6oFGCnSRnxXBlQsCk3315O/XqzU77qktXb'
            'nbN6BX/kxCxO/XbGXJW8FCEtUuT3LreZY2pCgA0wMI8UWH1/GHo7e96gh78QVB9nvKzQY0+F+Q0rrOC5ZdYWVY0F'
            'ZtJwy2XFtNm3wU58x2IyJcVQDhMJ2CToyJn0wS4QYVDaYC0BEB4dtqgckuuLS69xcaYAWFgrfz+lYgkieBkjdmAc'
            'zhzs23L79aDO+DbXG52zSaiISeKJ+Pzi9oFZQKwYzoDkZEIaxQns56s++nvEWzMTJQs77VkGQicK1BxeTSfonTrU'
            '2TgkbmfHNkPYnXhUroPxvwubYVg7AgMBAAE=',
            (None, 3072),
            id='rsa-3072',
        ),
        pytest.param(
            'MFowFAYHKoZIzj0CAQYJKyQDAwIIAQEHA0IABJ06UDB+dxE78jOkWRvRguolrGNnVenTEIKpy9UABBd3jM68nO4S'
            'BIzzvG2uT3BgcQydfxCuv7NfgkNeDWdxGRY=',
            ('1.3.36.3.3.2.8.1.1.7', None),
            id='unmapped-curve-reported-by-oid',
        ),
        pytest.param(
            'MIIBSzCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAAAAAAAAAAAAAA////////////'
            '////MFsEIP////8AAAABAAAAAAAAAAAAAAAA///////////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7'
            'zjw+J9JgSwMVAMSdNgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP'
            '40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVR'
            'AgEBA0IABJrbZ7NGMe4FrW0ccvN2RbaRaxZc/WT/KPswz4kOfLTwgc8tKSBVG6/PBPQ9qTjhh5jFp+alFLKdM0g1'
            'Up9iu9Q=',
            (None, None),
            id='explicit-curve-parameters',
        ),
        pytest.param('MFIwEAYHKoZIzj0CAQYFK4EE', (None, None), id='truncated'),
        pytest.param('not base64!', (None, None), id='invalid-base64'),
    ],
)
def test_public_key_curve_and_size(
    value: str,
    expected: tuple[str | None, int | None],
):
    assert crypto_extension.model.public_key_curve_and_size(value) == expected


def go_binary_components(
    path: str,
    crypto_settings: list[str],
) -> list[dict]:
    """
    Mirrors the syft output for a Go binary: crypto settings are only recorded on the component of
    the main module, not on the `stdlib` component containing the Go Cryptographic Module.
    """
    location_property = {'name': 'syft:location:0:path', 'value': path}

    return [
        {
            'type': 'library',
            'name': 'stdlib',
            'version': 'go1.27.1',
            'purl': 'pkg:golang/stdlib@1.27.1',
            'properties': [location_property],
        },
        {
            'type': 'library',
            'name': 'example.org/main',
            'version': 'UNKNOWN',
            'purl': 'pkg:golang/example.org/main',
            'properties': [
                location_property,
                *(
                    {'name': f'syft:metadata:goCryptoSettings:{idx}', 'value': crypto_setting}
                    for idx, crypto_setting in enumerate(crypto_settings)
                ),
            ],
        },
    ]


def test_go_fips140_module_validation(
    crypto_mapping: odg.extensions_cfg.CryptoMapping,
    crypto_finding_cfg: odg.findings.Finding,
):
    crypto_settings_by_path = {
        '/certified': ['GODEBUG=fips140=on', 'GOFIPS140=v1.0.0-c2097c7c'],
        '/certified-mode-off': ['GODEBUG=fips140=off', 'GOFIPS140=v1.0.0-c2097c7c'],
        '/godebug-only': ['GODEBUG=fips140=on'],
        '/in-process': ['GODEBUG=fips140=on', 'GOFIPS140=v1.26.0'],
        '/latest': ['GODEBUG=fips140=on', 'GOFIPS140=latest'],
        '/plain': [],
    }
    cbom = {
        'specVersion': '1.6',
        'components': [
            *(
                component
                for path, crypto_settings in crypto_settings_by_path.items()
                for component in go_binary_components(path, crypto_settings)
            ),
            # not the Go standard library, hence not rated (absent from the findings below)
            {
                'type': 'library',
                'name': 'stdlib',
                'version': '1.0.0',
                'purl': 'pkg:cargo/stdlib@1.0.0',
                'properties': [{'name': 'syft:location:0:path', 'value': '/non-go'}],
            },
        ],
    }
    fips = next(standard for standard in crypto_mapping.standards if standard.name == 'FIPS')

    def severity_by_path(
        standard: crypto_extension.config.Standard,
    ) -> dict[str, str]:
        crypto_assets = crypto_extension.model.iter_crypto_assets(
            cbom=cbom,
            crypto_libraries=crypto_mapping.libraries,
            included_asset_types=None,
        )
        findings = crypto_extension.validate.iter_findings_for_standards(
            crypto_assets=crypto_assets,
            standards=[standard],
            crypto_finding_cfg=crypto_finding_cfg,
        )
        return {
            location: finding.severity
            for finding in findings
            for location in finding.asset.locations
        }

    assert severity_by_path(fips) == {
        '/certified': 'compliant',
        '/certified-mode-off': 'not-standard-compliant',
        '/godebug-only': 'not-standard-compliant',
        '/in-process': 'not-standard-compliant',
        '/latest': 'not-standard-compliant',
        '/plain': 'not-standard-compliant',
    }

    # newly certified module versions are accepted once added to the standard
    fips_v1_26_certified = copy.deepcopy(fips)
    stdlib = next(
        library
        for library in fips_v1_26_certified.libraries.validated_crypto_libraries
        if library.name == 'stdlib'
    )
    stdlib.go_fips140_modules.append('v1.26.0')

    assert severity_by_path(fips_v1_26_certified)['/in-process'] == 'compliant'


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

    p384_public_key = next(
        component['cryptoProperties']['relatedCryptoMaterialProperties']['value']
        for component in cbom['components']
        if 'relatedCryptoMaterialProperties' in component.get('cryptoProperties', {})
    )
    p256_public_key = (
        'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEB9/oo+1sUmR1msJwmaZ4hSQXc06pEr0lbR7uRKGWFPOc1kIykO9p'
        'zAB6nCdl9BFjPEW06QEJYwjbO7zT0H37xA=='
    )

    def iter_findings(public_key: str) -> list[odg.model.CryptoFinding]:
        for component in cbom['components']:
            crypto_properties = component.get('cryptoProperties', {})
            if related_crypto_material := crypto_properties.get('relatedCryptoMaterialProperties'):
                related_crypto_material['value'] = public_key

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
    assert iter_findings(public_key=p384_public_key) == []

    # P-256 is not allowed for NCS root CAs
    findings = iter_findings(public_key=p256_public_key)
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
