import pytest

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
                            'location': '/etc/ssl/cert.pem',
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
                            'location': '/etc/ssl/cert.pem',
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
                            'location': '/etc/ssl/cert.pem',
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
                            'location': '/etc/ssl/cert.pem',
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
