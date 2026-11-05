import odg.model
import util
import deliverydb.model as dm
import deliverydb.util as du


_BASE_META = {
    'type': 'finding/vulnerability',
    'datasource': 'bdba',
    'creation_date': '2025-01-01T00:00:00+00:00',
}

_BASE_DATA = {
    'package_name': 'openssl',
    'package_version': '3.0.0',
    'base_url': 'https://scanner.example.com',
    'report_url': 'https://scanner.example.com/products/1/',
    'product_id': 1,
    'group_id': 1,
    'severity': 'HIGH',
    'cve': 'CVE-2025-0001',
    'cvss_score': 7.5,
}

_LEGACY_DATA = {
    **_BASE_DATA,
    'cvss_score': None,
    'cvss_v3_score': 7.5,
}


def _make_artefact_metadata_row(
    data: dict | None = None,
    meta: dict | None = None,
) -> dm.ArtefactMetaData:
    return dm.ArtefactMetaData(
        type='finding/vulnerability',
        component_name='example.org/component',
        component_version='1.0.0',
        artefact_kind='resource',
        artefact_name='my-image',
        artefact_version='1.0.0',
        artefact_type='ociImage',
        artefact_extra_id={},
        artefact_extra_id_normalised='',
        data=data if data is not None else _BASE_DATA,
        meta=meta if meta is not None else _BASE_META,
        datasource='bdba',
    )


class TestDbArtefactMetadataToDict:
    def _roundtrip(self, row: dm.ArtefactMetaData) -> dict:
        """Old serialization path: build dict → parse into dataclass → serialize back."""
        return util.dict_serialisation(
            odg.model.ArtefactMetadata.from_dict(du.db_artefact_metadata_to_dict(row)),
        )

    def test_cvss_score_backfilled_from_cvss_v3_score(self):
        # Legacy BDBA rows store only cvss_v3_score; the raw-dict path must backfill cvss_score
        # so it is consistent with the dataclass path (BDBAVulnerabilityFinding.__post_init__).
        row = _make_artefact_metadata_row(data=_LEGACY_DATA)

        result = du.db_artefact_metadata_to_dict(row)

        assert result['data']['cvss_score'] == self._roundtrip(row)['data']['cvss_score']

    def test_cvss_score_not_overwritten_when_present(self):
        row = _make_artefact_metadata_row(data={**_BASE_DATA, 'cvss_v3_score': 9.0})

        result = du.db_artefact_metadata_to_dict(row)

        assert result['data']['cvss_score'] == self._roundtrip(row)['data']['cvss_score']

    def test_meta_matches_roundtrip(self):
        # db_artefact_metadata_to_dict must emit the same meta shape as the old roundtrip,
        # including keys that may be absent from the stored JSONB (responsibles, assignee_mode,
        # last_update).
        row = _make_artefact_metadata_row()

        result = du.db_artefact_metadata_to_dict(row)

        assert result['meta'] == self._roundtrip(row)['meta']
