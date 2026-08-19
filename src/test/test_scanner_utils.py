import unittest.mock

import ocm
import ocm.iter
import pytest

import consts
import odg.findings
import odg.labels
import odg.model
import scanner_utils.cyclonedx
import scanner_utils.findings
import scanner_utils.rescore

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_resource_node(
    component_name: str = 'example.org/test',
    version: str = '1.0.0',
) -> ocm.iter.ResourceNode:
    component = ocm.Component(
        name=component_name,
        version=version,
        repositoryContexts=[],
        provider='test',
        sources=[],
        componentReferences=[],
        resources=[],
    )
    resource = ocm.Resource(
        name='test-image',
        version=version,
        type=ocm.ArtefactType.OCI_IMAGE,
        access=None,
    )
    return ocm.iter.ResourceNode(
        path=(ocm.iter.NodePathEntry(component=component),),
        resource=resource,
    )


def _make_component_and_resource(
    resource_label: ocm.Label | None = None,
    component_label: ocm.Label | None = None,
):
    resource = ocm.Resource(
        name='test-resource',
        version='1.0.0',
        type='ociImage',
        access=None,
        labels=[resource_label] if resource_label else [],
    )
    component = ocm.Component(
        name='test-component',
        version='1.0.0',
        repositoryContexts=[],
        provider='test',
        sources=[],
        componentReferences=[],
        resources=[resource],
        labels=[component_label] if component_label else [],
    )
    return component, resource


def _collect_package_version_overwrites(component, resource, delivery_service_writebacks=()):
    delivery_service_client = unittest.mock.Mock()
    with (
        unittest.mock.patch('odg.model.component_artefact_id_from_ocm'),
        unittest.mock.patch(
            'odg.util.iter_scanner_writebacks',
            return_value=iter(delivery_service_writebacks),
        ),
    ):
        return list(
            scanner_utils.findings.iter_package_version_overwrites(
                component=component,
                resource=resource,
                delivery_service_client=delivery_service_client,
            ),
        )


def _make_pkg_version_hint_label(entries: list[dict]) -> ocm.Label:
    return ocm.Label(
        name=odg.labels.PackageVersionHintLabel.name,
        value=entries,
    )


_CVE_CATEGORISATION_VALUE = {
    'network_exposure': 'public',
    'authentication_enforced': True,
    'user_interaction': 'operator',
    'confidentiality_requirement': 'high',
    'integrity_requirement': 'high',
    'availability_requirement': 'low',
    'comment': None,
}

# ---------------------------------------------------------------------------
# Tests — findings
# ---------------------------------------------------------------------------


class TestDeleteStaleFindings:
    def _make_finding(
        self,
        cve: str = 'CVE-2024-0001',
        package_name: str = 'pkg',
        component_version: str | None = None,
    ) -> odg.model.ArtefactMetadata:
        return odg.model.ArtefactMetadata(
            artefact=odg.model.ComponentArtefactId(
                component_name='example.org/test',
                component_version=component_version,
            ),
            meta=odg.model.Metadata(
                datasource=odg.model.Datasource.BDBA,
                type=odg.model.Datatype.VULNERABILITY_FINDING,
            ),
            data=odg.model.VulnerabilityFinding(
                severity='MEDIUM',
                package_name=package_name,
                package_version='1.0',
                cve=cve,
                cvss_score=5.0,
            ),
        )

    def test_deletes_finding_absent_from_current_scan(self):
        stale = self._make_finding(cve='CVE-2024-0001')
        live = self._make_finding(cve='CVE-2024-0002')
        existing = {stale.key: stale, live.key: live}
        client = unittest.mock.Mock()

        scanner_utils.findings.delete_stale_findings(existing, [live], client)

        client.delete_metadata.assert_called_once_with(data=[stale])

    def test_no_deletion_when_all_findings_still_present(self):
        am = self._make_finding()
        existing = {am.key: am}
        client = unittest.mock.Mock()

        scanner_utils.findings.delete_stale_findings(existing, [am], client)

        client.delete_metadata.assert_not_called()

    def test_no_deletion_when_both_sets_empty(self):
        client = unittest.mock.Mock()

        scanner_utils.findings.delete_stale_findings({}, [], client)

        client.delete_metadata.assert_not_called()

    def test_deletes_all_when_current_scan_empty(self):
        am1 = self._make_finding(cve='CVE-2024-0001')
        am2 = self._make_finding(cve='CVE-2024-0002')
        existing = {am1.key: am1, am2.key: am2}
        client = unittest.mock.Mock()

        scanner_utils.findings.delete_stale_findings(existing, [], client)

        client.delete_metadata.assert_called_once()
        deleted = client.delete_metadata.call_args.kwargs['data']
        assert set(am.key for am in deleted) == {am1.key, am2.key}

    def test_component_version_difference_does_not_cause_false_stale(self):
        # Existing findings are stored without component_version (None); current findings
        # may be built with a component_version set. The comparison must ignore this difference
        # and match on (type, data.key) only — otherwise all findings are incorrectly deleted.
        existing_am = self._make_finding(cve='CVE-2024-0001', component_version=None)
        current_am = self._make_finding(cve='CVE-2024-0001', component_version='1.0.0')
        existing = {existing_am.key: existing_am}
        client = unittest.mock.Mock()

        scanner_utils.findings.delete_stale_findings(existing, [current_am], client)

        client.delete_metadata.assert_not_called()


class TestIterExistingFindings:
    def _raw_finding_dict(self, datasource: str = 'bdba') -> dict:
        return {
            'artefact': {
                'component_name': 'example.org/test',
                'component_version': None,
                'artefact': {
                    'artefact_name': 'test-image',
                    'artefact_type': 'ociImage',
                    'artefact_version': '1.0.0',
                },
                'artefact_kind': 'resource',
            },
            'meta': {
                'datasource': datasource,
                'type': 'finding/vulnerability',
                'creation_date': '2025-01-01T00:00:00+00:00',
            },
            'data': {
                'severity': 'MEDIUM',
                'package_name': 'pkg',
                'package_version': '1.0',
                'cve': 'CVE-2024-0001',
                'cvss_score': 5.0,
            },
            'discovery_date': '2025-01-01',
            'allowed_processing_time': '30d',
        }

    def test_queries_delivery_client_with_correct_args(self):
        node = _make_resource_node()
        client = unittest.mock.Mock()
        client.query_metadata.return_value = []

        list(
            scanner_utils.findings.iter_existing_findings(
                delivery_service_client=client,
                resource_node=node,
                finding_type=odg.model.Datatype.VULNERABILITY_FINDING,
                datasource=odg.model.Datasource.BDBA,
            ),
        )

        client.query_metadata.assert_called_once()
        kwargs = client.query_metadata.call_args.kwargs
        assert kwargs['datasource'] == odg.model.Datasource.BDBA
        assert kwargs['type'] == odg.model.Datatype.VULNERABILITY_FINDING

    def test_deserialises_returned_findings(self):
        node = _make_resource_node()
        client = unittest.mock.Mock()
        client.query_metadata.return_value = [self._raw_finding_dict()]

        results = list(
            scanner_utils.findings.iter_existing_findings(
                delivery_service_client=client,
                resource_node=node,
                finding_type=odg.model.Datatype.VULNERABILITY_FINDING,
                datasource=odg.model.Datasource.BDBA,
            ),
        )

        assert len(results) == 1
        assert isinstance(results[0], odg.model.ArtefactMetadata)
        assert isinstance(results[0].data, odg.model.VulnerabilityFinding)
        assert results[0].data.cve == 'CVE-2024-0001'

    def test_accepts_tuple_of_finding_types(self):
        node = _make_resource_node()
        client = unittest.mock.Mock()
        client.query_metadata.return_value = []

        list(
            scanner_utils.findings.iter_existing_findings(
                delivery_service_client=client,
                resource_node=node,
                finding_type=(
                    odg.model.Datatype.VULNERABILITY_FINDING,
                    odg.model.Datatype.LICENSE_FINDING,
                ),
                datasource=odg.model.Datasource.BDBA,
            ),
        )

        kwargs = client.query_metadata.call_args.kwargs
        assert kwargs['type'] == (
            odg.model.Datatype.VULNERABILITY_FINDING,
            odg.model.Datatype.LICENSE_FINDING,
        )

    def test_empty_results_from_delivery_client(self):
        node = _make_resource_node()
        client = unittest.mock.Mock()
        client.query_metadata.return_value = []

        results = list(
            scanner_utils.findings.iter_existing_findings(
                delivery_service_client=client,
                resource_node=node,
                finding_type=odg.model.Datatype.VULNERABILITY_FINDING,
                datasource=odg.model.Datasource.BDBA,
            ),
        )

        assert results == []


class TestMakeArtefactScanInfo:
    def test_returns_artefact_scan_info_with_correct_meta(self):
        node = _make_resource_node()

        am = scanner_utils.findings.make_artefact_scan_info(
            resource_node=node,
            datasource=odg.model.Datasource.BDBA,
        )

        assert am.meta.type == odg.model.Datatype.ARTEFACT_SCAN_INFO
        assert am.meta.datasource == odg.model.Datasource.BDBA

    def test_artefact_fields_match_resource_node(self):
        node = _make_resource_node(component_name='my.org/comp', version='2.3.4')

        am = scanner_utils.findings.make_artefact_scan_info(
            resource_node=node,
            datasource=odg.model.Datasource.CLAMAV,
        )

        assert am.artefact.component_name == 'my.org/comp'
        assert am.artefact.component_version == '2.3.4'
        assert am.meta.datasource == odg.model.Datasource.CLAMAV

    def test_different_datasources_produce_different_keys(self):
        node = _make_resource_node()

        bdba = scanner_utils.findings.make_artefact_scan_info(node, odg.model.Datasource.BDBA)
        clamav = scanner_utils.findings.make_artefact_scan_info(node, odg.model.Datasource.CLAMAV)

        assert bdba.meta.datasource != clamav.meta.datasource
        assert bdba.key != clamav.key


class TestBDBAVulnerabilityFindingUrls:
    def test_report_url_added_to_urls_on_construction(self):
        finding = odg.model.BDBAVulnerabilityFinding(
            severity='MEDIUM',
            package_name='pkg',
            package_version='1.0',
            cve='CVE-2024-0001',
            cvss_score=5.0,
            base_url='https://bdba.example',
            report_url='https://bdba.example/report/42',
            product_id=42,
            group_id=7,
        )

        assert any('bdba.example/report/42' in u for u in finding.urls)
        assert any('nvd.nist.gov' in u for u in finding.urls)

    def test_report_url_not_duplicated_when_already_present(self):
        bdba_link = '[BDBA 42](https://bdba.example/report/42)'
        finding = odg.model.BDBAVulnerabilityFinding(
            severity='MEDIUM',
            package_name='pkg',
            package_version='1.0',
            cve='CVE-2024-0001',
            cvss_score=5.0,
            base_url='https://bdba.example',
            report_url='https://bdba.example/report/42',
            product_id=42,
            group_id=7,
            urls=[bdba_link],
        )

        assert finding.urls.count(bdba_link) == 1

    def test_urls_not_part_of_finding_key(self):
        # Ensures that adding the BDBA link to urls on deserialization does not change the key,
        # preventing accidental key drift between old and new DB records.
        base_kwargs = dict(
            severity='MEDIUM',
            package_name='pkg',
            package_version='1.0',
            cve='CVE-2024-0001',
            cvss_score=5.0,
            base_url='https://bdba.example',
            report_url='https://bdba.example/report/42',
            product_id=42,
            group_id=7,
        )
        without_extra_url = odg.model.BDBAVulnerabilityFinding(**base_kwargs)
        with_extra_url = odg.model.BDBAVulnerabilityFinding(
            **base_kwargs,
            urls=['https://extra.example'],
        )

        assert without_extra_url.key == with_extra_url.key


class TestIterPackageVersionOverwrites:
    def test_from_resource_label(self):
        label = ocm.Label(
            name='cloud.gardener.cnudie/dso/scanning-hints/package-versions',
            value=[{'name': 'openssl', 'version': '3.0.1'}],
        )
        component, resource = _make_component_and_resource(resource_label=label)
        results = _collect_package_version_overwrites(component, resource)
        assert len(results) == 1
        assert results[0].package_name == 'openssl'
        assert results[0].package_version_to == '3.0.1'

    def test_from_component_label_fallback(self):
        label = ocm.Label(
            name='cloud.gardener.cnudie/dso/scanning-hints/package-versions',
            value=[{'name': 'zlib', 'version': '1.2.11'}],
        )
        component, resource = _make_component_and_resource(component_label=label)
        results = _collect_package_version_overwrites(component, resource)
        assert len(results) == 1
        assert results[0].package_name == 'zlib'
        assert results[0].package_version_to == '1.2.11'

    def test_resource_label_takes_precedence_over_component_label(self):
        resource_label = ocm.Label(
            name='cloud.gardener.cnudie/dso/scanning-hints/package-versions',
            value=[{'name': 'openssl', 'version': '3.0.1'}],
        )
        component_label = ocm.Label(
            name='cloud.gardener.cnudie/dso/scanning-hints/package-versions',
            value=[{'name': 'zlib', 'version': '1.2.11'}],
        )
        component, resource = _make_component_and_resource(
            resource_label=resource_label,
            component_label=component_label,
        )
        results = _collect_package_version_overwrites(component, resource)
        assert len(results) == 1
        assert results[0].package_name == 'openssl'

    def test_no_label_returns_empty(self):
        component, resource = _make_component_and_resource()
        results = _collect_package_version_overwrites(component, resource)
        assert results == []

    def test_multiple_hints_in_label(self):
        label = _make_pkg_version_hint_label(
            [
                {'name': 'openssl', 'version': '3.0.1'},
                {'name': 'zlib', 'version': '1.2.13'},
            ],
        )
        component, resource = _make_component_and_resource(resource_label=label)
        results = _collect_package_version_overwrites(component, resource)
        assert len(results) == 2
        assert {r.package_name for r in results} == {'openssl', 'zlib'}

    def test_hint_missing_name_is_skipped(self):
        label = _make_pkg_version_hint_label(
            [
                {'version': '3.0.1'},
                {'name': 'zlib', 'version': '1.2.13'},
            ],
        )
        component, resource = _make_component_and_resource(resource_label=label)
        results = _collect_package_version_overwrites(component, resource)
        assert len(results) == 1
        assert results[0].package_name == 'zlib'

    def test_hint_missing_version_is_skipped(self):
        label = _make_pkg_version_hint_label(
            [
                {'name': 'openssl'},
                {'name': 'zlib', 'version': '1.2.13'},
            ],
        )
        component, resource = _make_component_and_resource(resource_label=label)
        results = _collect_package_version_overwrites(component, resource)
        assert len(results) == 1
        assert results[0].package_name == 'zlib'

    def test_delivery_service_writebacks_are_included(self):
        component, resource = _make_component_and_resource()
        writeback = odg.model.PackageVersionScannerWriteback(
            package_name='curl',
            package_version_from=None,
            package_version_to='8.0.0',
        )
        results = _collect_package_version_overwrites(component, resource, [writeback])
        assert len(results) == 1
        assert results[0].package_name == 'curl'

    def test_delivery_service_writebacks_combined_with_label_hints(self):
        label = _make_pkg_version_hint_label([{'name': 'openssl', 'version': '3.0.1'}])
        component, resource = _make_component_and_resource(resource_label=label)
        writeback = odg.model.PackageVersionScannerWriteback(
            package_name='curl',
            package_version_from=None,
            package_version_to='8.0.0',
        )
        results = _collect_package_version_overwrites(component, resource, [writeback])
        assert {r.package_name for r in results} == {'curl', 'openssl'}

    def test_package_version_from_is_none_for_label_hints(self):
        label = _make_pkg_version_hint_label([{'name': 'openssl', 'version': '3.0.1'}])
        component, resource = _make_component_and_resource(resource_label=label)
        results = _collect_package_version_overwrites(component, resource)
        assert results[0].package_version_from is None


# ---------------------------------------------------------------------------
# Tests — rescore
# ---------------------------------------------------------------------------

_VULNERABILITY_CFG_RAW = [
    {
        'type': odg.model.Datatype.VULNERABILITY_FINDING,
        'categorisations': [
            {'id': 'NONE', 'display_name': 'NONE', 'value': 0},
            {
                'id': 'MEDIUM',
                'display_name': 'MEDIUM',
                'value': 2,
                'allowed_processing_time': 90,
                'rescoring': 'automatic',
                'selector': {'cve_score_range': {'min': 4.0, 'max': 6.9}},
            },
        ],
        'rescoring_ruleset': {
            'name': 'test-ruleset',
            'operations': {
                'not-exploitable': f'{consts.RESCORING_OPERATOR_SET_TO_PREFIX}NONE',
            },
            'rules': [
                {
                    'category_value': 'network_exposure:public',
                    'name': 'local-only',
                    'rules': [
                        {'cve_values': ['AV:L'], 'operation': 'not-exploitable'},
                    ],
                },
            ],
        },
    },
]


@pytest.fixture
def vulnerability_cfg() -> odg.findings.Finding:
    return odg.findings.Finding.from_dict(
        findings_raw=_VULNERABILITY_CFG_RAW,
        finding_type=odg.model.Datatype.VULNERABILITY_FINDING,
    )


@pytest.fixture
def cve_categorisation():
    label = ocm.Label(
        name='security.ocm.software/risk-profile',
        value=_CVE_CATEGORISATION_VALUE,
    )
    return odg.labels.deserialise_label(label).value


class TestComputeAutoTriageCves:
    _LOCAL_CVSS = 'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'

    def _vuln(
        self,
        cve: str,
        cvss_vector: str = _LOCAL_CVSS,
        cvss_score: float = 5.0,
        is_skippable: bool = False,
        is_already_triaged: bool = False,
    ) -> scanner_utils.rescore.VulnerabilityCandidate:
        return scanner_utils.rescore.VulnerabilityCandidate(
            cve=cve,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            is_skippable=is_skippable,
            is_already_triaged=is_already_triaged,
        )

    def _compute(self, candidates, vulnerability_cfg, cve_categorisation, version='3.0.1'):
        return scanner_utils.rescore.compute_auto_triage_cves(
            component_name='openssl',
            component_version=version,
            vulnerabilities=candidates,
            vulnerability_cfg=vulnerability_cfg,
            cve_categorisation=cve_categorisation,
        )

    def test_skippable_is_not_triaged(self, vulnerability_cfg, cve_categorisation):
        result = self._compute(
            [self._vuln('CVE-2024-0001', is_skippable=True)],
            vulnerability_cfg,
            cve_categorisation,
        )
        assert result == []

    def test_already_triaged_is_not_triaged_again(self, vulnerability_cfg, cve_categorisation):
        result = self._compute(
            [self._vuln('CVE-2024-0001', is_already_triaged=True)],
            vulnerability_cfg,
            cve_categorisation,
        )
        assert result == []

    def test_no_component_version_returns_empty(self, vulnerability_cfg, cve_categorisation):
        result = self._compute(
            [self._vuln('CVE-2024-0001')],
            vulnerability_cfg,
            cve_categorisation,
            version=None,
        )
        assert result == []

    def test_empty_candidates_returns_empty(self, vulnerability_cfg, cve_categorisation):
        result = self._compute([], vulnerability_cfg, cve_categorisation)
        assert result == []

    def test_no_cvss_vector_does_not_raise(self, vulnerability_cfg, cve_categorisation):
        # A non-skippable candidate with cvss_vector=None must be silently skipped
        # without attempting CVSSV3.parse (which would crash on None).
        result = self._compute(
            [self._vuln('CVE-2024-0001', cvss_vector=None, cvss_score=5.0)],
            vulnerability_cfg,
            cve_categorisation,
        )
        assert result == []

    def test_invalid_cvss_vector_does_not_raise(self, vulnerability_cfg, cve_categorisation):
        # A malformed vector string must be caught and the candidate skipped without crashing.
        result = self._compute(
            [self._vuln('CVE-2024-0001', cvss_vector='not-a-valid-vector', cvss_score=5.0)],
            vulnerability_cfg,
            cve_categorisation,
        )
        assert result == []

    def test_only_matching_cves_are_returned(self, vulnerability_cfg, cve_categorisation):
        network_cvss = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
        result = self._compute(
            [
                self._vuln('CVE-2024-0001', cvss_vector=self._LOCAL_CVSS),  # matches → triaged
                self._vuln('CVE-2024-0002', cvss_vector=network_cvss),  # no match → kept
            ],
            vulnerability_cfg,
            cve_categorisation,
        )
        assert result == ['CVE-2024-0001']


# ---------------------------------------------------------------------------
# Tests — cyclonedx
# ---------------------------------------------------------------------------


class TestIterVulnerabilityFindings:
    @staticmethod
    def _make_cyclonedx(
        *,
        cve: str = 'CVE-2025-9999',
        score: float | None = 5.3,
        severity: str = 'medium',
        vector: str | None = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
        source: str = 'NVD',
        pkg_name: str = 'curl',
        pkg_version: str = '8.0.0',
        purl: str = 'pkg:apk/alpine/curl@8.0.0',
        description: str | None = None,
        recommendation: str | None = None,
        advisory_urls: list[str] = (),
        extra_components: list[dict] = (),
        extra_affects: list[dict] = (),
    ) -> dict:
        ref = purl or pkg_name
        rating: dict = {'source': {'name': source}, 'severity': severity, 'method': 'CVSSv31'}
        if score is not None:
            rating['score'] = score
        if vector is not None:
            rating['vector'] = vector
        vuln: dict = {
            'id': cve,
            'ratings': [rating],
            'affects': [{'ref': ref}, *extra_affects],
        }
        if description is not None:
            vuln['description'] = description
        if recommendation is not None:
            vuln['recommendation'] = recommendation
        if advisory_urls:
            vuln['advisories'] = [{'url': u} for u in advisory_urls]
        return {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.5',
            'components': [
                {'bom-ref': ref, 'name': pkg_name, 'version': pkg_version, 'purl': purl},
                *extra_components,
            ],
            'vulnerabilities': [vuln],
        }

    def test_basic_finding_fields(self, vulnerability_cfg):
        findings = list(
            scanner_utils.cyclonedx.iter_vulnerability_findings(
                self._make_cyclonedx(
                    description='A test vulnerability',
                    recommendation='Update to 8.1.0',
                    advisory_urls=['https://example.com/advisory'],
                ),
                vulnerability_cfg,
            ),
        )
        assert len(findings) == 1
        f = findings[0]
        assert f.cve == 'CVE-2025-9999'
        assert f.package_name == 'curl'
        assert f.package_version == '8.0.0'
        assert f.purl == 'pkg:apk/alpine/curl@8.0.0'
        assert f.cvss_score == 5.3
        assert f.rating_source == 'NVD'
        assert f.summary == 'A test vulnerability'
        assert f.recommendation == 'Update to 8.1.0'
        assert 'https://example.com/advisory' in f.urls

    def test_cvss_vector_parsed(self, vulnerability_cfg):
        findings = list(
            scanner_utils.cyclonedx.iter_vulnerability_findings(
                self._make_cyclonedx(),
                vulnerability_cfg,
            ),
        )
        assert findings[0].cvss is not None

    def test_nvd_preferred_over_ghsa(self, vulnerability_cfg):
        ref = 'pkg:npm/lodash@4.17.20'
        doc = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.5',
            'components': [{'bom-ref': ref, 'name': 'lodash', 'version': '4.17.20'}],
            'vulnerabilities': [
                {
                    'id': 'CVE-2025-1111',
                    'ratings': [
                        {'source': {'name': 'GHSA'}, 'score': 6.0, 'method': 'CVSSv31'},
                        {
                            'source': {'name': 'NVD'},
                            'score': 5.5,
                            'method': 'CVSSv31',
                            'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
                        },
                    ],
                    'affects': [{'ref': ref}],
                },
            ],
        }
        findings = list(
            scanner_utils.cyclonedx.iter_vulnerability_findings(
                doc,
                vulnerability_cfg,
            ),
        )
        assert findings[0].cvss_score == 5.5  # NVD wins over GHSA 6.0
        assert findings[0].rating_source == 'NVD'

    def test_metadata_component_ref_resolved(self, vulnerability_cfg):
        # A vulnerability whose affects[].ref targets metadata.component must resolve
        # package_name/package_version/purl from that component, not fall back to the raw ref.
        ref = 'pkg:oci/my-image@sha256:abc123'
        doc = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.5',
            'metadata': {
                'component': {
                    'bom-ref': ref,
                    'name': 'my-image',
                    'version': '1.2.3',
                    'purl': ref,
                },
            },
            'components': [],
            'vulnerabilities': [
                {
                    'id': 'CVE-2025-5555',
                    'ratings': [
                        {
                            'source': {'name': 'NVD'},
                            'score': 5.0,
                            'method': 'CVSSv31',
                            'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
                        },
                    ],
                    'affects': [{'ref': ref}],
                },
            ],
        }
        findings = list(
            scanner_utils.cyclonedx.iter_vulnerability_findings(doc, vulnerability_cfg),
        )
        assert len(findings) == 1
        assert findings[0].package_name == 'my-image'
        assert findings[0].package_version == '1.2.3'
        assert findings[0].purl == ref

        # "National Vulnerability Database" is an alias for "nvd" and must win over GHSA.
        ref = 'pkg:npm/lodash@4.17.20'
        doc = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.5',
            'components': [{'bom-ref': ref, 'name': 'lodash', 'version': '4.17.20'}],
            'vulnerabilities': [
                {
                    'id': 'CVE-2025-4444',
                    'ratings': [
                        {'source': {'name': 'GHSA'}, 'score': 6.0, 'method': 'CVSSv31'},
                        {
                            'source': {'name': 'National Vulnerability Database'},
                            'score': 5.5,
                            'method': 'CVSSv31',
                            'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
                        },
                    ],
                    'affects': [{'ref': ref}],
                },
            ],
        }
        findings = list(
            scanner_utils.cyclonedx.iter_vulnerability_findings(
                doc,
                vulnerability_cfg,
            ),
        )
        assert findings[0].cvss_score == 5.5  # NVD alias wins over GHSA 6.0
        assert findings[0].rating_source == 'National Vulnerability Database'

    def test_below_threshold_is_skipped(self, vulnerability_cfg):
        # score=1.0 is below MEDIUM minimum (4.0) → categorise_finding returns None → skip
        findings = list(
            scanner_utils.cyclonedx.iter_vulnerability_findings(
                self._make_cyclonedx(score=1.0, vector=None),
                vulnerability_cfg,
            ),
        )
        assert findings == []

    def test_no_numeric_score_is_skipped(self, vulnerability_cfg):
        # Severity-only ratings (no numeric score) must be skipped entirely.
        findings = list(
            scanner_utils.cyclonedx.iter_vulnerability_findings(
                self._make_cyclonedx(score=None, vector=None),
                vulnerability_cfg,
            ),
        )
        assert findings == []

    def test_multi_affect_yields_one_finding_per_component(self, vulnerability_cfg):
        doc = self._make_cyclonedx(
            extra_components=[{'bom-ref': 'ref-b', 'name': 'lib-b', 'version': '2.0'}],
            extra_affects=[{'ref': 'ref-b'}],
        )
        findings = list(
            scanner_utils.cyclonedx.iter_vulnerability_findings(
                doc,
                vulnerability_cfg,
            ),
        )
        assert len(findings) == 2
        assert {f.package_name for f in findings} == {'curl', 'lib-b'}

    def test_empty_document_yields_nothing(self, vulnerability_cfg):
        assert (
            list(
                scanner_utils.cyclonedx.iter_vulnerability_findings(
                    {},
                    vulnerability_cfg,
                ),
            )
            == []
        )

    def test_no_vulnerabilities_key(self, vulnerability_cfg):
        assert (
            list(
                scanner_utils.cyclonedx.iter_vulnerability_findings(
                    {'bomFormat': 'CycloneDX', 'components': []},
                    vulnerability_cfg,
                ),
            )
            == []
        )

    def test_severity_comes_from_categorisation_not_cyclonedx(self, vulnerability_cfg):
        # The CycloneDX rating says 'medium' but severity on VulnerabilityFinding must be
        # the categorisation.id (configured in vulnerability_cfg), not the raw string.
        findings = list(
            scanner_utils.cyclonedx.iter_vulnerability_findings(
                self._make_cyclonedx(),
                vulnerability_cfg,
            ),
        )
        assert findings[0].severity == 'MEDIUM'

    def test_no_affects_is_skipped(self, vulnerability_cfg):
        doc = self._make_cyclonedx()
        doc['vulnerabilities'][0]['affects'] = []
        findings = list(
            scanner_utils.cyclonedx.iter_vulnerability_findings(
                doc,
                vulnerability_cfg,
            ),
        )
        assert findings == []

    def test_cvssv2_only_rating_yields_finding_without_parsed_vector(self, vulnerability_cfg):
        ref = 'pkg:apk/alpine/curl@8.0.0'
        doc = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.5',
            'components': [{'bom-ref': ref, 'name': 'curl', 'version': '8.0.0'}],
            'vulnerabilities': [
                {
                    'id': 'CVE-2025-2222',
                    'ratings': [
                        {
                            'source': {'name': 'NVD'},
                            'score': 5.0,
                            'method': 'CVSSv2',
                            'vector': 'AV:N/AC:L/Au:N/C:P/I:P/A:P',
                        },
                    ],
                    'affects': [{'ref': ref}],
                },
            ],
        }
        # Score is used as-is; vector is not parsed (v2 vector format not supported).
        findings = list(
            scanner_utils.cyclonedx.iter_vulnerability_findings(
                doc,
                vulnerability_cfg,
            ),
        )
        assert len(findings) == 1
        assert findings[0].cvss_score == 5.0
        assert findings[0].cvss is None

    def test_cvssv4_only_rating_yields_finding_without_parsed_vector(self, vulnerability_cfg):
        ref = 'pkg:apk/alpine/curl@8.0.0'
        vector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N'
        doc = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.5',
            'components': [{'bom-ref': ref, 'name': 'curl', 'version': '8.0.0'}],
            'vulnerabilities': [
                {
                    'id': 'CVE-2025-3333',
                    'ratings': [
                        {
                            'source': {'name': 'NVD'},
                            'score': 6.5,
                            'method': 'CVSSv4',
                            'vector': vector,
                        },
                    ],
                    'affects': [{'ref': ref}],
                },
            ],
        }
        # Score is used as-is; vector is not parsed (v4 vector format not supported).
        findings = list(
            scanner_utils.cyclonedx.iter_vulnerability_findings(
                doc,
                vulnerability_cfg,
            ),
        )
        assert len(findings) == 1
        assert findings[0].cvss_score == 6.5
        assert findings[0].cvss is None

    @pytest.mark.parametrize(
        'patch,match',
        [
            (lambda d: d['vulnerabilities'][0].__delitem__('id'), 'no id'),
            (lambda d: d['components'][0].__delitem__('name'), 'no name'),
            (lambda d: d['components'][0].__delitem__('version'), 'no version'),
        ],
    )
    def test_missing_required_field_raises(self, vulnerability_cfg, patch, match):
        doc = self._make_cyclonedx()
        patch(doc)
        with pytest.raises(ValueError, match=match):
            list(scanner_utils.cyclonedx.iter_vulnerability_findings(doc, vulnerability_cfg))

    def test_not_affected_analysis_state_skips_finding(self, vulnerability_cfg):
        # A vulnerability with analysis.state == 'not_affected' must produce no finding
        # even when it has a valid rating (score in MEDIUM range) and an affected ref.
        doc = self._make_cyclonedx(score=5.3, vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N')
        doc['vulnerabilities'][0]['analysis'] = {'state': 'not_affected'}
        findings = list(
            scanner_utils.cyclonedx.iter_vulnerability_findings(doc, vulnerability_cfg),
        )
        assert findings == []

    def test_malformed_cvssv3_vector_yields_finding_with_cvss_none(self, vulnerability_cfg):
        # A CVSSv3 rating with an unparseable vector string must still yield a finding
        # (score is valid) but with cvss=None rather than raising.
        doc = self._make_cyclonedx(
            score=5.3,
            vector='CVSS:3.1/AV:INVALID/broken',
        )
        findings = list(
            scanner_utils.cyclonedx.iter_vulnerability_findings(doc, vulnerability_cfg),
        )
        assert len(findings) == 1
        assert findings[0].cvss_score == 5.3
        assert findings[0].cvss is None
