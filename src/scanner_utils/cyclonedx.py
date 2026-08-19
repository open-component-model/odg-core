import collections.abc
import dataclasses
import logging
import re

import odg.cvss
import odg.findings
import odg.model

logger = logging.getLogger(__name__)

# Preferred source order when multiple CVSS ratings are present.
_PREFERRED_SOURCES = ('nvd', 'redhat', 'ghsa')

# Map known long-form / alternate source names to their canonical key in _PREFERRED_SOURCES.
_SOURCE_ALIASES: dict[str, str] = {
    'national vulnerability database': 'nvd',
}

_CVSS_PREFIX_RE = re.compile(r'^CVSS:[^/]+/')


@dataclasses.dataclass
class CyclonedxRating:
    method: str
    score: float | None
    severity: str
    vector: str | None
    source_name: str | None

    @classmethod
    def from_dict(cls, raw: dict) -> 'CyclonedxRating':
        return cls(
            method=(raw.get('method') or ''),
            score=raw.get('score'),
            severity=(raw.get('severity') or ''),
            vector=raw.get('vector'),
            source_name=(raw.get('source') or {}).get('name'),
        )


@dataclasses.dataclass
class CyclonedxComponent:
    name: str
    version: str
    purl: str | None

    @classmethod
    def from_dict(cls, raw: dict) -> 'CyclonedxComponent':
        return cls(
            name=(raw.get('name') or ''),
            version=(raw.get('version') or ''),
            purl=raw.get('purl'),
        )


def _strip_cvss_prefix(vector: str) -> str:
    # "CVSS:3.1/AV:N/..." → "AV:N/..."  (CVSSV3.parse expects no prefix token)
    return _CVSS_PREFIX_RE.sub('', vector)


def _pick_rating(ratings: list[CyclonedxRating]) -> CyclonedxRating | None:
    """Return the best rating from a CycloneDX vulnerability's ratings array.

    Prefers CVSSv3 from trusted sources: nvd → redhat → ghsa → first CVSSv3 → first.
    Non-v3 ratings are accepted for their score but their vector will not be parsed.
    """
    if not ratings:
        return None

    cvssv3 = [r for r in ratings if 'v3' in r.method.lower()]

    for source in _PREFERRED_SOURCES:
        for r in cvssv3:
            raw = (r.source_name or '').lower()
            canonical = _SOURCE_ALIASES.get(raw, raw)
            if canonical == source:
                return r

    if cvssv3:
        return cvssv3[0]

    return ratings[0]


def iter_vulnerability_findings(
    cyclonedx: dict,
    vulnerability_cfg: odg.findings.Finding,
) -> collections.abc.Generator[odg.model.VulnerabilityFinding, None, None]:
    """Parse a CycloneDX JSON document and yield one VulnerabilityFinding per affected component.

    - Resolves package_name / package_version / purl via bom-ref → component index.
    - A vulnerability that affects N components yields N findings (same CVE, different package).
    - Skips findings where categorise_finding() returns None (outside configured score ranges).
    - Skips findings with no numeric CVSS score.
    """
    cdx_components_by_ref: dict[str, CyclonedxComponent] = {}
    for cdx_component in cyclonedx.get('components') or []:
        if ref := cdx_component.get('bom-ref'):
            cdx_components_by_ref[ref] = CyclonedxComponent.from_dict(cdx_component)
    cdx_meta_component = cyclonedx.get('metadata', {}).get('component') or {}
    if meta_ref := cdx_meta_component.get('bom-ref'):
        cdx_components_by_ref.setdefault(meta_ref, CyclonedxComponent.from_dict(cdx_meta_component))

    for vuln in cyclonedx.get('vulnerabilities') or []:
        if not (cve := vuln.get('id')):
            raise ValueError(f'vulnerability entry has no id: {vuln!r}')

        analysis_state = (vuln.get('analysis') or {}).get('state', '')
        if analysis_state == 'not_affected':
            logger.debug('skipping %s: analysis state is not_affected', cve)
            continue

        description = vuln.get('description')
        recommendation = vuln.get('recommendation')
        urls = [a['url'] for a in (vuln.get('advisories') or []) if a.get('url')]

        ratings = [CyclonedxRating.from_dict(r) for r in (vuln.get('ratings') or [])]
        rating = _pick_rating(ratings)
        if rating:
            cvss_score = rating.score
            raw_vector = rating.vector
            rating_source = rating.source_name
        else:
            cvss_score = None
            raw_vector = None
            rating_source = (vuln.get('source') or {}).get('name')

        if cvss_score is None:
            logger.debug('skipping %s: no numeric score available', cve)
            continue

        categorisation = odg.findings.categorise_finding(
            finding_cfg=vulnerability_cfg,
            finding_property=cvss_score,
        )
        if not categorisation:
            continue

        cvss: odg.cvss.CVSSV3 | None = None
        if raw_vector and rating and 'v3' in rating.method.lower():
            try:
                cvss = odg.cvss.CVSSV3.parse(_strip_cvss_prefix(raw_vector))
            except (ValueError, KeyError, IndexError):
                logger.debug('could not parse CVSS vector %r for %s', raw_vector, cve)

        affects = vuln.get('affects') or []
        if not affects:
            logger.warning('skipping %s: no affected components listed', cve)
            continue

        for affect in affects:
            ref = affect.get('ref', '')
            cdx_component = cdx_components_by_ref.get(ref)
            if not cdx_component or not cdx_component.name:
                raise ValueError(f'{cve}: component {ref!r} has no name')
            if not cdx_component.version:
                raise ValueError(f'{cve}: component {ref!r} has no version')
            yield odg.model.VulnerabilityFinding(
                severity=categorisation.id,
                package_name=cdx_component.name,
                package_version=cdx_component.version,
                cve=cve,
                purl=cdx_component.purl,
                cvss_score=cvss_score,
                cvss=cvss,
                rating_source=rating_source,
                summary=description,
                recommendation=recommendation,
                urls=list(urls),
            )
