"""
Shared synthetic data generators for ODG perf tests.

Provides deterministic CVE/package pools, artefact variant lists, and rescorings
as real odg.model objects.
"""

# ruff: noqa
# flake8: noqa

import datetime
import random

import odg.model

# ── tunables ──────────────────────────────────────────────────────────────────

COMPONENT_NAME = 'github.com/gardenlinux/gardenlinux'
COMPONENT_VERSION = '2150.10.0'
SEED = 42
N_CVES = 1500
N_PACKAGES = 400

_SEED_DATE = datetime.date(2026, 8, 12)

# ── artefact variants ─────────────────────────────────────────────────────────

_PLATFORMS = [
    ('amd64', 'ali', 'ali', None),
    ('amd64', 'aws', 'aws', None),
    ('amd64', 'azure', 'azure', None),
    ('amd64', 'gcp', 'gcp', None),
    ('amd64', 'openstack', 'openstack', 'vmware'),
    ('amd64', 'openstack-metal', 'openstack_platform_variant:metal', None),
    ('arm64', 'aws', 'aws', None),
    ('arm64', 'azure', 'azure', None),
    ('arm64', 'gcp', 'gcp', None),
]

_FLAGS_BASE = 'log,sap,ssh,_fwcfg,_legacy,_nopkg,_prod,_slim,base,server,cloud'
_FLAGS_METAL = 'log,openstackMetal,sap,ssh,_fwcfg,_legacy,_nopkg,_prod,_slim,base,server,openstack,metal,multipath,iscsi,nvme,gardener'

_CVE_PREFIXES = ['CVE-2024', 'CVE-2025', 'CVE-2026']
_LICENSE_NAMES = [
    'Apache-2.0',
    'BSD-2-Clause',
    'BSD-3-Clause',
    'CDDL-1.0',
    'GPL-2.0',
    'GPL-3.0',
    'ISC',
    'LGPL-2.1',
    'MIT',
    'MPL-2.0',
]
_PKG_NAMES = [
    'bash',
    'cni-plugins',
    'containerd',
    'coreutils',
    'curl',
    'dbus',
    'e2fsprogs',
    'etcd',
    'fdisk',
    'glibc',
    'golang-net',
    'grpc',
    'gzip',
    'iproute2',
    'iptables',
    'iputils',
    'kube-proxy',
    'kubelet',
    'libc',
    'libcurl',
    'libgcc',
    'libpcre',
    'libssl',
    'libstdc++',
    'libz',
    'linux-kernel',
    'lvm2',
    'mount',
    'net-tools',
    'nftables',
    'openssh',
    'openssl',
    'parted',
    'protobuf',
    'python3',
    'runc',
    'seaweedfs',
    'sudo',
    'systemd',
    'tar',
    'udev',
    'util-linux',
    'wget',
    'xz-utils',
]
_SUMMARY_TEMPLATES = [
    '{pkg} {ver} contains a heap-based buffer overflow allowing remote code execution via crafted input.',
    'An integer overflow in {pkg} {ver} leads to memory corruption and potential privilege escalation.',
    'Use-after-free in {pkg} {ver} allows local attackers to gain elevated privileges.',
    '{pkg} {ver} fails to validate TLS certificates, enabling man-in-the-middle attacks.',
    'Path traversal in {pkg} {ver} allows unauthenticated file read from the host filesystem.',
]

_SEED_USER = odg.model.User(username='seed-user@example.com')


# ── helpers ───────────────────────────────────────────────────────────────────


def make_meta(
    now: datetime.datetime, datasource: odg.model.Datasource, datatype: odg.model.Datatype
) -> odg.model.Metadata:
    return odg.model.Metadata(datasource=datasource, type=datatype, creation_date=now)


def _artefact_ref(
    component_name: str | None,
    component_version: str | None,
    artefact_name: str | None,
    artefact_version: str | None,
    artefact_type: str | None,
    artefact_extra_id: dict,
    artefact_kind: odg.model.ArtefactKind | None,
) -> odg.model.ComponentArtefactId:
    return odg.model.ComponentArtefactId(
        component_name=component_name,
        component_version=component_version,
        artefact=odg.model.LocalArtefactId(
            artefact_name=artefact_name,
            artefact_version=artefact_version,
            artefact_type=artefact_type,
            artefact_extra_id=artefact_extra_id,
        ),
        artefact_kind=artefact_kind,
    )


def make_rescoring(
    artefact: odg.model.ComponentArtefactId,
    finding: odg.model.RescoringVulnerabilityFinding | odg.model.RescoringLicenseFinding,
    referenced_type: odg.model.Datatype,
    severity: str,
    comment: str,
    now: datetime.datetime,
    due_date: datetime.date | None = None,
) -> odg.model.ArtefactMetadata:
    return odg.model.ArtefactMetadata(
        artefact=artefact,
        meta=make_meta(now, odg.model.Datasource.DELIVERY_DASHBOARD, odg.model.Datatype.RESCORING),
        data=odg.model.CustomRescoring(
            finding=finding,
            referenced_type=referenced_type,
            severity=severity,
            user=_SEED_USER,
            comment=comment,
            due_date=due_date,
        ),
    )


# ── public generators ─────────────────────────────────────────────────────────


def build_variants() -> list[dict]:
    import json as _json

    variants = []
    for arch, cloud, platform, pv in _PLATFORMS:
        flags = _FLAGS_METAL if 'metal' in cloud else _FLAGS_BASE + f',{cloud}'
        for signed in (True, False):
            f = flags if signed else flags + ',_unsigned,_usi'
            extra_id: dict = {
                'architecture': arch,
                'feature-flags': f + ',multipath,iscsi,nvme,gardener',
                'platform': platform,
            }
            if pv:
                extra_id['platform_variant'] = pv
            for artefact_name, artefact_type in (
                ('gardenlinux', 'virtual_machine_image'),
                ('rootfs', 'application/tar+vm-image-rootfs'),
            ):
                variants.append(
                    {
                        'artefact_name': artefact_name,
                        'artefact_type': artefact_type,
                        'extra_id': extra_id,
                    }
                )

    seen: set[str] = set()
    unique = []
    for v in variants:
        key = (v['artefact_name'], _json.dumps(v['extra_id'], sort_keys=True))
        if key not in seen:
            seen.add(key)
            unique.append(v)
    return unique


def make_cve_pool(rng: random.Random, n: int) -> list[odg.model.BDBAVulnerabilityFinding]:
    pool = []
    seen: set[str] = set()
    while len(pool) < n:
        cve = f'{rng.choice(_CVE_PREFIXES)}-{rng.randint(10000, 99999)}'
        if cve in seen:
            continue
        seen.add(cve)
        pkg = rng.choice(_PKG_NAMES)
        ver = f'{rng.randint(1, 5)}.{rng.randint(0, 20)}.{rng.randint(0, 10)}'
        pool.append(
            odg.model.BDBAVulnerabilityFinding(
                package_name=pkg,
                package_version=ver,
                base_url='https://bdba.example.com',
                report_url='https://bdba.example.com/products/1000000/',
                product_id=1000000,
                group_id=1000,
                cve=cve,
                cvss_score=round(rng.uniform(1.0, 10.0), 1),
                severity='NONE',
                summary=rng.choice(_SUMMARY_TEMPLATES).format(pkg=pkg, ver=ver),
            )
        )
    return pool


def make_pkg_pool(rng: random.Random, n: int) -> list[odg.model.StructureInfo]:
    pool = []
    seen: set[str] = set()
    while len(pool) < n:
        pkg = rng.choice(_PKG_NAMES) + f'-{rng.randint(0, 50)}'
        if pkg in seen:
            continue
        seen.add(pkg)
        ver = f'{rng.randint(1, 5)}.{rng.randint(0, 20)}.{rng.randint(0, 10)}'
        pool.append(
            odg.model.StructureInfo(
                package_name=pkg,
                package_version=ver,
                base_url='https://bdba.example.com',
                report_url='https://bdba.example.com/products/1000000/',
                product_id=1000000,
                group_id=1000,
                licenses=[odg.model.License(name=rng.choice(_LICENSE_NAMES))],
                filesystem_paths=[],
            )
        )
    return pool


def make_rescorings(
    cve_pool: list[odg.model.BDBAVulnerabilityFinding],
    pkg_pool: list[odg.model.StructureInfo],
    variant: dict,
    now: datetime.datetime,
) -> list[odg.model.ArtefactMetadata]:
    """Rescorings covering all scopes and edge cases (matching + non-matching).

    Matching entries (should apply to our component):
      - single-artefact, component, and global scope vulnerability rescorings
      - artefact and component scope license rescorings
      - one entry with a due_date

    Non-matching entries (must NOT apply — wrong component / CVE / package):
      - wrong component name
      - CVE absent from dataset
      - package name not in artefacts
    """
    c = cve_pool
    p = pkg_pool

    def _vuln(
        cve_entry: odg.model.BDBAVulnerabilityFinding,
    ) -> odg.model.RescoringVulnerabilityFinding:
        return odg.model.RescoringVulnerabilityFinding(
            package_name=cve_entry.package_name,
            cve=cve_entry.cve,
        )

    def _lic(pkg_entry: odg.model.StructureInfo) -> odg.model.RescoringLicenseFinding:
        return odg.model.RescoringLicenseFinding(
            package_name=pkg_entry.package_name,
            license=pkg_entry.licenses[0],
        )

    # artefact refs at each scope for our component
    ref_global = _artefact_ref(None, None, None, None, None, {}, None)
    ref_component = _artefact_ref(COMPONENT_NAME, None, None, None, None, {}, None)
    ref_artefact = _artefact_ref(
        COMPONENT_NAME,
        None,
        variant['artefact_name'],
        None,
        variant['artefact_type'],
        {},
        odg.model.ArtefactKind.RESOURCE,
    )
    ref_single = _artefact_ref(
        COMPONENT_NAME,
        COMPONENT_VERSION,
        variant['artefact_name'],
        COMPONENT_VERSION,
        variant['artefact_type'],
        variant['extra_id'],
        odg.model.ArtefactKind.RESOURCE,
    )
    ref_other_cmp = _artefact_ref(
        'github.com/other-org/other-component',
        COMPONENT_VERSION,
        variant['artefact_name'],
        COMPONENT_VERSION,
        variant['artefact_type'],
        variant['extra_id'],
        odg.model.ArtefactKind.RESOURCE,
    )

    V = odg.model.Datatype.VULNERABILITY_FINDING
    L = odg.model.Datatype.LICENSE_FINDING

    return [
        # ── matching ──────────────────────────────────────────────────────────
        make_rescoring(
            ref_single,
            _vuln(c[0]),
            V,
            'NONE',
            'Not affected: gardenlinux strips this codepath.',
            now,
        ),
        make_rescoring(ref_component, _vuln(c[1]), V, 'NONE', 'Mitigated at component level.', now),
        make_rescoring(
            ref_global, _vuln(c[2]), V, 'MEDIUM', 'Only exploitable with physical access.', now
        ),
        make_rescoring(
            ref_component,
            _vuln(c[3]),
            V,
            'NONE',
            'Accepted risk.',
            now,
            due_date=_SEED_DATE + datetime.timedelta(days=90),
        ),
        make_rescoring(ref_artefact, _lic(p[0]), L, 'NONE', 'License reviewed and approved.', now),
        make_rescoring(ref_component, _lic(p[1]), L, 'NONE', 'Approved for all artefacts.', now),
        # ── non-matching ──────────────────────────────────────────────────────
        make_rescoring(ref_other_cmp, _vuln(c[0]), V, 'NONE', 'Different component.', now),
        make_rescoring(
            ref_component,
            odg.model.RescoringVulnerabilityFinding(
                package_name=c[0].package_name, cve='CVE-1999-00001'
            ),
            V,
            'NONE',
            'CVE absent from dataset.',
            now,
        ),
        make_rescoring(
            ref_single,
            odg.model.RescoringVulnerabilityFinding(
                package_name='nonexistent-pkg-xyz', cve=c[0].cve
            ),
            V,
            'NONE',
            'Package not in artefacts.',
            now,
        ),
    ]
