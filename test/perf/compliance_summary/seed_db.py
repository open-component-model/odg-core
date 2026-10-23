"""
Seed a delivery-service DB with synthetic gardenlinux compliance data via the ODG API.

Generates a dataset similar to real prod data:
  - 36 artefact variants (gardenlinux/virtual_machine_image + rootfs/application/tar+vm-image-rootfs)
  - N_CVES vulnerability findings per variant  (default 1500, shared across variants)
  - structure_info (packages) per variant
  - meta/artefact_scan_info per variant
  - rescorings at all scopes (matching + non-matching edge cases)

Data is uploaded via client.update_metadata() in one PUT per variant, exactly as BDBA does it.

Usage:
    from compliance_summary.seed_db import seed, dump
"""

import collections.abc
import datetime
import logging
import random
import subprocess

import odg.model

from utils.mock_data import (
    COMPONENT_NAME,
    COMPONENT_VERSION,
    N_CVES,
    N_PACKAGES,
    SEED,
    build_variants,
    make_cve_pool,
    make_pkg_pool,
    make_rescorings,
)

logger = logging.getLogger(__name__)

VARIANTS = build_variants()
logger.info(f'Generated {len(VARIANTS)} artefact variants')

_BASE_URL = 'https://bdba.example.com'
_REPORT_URL = f'{_BASE_URL}/products/1000000/'
_PRODUCT_ID = 1000000
_GROUP_ID = 1000
_DISCOVERY_DATE = datetime.date(2026, 8, 12)


def _iter_variant_metadata(
    variant: dict,
    cve_pool: list[odg.model.BDBAVulnerabilityFinding],
    pkg_pool: list[odg.model.StructureInfo],
    now: datetime.datetime,
) -> collections.abc.Iterator:
    artefact_ref = odg.model.ComponentArtefactId(
        component_name=COMPONENT_NAME,
        component_version=None,
        artefact=odg.model.LocalArtefactId(
            artefact_name=variant['artefact_name'],
            artefact_version=COMPONENT_VERSION,
            artefact_type=variant['artefact_type'],
            artefact_extra_id=variant['extra_id'],
        ),
        artefact_kind=odg.model.ArtefactKind.RESOURCE,
    )
    scan_info_ref = odg.model.ComponentArtefactId(
        component_name=COMPONENT_NAME,
        component_version=COMPONENT_VERSION,
        artefact=odg.model.LocalArtefactId(
            artefact_name=variant['artefact_name'],
            artefact_version=COMPONENT_VERSION,
            artefact_type=variant['artefact_type'],
            artefact_extra_id=variant['extra_id'],
        ),
        artefact_kind=odg.model.ArtefactKind.RESOURCE,
    )

    def _meta(datatype: odg.model.Datatype) -> odg.model.Metadata:
        return odg.model.Metadata(
            datasource=odg.model.Datasource.BDBA,
            type=datatype,
            creation_date=now,
        )

    yield odg.model.ArtefactMetadata(
        artefact=scan_info_ref,
        meta=_meta(odg.model.Datatype.ARTEFACT_SCAN_INFO),
        data={'report_url': _REPORT_URL, 'product_id': _PRODUCT_ID},
    )
    for pkg in pkg_pool:
        yield odg.model.ArtefactMetadata(
            artefact=artefact_ref,
            meta=_meta(odg.model.Datatype.STRUCTURE_INFO),
            data=pkg,
            discovery_date=_DISCOVERY_DATE,
        )
    for cve in cve_pool:
        yield odg.model.ArtefactMetadata(
            artefact=artefact_ref,
            meta=_meta(odg.model.Datatype.VULNERABILITY_FINDING),
            data=cve,
            discovery_date=_DISCOVERY_DATE,
        )


def seed(base_url: str, n_cves: int = N_CVES, n_packages: int = N_PACKAGES):
    import odg_client

    rng = random.Random(SEED)
    cve_pool = make_cve_pool(rng, n_cves)
    pkg_pool = make_pkg_pool(rng, n_packages)
    now = datetime.datetime.now(tz=datetime.timezone.utc)

    routes = odg_client.DeliveryServiceRoutes(base_url=base_url)
    client = odg_client.DeliveryServiceClient(routes=routes)

    logger.info(
        f'Seeding {COMPONENT_NAME} {COMPONENT_VERSION} — '
        f'{len(VARIANTS)} variants × {n_cves} CVEs + {n_packages} packages '
        f'via {base_url}',
    )

    total_rows = 0
    for idx, variant in enumerate(VARIANTS):
        batch = list(_iter_variant_metadata(variant, cve_pool, pkg_pool, now))
        client.update_metadata(data=batch)
        total_rows += len(batch)
        logger.info(
            f'  [{idx + 1:2d}/{len(VARIANTS)}] {variant["artefact_name"]} '
            f'{variant["extra_id"].get("architecture", "?")} '
            f'{variant["extra_id"].get("platform", "?")} '
            f'— {len(batch)} rows',
        )

    rescoring_batch = make_rescorings(cve_pool, pkg_pool, VARIANTS[0], now)
    client.update_metadata(data=rescoring_batch)
    total_rows += len(rescoring_batch)
    logger.info(f'  rescorings — {len(rescoring_batch)} entries')

    logger.info(f'Done: {total_rows} rows across {len(VARIANTS)} variants')


def dump(pg, dump_path: str):
    """Write a pg_dump of the running PostgresContainer to dump_path."""
    import shutil

    container_id = pg._container.get_wrapped_container().id
    logger.info(f'Dumping to {dump_path} …')
    subprocess.run(
        [
            'docker',
            'exec',
            container_id,
            'pg_dump',
            '--username',
            'postgres',
            '--format',
            'custom',
            '--no-owner',
            '--no-privileges',
            'postgres',
        ],
        check=True,
        stdout=open(dump_path, 'wb'),
    )
    logger.info(f'Dump written to {dump_path} ({shutil.disk_usage(dump_path).total}B on disk)')
