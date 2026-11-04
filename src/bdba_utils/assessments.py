import ocm
import structlog

import bdba.client
import bdba.model as bm
import odg_client
import scanner_utils.findings

logger = structlog.get_logger(__name__)


def upload_version_hints(
    scan_result: bm.AnalysisResult,
    component: ocm.Component,
    resource: ocm.Resource,
    bdba_client: bdba.client.BDBAApi,
    delivery_service_client: odg_client.DeliveryServiceClient,
) -> bm.AnalysisResult:
    if not (
        package_version_overwrites := tuple(
            scanner_utils.findings.iter_package_version_overwrites(
                component=component,
                resource=resource,
                delivery_service_client=delivery_service_client,
            ),
        )
    ):
        return scan_result

    logger.info(f'uploading package-version-hints for {scan_result.display_name}')

    for bdba_component in scan_result.components:
        name = bdba_component.name
        version = bdba_component.version

        if not (
            filtered_package_version_overwrites := tuple(
                package_version_overwrite
                for package_version_overwrite in package_version_overwrites
                if package_version_overwrite.matches(
                    package_name=name,
                    package_version=version,
                )
            )
        ):
            continue

        # take the first overwrite since they are sorted by specificity/creation-date already
        package_version_overwrite = filtered_package_version_overwrites[0]

        logger.info(f'Found {package_version_overwrite=} for {name}:{version}')

        if package_version_overwrite.package_version_to == version:
            logger.info('No change in package version -> skipping update')
            continue

        digests = [eo.sha1 for eo in bdba_component.extended_objects]

        bdba_client.set_component_version(
            component_name=name,
            component_version=package_version_overwrite.package_version_to,
            objects=digests,
            app_id=scan_result.product_id,
        )

        # the bdba api does not properly react to multiple component versions being set in
        # a short period of time. This even stays true if all component versions are set
        # using one single api request. That's why, adding a small delay in case multiple
        # hints and thus possible version overrides exist by retrieving scan result again
        scan_result = bdba_client.wait_for_scan_result(
            product_id=scan_result.product_id,
            polling_interval_seconds=15,  # re-scanning usually don't take a minute
        )

    return scan_result
