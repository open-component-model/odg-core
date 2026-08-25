import collections.abc
import dataclasses

import ocm
import ocm.iter

import odg.labels
import odg.model
import odg.util
import odg_client


def iter_existing_findings(
    delivery_service_client: odg_client.DeliveryServiceClient,
    resource_node: ocm.iter.ResourceNode,
    finding_type: odg.model.Datatype | tuple[odg.model.Datatype, ...],
    datasource: odg.model.Datasource,
) -> collections.abc.Generator[odg.model.ArtefactMetadata, None, None]:
    artefact = odg.model.component_artefact_id_from_ocm(
        component=resource_node.component_id,
        artefact=resource_node.resource,
    )

    findings_raw = delivery_service_client.query_metadata(
        artefacts=(artefact,),
        type=finding_type,
        datasource=datasource,
    )

    return (odg.model.ArtefactMetadata.from_dict(finding_raw) for finding_raw in findings_raw)


def delete_stale_findings(
    existing_findings_by_key: dict[str, odg.model.ArtefactMetadata],
    current_findings: collections.abc.Iterable[odg.model.ArtefactMetadata],
    delivery_service_client: odg_client.DeliveryServiceClient,
) -> None:
    """
    Deletes findings from the delivery service that were present in a previous scan but are absent
    from the current one (e.g. a vulnerability that was patched, or a custom version entry that
    resolved a false positive).

    A finding is considered present in the current scan when both its datatype and its data key
    (package+version+CVE for vulnerability findings) match. The artefact's component version is
    intentionally excluded from this comparison because findings are stored without it.
    """
    current_type_and_data_keys = {
        (am.meta.type, am.data.key)
        for am in current_findings
        if dataclasses.is_dataclass(am.data) and hasattr(am.data, 'key')
    }

    stale = [
        am
        for am in existing_findings_by_key.values()
        if (am.meta.type, am.data.key) not in current_type_and_data_keys
    ]

    if stale:
        delivery_service_client.delete_metadata(data=stale)


def iter_package_version_overwrites(
    component: ocm.Component,
    resource: ocm.Resource,
    delivery_service_client: odg_client.DeliveryServiceClient,
) -> collections.abc.Iterable[odg.model.PackageVersionScannerWriteback]:
    """
    Yields package-version overwrite entries for a given component/resource, merging
    hints from the delivery service (scanner writebacks) and OCM label hints. Resource-level
    labels take precedence over component-level labels; if a resource label is present the
    component label is ignored entirely.
    """
    artefact = odg.model.component_artefact_id_from_ocm(
        component=component,
        artefact=resource,
    )

    yield from odg.util.iter_scanner_writebacks(
        scanner_writeback_type=odg.model.ScannerWritebackType.PACKAGE_VERSION,
        artefact_id=artefact,
        delivery_service_client=delivery_service_client,
    )

    package_hints_label = resource.find_label(name=odg.labels.PackageVersionHintLabel.name)

    if not package_hints_label:
        package_hints_label = component.find_label(name=odg.labels.PackageVersionHintLabel.name)

        if not package_hints_label:
            return

    yield from (
        odg.model.PackageVersionScannerWriteback(
            package_name=package_name,
            package_version_from=None,
            package_version_to=package_version_to,
        )
        for hint in package_hints_label.value
        if ((package_name := hint.get('name')) and (package_version_to := hint.get('version')))
    )


def make_artefact_scan_info(
    resource_node: ocm.iter.ResourceNode,
    datasource: odg.model.Datasource,
) -> odg.model.ArtefactMetadata:
    """
    Returns the mandatory ARTEFACT_SCAN_INFO envelope for a completed scan.

    New scanner extensions should call this to emit the scan heartbeat without needing to know
    about the internal ArtefactMetadata structure.
    """
    return odg.model.artefact_scan_info(
        artefact_node=resource_node,
        datasource=datasource,
    )
