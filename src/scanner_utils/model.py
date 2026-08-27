import dataclasses
import enum

import ocm


class ScanningMode(enum.StrEnum):
    """
    ADR 005: configurable scanning modes for vulnerability scanners.

    - BINARY: fetch and scan the artifact directly
    - SBOM: use a pre-existing SBOM only
    - SBOM_WITH_BINARY_FALLBACK: use SBOM when available, fall back to binary scanning
    """

    BINARY = 'binary'
    SBOM = 'sbom'
    SBOM_WITH_BINARY_FALLBACK = 'sbom_with_binary_fallback'


class ScanTarget(enum.Enum):
    SBOM = 'sbom'
    OCI_IMAGE = 'oci_image'
    OCI_IMAGE_ARCHIVE = 'oci_image_archive'
    FILE = 'file'


@dataclasses.dataclass
class RouteEvidence:
    """
    All observable facts about an OCM resource used to decide how to scan it.

    Fields are populated progressively: access/resource/manifest fields are set before
    the first `decide_route` call; blob fields are filled in inside the blob loop.
    """

    access_type: ocm.AccessType | None = None
    access_media_type: str | None = None  # mediaType on LocalBlobAccess / OciBlobAccess
    artefact_type: ocm.ArtefactType | None = None
    manifest_class_type: type | None = None  # Python class of the fetched OCI manifest
    manifest_media_type: str | None = None
    manifest_artifact_type: str | None = None  # None for container images, set for ORAS artifacts
    blob_media_type: str | None = None  # mediaType of the current blob layer
    is_tar: bool | None = None  # whether the blob is a tar archive


class SbomNotAvailable(Exception):
    """
    Raised when the scanner requires an SBOM (scan_target=SBOM or SBOM_WITH_BINARY_FALLBACK)
    but none has been generated yet for this artefact.

    Callers should requeue the backlog item with a delay to allow the sbom_generator job
    to complete before retrying.
    """


class ScanError(Exception):
    """
    Raised by a scan hook to signal a scan failure.

    fallback_to_file_scan: if True, scan_ocm_resource will retry the current blob
    as a file scan instead of propagating the error.
    """

    def __init__(self, message: str, details: str = '', fallback_to_file_scan: bool = False):
        super().__init__(message)
        self.details = details
        self.fallback_to_file_scan = fallback_to_file_scan
