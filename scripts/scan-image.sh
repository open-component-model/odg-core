#!/usr/bin/env bash
# Runs CIS Docker Benchmark (dockle) and optionally STIG/OpenSCAP against a local
# container image, writing machine-readable JSON + human-readable HTML reports to
# a timestamped directory under reports/.
#
# Usage:
#   ./scripts/scan-image.sh [IMAGE]
#
# Examples:
#   ./scripts/scan-image.sh odg-core:0.1.0
#   ./scripts/scan-image.sh                        # defaults to odg-core:0.1.0
#
# Output layout:
#   reports/<image-tag>-<timestamp>/
#     dockle.json      — raw findings (one object per check code)
#     dockle.txt       — human-readable summary printed here and saved
#     rootfs/          — extracted container filesystem (used by STIG)
#     stig/            — OpenSCAP XML + HTML reports (requires STIG content)
#
# Exit codes:
#   0  all checks passed (or only INFO/SKIP)
#   1  one or more WARN/FATAL findings, or a scanner error

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────

IMAGE="${1:-odg-core:0.1.0}"
DOCKLE_IMAGE="goodwithtech/dockle:latest"
# Set to the openscap image you have available; leave blank to skip STIG.
OPENSCAP_IMAGE="${OPENSCAP_IMAGE:-}"

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
# Replace : and / with - so the directory name is shell-safe
IMAGE_SLUG="${IMAGE//[:\/]/-}"
REPORT_DIR="reports/${IMAGE_SLUG}-${TIMESTAMP}"

# ── Helpers ───────────────────────────────────────────────────────────────────

info()  { echo "[INFO]  $*"; }
warn()  { echo "[WARN]  $*" >&2; }
fatal() { echo "[FATAL] $*" >&2; exit 1; }

require() {
    command -v "$1" >/dev/null 2>&1 || fatal "'$1' not found — install it first"
}

# ── Preflight ─────────────────────────────────────────────────────────────────

require docker
require jq

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    fatal "Image '$IMAGE' not found locally. Pull or build it first."
fi

mkdir -p "$REPORT_DIR"
info "Reports will be written to: $REPORT_DIR"

# ── Save image tar (shared by dockle + STIG rootfs extraction) ────────────────

TAR="$REPORT_DIR/image.tar"
info "Saving image to $TAR …"
docker save "$IMAGE" -o "$TAR"

# ── CIS Docker Benchmark — dockle ─────────────────────────────────────────────
# CIS section 4 checks the image build, not runtime behaviour:
#   - CIS-DI-0001  No root USER
#   - CIS-DI-0005  HEALTHCHECK instruction present
#   - CIS-DI-0006  No unexpected SETUID/SETGID binaries
#   - CIS-DI-0008  No credentials or secrets baked into image layers
#   - CIS-DI-0009  No apk/apt upgrade (would float package versions)
#   - CIS-DI-0010  No ADD with remote URL (use COPY + explicit download instead)
#   - DKL-DI-0005  No apt/apk cache left in layers
#   - DKL-LI-0001  Avoid latest tags on FROM lines
#
# Levels:
#   FATAL  direct violation, must fix
#   WARN   probable violation, should fix
#   INFO   advisory, good to review
#   SKIP   check not applicable (e.g. no /etc/passwd in scratch)
#
# This run fails (exit 1) on WARN or FATAL; INFO and SKIP are reported but do
# not set a non-zero exit code.

info "Running CIS Docker Benchmark (dockle) …"
DOCKLE_JSON="$REPORT_DIR/dockle.json"
DOCKLE_LOG="$REPORT_DIR/dockle.log"
dockle_rc=0

docker run --rm \
    -v "$PWD/$TAR:/image.tar:ro" \
    -v "$PWD/$REPORT_DIR:/out" \
    "$DOCKLE_IMAGE" \
    --exit-code 1 --exit-level warn \
    --format json --output /out/dockle.json \
    --accept-file settings.py \
    --input /image.tar \
    > "$DOCKLE_LOG" 2>&1 || dockle_rc=$?

cat "$DOCKLE_LOG"

if grep -q 'ERROR' "$DOCKLE_LOG"; then
    warn "dockle logged an error — not all checks were evaluated"
    dockle_rc=1
fi

# Render human-readable summary and save it alongside the JSON
DOCKLE_TXT="$REPORT_DIR/dockle.txt"
if [[ -f "$DOCKLE_JSON" ]]; then
    {
        echo "=== CIS Docker Benchmark — dockle report ==="
        echo "Image : $IMAGE"
        echo "Date  : $TIMESTAMP"
        echo ""
        echo "--- Findings (FATAL / WARN / INFO) ---"
        jq -r '
            .details[]?
            | "\(.level)\t\(.code)\t\(.title // "")"
              + (if (.alerts | length) > 0
                 then "\n          " + (.alerts | join("\n          "))
                 else "" end)
        ' "$DOCKLE_JSON" | sort || true
        echo ""
        echo "--- Summary ---"
        jq -r '
            (.details // [])
            | group_by(.level)[]
            | "\(.[0].level): \(length) check(s)"
        ' "$DOCKLE_JSON" || true
    } | tee "$DOCKLE_TXT"
else
    warn "dockle produced no JSON — check $DOCKLE_LOG"
fi

# ── STIG / OpenSCAP ───────────────────────────────────────────────────────────
# DISA STIG checks verify that the OS inside the container is configured to
# the Security Requirements Guide (SRG) for General Purpose Operating Systems.
# Examples of what it checks:
#   - FIPS-approved crypto only (no MD5, no RC4)
#   - Audit daemon configured and rules in place
#   - No world-writable files
#   - No unnecessary SUID binaries
#   - Correct file permissions on /etc/passwd, /etc/shadow, etc.
#   - SSH daemon settings (if sshd is present)
#
# It works by mounting the container's extracted rootfs (not running the
# container) and evaluating SCAP XML rules against those files.  The HTML
# report is the most readable output; the XML is machine-parseable.

if [[ -z "$OPENSCAP_IMAGE" ]]; then
    info "OPENSCAP_IMAGE not set — skipping STIG scan."
    info "To enable: OPENSCAP_IMAGE=<image> ./scripts/scan-image.sh $IMAGE"
else
    info "Extracting rootfs for OpenSCAP …"
    ROOTFS="$REPORT_DIR/rootfs"
    mkdir -p "$ROOTFS"
    CONTAINER_ID=$(docker create "$IMAGE")
    docker export "$CONTAINER_ID" | tar -xC "$ROOTFS"
    docker rm "$CONTAINER_ID" >/dev/null

    STIG_OUT="$REPORT_DIR/stig"
    mkdir -p "$STIG_OUT"

    oscap_scan() {
        local profile="$1"; shift
        docker run --rm -u 0:0 \
            -e OSCAP_PROBE_ROOT=/rootfs \
            -v "$PWD/$ROOTFS:/rootfs:ro" \
            -v "$PWD/.github/stig:/stig:ro" \
            -v "$PWD/$STIG_OUT:/out" \
            "$OPENSCAP_IMAGE" xccdf eval "$@"
    }

    stig_rc=0

    if [[ -f ".github/stig/tailoring.xml" ]]; then
        info "Running GPOS SRG profile …"
        oscap_scan gpos \
            --tailoring-file /stig/tailoring.xml \
            --profile xccdf_software.ocm_profile_gpos-container \
            --results /out/gpos-results.xml \
            --report /out/gpos-report.html \
            /usr/share/xml/scap/ssg/content/ssg-chainguard-gpos-ds.xml \
            || stig_rc=$?
    else
        warn ".github/stig/tailoring.xml not found — skipping GPOS profile"
        warn "Add a tailoring file to enable STIG scanning"
    fi

    [[ $stig_rc -ne 0 ]] && dockle_rc=1
fi

# ── Final summary ─────────────────────────────────────────────────────────────

echo ""
echo "=== Scan complete ==="
echo "Reports: $REPORT_DIR/"
[[ -f "$DOCKLE_TXT" ]]      && echo "  dockle (CIS)  : $DOCKLE_TXT"
[[ -f "$DOCKLE_JSON" ]]     && echo "  dockle (JSON) : $DOCKLE_JSON"
[[ -d "$REPORT_DIR/stig" ]] && echo "  STIG HTML     : $REPORT_DIR/stig/gpos-report.html"
echo ""

exit "$dockle_rc"
