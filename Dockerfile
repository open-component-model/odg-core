# ── Stage 1: build cbomkit-theia ─────────────────────────────────────────────
FROM golang:1.27.1-alpine3.24@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS cbomkit-theia-builder
# renovate: datasource=github-releases depName=cbomkit/cbomkit-theia versioningTemplate=semver-coerced extractVersionTemplate=^v?(?<version>.*)$
ARG CBOMKIT_THEIA_VERSION=1.1.2
ARG CBOMKIT_THEIA_COMMIT=dcd95ac86d1cbe6e867ff3ee059b9ef77bac6a59
# Cache mounts: local BuildKit only — harmless no-op where unsupported (e.g. kaniko in CI)
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    apk add --no-cache git \
 && git clone --depth 1 --branch release/${CBOMKIT_THEIA_VERSION} https://github.com/cbomkit/cbomkit-theia.git /cbomkit-theia \
 && cd /cbomkit-theia \
 && git rev-parse HEAD | grep -qx ${CBOMKIT_THEIA_COMMIT} \
 && go mod download -x && go build -v


# ── Stage 2: installer ────────────────────────────────────────────────────────
# Full BCI image with zypper — installs packages, builds the venv, and
# assembles a minimal /rootfs containing only the runtime packages needed.
# Nothing from this stage's build tooling reaches the final image.
FROM registry.suse.com/bci/python:3.14@sha256:5ee77207d55d42d760ade2f24418dc01c216f2bfde0c5ce14977137d4f59dd2e AS installer

COPY --from=ghcr.io/astral-sh/uv:0.13.10@sha256:a3ea1357342c1a4bf9a0c53a3deb1b55379aefa037338d8113d5771efa01774f /uv /usr/local/bin/

RUN zypper --non-interactive install --no-recommends \
    clamav \
    git-core \
    libclamunrar12 \
    postgresql16 \
 && zypper --non-interactive clean --all \
 && mkdir -p /clamav-libs/usr/lib64 /clamav-libs/lib64 /pg-libs/usr/lib64 /pg-libs/lib64 /git-libs/usr/lib64 /git-libs/lib64 \
 && bash -euo pipefail -c ' \
    for bin in /usr/sbin/clamd /usr/bin/freshclam; do \
        ldd "$bin" \
        | awk '"'"'/=>/ && !/vdso/ && $3 != "not" {print $3}'"'"' \
        | while read -r lib; do \
            case "$lib" in \
                /usr/lib64/*) cp --dereference "$lib" /clamav-libs/usr/lib64/ ;; \
                /lib64/*)     cp --dereference "$lib" /clamav-libs/lib64/ ;; \
                *)            echo "unexpected lib path: $lib" >&2; exit 1 ;; \
            esac; \
          done; \
    done \
    && ldd /usr/lib/postgresql16/bin/pg_dump \
        | awk '"'"'/=>/ && !/vdso/ && $3 != "not" {print $3}'"'"' \
        | while read -r lib; do \
            case "$lib" in \
                /usr/lib64/*) cp --dereference "$lib" /pg-libs/usr/lib64/ ;; \
                /lib64/*)     cp --dereference "$lib" /pg-libs/lib64/ ;; \
                *)            echo "unexpected lib path: $lib" >&2; exit 1 ;; \
            esac; \
          done \
    && ldd /usr/bin/git \
        | awk '"'"'/=>/ && !/vdso/ && $3 != "not" {print $3}'"'"' \
        | while read -r lib; do \
            case "$lib" in \
                /usr/lib64/*) cp --dereference "$lib" /git-libs/usr/lib64/ ;; \
                /lib64/*)     cp --dereference "$lib" /git-libs/lib64/ ;; \
                *)            echo "unexpected lib path: $lib" >&2; exit 1 ;; \
            esac; \
          done' \
 && cp --dereference /usr/lib64/libclamunrar.so.12 /clamav-libs/usr/lib64/ \
 && cp --dereference /usr/lib64/libclamunrar_iface.so.12 /clamav-libs/usr/lib64/

# Assemble minimal rootfs from exactly the runtime packages Python needs.
# rpm -ql gives the authoritative file manifest — no hand-picked paths.
RUN mkdir -p /rootfs/lib /rootfs/etc \
        /rootfs/home/odg \
        /rootfs/freshclam \
        /rootfs/www \
        /rootfs/run/clamav \
        /rootfs/var/lib/clamav \
        /rootfs/var/log/clamav \
        /rootfs/tmp \
        /rootfs/var/tmp \
        /rootfs/usr/local/bin \
        /rootfs/usr/sbin \
        /rootfs/usr/bin \
        /rootfs/etc/clamav \
 && bash -euo pipefail -c ' \
    pkgs=" \
        libpython3_14-1_0 \
        python314-base \
        glibc \
        libz1 \
        libbz2-1 \
        liblzma5 \
        libffi8 \
        libexpat1 \
        libmpdec4 \
        libopenssl3 \
        libsqlite3-0 \
        libgcc_s1 \
        libstdc++6 \
        ca-certificates" \
    && rpm -q $pkgs \
    && rpm -ql $pkgs \
        | while read -r f; do \
            test -f "$f" || continue; \
            mkdir -p "/rootfs$(dirname "$f")"; \
            cp --dereference "$f" "/rootfs$f"; \
          done' \
 && mkdir -p /rootfs/usr/lib64 /rootfs/lib64 \
 && cp -a /clamav-libs/usr/lib64/. /rootfs/usr/lib64/ \
 && cp -a /clamav-libs/lib64/. /rootfs/lib64/ \
 && cp -a /pg-libs/usr/lib64/. /rootfs/usr/lib64/ \
 && cp -a /pg-libs/lib64/. /rootfs/lib64/ \
 && cp -a /git-libs/usr/lib64/. /rootfs/usr/lib64/ \
 && cp -a /git-libs/lib64/. /rootfs/lib64/ \
 && cp -a /etc/certs /rootfs/etc/certs \
 && chmod 1777 /rootfs/tmp /rootfs/var/tmp \
 && ln -sf /usr/bin/python3.14 /rootfs/usr/local/bin/python3 \
 && printf 'root:x:0:0:root:/root:/sbin/nologin\nodg:x:10000:10000::/home/odg:/sbin/nologin\n' \
        > /rootfs/etc/passwd \
 && printf 'root:x:0:\nodg:x:10000:\n' > /rootfs/etc/group \
 && chown -R 10000:10000 \
        /rootfs/home/odg \
        /rootfs/freshclam \
        /rootfs/www \
        /rootfs/run/clamav \
        /rootfs/var/lib/clamav \
        /rootfs/var/log/clamav \
 && printf '/lib64\n/usr/lib64\n' > /rootfs/etc/ld.so.conf \
 && ldconfig -r /rootfs

# Download SAP CA certs (curl is in the BCI base; not installed explicitly)
ADD --checksum=sha256:840ce93e2c8e3e15ff9c48b360fa87ac726f1eb6d25cb1fc2711739515bac139 \
    https://aia.pki.co.sap.com/aia/SAP%20Global%20Root%20CA.crt \
    /etc/pki/trust/anchors/SAP_Global_Root_CA.crt
ADD --checksum=sha256:f26b88731b0c8f124cf39f8e8bfac441faf20414a1ab53413f345a3e316a9364 \
    https://aia.pki.co.sap.com/aia/SAPNetCA_G2_2.crt \
    /etc/pki/trust/anchors/SAPNetCA_G2_2.crt
RUN update-ca-certificates

# Build the Python venv
ENV VIRTUAL_ENV=/opt/venv
COPY uv.lock pyproject.toml ./
RUN uv export --frozen --no-dev --no-emit-project --no-emit-workspace \
        --format=requirements-txt -o constraints.txt

ARG ODG_CORE_LIBS_VERSION
RUN --mount=type=bind,source=dist/,target=/dist \
    uv venv "$VIRTUAL_ENV" \
 && uv pip install --no-cache --find-links /dist \
        --constraint constraints.txt \
        odg-core-libs==${ODG_CORE_LIBS_VERSION} \
 && ln -sf /var/lib/ca-certificates/ca-bundle.pem "$($VIRTUAL_ENV/bin/python3 -m certifi)" \
 && $VIRTUAL_ENV/bin/python3 -m compileall -q "$VIRTUAL_ENV/lib"


# ── Stage 3: final (scratch) ──────────────────────────────────────────────────
# No base OS, no package manager, no shell — only what we explicitly copy in.
FROM scratch

# Minimal SUSE runtime: Python + glibc + openssl + ca-certs, plus all runtime
# .so libs (clamav, pg, C++ runtime), the ld.so.cache built in the installer,
# and ClamAV's /etc/certs (code-signing certs ClamAV 1.x reads from this
# compiled-in directory at verifier init to validate downloaded CVDs; absence
# fails freshclam init and makes clamd reject the DB as "Broken or not a CVD")
COPY --from=installer /rootfs /

# Python venv
COPY --from=installer /opt/venv /opt/venv

# Static Go binaries — no .so dependencies
COPY --from=aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb \
    /usr/local/bin/trivy /usr/local/bin/trivy
# Alpine's syft (1.42) predates native Go FIPS 140 detection (`goCryptoSettings`, syft >= 1.51)
COPY --from=anchore/syft:v1.57.2@sha256:e97e20b6e6d1699c60296b66ab337941724f9bd06ac279d893eda89601fc4b2a \
    /syft /usr/local/bin/syft
COPY --from=cbomkit-theia-builder /cbomkit-theia/cbomkit-theia /usr/local/bin/cbomkit-theia
COPY --from=installer /usr/lib/postgresql16/bin/pg_dump /usr/local/bin/pg_dump

# clamav binaries (their shared libs and the dlopen-loaded libclamunrar are in /rootfs)
COPY --from=installer /usr/sbin/clamd /usr/sbin/clamd
COPY --from=installer /usr/bin/freshclam /usr/bin/freshclam

# git binary — needed by the SLA report extension (gitpython calls the git CLI)
COPY --from=installer /usr/bin/git /usr/bin/git

# CA certificates (SUSE uses /var/lib/ca-certificates; certifi symlink points to ca-bundle.pem)
COPY --from=installer /var/lib/ca-certificates/ /var/lib/ca-certificates/
COPY --from=installer /etc/ssl/certs/ /etc/ssl/certs/
COPY --from=installer /etc/pki/trust/anchors/ /etc/pki/trust/anchors/

# ClamAV config and entrypoint
COPY src/malware/clamd.conf /etc/clamav/clamd.conf
COPY src/malware/clamav_entrypoint.py /clamav_entrypoint.py

ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
ENV HOME=/home/odg
ENV XDG_CACHE_HOME=/tmp/.cache
ENV TRIVY_CACHE_DIR=/tmp/.cache/trivy
# gitpython raises ImportError on import when no git binary is present; quiet
# suppresses that — extensions that actually need git (sla-report) must have git
# available in their own environment or override this
ENV GIT_PYTHON_REFRESH=quiet

USER 10000:10000
