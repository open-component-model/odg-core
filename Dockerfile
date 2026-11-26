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
# Full BCI image with zypper — installs packages and builds the venv.
# Nothing from this stage's build tooling reaches the final image.
FROM registry.suse.com/bci/python:3.14@sha256:5ee77207d55d42d760ade2f24418dc01c216f2bfde0c5ce14977137d4f59dd2e AS installer

COPY --from=ghcr.io/astral-sh/uv:0.13.10@sha256:a3ea1357342c1a4bf9a0c53a3deb1b55379aefa037338d8113d5771efa01774f /uv /usr/local/bin/

RUN zypper --non-interactive install --no-recommends \
    clamav \
    libclamunrar12 \
    postgresql16 \
 && zypper --non-interactive clean --all \
 && mkdir -p /clamav-libs/usr/lib64 /clamav-libs/lib64 /pg-libs/usr/lib64 /pg-libs/lib64 \
 && for bin in /usr/sbin/clamd /usr/bin/freshclam; do \
        ldd "$bin" \
        | awk '/=>/ && !/vdso/ {print $3}' \
        | while read -r lib; do \
            case "$lib" in \
                /usr/lib64/*) cp --dereference "$lib" /clamav-libs/usr/lib64/ ;; \
                /lib64/*)     cp --dereference "$lib" /clamav-libs/lib64/ ;; \
            esac; \
          done; \
    done \
 && ldd /usr/lib/postgresql16/bin/pg_dump \
        | awk '/=>/ && !/vdso/ {print $3}' \
        | while read -r lib; do \
            case "$lib" in \
                /usr/lib64/*) cp --dereference "$lib" /pg-libs/usr/lib64/ ;; \
                /lib64/*)     cp --dereference "$lib" /pg-libs/lib64/ ;; \
            esac; \
          done

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


# ── Stage 3: final (micro) ────────────────────────────────────────────────────
# No package manager, no compiler, no shell — only the runtime.
FROM registry.suse.com/bci/python:3.14-micro@sha256:d7f871893926b3cdd81d21698c641c87db94be9a906feb626d6992f036988165

# Python venv
COPY --from=installer /opt/venv /opt/venv

# C++ runtime — required by venv C extensions (greenlet, psycopg, etc.)
COPY --from=installer /usr/lib64/libstdc++.so.6 /usr/lib64/
COPY --from=installer /usr/lib64/libgcc_s.so.1 /usr/lib64/

# Static Go binaries — no .so dependencies
COPY --from=aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb \
    /usr/local/bin/trivy /usr/local/bin/trivy
# Alpine's syft (1.42) predates native Go FIPS 140 detection (`goCryptoSettings`, syft >= 1.51)
COPY --from=anchore/syft:v1.57.2@sha256:e97e20b6e6d1699c60296b66ab337941724f9bd06ac279d893eda89601fc4b2a \
    /syft /usr/local/bin/syft
COPY --from=cbomkit-theia-builder /cbomkit-theia/cbomkit-theia /usr/local/bin/cbomkit-theia
COPY --from=installer /usr/lib/postgresql16/bin/pg_dump /usr/local/bin/pg_dump
COPY --from=installer /pg-libs/usr/lib64/ /usr/lib64/
COPY --from=installer /pg-libs/lib64/ /lib64/

# clamav binaries
COPY --from=installer /usr/sbin/clamd /usr/sbin/clamd
COPY --from=installer /usr/bin/freshclam /usr/bin/freshclam
# ClamAV code-signing cert — required by ClamAV 1.x to verify downloaded CVD signatures
COPY --from=installer /etc/certs/clamav.crt /etc/certs/clamav.crt

# clamav shared libraries — collected via ldd in installer stage
COPY --from=installer /clamav-libs/usr/lib64/ /usr/lib64/
COPY --from=installer /clamav-libs/lib64/ /lib64/
# libclamunrar is dlopen-loaded at runtime (not visible to ldd)
COPY --from=installer /usr/lib64/libclamunrar.so.12 /usr/lib64/
COPY --from=installer /usr/lib64/libclamunrar_iface.so.12 /usr/lib64/

# CA certificates (SUSE uses /var/lib/ca-certificates; certifi symlink points to ca-bundle.pem)
COPY --from=installer /var/lib/ca-certificates/ /var/lib/ca-certificates/
COPY --from=installer /etc/ssl/certs/ /etc/ssl/certs/
COPY --from=installer /etc/pki/trust/anchors/ /etc/pki/trust/anchors/

# ClamAV config and entrypoint
COPY src/malware/clamd.conf /etc/clamav/clamd.conf
COPY src/malware/clamav_entrypoint.py /clamav_entrypoint.py

# Runtime directories and unprivileged user
# micro has no useradd — write /etc/passwd and /etc/group entries directly
RUN sed -i 's|^root:.*|root:x:0:0:root:/root:/sbin/nologin|' /etc/passwd \
 && echo 'odg:x:10000:10000::/home/odg:/sbin/nologin' >> /etc/passwd \
 && echo 'odg:x:10000:' >> /etc/group \
 && mkdir -p /home/odg /freshclam /www /run/clamav /var/lib/clamav /var/log/clamav \
 && chown -R 10000:10000 /home/odg /freshclam /www /run/clamav /var/lib/clamav /var/log/clamav \
 && rm -f \
        /bin/bash /bin/sh /bin/rbash \
        /usr/bin/bash /usr/bin/sh /usr/bin/rbash \
        /usr/bin/python3.14 /usr/bin/python3 /usr/local/bin/python3 \
        /usr/bin/pip /usr/bin/pip3 /usr/bin/pip3.14 /usr/bin/pip-3.14 /usr/bin/pip3-3.14 \
        /usr/local/bin/pydoc /usr/bin/pydoc3.14 \
        /usr/bin/ldd /usr/bin/chroot /usr/bin/install

ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
# micro base ships a pre-built ld.so.cache that only covers /lib64/; libs
# copied into /usr/lib64/ at image-build time (clamav, pg, C++ runtime) are
# invisible to the cache.  LD_LIBRARY_PATH is checked before the cache so the
# dynamic linker finds them without ldconfig.
ENV LD_LIBRARY_PATH=/usr/lib64
# runtime-writable paths live in tmpfs/emptyDir mounts (/tmp covers caches via
# XDG_CACHE_HOME/TRIVY_CACHE_DIR); HOME itself stays read-only under
# readOnlyRootFilesystem
ENV HOME=/home/odg
ENV XDG_CACHE_HOME=/tmp/.cache
ENV TRIVY_CACHE_DIR=/tmp/.cache/trivy
# gitpython raises ImportError on import when no git binary is present; quiet
# suppresses that — extensions that actually need git (sla-report) must have git
# available in their own environment or override this
ENV GIT_PYTHON_REFRESH=quiet

USER 10000:10000
