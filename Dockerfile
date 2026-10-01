FROM golang:1.27.1-alpine3.24@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS cbomkit-theia-builder
# renovate: datasource=github-releases depName=cbomkit/cbomkit-theia versioningTemplate=semver-coerced extractVersionTemplate=^v?(?<version>.*)$
ARG CBOMKIT_THEIA_VERSION=1.1.2
# Cache mounts: local BuildKit only — harmless no-op where unsupported (e.g. kaniko in CI)
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    apk add --no-cache git \
 && git clone --depth 1 --branch release/${CBOMKIT_THEIA_VERSION} https://github.com/cbomkit/cbomkit-theia.git /cbomkit-theia \
 && cd /cbomkit-theia && go mod download -x && go build -v

FROM python:3.14-alpine3.24@sha256:9e9fde4d32eedce0b661d9ab91e826b62dddf28e928c230ec55f1866cac66b01

# uv from its official image — no pip, no --break-system-packages
COPY --from=ghcr.io/astral-sh/uv:0.12.21@sha256:a7aed3216253ee804de3e2d8afa5073baa1a177335345d43845cd4165e43b711 /uv /uvx /usr/local/bin/

COPY src/malware/clamav_entrypoint.sh /
COPY src/malware/clamd.conf /etc/clamav/clamd.conf
COPY --from=cbomkit-theia-builder /cbomkit-theia/cbomkit-theia /usr/bin/cbomkit-theia

RUN apk add --no-cache \
    bash \
    ca-certificates \
    clamav \
    clamav-libunrar \
    curl \
    git \
    helm \
    postgresql16-client \
    syft \
 && curl https://aia.pki.co.sap.com/aia/SAP%20Global%20Root%20CA.crt -o \
    /usr/local/share/ca-certificates/SAP_Global_Root_CA.crt \
 && curl https://aia.pki.co.sap.com/aia/SAPNetCA_G2_2.crt -o \
    /usr/local/share/ca-certificates/SAPNetCA_G2_2.crt \
 && update-ca-certificates \
 && mkdir /freshclam \
 && chown clamav /freshclam

COPY --from=aquasec/trivy:latest@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969 /usr/local/bin/trivy /usr/local/bin/trivy

ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Workaround to pin versions for pip install with local deps 
COPY uv.lock pyproject.toml ./
RUN uv export --frozen --no-dev --no-emit-project --no-emit-workspace \
        --format=requirements-txt -o constraints.txt

ARG ODG_CORE_LIBS_VERSION
RUN --mount=type=bind,source=dist/,target=/dist \
    uv venv "$VIRTUAL_ENV" \
 && uv pip install --no-cache --find-links /dist \
        --constraint constraints.txt \
        odg-core-libs==${ODG_CORE_LIBS_VERSION} \
 && ln -sf /etc/ssl/certs/ca-certificates.crt "$(python -m certifi)"
