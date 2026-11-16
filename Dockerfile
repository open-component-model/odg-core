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

FROM python:3.14-alpine3.24@sha256:eb2c62658b8d51bff0acc408504b76521d02030de56a8a3c1e830083e89b89d2

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
 && curl https://aia.pki.co.sap.com/aia/SAP%20Global%20Root%20CA.crt -o \
    /usr/local/share/ca-certificates/SAP_Global_Root_CA.crt \
 && curl https://aia.pki.co.sap.com/aia/SAPNetCA_G2_2.crt -o \
    /usr/local/share/ca-certificates/SAPNetCA_G2_2.crt \
 && update-ca-certificates \
 && mkdir /freshclam \
 && chown clamav /freshclam

COPY --from=aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb /usr/local/bin/trivy /usr/local/bin/trivy
# Alpine's syft (1.42) predates native Go FIPS 140 detection (`goCryptoSettings`, syft >= 1.51)
COPY --from=anchore/syft:v1.57.0@sha256:3c70e6d5979364cefdc22b51617a78fd264574d3bd6b4f84a351204147025e2a /syft /usr/local/bin/syft

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
 && ln -sf /etc/ssl/certs/ca-certificates.crt "$(python -m certifi)" \
 && python -m compileall -q "$VIRTUAL_ENV/lib"
