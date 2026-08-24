FROM golang:1.26.6-alpine3.24 AS cbomkit-theia-builder
ARG CBOMKIT_THEIA_VERSION=1.0.1
RUN apk add --no-cache git \
 && git clone --branch ${CBOMKIT_THEIA_VERSION} https://github.com/IBM/cbomkit-theia.git /cbomkit-theia \
 && cd /cbomkit-theia && go mod download && go build

FROM python:3.12-alpine3.24

# uv from its official image — no pip, no --break-system-packages
COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /uvx /usr/local/bin/

COPY src/malware/clamav_entrypoint.sh /
COPY src/malware/clamd.conf /etc/clamav/clamd.conf
COPY --from=cbomkit-theia-builder /cbomkit-theia/cbomkit-theia /usr/bin/cbomkit-theia

RUN apk add --no-cache \
    bash=5.3.9-r1 \
    ca-certificates=20260611-r0 \
    clamav=1.4.6-r0 \
    clamav-libunrar=1.4.6-r0 \
    curl=8.21.0-r0 \
    git=2.54.0-r0 \
    helm=3.19.0-r7 \
    postgresql16-client=16.15-r0 \
    syft=1.42.4-r1 \
 && curl https://aia.pki.co.sap.com/aia/SAP%20Global%20Root%20CA.crt -o \
    /usr/local/share/ca-certificates/SAP_Global_Root_CA.crt \
 && curl https://aia.pki.co.sap.com/aia/SAPNetCA_G2_2.crt -o \
    /usr/local/share/ca-certificates/SAPNetCA_G2_2.crt \
 && update-ca-certificates \
 && mkdir /freshclam \
 && chown clamav /freshclam

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
