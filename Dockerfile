FROM golang:alpine AS cbomkit-theia-builder
ARG CBOMKIT_THEIA_VERSION=1.0.1
RUN apk add --no-cache git \
 && git clone --branch ${CBOMKIT_THEIA_VERSION} https://github.com/IBM/cbomkit-theia.git /cbomkit-theia \
 && cd /cbomkit-theia && go mod download && go build

FROM alpine:3

# uv from its official image — no pip, no --break-system-packages
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

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
    python3 \
    syft \
 && curl https://aia.pki.co.sap.com/aia/SAP%20Global%20Root%20CA.crt -o \
    /usr/local/share/ca-certificates/SAP_Global_Root_CA.crt \
 && curl https://aia.pki.co.sap.com/aia/SAPNetCA_G2_2.crt -o \
    /usr/local/share/ca-certificates/SAPNetCA_G2_2.crt \
 && update-ca-certificates \
 && mkdir /freshclam \
 && chown clamav /freshclam

ARG ODG_CORE_LIBS_VERSION
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
COPY dist/ /dist/
RUN uv venv "$VIRTUAL_ENV" \
 && uv pip install --no-cache --find-links /dist odg-core-libs==${ODG_CORE_LIBS_VERSION} \
 && rm -rf /dist
