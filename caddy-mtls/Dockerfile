# shellcheck shell=bash disable=SC2034
# syntax=docker/dockerfile:1.7
ARG BUILD_FROM=ghcr.io/hassio-addons/base:20.1.0

# ---- Stage 1: Build a custom Caddy with DNS provider modules via xcaddy ----
# The Home Assistant builder runs this under QEMU for non-native target
# architectures, so we build natively for the target platform. We deliberately
# avoid the BUILDPLATFORM/TARGETPLATFORM cross-compile pattern because it
# forces buildx into the docker-container driver, which does not load the
# resulting image into the local Docker daemon and thus breaks the HA
# builder's subsequent `docker tag` step.
FROM golang:1.25.1-alpine AS caddy-builder

ARG CADDY_VERSION=v2.10.2
ARG XCADDY_VERSION=v0.4.4

ENV CGO_ENABLED=0

# hadolint ignore=DL3018
RUN apk add --no-cache git ca-certificates

# Install xcaddy and immediately use it to build a custom Caddy binary
# (kept in a single RUN layer to satisfy hadolint DL3059 and because the
# intermediate xcaddy binary is not needed in the final builder image).
RUN go install "github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION}" \
 && xcaddy build "${CADDY_VERSION}" \
        --with github.com/caddy-dns/cloudflare \
        --with github.com/caddy-dns/route53 \
        --with github.com/caddy-dns/hetzner \
        --output /caddy

# ---- Stage 2: Final image based on community add-ons base (s6-overlay v3) ----
# hadolint ignore=DL3006
FROM ${BUILD_FROM}

# Re-declare build args needed in the final stage
ARG BUILD_ARCH
ARG BUILD_DATE
ARG BUILD_DESCRIPTION="Caddy reverse proxy with mTLS authentication"
ARG BUILD_NAME="Caddy mTLS Proxy"
ARG BUILD_REF
ARG BUILD_REPOSITORY
ARG BUILD_VERSION

# Install runtime dependencies. The hassio-addons base already provides bash,
# jq, curl, tzdata, ca-certificates, s6-overlay and bashio. We need:
#   - openssl: cert generation / CRL management
#   - libcap:  setcap on the Caddy binary
#   - python3 + py3-pip: cert manager FastAPI app and expiry monitor
#   - py3-fastapi, py3-uvicorn, py3-jinja2: avoid pip-compiling at build time
# hadolint ignore=DL3018
RUN apk add --no-cache \
        openssl \
        libcap \
        python3 \
        py3-fastapi \
        py3-jinja2 \
        py3-python-multipart \
        uvicorn

# Install the custom Caddy build from the builder stage and grant it the
# capability to bind to privileged ports (80/443) without running as root.
COPY --from=caddy-builder /caddy /usr/bin/caddy
RUN setcap cap_net_bind_service=+ep /usr/bin/caddy \
 && /usr/bin/caddy version

# Pre-create directories used at runtime
RUN mkdir -p /data/certs /data/caddy /data/www /etc/caddy

# Copy the s6-overlay services, scripts and assets
COPY rootfs /

# Make every shell asset executable in one place
RUN chmod a+x \
        /etc/s6-overlay/scripts/init-caddy \
        /etc/s6-overlay/scripts/lib/cert-helpers.sh \
        /etc/s6-overlay/scripts/lib/state.sh \
        /etc/s6-overlay/s6-rc.d/init-caddy/up \
        /etc/s6-overlay/s6-rc.d/caddy/run \
        /etc/s6-overlay/s6-rc.d/caddy/finish \
        /etc/s6-overlay/s6-rc.d/cert-mgr/run \
        /etc/s6-overlay/s6-rc.d/cert-mgr/finish \
        /etc/s6-overlay/s6-rc.d/cert-monitor/run \
        /etc/s6-overlay/s6-rc.d/cert-monitor/finish

# Health monitoring: probe Caddy's local admin API and the cert-mgr
# ingress port. We deliberately avoid hitting the public HTTPS port
# because that would require a valid (ACME-issued) TLS certificate to
# be present, which isn't true during the brief startup window or when
# ACME challenges are temporarily failing - both of which are normal,
# recoverable conditions that should not flap the add-on.
HEALTHCHECK --start-period=2m --interval=30s --timeout=10s --retries=3 \
    CMD curl --silent --fail --max-time 5 http://127.0.0.1:2019/config/ > /dev/null \
        && curl --silent --fail --max-time 5 http://127.0.0.1:8099/_health > /dev/null \
        || exit 1

# OCI image labels
LABEL \
    io.hass.name="${BUILD_NAME}" \
    io.hass.description="${BUILD_DESCRIPTION}" \
    io.hass.arch="${BUILD_ARCH}" \
    io.hass.type="addon" \
    io.hass.version="${BUILD_VERSION}" \
    maintainer="LinumIQ <opensource@linumiq.com>" \
    org.opencontainers.image.title="${BUILD_NAME}" \
    org.opencontainers.image.description="${BUILD_DESCRIPTION}" \
    org.opencontainers.image.vendor="LinumIQ" \
    org.opencontainers.image.authors="LinumIQ <opensource@linumiq.com>" \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.url="https://github.com/LinumIQ/ha-apps" \
    org.opencontainers.image.source="${BUILD_REPOSITORY}" \
    org.opencontainers.image.documentation="https://github.com/LinumIQ/ha-apps/blob/main/caddy-mtls/DOCS.md" \
    org.opencontainers.image.created=${BUILD_DATE} \
    org.opencontainers.image.revision=${BUILD_REF} \
    org.opencontainers.image.version=${BUILD_VERSION}
