# shellcheck shell=bash disable=SC2034
# syntax=docker/dockerfile:1.7
ARG BUILD_FROM=ghcr.io/hassio-addons/base:20.1.0

# ---- Stage 1: Build a custom Caddy with DNS provider modules via xcaddy ----
# Cross-compile from the build platform to the target arch so users on slow
# Pi-class hardware are not forced to compile Go locally.
FROM --platform=$BUILDPLATFORM golang:1.25.1-alpine AS caddy-builder

ARG TARGETOS
ARG TARGETARCH
ARG CADDY_VERSION=v2.10.2
ARG XCADDY_VERSION=v0.4.4

ENV CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH}

# hadolint ignore=DL3018
RUN apk add --no-cache git ca-certificates

RUN go install "github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION}"

RUN xcaddy build "${CADDY_VERSION}" \
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
# jq, curl, tzdata, ca-certificates, s6-overlay and bashio. We only need the
# OpenSSL CLI for cert generation and libcap (for setcap on the Caddy binary).
# hadolint ignore=DL3018
RUN apk add --no-cache openssl libcap

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
        /etc/s6-overlay/s6-rc.d/init-caddy/up \
        /etc/s6-overlay/s6-rc.d/caddy/run \
        /etc/s6-overlay/s6-rc.d/caddy/finish

# Health monitoring is handled by the Home Assistant Supervisor watchdog
# (see config.yaml `watchdog:`); a Docker HEALTHCHECK would be ignored by
# Supervisor and only complicate plain `docker run` workflows.

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
    org.opencontainers.image.url="https://github.com/LinumIQ/home-assistant-addons" \
    org.opencontainers.image.source="${BUILD_REPOSITORY}" \
    org.opencontainers.image.documentation="https://github.com/LinumIQ/home-assistant-addons/blob/main/caddy-mtls/DOCS.md" \
    org.opencontainers.image.created=${BUILD_DATE} \
    org.opencontainers.image.revision=${BUILD_REF} \
    org.opencontainers.image.version=${BUILD_VERSION}
