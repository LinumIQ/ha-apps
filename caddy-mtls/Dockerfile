# shellcheck shell=bash disable=SC2034
# syntax=docker/dockerfile:1.7
ARG BUILD_FROM=ghcr.io/hassio-addons/base:21.0.10

# ---- Stage 1: Build a custom Caddy with DNS provider modules via xcaddy ----
# The Home Assistant builder runs this under QEMU for non-native target
# architectures, so we build natively for the target platform. We deliberately
# avoid the BUILDPLATFORM/TARGETPLATFORM cross-compile pattern because it
# forces buildx into the docker-container driver, which does not load the
# resulting image into the local Docker daemon and thus breaks the HA
# builder's subsequent `docker tag` step.
# golang 1.27.3-alpine3.24, multi-arch index digest 2026-10-27
FROM golang:1.27.3-alpine3.24@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS caddy-builder

# Caddy 2.11.7: 2.11.6 fixed GHSA-6365-7ppr-5r92, 2.11.7 fixed 2.11.6's
# stream regressions. The DNS provider modules are pinned to release tags
# (Go's checksum database verifies their contents); all three implement the
# libdns v1 API that Caddy >= 2.10 requires. hetzner v2 is a new major
# version (module path .../hetzner/v2) for the Hetzner Console's Cloud DNS
# API; v1 implemented the deprecated DNS Console API (dns.hetzner.com).
ARG CADDY_VERSION=v2.11.7
ARG XCADDY_VERSION=v0.4.7
ARG CADDY_DNS_CLOUDFLARE=github.com/caddy-dns/cloudflare@v0.2.4
ARG CADDY_DNS_ROUTE53=github.com/caddy-dns/route53@v1.6.2
ARG CADDY_DNS_HETZNER=github.com/caddy-dns/hetzner/v2@v2.0.1

ENV CGO_ENABLED=0

# hadolint ignore=DL3018
RUN apk add --no-cache git ca-certificates

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

# Install xcaddy and immediately use it to build a custom Caddy binary
# (kept in a single RUN layer to satisfy hadolint DL3059 and because the
# intermediate xcaddy binary is not needed in the final builder image).
# The build fails unless the binary reports the pinned version and lists
# every DNS provider module (one grep per module, each must match).
RUN go install "github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION}" \
 && xcaddy build "${CADDY_VERSION}" \
        --with "${CADDY_DNS_CLOUDFLARE}" \
        --with "${CADDY_DNS_ROUTE53}" \
        --with "${CADDY_DNS_HETZNER}" \
        --output /caddy \
 && /caddy list-modules > /tmp/caddy-modules.txt \
 && grep -qx 'dns\.providers\.cloudflare' /tmp/caddy-modules.txt \
 && grep -qx 'dns\.providers\.route53' /tmp/caddy-modules.txt \
 && grep -qx 'dns\.providers\.hetzner' /tmp/caddy-modules.txt \
 && /caddy version | grep -q "^${CADDY_VERSION} " \
 && /caddy build-info | grep -E '^dep\s+github\.com/(caddy-dns|libdns)/'

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
#   - libcrypto3 + libssl3: the base image pins them in its apk world
#     (`libcrypto3=<ver>`, 3.5.9-r0 in base 21.0.10). Naming them here
#     replaces that pin, so they are upgraded together with `openssl`, which
#     always requires the exactly matching libraries from the current
#     repository. Today the pin equals the repository version (a no-op); the
#     names keep the build working once Alpine ships a newer OpenSSL than the
#     base image was built with (otherwise: "unable to select packages ...
#     breaks: openssl").
#   - python3 + a virtualenv with the cert-mgr panel's dependencies (FastAPI,
#     Starlette, uvicorn, Jinja2, python-multipart), installed by pip from
#     requirements.txt with --require-hashes (wheels only, no compiler; pip
#     itself is removed again in the same layer). Alpine's py3-* packages are
#     not used: Alpine 3.24 ships py3-starlette 1.1.0, below the 1.3.1
#     security minimum (see requirements.in).
# hadolint ignore=DL3018
RUN apk add --no-cache \
        libcrypto3 \
        libssl3 \
        openssl \
        libcap \
        python3

COPY requirements.txt /tmp/cert-mgr-requirements.txt

# PIP_EXTRA_INDEX_URL (set by the base image to Home Assistant's wheel index)
# is unset: only PyPI is consulted, exactly as when requirements.txt was
# generated.
RUN set -eux; \
    unset PIP_EXTRA_INDEX_URL; \
    python3 -m venv /usr/lib/cert-mgr/.venv; \
    /usr/lib/cert-mgr/.venv/bin/pip install --no-cache-dir --disable-pip-version-check \
        --require-hashes --only-binary=:all: -r /tmp/cert-mgr-requirements.txt; \
    /usr/lib/cert-mgr/.venv/bin/pip uninstall --yes --disable-pip-version-check pip; \
    rm -f /tmp/cert-mgr-requirements.txt; \
    /usr/lib/cert-mgr/.venv/bin/python3 -c 'import fastapi, jinja2, pydantic, python_multipart, starlette, uvicorn; print("fastapi", fastapi.__version__, "starlette", starlette.__version__, "pydantic", pydantic.__version__)'

# The panel and the expiry monitor run with the virtualenv's interpreter.
# Python never writes bytecode at runtime (the code is precompiled below).
ENV PATH="/usr/lib/cert-mgr/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1

# Install the custom Caddy build from the builder stage and grant it the
# capability to bind to privileged ports (80/443) without running as root.
COPY --from=caddy-builder /caddy /usr/bin/caddy
RUN setcap cap_net_bind_service=+ep /usr/bin/caddy \
 && /usr/bin/caddy version

# Pre-create directories used at runtime
RUN mkdir -p /data/certs /data/caddy /data/www /etc/caddy

# Copy the s6-overlay services, scripts and assets. The services are defined
# in /etc/s6-overlay/s6-rc.d and started through the `user` bundle in
# /etc/s6-overlay/user-bundles.d (s6-overlay >= 3.2.3.2, base image 21.x): a
# bundle left in s6-rc.d/user makes s6-overlay's rc.init rewrite it at every
# start (a write into /etc/s6-overlay, which the AppArmor profile is not meant
# to allow).
COPY rootfs /

# Normalise the permissions of everything copied from rootfs/ (the build
# context's modes depend on the checkout's umask; the base image keeps its own
# s6 services under /package, so these directories hold only this add-on's
# files and the base's bundle definitions), make every executable asset
# executable in one place and precompile the panel + monitor. The build fails
# on a base image whose s6-overlay does not start bundles from
# user-bundles.d (base < 21: none of the add-on's services would start).
RUN if [ -e /etc/s6-overlay/s6-rc.d/user ] \
        || [ ! -f /etc/s6-overlay/user-bundles.d/user/type ]; then \
        echo "BUILD_FROM: s6-overlay without user-bundles.d (need base 21.x)" >&2; \
        exit 1; \
    fi \
    && find /etc/s6-overlay/s6-rc.d /etc/s6-overlay/user-bundles.d /etc/s6-overlay/scripts \
        /etc/caddy /usr/lib/cert-mgr \
        -path /usr/lib/cert-mgr/.venv -prune \
        -o -type d -exec chmod 0755 {} + -o -type f -exec chmod 0644 {} + \
    && chmod a+x \
        /etc/s6-overlay/scripts/init-caddy \
        /etc/s6-overlay/scripts/lib/cert-helpers.sh \
        /etc/s6-overlay/scripts/lib/dns-provider.sh \
        /etc/s6-overlay/scripts/lib/state.sh \
        /etc/s6-overlay/s6-rc.d/init-caddy/up \
        /etc/s6-overlay/s6-rc.d/caddy/run \
        /etc/s6-overlay/s6-rc.d/caddy/finish \
        /etc/s6-overlay/s6-rc.d/cert-mgr/run \
        /etc/s6-overlay/s6-rc.d/cert-mgr/finish \
        /etc/s6-overlay/s6-rc.d/cert-monitor/run \
        /etc/s6-overlay/s6-rc.d/cert-monitor/finish \
    && /usr/lib/cert-mgr/.venv/bin/python3 -m compileall -q \
        /usr/lib/cert-mgr/app.py /usr/lib/cert-mgr/monitor.py

# Health monitoring: probe Caddy's local admin API and the cert-mgr
# ingress port. We deliberately avoid hitting the public HTTPS port
# because that would require a valid (ACME-issued) TLS certificate to
# be present, which isn't true during the brief startup window or when
# ACME challenges are temporarily failing - both of which are normal,
# recoverable conditions that should not flap the add-on.
# Exec form (hadolint DL3025); the shell is needed for the `&&` chain.
HEALTHCHECK --start-period=2m --interval=30s --timeout=10s --retries=3 \
    CMD ["/bin/sh", "-c", "curl --silent --fail --max-time 5 http://127.0.0.1:2019/config/ > /dev/null && curl --silent --fail --max-time 5 http://127.0.0.1:8099/_health > /dev/null || exit 1"]

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
