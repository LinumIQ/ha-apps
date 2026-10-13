ARG BUILD_FROM=ghcr.io/hassio-addons/base:20.1.0

# hadolint ignore=DL3006
FROM ${BUILD_FROM}

# Re-declare build args needed in the final stage
ARG BUILD_ARCH
ARG BUILD_DATE
ARG BUILD_DESCRIPTION="frpc client wrapping the fatedier/frp tunnel"
ARG BUILD_NAME="FRP Tunnel"
ARG BUILD_REF
ARG BUILD_REPOSITORY
ARG BUILD_VERSION

# Pinned upstream frp release (v0.65.x line) and the SHA-256 of each release
# tarball, as published in the release's frp_sha256_checksums.txt. Bumping
# FRP_VERSION requires updating both checksums; the build fails on a mismatch.
ARG FRP_VERSION=0.65.0
ARG FRP_SHA256_AMD64=52ced8c5fdf772f48a9909da4c10c7568c061861946ac9af7a86eeaf14b7e6d5
ARG FRP_SHA256_ARM64=d3e2be696d70b8e8dc475a81b8b5e4089f3a2acde5e42e47d6fc020fe3ddb180

# The hassio-addons base already provides bash, jq, curl, tzdata,
# ca-certificates, s6-overlay and bashio. Added here:
#   - frpc (upstream GitHub release, checksum-verified) and the unprivileged
#     `frpc` system user it runs as;
#   - python3 + a virtualenv with the panel's dependencies, installed by pip
#     from requirements.txt with --require-hashes (wheels only, no compiler;
#     pip itself is removed again in the same layer).
# hadolint ignore=DL3003
RUN set -eux; \
    case "${BUILD_ARCH}" in \
        amd64)   FRP_ARCH=linux_amd64; FRP_SHA256="${FRP_SHA256_AMD64}" ;; \
        aarch64) FRP_ARCH=linux_arm64; FRP_SHA256="${FRP_SHA256_ARM64}" ;; \
        *) echo "Unsupported BUILD_ARCH: ${BUILD_ARCH}" >&2; exit 1 ;; \
    esac; \
    cd /tmp; \
    curl -fsSLo frp.tar.gz \
        "https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_${FRP_ARCH}.tar.gz"; \
    printf '%s  frp.tar.gz\n' "${FRP_SHA256}" > frp.tar.gz.sha256; \
    sha256sum -c frp.tar.gz.sha256; \
    tar -xzf frp.tar.gz; \
    install -m 0755 "frp_${FRP_VERSION}_${FRP_ARCH}/frpc" /usr/bin/frpc; \
    rm -rf frp.tar.gz frp.tar.gz.sha256 "frp_${FRP_VERSION}_${FRP_ARCH}"; \
    /usr/bin/frpc --version; \
    addgroup -S frpc; \
    adduser -S -D -H -h /nonexistent -s /sbin/nologin -G frpc frpc

COPY requirements.txt /tmp/frp-mgr-requirements.txt

# hadolint ignore=DL3018
RUN set -eux; \
    apk add --no-cache python3; \
    python3 -m venv /usr/lib/frp-mgr/.venv; \
    /usr/lib/frp-mgr/.venv/bin/pip install --no-cache-dir --disable-pip-version-check \
        --require-hashes --only-binary=:all: -r /tmp/frp-mgr-requirements.txt; \
    /usr/lib/frp-mgr/.venv/bin/pip uninstall --yes --disable-pip-version-check pip; \
    rm -f /tmp/frp-mgr-requirements.txt; \
    /usr/lib/frp-mgr/.venv/bin/python3 -c 'import jinja2, python_multipart, starlette, uvicorn; print("starlette", starlette.__version__)'

# The panel and the renderer run with the virtualenv's interpreter. Python
# never writes bytecode at runtime (the code is precompiled below; the
# AppArmor profile does not allow writes under /usr).
ENV PATH="/usr/lib/frp-mgr/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1

# Copy the s6-overlay services and the frp-mgr panel / renderer
COPY rootfs /

# Normalise the permissions of everything copied from rootfs/ (the build
# context's modes depend on the checkout's umask; frpc runs unprivileged and
# must be able to traverse /etc), make every executable asset executable in
# one place, precompile the panel and pre-create the runtime data directory
# (bind-mounted by Supervisor; used as-is outside it).
RUN find /etc/s6-overlay/s6-rc.d /usr/lib/frp-mgr -path /usr/lib/frp-mgr/.venv -prune \
        -o -type d -exec chmod 0755 {} + -o -type f -exec chmod 0644 {} + \
    && chmod 0755 /etc /etc/s6-overlay /usr /usr/lib \
    && chmod a+x \
        /etc/s6-overlay/s6-rc.d/frpc/run \
        /etc/s6-overlay/s6-rc.d/frpc/finish \
        /etc/s6-overlay/s6-rc.d/frp-mgr/run \
        /etc/s6-overlay/s6-rc.d/frp-mgr/finish \
    && /usr/lib/frp-mgr/.venv/bin/python3 -m compileall -q /usr/lib/frp-mgr/app.py /usr/lib/frp-mgr/config.py \
    && mkdir -p /data

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
    org.opencontainers.image.documentation="https://github.com/LinumIQ/ha-apps/blob/main/frp-tunnel/DOCS.md" \
    org.opencontainers.image.created=${BUILD_DATE} \
    org.opencontainers.image.revision=${BUILD_REF} \
    org.opencontainers.image.version=${BUILD_VERSION}
