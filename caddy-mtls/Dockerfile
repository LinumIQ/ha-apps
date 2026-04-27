# Home Assistant Add-on: Caddy mTLS Proxy
# Dockerfile for building Caddy with DNS modules
#
# Build args:
#   BUILD_FROM   - Home Assistant base image (provided by Supervisor for each arch).
#                  We declare a sensible default so plain `docker build` also works.
#   BUILD_ARCH   - Target arch label, set by Supervisor (informational).
#   BUILD_VERSION- Add-on version, set by Supervisor (informational).

ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:3.23
ARG BUILD_ARCH=amd64
ARG BUILD_VERSION=dev

# Build Caddy with DNS plugins on the build platform; cross-compile to TARGETOS/TARGETARCH.
FROM --platform=$BUILDPLATFORM golang:1.26.2-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH}

# Install xcaddy for building Caddy with plugins
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# Build Caddy with DNS provider modules
RUN xcaddy build v2.10.2 \
    --with github.com/caddy-dns/cloudflare \
    --with github.com/caddy-dns/route53 \
    --with github.com/caddy-dns/hetzner

# Final image
FROM $BUILD_FROM

# Install dependencies
RUN apk add --no-cache \
    openssl \
    bash \
    jq \
    libqrencode-tools \
    libcap

# Copy custom-built Caddy binary
COPY --from=builder /go/caddy /usr/bin/caddy

# Grant Caddy permission to bind to privileged ports
RUN setcap cap_net_bind_service=+ep /usr/bin/caddy

# Create directories
RUN mkdir -p /data/certs /data/caddy /data/www /etc/caddy

# Copy scripts and templates
COPY run.sh /
COPY generate-certs.sh /
COPY Caddyfile.template /etc/caddy/
COPY templates/ /templates/

# Make scripts executable
RUN chmod a+x /run.sh /generate-certs.sh

# Set working directory
WORKDIR /data

# Labels
LABEL \
    io.hass.name="Caddy mTLS Proxy" \
    io.hass.description="Caddy reverse proxy with mTLS authentication" \
    io.hass.type="addon" \
    io.hass.version="1.0.0"

# Entrypoint
CMD [ "/run.sh" ]
