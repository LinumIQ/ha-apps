# Home Assistant Add-on: Caddy mTLS Proxy
# Dockerfile for building Caddy with DNS modules

ARG BUILD_FROM
FROM golang:1.25.5-alpine AS builder

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
