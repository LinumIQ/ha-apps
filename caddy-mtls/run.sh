#!/usr/bin/with-contenv bashio
# Home Assistant Add-on: Caddy mTLS Proxy
# Main entrypoint script

set -e

# Source certificate generation functions
source /generate-certs.sh

###############################################################################
# Read configuration from Home Assistant
###############################################################################

bashio::log.info "Reading configuration..."

DOMAIN=$(bashio::config 'domain')
EMAIL=$(bashio::config 'email')
UPSTREAM_HOST=$(bashio::config 'upstream_host')
UPSTREAM_PORT=$(bashio::config 'upstream_port')
MTLS_ENABLED=$(bashio::config 'mtls_enabled')

# CA subject fields
CA_COUNTRY=$(bashio::config 'ca_country')
CA_STATE=$(bashio::config 'ca_state')
CA_LOCALITY=$(bashio::config 'ca_locality')
CA_ORGANIZATION=$(bashio::config 'ca_organization')
CA_COMMON_NAME=$(bashio::config 'ca_common_name')

# Client certificate configuration
CLIENT_CERT_PASSWORD=$(bashio::config 'client_cert_password')

# ACME DNS configuration
ACME_DNS_PROVIDER=$(bashio::config 'acme_dns_provider')
DNS_API_TOKEN=$(bashio::config 'dns_api_token')

# Paths
CERT_DIR="/data/certs"
WWW_DIR="/data/www"
CADDY_DATA="/data/caddy"
CADDYFILE="/etc/caddy/Caddyfile"

# Create directories
mkdir -p "$CERT_DIR" "$WWW_DIR" "$CADDY_DATA"

###############################################################################
# Validate configuration
###############################################################################

if [[ -z "$DOMAIN" ]]; then
    bashio::log.fatal "Domain is required. Please configure the domain in add-on settings."
    exit 1
fi

if [[ -z "$EMAIL" ]]; then
    bashio::log.fatal "Email is required for Let's Encrypt. Please configure the email in add-on settings."
    exit 1
fi

if [[ "$ACME_DNS_PROVIDER" != "none" ]] && [[ -z "$DNS_API_TOKEN" ]]; then
    bashio::log.fatal "DNS API token is required when using DNS-01 challenge."
    exit 1
fi

###############################################################################
# Generate certificates if mTLS is enabled
###############################################################################

if bashio::var.true "$MTLS_ENABLED"; then
    bashio::log.info "mTLS is enabled, checking certificates..."

    # Export variables for generate-certs.sh
    export CERT_DIR CA_COUNTRY CA_STATE CA_LOCALITY CA_ORGANIZATION CA_COMMON_NAME DOMAIN CLIENT_CERT_PASSWORD

    # Generate CA if it doesn't exist
    if [[ ! -f "$CERT_DIR/mTLS-CA.crt" ]]; then
        bashio::log.info "Generating CA certificate..."
        generate_ca
    else
        bashio::log.info "CA certificate already exists"
    fi

    # Generate server certificate if it doesn't exist
    if [[ ! -f "$CERT_DIR/mTLS-server.crt" ]]; then
        bashio::log.info "Generating server certificate for $DOMAIN..."
        generate_server_cert "$DOMAIN"
    else
        bashio::log.info "Server certificate already exists"
    fi

    # Generate client certificates
    bashio::log.info "Processing client certificates..."

    for client_name in $(bashio::config 'client_names'); do
        if [[ ! -f "$CERT_DIR/mTLS-client-${client_name}.p12" ]]; then
            bashio::log.info "Generating client certificate for: $client_name"
            generate_client_cert "$client_name"
        else
            bashio::log.info "Client certificate already exists for: $client_name"
        fi

        # Copy .p12 to www directory for download
        cp "$CERT_DIR/mTLS-client-${client_name}.p12" "$WWW_DIR/"
    done

    # Copy CA certificate for download
    cp "$CERT_DIR/mTLS-CA.crt" "$WWW_DIR/"
fi

###############################################################################
# Generate download page for ingress
###############################################################################

bashio::log.info "Generating certificate download page..."

# Get ingress entry and ensure exactly one trailing slash (double-slash protection)
INGRESS_ENTRY="$(bashio::addon.ingress_entry)/"
INGRESS_ENTRY="${INGRESS_ENTRY%//}/"

# Get full ingress URL for QR codes (includes host)
INGRESS_URL="http://homeassistant.local:8123/"
INGRESS_URL="${INGRESS_URL%//}/"

# Start HTML
cat > "$WWW_DIR/index.html" << 'HTMLHEAD'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Caddy mTLS - Certificate Download</title>
    <style>
        :root {
            --primary-color: #03a9f4;
            --bg-color: #1c1c1c;
            --card-bg: #2d2d2d;
            --text-color: #ffffff;
            --text-muted: #9e9e9e;
        }
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }
        .container { max-width: 800px; margin: 0 auto; }
        h1 {
            color: var(--primary-color);
            border-bottom: 2px solid var(--primary-color);
            padding-bottom: 10px;
        }
        h2 { color: var(--text-color); margin-top: 30px; }
        .card {
            background: var(--card-bg);
            border-radius: 8px;
            padding: 20px;
            margin: 15px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        .client-card {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 20px;
        }
        .client-info { flex: 1; min-width: 200px; }
        .client-name {
            font-size: 1.2em;
            font-weight: bold;
            color: var(--primary-color);
        }
        .qr-code {
            background: white;
            padding: 10px;
            border-radius: 8px;
        }
        .qr-code img { display: block; width: 150px; height: 150px; }
        .download-btn {
            display: inline-block;
            background: var(--primary-color);
            color: white;
            padding: 10px 20px;
            border-radius: 4px;
            text-decoration: none;
            margin-top: 10px;
            transition: opacity 0.2s;
        }
        .download-btn:hover { opacity: 0.8; }
        .instructions {
            background: #3d3d3d;
            padding: 15px;
            border-radius: 4px;
            margin-top: 15px;
        }
        .instructions h3 { margin-top: 0; color: var(--primary-color); }
        .instructions ol { padding-left: 20px; }
        .muted { color: var(--text-muted); font-size: 0.9em; }
        code {
            background: #1c1c1c;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Caddy mTLS Certificates</h1>
HTMLHEAD

# Add mTLS status
if bashio::var.true "$MTLS_ENABLED"; then
    cat >> "$WWW_DIR/index.html" << HTMLSTATUS
        <p>mTLS authentication is <strong style="color: #4caf50;">enabled</strong> for <code>$DOMAIN</code></p>

        <h2>📜 CA Certificate</h2>
        <div class="card">
            <p>Install this CA certificate on devices that need to trust client certificates:</p>
            <a href="${INGRESS_ENTRY}mTLS-CA.crt" class="download-btn" download>⬇️ Download CA Certificate</a>
        </div>

        <h2>👤 Client Certificates</h2>
        <p class="muted">Each user needs their own .p12 file installed on their device.</p>
HTMLSTATUS

    # Generate client certificate cards with QR codes
    for client_name in $(bashio::config 'client_names'); do
        # Use full URL for QR codes (scannable), relative path for HTML links
        P12_URL_FULL="${INGRESS_URL}mTLS-client-${client_name}.p12"
        P12_URL="${INGRESS_ENTRY}mTLS-client-${client_name}.p12"

        # Generate QR code as base64 PNG (using full URL for scanning)
        QR_BASE64=$(echo -n "$P12_URL_FULL" | qrencode -t PNG -o - | base64 -w 0)
        bashio::log.info "QR URL: $P12_URL_FULL"

        cat >> "$WWW_DIR/index.html" << HTMLCLIENT
        <div class="card client-card">
            <div class="client-info">
                <div class="client-name">$client_name</div>
                <p class="muted">PKCS#12 certificate bundle</p>
                <a href="$P12_URL" class="download-btn" download>⬇️ Download .p12</a>
            </div>
            <div class="qr-code">
                <img src="data:image/png;base64,$QR_BASE64" alt="QR Code for $client_name">
                <p class="muted" style="text-align:center; margin: 5px 0 0 0; font-size: 0.8em;">Scan to download</p>
            </div>
        </div>
HTMLCLIENT
    done

    # Add import instructions
    cat >> "$WWW_DIR/index.html" << 'HTMLINSTRUCTIONS'
        <div class="instructions">
            <h3>📱 How to Import Certificates</h3>

            <h4>iOS / iPadOS</h4>
            <ol>
                <li>Download the .p12 file (or scan QR code)</li>
                <li>Go to Settings → Profile Downloaded</li>
                <li>Install the profile and enter the certificate password</li>
                <li>Go to Settings → General → About → Certificate Trust Settings</li>
                <li>Enable full trust for the CA certificate</li>
            </ol>

            <h4>Android</h4>
            <ol>
                <li>Download the .p12 file</li>
                <li>Go to Settings → Security → Encryption & credentials</li>
                <li>Tap "Install a certificate" → "VPN & app user certificate"</li>
                <li>Select the downloaded .p12 file and enter the password</li>
            </ol>

            <h4>Windows</h4>
            <ol>
                <li>Download the .p12 file</li>
                <li>Double-click the file to open Certificate Import Wizard</li>
                <li>Select "Current User" and click Next</li>
                <li>Enter the certificate password</li>
                <li>Let Windows automatically select the certificate store</li>
            </ol>

            <h4>macOS</h4>
            <ol>
                <li>Download the .p12 file</li>
                <li>Double-click to open in Keychain Access</li>
                <li>Enter the certificate password when prompted</li>
                <li>The certificate will be added to your login keychain</li>
            </ol>

            <h4>Linux (Firefox)</h4>
            <ol>
                <li>Download the .p12 file</li>
                <li>Go to Settings → Privacy & Security → Certificates</li>
                <li>Click "View Certificates" → "Your Certificates" tab</li>
                <li>Click "Import" and select the .p12 file</li>
                <li>Enter the certificate password</li>
            </ol>
        </div>
HTMLINSTRUCTIONS

else
    cat >> "$WWW_DIR/index.html" << 'HTMLDISABLED'
        <div class="card">
            <p>⚠️ mTLS authentication is <strong style="color: #ff9800;">disabled</strong>.</p>
            <p>Enable mTLS in the add-on configuration to generate client certificates.</p>
        </div>
HTMLDISABLED
fi

# Close HTML
cat >> "$WWW_DIR/index.html" << 'HTMLFOOT'
    </div>
</body>
</html>
HTMLFOOT

bashio::log.info "Download page generated at $WWW_DIR/index.html"

###############################################################################
# Generate Caddyfile from template
###############################################################################

bashio::log.info "Generating Caddyfile..."

# Determine TLS configuration
TLS_CONFIG=""
if [[ "$ACME_DNS_PROVIDER" == "cloudflare" ]]; then
    TLS_CONFIG="dns cloudflare $DNS_API_TOKEN"
elif [[ "$ACME_DNS_PROVIDER" == "route53" ]]; then
    TLS_CONFIG="dns route53 $DNS_API_TOKEN"
elif [[ "$ACME_DNS_PROVIDER" == "hetzner" ]]; then
    TLS_CONFIG="dns hetzner $DNS_API_TOKEN"
fi

# Determine mTLS client auth configuration
MTLS_CONFIG=""
if bashio::var.true "$MTLS_ENABLED"; then
    MTLS_CONFIG="client_auth {
            mode require_and_verify
            trusted_ca_cert_file $CERT_DIR/mTLS-CA.crt
        }"
fi

# Generate Caddyfile
cat > "$CADDYFILE" << CADDYFILE
# Caddy mTLS Proxy - Auto-generated configuration
# Do not edit manually - changes will be overwritten on restart

{
    # Global options
    email $EMAIL

    # Caddy data directory
    storage file_system {
        root $CADDY_DATA
    }

    # Admin API (disabled for security)
    admin off
}

# Main HTTPS site with mTLS
$DOMAIN {
    tls {
        $TLS_CONFIG
        $MTLS_CONFIG
    }

    # Reverse proxy to Home Assistant
    reverse_proxy $UPSTREAM_HOST:$UPSTREAM_PORT {
        # WebSocket support
        header_up Host {host}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }

    # Logging
    log {
        output stdout
        format console
        level INFO
    }
}

# Ingress server for certificate downloads
:8099 {
    # Only accept connections from Home Assistant ingress
    @blocked not remote_ip 172.30.32.2
    abort @blocked

    # Serve static files
    root * $WWW_DIR
    file_server

    # Logging
    log {
        output stdout
        format console
        level INFO
    }
}
CADDYFILE

bashio::log.info "Caddyfile generated at $CADDYFILE"

###############################################################################
# Copy certificates to addon_config for alternative access
###############################################################################

bashio::log.info "Copying certificates to addon_config..."

if [[ -d "/config" ]]; then
    mkdir -p /config/certs

    if bashio::var.true "$MTLS_ENABLED"; then
        cp "$CERT_DIR/mTLS-CA.crt" /config/certs/ 2>/dev/null || true

        for client_name in $(bashio::config 'client_names'); do
            cp "$CERT_DIR/mTLS-client-${client_name}.p12" /config/certs/ 2>/dev/null || true
        done

        bashio::log.info "Certificates copied to /config/certs/"
        bashio::log.info "Access via: /addon_configs/local_caddy_mtls/certs/"
    fi
fi

###############################################################################
# Start Caddy
###############################################################################

bashio::log.info "Starting Caddy..."
bashio::log.info "Domain: $DOMAIN"
bashio::log.info "Upstream: $UPSTREAM_HOST:$UPSTREAM_PORT"
bashio::log.info "mTLS: $MTLS_ENABLED"
bashio::log.info "ACME DNS Provider: $ACME_DNS_PROVIDER"

exec caddy run --config "$CADDYFILE"
