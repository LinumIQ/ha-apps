#!/usr/bin/env bash
# Home Assistant Add-on: Caddy mTLS Proxy
# Certificate generation functions using OpenSSL ECDSA (prime256v1)

###############################################################################
# Generate CA Certificate
# Creates a self-signed CA certificate valid for 100 years
###############################################################################
generate_ca() {
    local ca_key="$CERT_DIR/mTLS-CA.key"
    local ca_crt="$CERT_DIR/mTLS-CA.crt"

    # Generate CA private key
    openssl ecparam -name prime256v1 -genkey -noout -out "$ca_key"

    # Generate CA certificate
    openssl req -new -x509 -sha256 \
        -key "$ca_key" \
        -out "$ca_crt" \
        -days 36500 \
        -subj "/C=$CA_COUNTRY/ST=$CA_STATE/L=$CA_LOCALITY/O=$CA_ORGANIZATION/CN=$CA_COMMON_NAME"

    # Set permissions
    chmod 600 "$ca_key"
    chmod 644 "$ca_crt"

    bashio::log.info "CA certificate generated: $ca_crt"
}

###############################################################################
# Generate Server Certificate
# Creates a server certificate signed by the CA
# Arguments:
#   $1 - Domain name (FQDN)
###############################################################################
generate_server_cert() {
    local domain="$1"
    local server_key="$CERT_DIR/mTLS-server.key"
    local server_csr="$CERT_DIR/mTLS-server.csr"
    local server_crt="$CERT_DIR/mTLS-server.crt"
    local ca_key="$CERT_DIR/mTLS-CA.key"
    local ca_crt="$CERT_DIR/mTLS-CA.crt"

    # Create extensions file for SAN (Subject Alternative Name)
    local ext_file="$CERT_DIR/server.ext"
    cat > "$ext_file" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $domain
DNS.2 = *.$domain
EOF

    # Generate server private key
    openssl ecparam -name prime256v1 -genkey -noout -out "$server_key"

    # Generate CSR
    openssl req -new -sha256 \
        -key "$server_key" \
        -out "$server_csr" \
        -subj "/C=$CA_COUNTRY/ST=$CA_STATE/L=$CA_LOCALITY/O=$CA_ORGANIZATION/CN=$domain"

    # Sign the certificate with CA
    openssl x509 -req \
        -in "$server_csr" \
        -CA "$ca_crt" \
        -CAkey "$ca_key" \
        -CAcreateserial \
        -out "$server_crt" \
        -days 36500 \
        -sha256 \
        -extfile "$ext_file"

    # Clean up
    rm -f "$server_csr" "$ext_file"

    # Set permissions
    chmod 600 "$server_key"
    chmod 644 "$server_crt"

    bashio::log.info "Server certificate generated: $server_crt"
}

###############################################################################
# Generate Client Certificate
# Creates a client certificate signed by the CA and exports as PKCS#12
# Arguments:
#   $1 - Client name (used in CN and filename)
###############################################################################
generate_client_cert() {
    local client_name="$1"
    local client_key="$CERT_DIR/mTLS-client-${client_name}.key"
    local client_csr="$CERT_DIR/mTLS-client-${client_name}.csr"
    local client_crt="$CERT_DIR/mTLS-client-${client_name}.crt"
    local client_p12="$CERT_DIR/mTLS-client-${client_name}.p12"
    local ca_key="$CERT_DIR/mTLS-CA.key"
    local ca_crt="$CERT_DIR/mTLS-CA.crt"

    # Create extensions file for client certificate
    local ext_file="$CERT_DIR/client-${client_name}.ext"
    cat > "$ext_file" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth
EOF

    # Generate client private key
    openssl ecparam -name prime256v1 -genkey -noout -out "$client_key"

    # Generate CSR
    openssl req -new -sha256 \
        -key "$client_key" \
        -out "$client_csr" \
        -subj "/C=$CA_COUNTRY/ST=$CA_STATE/L=$CA_LOCALITY/O=$CA_ORGANIZATION/CN=$client_name"

    # Sign the certificate with CA
    openssl x509 -req \
        -in "$client_csr" \
        -CA "$ca_crt" \
        -CAkey "$ca_key" \
        -CAcreateserial \
        -out "$client_crt" \
        -days 36500 \
        -sha256 \
        -extfile "$ext_file"

    # Export to PKCS#12 format
    openssl pkcs12 -export \
        -out "$client_p12" \
        -inkey "$client_key" \
        -in "$client_crt" \
        -certfile "$ca_crt" \
        -passout "pass:$CLIENT_CERT_PASSWORD" \
        -legacy

    # Clean up CSR and extensions file (keep key and crt for potential re-export)
    rm -f "$client_csr" "$ext_file"

    # Set permissions
    chmod 600 "$client_key"
    chmod 644 "$client_crt"
    chmod 644 "$client_p12"

    bashio::log.info "Client certificate generated: $client_p12"
}

###############################################################################
# Regenerate CA (for certificate revocation)
# Removes all certificates and regenerates the CA
# WARNING: This will invalidate ALL existing client certificates!
###############################################################################
regenerate_ca() {
    bashio::log.warning "Regenerating CA - all existing certificates will be invalidated!"

    # Remove all existing certificates
    rm -f "$CERT_DIR"/*.key
    rm -f "$CERT_DIR"/*.crt
    rm -f "$CERT_DIR"/*.csr
    rm -f "$CERT_DIR"/*.p12
    rm -f "$CERT_DIR"/*.srl

    bashio::log.info "All certificates removed. Restart the add-on to generate new certificates."
}

###############################################################################
# List all client certificates
###############################################################################
list_client_certs() {
    bashio::log.info "Client certificates in $CERT_DIR:"

    for p12 in "$CERT_DIR"/mTLS-client-*.p12; do
        if [[ -f "$p12" ]]; then
            local name=$(basename "$p12" .p12 | sed 's/mTLS-client-//')
            local expiry=$(openssl pkcs12 -in "$p12" -passin "pass:$CLIENT_CERT_PASSWORD" -nokeys -legacy 2>/dev/null | \
                          openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
            bashio::log.info "  - $name (expires: $expiry)"
        fi
    done
}
