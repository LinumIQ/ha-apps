#!/usr/bin/env bash
# ==============================================================================
# Home Assistant Add-on: Caddy mTLS Proxy
# Certificate generation helpers (OpenSSL, ECDSA prime256v1)
#
# This file is sourced by /etc/s6-overlay/scripts/init-caddy and expects the
# following globals to already be set:
#   CERT_DIR
#   CA_COUNTRY, CA_STATE, CA_LOCALITY, CA_ORGANIZATION, CA_COMMON_NAME
#   CLIENT_CERT_PASSWORD
#
# Certificate validity (years/days):
#   CA       : 10 years   (3650 days)
#   Server   : 1  year    (365  days; intermediate, regenerated on demand)
#   Client   : 5  years   (1826 days)
# ==============================================================================

readonly CA_VALIDITY_DAYS="${CA_VALIDITY_DAYS:-3650}"
readonly SERVER_VALIDITY_DAYS="${SERVER_VALIDITY_DAYS:-365}"
readonly CLIENT_VALIDITY_DAYS="${CLIENT_VALIDITY_DAYS:-1826}"

###############################################################################
# Generate a self-signed CA certificate (ECDSA prime256v1).
###############################################################################
generate_ca() {
    local ca_key="${CERT_DIR}/mTLS-CA.key"
    local ca_crt="${CERT_DIR}/mTLS-CA.crt"

    if ! openssl ecparam -name prime256v1 -genkey -noout -out "${ca_key}"; then
        bashio::exit.nok "Failed to generate CA private key"
    fi

    if ! openssl req -new -x509 -sha256 \
            -key "${ca_key}" \
            -out "${ca_crt}" \
            -days "${CA_VALIDITY_DAYS}" \
            -subj "/C=${CA_COUNTRY}/ST=${CA_STATE}/L=${CA_LOCALITY}/O=${CA_ORGANIZATION}/CN=${CA_COMMON_NAME}"; then
        bashio::exit.nok "Failed to self-sign CA certificate"
    fi

    chmod 600 "${ca_key}"
    chmod 644 "${ca_crt}"
    bashio::log.info "CA certificate generated at ${ca_crt}"
}

###############################################################################
# Generate a server certificate signed by the CA.
# Arguments:
#   $1 - FQDN
###############################################################################
generate_server_cert() {
    local domain="$1"
    local server_key="${CERT_DIR}/mTLS-server.key"
    local server_csr="${CERT_DIR}/mTLS-server.csr"
    local server_crt="${CERT_DIR}/mTLS-server.crt"
    local ca_key="${CERT_DIR}/mTLS-CA.key"
    local ca_crt="${CERT_DIR}/mTLS-CA.crt"
    local ext_file="${CERT_DIR}/server.ext"

    cat > "${ext_file}" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment,dataEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names

[alt_names]
DNS.1 = ${domain}
DNS.2 = *.${domain}
EOF

    if ! openssl ecparam -name prime256v1 -genkey -noout -out "${server_key}"; then
        bashio::exit.nok "Failed to generate server private key"
    fi
    if ! openssl req -new -sha256 \
            -key "${server_key}" \
            -out "${server_csr}" \
            -subj "/C=${CA_COUNTRY}/ST=${CA_STATE}/L=${CA_LOCALITY}/O=${CA_ORGANIZATION}/CN=${domain}"; then
        bashio::exit.nok "Failed to generate server CSR"
    fi
    if ! openssl x509 -req \
            -in "${server_csr}" \
            -CA "${ca_crt}" -CAkey "${ca_key}" -CAcreateserial \
            -out "${server_crt}" \
            -days "${SERVER_VALIDITY_DAYS}" \
            -sha256 \
            -extfile "${ext_file}"; then
        bashio::exit.nok "Failed to sign server certificate"
    fi

    rm -f "${server_csr}" "${ext_file}"
    chmod 600 "${server_key}"
    chmod 644 "${server_crt}"
    bashio::log.info "Server certificate generated at ${server_crt}"
}

###############################################################################
# Generate a client certificate signed by the CA and export to PKCS#12.
# Arguments:
#   $1 - client name (used in CN and filename)
###############################################################################
generate_client_cert() {
    local client_name="$1"
    local client_key="${CERT_DIR}/mTLS-client-${client_name}.key"
    local client_csr="${CERT_DIR}/mTLS-client-${client_name}.csr"
    local client_crt="${CERT_DIR}/mTLS-client-${client_name}.crt"
    local client_p12="${CERT_DIR}/mTLS-client-${client_name}.p12"
    local ca_key="${CERT_DIR}/mTLS-CA.key"
    local ca_crt="${CERT_DIR}/mTLS-CA.crt"
    local ext_file="${CERT_DIR}/client-${client_name}.ext"

    cat > "${ext_file}" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment,dataEncipherment
extendedKeyUsage=clientAuth
EOF

    if ! openssl ecparam -name prime256v1 -genkey -noout -out "${client_key}"; then
        bashio::exit.nok "Failed to generate client private key for '${client_name}'"
    fi
    if ! openssl req -new -sha256 \
            -key "${client_key}" \
            -out "${client_csr}" \
            -subj "/C=${CA_COUNTRY}/ST=${CA_STATE}/L=${CA_LOCALITY}/O=${CA_ORGANIZATION}/CN=${client_name}"; then
        bashio::exit.nok "Failed to generate client CSR for '${client_name}'"
    fi
    if ! openssl x509 -req \
            -in "${client_csr}" \
            -CA "${ca_crt}" -CAkey "${ca_key}" -CAcreateserial \
            -out "${client_crt}" \
            -days "${CLIENT_VALIDITY_DAYS}" \
            -sha256 \
            -extfile "${ext_file}"; then
        bashio::exit.nok "Failed to sign client certificate for '${client_name}'"
    fi

    # Export PKCS#12 with -legacy so iOS / Android importers (which still
    # expect older PBE algorithms) can open the file.
    if ! openssl pkcs12 -export \
            -out "${client_p12}" \
            -inkey "${client_key}" \
            -in "${client_crt}" \
            -certfile "${ca_crt}" \
            -name "${client_name}" \
            -passout "pass:${CLIENT_CERT_PASSWORD}" \
            -legacy; then
        bashio::exit.nok "Failed to export PKCS#12 for '${client_name}'"
    fi

    rm -f "${client_csr}" "${ext_file}"
    chmod 600 "${client_key}" "${client_p12}"
    chmod 644 "${client_crt}"
    bashio::log.info "Client certificate generated at ${client_p12}"
}
