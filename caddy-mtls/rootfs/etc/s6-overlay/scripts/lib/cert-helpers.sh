#!/usr/bin/env bash
# ==============================================================================
# Home Assistant Add-on: Caddy mTLS Proxy
# Certificate generation + revocation helpers (OpenSSL, ECDSA prime256v1).
#
# Sourced by:
#   /etc/s6-overlay/scripts/init-caddy
#   /usr/lib/cert-mgr/scripts/run.sh   (via subprocess from the FastAPI app)
#
# Required globals (env vars):
#   CERT_DIR
#   CA_COUNTRY, CA_STATE, CA_LOCALITY, CA_ORGANIZATION, CA_COMMON_NAME
#   CLIENT_CERT_PASSWORD
#   DOMAIN          (used as CRL_DOMAIN at issuance time)
#
# Validity (days), overridable via env:
#   CA       : 300 years  (109575 days)
#   Client   : 300 years  (109575 days)
# ==============================================================================

readonly CA_VALIDITY_DAYS="${CA_VALIDITY_DAYS:-109575}"
readonly CLIENT_VALIDITY_DAYS="${CLIENT_VALIDITY_DAYS:-109575}"
readonly CRL_VALIDITY_DAYS="${CRL_VALIDITY_DAYS:-30}"
readonly OPENSSL_CA_CNF="${OPENSSL_CA_CNF:-/etc/caddy/openssl-ca.cnf}"

# ---------------------------------------------------------------------------
# Logging fallback (works even when bashio is not loaded, e.g. when sourced
# by a non-bashio subprocess).
# ---------------------------------------------------------------------------
_ch_log() {
    if command -v bashio::log.info >/dev/null 2>&1; then
        bashio::log.info "$*"
    else
        printf '[cert-helpers] %s\n' "$*" >&2
    fi
}

_ch_die() {
    if command -v bashio::exit.nok >/dev/null 2>&1; then
        bashio::exit.nok "$*"
    else
        printf '[cert-helpers] FATAL: %s\n' "$*" >&2
        exit 1
    fi
}

###############################################################################
# Initialise the OpenSSL CA "database" (idempotent).
# Creates /data/certs/ca-db/{index.txt,index.txt.attr,serial,crlnumber,newcerts}
###############################################################################
init_ca_db() {
    local db_dir="${CERT_DIR}/ca-db"
    mkdir -p "${db_dir}/newcerts"

    [[ -f "${db_dir}/index.txt"      ]] || : > "${db_dir}/index.txt"
    [[ -f "${db_dir}/index.txt.attr" ]] || printf 'unique_subject = no\n' > "${db_dir}/index.txt.attr"
    [[ -f "${db_dir}/serial"         ]] || printf '1000\n' > "${db_dir}/serial"
    [[ -f "${db_dir}/crlnumber"      ]] || printf '1000\n' > "${db_dir}/crlnumber"

    chmod 700 "${db_dir}"
    chmod 600 "${db_dir}/index.txt" "${db_dir}/serial" "${db_dir}/crlnumber" \
              "${db_dir}/index.txt.attr" 2>/dev/null || true
}

###############################################################################
# Generate a self-signed CA certificate (ECDSA prime256v1).
###############################################################################
generate_ca() {
    local ca_key="${CERT_DIR}/mTLS-CA.key"
    local ca_crt="${CERT_DIR}/mTLS-CA.crt"

    if ! openssl ecparam -name prime256v1 -genkey -noout -out "${ca_key}"; then
        _ch_die "Failed to generate CA private key"
    fi

    if ! openssl req -new -x509 -sha256 \
            -key "${ca_key}" \
            -out "${ca_crt}" \
            -days "${CA_VALIDITY_DAYS}" \
            -subj "/C=${CA_COUNTRY}/ST=${CA_STATE}/L=${CA_LOCALITY}/O=${CA_ORGANIZATION}/CN=${CA_COMMON_NAME}"; then
        _ch_die "Failed to self-sign CA certificate"
    fi

    chmod 600 "${ca_key}"
    chmod 644 "${ca_crt}"
    init_ca_db
    _ch_log "CA certificate generated at ${ca_crt}"
}

###############################################################################
# Issue a client certificate via `openssl ca` and export PKCS#12.
# Arguments:
#   $1 - client name (used in CN and filename)
###############################################################################
generate_client_cert() {
    local client_name="$1"
    local client_key="${CERT_DIR}/mTLS-client-${client_name}.key"
    local client_csr="${CERT_DIR}/mTLS-client-${client_name}.csr"
    local client_crt="${CERT_DIR}/mTLS-client-${client_name}.crt"
    local client_p12="${CERT_DIR}/mTLS-client-${client_name}.p12"
    local ca_crt="${CERT_DIR}/mTLS-CA.crt"

    init_ca_db

    if ! openssl ecparam -name prime256v1 -genkey -noout -out "${client_key}"; then
        _ch_die "Failed to generate client private key for '${client_name}'"
    fi
    if ! openssl req -new -sha256 \
            -key "${client_key}" \
            -out "${client_csr}" \
            -subj "/C=${CA_COUNTRY}/ST=${CA_STATE}/L=${CA_LOCALITY}/O=${CA_ORGANIZATION}/CN=${client_name}"; then
        _ch_die "Failed to generate client CSR for '${client_name}'"
    fi

    SAN_DNS="DNS:${client_name}.invalid" \
    CRL_DOMAIN="${DOMAIN:-localhost}" \
    openssl ca -batch -notext \
        -config "${OPENSSL_CA_CNF}" \
        -extensions client_ext \
        -days "${CLIENT_VALIDITY_DAYS}" \
        -in "${client_csr}" \
        -out "${client_crt}" \
        || _ch_die "Failed to sign client certificate for '${client_name}'"

    if ! openssl pkcs12 -export \
            -out "${client_p12}" \
            -inkey "${client_key}" \
            -in "${client_crt}" \
            -certfile "${ca_crt}" \
            -name "${client_name}" \
            -passout "pass:${CLIENT_CERT_PASSWORD}" \
            -legacy; then
        _ch_die "Failed to export PKCS#12 for '${client_name}'"
    fi

    rm -f "${client_csr}"
    chmod 600 "${client_key}" "${client_p12}"
    chmod 644 "${client_crt}"
    _ch_log "Client certificate generated at ${client_p12}"
}

###############################################################################
# Revoke a certificate by serial number (hex, no 0x prefix, uppercase).
###############################################################################
revoke_cert_by_serial() {
    local serial="$1"
    local reason="${2:-unspecified}"
    local newcert_pem="${CERT_DIR}/ca-db/newcerts/${serial}.pem"

    # Normalize CRL reason: openssl wants camelCase RFC 5280 names.
    case "${reason}" in
        unspecified|keyCompromise|CACompromise|affiliationChanged|superseded|cessationOfOperation|certificateHold|removeFromCRL)
            : ;;
        key_compromise|key-compromise) reason="keyCompromise" ;;
        ca_compromise|ca-compromise) reason="CACompromise" ;;
        affiliation_changed|affiliation-changed) reason="affiliationChanged" ;;
        cessation_of_operation|cessation-of-operation) reason="cessationOfOperation" ;;
        certificate_hold|certificate-hold) reason="certificateHold" ;;
        remove_from_crl|remove-from-crl) reason="removeFromCRL" ;;
        *) reason="unspecified" ;;
    esac

    if [[ ! -f "${newcert_pem}" ]]; then
        _ch_log "WARNING: newcerts file '${newcert_pem}' missing; cannot revoke serial ${serial}"
        return 1
    fi

    local out
    if ! out="$(SAN_DNS="DNS:none" CRL_DOMAIN="none" \
            openssl ca -batch \
                -config "${OPENSSL_CA_CNF}" \
                -revoke "${newcert_pem}" \
                -crl_reason "${reason}" 2>&1)"; then
        if printf '%s' "${out}" | grep -qi 'Already revoked'; then
            _ch_log "Serial ${serial} already revoked"
            return 0
        fi
        _ch_log "Failed to revoke serial ${serial}: ${out}"
        return 1
    fi
    _ch_log "Revoked serial ${serial} (reason: ${reason})"
    return 0
}

###############################################################################
# Generate / refresh the CRL file.
###############################################################################
generate_crl() {
    local crl_path="${CERT_DIR}/mTLS-CA.crl"

    init_ca_db

    SAN_DNS="DNS:none" CRL_DOMAIN="none" \
    openssl ca -batch \
        -config "${OPENSSL_CA_CNF}" \
        -gencrl \
        -crldays "${CRL_VALIDITY_DAYS}" \
        -out "${crl_path}" \
        || _ch_die "Failed to generate CRL"
    chmod 644 "${crl_path}"
    _ch_log "CRL generated at ${crl_path}"
}

###############################################################################
# Read the serial of a cert (uppercase hex, no 0x prefix).
###############################################################################
cert_serial_hex() {
    local cert="$1"
    local raw
    raw="$(openssl x509 -in "${cert}" -noout -serial 2>/dev/null)" || return 1
    printf '%s' "${raw#serial=}" | tr 'a-f' 'A-F'
}

###############################################################################
# Revoke a client certificate by name.
###############################################################################
revoke_client_by_name() {
    local client_name="$1"
    local reason="${2:-unspecified}"
    local client_crt="${CERT_DIR}/mTLS-client-${client_name}.crt"
    local active_pem="${CERT_DIR}/active/mTLS-client-${client_name}.pem"
    local active_crt_legacy="${CERT_DIR}/active/mTLS-client-${client_name}.crt"

    if [[ ! -f "${client_crt}" ]]; then
        _ch_log "Client cert '${client_name}' not found, removing from active dir if present"
        rm -f "${active_pem}" "${active_crt_legacy}"
        return 0
    fi

    local serial
    serial="$(cert_serial_hex "${client_crt}")" \
        || { _ch_log "Could not parse serial of '${client_crt}'"; return 1; }

    revoke_cert_by_serial "${serial}" "${reason}" || return 1
    rm -f "${active_pem}" "${active_crt_legacy}"
    return 0
}

###############################################################################
# Populate (or rebuild) the active client cert allowlist directory used by
# Caddy's `verifier leaf folder` block.
###############################################################################
populate_active_dir() {
    local active_dir="${CERT_DIR}/active"
    mkdir -p "${active_dir}"
    chmod 755 "${active_dir}"

    # Caddy's leaf folder loader only reads files ending in .pem
    find "${active_dir}" -maxdepth 1 -type f \( -name '*.crt' -o -name '*.pem' \) -delete 2>/dev/null || true
    find "${active_dir}" -maxdepth 1 -type l -delete 2>/dev/null || true

    local name src
    for name in "$@"; do
        [[ -z "${name}" ]] && continue
        src="${CERT_DIR}/mTLS-client-${name}.crt"
        if [[ -f "${src}" ]]; then
            cp "${src}" "${active_dir}/mTLS-client-${name}.pem"
            chmod 644 "${active_dir}/mTLS-client-${name}.pem"
        fi
    done
}

###############################################################################
# Wipe everything under CERT_DIR (used by full CA regeneration).
###############################################################################
wipe_cert_dir() {
    if [[ -d "${CERT_DIR}" ]]; then
        find "${CERT_DIR}" -mindepth 1 -delete 2>/dev/null || true
    fi
    mkdir -p "${CERT_DIR}"
    chmod 700 "${CERT_DIR}"
}
