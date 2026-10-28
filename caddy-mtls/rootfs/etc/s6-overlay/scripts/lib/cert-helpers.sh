#!/usr/bin/env bash
# ==============================================================================
# Home Assistant Add-on: Caddy mTLS Proxy
# Certificate generation + revocation helpers (OpenSSL, ECDSA prime256v1).
#
# Sourced by:
#   /etc/s6-overlay/scripts/init-caddy
#   /usr/lib/cert-mgr/app.py   (the panel, via `bash -c`)
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
# Run `openssl <args...>` and print its output (stdout and stderr) only if it
# fails: `openssl ca` writes a "Certificate Details" dump of every issued
# certificate and progress lines ("Using configuration from ...", "Database
# updated") to stderr, which would otherwise fill the add-on log. On failure
# the whole output goes to stderr, so the caller's error message is preceded
# by openssl's reason.
###############################################################################
_ch_openssl_quiet() {
    local out rc=0
    out="$(openssl "$@" 2>&1)" || rc=$?
    if (( rc != 0 )); then
        printf '%s\n' "${out}" >&2
    fi
    return "${rc}"
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
    _ch_openssl_quiet ca -batch -notext \
        -config "${OPENSSL_CA_CNF}" \
        -extensions client_ext \
        -days "${CLIENT_VALIDITY_DAYS}" \
        -in "${client_csr}" \
        -out "${client_crt}" \
        || _ch_die "Failed to sign client certificate for '${client_name}'"

    if ! _ch_export_p12 "${client_name}" "${client_p12}"; then
        _ch_die "Failed to export PKCS#12 for '${client_name}'"
    fi

    rm -f "${client_csr}"
    chmod 600 "${client_key}" "${client_p12}"
    chmod 644 "${client_crt}"
    _ch_log "Client certificate generated at ${client_p12}"
}

###############################################################################
# Export a client's PKCS#12 bundle (key + certificate + CA certificate),
# encrypted with CLIENT_CERT_PASSWORD. openssl reads the password from the
# environment, never from its command line (visible in /proc). `-legacy`
# (RC2/3DES): older Apple / Android importers need it; OpenSSL 3 opens such
# a bundle only with `-legacy` as well.
# Arguments:
#   $1 - client name
#   $2 - output file
###############################################################################
_ch_export_p12() {
    local client_name="$1" out="$2"
    CLIENT_CERT_PASSWORD="${CLIENT_CERT_PASSWORD:-}" openssl pkcs12 -export \
        -out "${out}" \
        -inkey "${CERT_DIR}/mTLS-client-${client_name}.key" \
        -in "${CERT_DIR}/mTLS-client-${client_name}.crt" \
        -certfile "${CERT_DIR}/mTLS-CA.crt" \
        -name "${client_name}" \
        -passout env:CLIENT_CERT_PASSWORD \
        -legacy
}

###############################################################################
# Does the client's .p12 bundle exist and open with the current
# CLIENT_CERT_PASSWORD? (Without `-legacy`, OpenSSL 3 cannot decrypt the
# RC2-40 certificate bag even with the right password.)
# Arguments:
#   $1 - client name
###############################################################################
client_p12_opens() {
    local client_p12="${CERT_DIR}/mTLS-client-$1.p12"
    [[ -s "${client_p12}" ]] || return 1
    CLIENT_CERT_PASSWORD="${CLIENT_CERT_PASSWORD:-}" openssl pkcs12 -legacy -noout \
        -in "${client_p12}" -passin env:CLIENT_CERT_PASSWORD >/dev/null 2>&1
}

###############################################################################
# Re-export a client's .p12 bundle from its key and certificate with the
# current CLIENT_CERT_PASSWORD (replaced atomically, mode 600). Returns 1 and
# leaves the bundle as it was if the key or certificate is missing or the
# export fails.
# Arguments:
#   $1 - client name
###############################################################################
reencrypt_client_p12() {
    local client_name="$1"
    local client_key="${CERT_DIR}/mTLS-client-${client_name}.key"
    local client_crt="${CERT_DIR}/mTLS-client-${client_name}.crt"
    local client_p12="${CERT_DIR}/mTLS-client-${client_name}.p12"
    local tmp="${client_p12}.tmp"

    [[ -s "${client_key}" && -s "${client_crt}" ]] || return 1
    rm -f "${tmp}"
    if ! _ch_export_p12 "${client_name}" "${tmp}" >/dev/null 2>&1; then
        rm -f "${tmp}"
        return 1
    fi
    chmod 600 "${tmp}"
    mv -f "${tmp}" "${client_p12}"
}

###############################################################################
# Is this a valid client name? 1-64 characters: letters, digits, '.', '_'
# and '-', not starting with a dot (no "." / ".." / hidden files). The same
# rule as the client_names option's schema (config.yaml) and the panel
# (app.py, CLIENT_NAME_RE).
# Arguments:
#   $1 - client name
###############################################################################
client_name_valid() {
    local LC_ALL=C
    [[ "$1" =~ ^[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}$ ]]
}

###############################################################################
# Is a serial (uppercase hex) marked revoked in the CA database?
###############################################################################
cert_serial_revoked() {
    local index="${CERT_DIR}/ca-db/index.txt"
    [[ -f "${index}" ]] || return 1
    awk -F '\t' -v serial="$1" \
        '$1 == "R" && toupper($4) == serial { found = 1 } END { exit !found }' "${index}"
}

###############################################################################
# Can a client certificate found on disk be adopted as it is (a client the
# state file does not know, e.g. after an interrupted issuance)? Its key and
# certificate exist, the certificate verifies against the current CA and it
# is not revoked in the CA database. (The .p12 bundle is checked separately,
# see client_p12_opens / reencrypt_client_p12.)
# Arguments:
#   $1 - client name
###############################################################################
client_cert_reusable() {
    local client_crt="${CERT_DIR}/mTLS-client-$1.crt"
    local serial
    [[ -s "${client_crt}" && -s "${CERT_DIR}/mTLS-client-$1.key" ]] || return 1
    openssl verify -CAfile "${CERT_DIR}/mTLS-CA.crt" "${client_crt}" >/dev/null 2>&1 || return 1
    serial="$(cert_serial_hex "${client_crt}")" || return 1
    ! cert_serial_revoked "${serial}"
}

###############################################################################
# Normalise a CRL reason: openssl wants the camelCase RFC 5280 names.
###############################################################################
_ch_crl_reason() {
    case "$1" in
        unspecified|keyCompromise|CACompromise|affiliationChanged|superseded|cessationOfOperation|certificateHold|removeFromCRL)
            printf '%s' "$1" ;;
        key_compromise|key-compromise) printf 'keyCompromise' ;;
        ca_compromise|ca-compromise) printf 'CACompromise' ;;
        affiliation_changed|affiliation-changed) printf 'affiliationChanged' ;;
        cessation_of_operation|cessation-of-operation) printf 'cessationOfOperation' ;;
        certificate_hold|certificate-hold) printf 'certificateHold' ;;
        remove_from_crl|remove-from-crl) printf 'removeFromCRL' ;;
        *) printf 'unspecified' ;;
    esac
}

###############################################################################
# Revoke a certificate file in the CA database. `openssl ca -revoke` also
# takes a certificate whose serial the database does not hold (no
# ca-db/newcerts copy, e.g. issued before the CA database existed): it adds
# the entry and revokes it in one step.
# Arguments:
#   $1 - certificate file (PEM) issued by this CA
#   $2 - CRL reason (default: unspecified)
###############################################################################
revoke_cert_file() {
    local cert="$1" reason serial out
    reason="$(_ch_crl_reason "${2:-unspecified}")"
    serial="$(cert_serial_hex "${cert}")" || serial="?"
    if ! out="$(SAN_DNS="DNS:none" CRL_DOMAIN="none" \
            openssl ca -batch \
                -config "${OPENSSL_CA_CNF}" \
                -revoke "${cert}" \
                -crl_reason "${reason}" 2>&1)"; then
        if [[ "${out}" == *"lready revoked"* ]]; then
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
# Revoke a certificate by serial number (uppercase hex, no 0x prefix) through
# the CA database's copy in ca-db/newcerts - the fallback when the client's
# own certificate file is gone.
###############################################################################
revoke_cert_by_serial() {
    local serial="$1"
    local reason="${2:-unspecified}"
    local newcert_pem="${CERT_DIR}/ca-db/newcerts/${serial}.pem"

    if [[ ! "${serial}" =~ ^[0-9A-F]+$ ]]; then
        _ch_log "WARNING: invalid serial '${serial}'"
        return 1
    fi
    if [[ ! -f "${newcert_pem}" ]]; then
        _ch_log "WARNING: newcerts file '${newcert_pem}' missing; cannot revoke serial ${serial}"
        return 1
    fi
    revoke_cert_file "${newcert_pem}" "${reason}"
}

###############################################################################
# Generate / refresh the CRL file.
###############################################################################
generate_crl() {
    local crl_path="${CERT_DIR}/mTLS-CA.crl"

    init_ca_db

    SAN_DNS="DNS:none" CRL_DOMAIN="none" \
    _ch_openssl_quiet ca -batch \
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
# Revoke a client certificate by name and remove it from the active/
# allowlist. The client's own certificate file is revoked; without it, the
# CA database's copy of the given serial (ca-db/newcerts). With neither, the
# serial cannot be added to the CRL: a warning is logged and the client is
# still removed from the allowlist (which is what Caddy enforces).
# Arguments:
#   $1 - client name
#   $2 - CRL reason (default: unspecified)
#   $3 - the client's serial from state.json (optional; used only when the
#        certificate file is missing)
###############################################################################
revoke_client_by_name() {
    local client_name="$1"
    local reason="${2:-unspecified}"
    local serial="${3:-}"
    local client_crt="${CERT_DIR}/mTLS-client-${client_name}.crt"
    local active_pem="${CERT_DIR}/active/mTLS-client-${client_name}.pem"
    local active_crt_legacy="${CERT_DIR}/active/mTLS-client-${client_name}.crt"

    if [[ -f "${client_crt}" ]]; then
        revoke_cert_file "${client_crt}" "${reason}" || return 1
    elif [[ "${serial}" =~ ^[0-9A-F]+$ && -f "${CERT_DIR}/ca-db/newcerts/${serial}.pem" ]]; then
        _ch_log "Client cert '${client_name}' not found, revoking serial ${serial} via the CA database copy"
        revoke_cert_by_serial "${serial}" "${reason}" || return 1
    else
        _ch_log "WARNING: no certificate file for client '${client_name}' (serial ${serial:-unknown}): it cannot be added to the CRL; removing it from the active allowlist"
    fi
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
