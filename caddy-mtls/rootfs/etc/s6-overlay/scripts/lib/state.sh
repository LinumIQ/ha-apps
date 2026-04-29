#!/usr/bin/env bash
# ==============================================================================
# Home Assistant Add-on: Caddy mTLS Proxy
# Helpers for /data/state.json (the source of truth for issued/revoked certs).
#
# Schema (version 1):
#   {
#     "version": 1,
#     "ca":     { serial, fingerprint_sha256, not_before, not_after,
#                 subject_cn, generated_at },
#     "server": { serial, fingerprint_sha256, not_before, not_after,
#                 domain, generated_at },
#     "clients": [
#       { "name": "...", "serial": "...", "fingerprint_sha256": "...",
#         "not_before": "...", "not_after": "...",
#         "status": "active"|"revoked",
#         "issued_at": "...", "revoked_at": null|"...",
#         "revocation_reason": null|"...",
#         "last_notified_threshold_days": null|<int> }
#     ],
#     "crl_number": <int>,
#     "crl_generated_at": "..."
#   }
#
# Concurrency: writers MUST hold an flock on STATE_LOCK while doing
# read-modify-write.  Readers can rely on the temp-file + atomic rename
# strategy used by `state_write`.
# ==============================================================================

readonly STATE_FILE="${STATE_FILE:-/data/state.json}"
readonly STATE_LOCK="${STATE_LOCK:-/data/state.json.lock}"

_state_log() {
    if command -v bashio::log.info >/dev/null 2>&1; then
        bashio::log.info "$*"
    else
        printf '[state] %s\n' "$*" >&2
    fi
}

###############################################################################
# Initialise an empty state file if missing.
###############################################################################
state_init() {
    if [[ -f "${STATE_FILE}" ]]; then
        # Migration: drop the legacy ".server" field that older versions
        # populated for the (now removed) auto-generated internal cert.
        if jq -e 'has("server")' < "${STATE_FILE}" >/dev/null 2>&1; then
            state_jq 'del(.server)'
        fi
        return 0
    fi
    touch "${STATE_LOCK}"
    cat > "${STATE_FILE}.tmp" <<'JSON'
{
  "version": 1,
  "ca": null,
  "clients": [],
  "crl_number": 0,
  "crl_generated_at": null
}
JSON
    mv "${STATE_FILE}.tmp" "${STATE_FILE}"
    chmod 600 "${STATE_FILE}"
}

###############################################################################
# Apply a jq filter to the state file in place (atomic).
# Usage: state_jq '<filter>' [--arg ...]
###############################################################################
state_jq() {
    touch "${STATE_LOCK}"
    {
        flock -x 9
        local tmp="${STATE_FILE}.tmp"
        jq "$@" < "${STATE_FILE}" > "${tmp}"
        mv "${tmp}" "${STATE_FILE}"
        chmod 600 "${STATE_FILE}"
    } 9>"${STATE_LOCK}"
}

###############################################################################
# Print the current ISO-8601 UTC timestamp.
###############################################################################
now_iso() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

###############################################################################
# Print metadata for a cert as a JSON object on stdout.
# Arguments:
#   $1 - cert path
###############################################################################
cert_meta_json() {
    local cert="$1"
    [[ -f "${cert}" ]] || { echo "null"; return 0; }

    local serial fp not_before not_after subj_cn
    serial="$(openssl x509 -in "${cert}" -noout -serial 2>/dev/null | sed 's/^serial=//' | tr 'a-f' 'A-F')" || return 1
    fp="$(openssl x509 -in "${cert}" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*Fingerprint=//')" || return 1
    # Use OpenSSL's ISO-8601 date formatter (OpenSSL 3.0+) so we don't have
    # to fight busybox `date -d`, which cannot parse OpenSSL's default
    # "Apr 26 15:20:18 2036 GMT" notation. The output is e.g.
    # "notBefore=2026-04-29 15:20:18Z" - normalise the space to a "T".
    not_before="$(openssl x509 -in "${cert}" -noout -startdate -dateopt iso_8601 2>/dev/null | sed -e 's/^notBefore=//' -e 's/ /T/')" || return 1
    not_after="$(openssl x509 -in "${cert}" -noout -enddate   -dateopt iso_8601 2>/dev/null | sed -e 's/^notAfter=//'  -e 's/ /T/')" || return 1
    subj_cn="$(openssl x509 -in "${cert}" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//' | tr ',' '\n' | grep -E '^CN=' | head -1 | sed 's/^CN=//')"

    local nb_iso="${not_before}" na_iso="${not_after}"

    jq -n \
        --arg serial "${serial}" \
        --arg fp "${fp}" \
        --arg nb "${nb_iso}" \
        --arg na "${na_iso}" \
        --arg cn "${subj_cn}" \
        '{serial: $serial, fingerprint_sha256: $fp, not_before: $nb, not_after: $na, subject_cn: $cn}'
}

###############################################################################
# Refresh the CA metadata in state.json from the cert files on disk.
###############################################################################
state_refresh_ca() {
    local meta
    meta="$(cert_meta_json "${CERT_DIR}/mTLS-CA.crt")"
    [[ "${meta}" == "null" ]] && return 0
    state_jq --argjson meta "${meta}" --arg ts "$(now_iso)" \
        '.ca = ($meta + {generated_at: (.ca.generated_at // $ts)})'
}

###############################################################################
# Refresh metadata for a single client (does NOT toggle status).
# Arguments:
#   $1 - client name
###############################################################################
state_refresh_client() {
    local name="$1"
    local meta
    meta="$(cert_meta_json "${CERT_DIR}/mTLS-client-${name}.crt")"
    [[ "${meta}" == "null" ]] && return 0
    local ts
    ts="$(now_iso)"
    state_jq --arg name "${name}" --argjson meta "${meta}" --arg ts "${ts}" \
        '
        if (.clients | map(.name) | index($name)) == null then
            .clients += [
                $meta + {
                    name: $name, status: "active",
                    issued_at: $ts, revoked_at: null,
                    revocation_reason: null,
                    last_notified_threshold_days: null
                }
            ]
        else
            .clients = (.clients | map(
                if .name == $name then
                    . + $meta
                else . end
            ))
        end'
}

###############################################################################
# Mark a client as revoked in state.json.
###############################################################################
state_mark_revoked() {
    local name="$1"
    local reason="${2:-unspecified}"
    local ts
    ts="$(now_iso)"
    state_jq --arg name "${name}" --arg reason "${reason}" --arg ts "${ts}" \
        '.clients = (.clients | map(
            if .name == $name then
                .status = "revoked" |
                .revoked_at = $ts |
                .revocation_reason = $reason
            else . end))'
}

###############################################################################
# Update CRL metadata (number + generated_at) from the CRL file on disk.
###############################################################################
state_refresh_crl() {
    local crl="${CERT_DIR}/mTLS-CA.crl"
    [[ -f "${crl}" ]] || return 0
    local crlnum
    crlnum="$(openssl crl -in "${crl}" -noout -crlnumber 2>/dev/null \
        | sed -e 's/^crlNumber=//' -e 's/^0x//')"
    crlnum="$(printf '%d' "0x${crlnum}" 2>/dev/null || echo 0)"
    state_jq --argjson n "${crlnum}" --arg ts "$(now_iso)" \
        '.crl_number = $n | .crl_generated_at = $ts'
}

###############################################################################
# Print active client names (one per line) from state.json.
###############################################################################
state_active_clients() {
    [[ -f "${STATE_FILE}" ]] || return 0
    jq -r '.clients[] | select(.status == "active") | .name' < "${STATE_FILE}"
}

###############################################################################
# Print all client names from state.json (active + revoked).
###############################################################################
state_all_clients() {
    [[ -f "${STATE_FILE}" ]] || return 0
    jq -r '.clients[].name' < "${STATE_FILE}"
}

###############################################################################
# Reset the state file to empty (used by full CA regen).
###############################################################################
state_reset() {
    rm -f "${STATE_FILE}"
    state_init
}
