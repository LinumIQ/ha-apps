#!/usr/bin/env bash
# ==============================================================================
# FRP Tunnel add-on - end-to-end harness (runs the add-on OUTSIDE Supervisor)
#
# Builds (or reuses) the add-on image, starts it with a temporary
# /data/options.json, drives the ingress panel over HTTP (start pairing ->
# read user_code -> approve -> poll until paired -> status), and verifies the
# state file, the rendered frpc.toml, the frpc process, the public URL and a
# few security properties. Prints PASS/FAIL per check. See README.md.
#
# Required env: APP_BASE API_BASE SERVER_ADDR SERVER_PORT DOMAIN_BASE
#               LOCAL_HOST LOCAL_PORT
# Approval:     E2E_APPROVE_CMD (gets the user_code appended as last argument)
#          or   E2E_EMAIL + E2E_PASSWORD + E2E_ANON_KEY [+ E2E_TOTP_SECRET]
# Optional:     DOCKER ADDON_IMAGE NETWORK and the E2E_* knobs in README.md
#
# There are NO built-in defaults for the stack (no silent production
# fallback): every required variable must be set explicitly.
#
# Exit status: 0 = all checks passed, 1 = at least one check failed,
#              2 = usage / configuration error.
# Do not run with `bash -x`: the trace would expose tokens. Tokens are never
# put on a command line (visible in `ps`): they are matched in-shell or via
# pattern files in the private (mode 700) work directory.
# ==============================================================================
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ADDON_DIR="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

APP_BASE="${APP_BASE:-}"
API_BASE="${API_BASE:-}"
SERVER_ADDR="${SERVER_ADDR:-}"
SERVER_PORT="${SERVER_PORT:-}"
DOMAIN_BASE="${DOMAIN_BASE:-}"
LOCAL_HOST="${LOCAL_HOST:-}"
LOCAL_PORT="${LOCAL_PORT:-}"
DOCKER="${DOCKER:-docker}"
NETWORK="${NETWORK:-}"
ADDON_IMAGE="${ADDON_IMAGE:-}"
BUILD_FROM="${E2E_BUILD_FROM:-ghcr.io/hassio-addons/base:20.1.0}"
BUILD_TAG="${E2E_BUILD_TAG:-frp-tunnel-e2e}"
PIN_SERVER="${E2E_PIN_SERVER:-1}"
KEEP_PAIRED="${E2E_KEEP_PAIRED:-0}"
KEEP_CONTAINER="${E2E_KEEP_CONTAINER:-0}"
ALLOWED_IPS="${E2E_ALLOWED_INGRESS_IPS:-127.0.0.1}"
BOOT_TIMEOUT="${E2E_BOOT_TIMEOUT:-90}"
PAIR_TIMEOUT="${E2E_PAIR_TIMEOUT:-180}"
FRPC_TIMEOUT="${E2E_FRPC_TIMEOUT:-60}"
PUBLIC_TIMEOUT="${E2E_PUBLIC_TIMEOUT:-180}"
PUBLIC_FROM="${E2E_PUBLIC_FROM:-host}"
PANEL="http://127.0.0.1:8099"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
CTR=""
WORK_DIR=""
UNPAIRED=false
SECRETS=()

# ------------------------------------------------------------------------------
# Output helpers
# ------------------------------------------------------------------------------
log() { printf '[e2e] %s\n' "$*" >&2; }
pass() { PASS_COUNT=$((PASS_COUNT + 1)); printf 'PASS  %s\n' "$1"; }
fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf 'FAIL  %s%s\n' "$1" "${2:+ -- $2}"
}
skip() { SKIP_COUNT=$((SKIP_COUNT + 1)); printf 'SKIP  %s%s\n' "$1" "${2:+ -- $2}"; }
check() { # check <name> <command...>: PASS if the command succeeds
    local name="$1"
    shift
    if "$@"; then pass "${name}"; else fail "${name}"; fi
}
usage() {
    cat >&2 <<'EOF'
usage: run.sh            (configured through the environment only)

Required:  APP_BASE API_BASE SERVER_ADDR SERVER_PORT DOMAIN_BASE LOCAL_HOST LOCAL_PORT
Approval:  E2E_APPROVE_CMD  or  E2E_EMAIL + E2E_PASSWORD + E2E_ANON_KEY [+ E2E_TOTP_SECRET(_FILE)]
Optional:  DOCKER ADDON_IMAGE NETWORK E2E_PIN_SERVER E2E_PUBLIC_FROM E2E_CURL_ARGS E2E_EXPECT
           E2E_KEEP_PAIRED E2E_KEEP_CONTAINER E2E_ALLOWED_INGRESS_IPS E2E_*_TIMEOUT E2E_BUILD_*
Exit:      0 all checks passed, 1 a check failed, 2 usage/configuration error
EOF
}
usage_error() { log "ERROR: $*"; usage; log "See ${SCRIPT_DIR}/README.md"; exit 2; }

case "${1:-}" in
    -h | --help) usage; exit 0 ;;
    "") ;;
    *) usage_error "unexpected argument '$1' (the harness takes no arguments)" ;;
esac

# Replace every known secret in stdin by <redacted>.
mask() {
    local line secret
    while IFS= read -r line || [[ -n "${line}" ]]; do
        for secret in "${SECRETS[@]+"${SECRETS[@]}"}"; do
            [[ -n "${secret}" ]] && line="${line//"${secret}"/<redacted>}"
        done
        printf '%s\n' "${line}"
    done
}

# Abort: remaining checks are meaningless (cleanup runs from the EXIT trap).
abort() {
    fail "$1" "${2:-}"
    summary
    exit 1
}

summary() {
    printf '\n%d passed, %d failed, %d skipped\n' "${PASS_COUNT}" "${FAIL_COUNT}" "${SKIP_COUNT}"
    if (( FAIL_COUNT > 0 )) && [[ -n "${CTR}" ]]; then
        log "last container log lines (secrets masked):"
        "${DOCKER}" logs --tail 80 "${CTR}" 2>&1 | mask >&2 || true
    fi
}

cleanup() {
    local rc=$?
    if [[ -n "${CTR}" ]]; then
        if [[ "${KEEP_CONTAINER}" == 1 ]]; then
            log "keeping container ${CTR} (E2E_KEEP_CONTAINER=1)"
        else
            # Best effort: revoke the device token server-side if a run was
            # interrupted while paired.
            if [[ "${UNPAIRED}" == false && "${KEEP_PAIRED}" != 1 ]] \
                && "${DOCKER}" exec "${CTR}" test -s /data/frp-state.json >/dev/null 2>&1; then
                "${DOCKER}" exec "${CTR}" curl -s -o /dev/null -X POST "${PANEL}/unpair" >/dev/null 2>&1 || true
            fi
            "${DOCKER}" rm -f "${CTR}" >/dev/null 2>&1 || true
        fi
    fi
    [[ -n "${WORK_DIR}" ]] && rm -rf "${WORK_DIR}"
    exit "${rc}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# ------------------------------------------------------------------------------
# Container helpers
# ------------------------------------------------------------------------------
cexec() { "${DOCKER}" exec "${CTR}" "$@"; }

# panel_code <METHOD> <path>: HTTP status code ("000" on transport errors)
panel_code() {
    cexec curl -s -o /dev/null -w '%{http_code}' -X "$1" "${PANEL}$2" 2>/dev/null || printf '000'
}

# panel_redirect <METHOD> <path>: "<code> <redirect-url>"
panel_redirect() {
    cexec curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -X "$1" "${PANEL}$2" 2>/dev/null \
        || printf '000 -'
}

# status_field <key>: field of GET /api/status (jq runs inside the container)
status_field() {
    # shellcheck disable=SC2016  # $1 / $k are expanded by the inner sh / jq
    cexec sh -c 'curl -fsS "$0/api/status" | jq -r --arg k "$1" ".[\$k] | if . == null then \"\" else tostring end"' \
        "${PANEL}" "$1" 2>/dev/null || true
}

# state_field <key>: field of /data/frp-state.json
state_field() {
    # shellcheck disable=SC2016
    cexec jq -r --arg k "$1" '.[$k] | if . == null then "" else tostring end' /data/frp-state.json 2>/dev/null || true
}

frpc_running() {
    local out up pid comm
    out="$(cexec s6-svstat -o up,pid /run/service/frpc 2>/dev/null)" || return 1
    read -r up pid <<<"${out}"
    [[ "${up}" == true && "${pid}" =~ ^[0-9]+$ ]] || return 1
    comm="$(cexec cat "/proc/${pid}/comm" 2>/dev/null)" || return 1
    [[ "${comm}" == frpc ]]
}

wait_for() { # wait_for <timeout-seconds> <command...>
    local timeout="$1" deadline
    shift
    deadline=$((SECONDS + timeout))
    until "$@"; do
        (( SECONDS >= deadline )) && return 1
        sleep 2
    done
}

# No `grep -q`: an early exit would SIGPIPE `docker logs` and, with
# pipefail, turn a match into a failure.
logs_contain() { "${DOCKER}" logs "${CTR}" 2>&1 | grep -F -- "$1" >/dev/null; }
# logs_contain_secret <file>: like logs_contain, but the pattern (a token) is
# read from a mode-600 file so it never appears in grep's argv.
logs_contain_secret() { "${DOCKER}" logs "${CTR}" 2>&1 | grep -F -f "$1" >/dev/null; }
# secret_file <name> <value>: write a secret into the private work directory.
secret_file() { printf '%s\n' "$2" >"${WORK_DIR}/$1"; printf '%s' "${WORK_DIR}/$1"; }
file_exists() { cexec test -s "$1"; }
file_absent() { ! cexec test -e "$1"; }
file_mode_is() { [[ "$(cexec stat -c '%a' "$1" 2>/dev/null)" == "$2" ]]; }
# In-shell match (no grep): the expected line may contain the tunnel token.
toml_has_line() {
    local line
    while IFS= read -r line; do
        [[ "${line}" == "$1" ]] && return 0
    done <<<"${TOML}"
    return 1
}
frpc_verify() { cexec frpc verify -c /data/frpc.toml >/dev/null 2>&1; }
state_gone() { file_absent /data/frp-state.json && file_absent /data/frpc.toml; }

# ------------------------------------------------------------------------------
# 0. Configuration
# ------------------------------------------------------------------------------
for var in APP_BASE API_BASE SERVER_ADDR SERVER_PORT DOMAIN_BASE LOCAL_HOST LOCAL_PORT; do
    [[ -n "${!var:-}" ]] || usage_error "${var} is required"
done
[[ "${SERVER_PORT}" =~ ^[0-9]+$ ]] || usage_error "SERVER_PORT must be numeric"
[[ "${LOCAL_PORT}" =~ ^[0-9]+$ ]] || usage_error "LOCAL_PORT must be numeric"
for var in APP_BASE API_BASE SERVER_ADDR DOMAIN_BASE LOCAL_HOST; do
    [[ "${!var}" =~ ^[A-Za-z0-9.:/_-]+$ ]] || usage_error "${var} contains unexpected characters"
done
APP_BASE="${APP_BASE%/}"
API_BASE="${API_BASE%/}"
if [[ -n "${E2E_APPROVE_CMD:-}" ]]; then
    APPROVAL="command"
elif [[ -n "${E2E_EMAIL:-}" && -n "${E2E_PASSWORD:-}" && -n "${E2E_ANON_KEY:-}" ]]; then
    APPROVAL="gotrue"
    command -v python3 >/dev/null || usage_error "python3 is required for GoTrue approval"
else
    usage_error "set E2E_APPROVE_CMD, or E2E_EMAIL + E2E_PASSWORD + E2E_ANON_KEY"
fi
command -v "${DOCKER}" >/dev/null || usage_error "container CLI '${DOCKER}' not found"
command -v curl >/dev/null || usage_error "curl is required"
read -r -a CURL_EXTRA <<<"${E2E_CURL_ARGS:-}"
[[ "${PUBLIC_FROM}" == host || "${PUBLIC_FROM}" == addon ]] || usage_error "E2E_PUBLIC_FROM must be host or addon"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/frp-tunnel-e2e.XXXXXX")"
log "app=${APP_BASE} api=${API_BASE} frps=${SERVER_ADDR}:${SERVER_PORT} domain_base=${DOMAIN_BASE}"
log "local=${LOCAL_HOST}:${LOCAL_PORT} network=${NETWORK:-<default>} approval=${APPROVAL} pin_server=${PIN_SERVER}"

# ------------------------------------------------------------------------------
# 1. Image
# ------------------------------------------------------------------------------
if [[ -n "${ADDON_IMAGE}" ]]; then
    IMAGE="${ADDON_IMAGE}"
    if "${DOCKER}" image inspect "${IMAGE}" >/dev/null 2>&1 || "${DOCKER}" pull "${IMAGE}" >/dev/null 2>&1; then
        pass "image available (${IMAGE})"
    else
        abort "image available (${IMAGE})"
    fi
else
    IMAGE="${BUILD_TAG}"
    case "$(uname -m)" in
        aarch64 | arm64) BUILD_ARCH_DEFAULT=aarch64 ;;
        *) BUILD_ARCH_DEFAULT=amd64 ;;
    esac
    BUILD_ARCH="${E2E_BUILD_ARCH:-${BUILD_ARCH_DEFAULT}}"
    log "building ${IMAGE} (BUILD_ARCH=${BUILD_ARCH}) from ${ADDON_DIR} ..."
    if "${DOCKER}" build --build-arg "BUILD_FROM=${BUILD_FROM}" --build-arg "BUILD_ARCH=${BUILD_ARCH}" \
        -t "${IMAGE}" "${ADDON_DIR}" >"${WORK_DIR}/build.log" 2>&1; then
        pass "image built (${IMAGE})"
    else
        tail -n 40 "${WORK_DIR}/build.log" >&2
        abort "image built (${IMAGE})"
    fi
fi

# ------------------------------------------------------------------------------
# 2. Container with a temporary /data/options.json
# ------------------------------------------------------------------------------
{
    printf '{\n  "log_level": "info",\n'
    printf '  "app_base": "%s",\n  "api_base": "%s",\n' "${APP_BASE}" "${API_BASE}"
    if [[ "${PIN_SERVER}" == 1 ]]; then
        printf '  "server_addr": "%s",\n  "server_port": %s,\n' "${SERVER_ADDR}" "${SERVER_PORT}"
        printf '  "domain_base": "%s",\n' "${DOMAIN_BASE}"
    fi
    printf '  "local_host": "%s",\n  "local_port": %s\n}\n' "${LOCAL_HOST}" "${LOCAL_PORT}"
} >"${WORK_DIR}/options.json"
# bashio::config (used by the base image's log-level oneshot) asks the
# Supervisor API, which does not exist here. Seed bashio's cache with the
# options so it never needs to; the add-on itself reads /data/options.json.
mkdir -p "${WORK_DIR}/bashio-cache"
cp "${WORK_DIR}/options.json" "${WORK_DIR}/bashio-cache/addons.self.options.config.cache"

CTR="frp-tunnel-e2e-$$-${RANDOM}"
create_args=(--name "${CTR}" -e "ALLOWED_INGRESS_IPS=${ALLOWED_IPS}")
[[ -n "${NETWORK}" ]] && create_args+=(--network "${NETWORK}")
if ! "${DOCKER}" create "${create_args[@]}" "${IMAGE}" >/dev/null; then
    CTR=""
    abort "container created"
fi
"${DOCKER}" cp "${WORK_DIR}/options.json" "${CTR}:/data/options.json" >/dev/null \
    || abort "options.json copied into the container"
"${DOCKER}" cp "${WORK_DIR}/bashio-cache" "${CTR}:/tmp/.bashio" >/dev/null \
    || abort "bashio option cache seeded"
"${DOCKER}" start "${CTR}" >/dev/null || abort "container started"
pass "container started (${CTR})"

panel_healthy() { [[ "$(cexec curl -fsS "${PANEL}/_health" 2>/dev/null)" == ok ]]; }
wait_for "${BOOT_TIMEOUT}" panel_healthy || abort "panel healthy on :8099" "no /_health within ${BOOT_TIMEOUT}s"
pass "panel healthy on :8099"

check "fresh add-on is not paired" test "$(status_field paired)" == false
check "frpc waits while unpaired" logs_contain "Not paired yet"

# The ingress guard must reject clients other than ALLOWED_INGRESS_IPS.
CTR_IP="$("${DOCKER}" inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "${CTR}" 2>/dev/null | awk '{print $1}')"
if [[ -n "${CTR_IP}" && "${CTR_IP}" != 127.* ]]; then
    code="$(cexec curl -s -o /dev/null -w '%{http_code}' "http://${CTR_IP}:8099/api/status" 2>/dev/null || printf '000')"
    check "ingress guard rejects ${CTR_IP} (HTTP ${code})" test "${code}" == 403
else
    skip "ingress guard rejects non-ingress clients" "container IP unknown"
fi

# ------------------------------------------------------------------------------
# 3. Pairing: start -> user_code -> approve -> poll
# ------------------------------------------------------------------------------
read -r code location <<<"$(panel_redirect POST /pair/start)"
if [[ "${code}" == 303 && "${location}" != *error=* ]]; then
    pass "pairing started (POST /pair/start -> 303)"
else
    abort "pairing started (POST /pair/start)" "HTTP ${code} ${location}"
fi
USER_CODE="$(status_field user_code)"
INTERVAL="$(status_field interval)"
[[ "${INTERVAL}" =~ ^[0-9]+$ ]] || INTERVAL=5
if [[ "${USER_CODE}" =~ ^[A-Z0-9]{4}-[A-Z0-9]{4}$ ]]; then
    pass "user_code shown (${USER_CODE})"
else
    abort "user_code shown" "got '${USER_CODE}'"
fi

export E2E_USER_CODE="${USER_CODE}"
if [[ "${APPROVAL}" == command ]]; then
    # The command string is run by bash with the user_code appended.
    if bash -c "${E2E_APPROVE_CMD} \"\$1\"" e2e-approve "${USER_CODE}"; then
        pass "device approved (E2E_APPROVE_CMD)"
    else
        abort "device approved (E2E_APPROVE_CMD)"
    fi
else
    if python3 "${SCRIPT_DIR}/approve.py" "${USER_CODE}"; then
        pass "device approved (GoTrue login + TOTP aal2)"
    else
        abort "device approved (GoTrue login + TOTP aal2)"
    fi
fi

POLL_STATUS=""
deadline=$((SECONDS + PAIR_TIMEOUT))
while (( SECONDS < deadline )); do
    # shellcheck disable=SC2016
    resp="$(cexec sh -c 'curl -sS -X POST "$0/pair/poll" | jq -r "(.status // \"\") + \"|\" + (.error // \"\")"' \
        "${PANEL}" 2>/dev/null || true)"
    POLL_STATUS="${resp%%|*}"
    case "${POLL_STATUS}" in
        paired) break ;;
        pending | slow_down | retry | "") sleep $((INTERVAL + 1)) ;;
        *) break ;;
    esac
done
if [[ "${POLL_STATUS}" == paired ]]; then
    pass "pairing completed (POST /pair/poll -> paired)"
else
    abort "pairing completed (POST /pair/poll)" "last answer: ${resp:-<none>}"
fi

# ------------------------------------------------------------------------------
# 4. Status, state file and frpc.toml
# ------------------------------------------------------------------------------
SUB="$(status_field subdomain)"
EXPECTED_HOST="${SUB}.${DOMAIN_BASE}"
check "status: paired" test "$(status_field paired)" == true
check "status: subdomain is a DNS label (${SUB})" grep -qE '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$' <<<"${SUB}"
check "status: public_url = https://${EXPECTED_HOST}" test "$(status_field public_url)" == "https://${EXPECTED_HOST}"
check "status: tls = true" test "$(status_field tls)" == true

TOKEN="$(state_field token)"
DEVICE_TOKEN="$(state_field device_token)"
SECRETS=("${TOKEN}" "${DEVICE_TOKEN}")
STATE_DOMAIN_BASE="$(state_field domain_base)"
check "state: subdomain = ${SUB}" test "$(state_field subdomain)" == "${SUB}"
check "state: token present (${#TOKEN} chars)" test "${#TOKEN}" -ge 16
check "state: device_token present (${#DEVICE_TOKEN} chars)" test "${#DEVICE_TOKEN}" -ge 16
check "state: server-provided domain_base present (${STATE_DOMAIN_BASE:-missing})" test -n "${STATE_DOMAIN_BASE}"
check "state: server-provided domain_base = ${DOMAIN_BASE}" test "${STATE_DOMAIN_BASE}" == "${DOMAIN_BASE}"
for key in server_addr server_port; do
    want="SERVER_ADDR"
    [[ "${key}" == server_port ]] && want="SERVER_PORT"
    got="$(state_field "${key}")"
    if [[ "${got}" == "${!want}" ]]; then
        pass "state: server-provided ${key} = ${got}"
    elif [[ "${PIN_SERVER}" == 1 ]]; then
        log "NOTE: server advertises ${key}=${got:-<none>}, test pins ${!want} (option override wins)"
    else
        fail "state: server-provided ${key} = ${!want}" "got ${got:-<none>}"
    fi
done
check "state file mode 600" file_mode_is /data/frp-state.json 600
check "pairing file removed" file_absent /data/frp-pairing.json

TOML="$(cexec cat /data/frpc.toml 2>/dev/null || true)"
check "frpc.toml: serverAddr = \"${SERVER_ADDR}\"" toml_has_line "serverAddr = \"${SERVER_ADDR}\""
check "frpc.toml: serverPort = ${SERVER_PORT}" toml_has_line "serverPort = ${SERVER_PORT}"
check "frpc.toml: customDomains = [\"${EXPECTED_HOST}\"]" toml_has_line "customDomains = [\"${EXPECTED_HOST}\"]"
check "frpc.toml: transport.tls.enable = true" toml_has_line "transport.tls.enable = true"
check "frpc.toml: loginFailExit = false" toml_has_line "loginFailExit = false"
check "frpc.toml: [metadatas] token = state token" toml_has_line "token = \"${TOKEN}\""
check "frpc.toml: localIP = \"${LOCAL_HOST}\"" toml_has_line "localIP = \"${LOCAL_HOST}\""
check "frpc.toml: localPort = ${LOCAL_PORT}" toml_has_line "localPort = ${LOCAL_PORT}"
check "frpc.toml mode 600" file_mode_is /data/frpc.toml 600
check "frpc.toml passes 'frpc verify'" frpc_verify

# ------------------------------------------------------------------------------
# 5. frpc process and frps login (TLS)
# ------------------------------------------------------------------------------
if wait_for "${FRPC_TIMEOUT}" frpc_running; then
    pass "frpc process up (s6-svstat up, pid is frpc)"
else
    fail "frpc process up (s6-svstat up, pid is frpc)"
fi
if wait_for "${FRPC_TIMEOUT}" logs_contain "login to server success"; then
    pass "frpc logged in to frps over TLS"
else
    fail "frpc logged in to frps over TLS"
fi
if wait_for "${FRPC_TIMEOUT}" logs_contain "start proxy success"; then
    pass "frps accepted the http proxy for ${EXPECTED_HOST}"
else
    fail "frps accepted the http proxy for ${EXPECTED_HOST}"
fi

# ------------------------------------------------------------------------------
# 6. Public URL serves the local service
# ------------------------------------------------------------------------------
EXPECT="${E2E_EXPECT:-}"
if [[ -z "${EXPECT}" ]]; then
    EXPECT="$(cexec curl -fsS --max-time 10 "http://${LOCAL_HOST}:${LOCAL_PORT}/" 2>/dev/null \
        | head -n 1 | tr -d '\r' || true)"
fi
if [[ -z "${EXPECT}" ]]; then
    fail "public URL serves ${LOCAL_HOST}:${LOCAL_PORT}" \
        "local service unreachable from the add-on container; set E2E_EXPECT"
else
    # The public request is made from the harness host (default) or from
    # inside the add-on container (E2E_PUBLIC_FROM=addon), e.g. when the
    # host cannot reach the edge proxy directly.
    public_curl() {
        if [[ "${PUBLIC_FROM}" == addon ]]; then
            cexec curl "$@"
        else
            curl "$@"
        fi
    }
    public_ok() {
        local body
        body="$(public_curl -sS --max-time 15 "${CURL_EXTRA[@]+"${CURL_EXTRA[@]}"}" \
            "https://${EXPECTED_HOST}/" 2>/dev/null)" || return 1
        grep -qF -- "${EXPECT}" <<<"${body}"
    }
    if wait_for "${PUBLIC_TIMEOUT}" public_ok; then
        pass "https://${EXPECTED_HOST}/ serves ${LOCAL_HOST}:${LOCAL_PORT} ('${EXPECT}')"
    else
        fail "https://${EXPECTED_HOST}/ serves ${LOCAL_HOST}:${LOCAL_PORT}" \
            "expected '${EXPECT}', last HTTP $(public_curl -s -o /dev/null -w '%{http_code}' --max-time 15 \
            "${CURL_EXTRA[@]+"${CURL_EXTRA[@]}"}" "https://${EXPECTED_HOST}/" 2>/dev/null || true)"
    fi
fi

# ------------------------------------------------------------------------------
# 7. Refresh + re-render on restart
# ------------------------------------------------------------------------------
HASH_BEFORE="$(cexec sha256sum /data/frpc.toml 2>/dev/null | awk '{print $1}')"
read -r code location <<<"$(panel_redirect POST /tunnel/refresh)"
if [[ "${code}" == 303 && "${location}" == *ok=* ]]; then
    pass "refresh tunnel config (POST /tunnel/refresh -> 303 ok)"
else
    fail "refresh tunnel config (POST /tunnel/refresh)" "HTTP ${code} ${location}"
fi
check "refresh kept frpc.toml unchanged" \
    test "$(cexec sha256sum /data/frpc.toml 2>/dev/null | awk '{print $1}')" == "${HASH_BEFORE}"

cexec rm -f /data/frpc.toml || true
cexec s6-svc -r /run/service/frpc || true
toml_back() { [[ "$(cexec sha256sum /data/frpc.toml 2>/dev/null | awk '{print $1}')" == "${HASH_BEFORE}" ]]; }
check "frpc restart re-renders frpc.toml from the state" wait_for "${FRPC_TIMEOUT}" toml_back
check "frpc up again after restart" wait_for "${FRPC_TIMEOUT}" frpc_running

# ------------------------------------------------------------------------------
# 8. Secrets never logged
# ------------------------------------------------------------------------------
if [[ -n "${TOKEN}" ]] && logs_contain_secret "$(secret_file token.pattern "${TOKEN}")"; then
    fail "tunnel token never logged"
else
    pass "tunnel token never logged"
fi
if [[ -n "${DEVICE_TOKEN}" ]] && logs_contain_secret "$(secret_file device-token.pattern "${DEVICE_TOKEN}")"; then
    fail "device token never logged"
else
    pass "device token never logged"
fi

# ------------------------------------------------------------------------------
# 9. Unpair (revokes the device token server-side)
# ------------------------------------------------------------------------------
if [[ "${KEEP_PAIRED}" == 1 ]]; then
    skip "unpair" "E2E_KEEP_PAIRED=1"
else
    read -r code location <<<"$(panel_redirect POST /unpair)"
    if [[ "${code}" == 303 && "${location}" == *ok=* ]]; then
        UNPAIRED=true
        pass "unpair (POST /unpair -> 303 ok)"
    else
        fail "unpair (POST /unpair)" "HTTP ${code} ${location}"
    fi
    check "unpair removed state + frpc.toml" state_gone
    not_running() { ! frpc_running; }
    check "frpc stopped after unpair" wait_for "${FRPC_TIMEOUT}" not_running
fi

summary
(( FAIL_COUNT == 0 ))
