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
# Server verification (v2.2): E2E_FRPS_CA_FILE (PEM of the CA that signed the
#               frps certificate) [+ E2E_FRPS_SERVER_NAME, E2E_TLS_NEGATIVE]
# Optional:     DOCKER ADDON_IMAGE NETWORK E2E_CREATE_ARGS and the E2E_* knobs
#               in README.md
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
BUILD_FROM="${E2E_BUILD_FROM:-ghcr.io/hassio-addons/base:21.0.10}"
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
CA_FILE="${E2E_FRPS_CA_FILE:-}"
EXPECT_SERVER_NAME="${E2E_FRPS_SERVER_NAME:-}"
TLS_NEGATIVE="${E2E_TLS_NEGATIVE:-1}"
EXPECT_ACCOUNT="${E2E_ACCOUNT_EMAIL_MASKED:-}"
PANEL="http://127.0.0.1:8099"
# The panel refuses state-changing requests that are not same-origin (CSRF
# guard); a browser sends this header itself, the harness has to add it.
SAME_ORIGIN=(-H "Sec-Fetch-Site: same-origin")

# A stand-in for the Supervisor API token every add-on container gets: frpc
# must never see it (it renders its config as a Go template with .Envs), and
# user frpc must not be able to read it anywhere in the container.
SUPERVISOR_DUMMY="e2e-dummy-supervisor-token-$$-${RANDOM}"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
CTR=""
CTR_DEFAULT=""
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
Server verification (v2.2):
           E2E_FRPS_CA_FILE [E2E_FRPS_SERVER_NAME] [E2E_TLS_NEGATIVE=1|0]
Optional:  DOCKER ADDON_IMAGE NETWORK E2E_CREATE_ARGS E2E_PIN_SERVER E2E_PUBLIC_FROM E2E_CURL_ARGS
           E2E_EXPECT E2E_ACCOUNT_EMAIL_MASKED E2E_KEEP_PAIRED E2E_KEEP_CONTAINER
           E2E_ALLOWED_INGRESS_IPS E2E_*_TIMEOUT E2E_BUILD_*
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
                "${DOCKER}" exec "${CTR}" curl -s -o /dev/null "${SAME_ORIGIN[@]}" -X POST "${PANEL}/unpair" \
                    >/dev/null 2>&1 || true
            fi
            "${DOCKER}" rm -f "${CTR}" >/dev/null 2>&1 || true
        fi
    fi
    [[ -n "${CTR_DEFAULT}" ]] && "${DOCKER}" rm -f "${CTR_DEFAULT}" >/dev/null 2>&1
    [[ -n "${WORK_DIR}" ]] && rm -rf "${WORK_DIR}"
    exit "${rc}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# ------------------------------------------------------------------------------
# Container helpers
# ------------------------------------------------------------------------------
cexec() { "${DOCKER}" exec "${CTR}" "$@"; }

# panel_code <METHOD> <path> [curl args...]: HTTP status code ("000" on
# transport errors). No CSRF header: callers add one when they want it.
panel_code() {
    local method="$1" path="$2"
    shift 2
    cexec curl -s -o /dev/null -w '%{http_code}' "$@" -X "${method}" "${PANEL}${path}" 2>/dev/null \
        || printf '000'
}

# panel_redirect <METHOD> <path>: "<code> <redirect-url>" (same-origin request)
panel_redirect() {
    cexec curl -s -o /dev/null -w '%{http_code} %{redirect_url}' "${SAME_ORIGIN[@]}" -X "$1" "${PANEL}$2" \
        2>/dev/null || printf '000 -'
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
# file_owner_is <path> <user:group>
file_owner_is() { [[ "$(cexec stat -c '%U:%G' "$1" 2>/dev/null)" == "$2" ]]; }
# pem_body <pem text on stdin>: base64 of all certificates, whitespace removed
# (the add-on re-encodes the PEM, so line wrapping may differ).
pem_body() { grep -v -- '-----' | tr -d ' \t\r\n'; }
log_count() { "${DOCKER}" logs "${CTR}" 2>&1 | grep -c -F -- "$1" || true; }
frpc_pid() {
    local out up pid
    out="$(cexec s6-svstat -o up,pid /run/service/frpc 2>/dev/null)" || return 1
    read -r up pid <<<"${out}"
    [[ "${up}" == true && "${pid}" =~ ^[0-9]+$ ]] || return 1
    printf '%s' "${pid}"
}
frpc_user() {
    local pid
    pid="$(frpc_pid)" || return 1
    cexec stat -c '%U' "/proc/${pid}" 2>/dev/null
}
# frpc's environment, one variable per line. Read as user frpc (root would
# need CAP_SYS_PTRACE for another user's process; the AppArmor profile allows
# reading own-uid environments).
frpc_environ() {
    local pid
    pid="$(frpc_pid)" || return 1
    "${DOCKER}" exec --user frpc "${CTR}" cat "/proc/${pid}/environ" 2>/dev/null | tr '\0' '\n'
}
# Names of the variables in frpc's environment, one per line.
frpc_env_names() {
    local env
    env="$(frpc_environ)" || return 1
    [[ -n "${env}" ]] || return 1
    printf '%s\n' "${env}" | cut -d= -f1 | sort
}
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
if [[ -n "${CA_FILE}" ]]; then
    [[ -r "${CA_FILE}" ]] || usage_error "E2E_FRPS_CA_FILE '${CA_FILE}' is not readable"
    grep -q -- '-----BEGIN CERTIFICATE-----' "${CA_FILE}" || usage_error "E2E_FRPS_CA_FILE is not a PEM certificate"
fi
[[ -z "${EXPECT_SERVER_NAME}" || "${EXPECT_SERVER_NAME}" =~ ^[A-Za-z0-9.:-]+$ ]] \
    || usage_error "E2E_FRPS_SERVER_NAME contains unexpected characters"
read -r -a CREATE_EXTRA <<<"${E2E_CREATE_ARGS:-}"
read -r -a CURL_EXTRA <<<"${E2E_CURL_ARGS:-}"
[[ "${PUBLIC_FROM}" == host || "${PUBLIC_FROM}" == addon ]] || usage_error "E2E_PUBLIC_FROM must be host or addon"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/frp-tunnel-e2e.XXXXXX")"
log "app=${APP_BASE} api=${API_BASE} frps=${SERVER_ADDR}:${SERVER_PORT} domain_base=${DOMAIN_BASE}"
log "local=${LOCAL_HOST}:${LOCAL_PORT} network=${NETWORK:-<default>} approval=${APPROVAL} pin_server=${PIN_SERVER}"
if [[ -n "${CA_FILE}" ]]; then
    log "frps verification: expected (CA ${CA_FILE}${EXPECT_SERVER_NAME:+, server_name ${EXPECT_SERVER_NAME}})"
else
    log "frps verification: not checked (no E2E_FRPS_CA_FILE)"
fi

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
mkdir -p "${WORK_DIR}/data" "${WORK_DIR}/tmp/.bashio"
cp "${WORK_DIR}/options.json" "${WORK_DIR}/data/options.json"
cp "${WORK_DIR}/options.json" "${WORK_DIR}/tmp/.bashio/addons.self.options.config.cache"
# copy_into <host-dir> <container-dir> [container]: copy the directory's
# content owned by root, as Supervisor would create it (`docker cp` keeps the
# host uid, which root inside the container could only read with
# CAP_DAC_OVERRIDE - not granted by the add-on's AppArmor profile).
copy_into() {
    tar -C "$1" --owner=0 --group=0 --numeric-owner -cf - . | "${DOCKER}" cp - "${3:-${CTR}}:$2"
}

CTR="frp-tunnel-e2e-$$-${RANDOM}"
# SUPERVISOR_TOKEN and its legacy name HASSIO_TOKEN (same value): what
# Supervisor puts into every add-on's environment.
create_args=(--name "${CTR}" -e "ALLOWED_INGRESS_IPS=${ALLOWED_IPS}"
    -e "SUPERVISOR_TOKEN=${SUPERVISOR_DUMMY}" -e "HASSIO_TOKEN=${SUPERVISOR_DUMMY}")
[[ -n "${NETWORK}" ]] && create_args+=(--network "${NETWORK}")
# e.g. E2E_CREATE_ARGS="--security-opt apparmor=frp_tunnel" (profile loaded on the host)
create_args+=("${CREATE_EXTRA[@]+"${CREATE_EXTRA[@]}"}")
if ! "${DOCKER}" create "${create_args[@]}" "${IMAGE}" >/dev/null; then
    CTR=""
    abort "container created"
fi
copy_into "${WORK_DIR}/data" /data >/dev/null || abort "options.json copied into the container"
copy_into "${WORK_DIR}/tmp" /tmp >/dev/null || abort "bashio option cache seeded"
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
    # GHSA-86qp-5c8j-p5mr: a crafted Host header must not unlock any path.
    code="$(cexec curl -s -o /dev/null -w '%{http_code}' "${SAME_ORIGIN[@]}" -H 'Host: x/_health?a=' \
        -X POST "http://${CTR_IP}:8099/pair/start" 2>/dev/null || printf '000')"
    check "ingress guard ignores a crafted Host header (HTTP ${code})" test "${code}" == 403
    code="$(cexec curl -s -o /dev/null -w '%{http_code}' "http://${CTR_IP}:8099/_health" 2>/dev/null || printf '000')"
    check "/_health has no ingress exemption (HTTP ${code})" test "${code}" == 403
else
    skip "ingress guard rejects non-ingress clients" "container IP unknown"
fi
# The DEFAULT allow-list (no ALLOWED_INGRESS_IPS: the Supervisor's ingress
# proxy only) must refuse loopback - in particular the unprivileged frpc user,
# who could otherwise drive the panel (unpair, refresh). Checked in a second,
# unpaired container of the same image.
CTR_DEFAULT="${CTR}-default"
default_args=(--name "${CTR_DEFAULT}")
[[ -n "${NETWORK}" ]] && default_args+=(--network "${NETWORK}")
default_args+=("${CREATE_EXTRA[@]+"${CREATE_EXTRA[@]}"}")
if "${DOCKER}" create "${default_args[@]}" "${IMAGE}" >/dev/null \
    && copy_into "${WORK_DIR}/data" /data "${CTR_DEFAULT}" >/dev/null \
    && copy_into "${WORK_DIR}/tmp" /tmp "${CTR_DEFAULT}" >/dev/null \
    && "${DOCKER}" start "${CTR_DEFAULT}" >/dev/null; then
    # default_code <user> <METHOD> <path>: HTTP status from inside that container
    default_code() {
        "${DOCKER}" exec --user "$1" "${CTR_DEFAULT}" curl -s -o /dev/null -w '%{http_code}' \
            "${SAME_ORIGIN[@]}" -X "$2" "${PANEL}$3" 2>/dev/null || printf '000'
    }
    default_panel_up() { [[ "$(default_code root GET /_health)" == 403 ]]; }
    if wait_for "${BOOT_TIMEOUT}" default_panel_up; then
        pass "default allow-list: loopback refused for root (HTTP 403)"
        code="$(default_code frpc GET /api/status)"
        check "default allow-list: user frpc gets HTTP ${code} for GET 127.0.0.1:8099/api/status (want 403)" \
            test "${code}" == 403
        code="$(default_code frpc POST /unpair)"
        check "default allow-list: user frpc gets HTTP ${code} for a same-origin POST /unpair (want 403)" \
            test "${code}" == 403
    else
        fail "default allow-list: loopback refused" "last HTTP $(default_code root GET /_health)"
    fi
    "${DOCKER}" rm -f "${CTR_DEFAULT}" >/dev/null 2>&1 || true
else
    fail "default allow-list container started"
fi
CTR_DEFAULT=""

code="$(panel_code POST /pair/start)"
check "CSRF: POST without Sec-Fetch-Site/Origin refused (HTTP ${code})" test "${code}" == 403
code="$(panel_code POST /pair/start -H 'Sec-Fetch-Site: cross-site')"
check "CSRF: cross-site POST refused (HTTP ${code})" test "${code}" == 403
check "CSRF: refused POSTs did not start a pairing" test "$(status_field pairing_active)" == false

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
check "user_code is not in the redirect URL" test "${location}" == "${location//"${USER_CODE}"/}"
not_logged_code() { ! logs_contain "${USER_CODE}"; }
check "user_code is not in the add-on log" not_logged_code

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
    resp="$(cexec sh -c 'curl -sS -H "Sec-Fetch-Site: same-origin" -X POST "$0/pair/poll" |
        jq -r "(.status // \"\") + \"|\" + (.error // \"\")"' \
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
ACCOUNT="$(status_field account_email_masked)"
if [[ -n "${EXPECT_ACCOUNT}" ]]; then
    check "status: account_email_masked = ${EXPECT_ACCOUNT}" test "${ACCOUNT}" == "${EXPECT_ACCOUNT}"
elif [[ -n "${ACCOUNT}" ]]; then
    pass "status: account_email_masked shown (${ACCOUNT})"
elif [[ -n "${CA_FILE}" ]]; then
    fail "status: account_email_masked shown" "a v2.2 server must send it"
else
    skip "status: account_email_masked shown" "server does not send it (pre-2.2)"
fi

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
check "frpc.toml mode 640 root:frpc" file_mode_is /data/frpc.toml 640
check "frpc.toml owned by root:frpc" file_owner_is /data/frpc.toml root:frpc
check "frpc.toml passes 'frpc verify'" frpc_verify

# ------------------------------------------------------------------------------
# 4b. Server verification (frps certificate pinned to the server-provided CA)
# ------------------------------------------------------------------------------
TLS_MODE="$(status_field tls_mode)"
STATE_SERVER_NAME="$(state_field server_name)"
if [[ -n "${CA_FILE}" ]]; then
    check "status: tls_mode = verified (got ${TLS_MODE:-none})" test "${TLS_MODE}" == verified
    EXPECTED_SN="${EXPECT_SERVER_NAME:-${STATE_SERVER_NAME}}"
    check "state: server-provided server_name present (${STATE_SERVER_NAME:-missing})" test -n "${STATE_SERVER_NAME}"
    [[ -n "${EXPECT_SERVER_NAME}" ]] \
        && check "state: server_name = ${EXPECT_SERVER_NAME}" test "${STATE_SERVER_NAME}" == "${EXPECT_SERVER_NAME}"
    CA_WANT="$(pem_body <"${CA_FILE}")"
    check "state: server_ca_pem = E2E_FRPS_CA_FILE" test "$(state_field server_ca_pem | pem_body)" == "${CA_WANT}"
    check "/data/frps-ca.pem = E2E_FRPS_CA_FILE" test "$(cexec cat /data/frps-ca.pem 2>/dev/null | pem_body)" == "${CA_WANT}"
    check "/data/frps-ca.pem mode 640 root:frpc" file_mode_is /data/frps-ca.pem 640
    check "/data/frps-ca.pem owned by root:frpc" file_owner_is /data/frps-ca.pem root:frpc
    check "frpc.toml: transport.tls.trustedCaFile = \"/data/frps-ca.pem\"" \
        toml_has_line 'transport.tls.trustedCaFile = "/data/frps-ca.pem"'
    check "frpc.toml: transport.tls.serverName = \"${EXPECTED_SN}\"" \
        toml_has_line "transport.tls.serverName = \"${EXPECTED_SN}\""
else
    skip "frps certificate pinned" "E2E_FRPS_CA_FILE not set (panel reports tls_mode=${TLS_MODE:-?})"
fi

# ------------------------------------------------------------------------------
# 5. frpc process and frps login (TLS)
# ------------------------------------------------------------------------------
if wait_for "${FRPC_TIMEOUT}" frpc_running; then
    pass "frpc process up (s6-svstat up, pid is frpc)"
else
    fail "frpc process up (s6-svstat up, pid is frpc)"
fi
if wait_for "${FRPC_TIMEOUT}" logs_contain "login to server success"; then
    if [[ -n "${CA_FILE}" ]]; then
        pass "frpc logged in to frps over TLS with the verified, pinned certificate"
    else
        pass "frpc logged in to frps over TLS"
    fi
else
    fail "frpc logged in to frps over TLS"
fi
no_tls_errors() { ! logs_contain "x509:" && ! logs_contain "tls: failed to verify"; }
check "no certificate verification errors in the log" no_tls_errors
check "frpc runs as the unprivileged user frpc ($(frpc_user || echo '?'))" test "$(frpc_user)" == frpc
if [[ -n "${CA_FILE}" ]]; then
    # The panel calls the frps certificate "verified" only after frpc has
    # logged in with the pinned CA (reported by the frpc log watcher).
    tls_verified() { [[ "$(status_field tls_verified)" == true && "$(status_field tls_login)" == ok ]]; }
    check "status: tls_verified = true after frpc's login with the pinned CA" wait_for "${FRPC_TIMEOUT}" tls_verified
fi

# frpc must run with a scrubbed environment: it expands {{ .Envs.NAME }} in
# its configuration file, so it must never see the add-on's SUPERVISOR_TOKEN.
contenv_token="$(cexec cat /run/s6/container_environment/SUPERVISOR_TOKEN 2>/dev/null || true)"
check "precondition: the add-on environment carries SUPERVISOR_TOKEN" \
    test "${contenv_token}" == "${SUPERVISOR_DUMMY}"
FRPC_ENV="$(frpc_env_names | tr '\n' ' ' || true)"
FRPC_ENV="${FRPC_ENV% }"
check "frpc environment readable (variables: ${FRPC_ENV:-none})" test -n "${FRPC_ENV}"
env_has_no_token() { [[ -n "${FRPC_ENV}" && "${FRPC_ENV}" != *SUPERVISOR_TOKEN* ]]; }
check "frpc environment has no SUPERVISOR_TOKEN" env_has_no_token
env_scrubbed() {
    local name
    [[ -n "${FRPC_ENV}" ]] || return 1
    for name in ${FRPC_ENV}; do
        [[ "${name}" == PATH || "${name}" == HOME || "${name}" == TZ ]] || return 1
    done
}
check "frpc environment is scrubbed (PATH, HOME, TZ only)" env_scrubbed
# ... and user frpc cannot read the token anywhere else either (review
# 2026-10-27, FRP-01): s6-overlay keeps the container environment, token
# included, in /run/s6/container_environment, which the frp-init oneshot makes
# root-only before frpc starts.
contenv_denied() {
    local err
    # stdout (the token, should the read succeed) goes to /dev/null
    if err="$("${DOCKER}" exec --user frpc "${CTR}" cat /run/s6/container_environment/SUPERVISOR_TOKEN 2>&1 >/dev/null)"; then
        return 1
    fi
    [[ "${err}" == *"ermission denied"* ]]
}
check "user frpc cannot read /run/s6/container_environment/SUPERVISOR_TOKEN (permission denied)" contenv_denied
# Every file user frpc can read under /run /var/run /tmp /etc /data is
# searched for the Supervisor token and the device token. The patterns come
# on stdin from files in the private work directory (never argv). /data is
# searched last: finding the tunnel token in /data/frpc.toml, which frpc must
# read, proves that the scan ran through. Under the add-on's own AppArmor
# profile (E2E_CREATE_ARGS) /etc is left out: the profile denies most of it to
# every process of the add-on, and the scan's reads would show up as denials.
scan_roots=(/run /var/run /tmp /etc /data)
case "$("${DOCKER}" inspect -f '{{.AppArmorProfile}}' "${CTR}" 2>/dev/null || true)" in
    "" | unconfined | docker-default | containers-default*) ;;
    *) scan_roots=(/run /var/run /tmp /data) ;;
esac
# frpc_readable_with <pattern-file>: the files user frpc can read that contain
# one of the patterns (one path per line).
frpc_readable_with() {
    "${DOCKER}" exec -i --user frpc "${CTR}" timeout 120 grep -rlsF -f - "${scan_roots[@]}" \
        <"$1" 2>/dev/null || true
}
token_patterns="${SUPERVISOR_DUMMY}"
[[ -n "${DEVICE_TOKEN}" ]] && token_patterns+=$'\n'"${DEVICE_TOKEN}"
copies="$(frpc_readable_with "$(secret_file frpc-scan.pattern "${token_patterns}")")"
found="${copies//$'\n'/ }"
check "no file readable by user frpc contains the Supervisor or device token (${scan_roots[*]}; found: ${found:-none})" \
    test -z "${copies}"
scan_control() {
    local hits
    [[ -n "${TOKEN}" ]] || return 1
    hits="$(frpc_readable_with "$(secret_file frpc-scan-control.pattern "${TOKEN}")")"
    grep -qx /data/frpc.toml <<<"${hits}"
}
check "the scan as user frpc reached /data (control: tunnel token found in /data/frpc.toml)" scan_control
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

# Negative check: with a certificate name the frps certificate is NOT valid
# for, frpc must refuse the server (proves the pin is enforced by frpc).
if [[ -n "${CA_FILE}" && "${TLS_NEGATIVE}" == 1 ]]; then
    LOGINS_BEFORE="$(log_count "login to server success")"
    login_failures() {
        echo $(($(log_count "connect to server error") + $(log_count "login to the server failed")))
    }
    FAILURES_BEFORE="$(login_failures)"
    # shellcheck disable=SC2016  # jq program
    cexec sh -c 'cp -p /data/frp-state.json /data/.e2e-state.bak &&
        jq ".server_name = \"wrong-name.invalid\"" /data/.e2e-state.bak >/data/frp-state.json' \
        && cexec s6-svc -r /run/service/frpc
    # frpc reports the x509 error ("certificate is valid for <names>, not
    # wrong-name.invalid") or, when the handshake fails inside its muxed
    # session, just "connect to server error: session shutdown".
    tls_refused() {
        logs_contain "not wrong-name.invalid" || (( $(login_failures) >= FAILURES_BEFORE + 2 ))
    }
    check "TLS pin enforced: frpc refuses a certificate not valid for serverName" \
        wait_for "${FRPC_TIMEOUT}" tls_refused
    check "TLS pin enforced: no login with the wrong serverName" \
        test "$(log_count "login to server success")" == "${LOGINS_BEFORE}"
    tls_login_failed() {
        [[ "$(status_field tls_login)" == failed && "$(status_field tls_verified)" == false ]] \
            && status_field tls_errors | grep -F "could not log in" >/dev/null
    }
    check "status: tls_login = failed, tls_verified = false, red banner (wrong serverName)" \
        wait_for "${FRPC_TIMEOUT}" tls_login_failed
    cexec sh -c 'cp -p /data/.e2e-state.bak /data/frp-state.json && rm -f /data/.e2e-state.bak' \
        && cexec s6-svc -r /run/service/frpc
    relogged() { (( $(log_count "login to server success") > LOGINS_BEFORE )); }
    check "frpc logs in again after restoring serverName" wait_for "${FRPC_TIMEOUT}" relogged
    check "frpc.toml restored" wait_for "${FRPC_TIMEOUT}" toml_back
    check "status: tls_verified = true again" wait_for "${FRPC_TIMEOUT}" tls_verified

    # Fail closed: a pinned CA that no longer passes validation, with no
    # valid copy left, must stop frpc - never an unverified connection.
    LOGINS_BEFORE="$(log_count "login to server success")"
    # shellcheck disable=SC2016  # jq program
    cexec sh -c 'cp -p /data/frp-state.json /data/.e2e-state.bak &&
        jq ".server_ca_pem = \"garbage\"" /data/.e2e-state.bak >/data/frp-state.json &&
        rm -f /data/frps-ca.pem' \
        && cexec s6-svc -r /run/service/frpc
    blocked() { logs_contain "frpc is NOT started" && ! frpc_running; }
    check "fail closed: frpc not started without a valid CA" wait_for "${FRPC_TIMEOUT}" blocked
    check "fail closed: no frpc.toml" file_absent /data/frpc.toml
    check "status: tls_mode = blocked (got $(status_field tls_mode))" test "$(status_field tls_mode)" == blocked
    check "fail closed: no login without a valid CA" \
        test "$(log_count "login to server success")" == "${LOGINS_BEFORE}"
    cexec sh -c 'cp -p /data/.e2e-state.bak /data/frp-state.json && rm -f /data/.e2e-state.bak' \
        && cexec s6-svc -r /run/service/frpc
    check "frpc logs in again after restoring the CA" wait_for "${FRPC_TIMEOUT}" relogged
    check "frpc.toml restored" wait_for "${FRPC_TIMEOUT}" toml_back
elif [[ -n "${CA_FILE}" ]]; then
    skip "TLS pin enforced (wrong serverName refused)" "E2E_TLS_NEGATIVE=0"
fi

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
    check "unpair removed the pinned CA" file_absent /data/frps-ca.pem
    not_running() { ! frpc_running; }
    check "frpc stopped after unpair" wait_for "${FRPC_TIMEOUT}" not_running
fi

summary
(( FAIL_COUNT == 0 ))
