#!/usr/bin/env bash
# ==============================================================================
# FRP Tunnel add-on - AppArmor smoke test (CI and local; needs sudo, a kernel
# with AppArmor enabled and docker).
#
# usage: apparmor-smoke.sh <image> <apparmor.txt>
#
# Loads the add-on's profile in enforce mode, boots the image confined by it
# (like Supervisor does) and exercises every code path that touches files,
# processes or the network without a LinumIQ backend: s6-overlay start-up,
# bashio, the panel (health, status, a same-origin POST), the renderer writing
# frpc.toml + the pinned frps CA (root:frpc 0640), frpc started as user frpc
# (it fails to connect - nothing listens - which is expected) with its log
# watcher, unpair and a clean `docker stop`. Fails on any AppArmor denial for
# the profile.
# Env: DOCKER (default docker).
# ==============================================================================
# Helper functions are called indirectly (check, wait_for, trap).
# shellcheck disable=SC2329
set -euo pipefail

IMAGE="${1:?usage: apparmor-smoke.sh <image> <apparmor.txt>}"
PROFILE_FILE="${2:?usage: apparmor-smoke.sh <image> <apparmor.txt>}"
DOCKER="${DOCKER:-docker}"
PROFILE="$(sed -n 's/^profile \([A-Za-z0-9_-]*\) .*/\1/p' "${PROFILE_FILE}" | head -n 1)"
CTR="frp-tunnel-aa-smoke-$$"
WORK="$(mktemp -d)"
FAILED=0

log() { printf '[aa-smoke] %s\n' "$*" >&2; }
ok() { printf 'PASS  %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1"; FAILED=1; }
check() { # check <name> <command...>
    local name="$1"
    shift
    if "$@"; then ok "${name}"; else bad "${name}"; fi
}
cleanup() {
    "${DOCKER}" rm -f "${CTR}" >/dev/null 2>&1 || true
    rm -rf "${WORK}"
}
trap cleanup EXIT

[[ -n "${PROFILE}" ]] || { log "no 'profile <name>' line in ${PROFILE_FILE}"; exit 2; }
if [[ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" != Y ]]; then
    log "AppArmor is not enabled in this kernel"
    exit 2
fi
denials() { sudo dmesg | grep -F 'apparmor="DENIED"' | grep -F "profile=\"${PROFILE}" || true; }
cexec() { "${DOCKER}" exec "${CTR}" "$@"; }
wait_for() {
    local timeout="$1" deadline
    shift
    deadline=$((SECONDS + timeout))
    until "$@"; do
        (( SECONDS >= deadline )) && return 1
        sleep 1
    done
}

sudo apparmor_parser -r -W "${PROFILE_FILE}"
log "profile ${PROFILE} loaded ($(apparmor_parser -V | head -n 1))"
denials >"${WORK}/before"

# Options as Supervisor would write them; app_base points at a closed local
# port so that no request ever leaves the runner.
mkdir -p "${WORK}/data" "${WORK}/tmp/.bashio"
cat >"${WORK}/data/options.json" <<'JSON'
{"log_level": "info", "app_base": "http://127.0.0.1:9", "api_base": "http://127.0.0.1:9"}
JSON
cp "${WORK}/data/options.json" "${WORK}/tmp/.bashio/addons.self.options.config.cache"
# Files go in owned by root (as Supervisor creates them): `docker cp` would
# keep the runner's uid, which root could only read with CAP_DAC_OVERRIDE.
copy_into() { tar -C "$1" --owner=0 --group=0 --numeric-owner -cf - . | "${DOCKER}" cp - "${CTR}:$2"; }
# A CA to pin (any CA works: frpc never gets as far as a TLS handshake).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "${WORK}/ca.key" \
    -subj "/CN=AppArmor smoke CA" -days 2 -addext basicConstraints=critical,CA:TRUE \
    -addext keyUsage=critical,keyCertSign -out "${WORK}/ca.pem" 2>/dev/null
mkdir -p "${WORK}/state"
python3 - "${WORK}/ca.pem" "${WORK}/state/frp-state.json" <<'PY'
import json, sys
ca = open(sys.argv[1]).read()
json.dump({"version": 2, "device_token": "smoke-device-token-0123456789", "subdomain": "smoke",
           "token": "smoke-tunnel-token-0123456789", "server_addr": "127.0.0.1", "server_port": 7000,
           "domain_base": "smoke.invalid", "server_name": "frps.smoke.invalid", "server_ca_pem": ca},
          open(sys.argv[2], "w"))
PY

"${DOCKER}" create --name "${CTR}" --security-opt "apparmor=${PROFILE}" \
    -e ALLOWED_INGRESS_IPS=127.0.0.1 -e TZ=Europe/Vienna "${IMAGE}" >/dev/null
copy_into "${WORK}/data" /data
copy_into "${WORK}/tmp" /tmp
"${DOCKER}" start "${CTR}" >/dev/null

health() { [[ "$(cexec curl -fsS http://127.0.0.1:8099/_health 2>/dev/null)" == ok ]]; }
logs_contain() { "${DOCKER}" logs "${CTR}" 2>&1 | grep -F -- "$1" >/dev/null; }
logs_lack() { ! logs_contain "$1"; }
http_code() { # http_code <method> <path> [curl args...]
    local method="$1" path="$2"
    shift 2
    cexec curl -s -o /dev/null -w '%{http_code}' "$@" -X "${method}" "http://127.0.0.1:8099${path}" || true
}
check "panel healthy under ${PROFILE}" wait_for 60 health
# Read from the host: the profile itself does not allow reading AppArmor labels.
pid1="$("${DOCKER}" inspect -f '{{.State.Pid}}' "${CTR}")"
check "PID 1 confined by ${PROFILE} (enforce)" \
    test "$(sudo cat "/proc/${pid1}/attr/current" 2>/dev/null)" == "${PROFILE} (enforce)"
check "frpc service waits while unpaired" wait_for 30 logs_contain "Not paired yet"
code="$(http_code POST /pair/start -H 'Sec-Fetch-Site: same-origin')"
check "same-origin POST handled (backend unreachable -> 303, got ${code})" test "${code}" == 303

# Pair "offline": state with a pinned CA, then restart the frpc service.
chmod 600 "${WORK}/state/frp-state.json"
copy_into "${WORK}/state" /data
cexec s6-svc -r /run/service/frpc
frpc_up() {
    local up pid
    read -r up pid <<<"$(cexec s6-svstat -o up,pid /run/service/frpc 2>/dev/null)"
    [[ "${up}" == true && "$(cexec cat "/proc/${pid}/comm" 2>/dev/null)" == frpc ]] || return 1
    [[ "$(cexec stat -c '%U' "/proc/${pid}" 2>/dev/null)" == frpc ]]
}
check "frpc runs as user frpc" wait_for 30 frpc_up
check "frpc.toml + frps-ca.pem are 640 root:frpc" \
    test "$(cexec stat -c '%a %U:%G' /data/frpc.toml /data/frps-ca.pem 2>/dev/null | sort -u)" == "640 root:frpc"
# 127.0.0.1:7000 is closed: frpc must get as far as connecting (config, CA
# file and DNS-free address all readable as user frpc).
check "frpc read its config and tried to connect" wait_for 30 logs_contain "connection refused"
# The log watcher (coprocess of the frpc service) records it for the panel.
watcher_saw_it() {
    [[ "$(cexec jq -r '"\(.state) \(.network_failures)"' /run/frp-mgr/frpc-status.json 2>/dev/null)" == "failed "[1-9]* ]]
}
check "frpc log watcher recorded the failed connection" wait_for 30 watcher_saw_it
check "no 'permission denied' in the log" logs_lack "ermission denied"
code="$(http_code GET /)"
check "panel page renders (paired, pinned CA; got ${code})" test "${code}" == 200
code="$(http_code POST /unpair -H 'Sec-Fetch-Site: same-origin')"
gone() { ! cexec test -e /data/frp-state.json && ! cexec test -e /data/frps-ca.pem; }
check "unpair answered (got ${code})" test "${code}" == 303
check "unpair removed the pairing files" wait_for 15 gone

stop_container() { "${DOCKER}" stop -t 20 "${CTR}" >/dev/null; }
check "clean docker stop" stop_container
sleep 1
denials >"${WORK}/after"
new="$(comm -13 "${WORK}/before" "${WORK}/after" || true)"
if [[ -z "${new}" ]]; then
    ok "no AppArmor denials for ${PROFILE}"
else
    bad "no AppArmor denials for ${PROFILE}"
    printf '%s\n' "${new}" >&2
fi
if (( FAILED )); then
    log "container log (last 60 lines):"
    "${DOCKER}" logs --tail 60 "${CTR}" >&2 2>&1 || true
fi
exit "${FAILED}"
