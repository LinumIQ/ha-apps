#!/usr/bin/env bash
# ==============================================================================
# FRP Tunnel add-on - AppArmor smoke test (CI and local; needs sudo or root,
# a kernel with AppArmor enabled and docker).
#
# usage: apparmor-smoke.sh <image> <apparmor.txt>
#
# Loads the add-on's profile in enforce mode, boots the image confined by it
# (like Supervisor does) and exercises every code path that touches files,
# processes or the network without a LinumIQ backend: s6-overlay start-up,
# bashio, the panel (health, status, a same-origin POST), the renderer writing
# frpc.toml + the pinned frps CA (root:frpc 0640) and reading Home Assistant's
# port from a fake Supervisor API (a second, unconfined container reachable
# as `supervisor`), frpc started as user frpc
# (it fails to connect - nothing listens - which is expected) with its log
# watcher, unpair and a clean `docker stop`. Fails on any AppArmor denial for
# the profile.
#
# Denials are read from the kernel log (dmesg) AND - where auditd runs, e.g.
# on a server, and the kernel log stays silent - from /var/log/audit/audit.log
# (only lines written after the start). Before the test, a deliberately
# denied write in a throw-away container proves that a denial is actually
# seen; the test refuses to run (exit 2) when it is not. The profile is
# loaded without the parser's cache (-K), checked by name, and unloaded again
# on exit when it was not loaded before.
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
SUP_CTR="${CTR}-supervisor"
SUP_TOKEN="smoke-supervisor-token-0123456789"
WORK="$(mktemp -d)"
FAILED=0
SUDO=()
(( EUID == 0 )) || SUDO=(sudo)
UNLOAD=false
AUDIT_LOG=/var/log/audit/audit.log
AUDIT_OFFSET=""
DMESG_OK=false

log() { printf '[aa-smoke] %s\n' "$*" >&2; }
ok() { printf 'PASS  %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1"; FAILED=1; }
check() { # check <name> <command...>
    local name="$1"
    shift
    if "$@"; then ok "${name}"; else bad "${name}"; fi
}
cleanup() {
    "${DOCKER}" rm -f "${CTR}" "${SUP_CTR}" "${CTR}-probe" >/dev/null 2>&1 || true
    if [[ "${UNLOAD}" == true ]]; then
        "${SUDO[@]}" apparmor_parser -R -K "${PROFILE_FILE}" >/dev/null 2>&1 || true
    fi
    rm -rf "${WORK}"
}
trap cleanup EXIT

[[ -n "${PROFILE}" ]] || { log "no 'profile <name>' line in ${PROFILE_FILE}"; exit 2; }
if [[ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" != Y ]]; then
    log "AppArmor is not enabled in this kernel"
    exit 2
fi
# Denials of this profile (and its children), from every readable source.
# Not counted: runc's term/kill signals at `docker stop` (peer="runc"), which
# Ubuntu's runc profile triggers for any confined container.
denials() {
    {
        if [[ "${DMESG_OK}" == true ]]; then "${SUDO[@]}" dmesg 2>/dev/null || true; fi
        if [[ -n "${AUDIT_OFFSET}" ]]; then
            "${SUDO[@]}" tail -n "+$((AUDIT_OFFSET + 1))" "${AUDIT_LOG}" 2>/dev/null || true
        fi
    } | grep -F 'apparmor="DENIED"' | grep -E "profile=\"${PROFILE}(\"|//)" \
        | grep -v -E 'operation="signal".*peer="runc"' | sort -u || true
}
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

# Denial sources: the kernel log, and the audit log from its current end.
"${SUDO[@]}" dmesg >/dev/null 2>&1 && DMESG_OK=true
if "${SUDO[@]}" test -r "${AUDIT_LOG}"; then
    AUDIT_OFFSET="$("${SUDO[@]}" wc -l "${AUDIT_LOG}" | awk '{print $1}')"
fi
if [[ "${DMESG_OK}" != true && -z "${AUDIT_OFFSET}" ]]; then
    log "neither dmesg nor ${AUDIT_LOG} is readable: AppArmor denials cannot be detected"
    exit 2
fi
SOURCES=""
if [[ "${DMESG_OK}" == true ]]; then SOURCES="dmesg"; fi
if [[ -n "${AUDIT_OFFSET}" ]]; then SOURCES="${SOURCES:+${SOURCES} + }${AUDIT_LOG}"; fi

if ! "${SUDO[@]}" grep -q "^${PROFILE} (" /sys/kernel/security/apparmor/profiles 2>/dev/null; then
    UNLOAD=true
fi
# -K: no profile cache. The cache is keyed by the file's basename, and every
# add-on's profile is called apparmor.txt - with the cache, a host that has
# cached another add-on's apparmor.txt silently loads THAT profile instead.
"${SUDO[@]}" apparmor_parser -r -K "${PROFILE_FILE}"
if ! "${SUDO[@]}" grep -qx "${PROFILE} (enforce)" /sys/kernel/security/apparmor/profiles; then
    log "profile ${PROFILE} is not loaded in enforce mode after apparmor_parser"
    exit 2
fi
log "profile ${PROFILE} loaded ($(apparmor_parser -V | head -n 1))"

# Prove that a denial of this profile is seen on this host: a write below
# /etc/s6-overlay (read-only in the profile) in a throw-away container.
"${DOCKER}" run --rm --name "${CTR}-probe" --security-opt "apparmor=${PROFILE}" \
    --entrypoint /bin/sh "${IMAGE}" -c 'echo x > /etc/s6-overlay/aa-smoke-probe' >/dev/null 2>&1 || true
probe_seen() { denials | grep -F 'aa-smoke-probe' >/dev/null; }
if ! wait_for 10 probe_seen; then
    log "a deliberate AppArmor denial was not seen (sources: ${SOURCES}): denials cannot be detected here"
    exit 2
fi
log "denial detection works (deliberate probe seen; sources: ${SOURCES})"
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

# Fake Supervisor API (unconfined, same image's Python): /core/info answers
# Home Assistant's port 80 - only with the add-on's bearer token.
"${DOCKER}" run -d --name "${SUP_CTR}" -e "FAKE_TOKEN=${SUP_TOKEN}" \
    --entrypoint /usr/lib/frp-mgr/.venv/bin/python3 "${IMAGE}" -c '
import http.server, json, os
TOKEN = os.environ["FAKE_TOKEN"]
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        ok = self.path == "/core/info" and self.headers.get("Authorization") == "Bearer " + TOKEN
        body = json.dumps({"result": "ok", "data": {"port": 80}} if ok else {"result": "error"}).encode()
        self.send_response(200 if ok else 401 if self.path == "/core/info" else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
http.server.ThreadingHTTPServer(("0.0.0.0", 80), Handler).serve_forever()
' >/dev/null
sup_ip="$("${DOCKER}" inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${SUP_CTR}")"
[[ -n "${sup_ip}" ]] || { log "fake Supervisor has no IP address"; exit 2; }

"${DOCKER}" create --name "${CTR}" --security-opt "apparmor=${PROFILE}" \
    --add-host "supervisor:${sup_ip}" -e "SUPERVISOR_TOKEN=${SUP_TOKEN}" \
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
    test "$("${SUDO[@]}" cat "/proc/${pid1}/attr/current" 2>/dev/null)" == "${PROFILE} (enforce)"
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
# local_port is not set: the renderer took Home Assistant's port from the
# (fake) Supervisor API, and so does the panel.
check "renderer: local_port from the Supervisor API (localPort = 80)" \
    cexec grep -qx 'localPort = 80' /data/frpc.toml
renderer_logged_origin() {
    "${DOCKER}" logs "${CTR}" 2>&1 | grep -F "(frpc-render) frpc.toml" \
        | grep -F "local=homeassistant:80 (port from supervisor)" >/dev/null
}
check "renderer logged the port's origin" renderer_logged_origin
panel_port() {
    [[ "$(cexec sh -c "curl -fsS http://127.0.0.1:8099/api/status | jq -r '\"\\(.local_port) \\(.sources.local_port)\"'" 2>/dev/null)" == "80 supervisor" ]]
}
# (the panel caches the lookup; a failed one is retried after 60 s)
check "panel: local_port 80 from the Supervisor API" wait_for 70 panel_port
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
