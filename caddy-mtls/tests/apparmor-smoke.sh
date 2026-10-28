#!/usr/bin/env bash
# ==============================================================================
# Caddy mTLS Proxy add-on - AppArmor smoke test (CI and local; needs sudo or
# root, a kernel with AppArmor enabled and docker).
#
# usage: apparmor-smoke.sh <image> <apparmor.txt>
#
# Loads the add-on's profile in enforce mode, boots the image confined by it
# (like Supervisor does) and exercises every code path that touches files,
# processes or the network: s6-overlay start-up, bashio, init-caddy (CA,
# client certificates, CRL, Caddyfile, `caddy validate`), Caddy (admin API,
# its ACME client against a closed local port), the cert-mgr panel (health,
# dashboard, state, a .p12 download, a client add and a revocation, each
# with `openssl ca` and a forced `caddy reload`), the "Public certificate"
# card (Caddy's acme.log, openssl x509 on Caddy's storage, the live probe of
# port 443), the cert-monitor (sensors and the "no public certificate"
# notification at a fake Supervisor inside the container, then its
# dismissal), a clean `docker stop` (< 10 s, exit 0, no s6 warnings) and a
# restart as Supervisor does it (a new container with the previous /data)
# with a new client name and a new client_cert_password (issuance and .p12
# re-encryption at start-up). Fails on any AppArmor denial for the profile.
#
# No external network traffic: the container runs with --network none and
# ACME_CA_URL points at a closed local port. A profile that was not loaded
# before is unloaded again on exit.
# Env: DOCKER (default docker).
# ==============================================================================
# Helper functions are called indirectly (check, wait_for, trap).
# shellcheck disable=SC2329
set -euo pipefail

IMAGE="${1:?usage: apparmor-smoke.sh <image> <apparmor.txt>}"
PROFILE_FILE="${2:?usage: apparmor-smoke.sh <image> <apparmor.txt>}"
DOCKER="${DOCKER:-docker}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE="$(sed -n 's/^profile \([A-Za-z0-9_-]*\) .*/\1/p' "${PROFILE_FILE}" | head -n 1)"
CTR1="caddy-mtls-aa-smoke-$$"
CTR2="${CTR1}-restart"
CTR="${CTR1}"
WORK="$(mktemp -d)"
INGRESS_PREFIX="/api/hassio_ingress/aa-smoke"
FAILED=0
SUDO=()
(( EUID == 0 )) || SUDO=(sudo)
UNLOAD=false

log() { printf '[aa-smoke] %s\n' "$*" >&2; }
ok() { printf 'PASS  %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1"; FAILED=1; }
check() { # check <name> <command...>
    local name="$1"
    shift
    if "$@"; then ok "${name}"; else bad "${name}"; fi
}
cleanup() {
    "${DOCKER}" rm -f "${CTR1}" "${CTR2}" >/dev/null 2>&1 || true
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
# AppArmor reports denials to the kernel log - or, when auditd runs (e.g. on
# a server), only to the audit log. Both are read; sorted for `comm`.
# Not counted: runc's kill/term signals at `docker stop` (peer="runc"), which
# Ubuntu's runc profile triggers for any confined container.
denials() {
    {
        "${SUDO[@]}" dmesg 2>/dev/null || true
        "${SUDO[@]}" cat /var/log/audit/audit.log 2>/dev/null || true
    } | grep -F 'apparmor="DENIED"' | grep -F "profile=\"${PROFILE}\"" \
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
denials >"${WORK}/before"

# Options as Supervisor would write them, plus bashio's option cache (there
# is no Supervisor API here).
mkdir -p "${WORK}/data" "${WORK}/tmp/.bashio"
cat >"${WORK}/data/options.json" <<'JSON'
{"domain": "home.example.com", "email": "smoke@example.com",
 "upstream_host": "127.0.0.1", "upstream_port": 8123, "mtls_enabled": true,
 "ca_country": "AT", "ca_state": "Styria", "ca_locality": "Graz",
 "ca_organization": "LinumIQ", "ca_common_name": "AppArmor smoke CA",
 "client_names": ["alice", "bob"], "client_cert_password": "aa-smoke-password",
 "acme_dns_provider": "none", "dns_api_token": "", "log_level": "info",
 "cert_expiry_warn_days": [30, 14, 7, 1], "cert_check_interval_hours": 6}
JSON
cp "${WORK}/data/options.json" "${WORK}/tmp/.bashio/addons.self.options.config.cache"
chmod -R go+rX "${WORK}"
# Files go in owned by root (as Supervisor creates them): `docker cp` would
# keep the runner's uid, which root could only read with CAP_DAC_OVERRIDE.
copy_into() { tar -C "$1" --owner=0 --group=0 --numeric-owner -cf - . | "${DOCKER}" cp - "${CTR}:$2"; }

# The cert-monitor talks to a fake Supervisor (tests/fake-supervisor.py,
# started inside the container, i.e. under the profile too) and raises the
# "no public certificate" notification after 5 s instead of 2 minutes.
SUPERVISOR_LOG=/tmp/supervisor-requests.jsonl
"${DOCKER}" create --name "${CTR}" --security-opt "apparmor=${PROFILE}" --network none \
    -e ACME_CA_URL=http://127.0.0.1:9/directory -e TZ=Europe/Vienna \
    -e SUPERVISOR_TOKEN=aa-smoke-token -e SUPERVISOR_URL=http://127.0.0.1:8765 \
    -e CERT_MONITOR_PUBLIC_CERT_GRACE_SECONDS=5 -e CERT_MONITOR_FAST_INTERVAL_SECONDS=2 \
    "${IMAGE}" >/dev/null
copy_into "${WORK}/data" /data
copy_into "${WORK}/tmp" /tmp
tar -C "${SCRIPT_DIR}" --owner=0 --group=0 --numeric-owner -cf - fake-supervisor.py | "${DOCKER}" cp - "${CTR}:/tmp"
"${DOCKER}" start "${CTR}" >/dev/null
"${DOCKER}" exec -d "${CTR}" /usr/lib/cert-mgr/.venv/bin/python3 /tmp/fake-supervisor.py 8765 "${SUPERVISOR_LOG}"

health() { [[ "$(cexec curl -fsS http://127.0.0.1:8099/_health 2>/dev/null)" == ok ]]; }
admin_up() { cexec curl -fsS -o /dev/null http://127.0.0.1:2019/config/ 2>/dev/null; }
logs_contain() { "${DOCKER}" logs "${CTR}" 2>&1 | grep -F -- "$1" >/dev/null; }
logs_lack() { ! logs_contain "$1"; }
log_count() { "${DOCKER}" logs "${CTR}" 2>&1 | grep -c -F -- "$1" || true; }
http_code() { # http_code <method> <path> [curl args...]
    local method="$1" path="$2"
    shift 2
    cexec curl -s -o /dev/null -w '%{http_code}' "$@" -X "${method}" "http://127.0.0.1:8099${path}" || true
}
state() { cexec jq -r "$1" /data/state.json 2>/dev/null; }

check "panel healthy under ${PROFILE}" wait_for 90 health
check "Caddy admin API up under ${PROFILE}" wait_for 30 admin_up
check "init-caddy completed (CA, clients, CRL, Caddyfile validated)" logs_contain "Init complete:"
# Read from the host: the profile itself does not allow reading AppArmor labels.
pid1="$("${DOCKER}" inspect -f '{{.State.Pid}}' "${CTR}")"
check "PID 1 confined by ${PROFILE} (enforce)" \
    test "$("${SUDO[@]}" cat "/proc/${pid1}/attr/current" 2>/dev/null)" == "${PROFILE} (enforce)"
check "cert-monitor started" wait_for 30 logs_contain "cert-monitor starting"
check "Caddy's ACME client ran (sinkhole refused)" wait_for 60 logs_contain "127.0.0.1:9"
acme_log_has_error() { cexec grep -F '"level":"error"' /data/caddy/log/acme.log >/dev/null 2>&1; }
check "Caddy writes its certificate events to /data/caddy/log/acme.log" wait_for 60 acme_log_has_error
card_state() { cexec curl -fsS http://127.0.0.1:8099/public-cert 2>/dev/null | sed -n 's/.*data-state="\([a-z_]*\)".*/\1/p'; }
card_state_is() { [[ "$(card_state)" == "$1" ]]; }
check "Public certificate card: missing (red)" wait_for 30 card_state_is missing
supervisor_got() { # supervisor_got <path suffix>
    cexec sh -c 'test -f "$1" && jq -s -e --arg p "$0" "[.[] | select(.path | endswith(\$p))] | length > 0" "$1"' \
        "$1" "${SUPERVISOR_LOG}" >/dev/null 2>&1
}
check "cert-monitor: notification raised at the fake Supervisor" \
    wait_for 60 supervisor_got /persistent_notification/create
# A certificate in Caddy's storage: openssl x509 on it and the live probe of
# port 443 run under the profile; the monitor dismisses the notification.
cexec sh -c 'd=/data/caddy/certificates/aa-smoke/home.example.com && mkdir -p "$d" &&
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 90 \
        -subj "/O=AppArmor smoke CA/CN=AA R1" -keyout "$d/home.example.com.key" \
        -out "$d/home.example.com.crt"' >/dev/null 2>&1 || true
check "Public certificate card: ok (green) from Caddy's storage" wait_for 30 card_state_is ok
check "cert-monitor: notification dismissed" wait_for 30 supervisor_got /persistent_notification/dismiss
code="$(http_code GET /)"
check "dashboard renders (got ${code})" test "${code}" == 200
code="$(http_code GET /api/state)"
check "/api/state answers (got ${code})" test "${code}" == 200
code="$(http_code GET /download/client/alice)"
check ".p12 download (got ${code})" test "${code}" == 200

# A real reload replaces Caddy's servers ("stopped previous server"); an
# unforced reload of the unchanged Caddyfile only logs "config is unchanged".
reloads_before="$(log_count 'stopped previous server')"
code="$(http_code POST /api/clients -H "X-Ingress-Path: ${INGRESS_PREFIX}" --data-urlencode name=carol)"
check "client add answered (got ${code})" test "${code}" == 303
check "carol issued and active" test "$(state '.clients[] | select(.name == "carol") | .status')" == active
code="$(http_code POST /api/clients/bob/revoke -H "X-Ingress-Path: ${INGRESS_PREFIX}" --data-urlencode reason=superseded)"
check "client revoke answered (got ${code})" test "${code}" == 303
check "bob revoked, CRL regenerated" \
    test "$(state '.clients[] | select(.name == "bob") | .status')" == revoked
reloaded() { (( $(log_count 'stopped previous server') >= reloads_before + 2 )); }
check "Caddy reloaded twice (forced reload)" wait_for 15 reloaded
check "no 'config is unchanged' (reload was forced)" logs_lack "config is unchanged"
check "no 'permission denied' in the log" logs_lack "ermission denied"

# A stop as Supervisor does it: < 10 s, exit code 0, no s6 warnings.
stop_container() {
    local t0 ms
    t0="$(date +%s%N)"
    "${DOCKER}" stop -t 30 "${CTR}" >/dev/null || return 1
    ms=$(( ($(date +%s%N) - t0) / 1000000 ))
    log "${CTR}: docker stop took ${ms} ms"
    [[ "$("${DOCKER}" inspect -f '{{.State.Status}} {{.State.ExitCode}}' "${CTR}")" == "exited 0" ]] \
        && (( ms < 10000 )) \
        && ! "${DOCKER}" logs "${CTR}" 2>&1 \
            | grep -E 'finish script lifetime|unable to stop service|s6-ipcclient: fatal|sending it a SIGKILL' >/dev/null
}
check "clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_container

# Restart: a new container under the profile with the previous /data, a new
# client name and a new client_cert_password.
"${DOCKER}" cp "${CTR}:/data" - >"${WORK}/data.tar"
sed -e 's/"client_names": \["alice", "bob"\]/"client_names": ["alice", "bob", "dave"]/' \
    -e 's/"aa-smoke-password"/"aa-smoke-password-2"/' "${WORK}/data/options.json" >"${WORK}/options.json"
mv "${WORK}/options.json" "${WORK}/data/options.json"
cp "${WORK}/data/options.json" "${WORK}/tmp/.bashio/addons.self.options.config.cache"
chmod -R go+rX "${WORK}"
"${DOCKER}" create --name "${CTR2}" --security-opt "apparmor=${PROFILE}" --network none \
    -e ACME_CA_URL=http://127.0.0.1:9/directory -e TZ=Europe/Vienna "${IMAGE}" >/dev/null
CTR="${CTR2}"
"${DOCKER}" cp - "${CTR}:/" <"${WORK}/data.tar"
copy_into "${WORK}/data" /data
copy_into "${WORK}/tmp" /tmp
"${DOCKER}" start "${CTR}" >/dev/null
check "restart: panel healthy under ${PROFILE}" wait_for 90 health
pid1="$("${DOCKER}" inspect -f '{{.State.Pid}}' "${CTR}")"
check "restart: PID 1 confined by ${PROFILE} (enforce)" \
    test "$("${SUDO[@]}" cat "/proc/${pid1}/attr/current" 2>/dev/null)" == "${PROFILE} (enforce)"
check "restart: init-caddy completed" wait_for 30 logs_contain "Init complete:"
check "restart: dave (new in client_names) issued" \
    test "$(state '.clients[] | select(.name == "dave") | .status')" == active
check "restart: .p12 bundles re-encrypted with the new password" \
    logs_contain "Re-encrypted the .p12 bundle of client 'alice'"
check "restart: no 'permission denied' in the log" logs_lack "ermission denied"
check "restart: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_container
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
