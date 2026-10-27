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
# with `openssl ca` and a forced `caddy reload`), the cert-monitor and a
# clean `docker stop`. Fails on any AppArmor denial for the profile.
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
PROFILE="$(sed -n 's/^profile \([A-Za-z0-9_-]*\) .*/\1/p' "${PROFILE_FILE}" | head -n 1)"
CTR="caddy-mtls-aa-smoke-$$"
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
    "${DOCKER}" rm -f "${CTR}" >/dev/null 2>&1 || true
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

"${DOCKER}" create --name "${CTR}" --security-opt "apparmor=${PROFILE}" --network none \
    -e ACME_CA_URL=http://127.0.0.1:9/directory -e TZ=Europe/Vienna "${IMAGE}" >/dev/null
copy_into "${WORK}/data" /data
copy_into "${WORK}/tmp" /tmp
"${DOCKER}" start "${CTR}" >/dev/null

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

stop_container() {
    "${DOCKER}" stop -t 30 "${CTR}" >/dev/null \
        && [[ "$("${DOCKER}" inspect -f '{{.State.Status}}' "${CTR}")" == exited ]]
}
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
