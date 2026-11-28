#!/usr/bin/env bash
# ==============================================================================
# Caddy mTLS Proxy add-on - forwarded_headers against a real Home Assistant
# Core. Not part of CI: it needs the Core image (about 2 GB) and takes about
# 10 minutes.
#
# usage: real-core.sh <image> [<old-image>]
#   <image>      the add-on image under test (2.2.0 or later)
#   <old-image>  optional: an image of 2.1.x, to reproduce the old
#                "400: Bad Request" (e.g. ghcr.io/linumiq/amd64-addon-caddy-mtls:2.1.3)
#
# On an --internal Docker network (no internet), with Home Assistant Core as
# "homeassistant:8123" (its own defaults, onboarded with a test user), a
# client container and the add-on booted outside Supervisor (as
# tests/smoke.sh does it, with a fake Supervisor for the notification; the
# monitor's control interval 2 s, test interval 5 s):
#   old   2.1.x: every proxied request is answered "400: Bad Request", Core
#         logs "A request from a reverse proxy was received from <add-on>".
#   always  2.2.0, forwarded_headers always: 400, red card, notification.
#   auto    2.2.0, auto with mTLS: mode strip; the page loads through the
#         mTLS port; Core logs the add-on's address for a wrong token; the
#         websocket works; no further probing lines while Core runs.
#   yaml    an http: block in configuration.yaml + Core restart: Core 2026.7+
#         ignores it (repair "yaml_still_present_after_migration"), the
#         add-on stays in strip.
#   ui      the reverse-proxy settings through Core's websocket API (what
#         Settings > System > Network > HTTP server does), restart, confirm:
#         the running add-on switches to pass without a restart; Core logs
#         the client's own address; the websocket works.
#   start   a new add-on container with that Core: pass at the start.
#   back    settings removed, restart, confirm: the add-on switches to strip.
#   header  header authentication (2.3.0, mTLS on, a per-run fake key): the
#         page, the API and the websocket of the real Core with the key and
#         no client certificate; 403 without it.
# With the monitor's default intervals (control 12 s, test 60 s):
#   first-boot  Core down at the add-on's first start: polled every 2.5 s, the
#         switch to strip within 5 s of Core's first answer (review B-5); no
#         "addresses hidden" notification - Core never trusted the add-on
#         (re-review B2-1).
#   early-restart  Core gets the reverse-proxy settings (restart) 1 s after
#         the add-on started: noticed without Check again (B-4).
#   untrust  settings removed while in pass: strip within 20 s of Core being
#         back, not after the minute test; the "addresses hidden"
#         notification (B-3, B-12).
#   stall  Core paused 15 s (one control request unanswered; with the 5 s
#         watch timeout and the 12 s interval a pause shorter than about 17 s
#         can never fail two in a row): nothing happens, 0 lines; paused
#         40 s: unreachable without a 502 claim, one test afterwards (B-6).
# For each phase the script counts the lines in Core's log that refused
# forwarded requests caused (the probe's share and the visitors' share).
#
# Env: DOCKER (default docker), CORE_IMAGE (default
#      ghcr.io/home-assistant/home-assistant:2026.11.3), REALCORE_PREFIX
#      (name prefix of containers and the network, default caddy-mtls-core),
#      REALCORE_SUBNET (default 10.233.44.0/24), REALCORE_EVIDENCE (a
#      directory that receives the logs; default: none).
# Prints PASS/FAIL per check and a summary; exit 0 = all passed.
# ==============================================================================
# Helper functions are called indirectly (check, wait_for, trap).
# shellcheck disable=SC2329
set -euo pipefail
umask 077

usage() { printf 'usage: %s <image> [<old-image>]\n' "${0##*/}" >&2; exit 2; }
[[ $# -ge 1 && $# -le 2 && -n "$1" && "$1" != -* ]] || usage
IMAGE="$1"
OLD_IMAGE="${2:-}"
DOCKER="${DOCKER:-docker}"
CORE_IMAGE="${CORE_IMAGE:-ghcr.io/home-assistant/home-assistant:2026.11.3}"
P="${REALCORE_PREFIX:-caddy-mtls-core}"
SUBNET="${REALCORE_SUBNET:-10.233.44.0/24}"
EVIDENCE="${REALCORE_EVIDENCE:-}"
NET="${P}-net"
CORE="${P}-ha"
CLIENT="${P}-client"
DOMAIN="caddy-mtls-core.localhost"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
PASSWORD="core-test-$$-${RANDOM}${RANDOM}"
SUPERVISOR_LOG=/tmp/supervisor-requests.jsonl
CONTAINERS=()
PASS_COUNT=0
FAIL_COUNT=0
ADDON=""
ADDON_IP=""
# A file with the header key for the next boot_addon (header authentication).
ADDON_KEY_FILE=""
TOKEN=""
SUMMARY=()

log() { printf '[real-core] %s\n' "$*" >&2; }
pass() { PASS_COUNT=$((PASS_COUNT + 1)); printf 'PASS  %s\n' "$1"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); printf 'FAIL  %s\n' "$1"; }
check() { local name="$1"; shift; if "$@"; then pass "${name}"; else fail "${name}"; fi; }
note() { SUMMARY+=("$1"); log "$1"; }
wait_for() {
    local timeout="$1" deadline
    shift
    deadline=$((SECONDS + timeout))
    until "$@"; do
        (( SECONDS >= deadline )) && return 1
        sleep 1
    done
}
save_evidence() {
    [[ -n "${EVIDENCE}" ]] || return 0
    mkdir -p "${EVIDENCE}"
    "${DOCKER}" logs "${CORE}" >"${EVIDENCE}/core.log" 2>&1 || true
    local c
    for c in "${CONTAINERS[@]+"${CONTAINERS[@]}"}"; do
        [[ "${c}" == "${CORE}" || "${c}" == "${CLIENT}" ]] && continue
        "${DOCKER}" logs "${c}" >"${EVIDENCE}/${c}.log" 2>&1 || true
    done
}
cleanup() {
    local rc=$? c
    save_evidence || true
    for c in "${CONTAINERS[@]+"${CONTAINERS[@]}"}"; do
        "${DOCKER}" rm -f "${c}" >/dev/null 2>&1 || true
    done
    "${DOCKER}" network rm "${NET}" >/dev/null 2>&1 || true
    rm -rf "${WORK}"
    exit "${rc}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

command -v jq >/dev/null || { log "jq is required"; exit 2; }
"${DOCKER}" image inspect "${IMAGE}" >/dev/null 2>&1 || { log "image ${IMAGE} not found"; exit 2; }
"${DOCKER}" image inspect "${CORE_IMAGE}" >/dev/null 2>&1 || "${DOCKER}" pull "${CORE_IMAGE}" >/dev/null
if [[ -n "${OLD_IMAGE}" ]]; then
    "${DOCKER}" image inspect "${OLD_IMAGE}" >/dev/null 2>&1 || "${DOCKER}" pull "${OLD_IMAGE}" >/dev/null
fi

# The test network must not overlap another Docker network.
while read -r subnet; do
    [[ -z "${subnet}" ]] && continue
    if python3 -c 'import ipaddress,sys; sys.exit(0 if ipaddress.ip_network(sys.argv[1]).overlaps(ipaddress.ip_network(sys.argv[2])) else 1)' \
        "${SUBNET}" "${subnet}" 2>/dev/null; then
        log "REALCORE_SUBNET ${SUBNET} overlaps the Docker network subnet ${subnet}"
        exit 2
    fi
done < <("${DOCKER}" network ls -q | xargs "${DOCKER}" network inspect -f '{{range .IPAM.Config}}{{println .Subnet}}{{end}}')

"${DOCKER}" network create --internal --subnet "${SUBNET}" "${NET}" >/dev/null

# --- Home Assistant Core, a client --------------------------------------------
log "starting Home Assistant Core (${CORE_IMAGE})"
CONTAINERS+=("${CORE}")
"${DOCKER}" run -d --name "${CORE}" --network "${NET}" --network-alias homeassistant \
    --memory 2g -e TZ=Europe/Vienna "${CORE_IMAGE}" >/dev/null
CONTAINERS+=("${CLIENT}")
"${DOCKER}" run -d --name "${CLIENT}" --network "${NET}" --memory 256m --entrypoint sleep "${IMAGE}" 86400 >/dev/null
tar -C "${SCRIPT_DIR}" --owner=0 --group=0 --numeric-owner -cf - real-core-ws.py | "${DOCKER}" cp - "${CLIENT}:/tmp"
CLIENT_IP="$("${DOCKER}" inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${CLIENT}")"

client() { "${DOCKER}" exec "${CLIENT}" "$@"; }
core_up() { client curl -fsS -o /dev/null --max-time 5 http://homeassistant:8123/manifest.json 2>/dev/null; }
core_down() { ! core_up; }
# Lines in Core's log.
core_count() { "${DOCKER}" logs "${CORE}" 2>&1 | grep -c -F -- "$1" || true; }
REFUSED_A="A request from a reverse proxy was received from"
REFUSED_B="Received X-Forwarded-For header from an untrusted proxy"
refused_lines() { echo $(( $(core_count "${REFUSED_A}") + $(core_count "${REFUSED_B}") )); }
ws() { client python3 /tmp/real-core-ws.py ws://homeassistant:8123/api/websocket "${TOKEN}" "$@"; }

check "core: Home Assistant answers on homeassistant:8123" wait_for 600 core_up

# Onboarding: the owner user, then an access token.
auth_code="$(client curl -fsS -X POST http://homeassistant:8123/api/onboarding/users \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg p "${PASSWORD}" '{client_id: "http://homeassistant:8123/", name: "Test", username: "test", password: $p, language: "en"}')" \
    | jq -r .auth_code)" || auth_code=""
TOKEN="$(client curl -fsS -X POST http://homeassistant:8123/auth/token \
    --data-urlencode grant_type=authorization_code --data-urlencode "code=${auth_code}" \
    --data-urlencode client_id=http://homeassistant:8123/ | jq -r .access_token)" || TOKEN=""
check "core: onboarded, access token" test -n "${TOKEN}" -a "${TOKEN}" != null
check "core: websocket direct (auth + ping)" eval '[[ "$(ws ping 2>&1)" == pong ]]'
http_config() { ws call '{"type": "http/config"}' | jq -c '.result'; }
check "core: HTTP config in storage, no reverse proxy (Core's default)" eval '
    [[ "$(http_config | jq -r ".stable.use_x_forwarded_for // false")" == false ]]'

# --- the add-on ------------------------------------------------------------------
# The monitor's intervals: short (control 2 s, test 5 s) for the first phases;
# the last phases (the review's scenarios B-3 to B-6) use the defaults
# (control 12 s, test 60 s, 2.5 s while nothing is decided).
ADDON_ENV=(-e CADDY_MTLS_UPSTREAM_CONTROL_SECONDS=2 -e CADDY_MTLS_UPSTREAM_TEST_SECONDS=5)
# boot_addon <name> <image> <forwarded_headers> [<data.tar>]
boot_addon() {
    local name="${P}-$1" image="$2" fwd="$3" dir="${WORK}/$1"
    ADDON="${name}"
    mkdir -p "${dir}/data" "${dir}/tmp/.bashio"
    jq -n --arg fwd "${fwd}" --rawfile key "${ADDON_KEY_FILE:-/dev/null}" '{domain: "caddy-mtls-core.localhost", email: "test@example.com",
        upstream_host: "homeassistant", upstream_port: 8123, mtls_enabled: true,
        ca_country: "AT", ca_state: "Styria", ca_locality: "Graz", ca_organization: "LinumIQ",
        ca_common_name: "Real Core test CA", client_names: ["alice"], client_cert_password: "real-core-test",
        acme_dns_provider: "none", dns_api_token: "", log_level: "info", access_log: false,
        forwarded_headers: $fwd, cert_expiry_warn_days: [30, 14, 7, 1], cert_check_interval_hours: 6}
        + (if $key == "" then {} else {header_auth_key: $key} end)' \
        >"${dir}/data/options.json"
    cp "${dir}/data/options.json" "${dir}/tmp/.bashio/addons.self.options.config.cache"
    printf '%s\n' '{"name":"Caddy mTLS Proxy","network":{"80/tcp":8080,"443/tcp":8443}}' >"${dir}/tmp/.bashio/addons.self.info.cache"
    chmod -R go+rX "${dir}"
    CONTAINERS+=("${name}")
    "${DOCKER}" create --name "${name}" --network "${NET}" --memory 512m \
        -e ACME_CA_URL=http://127.0.0.1:9/directory -e TZ=Europe/Vienna \
        -e SUPERVISOR_TOKEN=real-core-test -e SUPERVISOR_URL=http://127.0.0.1:8765 \
        "${ADDON_ENV[@]+"${ADDON_ENV[@]}"}" "${image}" >/dev/null
    if [[ -n "${4:-}" ]]; then
        "${DOCKER}" cp - "${name}:/" <"$4"
    fi
    tar -C "${dir}/data" --owner=0 --group=0 --numeric-owner -cf - . | "${DOCKER}" cp - "${name}:/data"
    tar -C "${dir}/tmp" --owner=0 --group=0 --numeric-owner -cf - . | "${DOCKER}" cp - "${name}:/tmp"
    tar -C "${SCRIPT_DIR}" --owner=0 --group=0 --numeric-owner -cf - fake-supervisor.py | "${DOCKER}" cp - "${name}:/tmp"
    "${DOCKER}" start "${name}" >/dev/null
    "${DOCKER}" exec -d "${name}" python3 /tmp/fake-supervisor.py 8765 "${SUPERVISOR_LOG}"
    ADDON_IP="$("${DOCKER}" inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${name}")"
    wait_for 120 addon_booted || return 1
    # alice's client certificate for the client container
    "${DOCKER}" exec "${name}" cat /data/certs/mTLS-client-alice.crt | "${DOCKER}" exec -i "${CLIENT}" sh -c 'cat > /tmp/alice.crt'
    "${DOCKER}" exec "${name}" cat /data/certs/mTLS-client-alice.key | "${DOCKER}" exec -i "${CLIENT}" sh -c 'cat > /tmp/alice.key'
    wait_for 60 tls_up
}
aexec() { "${DOCKER}" exec "${ADDON}" "$@"; }
addon_booted() {
    aexec curl -fsS -o /dev/null --max-time 5 http://127.0.0.1:2019/config/ 2>/dev/null &&
        "${DOCKER}" logs "${ADDON}" 2>&1 | grep -F "Init complete:" >/dev/null
}
# proxied <path> [curl args]: "<body> <code>" of a request through port 443
# with alice's certificate.
proxied() {
    local path="$1"
    shift
    client curl -sk --max-time 15 --resolve "${DOMAIN}:443:${ADDON_IP}" \
        --cert /tmp/alice.crt --key /tmp/alice.key -w ' %{http_code}' "$@" "https://${DOMAIN}${path}" 2>/dev/null || true
}
code_of() { local out; out="$(proxied "$@")"; printf '%s' "${out##* }"; }
# The TLS handshake with alice's certificate succeeds (no HTTP request: it
# would reach Core and could be counted as a refusal).
tls_up() {
    client sh -c 'openssl s_client -connect "$0:443" -servername "$1" -cert /tmp/alice.crt -key /tmp/alice.key \
        -brief </dev/null 2>&1' "${ADDON_IP}" "${DOMAIN}" | grep -E "^(Protocol version|CONNECTION ESTABLISHED)" >/dev/null
}
mode_is() { [[ "$(aexec jq -r '"\(.mode) \(.applied)"' /data/upstream.json 2>/dev/null)" == "$1 true" ]]; }
card_is() { aexec curl -fsS --max-time 10 http://127.0.0.1:8099/upstream 2>/dev/null | grep -F "data-state=\"$1\"" >/dev/null; }
ws_proxied() {
    client python3 /tmp/real-core-ws.py "wss://${DOMAIN}/api/websocket" "${TOKEN}" \
        --connect "${ADDON_IP}:443" --cert /tmp/alice.crt --key /tmp/alice.key ping 2>&1
}
# wrong_token_logged_as <address>: a request with a wrong token through the
# proxy makes Core log the address it believes the client has.
wrong_token_logged_as() {
    local before
    # shellcheck disable=SC2034 # used in the eval'd condition
    before="$(core_count "Login attempt or request with invalid authentication from")"
    [[ "$(code_of /api/ -o /dev/null -H 'Authorization: Bearer wrong-token')" == 401 ]] || return 1
    wait_for 10 eval '(( $(core_count "Login attempt or request with invalid authentication from") > before ))' || return 1
    "${DOCKER}" logs "${CORE}" 2>&1 | grep -F "Login attempt or request with invalid authentication from" \
        | tail -n 1 | grep -F "($1)" >/dev/null
}
stop_addon() { "${DOCKER}" stop -t 30 "${ADDON}" >/dev/null 2>&1 || true; }
supervisor_got() {
    aexec sh -c 'test -f "$1" && jq -s -e "$0" "$1"' "[.[] | select($1)] | length > 0" "${SUPERVISOR_LOG}" >/dev/null 2>&1
}
# shellcheck disable=SC2016
no_upstream_note() {
    ! supervisor_got '.body.notification_id == "caddy_mtls_upstream_refuses" and (.path | endswith("/create"))'
}
core_running() { [[ "$("${DOCKER}" inspect -f '{{.State.Running}}' "${CORE}" 2>/dev/null)" == true ]]; }
# Core restarts by itself after http/config/configure (as after Save and
# restart in the UI); promote = "Confirm" in the dialog after the restart.
configure_core() { # configure_core <config-json>
    ws call "{\"type\": \"http/config/configure\", \"config\": $1}" | jq -e '.success and .result.restart' >/dev/null || return 1
    wait_for 120 core_down || log "Core did not go down visibly (restart quicker than 1 s?)"
    if ! wait_for 600 core_up; then
        core_running && return 1
        log "the Core container ended at the restart; starting it again"
        "${DOCKER}" start "${CORE}" >/dev/null
        wait_for 600 core_up || return 1
    fi
    ws call '{"type": "http/config/promote"}' | jq -e '.success' >/dev/null
}

# --- old: 2.1.x ------------------------------------------------------------------
if [[ -n "${OLD_IMAGE}" ]]; then
    log "old: ${OLD_IMAGE}"
    r0="$(refused_lines)"
    if boot_addon old "${OLD_IMAGE}" auto; then
        out="$(proxied /manifest.json)"
        check "old: 2.1.x - the page is answered \"400: Bad Request\" by Core" test "${out}" == "400: Bad Request 400"
        check "old: Core logged 'A request from a reverse proxy was received from ${ADDON_IP}'" \
            eval '"${DOCKER}" logs "${CORE}" 2>&1 | grep -F "${REFUSED_A} ${ADDON_IP}, but your HTTP integration is not set-up for reverse proxies" >/dev/null'
        note "old (2.1.x): Core log lines from refused forwarded requests: $(( $(refused_lines) - r0 )) for 1 proxied request (2.1.x sends no probe; the readiness check is a TLS handshake only)"
    else
        fail "old: add-on booted"
    fi
    stop_addon
fi

# --- always ----------------------------------------------------------------------
log "always: forwarded_headers always, Core without reverse-proxy settings"
r0="$(refused_lines)"
if boot_addon always "${IMAGE}" always; then
    r_start="$(( $(refused_lines) - r0 ))"
    check "always: mode pass, card broken (red)" eval 'mode_is pass && wait_for 20 card_is broken'
    out="$(proxied /manifest.json)"
    check "always: a proxied request is answered \"400: Bad Request\" by Core" test "${out}" == "400: Bad Request 400"
    check "always: notification at the (fake) Supervisor" wait_for 30 supervisor_got \
        '.path == "/core/api/services/persistent_notification/create" and .body.notification_id == "caddy_mtls_upstream_refuses"'
    r1="$(refused_lines)"
    sleep 30
    check "always: no probing lines in Core's log during 30 s (control requests only)" test "$(refused_lines)" == "${r1}"
    note "always: Core log lines: ${r_start} from the start probe, 1 per proxied request, 0 in 30 s of watching"
else
    fail "always: add-on booted"
fi
stop_addon

# --- auto: strip -------------------------------------------------------------------
log "auto: forwarded_headers auto (mTLS), Core without reverse-proxy settings"
r0="$(refused_lines)"
if boot_addon auto "${IMAGE}" auto; then
    r_start="$(( $(refused_lines) - r0 ))"
    check "auto: refused at the start -> mode strip, card strip" eval 'mode_is strip && wait_for 20 card_is strip'
    out="$(proxied /manifest.json)"
    check "auto: the page loads through the mTLS port (manifest.json 200)" eval '[[ "${out}" == *"\"name\""*" 200" ]]'
    out="$(proxied / -L)"
    check "auto: the frontend loads (/, redirects followed: 200 with HTML)" eval '[[ "${out}" == *"<html"*" 200" ]]'
    check "auto: Core logs the add-on's address (${ADDON_IP}) for a wrong token" wrong_token_logged_as "${ADDON_IP}"
    check "auto: websocket through the proxy (strip): auth_ok + pong" eval '[[ "$(ws_proxied)" == pong ]]'
    check "auto: no notification (strip works)" no_upstream_note
    r1="$(refused_lines)"
    sleep 60
    check "auto: no probing lines in Core's log during 60 s of watching (strip)" test "$(refused_lines)" == "${r1}"
    note "auto (strip): Core log lines: ${r_start} from the start probe, 0 in 60 s of watching (control every 2 s)"

    # --- yaml: an http: block in configuration.yaml is ignored by Core 2026.7+
    log "yaml: http: block in configuration.yaml, Core restart"
    "${DOCKER}" exec "${CORE}" cp /config/configuration.yaml /config/configuration.yaml.cm-backup
    "${DOCKER}" exec "${CORE}" sh -c "printf '\nhttp:\n  use_x_forwarded_for: true\n  trusted_proxies:\n    - ${SUBNET}\n' >> /config/configuration.yaml"
    r0="$(refused_lines)"
    "${DOCKER}" restart -t 60 "${CORE}" >/dev/null
    check "yaml: Core back after the restart" wait_for 600 core_up
    sleep 12
    check "yaml: Core 2026.7+ ignores the block: still refused, the add-on stays in strip" mode_is strip
    check "yaml: Core raised the repair 'yaml_still_present_after_migration'" eval '
        ws call "{\"type\": \"repairs/list_issues\"}" | jq -e "[.result.issues[] | select(.issue_id == \"yaml_still_present_after_migration\")] | length == 1" >/dev/null'
    note "yaml: Core log lines after the restart: $(( $(refused_lines) - r0 )) (the add-on's test request after it noticed the restart)"
    "${DOCKER}" exec "${CORE}" mv /config/configuration.yaml.cm-backup /config/configuration.yaml

    # --- ui: the reverse-proxy settings as Settings > System > Network does it
    log "ui: http/config/configure (trusted proxies ${SUBNET}), restart, promote"
    r0="$(refused_lines)"
    # shellcheck disable=SC2034 # used in an eval'd check
    lines="$("${DOCKER}" logs "${ADDON}" 2>&1 | wc -l)"
    check "ui: Core configured, restarted and confirmed" \
        configure_core "{\"use_x_forwarded_for\": true, \"trusted_proxies\": [\"${SUBNET}\"]}"
    check "ui: the running add-on switched to mode pass without a restart" wait_for 60 mode_is pass
    check "ui: the add-on logged the switch and reloaded Caddy" eval '
        "${DOCKER}" logs "${ADDON}" 2>&1 | tail -n "+$((lines + 1))" | grep -F "Forwarding headers: mode strip -> pass" >/dev/null'
    check "ui: card accepted" wait_for 30 card_is accepted
    check "ui: Core logs the client's own address (${CLIENT_IP}) for a wrong token" wrong_token_logged_as "${CLIENT_IP}"
    check "ui: websocket through the proxy (pass): auth_ok + pong" eval '[[ "$(ws_proxied)" == pong ]]'
    sleep 20
    note "ui (pass): Core log lines from the restart until 20 s after the switch: $(( $(refused_lines) - r0 )) (tests every 5 s while trusted)"
    "${DOCKER}" cp "${ADDON}:/data" - >"${WORK}/data-auto.tar"
else
    fail "auto: add-on booted"
fi
stop_addon

# --- start: a new add-on container with the trusting Core ----------------------------
log "start: new add-on container, Core trusts the network"
r0="$(refused_lines)"
if [[ -s "${WORK}/data-auto.tar" ]] && boot_addon start "${IMAGE}" auto "${WORK}/data-auto.tar"; then
    check "start: accepted at the start -> mode pass, card accepted" eval 'mode_is pass && wait_for 20 card_is accepted'
    check "start: Core logs the client's own address (${CLIENT_IP})" wrong_token_logged_as "${CLIENT_IP}"
    sleep 20
    note "start (pass): Core log lines: $(( $(refused_lines) - r0 )) (start probe and tests every 5 s while trusted)"

    # --- back: settings removed -> strip
    log "back: reverse-proxy settings removed, restart, promote"
    r0="$(refused_lines)"
    check "back: Core configured without reverse proxy, restarted, confirmed" configure_core '{}'
    check "back: the add-on switched to mode strip" wait_for 60 mode_is strip
    check "back: card strip" wait_for 30 card_is strip
    check "back: websocket through the proxy (strip again): auth_ok + pong" eval '[[ "$(ws_proxied)" == pong ]]'
    r1="$(refused_lines)"
    sleep 30
    check "back: no probing lines during 30 s after the switch" test "$(refused_lines)" == "${r1}"
    note "back: Core log lines: $(( r1 - r0 )) (the refused test that switched to strip), then 0 in 30 s"
else
    fail "start: add-on booted"
fi
stop_addon

# --- header: header authentication (2.3.0) -------------------------------------------
# A per-run fake key, read from files only (never on a command line).
log "header: header authentication (mTLS on, a key), no client certificate"
printf 'fakekey.NOT-A-SECRET.%s' "$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')" >"${WORK}/key"
printf 'X-Custom-PSK: %s\n' "$(cat "${WORK}/key")" | "${DOCKER}" exec -i "${CLIENT}" sh -c 'cat > /tmp/h-key'
# keyed <path> [curl args]: "<body> <code>" through port 443 WITHOUT a client
# certificate.
keyed() {
    local path="$1"
    shift
    client curl -sk --max-time 15 --resolve "${DOMAIN}:443:${ADDON_IP}" -w ' %{http_code}' "$@" \
        "https://${DOMAIN}${path}" 2>/dev/null || true
}
ADDON_KEY_FILE="${WORK}/key"
if boot_addon header "${IMAGE}" auto; then
    out="$(keyed /manifest.json -H @/tmp/h-key)"
    check "header: with the key, no certificate: Core's manifest.json 200" eval '[[ "${out}" == *"\"name\""*" 200" ]]'
    out="$(keyed / -L -H @/tmp/h-key)"
    check "header: with the key: the frontend loads (/, redirects followed: 200 with HTML)" eval '[[ "${out}" == *"<html"*" 200" ]]'
    out="$(keyed /api/ -H @/tmp/h-key -H "Authorization: Bearer ${TOKEN}")"
    check "header: with the key and the long-lived token: Core's API answers (200 API running)" eval '[[ "${out}" == *"API running"*" 200" ]]'
    check "header: without certificate and key: 403 (page and API)" eval '
        [[ "$(keyed / -o /dev/null)" == " 403" && "$(keyed /api/ -o /dev/null -H "Authorization: Bearer ${TOKEN}")" == " 403" ]]'
    check "header: websocket with the key, no certificate: auth_ok + pong" eval '
        [[ "$(client python3 /tmp/real-core-ws.py "wss://${DOMAIN}/api/websocket" "${TOKEN}" --connect "${ADDON_IP}:443" \
            --header-file /tmp/h-key ping 2>&1)" == pong ]]'
    check "header: websocket without the key: refused (403)" eval '
        [[ "$(client python3 /tmp/real-core-ws.py "wss://${DOMAIN}/api/websocket" "${TOKEN}" --connect "${ADDON_IP}:443" ping 2>&1)" == *"handshake failed"*"403"* ]]'
    check "header: alice's certificate still works without the key" eval '[[ "$(code_of /manifest.json -o /dev/null)" == 200 ]]'
    check "header: the key is not in the add-on log" eval '! "${DOCKER}" logs "${ADDON}" 2>&1 | grep -F -f "${WORK}/key" >/dev/null'
else
    fail "header: add-on booted"
fi
stop_addon
ADDON_KEY_FILE=""

# ==================================================================================
# The review's scenarios with the default intervals (control 12 s, test 60 s).
# ==================================================================================
ADDON_ENV=()
# seen_at: the time of the add-on's last successful control request.
seen_at() { aexec jq -r '.seen_at // 0' /data/upstream.json 2>/dev/null || echo 0; }
alog_since() { "${DOCKER}" logs "${ADDON}" 2>&1 | tail -n "+$(( $1 + 1 ))"; }
alines() { "${DOCKER}" logs "${ADDON}" 2>&1 | wc -l; }
# shellcheck disable=SC2016
hidden_raised() {
    supervisor_got '.body.notification_id == "caddy_mtls_upstream_addresses_hidden" and (.path | endswith("/create"))'
}

# --- B-5: the first start with Core down ------------------------------------------
log "first-boot: Core stopped at the add-on's first start, then started"
"${DOCKER}" stop -t 60 "${CORE}" >/dev/null
r0="$(refused_lines)"
if boot_addon first "${IMAGE}" auto; then
    check "first-boot: nothing decided, upstream down -> mode pass, card unreachable" eval '
        mode_is pass && wait_for 20 card_is unreachable'
    "${DOCKER}" start "${CORE}" >/dev/null
    t0=${SECONDS}
    first_answer=""
    switched=""
    codes=()
    while (( SECONDS - t0 < 400 )); do
        c="$(code_of /manifest.json -o /dev/null --max-time 3)"
        codes+=("$(( SECONDS - t0 )):${c}")
        if [[ -z "${first_answer}" && "${c}" != 502 && "${c}" != 000 && -n "${c}" ]]; then first_answer=$(( SECONDS - t0 )); fi
        if mode_is strip; then switched=$(( SECONDS - t0 )); break; fi
        sleep 0.5
    done
    log "first-boot timeline (s:code): ${codes[*]}"
    check "first-boot: switched to strip after Core came up" test -n "${switched}"
    window=$(( ${switched:-999} - ${first_answer:-0} ))
    check "first-boot: from Core's first answer to the switch <= 5 s (polling every 2.5 s; was about 10 s)" \
        test "${window}" -le 5
    n400="$(printf '%s\n' "${codes[@]}" | grep -c ':400$' || true)"
    note "first-boot: Core answered after ${first_answer:-?} s, the add-on switched to strip after ${switched:-never} s (${window} s later); 400s seen by a visitor polling every 0.5 s: ${n400}; Core log lines: $(( $(refused_lines) - r0 )) (1 probe + the visitor's refused requests)"
    sleep 3 # the monitor raises its notifications in the tick that switched
    check "first-boot: no 'visitor addresses are hidden' notification (Core never trusted the add-on; B2-1)" \
        eval '! hidden_raised'
    # shellcheck disable=SC2016
    check "first-boot: ... while the fake Supervisor got the start's dismiss of it (it does record)" \
        supervisor_got '.body.notification_id == "caddy_mtls_upstream_addresses_hidden" and (.path | endswith("/dismiss"))'
else
    fail "first-boot: add-on booted"
fi
stop_addon

# --- B-4: Core restarts right after the add-on started -----------------------------
log "early-restart: add-on starts in strip, Core gets the reverse-proxy settings 1 s later"
if boot_addon early "${IMAGE}" auto; then
    check "early-restart: strip at the start" eval 'mode_is strip && wait_for 20 card_is strip'
    sleep 1
    t0=${SECONDS}
    r0="$(refused_lines)"
    check "early-restart: Core configured, restarted and confirmed" \
        configure_core "{\"use_x_forwarded_for\": true, \"trusted_proxies\": [\"${SUBNET}\"]}"
    t_up=$(( SECONDS - t0 ))
    check "early-restart: the add-on notices the restart and switches to pass (no Check again)" wait_for 40 mode_is pass
    note "early-restart: Core back after ${t_up} s, the add-on in mode pass $(( SECONDS - t0 - t_up )) s later; Core log lines: $(( $(refused_lines) - r0 ))"

    # --- B-3: trust lost while passing addresses on --------------------------------
    log "untrust: reverse-proxy settings removed while in pass"
    r0="$(refused_lines)"
    l0="$(alines)"
    t0=${SECONDS}
    check "untrust: Core configured without reverse proxy, restarted, confirmed" configure_core '{}'
    t_up=$(( SECONDS - t0 ))
    check "untrust: the add-on switches to strip within one control interval (not the minute test)" wait_for 20 mode_is strip
    took=$(( SECONDS - t0 - t_up ))
    check "untrust: within 20 s of Core being back (was up to 60 s)" test "${took}" -le 20
    sleep 2 # Core writes its log lines asynchronously
    check "untrust: the notification 'visitor addresses are hidden' was raised" wait_for 15 hidden_raised
    note "untrust: Core back after ${t_up} s, the add-on in strip ${took} s later; Core log lines: $(( $(refused_lines) - r0 )) (the test that switched)"

    # --- B-6: a paused Core is slow, not down -----------------------------------------
    log "stall: Core paused for 15 s, 3 s after a control request (one control falls into it)"
    # Two answered control requests in a row first (Core settled after its
    # restart, the add-on's failure count at 0), then align with the second.
    for _ in 1 2; do
        # shellcheck disable=SC2034 # used in the eval'd condition
        s0="$(seen_at)"
        wait_for 40 eval '[[ "$(seen_at)" != "${s0}" ]]' || log "stall: no answered control request seen"
    done
    sleep 3
    r0="$(refused_lines)"
    l0="$(alines)"
    "${DOCKER}" pause "${CORE}" >/dev/null
    sleep 15
    "${DOCKER}" unpause "${CORE}" >/dev/null
    sleep 15
    check "stall 15 s: still strip, no state change" eval 'mode_is strip && card_is strip'
    check "stall 15 s: no 'does not answer' / 502 warning in the add-on log" eval '
        ! alog_since "${l0}" | grep -E "does not answer|502" >/dev/null'
    n15=$(( $(refused_lines) - r0 ))
    check "stall 15 s: no line in Core's log (was 1)" test "${n15}" == 0
    note "stall 15 s (one control request without answer): Core log lines: ${n15}"
    log "stall: Core paused for 40 s (at least two control requests without answer)"
    r0="$(refused_lines)"
    l0="$(alines)"
    "${DOCKER}" pause "${CORE}" >/dev/null
    sleep 40
    unanswered="$(alog_since "${l0}" | grep -F "does not answer" | tail -n 1)"
    "${DOCKER}" unpause "${CORE}" >/dev/null
    sleep 20
    log "stall 40 s: ${unanswered}"
    check "stall 40 s: called unreachable after two unanswered control requests, without claiming a 502" eval '
        [[ "${unanswered}" == *"does not answer (timed out)"*"requests wait for it or fail"* ]]'
    check "stall 40 s: back in strip after Core answered again" wait_for 30 mode_is strip
    n40=$(( $(refused_lines) - r0 ))
    note "stall 40 s (two or more control requests without answer): Core log lines: ${n40} (the test after it answered again)"
else
    fail "early-restart: add-on booted"
fi
stop_addon

printf '\nSummary of Home Assistant log lines caused by refused forwarded requests:\n'
printf '  %s\n' "${SUMMARY[@]+"${SUMMARY[@]}"}"
printf '\n%d passed, %d failed\n' "${PASS_COUNT}" "${FAIL_COUNT}"
(( FAIL_COUNT == 0 ))
