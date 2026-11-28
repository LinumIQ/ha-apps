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
# dashboard and the shared UI's static files, state, a .p12 download, a
# client add and a revocation, each
# with `openssl ca` and a forced `caddy reload`), the "Public certificate"
# card (Caddy's acme.log, openssl x509 on Caddy's storage, the live probe of
# port 443), the cert-monitor (sensors and the "no public certificate"
# notification at a fake Supervisor inside the container, then its
# dismissal), the forwarding headers (the start probe, a fake Home Assistant
# that refuses X-Forwarded-For: the monitor's switch to mode strip with a
# rewritten snippet and a reload, "Check again"), the local-network port
# (lan.py, the listener on 4443), a clean `docker stop`
# (< 10 s, exit 0, no s6 warnings) and a
# restart as Supervisor does it (a new container with the previous /data)
# with a new client name and a new client_cert_password (issuance and .p12
# re-encryption at start-up). Header authentication (2.3.0) is on: the key
# file (headerauth.py), the list of active client certificates (caddyctl.py,
# at the start and before each reload) and the gate run under the profile;
# custom Caddyfile snippets (2.3.0) are in use: customconf.py reads
# /config/caddy (README.txt written), copies the files, Caddy adapts the
# configuration twice for the integrity check; after the restart a reload
# whose snippet's key file was removed falls back to the add-on's own
# configuration and drops the snippets (rename, removal, reload lock).
# Fails on any AppArmor denial for the profile. Needs openssl on the host.
#
# No external network traffic: the container runs with --network none and
# ACME_CA_URL points at a closed local port. A profile that was not loaded
# before is unloaded again on exit.
# Env: DOCKER (default docker), SMOKE_PREFIX (container name prefix, default
# caddy-mtls-aa-smoke).
# ==============================================================================
# Helper functions are called indirectly (check, wait_for, trap).
# shellcheck disable=SC2329
set -euo pipefail

IMAGE="${1:?usage: apparmor-smoke.sh <image> <apparmor.txt>}"
PROFILE_FILE="${2:?usage: apparmor-smoke.sh <image> <apparmor.txt>}"
DOCKER="${DOCKER:-docker}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE="$(sed -n 's/^profile \([A-Za-z0-9_-]*\) .*/\1/p' "${PROFILE_FILE}" | head -n 1)"
CTR1="${SMOKE_PREFIX:-caddy-mtls-aa-smoke}-$$"
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
# Header authentication with a per-run fake key (from a file: never on a
# command line).
printf 'fakekey.NOT-A-SECRET.%s' "$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')" >"${WORK}/key"
jq --rawfile key "${WORK}/key" '. + {header_auth_key: $key}' "${WORK}/data/options.json" >"${WORK}/options.json"
mv "${WORK}/options.json" "${WORK}/data/options.json"
cp "${WORK}/data/options.json" "${WORK}/tmp/.bashio/addons.self.options.config.cache"
# Custom snippets (the addon_config mapping is /config).
mkdir -p "${WORK}/config/caddy"
printf '%s\n' 'respond /aa-custom "aa custom" 200' >"${WORK}/config/caddy/site.caddy"
printf '%s\n' 'servers {' '	protocols h1 h2' '}' >"${WORK}/config/caddy/global.caddy"
# The add-on's network settings with the local-network port (4443/tcp) on.
printf '%s\n' '{"name":"Caddy mTLS Proxy","network":{"80/tcp":8080,"443/tcp":8443,"4443/tcp":9443}}' \
    >"${WORK}/tmp/.bashio/addons.self.info.cache"
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
    -e CADDY_MTLS_UPSTREAM_CONTROL_SECONDS=1 -e CADDY_MTLS_UPSTREAM_TEST_SECONDS=3 \
    "${IMAGE}" >/dev/null
copy_into "${WORK}/data" /data
copy_into "${WORK}/tmp" /tmp
tar -C "${WORK}" --owner=0 --group=0 --numeric-owner -cf - config | "${DOCKER}" cp - "${CTR}:/"
tar -C "${SCRIPT_DIR}" --owner=0 --group=0 --numeric-owner -cf - fake-supervisor.py fake-upstream.py | "${DOCKER}" cp - "${CTR}:/tmp"
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
# The local-network site (lan.py read the container's routes under the
# profile) and Caddy's listener on 4443.
check "local-network port rendered (LAN port logged)" logs_contain "LAN port:    https://home.example.com:9443/"
lan_listening() {
    cexec curl -fsS http://127.0.0.1:2019/config/ 2>/dev/null | jq -e '[.apps.http.servers[].listen[]] | index(":4443") != null' >/dev/null &&
        cexec sh -c 'grep -qi ":115B " /proc/net/tcp6 /proc/net/tcp' # 0x115B = 4443, listening
}
check "Caddy listens on 4443 under ${PROFILE}" wait_for 30 lan_listening
check "custom snippets in use under ${PROFILE}: README.txt written, copies 0600, integrity check passed" eval '
    test "$(cexec jq -r .state /run/caddy-mtls/custom.json)" == loaded &&
    cexec test -s /config/caddy/README.txt && test "$(cexec stat -c %a /etc/caddy/custom/site.caddy)" == 600 &&
    cexec curl -fsS http://127.0.0.1:2019/config/ | jq -e "[.apps.http.servers[] | select(.listen == [\":443\"]) | .protocols] == [[\"h1\", \"h2\"]]" >/dev/null'
check "header authentication on: key file 0600 (headerauth.py), the list of active certificates written (caddyctl.py)" eval '
    test "$(cexec stat -c %a /etc/caddy/header-auth.key)" == 600 &&
    cexec grep -E "^not vars \{http.request.tls.client.fingerprint\} [0-9a-f]{64} [0-9a-f]{64}$" /etc/caddy/client-fingerprints.caddy >/dev/null'

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
# forwarded_headers (2.2.0): the start probe found no upstream (mode pass);
# a fake Home Assistant that refuses X-Forwarded-For comes up on
# 127.0.0.1:8123 - the monitor notices, sends the test request, switches to
# mode strip (rewrites /etc/caddy/forwarded-headers.caddy, caddy reload),
# all under the profile.
snippet_is() { cexec grep -qx "# Forwarding headers, mode $1 - written by the Caddy mTLS Proxy add-on" /etc/caddy/forwarded-headers.caddy 2>/dev/null; }
check "forwarding snippet written at the start (mode pass, upstream down)" snippet_is pass
"${DOCKER}" exec -d "${CTR}" /usr/lib/cert-mgr/.venv/bin/python3 /tmp/fake-upstream.py 8123 /tmp/up
upstream_card_state() { cexec curl -fsS http://127.0.0.1:8099/upstream 2>/dev/null | sed -n 's/.*data-state="\([a-z_]*\)".*/\1/p' | head -n 1; }
upstream_is_strip() { snippet_is strip && [[ "$(upstream_card_state)" == strip ]]; }
check "upstream came up refusing: the monitor switched to mode strip (snippet + reload)" wait_for 30 upstream_is_strip
code="$(http_code POST /api/upstream/check -H "X-Ingress-Path: ${INGRESS_PREFIX}")"
check "Check again answered (got ${code})" test "${code}" == 303
check "the fake upstream got the test requests (start of the watch + Check again)" \
    test "$(cexec sh -c 'wc -l < /tmp/up/refused.log' 2>/dev/null)" -ge 2
code="$(http_code GET /)"
check "dashboard renders (got ${code})" test "${code}" == 200
# The shared LinumIQ UI (stylesheets, a font, the footer logo, the app mark)
# is readable under the profile.
ui_files_served() {
    local path code
    for path in /static/shared/linumiq.css /static/app.css /static/shared/fonts/inter-latin.woff2 \
        /static/shared/brand/linumiq-logo.png /static/brand/icon.svg; do
        code="$(http_code GET "${path}")"
        [[ "${code}" == 200 ]] || { log "GET ${path}: ${code}"; return 1; }
    done
}
check "panel serves the shared UI files under ${PROFILE}" ui_files_served
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
# shellcheck disable=SC2034 # used in eval'd checks
carol_fp="$(cexec sh -c 'openssl x509 -in /data/certs/mTLS-client-carol.crt -outform DER | sha256sum | cut -d" " -f1')"
# shellcheck disable=SC2034 # used in eval'd checks
bob_fp="$(cexec sh -c 'openssl x509 -in /data/certs/mTLS-client-bob.crt -outform DER | sha256sum | cut -d" " -f1')"
check "the list regenerated before those reloads (caddyctl.py under ${PROFILE}): carol in it, bob out" eval '
    cexec grep -F "${carol_fp}" /etc/caddy/client-fingerprints.caddy >/dev/null &&
    ! cexec grep -F "${bob_fp}" /etc/caddy/client-fingerprints.caddy >/dev/null'
check "the key is not in the log" eval '! "${DOCKER}" logs "${CTR}" 2>&1 | grep -F -f "${WORK}/key" >/dev/null' 
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
# client name and a new client_cert_password - and a .localhost domain, so
# that Caddy's internal issuer gives it a certificate at once and the
# header-authentication gate answers HTTPS requests (no upstream: 502 = let
# through, 403 = refused by the gate, 000 = refused in the handshake).
"${DOCKER}" cp "${CTR}:/data" - >"${WORK}/data.tar"
jq '.client_names += ["dave"] | .client_cert_password = "aa-smoke-password-2" | .domain = "caddy-mtls-aa.localhost"' \
    "${WORK}/data/options.json" >"${WORK}/options.json"
mv "${WORK}/options.json" "${WORK}/data/options.json"
cp "${WORK}/data/options.json" "${WORK}/tmp/.bashio/addons.self.options.config.cache"
# And a site whose certificate files a snippet refers to (2.3.0): after its
# key is removed, a reload falls back to the add-on's own configuration and
# drops the snippets (the rename, the removal and the reload lock under the
# profile).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=aa other (fake)" \
    -addext "subjectAltName=DNS:other.caddy-mtls-aa.localhost" \
    -keyout "${WORK}/config/caddy/o.key" -out "${WORK}/config/caddy/o.crt" >/dev/null 2>&1
printf 'other.caddy-mtls-aa.localhost {\n\ttls /config/caddy/o.crt /config/caddy/o.key\n\trespond "aa other" 200\n}\n' \
    >"${WORK}/config/caddy/sites.caddy"
chmod -R go+rX "${WORK}"
"${DOCKER}" create --name "${CTR2}" --security-opt "apparmor=${PROFILE}" --network none \
    -e ACME_CA_URL=http://127.0.0.1:9/directory -e TZ=Europe/Vienna "${IMAGE}" >/dev/null
CTR="${CTR2}"
"${DOCKER}" cp - "${CTR}:/" <"${WORK}/data.tar"
copy_into "${WORK}/data" /data
copy_into "${WORK}/tmp" /tmp
tar -C "${WORK}" --owner=0 --group=0 --numeric-owner -cf - config | "${DOCKER}" cp - "${CTR}:/"
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
printf 'X-Custom-PSK: %s\n' "$(cat "${WORK}/key")" | "${DOCKER}" exec -i "${CTR}" sh -c 'cat > /tmp/h-key'
gate() { # gate [curl args]: the status of a request to the public site
    cexec curl -sk --max-time 10 -o /dev/null -w '%{http_code}' --resolve caddy-mtls-aa.localhost:443:127.0.0.1 \
        "$@" https://caddy-mtls-aa.localhost/gate-check 2>/dev/null || true
}
gate_up() { [[ "$(gate --http1.1)" == 403 ]]; }
check "restart: the gate under ${PROFILE}: no certificate/no key 403" wait_for 60 gate_up
check "restart: the gate: the key passes (502: no upstream), alice and carol pass, revoked bob fails in the handshake" eval '
    test "$(gate -H @/tmp/h-key)" == 502 &&
    test "$(gate --cert /data/certs/mTLS-client-alice.crt --key /data/certs/mTLS-client-alice.key)" == 502 &&
    test "$(gate --cert /data/certs/mTLS-client-carol.crt --key /data/certs/mTLS-client-carol.key)" == 502 &&
    test "$(gate --cert /data/certs/mTLS-client-bob.crt --key /data/certs/mTLS-client-bob.key)" == 000'
check "restart: site.caddy in use: only after the gate (403 without credentials, the custom answer with the key)" eval '
    test "$(cexec curl -sk --max-time 10 -o /dev/null -w "%{http_code}" --resolve caddy-mtls-aa.localhost:443:127.0.0.1 https://caddy-mtls-aa.localhost/aa-custom)" == 403 &&
    test "$(cexec curl -sk --max-time 10 --resolve caddy-mtls-aa.localhost:443:127.0.0.1 -H @/tmp/h-key https://caddy-mtls-aa.localhost/aa-custom)" == "aa custom"'
check "restart: sites.caddy in use, the fallback kept (/etc/caddy/Caddyfile.own)" eval '
    test "$(cexec jq -r .state /run/caddy-mtls/custom.json)" == loaded && cexec test -s /etc/caddy/Caddyfile.own &&
    test "$(cexec curl -sk --max-time 10 --resolve other.caddy-mtls-aa.localhost:443:127.0.0.1 https://other.caddy-mtls-aa.localhost/)" == "aa other"'
cexec rm /config/caddy/o.key
code="$(http_code POST /api/clients/carol/revoke -H "X-Ingress-Path: ${INGRESS_PREFIX}" --data-urlencode reason=superseded)"
check "restart: o.key removed, carol revoked (got ${code}): the reload fell back and dropped the snippets under ${PROFILE}" eval '
    test "${code}" == 303 && test "$(cexec jq -r .state /run/caddy-mtls/custom.json)" == rejected &&
    test "$(cexec jq -r .dropped /run/caddy-mtls/custom.json)" == reload && ! cexec test -e /etc/caddy/Caddyfile.own &&
    test "$(gate --cert /data/certs/mTLS-client-carol.crt --key /data/certs/mTLS-client-carol.key)" == 000'
check "restart: the key is not in the log" eval '! "${DOCKER}" logs "${CTR}" 2>&1 | grep -F -f "${WORK}/key" >/dev/null'
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
