#!/usr/bin/env bash
# ==============================================================================
# Caddy mTLS Proxy add-on - smoke test (CI and local; needs docker).
#
# usage: smoke.sh <image>
#
# Boots the image OUTSIDE Supervisor (a temporary /data/options.json plus
# bashio's option cache, as Supervisor would provide them) and checks:
#   main       mTLS on, domain caddy-mtls-smoke.localhost (Caddy's internal
#              issuer: a server certificate without any ACME traffic):
#              the panel (health, dashboard, //, /api/state; the shared
#              LinumIQ UI: stylesheets, fonts, logo and app mark with their
#              content types, the layout, no external URLs), the CA and the
#              seeded clients (files, modes, state.json), the Caddyfile and
#              Caddy's admin API (leaf verifier), the plain-HTTP site (CRL,
#              301 to https), real mTLS handshakes, client add / revoke /
#              regenerate through the panel (CRL, active/, Caddy reloaded: a
#              revoked certificate is rejected at once), revoking without the
#              CA database's copy or without the .crt (M2), invalid names
#              (L1), "Regenerate CA" (only active clients re-issued, revoked
#              ones stay revoked: M3), the .p12 download, the ingress
#              allow-list (crafted Host header), the host-port log line and no
#              secrets in the log; the "Public certificate" card (green: Caddy's
#              internal certificate, served on 443); log hygiene (no access
#              log, no admin.api / uvicorn lines for health probes and panel
#              requests, no "not formatted" warning, no openssl dump).
#   restart    two restarts as Supervisor does them (a new container with the
#              previous /data): new and invalid names in client_names (issued
#              resp. skipped at every start, revoked names skipped: M5, L1), a
#              changed client_cert_password (existing .p12 bundles re-encrypted
#              once, also in the /config mirror: M7).
#   no-mtls    mtls_enabled: false renders and validates (public domain);
#              upstream_port unset: Home Assistant Core's port from the
#              (seeded) Supervisor info; log_level debug turns the access logs
#              on.
#   access-log access_log: true: Caddy's "handled request" lines; a SIGTERM to
#              Caddy alone restarts it (exit 0); `kill -9` of Caddy stops the
#              add-on with exit code 137 within 10 s, without s6 warnings.
#   acme       public domain with the ACME sinkhole and a fake Supervisor
#              (tests/fake-supervisor.py, via SUPERVISOR_URL): acme.log fills
#              with errors, the card is red (error text, host ports), the
#              monitor raises the notification; a certificate placed in
#              Caddy's storage turns the card green and dismisses it; a
#              failed renewal turns it yellow.
#   fwd-*      forwarded_headers (2.2.0) beside a fake Home Assistant
#              (tests/fake-upstream.py, in a container whose network namespace
#              the add-on shares): auto with mTLS (start probe -> strip, the
#              headers that arrive, switch to pass after a "restart", back to
#              strip by the periodic test with the "addresses hidden"
#              notification, Check again, refusal counts, a failed reload:
#              red card, Caddy's real mode, one ERROR line, repair), the last
#              known mode while the upstream is down, always (400, red card,
#              notification, dismissed), never, auto without mTLS, the texts
#              for an upstream that is not Home Assistant.
#   lan*       the local-network port 4443 (host port seeded): proxied without
#              a client certificate from private sources, 403 for public IPv4
#              / IPv6 sources and for the container's default gateway,
#              session tickets of 4443 not resumable on 443 (TLS 1.2 and
#              1.3), SNI/Host tricks, revocation still at once on 443, the
#              redirect to 443; mTLS off with the port on.
#   dns-*      one boot per DNS provider (cloudflare, route53, hetzner, dummy
#              tokens, public domain, local-network port on): the rendered
#              `dns` directive (in both HTTPS sites, one automation policy) passes
#              `caddy validate` and Caddy runs with it (the module syntax at the
#              pinned versions), the token stays out of the Caddyfile and the
#              log, and Caddy's environment carries the credentials.
#   bad-*      refused starts: route53 token without ":", a Cloudflare token
#              the module rejects (its error text quotes the token: it must be
#              redacted), a domain with a port, an upstream without a port,
#              forwarded_headers never without mTLS (Home Assistant and
#              another upstream).
#   auth       header authentication (2.3.0): the gate in every mode, the
#              header removed before the upstream, websockets, revocation,
#              secrecy of the key (logs, files, processes, panel).
#   custom     Caddyfile snippets (2.3.0): harmless files of all four kinds
#              take effect at their places; broken, ignored and rejected
#              files (break-outs, other listeners, certificates over the
#              domain, TLS settings, wildcard sites) leave the add-on's own
#              configuration; lan.caddy while the port is off; one
#              environment for start and reload ({$VAR}); a referenced file
#              that breaks after the start: a revocation still applies (the
#              reload falls back and drops the snippets; also when s6 starts
#              Caddy again), a restart loads them again.
#
# No external network traffic: every container runs with --network none and
# ACME_CA_URL points at a closed local port (http://127.0.0.1:9/directory);
# the checks also assert that no ACME issuer points elsewhere.
#
# Every case ends with a `docker stop` that must take less than 10 s, exit 0
# and leave no s6 warnings in the log.
#
# Prints one PASS/FAIL line per check. Exit status: 0 all checks passed,
# 1 a check failed, 2 usage error. Containers are removed on exit.
# Env: DOCKER (default docker), SMOKE_BOOT_TIMEOUT (seconds, default 90),
# SMOKE_PREFIX (container name prefix, default caddy-mtls-smoke).
# ==============================================================================
# Helper functions are called indirectly (check, wait_for, trap).
# shellcheck disable=SC2329
set -euo pipefail
umask 077

usage() { printf 'usage: %s <image>\n' "${0##*/}" >&2; exit 2; }
[[ $# -eq 1 && -n "$1" && "$1" != -* ]] || usage
IMAGE="$1"
DOCKER="${DOCKER:-docker}"
BOOT_TIMEOUT="${SMOKE_BOOT_TIMEOUT:-90}"
command -v "${DOCKER}" >/dev/null || { printf 'container CLI %s not found\n' "${DOCKER}" >&2; exit 2; }
"${DOCKER}" image inspect "${IMAGE}" >/dev/null 2>&1 || { printf 'image %s not found\n' "${IMAGE}" >&2; exit 2; }

# Container names: SMOKE_PREFIX (e.g. a shared host's naming rule) or the default.
PREFIX="${SMOKE_PREFIX:-caddy-mtls-smoke}-$$"
WORK="$(mktemp -d)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACME_SINKHOLE="http://127.0.0.1:9/directory"
INGRESS_PREFIX="/api/hassio_ingress/smoke-token"
P12_PASSWORD="smoke-p12-$$-${RANDOM}${RANDOM}"
CF_TOKEN="smokeCloudflareToken0123456789abcdef-${RANDOM}"
HZ_TOKEN="smoke-hetzner-token-$$-${RANDOM}${RANDOM}"
R53_KEY_ID="AKIASMOKETEST${RANDOM}"
R53_SECRET="smoke/route53+secret-$$-${RANDOM}${RANDOM}"
CTR=""
CORE_INFO=""
CONTAINERS=()
# Extra `docker create` arguments of the next boot (e.g. environment).
EXTRA_CREATE_ARGS=()
# The network of the next boot: none, or container:<name> (the fake upstream's
# network namespace - still no external traffic).
BOOT_NETWORK=none
# The add-on's network settings as Supervisor reports them (bashio's cache).
SEED_NETWORK='{"80/tcp":8080,"443/tcp":8443}'
# The add-on's slug as Supervisor reports it (empty: none in the cache, as
# outside Supervisor).
SEED_SLUG=local_caddy_mtls
# A function called with the directory that becomes /config (the
# addon_config mapping) before it is copied in; set: /config exists even
# without a previous /data.
BOOT_CONFIG_HOOK=""
PASS_COUNT=0
FAIL_COUNT=0

log() { printf '[smoke] %s\n' "$*" >&2; }
pass() { PASS_COUNT=$((PASS_COUNT + 1)); printf 'PASS  %s\n' "$1"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); printf 'FAIL  %s%s\n' "$1" "${2:+ -- $2}"; }
check() { # check <name> <command...>
    local name="$1"
    shift
    if "$@"; then pass "${name}"; else fail "${name}"; fi
}
# SMOKE_ONLY (optional): the case groups to run, separated by blanks - main,
# no-mtls, access-log, acme, fwd, lan, dns, bad, auth, custom. Default: all.
smoke_case() { [[ -z "${SMOKE_ONLY:-}" || " ${SMOKE_ONLY} " == *" $1 "* ]]; }
cleanup() {
    local rc=$? c
    for c in "${CONTAINERS[@]+"${CONTAINERS[@]}"}"; do
        "${DOCKER}" rm -f "${c}" >/dev/null 2>&1 || true
    done
    rm -rf "${WORK}"
    exit "${rc}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

wait_for() { # wait_for <timeout-seconds> <command...>
    local timeout="$1" deadline
    shift
    deadline=$((SECONDS + timeout))
    until "$@"; do
        (( SECONDS >= deadline )) && return 1
        sleep 1
    done
}
cexec() { "${DOCKER}" exec "${CTR}" "$@"; }
# No `grep -q`: an early exit would SIGPIPE `docker logs` (pipefail).
logs_contain() { "${DOCKER}" logs "${CTR}" 2>&1 | grep -F -- "$1" >/dev/null; }
logs_lack() { ! logs_contain "$1"; }
log_line_count() { "${DOCKER}" logs "${CTR}" 2>&1 | wc -l; }
# new_logs_contain <line-count-before> <text>: the text is in a newer log line.
new_logs_contain() { "${DOCKER}" logs "${CTR}" 2>&1 | tail -n "+$(($1 + 1))" | grep -F -- "$2" >/dev/null; }
# The pattern (a secret) is read from a file, never put on a command line.
logs_lack_secret() { ! "${DOCKER}" logs "${CTR}" 2>&1 | grep -F -f "$1" >/dev/null; }
secret_file() { printf '%s\n' "$2" >"${WORK}/$1"; printf '%s' "${WORK}/$1"; }
# raw_file <name> <value>: the value exactly (no line break) in a file of WORK
# (a key for OPT_HEADER_KEY_FILE); prints the path. printf is a builtin: the
# value is on no command line.
raw_file() { printf '%s' "$2" >"${WORK}/$1"; printf '%s' "${WORK}/$1"; }
running() { [[ "$("${DOCKER}" inspect -f '{{.State.Running}}' "${CTR}" 2>/dev/null)" == true ]]; }
exited() { [[ "$("${DOCKER}" inspect -f '{{.State.Status}}' "${CTR}" 2>/dev/null)" == exited ]]; }
health() { [[ "$(cexec curl -fsS --max-time 5 http://127.0.0.1:8099/_health 2>/dev/null)" == ok ]]; }
admin_up() { cexec curl -fsS --max-time 5 -o /dev/null http://127.0.0.1:2019/config/ 2>/dev/null; }
booted() { running && health && admin_up && logs_contain "Init complete:"; }
file_mode_is() { [[ "$(cexec stat -c '%a' "$1" 2>/dev/null)" == "$2" ]]; }
file_exists() { cexec test -s "$1"; }
file_absent() { ! cexec test -e "$1"; }
state() { cexec jq -r "$1" /data/state.json 2>/dev/null; }
caddy_validate() { cexec caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; }
crt_serial() { cexec sh -c 'openssl x509 -in "$0" -noout -serial | sed "s/^serial=//" | tr a-f A-F' "$1" 2>/dev/null; }
crl_has_serial() { cexec openssl crl -in /data/certs/mTLS-CA.crl -noout -text 2>/dev/null | grep -E "Serial Number: *$1\$" >/dev/null; }
# panel <curl args...>: "<code> <redirect-url>" of a request to the panel.
panel() { cexec curl -s -o /dev/null -w '%{http_code} %{redirect_url}' "$@" 2>/dev/null || printf '000 -'; }
panel_post() { # panel_post <path> [form fields...] (as the ingress proxy would send it)
    local path="$1" field args=()
    shift
    for field in "$@"; do args+=(--data-urlencode "${field}"); done
    panel -X POST -H "X-Ingress-Path: ${INGRESS_PREFIX}" "${args[@]}" "http://127.0.0.1:8099${path}"
}
# adapted <jq filter>: apply a jq filter to Caddy's active JSON config.
adapted() { cexec sh -c 'curl -fsS --max-time 5 http://127.0.0.1:2019/config/ | jq -e "$0"' "$1" >/dev/null 2>&1; }
# Every ACME issuer in the active config uses the sinkhole and nothing else
# (no Let's Encrypt, no ZeroSSL; "acme" issuers without a CA would default to
# Let's Encrypt, so they fail the check too).
# shellcheck disable=SC2016
ISSUERS_ONLY_SINKHOLE='[.. | objects | select(has("module") and (.module == "acme" or .module == "zerossl"))] | length > 0 and all(.module == "acme" and .ca == $ca)'
issuers_only_sinkhole() {
    cexec sh -c 'curl -fsS --max-time 5 http://127.0.0.1:2019/config/ | jq -e --arg ca "$1" "$0"' \
        "${ISSUERS_ONLY_SINKHOLE}" "${ACME_SINKHOLE}" >/dev/null 2>&1
}
# s6 complaints of an unclean stop (2.0.0: cert-monitor's 5 s finish script
# was SIGKILLed, caddy/finish tore down the supervision tree while s6-rc was
# still stopping the services, so init-caddy could not be stopped).
S6_STOP_WARNINGS='finish script lifetime|unable to stop service|s6-ipcclient: fatal|sending it a SIGKILL'
# A stop as Supervisor does it (docker stop): done in less than 10 s, exit
# code 0, no s6 warnings in the log.
stop_cleanly() {
    local t0 ms
    t0="$(date +%s%N)"
    "${DOCKER}" stop -t 30 "${CTR}" >/dev/null 2>&1 || return 1
    ms=$(( ($(date +%s%N) - t0) / 1000000 ))
    log "${CTR}: docker stop took ${ms} ms, exit code $("${DOCKER}" inspect -f '{{.State.ExitCode}}' "${CTR}")"
    [[ "$("${DOCKER}" inspect -f '{{.State.Status}} {{.State.ExitCode}}' "${CTR}")" == "exited 0" ]] \
        && (( ms < 10000 )) \
        && ! "${DOCKER}" logs "${CTR}" 2>&1 | grep -E -- "${S6_STOP_WARNINGS}" >/dev/null
}

# boot <name> <options-json> [<data.tar>]: create, seed and start a container
# (not waited for). With <data.tar> (`docker cp <old>:/data -` of a stopped
# container) it is a restart as Supervisor does it: a new container with the
# previous /data - plus an empty /config (the addon_config mapping), so that
# init-caddy's /config/certs mirror runs.
boot() {
    local name="$1" options="$2" dir="${WORK}/$1"
    CTR="${PREFIX}-${name}"
    mkdir -p "${dir}/data" "${dir}/tmp/.bashio"
    printf '%s\n' "${options}" >"${dir}/data/options.json"
    # bashio::config asks the Supervisor API, which does not exist here: seed
    # bashio's cache with the options (and the add-on info with the default
    # host ports, which init-caddy logs) so it never needs to.
    cp "${dir}/data/options.json" "${dir}/tmp/.bashio/addons.self.options.config.cache"
    jq -n --argjson network "${SEED_NETWORK}" --arg slug "${SEED_SLUG}" \
        '{name: "Caddy mTLS Proxy", network: $network} + (if $slug == "" then {} else {slug: $slug} end)' \
        >"${dir}/tmp/.bashio/addons.self.info.cache"
    # Home Assistant Core's info (port), only when a case sets CORE_INFO.
    if [[ -n "${CORE_INFO:-}" ]]; then
        printf '%s\n' "${CORE_INFO}" >"${dir}/tmp/.bashio/core.info.cache"
    fi
    chmod -R go+rX "${dir}"
    CONTAINERS+=("${CTR}")
    "${DOCKER}" create --name "${CTR}" --network "${BOOT_NETWORK}" \
        -e ACME_CA_URL="${ACME_SINKHOLE}" -e TZ=Europe/Vienna \
        "${EXTRA_CREATE_ARGS[@]+"${EXTRA_CREATE_ARGS[@]}"}" "${IMAGE}" >/dev/null
    if [[ -n "${3:-}" ]]; then
        "${DOCKER}" cp - "${CTR}:/" <"$3"
    fi
    if [[ -n "${3:-}" || -n "${BOOT_CONFIG_HOOK}" ]]; then
        mkdir -p "${dir}/root/config"
        if [[ -n "${BOOT_CONFIG_HOOK}" ]]; then
            "${BOOT_CONFIG_HOOK}" "${dir}/root/config"
        fi
        tar -C "${dir}/root" --owner=0 --group=0 --numeric-owner -cf - config | "${DOCKER}" cp - "${CTR}:/"
    fi
    # Files go in owned by root, as Supervisor creates them.
    tar -C "${dir}/data" --owner=0 --group=0 --numeric-owner -cf - . | "${DOCKER}" cp - "${CTR}:/data"
    tar -C "${dir}/tmp" --owner=0 --group=0 --numeric-owner -cf - . | "${DOCKER}" cp - "${CTR}:/tmp"
    "${DOCKER}" start "${CTR}" >/dev/null
}
show_log_on_failure() {
    local before="$1"
    if (( FAIL_COUNT > before )); then
        log "container ${CTR} log (last 60 lines):"
        "${DOCKER}" logs --tail 60 "${CTR}" 2>&1 | sed 's/^/    /' >&2 || true
    fi
}
# options <domain> <mtls_enabled> <provider> <token> [<upstream_host> [<upstream_port>]]
# (upstream default 127.0.0.1:8123; an empty port leaves upstream_port unset;
# client_names, client_cert_password, log_level, access_log and
# forwarded_headers from OPT_CLIENT_NAMES / OPT_PASSWORD / OPT_LOG_LEVEL /
# OPT_ACCESS_LOG / OPT_FORWARDED; header_auth_name from OPT_HEADER_NAME and
# header_auth_key from the FILE OPT_HEADER_KEY_FILE (exactly its bytes; the
# key never goes on a command line), each left out when empty)
OPT_CLIENT_NAMES='["alice", "bob"]'
OPT_PASSWORD="${P12_PASSWORD}"
OPT_LOG_LEVEL=info
OPT_ACCESS_LOG=false
OPT_FORWARDED=auto
OPT_HEADER_NAME=""
OPT_HEADER_KEY_FILE=""
options() {
    jq -n --arg domain "$1" --argjson mtls "$2" --arg provider "$3" --arg token "$4" \
        --arg uhost "${5:-127.0.0.1}" --arg uport "${6-8123}" \
        --arg pass "${OPT_PASSWORD}" --argjson names "${OPT_CLIENT_NAMES}" \
        --arg level "${OPT_LOG_LEVEL}" --argjson access "${OPT_ACCESS_LOG}" \
        --arg forwarded "${OPT_FORWARDED}" --arg hname "${OPT_HEADER_NAME}" \
        --rawfile hkey "${OPT_HEADER_KEY_FILE:-/dev/null}" '{
        domain: $domain, email: "smoke@example.com",
        upstream_host: $uhost, mtls_enabled: $mtls,
        ca_country: "AT", ca_state: "Styria", ca_locality: "Graz",
        ca_organization: "LinumIQ", ca_common_name: "Caddy mTLS smoke CA",
        client_names: $names, client_cert_password: $pass,
        acme_dns_provider: $provider, dns_api_token: $token,
        log_level: $level, access_log: $access, forwarded_headers: $forwarded,
        cert_expiry_warn_days: [30, 14, 7, 1], cert_check_interval_hours: 6}
        + (if $uport == "" then {} else {upstream_port: ($uport | tonumber)} end)
        + (if $hname == "" then {} else {header_auth_name: $hname} end)
        + (if $hkey == "" then {} else {header_auth_key: $hkey} end)'
}
# The "Public certificate" card (GET /public-cert, as the dashboard reloads it).
card() { cexec curl -fsS --max-time 15 http://127.0.0.1:8099/public-cert 2>/dev/null; }
card_state_is() { [[ "$(card)" == *"data-state=\"$1\""* ]]; }
card_contains() { local html; html="$(card)" && [[ "${html}" == *"$1"* ]]; }
# The "Home Assistant connection" card (GET /upstream) and the forwarding
# snippet (forwarded_headers, 2.2.0).
upstream_card() { cexec curl -fsS --max-time 15 http://127.0.0.1:8099/upstream 2>/dev/null; }
upstream_card_is() { [[ "$(upstream_card)" == *"data-state=\"$1\""* ]]; }
upstream_card_contains() { local html; html="$(upstream_card)" && [[ "${html}" == *"$1"* ]]; }
snippet_is() { # snippet_is pass|strip
    cexec grep -qx -- "# Forwarding headers, mode $1 - written by the Caddy mTLS Proxy add-on" \
        /etc/caddy/forwarded-headers.caddy 2>/dev/null
}
# The header operations of every reverse_proxy handler in Caddy's active
# config, per mode.
# shellcheck disable=SC2016
HEADERS_PASS='[.. | objects | select(.handler? == "reverse_proxy") | .headers.request] | length > 0 and all(
    (.delete == ["Forwarded"]) and ((.set | keys | map(ascii_downcase)) == ["x-real-ip"])
    and ((.set | to_entries[0].value) == ["{http.request.remote.host}"]))'
# shellcheck disable=SC2016
HEADERS_STRIP='[.. | objects | select(.handler? == "reverse_proxy") | .headers.request] | length > 0 and all(
    ((.delete | sort) == ["Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP"])
    and (has("set") | not))'
command -v jq >/dev/null || { printf 'jq is required\n' >&2; exit 2; }
command -v tar >/dev/null || { printf 'tar is required\n' >&2; exit 2; }
command -v openssl >/dev/null || { printf 'openssl is required\n' >&2; exit 2; }

P12_PASS_FILE="$(secret_file p12-pass "${P12_PASSWORD}")"

# ==============================================================================
# 1. main: mTLS on, internal issuer
# ==============================================================================
DOMAIN="caddy-mtls-smoke.localhost"
# Helpers of several case groups.
dashboard() { cexec curl -fsS --max-time 10 "http://127.0.0.1:8099$1" 2>/dev/null; }
http80() { cexec curl -s --max-time 5 --resolve "${DOMAIN}:80:127.0.0.1" "$@" 2>/dev/null; }
# 502 = the client certificate was accepted and the request reached the (absent)
# upstream; 000 = the TLS handshake was refused.
mtls() { # mtls <cert> <key>  (empty: no client certificate)
    local args=()
    [[ -n "$1" ]] && args=(--cert "$1" --key "$2")
    cexec curl -sk --max-time 5 -o /dev/null -w '%{http_code}' --resolve "${DOMAIN}:443:127.0.0.1" \
        "${args[@]+"${args[@]}"}" "https://${DOMAIN}/" 2>/dev/null || true
}
mtls_is() { [[ "$(mtls "$2" "$3")" == "$1" ]]; }
if smoke_case main; then
log "main: booting ${IMAGE} (mTLS, ${DOMAIN})"
before=${FAIL_COUNT}
boot main "$(options "${DOMAIN}" true none "")"
if ! wait_for "${BOOT_TIMEOUT}" booted; then
    fail "main: add-on booted (panel, Caddy admin API, init complete)"
    show_log_on_failure "${before}"
    printf '\n%d passed, %d failed\n' "${PASS_COUNT}" "${FAIL_COUNT}"
    exit 1
fi
pass "main: add-on booted (panel, Caddy admin API, init complete)"

# --- image basics -------------------------------------------------------------
check "main: panel runs the venv's uvicorn (Python 3.14)" \
    test "$(cexec /usr/lib/cert-mgr/.venv/bin/python3 -c 'import sys; print(sys.version_info[:2] >= (3, 14))')" == True
check "main: venv contains no pip" file_absent /usr/lib/cert-mgr/.venv/bin/pip
# s6-overlay 3.2.3.2 (base 21) starts the `user` bundle from user-bundles.d; a
# bundle in s6-rc.d/user would be rewritten by rc.init at every start.
check "main: no s6-rc.d/user bundle (user-bundles.d layout), services up" \
    eval 'file_absent /etc/s6-overlay/s6-rc.d/user && file_exists /etc/s6-overlay/user-bundles.d/user/type &&
    test "$(cexec s6-svstat -o up /run/service/cert-monitor)" == true'
pids_of() { cexec sh -c 'for p in /proc/[0-9]*; do tr "\0" " " < "$p/cmdline" 2>/dev/null; echo; done' | grep -F -- "$1" >/dev/null; }
check "main: cert-mgr = /usr/lib/cert-mgr/.venv/bin/uvicorn" pids_of "/usr/lib/cert-mgr/.venv/bin/uvicorn app:app"
check "main: cert-monitor = venv python3 monitor.py" pids_of "/usr/lib/cert-mgr/.venv/bin/python3 monitor.py"

# The image's HEALTHCHECK command (exec form), run as Docker would run it.
healthcheck_passes() {
    local hc=()
    mapfile -t hc < <("${DOCKER}" image inspect "${IMAGE}" \
        | jq -r '.[0].Config.Healthcheck.Test | select(.[0] == "CMD") | .[1:][]')
    (( ${#hc[@]} > 0 )) && cexec "${hc[@]}" >/dev/null 2>&1
}
check "main: HEALTHCHECK (exec form) passes" healthcheck_passes

# --- CA + seeded clients --------------------------------------------------------
check "main: CA key 600, CA cert 644" \
    eval 'file_mode_is /data/certs/mTLS-CA.key 600 && file_mode_is /data/certs/mTLS-CA.crt 644'
for c in alice bob; do
    check "main: client ${c}: key 600, p12 600, crt 644" \
        eval "file_mode_is /data/certs/mTLS-client-${c}.key 600 && file_mode_is /data/certs/mTLS-client-${c}.p12 600 && file_mode_is /data/certs/mTLS-client-${c}.crt 644"
    check "main: client ${c}: active/mTLS-client-${c}.pem present (644)" \
        file_mode_is "/data/certs/active/mTLS-client-${c}.pem" 644
    check "main: client ${c}: state.json serial = certificate serial, status active" \
        test "$(state ".clients[] | select(.name == \"${c}\") | \"\(.serial) \(.status)\"")" \
        == "$(crt_serial "/data/certs/mTLS-client-${c}.crt") active"
done
check "main: state.json 600, CA fingerprint matches the CA file" eval '
    file_mode_is /data/state.json 600 &&
    test "$(state .ca.fingerprint_sha256)" == "$(cexec openssl x509 -in /data/certs/mTLS-CA.crt -noout -fingerprint -sha256 | sed "s/^.*Fingerprint=//")"'
check "main: CRL present (644), CRL number in state.json" \
    eval 'file_mode_is /data/certs/mTLS-CA.crl 644 && test "$(state .crl_number)" -gt 0'

# --- Caddyfile + admin API --------------------------------------------------------
check "main: init-caddy validated the Caddyfile" \
    eval 'logs_contain "Validating generated Caddyfile..." && logs_lack "failed validation"'
check "main: caddy validate /etc/caddy/Caddyfile" caddy_validate
check "main: admin API config has the leaf verifier on /data/certs/active" \
    adapted '[.. | objects | select(.verifier? == "leaf")] | length == 1 and (.[0] | tostring | contains("/data/certs/active"))'
check "main: admin API config requires and verifies client certificates" \
    adapted '[.. | objects | select(.mode? == "require_and_verify")] | length == 1'
# Header authentication (2.3.0) is off by default: the TLS and log rendering
# of 2.2.0, no gate, no key file.
check "default: header authentication off - no gate, no header removal, no diagnosis, logs unfiltered, no key file" eval '
    ! cexec grep -E "caddy_mtls_|header-auth.key|request_header|request>headers|log_append|verify_if_given" /etc/caddy/Caddyfile >/dev/null &&
    test "$(cexec grep -c "format console" /etc/caddy/Caddyfile)" == 2 &&
    file_absent /etc/caddy/header-auth.key &&
    logs_contain "Header auth: off (option header_auth_key)" &&
    test "$(cexec jq -c .header_auth /run/caddy-mtls/runtime.json)" == "{\"enabled\":false,\"name\":\"X-Custom-PSK\",\"key_length\":0}"'
check "default: the list of active client certificates is written (alice, bob) but not imported" eval '
    test "$(cexec grep -cE "^not vars \{http.request.tls.client.fingerprint\} [0-9a-f]{64} [0-9a-f]{64}$" /etc/caddy/client-fingerprints.caddy)" == 1 &&
    ! cexec grep -F client-fingerprints /etc/caddy/Caddyfile >/dev/null'
check "default: dashboard card Header authentication off, with the browser-side key helper" eval '
    html="$(dashboard /)" && [[ "${html}" == *"id=\"header-auth\""*"data-state=\"off\""* &&
    "${html}" == *">Suggest a key<"* && "${html}" == *"crypto.getRandomValues"* ]]'
check "main: init-caddy logged the published host ports" \
    logs_contain "Host ports:  80/tcp -> 8080, 443/tcp -> 8443"
check "main: init-caddy logged the router forwarding hint" \
    logs_contain "forward external TCP 80 -> <this host>:8080 and TCP 443 -> <this host>:8443"
check "main: explicit upstream_port used (127.0.0.1:8123)" \
    eval 'logs_contain "Upstream:    127.0.0.1:8123 (option upstream_port)" &&
    cexec grep -F "reverse_proxy 127.0.0.1:8123 {" /etc/caddy/Caddyfile >/dev/null'

# --- forwarded_headers (2.2.0): nothing listens on 127.0.0.1:8123 here --------------
check "fwd: the reverse_proxy block imports the forwarding snippet" \
    cexec grep -F "import /etc/caddy/forwarded-headers.caddy" /etc/caddy/Caddyfile
check "fwd: upstream unreachable at the first start -> mode pass (snippet, 644)" \
    eval 'snippet_is pass && file_mode_is /etc/caddy/forwarded-headers.caddy 644'
check "fwd: admin API config (mode pass): X-Real-IP set to the client, Forwarded removed" adapted "${HEADERS_PASS}"
check "fwd: init-caddy logged the unreachable upstream, no unconditional configuration.yaml block" eval '
    logs_contain "The upstream 127.0.0.1:8123 does not answer yet" &&
    logs_contain "Forwarding:  forwarded_headers auto, mode pass" &&
    logs_lack "Add this to /config/configuration.yaml" && logs_lack "use_x_forwarded_for"'
check "fwd: runtime.json carries the upstream, mTLS and forwarded_headers" \
    test "$(cexec jq -c "[.upstream_host, .upstream_port, .mtls_enabled, .forwarded_headers]" /run/caddy-mtls/runtime.json)" \
    == '["127.0.0.1",8123,true,"auto"]'
check "fwd: /data/upstream.json 600: unreachable, mode pass" eval '
    file_mode_is /data/upstream.json 600 &&
    test "$(cexec jq -c "[.reachable, .mode, .decisive]" /data/upstream.json)" == "[false,\"pass\",null]"'
# --- local-network port (2.2.0): off without a host port for 4443/tcp -----------
check "lan: off without a host port for 4443/tcp: no :4443 site, logged, runtime.json" eval '
    ! cexec grep -F ":4443 {" /etc/caddy/Caddyfile >/dev/null &&
    logs_contain "Host ports:  80/tcp -> 8080, 443/tcp -> 8443, 4443/tcp -> disabled" &&
    logs_contain "LAN port:    off (4443/tcp has no host port" &&
    test "$(cexec jq -c "[.lan_state, .lan_host_port, .lan_refused]" /run/caddy-mtls/runtime.json)" == "[\"off\",null,[]]"'
check "lan: admin API config has no listener on 4443" \
    adapted '[.apps.http.servers[].listen[]] | index(":4443") == null'
check "lan: the plain-HTTP site is the add-on's own (CRL + redirect), not Caddy's automatic one" \
    cexec grep -F "redir https://{host}{uri} permanent" /etc/caddy/Caddyfile
check "fwd: card 'Home Assistant connection' unreachable (502 explained)" eval '
    upstream_card_is unreachable && upstream_card_contains "<code>127.0.0.1:8123</code> does not answer" &&
    upstream_card_contains "502 Bad Gateway"'

# --- panel --------------------------------------------------------------------
check "main: dashboard HTML lists the seeded clients" \
    eval 'html="$(dashboard /)" && [[ "${html}" == *"Caddy mTLS"* && "${html}" == *alice* && "${html}" == *bob* ]]'
# The Revoke button's confirm() reads the client name from a data attribute
# (HTML-escaped); the name is never interpolated into the inline script (L1).
confirm_uses_data_attribute() {
    local html
    html="$(dashboard /)" || return 1
    [[ "${html}" == *'data-client="alice"'* && "${html}" == *"this.dataset.client"* \
        && "${html}" != *"Revoke client alice"* ]]
}
check "L1: Revoke confirm() takes the client name from a data attribute" confirm_uses_data_attribute
check "main: GET // (doubled ingress slash) serves the dashboard" \
    eval '[[ "$(dashboard //)" == *"Certificate Authority"* ]]'
# The shared LinumIQ UI (static/shared, static/brand and templates/_layout.html,
# copied from shared/ by scripts/sync-shared.sh) and the app's stylesheet.
content_type_is() { # content_type_is <path> <type>
    [[ "$(cexec curl -fsS --max-time 10 -o /dev/null -w '%{content_type}' "http://127.0.0.1:8099$1" 2>/dev/null)" == "$2"* ]]
}
check "main: shared stylesheet served (text/css)" content_type_is /static/shared/linumiq.css text/css
check "main: app stylesheet served (text/css)" content_type_is /static/app.css text/css
check "main: app mark served (image/svg+xml)" content_type_is /static/brand/icon.svg image/svg+xml
check "main: footer logo served (image/png)" content_type_is /static/shared/brand/linumiq-logo.png image/png
fonts_served() { # every font the shared stylesheet names, as font/woff2
    local css font n=0
    css="$(dashboard /static/shared/linumiq.css)" || return 1
    while IFS= read -r font; do
        n=$((n + 1))
        content_type_is "/static/shared/${font}" font/woff2 || { log "font ${font}: not served as font/woff2"; return 1; }
    done < <(printf '%s\n' "${css}" | grep -oE 'url\("fonts/[^"]+\.woff2"\)' | sed -E 's/^url\("(.*)"\)$/\1/' | sort -u)
    (( n == 4 ))
}
check "main: the 4 fonts of the shared stylesheet served (font/woff2)" fonts_served
uses_shared_layout() {
    local html
    html="$(dashboard /)" || return 1
    [[ "${html}" == "<!doctype html>"* \
        && "${html}" == *'href="static/shared/linumiq.css"'*'href="static/app.css"'* \
        && "${html}" == *'<header class="app-header">'*'src="static/brand/icon.svg"'*'<h1>Caddy mTLS</h1>'* \
        && "${html}" == *'<footer class="app-footer">'*'href="https://linumiq.com"'*'src="static/shared/brand/linumiq-logo.png"'*'</footer>'* \
        && "${html}" != *"state version"* ]]
}
check "main: dashboard uses the shared layout (stylesheets, app mark, footer logo, no state version line)" uses_shared_layout
# Nothing is loaded from another host (no Google Fonts, no CDN): the only
# absolute URL in an attribute is the footer's link to linumiq.com.
no_external_resources() {
    local html css urls
    html="$(dashboard /)$(card)" || return 1
    css="$(dashboard /static/shared/linumiq.css)$(dashboard /static/app.css)" || return 1
    urls="$(printf '%s\n' "${html}" | grep -oE '(href|src|srcset|action|poster|data)="([a-zA-Z][a-zA-Z0-9+.-]*:|//)[^"]*"' | sort -u || true)"
    [[ -z "${urls}" || "${urls}" == 'href="https://linumiq.com"' ]] || { log "absolute URLs: ${urls//$'\n'/ }"; return 1; }
    ! printf '%s\n' "${html}${css}" | grep -Ei 'fonts\.googleapis|gstatic|@import' >/dev/null \
        && ! printf '%s\n' "${css}" | grep -E 'https?:|url\(["'"'"']?//' >/dev/null
}
check "main: no external resources (dashboard, card, stylesheets)" no_external_resources
check "main: /api/state lists alice + bob active, CA present" \
    test "$(cexec sh -c 'curl -fsS http://127.0.0.1:8099/api/state | jq -r "([.clients[] | select(.status == \"active\") | .name] | sort | join(\",\")), (.ca != null)"' 2>/dev/null | tr '\n' ' ')" == "alice,bob true "

# --- plain HTTP site (container port 80) ------------------------------------------
check "main: port 80 serves /mTLS-CA.crl (= the CRL file)" eval '
    http80 -o /tmp/crl-http.pem "http://${DOMAIN}/mTLS-CA.crl" &&
    cexec cmp -s /tmp/crl-http.pem /data/certs/mTLS-CA.crl'
# `redir ... permanent` = 301 (CHANGELOG 1.2.5 said 308; unchanged here).
check "main: port 80 redirects other paths with 301 to https" \
    test "$(http80 -o /dev/null -w '%{http_code} %{redirect_url}' "http://${DOMAIN}/some/path?x=1")" \
    == "301 https://${DOMAIN}/some/path?x=1"

# --- mTLS handshakes (port 443, internal server certificate) ------------------------
check "main: HTTPS up with Caddy's internal certificate, alice's client certificate accepted" \
    wait_for 60 mtls_is 502 /data/certs/mTLS-client-alice.crt /data/certs/mTLS-client-alice.key
check "main: handshake without a client certificate refused" mtls_is 000 "" ""
cexec sh -c 'openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=alice -days 2 \
    -keyout /tmp/foreign.key -out /tmp/foreign.crt' >/dev/null 2>&1
check "main: client certificate from a foreign CA refused" mtls_is 000 /tmp/foreign.crt /tmp/foreign.key

# --- add a client ------------------------------------------------------------------
crl_before="$(state .crl_number)"
check "main: POST /api/clients (carol) -> 303 into the ingress path" \
    test "$(panel_post /api/clients name=carol)" == "303 http://127.0.0.1:8099${INGRESS_PREFIX}/?ok=Client+%27carol%27+created."
check "main: carol active in state.json, active/mTLS-client-carol.pem present" eval '
    test "$(state ".clients[] | select(.name == \"carol\") | .status")" == active &&
    file_mode_is /data/certs/active/mTLS-client-carol.pem 644 &&
    file_mode_is /data/certs/mTLS-client-carol.p12 600'
check "main: CRL regenerated after the add (number ${crl_before} -> higher)" \
    test "$(state .crl_number)" -gt "${crl_before}"
check "main: Caddy reloaded: carol's new certificate accepted" \
    mtls_is 502 /data/certs/mTLS-client-carol.crt /data/certs/mTLS-client-carol.key
check "main: duplicate name rejected with a flash error" \
    eval '[[ "$(panel_post /api/clients name=carol)" == "303 http://127.0.0.1:8099${INGRESS_PREFIX}/?error="*"already+exists"* ]]'
check "main: invalid name rejected with a flash error" \
    eval '[[ "$(panel_post /api/clients "name=bad name!")" == "303 http://127.0.0.1:8099${INGRESS_PREFIX}/?error="* ]]'
# "." and ".." would be dropped from the client's URLs by the browser (never
# revocable); a leading dot is refused in general (L1).
for bad in . .. .hidden; do
    check "L1: name '${bad}' rejected with a flash error" \
        eval '[[ "$(panel_post /api/clients "name=${bad}")" == "303 http://127.0.0.1:8099${INGRESS_PREFIX}/?error="* ]]'
done
check "L1: no client starting with a dot in state.json" \
    test "$(state '[.clients[] | select(.name | startswith("."))] | length')" == 0
check "main: carol's .p12 download = the file on disk" eval '
    cexec curl -fsS -o /tmp/carol.p12 http://127.0.0.1:8099/download/client/carol &&
    cexec cmp -s /tmp/carol.p12 /data/certs/mTLS-client-carol.p12'
p12_opens() { # p12_opens legacy|default
    local legacy=()
    [[ "$1" == legacy ]] && legacy=(-legacy)
    "${DOCKER}" exec -e P12PASS="${P12_PASSWORD}" "${CTR}" openssl pkcs12 "${legacy[@]+"${legacy[@]}"}" \
        -in /tmp/carol.p12 -passin env:P12PASS -nokeys -clcerts 2>/dev/null \
        | grep -F "subject=" | grep -F "CN=carol" >/dev/null
}
check "main: .p12 opens with the password (openssl pkcs12 -legacy)" p12_opens legacy
# Recorded, not asserted: the bundle uses RC2/3DES (-legacy export, for older
# Apple/Android importers), which OpenSSL 3 reads only with the legacy provider.
if p12_opens default; then log "note: the .p12 also opens without -legacy"; else log "note: the .p12 needs 'openssl pkcs12 -legacy' to open (RC2-40 certificate bag)"; fi
check "main: CA + CRL downloads" eval '
    cexec curl -fsS -o /dev/null http://127.0.0.1:8099/download/ca &&
    cexec curl -fsS -o /dev/null http://127.0.0.1:8099/download/crl'

# --- revoke a client --------------------------------------------------------------
bob_serial="$(crt_serial /data/certs/mTLS-client-bob.crt)"
crl_before="$(state .crl_number)"
check "main: bob accepted before the revocation" \
    mtls_is 502 /data/certs/mTLS-client-bob.crt /data/certs/mTLS-client-bob.key
log_lines_before="$(log_line_count)"
check "main: POST /api/clients/bob/revoke -> 303" \
    test "$(panel_post /api/clients/bob/revoke reason=keyCompromise)" == "303 http://127.0.0.1:8099${INGRESS_PREFIX}/?ok=Client+%27bob%27+revoked."
# Caddy really reloaded: an unforced `caddy reload` of the unchanged Caddyfile
# logs "config is unchanged" and keeps the old servers (and the old leaf
# verifier); a real reload replaces them ("stopped previous server").
check "main: Caddy log after the revoke: config reloaded (stopped previous server)" \
    wait_for 15 new_logs_contain "${log_lines_before}" "stopped previous server"
check "main: Caddy log after the revoke: no 'config is unchanged'" \
    eval '! new_logs_contain "${log_lines_before}" "config is unchanged"'
check "main: bob revoked in state.json (keyCompromise)" \
    test "$(state '.clients[] | select(.name == "bob") | "\(.status) \(.revocation_reason)"')" == "revoked keyCompromise"
check "main: CRL regenerated and lists bob's serial ${bob_serial}" \
    eval 'test "$(state .crl_number)" -gt "${crl_before}" && crl_has_serial "${bob_serial}"'
check "main: active/ no longer contains bob" file_absent /data/certs/active/mTLS-client-bob.pem
check "main: Caddy reloaded: bob's revoked certificate refused" \
    mtls_is 000 /data/certs/mTLS-client-bob.crt /data/certs/mTLS-client-bob.key
check "main: alice still accepted after bob's revocation" \
    mtls_is 502 /data/certs/mTLS-client-alice.crt /data/certs/mTLS-client-alice.key

# --- regenerate a client -----------------------------------------------------------
cexec cp /data/certs/mTLS-client-alice.crt /tmp/alice-old.crt
cexec cp /data/certs/mTLS-client-alice.key /tmp/alice-old.key
alice_old="$(crt_serial /tmp/alice-old.crt)"
check "main: POST /api/clients/alice/regenerate -> 303" \
    test "$(panel_post /api/clients/alice/regenerate)" == "303 http://127.0.0.1:8099${INGRESS_PREFIX}/?ok=Client+%27alice%27+regenerated."
alice_new="$(crt_serial /data/certs/mTLS-client-alice.crt)"
check "main: alice has a new serial (${alice_old} -> ${alice_new}), state.json follows" \
    eval '[[ -n "${alice_new}" && "${alice_new}" != "${alice_old}" ]] &&
    test "$(state ".clients[] | select(.name == \"alice\") | \"\(.serial) \(.status)\"")" == "${alice_new} active"'
check "main: CRL lists alice's superseded serial" crl_has_serial "${alice_old}"
check "main: active/mTLS-client-alice.pem = the new certificate" \
    cexec cmp -s /data/certs/active/mTLS-client-alice.pem /data/certs/mTLS-client-alice.crt
check "main: Caddy reloaded: alice's old certificate refused" mtls_is 000 /tmp/alice-old.crt /tmp/alice-old.key
check "main: Caddy reloaded: alice's new certificate accepted" \
    mtls_is 502 /data/certs/mTLS-client-alice.crt /data/certs/mTLS-client-alice.key

# p12_serial <.p12 in the container> <password>: serial of the client
# certificate in the bundle (uppercase hex), empty if it does not open.
p12_serial() {
    "${DOCKER}" exec -e P12PASS="$2" "${CTR}" sh -c 'openssl pkcs12 -legacy -in "$0" -passin env:P12PASS -nokeys -clcerts 2>/dev/null |
        openssl x509 -noout -serial 2>/dev/null | sed "s/^serial=//" | tr a-f A-F' "$1" 2>/dev/null || true
}
ok_url() { printf '303 http://127.0.0.1:8099%s/?ok=%s' "${INGRESS_PREFIX}" "$1"; }

# --- revoke without the CA database's copy / without the .crt (review M2) ---------
# The client's own certificate file is revoked; the CA database's copy
# (ca-db/newcerts/<serial>.pem) is only the fallback when the file is missing.
# Before, a missing newcerts copy made Revoke and Regenerate fail.
check "M2: POST /api/clients (erin, frank) -> 303" eval '
    test "$(panel_post /api/clients name=erin)" == "$(ok_url "Client+%27erin%27+created.")" &&
    test "$(panel_post /api/clients name=frank)" == "$(ok_url "Client+%27frank%27+created.")"'
erin_serial="$(crt_serial /data/certs/mTLS-client-erin.crt)"
frank_serial="$(crt_serial /data/certs/mTLS-client-frank.crt)"
cexec cp /data/certs/mTLS-client-frank.crt /tmp/frank.crt
cexec cp /data/certs/mTLS-client-frank.key /tmp/frank.key
check "M2: erin and frank accepted" eval '
    mtls_is 502 /data/certs/mTLS-client-erin.crt /data/certs/mTLS-client-erin.key &&
    mtls_is 502 /tmp/frank.crt /tmp/frank.key'
check "M2: erin's CA database copy newcerts/${erin_serial}.pem deleted" eval '
    file_exists "/data/certs/ca-db/newcerts/${erin_serial}.pem" &&
    cexec rm "/data/certs/ca-db/newcerts/${erin_serial}.pem" &&
    file_absent "/data/certs/ca-db/newcerts/${erin_serial}.pem"'
check "M2: POST /api/clients/erin/revoke (no newcerts copy) -> 303 revoked" \
    test "$(panel_post /api/clients/erin/revoke reason=keyCompromise)" == "$(ok_url "Client+%27erin%27+revoked.")"
check "M2: erin revoked in state.json, CRL lists ${erin_serial}, active/ without erin" eval '
    test "$(state ".clients[] | select(.name == \"erin\") | \"\(.status) \(.revocation_reason)\"")" == "revoked keyCompromise" &&
    crl_has_serial "${erin_serial}" && file_absent /data/certs/active/mTLS-client-erin.pem'
check "M2: Caddy reloaded: erin's certificate refused" \
    mtls_is 000 /data/certs/mTLS-client-erin.crt /data/certs/mTLS-client-erin.key
cexec rm /data/certs/mTLS-client-frank.crt
check "M2: POST /api/clients/frank/revoke (no .crt: newcerts fallback) -> 303 revoked" \
    test "$(panel_post /api/clients/frank/revoke reason=superseded)" == "$(ok_url "Client+%27frank%27+revoked.")"
check "M2: frank revoked in state.json, CRL lists ${frank_serial}, active/ without frank" eval '
    test "$(state ".clients[] | select(.name == \"frank\") | .status")" == revoked &&
    crl_has_serial "${frank_serial}" && file_absent /data/certs/active/mTLS-client-frank.pem'
check "M2: Caddy reloaded: frank's certificate refused" mtls_is 000 /tmp/frank.crt /tmp/frank.key
check "M2: revoking a revoked client again -> flash error, reason unchanged" eval '
    [[ "$(panel_post /api/clients/erin/revoke reason=superseded)" == "303 http://127.0.0.1:8099${INGRESS_PREFIX}/?error="*"already+revoked"* ]] &&
    test "$(state ".clients[] | select(.name == \"erin\") | .revocation_reason")" == keyCompromise'

# --- Regenerate CA (review M3) ------------------------------------------------------
# Only active clients get new certificates; revoked ones stay revoked (kept in
# state.json as history, without files). Before, they came back as active.
ca_fp_before="$(state .ca.fingerprint_sha256)"
alice_ca1="$(crt_serial /data/certs/mTLS-client-alice.crt)"
carol_ca1="$(crt_serial /data/certs/mTLS-client-carol.crt)"
cexec cp /data/certs/mTLS-client-alice.crt /tmp/alice-ca1.crt
cexec cp /data/certs/mTLS-client-alice.key /tmp/alice-ca1.key
# shellcheck disable=SC2016
REVOKED_FILTER='[.clients[] | select(.status != "active") | "\(.name) \(.status) \(.serial) \(.revocation_reason)"] | join(",")'
revoked_before="$(state "${REVOKED_FILTER}")"
revoked_unchanged() { [[ -n "${revoked_before}" ]] && test "$(state "${REVOKED_FILTER}")" == "${revoked_before}"; }
new_ca_in_place() {
    local fp
    fp="$(state .ca.fingerprint_sha256)"
    [[ -n "${fp}" && "${fp}" != "${ca_fp_before}" ]] &&
        test "${fp}" == "$(cexec openssl x509 -in /data/certs/mTLS-CA.crt -noout -fingerprint -sha256 | sed "s/^.*Fingerprint=//")"
}
check "M3: POST /api/ca/regenerate (REGENERATE-CA) -> 303" \
    test "$(panel_post /api/ca/regenerate confirm=REGENERATE-CA)" == "$(ok_url "CA+regenerated.")"
check "M3: new CA: fingerprint changed, state.json = the CA file" new_ca_in_place
check "M3: client list and order kept (alice,bob,carol,erin,frank)" \
    test "$(state '[.clients[].name] | join(",")')" == "alice,bob,carol,erin,frank"
alice_ca2="$(crt_serial /data/certs/mTLS-client-alice.crt)"
carol_ca2="$(crt_serial /data/certs/mTLS-client-carol.crt)"
reissued_by_new_ca() {
    [[ -n "${alice_ca2}" && "${alice_ca2}" != "${alice_ca1}" && -n "${carol_ca2}" && "${carol_ca2}" != "${carol_ca1}" ]] &&
        test "$(state '[.clients[] | select(.status == "active") | "\(.name)=\(.serial)"] | join(",")')" == "alice=${alice_ca2},carol=${carol_ca2}" &&
        cexec openssl verify -CAfile /data/certs/mTLS-CA.crt \
            /data/certs/mTLS-client-alice.crt /data/certs/mTLS-client-carol.crt >/dev/null 2>&1
}
check "M3: alice and carol active with new serials, signed by the new CA" reissued_by_new_ca
check "M3: bob, erin and frank still revoked (serial and reason unchanged)" eval '
    [[ "${revoked_before}" == "bob revoked "*" keyCompromise,erin revoked "*",frank revoked "* ]] && revoked_unchanged'
check "M3: no certificate files for the revoked clients" \
    eval '! cexec ls /data/certs | grep -E "^mTLS-client-(bob|erin|frank)\." >/dev/null'
check "M3: active/ = alice and carol (the new certificates)" eval '
    test "$(cexec ls /data/certs/active | tr "\n" " ")" == "mTLS-client-alice.pem mTLS-client-carol.pem " &&
    cexec cmp -s /data/certs/active/mTLS-client-alice.pem /data/certs/mTLS-client-alice.crt'
check "M3: Caddy reloaded: alice's new certificate accepted" \
    mtls_is 502 /data/certs/mTLS-client-alice.crt /data/certs/mTLS-client-alice.key
check "M3: alice's certificate of the old CA refused" mtls_is 000 /tmp/alice-ca1.crt /tmp/alice-ca1.key
check "M3: carol's new .p12 holds her new certificate" eval '
    [[ -n "${carol_ca2}" ]] && test "$(p12_serial /data/certs/mTLS-client-carol.p12 "${P12_PASSWORD}")" == "${carol_ca2}"'

# --- ingress allow-list -------------------------------------------------------------
# A second panel instance that does not allow loopback (as under Supervisor,
# where only 172.30.32.2 is allowed): /_health stays open, everything else is
# refused - also with a crafted Host header (GHSA-86qp-5c8j-p5mr: Starlette
# < 1.3.1 rebuilt request.url.path from it, which turned the /_health
# exemption into a bypass).
"${DOCKER}" exec -d -e ALLOWED_INGRESS_IPS=192.0.2.1 -w /usr/lib/cert-mgr "${CTR}" \
    /usr/lib/cert-mgr/.venv/bin/uvicorn app:app --app-dir /usr/lib/cert-mgr \
    --host 127.0.0.1 --port 8098 --log-level warning
code8098() { cexec curl -s --max-time 5 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || true; }
up8098() { [[ "$(code8098 http://127.0.0.1:8098/_health)" == 200 ]]; }
check "allow-list: second panel up, /_health open" wait_for 30 up8098
check "allow-list: /api/state from a non-ingress address -> 403" \
    test "$(code8098 http://127.0.0.1:8098/api/state)" == 403
check "allow-list: crafted Host header does not bypass it" \
    eval 'code="$(code8098 -H "Host: x/_health?" http://127.0.0.1:8098/api/state)"; [[ "${code}" == 403 || "${code}" == 400 ]]'

# --- "Public certificate" card ------------------------------------------------------
# Caddy's internal issuer (a .localhost domain) stands in for Let's Encrypt.
check "card: green (data-state ok) with Caddy's certificate for ${DOMAIN}" wait_for 30 card_state_is ok
check "card: issuer and expiry shown" eval '
    card_contains "Certificate for <strong>${DOMAIN}</strong> from Caddy Local Authority" &&
    card_contains "days)."'
check "card: the live probe sees the stored certificate on port 443 (despite mTLS)" \
    card_contains "Caddy serves it on port 443."
check "card: at the top of the dashboard" eval '
    html="$(dashboard /)" && pre="${html%%id=\"public-cert\"*}" && [[ "${pre}" != "${html}" && "${pre}" != *"Certificate Authority"* ]]'
check "card: the dashboard reloads it every 30 s" eval '[[ "$(dashboard /)" == *"fetch(\"public-cert\""*"30000"* ]]'
check "fwd: dashboard shows the connection card between the public certificate and the CA" eval '
    html="$(dashboard /)" && pre="${html%%id=\"upstream\"*}" && [[ "${pre}" != "${html}" && "${pre}" == *"id=\"public-cert\""* && "${pre}" != *"Certificate Authority"* ]]'
check "lan: dashboard card 'Local network' off, with the steps (Show disabled ports, 4443/tcp)" eval '
    html="$(dashboard /)" && [[ "${html}" == *"id=\"lan\""*"data-state=\"off\""* &&
    "${html}" == *"Show disabled ports"* && "${html}" == *"<code>4443/tcp</code>"* ]]'
check "fwd: the dashboard reloads the connection card every 30 s" eval '[[ "$(dashboard /)" == *"fetch(\"upstream\""*"30000"* ]]'
check "panel: no /openapi.json (FastAPI schema) -> 404" \
    test "$(cexec curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8099/openapi.json)" == 404

# --- logs ---------------------------------------------------------------------------
check "main: cert-monitor started" logs_contain "cert-monitor starting"
check "main: client_cert_password not in the log" logs_lack_secret "${P12_PASS_FILE}"
check "main: no 'permission denied' / Traceback in the log" \
    eval 'logs_lack "ermission denied" && logs_lack "Traceback"'
# Log hygiene (owner's log 2026-10-28: 701 access-log lines, one admin.api and
# one uvicorn line per health probe, the openssl dump, the fmt warning).
check "log: no 'Caddyfile input is not formatted' warning" logs_lack "not formatted"
check "log: no openssl 'Certificate Details' dump / progress lines (clients issued, CRLs made)" eval '
    logs_lack "Certificate Details" && logs_lack "Using configuration from" && logs_lack "Database updated"'
check "log: no Caddy access log ('handled request') by default, after the mTLS requests" logs_lack "handled request"
probe_is_silent() {
    local before
    before="$(log_line_count)"
    healthcheck_passes && sleep 1 &&
        ! new_logs_contain "${before}" "admin.api" && ! new_logs_contain "${before}" "/_health"
}
check "log: a health probe (HEALTHCHECK command) passes and leaves no admin.api / uvicorn line" probe_is_silent
check "log: no admin.api line at all (probes, panel reloads), no uvicorn access line" eval '
    logs_lack "admin.api" && logs_lack "\"GET /_health" && logs_lack "\"POST /api/clients"'
check "log: other Caddy loggers still log (Caddy's admin: stopped previous server)" \
    logs_contain "stopped previous server"
check "log: proxy errors still logged without the access log (http.log.error after a 502)" \
    logs_contain "http.log.error"
check "log: certificate events still in the add-on log (tls.obtain)" \
    logs_contain "certificate obtained successfully"
check "main: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
show_log_on_failure "${before}"

# ==============================================================================
# 1b. restart: client_names at every start (M5, L1), new client_cert_password (M7)
# ==============================================================================
# As Supervisor restarts an add-on: a new container with the previous /data.
P12_PASSWORD_NEW="smoke-p12-new-$$-${RANDOM}${RANDOM}"
P12_NEW_PASS_FILE="$(secret_file p12-pass-new "${P12_PASSWORD_NEW}")"
OPT_PASSWORD="${P12_PASSWORD_NEW}"
OPT_CLIENT_NAMES='["alice", "bob", "dave-phone", "bad name!", "..", ".hidden", "erin"]'
"${DOCKER}" cp "${CTR}:/data" - >"${WORK}/data-main.tar"
log "restart: new container with main's /data (client_names + dave-phone and invalid names, new client_cert_password)"
before=${FAIL_COUNT}
# /config/certs as a 2.2.0 left it: the bundle of bob (revoked since), and a
# file of the user's own.
seed_stale_bundles() {
    mkdir -p "$1/certs"
    printf 'stale bundle\n' >"$1/certs/mTLS-client-bob.p12"
    printf 'my notes\n' >"$1/certs/notes.txt"
}
BOOT_CONFIG_HOOK=seed_stale_bundles
boot restart "$(options "${DOMAIN}" true none "")" "${WORK}/data-main.tar"
BOOT_CONFIG_HOOK=""
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "restart: add-on booted (invalid client_names entries do not block the start)"
    check "Method 2: the copy of revoked bob's bundle removed at the start (logged), the user's own file kept" eval '
        file_absent /config/certs/mTLS-client-bob.p12 && file_exists /config/certs/notes.txt &&
        logs_contain "Removed the copy of '"'"'bob'"'"' from /config/certs (the client is not active)."'
    check "Method 2: runtime.json has the slug, the dashboard names the folder of the copies" eval '
        test "$(cexec jq -r .config_slug /run/caddy-mtls/runtime.json)" == local_caddy_mtls &&
        [[ "$(cexec curl -fsS --max-time 10 http://127.0.0.1:8099/ 2>/dev/null)" == *"<code>app_configs/local_caddy_mtls/certs/</code>"*"<code>addon_configs/local_caddy_mtls/certs/</code>"* ]]'
    check "M5: dave-phone (new in client_names) issued: state active, key/p12 600, active/ pem" eval '
        test "$(state ".clients[] | select(.name == \"dave-phone\") | .status")" == active &&
        test "$(state ".clients[] | select(.name == \"dave-phone\") | .serial")" == "$(crt_serial /data/certs/mTLS-client-dave-phone.crt)" &&
        file_mode_is /data/certs/mTLS-client-dave-phone.key 600 && file_mode_is /data/certs/mTLS-client-dave-phone.p12 600 &&
        cexec cmp -s /data/certs/active/mTLS-client-dave-phone.pem /data/certs/mTLS-client-dave-phone.crt'
    check "M5: log: client_names: issuing a client certificate for 'dave-phone'" \
        logs_contain "client_names: issuing a client certificate for 'dave-phone'."
    check "M5: dave-phone's certificate accepted" \
        wait_for 60 mtls_is 502 /data/certs/mTLS-client-dave-phone.crt /data/certs/mTLS-client-dave-phone.key
    check "M5: revoked bob and erin skipped with a warning, still revoked, not re-issued" eval '
        logs_contain "client_names: skipping '"'"'bob'"'"': this client was revoked" &&
        logs_contain "client_names: skipping '"'"'erin'"'"': this client was revoked" &&
        revoked_unchanged &&
        ! cexec ls /data/certs | grep -E "^mTLS-client-(bob|erin)\." >/dev/null'
    check "L1: invalid client_names entries skipped with a warning" eval '
        logs_contain "client_names: skipping \"bad name!\": a client name has 1-64 characters" &&
        logs_contain "client_names: skipping \"..\":" && logs_contain "client_names: skipping \".hidden\":"'
    check "M5/L1: state.json = the previous clients + dave-phone" \
        test "$(state '[.clients[].name] | join(",")')" == "alice,bob,carol,erin,frank,dave-phone"
    check "M5: alice and carol unchanged (same serials)" \
        test "$(state '[.clients[] | select(.name == "alice" or .name == "carol") | .serial] | join(",")')" == "${alice_ca2},${carol_ca2}"
    check "M7: log: the bundles of alice and carol re-encrypted (one line each), no other" eval '
        test "$("${DOCKER}" logs "${CTR}" 2>&1 | grep -c "Re-encrypted the .p12 bundle of client")" == 2 &&
        logs_contain "Re-encrypted the .p12 bundle of client '"'"'alice'"'"' with the current client_cert_password." &&
        logs_contain "Re-encrypted the .p12 bundle of client '"'"'carol'"'"' with the current client_cert_password."'
    for c in alice carol; do
        check "M7: ${c}'s .p12 opens with the new password (her current certificate), not with the old one" eval '
            serial="$(crt_serial "/data/certs/mTLS-client-${c}.crt")" && [[ -n "${serial}" ]] &&
            test "$(p12_serial "/data/certs/mTLS-client-${c}.p12" "${P12_PASSWORD_NEW}")" == "${serial}" &&
            test -z "$(p12_serial "/data/certs/mTLS-client-${c}.p12" "${P12_PASSWORD}")"'
    done
    check "M7: dave-phone's new .p12 opens with the new password" eval '
        serial="$(crt_serial /data/certs/mTLS-client-dave-phone.crt)" && [[ -n "${serial}" ]] &&
        test "$(p12_serial /data/certs/mTLS-client-dave-phone.p12 "${P12_PASSWORD_NEW}")" == "${serial}"'
    check "M7: re-encrypted bundles: mode 600, no temporary file left" eval '
        file_mode_is /data/certs/mTLS-client-alice.p12 600 && file_mode_is /data/certs/mTLS-client-carol.p12 600 &&
        ! cexec ls /data/certs | grep -F ".tmp" >/dev/null'
    check "M7: /config/certs mirror = the re-encrypted bundles (and dave-phone's)" eval '
        cexec cmp -s /config/certs/mTLS-client-alice.p12 /data/certs/mTLS-client-alice.p12 &&
        cexec cmp -s /config/certs/mTLS-client-carol.p12 /data/certs/mTLS-client-carol.p12 &&
        cexec cmp -s /config/certs/mTLS-client-dave-phone.p12 /data/certs/mTLS-client-dave-phone.p12'
    check "restart: the old client_cert_password not in the log" logs_lack_secret "${P12_PASS_FILE}"
    check "restart: the new client_cert_password not in the log" logs_lack_secret "${P12_NEW_PASS_FILE}"
    # For the second restart: the bundles and serials must stay as they are.
    bundles_before="$(cexec sh -c 'sha256sum /data/certs/*.p12' 2>/dev/null)"
    serials_before="$(state '[.clients[] | "\(.name)=\(.serial)"] | join(",")')"
    check "restart: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
else
    fail "restart: add-on booted (invalid client_names entries do not block the start)"
fi
show_log_on_failure "${before}"

# A second restart without any change re-exports and issues nothing.
"${DOCKER}" cp "${CTR}:/data" - >"${WORK}/data-restart.tar"
log "restart2: new container, same options"
before=${FAIL_COUNT}
boot restart2 "$(options "${DOMAIN}" true none "")" "${WORK}/data-restart.tar"
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "restart2: add-on booted"
    check "M7: second restart re-encrypts nothing" logs_lack "Re-encrypted the .p12 bundle"
    check "M5: second restart issues nothing" logs_lack "client_names: issuing"
    unchanged_since_restart() {
        [[ -n "${bundles_before:-}" && -n "${serials_before:-}" ]] &&
            test "$(cexec sh -c 'sha256sum /data/certs/*.p12' 2>/dev/null)" == "${bundles_before}" &&
            test "$(state '[.clients[] | "\(.name)=\(.serial)"] | join(",")')" == "${serials_before}"
    }
    check "restart2: bundles and serials unchanged" unchanged_since_restart
    check "restart2: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
else
    fail "restart2: add-on booted"
fi
show_log_on_failure "${before}"
OPT_PASSWORD="${P12_PASSWORD}"
OPT_CLIENT_NAMES='["alice", "bob"]'
fi

# ==============================================================================
# 2. no-mtls: mtls_enabled false (public domain, ACME sinkhole)
# ==============================================================================
if smoke_case no-mtls; then
log "no-mtls: booting (mtls_enabled: false, log_level debug)"
before=${FAIL_COUNT}
CORE_INFO='{"port": 80, "ssl": false}'
OPT_LOG_LEVEL=debug
SEED_SLUG=""
boot no-mtls "$(options home.example.com false none "" homeassistant "")"
SEED_SLUG=local_caddy_mtls
OPT_LOG_LEVEL=info
CORE_INFO=""
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "no-mtls: add-on booted"
    check "no-mtls: no slug from the Supervisor -> config_slug null" \
        test "$(cexec jq -r .config_slug /run/caddy-mtls/runtime.json)" == null
    check "no-mtls: caddy validate /etc/caddy/Caddyfile" caddy_validate
    check "no-mtls: no client_auth, no CRL site, no tls block in the Caddyfile" \
        eval '! cexec grep -E "client_auth|mTLS-CA.crl|^ *tls \{" /etc/caddy/Caddyfile >/dev/null'
    check "no-mtls: admin API config has no client authentication" \
        adapted '[.. | objects | select(has("client_authentication"))] | length == 0'
    check "no-mtls: every ACME issuer uses the sinkhole (no Let's Encrypt / ZeroSSL)" issuers_only_sinkhole
    check "no-mtls: no certificates generated" file_absent /data/certs/mTLS-CA.crt
    check "no-mtls: upstream_port unset -> Core's port from the Supervisor info (homeassistant:80)" \
        eval 'logs_contain "Upstream:    homeassistant:80 (Home Assistant Core'"'"'s port from the Supervisor API)" &&
        cexec grep -F "reverse_proxy homeassistant:80 {" /etc/caddy/Caddyfile >/dev/null'
    check "no-mtls: port 80 redirects with 301 to https://<domain>/ (the add-on's plain-HTTP site, no CRL)" eval '
        test "$(cexec curl -s --max-time 5 --resolve home.example.com:80:127.0.0.1 -o /dev/null -w "%{http_code} %{redirect_url}" http://home.example.com/x?y=1)" \
            == "301 https://home.example.com/x?y=1" &&
        test "$(cexec curl -s --max-time 5 --resolve home.example.com:80:127.0.0.1 -o /dev/null -w "%{http_code}" http://home.example.com/mTLS-CA.crl)" == 301'
    check "no-mtls: log_level debug renders the site's access log, uvicorn logs requests" eval '
        logs_contain "Access log:  on" && cexec grep -E "^[[:space:]]+log \{" /etc/caddy/Caddyfile >/dev/null &&
        cexec curl -fsS -o /dev/null http://127.0.0.1:8099/_health && sleep 1 && logs_contain "\"GET /_health"'
    check "no-mtls: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
else
    fail "no-mtls: add-on booted"
fi
show_log_on_failure "${before}"
fi

# ==============================================================================
# 2b. access-log: access_log true; Caddy restarted by s6 / crash stops the add-on
# ==============================================================================
if smoke_case access-log; then
log "access-log: booting (access_log: true)"
before=${FAIL_COUNT}
OPT_ACCESS_LOG=true
boot access-log "$(options "${DOMAIN}" true none "")"
OPT_ACCESS_LOG=false
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "access-log: add-on booted"
    check "access-log: init logs 'Access log:  on'" logs_contain "Access log:  on"
    check "access-log: a request is logged ('handled request')" eval '
        http80 -o /dev/null "http://${DOMAIN}/access-log-check" && wait_for 10 logs_contain "handled request"'
    check "access-log: still no admin.api / uvicorn access lines" eval '
        cexec curl -fsS -o /dev/null http://127.0.0.1:8099/_health && sleep 1 &&
        logs_lack "admin.api" && logs_lack "\"GET /_health"'
    # Caddy exiting with 0 while s6 wants it up (here: SIGTERM to Caddy alone)
    # is not a crash: s6 starts it again, the add-on keeps running.
    caddy_pid="$(cexec pidof caddy 2>/dev/null || true)"
    caddy_restarted() {
        local pid
        pid="$(cexec pidof caddy 2>/dev/null)" && [[ -n "${pid}" && "${pid}" != "${caddy_pid}" ]] && admin_up
    }
    check "access-log: SIGTERM to Caddy alone -> s6 restarts it (exit 0 is no crash)" eval '
        [[ -n "${caddy_pid}" ]] && cexec kill -TERM "${caddy_pid}" && wait_for 20 caddy_restarted && running &&
        logs_contain "Caddy exited with exit code 0; s6 starts it again."'
    # A Caddy crash stops the add-on with Caddy's exit code (signal 9 -> 137),
    # so Supervisor shows an error (and its Watchdog can restart it).
    crash_stops_addon() {
        local pid
        pid="$(cexec pidof caddy 2>/dev/null)" && [[ -n "${pid}" ]] || return 1
        cexec kill -9 "${pid}" || return 1
        wait_for 10 exited &&
            [[ "$("${DOCKER}" inspect -f '{{.State.ExitCode}}' "${CTR}")" == 137 ]]
    }
    check "crash: kill -9 of Caddy stops the add-on within 10 s with exit code 137" crash_stops_addon
    check "crash: the log names the reason" \
        logs_contain "Caddy stopped unexpectedly (killed by signal 9); stopping the add-on with exit code 137."
    check "crash: no s6 warnings (finish script lifetime, unable to stop service)" \
        eval '! "${DOCKER}" logs "${CTR}" 2>&1 | grep -E -- "${S6_STOP_WARNINGS}" >/dev/null'
else
    fail "access-log: add-on booted"
fi
show_log_on_failure "${before}"
fi

# ==============================================================================
# 2c. acme: no certificate (ACME sinkhole) -> red card + notification; a
#     certificate in Caddy's storage -> green card + dismissed
# ==============================================================================
# The fake Supervisor runs inside the container (--network none) on a free
# port; the monitor reaches it through SUPERVISOR_URL, with short test
# intervals (notification after 5 s instead of 2 minutes).
FAKE_SUPERVISOR_PORT=8765
SUPERVISOR_LOG=/tmp/supervisor-requests.jsonl
SMOKE_SUPERVISOR_TOKEN="smoke-supervisor-token-$$"
ACME_DOMAIN="home.example.com"
# supervisor_got <jq filter>: a request the fake Supervisor received matches.
supervisor_got() {
    cexec sh -c 'test -f "$1" && jq -s -e "$0" "$1"' "[.[] | select($1)] | length > 0" "${SUPERVISOR_LOG}" >/dev/null 2>&1
}
# supervisor_count <jq filter>: how many requests matched.
supervisor_count() {
    cexec sh -c 'jq -s "$0" "$1"' "[.[] | select($1)] | length" "${SUPERVISOR_LOG}" 2>/dev/null
}
NOTE_CREATE='.method == "POST" and .path == "/core/api/services/persistent_notification/create"
    and .body.notification_id == "caddy_mtls_public_certificate"'
if smoke_case acme; then
log "acme: booting (${ACME_DOMAIN}, ACME sinkhole, fake Supervisor)"
before=${FAIL_COUNT}
EXTRA_CREATE_ARGS=(
    -e "SUPERVISOR_TOKEN=${SMOKE_SUPERVISOR_TOKEN}"
    -e "SUPERVISOR_URL=http://127.0.0.1:${FAKE_SUPERVISOR_PORT}"
    -e CERT_MONITOR_PUBLIC_CERT_GRACE_SECONDS=5
    -e CERT_MONITOR_FAST_INTERVAL_SECONDS=2
)
boot acme "$(options "${ACME_DOMAIN}" true none "")"
EXTRA_CREATE_ARGS=()
tar -C "${SCRIPT_DIR}" --owner=0 --group=0 --numeric-owner -cf - fake-supervisor.py | "${DOCKER}" cp - "${CTR}:/tmp"
"${DOCKER}" exec -d "${CTR}" /usr/lib/cert-mgr/.venv/bin/python3 /tmp/fake-supervisor.py \
    "${FAKE_SUPERVISOR_PORT}" "${SUPERVISOR_LOG}"
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "acme: add-on booted"
    acme_error_logged() { cexec sh -c 'grep -F "\"logger\":\"tls.obtain\"" /data/caddy/log/acme.log | grep -F "\"level\":\"error\""' >/dev/null 2>&1; }
    check "acme: Caddy's certificate events in /data/caddy/log/acme.log (JSON), with errors" \
        wait_for 60 acme_error_logged
    check "acme: acme.log 600, its folder 700" eval '
        file_mode_is /data/caddy/log/acme.log 600 && file_mode_is /data/caddy/log 700'
    check "acme: the errors are in the add-on log as well (could not get certificate from issuer)" \
        logs_contain "could not get certificate from issuer"
    check "card: red (data-state missing): No public certificate yet" eval '
        wait_for 30 card_state_is missing && card_contains "<strong>No public certificate yet</strong>"'
    check "card: shows the last ACME error (connection refused at the sinkhole)" \
        card_contains "connect: connection refused"
    check "card: checklist with the real host ports (80 -> 8080, 443 -> 8443) and the restart hint" eval '
        card_contains "external TCP port 80 to this Home Assistant host, port 8080" &&
        card_contains "external TCP port 443 to this Home Assistant host, port 8443" &&
        card_contains "${ACME_DOMAIN} resolves to your public IP address" &&
        card_contains "restart the app to retry immediately"'
    check "card: /api/public-cert = missing, host ports 8080/8443" test \
        "$(cexec sh -c 'curl -fsS http://127.0.0.1:8099/api/public-cert |
            jq -r "[.state, .http_host_port, .https_host_port, (.last_error != null)] | map(tostring) | join(\" \")"')" \
        == "missing 8080 8443 true"
    check "notify: the monitor raised the notification at the (fake) Supervisor" \
        wait_for 60 supervisor_got "${NOTE_CREATE}"
    check "notify: title, token, message with the error, host ports and restart hint" supervisor_got "${NOTE_CREATE}
        and .authorization == \"Bearer ${SMOKE_SUPERVISOR_TOKEN}\"
        and .body.title == \"Caddy mTLS: no public certificate for ${ACME_DOMAIN}\"
        and (.body.message | contains(\"connection refused\") and contains(\"port 8080\")
             and contains(\"port 8443\") and contains(\"restart the app to retry immediately\"))"
    sleep 5
    check "notify: one log line for the state change, one notification (no repeats)" eval '
        test "$("${DOCKER}" logs "${CTR}" 2>&1 | grep -c "No public certificate for ${ACME_DOMAIN}")" == 1 &&
        test "$(supervisor_count "${NOTE_CREATE}")" == 1'
    # Success, simulated: a certificate in Caddy's storage, as Caddy stores
    # one it obtained (any issuer folder).
    cexec sh -c 'd=/data/caddy/certificates/smoke-acme/home.example.com && mkdir -p "$d" &&
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 90 \
            -subj "/O=Smoke ACME CA/CN=Smoke R1" -keyout "$d/home.example.com.key" \
            -out "$d/home.example.com.crt"' >/dev/null 2>&1 || true
    check "card: green (data-state ok) after the certificate appeared in Caddy's storage" \
        wait_for 30 card_state_is ok
    check "card: issuer and expiry of the stored certificate" eval '
        card_contains "from Smoke ACME CA (Smoke R1)" && card_contains "(89 days)."'
    check "notify: dismissed at the (fake) Supervisor" wait_for 30 supervisor_got \
        '.path == "/core/api/services/persistent_notification/dismiss" and .body.notification_id == "caddy_mtls_public_certificate"'
    check "notify: one log line for the certificate" eval '
        wait_for 10 logs_contain "Public certificate for ${ACME_DOMAIN}: Smoke ACME CA (Smoke R1)" &&
        test "$("${DOCKER}" logs "${CTR}" 2>&1 | grep -c "Public certificate for ${ACME_DOMAIN}")" == 1'
    # A failed renewal after the certificate was stored: yellow.
    cexec sh -c 'printf "%s\n" "{\"level\":\"error\",\"ts\":$(( $(date +%s) + 2 )),\"logger\":\"tls.renew\",\"msg\":\"could not get certificate from issuer\",\"identifier\":\"home.example.com\",\"error\":\"HTTP 400 urn:ietf:params:acme:error:connection - 192.0.2.1: Timeout during connect (likely firewall problem)\"}" >> /data/caddy/log/acme.log' || true
    check "card: yellow (data-state renewal_failing) after a failed renewal, with its error" eval '
        card_state_is renewal_failing && card_contains "renewing it" &&
        card_contains "connection: 192.0.2.1: Timeout during connect (likely firewall problem)"'
    check "acme: no admin.api / TLS handshake error lines from the panel's probes" eval '
        logs_lack "admin.api" && logs_lack "TLS handshake error"'
    check "acme: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
else
    fail "acme: add-on booted"
fi
show_log_on_failure "${before}"
fi

# ==============================================================================
# 2d. forwarded_headers: a fake Home Assistant (tests/fake-upstream.py) that
#     refuses X-Forwarded-For unless told to trust the proxy
# ==============================================================================
# The fake runs in its own container (the add-on image, --network none) in a
# restart loop on 127.0.0.1:8124; the add-on joins its network namespace
# (--network container:<fake>), so the fake answers init-caddy's probe at the
# start. Killing the fake's process is a quick "Home Assistant restart" (back
# after 0.5 s - quicker than the monitor's control interval: the kept-alive
# connection tells). The monitor runs with short intervals: control 1 s, test
# (mode pass under auto) 3 s.
FAKE_UP=""
fexec() { "${DOCKER}" exec "${FAKE_UP}" "$@"; }
fake_up_ok() { fexec curl -fsS -o /dev/null --max-time 2 http://127.0.0.1:8124/manifest.json 2>/dev/null; }
# The fake's container also names 127.0.0.1 "homeassistant" (/etc/hosts, which
# the add-on shares), so the add-on treats it as Home Assistant.
# FAKE_NET_SETUP: shell commands run in the fake's network namespace (with
# NET_ADMIN) before the add-on joins it.
FAKE_NET_SETUP=""
start_fake_upstream() { # start_fake_upstream <name> [trust]
    local caps=()
    FAKE_UP="${PREFIX}-up-$1"
    CONTAINERS+=("${FAKE_UP}")
    [[ -n "${FAKE_NET_SETUP}" ]] && caps=(--cap-add NET_ADMIN)
    "${DOCKER}" create --name "${FAKE_UP}" --network none --add-host homeassistant:127.0.0.1 \
        "${caps[@]+"${caps[@]}"}" -e "FAKE_TRUST=${2:-}" --entrypoint /bin/sh "${IMAGE}" -c \
        'mkdir -p /tmp/up; [ -z "${FAKE_TRUST}" ] || touch /tmp/up/trust; while :; do if [ ! -e /tmp/up/down ]; then python3 /tmp/fake-upstream.py 8124 /tmp/up & echo $! >/tmp/up/pid; wait; fi; sleep 0.5; done' \
        >/dev/null
    tar -C "${SCRIPT_DIR}" --owner=0 --group=0 --numeric-owner -cf - fake-upstream.py | "${DOCKER}" cp - "${FAKE_UP}:/tmp"
    "${DOCKER}" start "${FAKE_UP}" >/dev/null
    if [[ -n "${FAKE_NET_SETUP}" ]]; then
        "${DOCKER}" exec "${FAKE_UP}" sh -ec "${FAKE_NET_SETUP}" || return 1
    fi
    wait_for 20 fake_up_ok
}
fake_trust() { if [[ "$1" == on ]]; then fexec touch /tmp/up/trust; else fexec rm -f /tmp/up/trust; fi; }
fake_restart() { fexec sh -c 'kill "$(cat /tmp/up/pid)"'; }
# refusals: how many requests the fake refused (= Home Assistant log lines).
refusals() { fexec sh -c 'cat /tmp/up/refused.log 2>/dev/null | wc -l' | tr -d ' '; }
refusals_are() { [[ "$(refusals)" == "$1" ]]; }
# proxied <path> [curl args...]: the fake's JSON echo of a request through
# port 443 with alice's client certificate and spoofed forwarding headers.
proxied() {
    local path="$1"
    shift
    cexec curl -sk --max-time 10 --resolve "${DOMAIN}:443:127.0.0.1" \
        --cert /data/certs/mTLS-client-alice.crt --key /data/certs/mTLS-client-alice.key \
        -H "X-Forwarded-For: 203.0.113.9" -H "X-Real-IP: 203.0.113.8" -H "Forwarded: for=203.0.113.7" \
        -H "X-Forwarded-Host: evil.example" -H "X-Forwarded-Proto: http" \
        "$@" "https://${DOMAIN}${path}" 2>/dev/null
}
# echo_header <json> <name>: the values of a header in the echo (joined by
# ","; empty if absent); names compared case-insensitively.
echo_header() {
    jq -r --arg n "$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')" \
        '.headers | to_entries | map(select((.key | ascii_downcase) == $n) | .value[]) | join(",")' <<<"$1" 2>/dev/null
}
no_forwarding_headers() { # the echo carries none of them
    local h
    for h in X-Forwarded-For X-Forwarded-Proto X-Forwarded-Host X-Real-IP Forwarded; do
        [[ -z "$(echo_header "$1" "${h}")" ]] || { log "echo still has ${h}: $(echo_header "$1" "${h}")"; return 1; }
    done
}
NOTE_UP_CREATE='.method == "POST" and .path == "/core/api/services/persistent_notification/create"
    and .body.notification_id == "caddy_mtls_upstream_refuses"'
# shellcheck disable=SC2034 # used in eval'd checks
NOTE_HIDDEN_CREATE='.method == "POST" and .path == "/core/api/services/persistent_notification/create"
    and .body.notification_id == "caddy_mtls_upstream_addresses_hidden"'
# shellcheck disable=SC2034 # used in eval'd checks
NOTE_HIDDEN_DISMISS='.path == "/core/api/services/persistent_notification/dismiss"
    and .body.notification_id == "caddy_mtls_upstream_addresses_hidden"'
# shellcheck disable=SC2034 # used in eval'd checks
NOTE_UP_DISMISS='.path == "/core/api/services/persistent_notification/dismiss"
    and .body.notification_id == "caddy_mtls_upstream_refuses"'
FWD_ENV=(
    -e "SUPERVISOR_TOKEN=${SMOKE_SUPERVISOR_TOKEN}"
    -e "SUPERVISOR_URL=http://127.0.0.1:${FAKE_SUPERVISOR_PORT}"
    -e CADDY_MTLS_UPSTREAM_CONTROL_SECONDS=1
    -e CADDY_MTLS_UPSTREAM_TEST_SECONDS=3
    -e CADDY_MTLS_CUSTOM_RETRY_SECONDS=2
)
# boot_fwd <name> <options-json> [trust]: the add-on beside a fresh fake
# upstream, with the fake Supervisor.
boot_fwd() {
    start_fake_upstream "$1" "${3:-}" || { fail "$1: fake upstream up"; return 1; }
    BOOT_NETWORK="container:${FAKE_UP}"
    EXTRA_CREATE_ARGS=("${FWD_ENV[@]}")
    boot "$1" "$2"
    BOOT_NETWORK=none
    EXTRA_CREATE_ARGS=()
    tar -C "${SCRIPT_DIR}" --owner=0 --group=0 --numeric-owner -cf - fake-supervisor.py | "${DOCKER}" cp - "${CTR}:/tmp"
    "${DOCKER}" exec -d "${CTR}" /usr/lib/cert-mgr/.venv/bin/python3 /tmp/fake-supervisor.py \
        "${FAKE_SUPERVISOR_PORT}" "${SUPERVISOR_LOG}"
}
upstream_mode_is() { # upstream_mode_is pass|strip: snippet, state and Caddy agree
    snippet_is "$1" && [[ "$(cexec jq -r '"\(.mode) \(.applied)"' /data/upstream.json 2>/dev/null)" == "$1 true" ]] &&
        adapted "$([[ "$1" == pass ]] && printf '%s' "${HEADERS_PASS}" || printf '%s' "${HEADERS_STRIP}")"
}

# --- auto with mTLS: refused at the start -> strip; trust -> pass; back --------
if smoke_case fwd; then
log "fwd-auto: booting beside a fake Home Assistant that refuses X-Forwarded-For"
before=${FAIL_COUNT}
boot_fwd fwd-auto "$(options "${DOMAIN}" true none "" homeassistant 8124)"
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "fwd-auto: add-on booted"
    check "fwd-auto: start probe refused (one refusal = one Home Assistant log line) -> mode strip" eval '
        refusals_are 1 && upstream_mode_is strip'
    check "fwd-auto: init-caddy's short notice for strip (no 400 block)" eval '
        logs_contain "Home Assistant does not trust this add-on (127.0.0.1) as a reverse proxy. The add-on therefore removes the forwarding headers" &&
        logs_contain "Forwarding:  forwarded_headers auto, mode strip" && logs_lack "answers EVERY request"'
    check "fwd-auto: card strip: works, visitors appear as 127.0.0.1, consequences and steps" eval '
        upstream_card_is strip && upstream_card_contains "It works" &&
        upstream_card_contains "<code>127.0.0.1</code>" && upstream_card_contains "Can only log in from the local network" &&
        upstream_card_contains "Trust X-Forwarded-For" && upstream_card_contains "use_x_forwarded_for: true"'
    echo_strip="$(proxied /strip-check)"
    check "fwd-auto: strip: the request reaches the upstream (alice's certificate)" \
        test "$(jq -r .path <<<"${echo_strip}" 2>/dev/null)" == /strip-check
    check "fwd-auto: strip: no X-Forwarded-*, X-Real-IP or Forwarded reaches the upstream (spoofed ones neither)" \
        no_forwarding_headers "${echo_strip}"
    # shellcheck disable=SC2034 # used in eval'd checks
    lines="$(log_line_count)"
    sleep 6
    check "fwd-auto: strip: 6 s of watching (control requests only) -> still one refusal" refusals_are 1
    check "fwd-auto: strip: the monitor watches with control requests (no forwarding header)" \
        test "$(fexec sh -c 'grep -c "\"forwarded\": {}" /tmp/up/requests.jsonl')" -gt 4
    # Home Assistant gets the reverse proxy settings and restarts (quicker
    # than the control interval: the broken kept-alive connection tells).
    fake_trust on
    fake_restart
    check "fwd-auto: trust + restart -> the monitor switches to mode pass (no add-on restart)" wait_for 20 upstream_mode_is pass
    check "fwd-auto: Caddy reloaded for the switch (stopped previous server), monitor logged the switch" eval '
        wait_for 10 new_logs_contain "${lines}" "stopped previous server" &&
        new_logs_contain "${lines}" "Forwarding headers: mode strip -> pass"'
    check "fwd-auto: card accepted" wait_for 10 upstream_card_is accepted
    echo_pass="$(proxied /pass-check)"
    check "fwd-auto: pass: X-Forwarded-For = the real client (127.0.0.1), the spoofed value replaced" \
        test "$(echo_header "${echo_pass}" X-Forwarded-For)" == 127.0.0.1
    check "fwd-auto: pass: X-Real-IP = 127.0.0.1, X-Forwarded-Proto https, X-Forwarded-Host = the domain, no Forwarded" eval '
        test "$(echo_header "${echo_pass}" X-Real-IP)" == 127.0.0.1 &&
        test "$(echo_header "${echo_pass}" X-Forwarded-Proto)" == https &&
        test "$(echo_header "${echo_pass}" X-Forwarded-Host)" == "${DOMAIN}" &&
        test -z "$(echo_header "${echo_pass}" Forwarded)"'
    sleep 7
    check "fwd-auto: pass: tests every 3 s while trusted, still one refusal" eval '
        refusals_are 1 && test "$(fexec sh -c "grep -c \"X-Forwarded-For\" /tmp/up/requests.jsonl")" -ge 3'
    # Trust lost without a restart: the periodic test notices it.
    fake_trust off
    check "fwd-auto: trust lost -> the periodic test switches back to strip (one more refusal)" eval '
        wait_for 15 upstream_mode_is strip && refusals_are 2'
    check "fwd-auto: card strip again" wait_for 10 upstream_card_is strip
    # B-12: a switch to strip at run time raises one notification (none when
    # the add-on started in strip: only the dismissal of a previous run's).
    check "notify: addresses hidden at run time -> one notification with the consequences and the steps" eval '
        wait_for 15 supervisor_got "${NOTE_HIDDEN_CREATE}" &&
        test "$(supervisor_count "${NOTE_HIDDEN_CREATE}")" == 1 &&
        supervisor_got "${NOTE_HIDDEN_CREATE} and (.body.title == \"Caddy mTLS: Home Assistant no longer trusts the app - visitor addresses are hidden\")
            and (.body.message | contains(\"Can only log in from the local network\") and contains(\"Trust X-Forwarded-For\"))" &&
        test "$(supervisor_count "${NOTE_HIDDEN_DISMISS}")" == 1'
    check "fwd-auto: Check again (POST, ingress) -> 303 with the result, one more refusal" eval '
        [[ "$(panel_post /api/upstream/check)" == "303 http://127.0.0.1:8099${INGRESS_PREFIX}/?ok="*"does+not+trust"* ]] &&
        refusals_are 3'
    check "fwd-auto: /api/upstream = strip, refused" \
        test "$(cexec sh -c 'curl -fsS http://127.0.0.1:8099/api/upstream | jq -r "[.card, .state.decisive, .state.mode] | join(\" \")"')" \
        == "strip refused strip"
    check "notify: no upstream notification for strip / accepted, one dismissal after the start" eval '
        test "$(supervisor_count "${NOTE_UP_CREATE}")" == 0 && test "$(supervisor_count "${NOTE_UP_DISMISS}")" == 1'
    # B-2: a reload that fails (the Caddyfile broken on purpose) - the card is
    # red and everything follows the mode Caddy really runs (strip).
    cexec cp /etc/caddy/Caddyfile /tmp/Caddyfile.good
    cexec sh -c 'printf "broken-on-purpose {\n" >> /etc/caddy/Caddyfile'
    # shellcheck disable=SC2034 # used in eval'd checks
    lines="$(log_line_count)"
    fake_trust on
    fake_restart
    check "reload-failed: card red (Change not applied) with the error" eval '
        wait_for 20 upstream_card_is reload_failed && upstream_card_contains "Change not applied" &&
        upstream_card_contains "Applying the forwarding mode pass failed"'
    check "reload-failed: Caddy keeps strip - snippet, upstream.json (mode pass, running strip, not applied)" eval '
        snippet_is strip && adapted "${HEADERS_STRIP}" &&
        test "$(cexec jq -c "[.mode, .running, .applied]" /data/upstream.json)" == "[\"pass\",\"strip\",false]"'
    check "reload-failed: requests still arrive without forwarding headers (what Caddy runs)" \
        no_forwarding_headers "$(proxied /reload-failed-check)"
    sleep 4
    reload_error_logged_once() {
        local n
        n="$("${DOCKER}" logs "${CTR}" 2>&1 | tail -n "+$((lines + 1))" | grep -c "Applying the forwarding mode pass failed")"
        [[ "${n}" == 1 ]] || { log "reload error logged ${n} times"; return 1; }
    }
    check "reload-failed: one ERROR line for it, not one per retry (control interval 1 s)" reload_error_logged_once
    check "reload-failed: Check again -> flash error naming the failed reload" eval '
        [[ "$(panel_post /api/upstream/check)" == "303 http://127.0.0.1:8099${INGRESS_PREFIX}/?error=Applying+the+forwarding+mode+pass+failed"* ]]'
    cexec cp /tmp/Caddyfile.good /etc/caddy/Caddyfile
    check "reload-failed: repaired -> the retry applies pass, card accepted, logged once" eval '
        wait_for 15 upstream_mode_is pass && wait_for 10 upstream_card_is accepted &&
        new_logs_contain "${lines}" "Caddy reloaded: the forwarding mode pass applies now."'
    hidden_dismissed_twice() { test "$(supervisor_count "${NOTE_HIDDEN_DISMISS}")" == 2; }
    check "notify: addresses passed on again -> the hidden notification dismissed" wait_for 10 hidden_dismissed_twice
    # Back to strip (fwd-down below starts from this /data).
    fake_trust off
    fake_restart
    check "fwd-auto: trust gone with a restart -> strip again" wait_for 20 upstream_mode_is strip
    check "fwd-auto: no Traceback in the log" logs_lack "Traceback"
    check "fwd-auto: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
    "${DOCKER}" cp "${CTR}:/data" - >"${WORK}/data-fwd-auto.tar"
else
    fail "fwd-auto: add-on booted"
fi
show_log_on_failure "${before}"

# --- restart while the upstream is down: the last known mode (strip) ----------
log "fwd-down: new container with fwd-auto's /data, no upstream"
before=${FAIL_COUNT}
if [[ -s "${WORK}/data-fwd-auto.tar" ]]; then
    boot fwd-down "$(options "${DOMAIN}" true none "" homeassistant 8124)" "${WORK}/data-fwd-auto.tar"
    if wait_for "${BOOT_TIMEOUT}" booted; then
        pass "fwd-down: add-on booted"
        check "fwd-down: upstream unreachable -> the last known mode strip, card unreachable" eval '
            snippet_is strip && adapted "${HEADERS_STRIP}" && upstream_card_is unreachable &&
            logs_contain "The upstream homeassistant:8124 does not answer yet" &&
            logs_contain "Forwarding headers until then: mode strip (last known)"'
        check "fwd-down: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
    else
        fail "fwd-down: add-on booted"
    fi
else
    fail "fwd-down: /data of fwd-auto available"
fi
show_log_on_failure "${before}"

# --- always: every request answered 400 -> red card, notification -----------
log "fwd-always: forwarded_headers always, the fake refuses"
before=${FAIL_COUNT}
OPT_FORWARDED=always
boot_fwd fwd-always "$(options "${DOMAIN}" true none "" homeassistant 8124)"
OPT_FORWARDED=auto
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "fwd-always: add-on booted"
    check "fwd-always: refused, mode pass (broken)" eval 'refusals_are 1 && upstream_mode_is pass'
    check "fwd-always: init-caddy's prominent block with the steps and the 2026.7 note" eval '
        logs_contain "answers EVERY request through ${DOMAIN}" &&
        logs_contain "add 127.0.0.1 to '"'"'Trusted proxies'"'"'" &&
        logs_contain "Home Assistant before 2026.7: add this to configuration.yaml" &&
        logs_contain "      - 127.0.0.1"'
    check "fwd-always: a proxied request is answered 400 by the upstream (\"400: Bad Request\")" eval '
        test "$(cexec curl -sk --max-time 10 --resolve "${DOMAIN}:443:127.0.0.1" -w " %{http_code}" \
            --cert /data/certs/mTLS-client-alice.crt --key /data/certs/mTLS-client-alice.key "https://${DOMAIN}/x")" \
            == "400: Bad Request 400"'
    check "fwd-always: card red (broken): 400, forwarded_headers always, the steps, the auto alternative" eval '
        upstream_card_is broken && upstream_card_contains "Every request is answered" &&
        upstream_card_contains "<code>forwarded_headers</code> is <code>always</code>" &&
        upstream_card_contains "Or set the app option"'
    check "notify: the monitor raised the upstream notification at the (fake) Supervisor" \
        wait_for 30 supervisor_got "${NOTE_UP_CREATE}"
    check "notify: title, token, message with the domain, the steps and the YAML for old versions" supervisor_got "${NOTE_UP_CREATE}
        and .authorization == \"Bearer ${SMOKE_SUPERVISOR_TOKEN}\"
        and .body.title == \"Caddy mTLS: Home Assistant refuses the proxied requests\"
        and (.body.message | contains(\"400: Bad Request\") and contains(\"**${DOMAIN}**\")
             and contains(\"Trust X-Forwarded-For\") and contains(\"use_x_forwarded_for: true\"))"
    # shellcheck disable=SC2034 # used in eval'd checks
    refused_before="$(refusals)"
    sleep 4
    check "notify: raised once; no test requests in 4 s (always: start, comeback and Check again only)" eval '
        test "$(supervisor_count "${NOTE_UP_CREATE}")" == 1 && refusals_are "${refused_before}"'
    fake_trust on
    fake_restart
    check "fwd-always: trust + restart -> accepted, notification dismissed" eval '
        wait_for 20 upstream_card_is accepted && wait_for 15 supervisor_got "${NOTE_UP_DISMISS}"'
    check "fwd-always: mode stayed pass (no reload needed)" upstream_mode_is pass
    check "fwd-always: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
else
    fail "fwd-always: add-on booted"
fi
show_log_on_failure "${before}"

# --- never: headers removed whatever the upstream says ----------------------
log "fwd-never: forwarded_headers never, the fake trusts"
before=${FAIL_COUNT}
OPT_FORWARDED=never
boot_fwd fwd-never "$(options "${DOMAIN}" true none "" homeassistant 8124)" trust
OPT_FORWARDED=auto
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "fwd-never: add-on booted"
    check "fwd-never: mode strip, card never" eval 'upstream_mode_is strip && upstream_card_is never'
    check "fwd-never: no forwarding header reaches the upstream" no_forwarding_headers "$(proxied /never-check)"
    check "fwd-never: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
else
    fail "fwd-never: add-on booted"
fi
show_log_on_failure "${before}"

# --- auto without mTLS: stays pass (broken), notification --------------------
log "fwd-nomtls: mtls_enabled false, auto, the fake refuses"
before=${FAIL_COUNT}
boot_fwd fwd-nomtls "$(options home.example.com false none "" homeassistant 8124)"
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "fwd-nomtls: add-on booted"
    check "fwd-nomtls: refused, auto without mTLS stays at mode pass (broken)" eval '
        refusals_are 1 && upstream_mode_is pass && upstream_card_is broken'
    check "fwd-nomtls: the card explains why auto does not strip and offers mTLS, not never" eval '
        upstream_card_contains "mtls_enabled: false" && upstream_card_contains "Or turn mTLS on" &&
        ! upstream_card_contains "forwarded_headers: never" && ! upstream_card_contains "<code>never</code>"'
    check "fwd-nomtls: the log block offers mTLS, not never" eval '
        logs_contain "Or turn mTLS on (mtls_enabled: true): with forwarded_headers" && logs_lack "forwarded_headers: never"'
    check "notify: raised (mTLS off)" wait_for 30 supervisor_got "${NOTE_UP_CREATE} and (.body.message | contains(\"mtls_enabled: false\"))"
    check "fwd-nomtls: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
else
    fail "fwd-nomtls: add-on booted"
fi
show_log_on_failure "${before}"

# --- an upstream that is not Home Assistant: neutral texts (B-7) ---------------
log "fwd-other: upstream 127.0.0.1:8124 (not Home Assistant), auto, refusing"
before=${FAIL_COUNT}
boot_fwd fwd-other "$(options "${DOMAIN}" true none "" 127.0.0.1 8124)"
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "fwd-other: add-on booted"
    check "fwd-other: strip notice names the upstream, lower case inside sentences, card Upstream connection" eval '
        upstream_mode_is strip &&
        logs_contain "The upstream 127.0.0.1:8124 does not trust this add-on (127.0.0.1) as a reverse proxy." &&
        logs_contain "and the upstream 127.0.0.1:8124 sees every visitor as 127.0.0.1." &&
        logs_contain "let the upstream 127.0.0.1:8124 trust 127.0.0.1 as a reverse proxy" &&
        logs_contain "(card \"Upstream connection\")"'
    check "fwd-other: no \"The upstream\" mid-sentence, no Home Assistant card named" eval '
        logs_lack "and The upstream" && logs_lack "let The upstream" && logs_lack "Home Assistant connection"'
    check "fwd-other: card titled Upstream connection, no claim about Home Assistant" eval '
        upstream_card_contains "<h2 class=\"card__title\" id=\"hc-heading\">Upstream connection</h2>" &&
        ! upstream_card_contains "Home Assistant"'
    check "fwd-other: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
else
    fail "fwd-other: add-on booted"
fi
show_log_on_failure "${before}"

log "fwd-other-always: upstream 127.0.0.1:8124 (not Home Assistant), always, refusing"
before=${FAIL_COUNT}
OPT_FORWARDED=always
boot_fwd fwd-other-always "$(options "${DOMAIN}" true none "" 127.0.0.1 8124)"
OPT_FORWARDED=auto
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "fwd-other-always: add-on booted"
    check "fwd-other-always: the 400 block names the upstream in lower case and the card's own title" eval '
        logs_contain "The upstream 127.0.0.1:8124 answers EVERY request through ${DOMAIN}" &&
        logs_contain "Let the upstream 127.0.0.1:8124 trust 127.0.0.1 as a reverse" &&
        logs_contain "Or set forwarded_headers to auto: the upstream 127.0.0.1:8124 then sees" &&
        logs_contain "Details: the add-on'"'"'s web interface (card \"Upstream connection\")." &&
        logs_lack "forwarded_headers: never" && logs_lack "Home Assistant connection"'
    # shellcheck disable=SC2016
    note_other='.body.title == "Caddy mTLS: the upstream refuses the proxied requests"
        and (.body.message | contains("card \"Upstream connection\"") and (contains("Home Assistant") | not))'
    check "fwd-other-always: notification neutral, naming the Upstream connection card" \
        wait_for 30 supervisor_got "${NOTE_UP_CREATE} and ${note_other}"
    check "fwd-other-always: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
else
    fail "fwd-other-always: add-on booted"
fi
show_log_on_failure "${before}"
fi

# ==============================================================================
# 2e. lan: the local-network HTTPS port (container port 4443, host port 9443)
# ==============================================================================
# The fake upstream's network namespace gets (NET_ADMIN, before the add-on
# joins it) a default route via 10.99.0.1 - the "Docker gateway" init-caddy
# must refuse - and loopback addresses to connect from: 10.99.0.1 (that
# gateway), 10.99.0.2 (private), 198.51.100.7 and 2001:db8::7 (public).
LAN_DOMAIN="${DOMAIN}"
# lan_get <source-address> [curl args...]: "<code>" of GET https://<domain>:4443/
# without a client certificate, connecting from <source-address>.
lan_get() {
    local src="$1" ip="$1"
    shift
    [[ "${src}" == *:* ]] && ip="[${src}]"
    cexec curl -sk --max-time 10 --interface "${src}" --resolve "${LAN_DOMAIN}:4443:${ip}" \
        "$@" "https://${LAN_DOMAIN}:4443/lan-check" 2>/dev/null || true
}
# s_client <port> <tls1_2|tls1_3> <session-arg> <file> [extra args]: the lines
# "New, ..." / "Reused, ..." / alerts of an openssl handshake with one request.
s_client() {
    cexec sh -c 'printf "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" "$4" |
        openssl s_client -connect "127.0.0.1:$0" -servername "$4" -"$1" -ign_eof "$2" "$3" 2>&1 |
        grep -E "^(New|Reused),|alert|HTTP/1.1 [0-9]+" || true' "$1" "$2" "$3" "$4" "${LAN_DOMAIN}"
}
if smoke_case lan; then
log "lan: booting (mTLS, local-network port on, a fake Home Assistant that trusts the proxy)"
before=${FAIL_COUNT}
FAKE_NET_SETUP='ip addr add 10.99.0.2/24 dev lo; ip addr add 10.99.0.1/32 dev lo;
    ip route add default via 10.99.0.1 dev lo; ip addr add 198.51.100.7/32 dev lo;
    ip -6 addr add 2001:db8::7/128 dev lo'
SEED_NETWORK='{"80/tcp":8080,"443/tcp":8443,"4443/tcp":9443}'
boot_fwd lan "$(options "${DOMAIN}" true none "" homeassistant 8124)" trust
SEED_NETWORK='{"80/tcp":8080,"443/tcp":8443}'
FAKE_NET_SETUP=""
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "lan: add-on booted"
    check "lan: site https://<domain>:4443 rendered, without client_auth, refusing the default gateway 10.99.0.1" eval '
        cexec grep -F "https://${DOMAIN}:4443 {" /etc/caddy/Caddyfile >/dev/null &&
        cexec grep -F "@docker_gateway remote_ip 10.99.0.1" /etc/caddy/Caddyfile >/dev/null &&
        test "$(cexec grep -c client_auth /etc/caddy/Caddyfile)" == 1'
    check "lan: logged (host port, URL, never forward, the refused gateway), runtime.json" eval '
        logs_contain "4443/tcp -> 9443" && logs_contain "LAN port:    https://${DOMAIN}:9443/" &&
        logs_contain "never forward it on the router" && logs_contain "also refused: 10.99.0.1" &&
        test "$(cexec jq -c "[.lan_state, .lan_host_port, .lan_refused]" /run/caddy-mtls/runtime.json)" == "[\"on\",9443,[\"10.99.0.1\"]]"'
    check "lan: admin API config: :443 requires client certificates, :4443 does not" adapted '
        ([.apps.http.servers[] | select(.listen == [":443"]) | .. | objects | select(.mode? == "require_and_verify")] | length == 1)
        and ([.apps.http.servers[] | select(.listen == [":4443"]) | .. | objects | select(has("client_authentication"))] | length == 0)'
    check "lan: strict SNI-Host enforcement still on for the mTLS server (srv0), not added to others" eval '
        logs_contain "enabling strict SNI-Host enforcement because TLS client auth is configured" &&
        ! "${DOCKER}" logs "${CTR}" 2>&1 | grep -F "strict SNI-Host" | grep -v "\"srv0\"" >/dev/null &&
        adapted "(.apps.http.servers.srv0.listen == [\":443\"])"'
    check "lan: forwarding snippet imported by both sites" \
        test "$(cexec grep -c "import /etc/caddy/forwarded-headers.caddy" /etc/caddy/Caddyfile)" == 2
    lan_ok="$(lan_get 127.0.0.1)"
    check "lan: no client certificate, from 127.0.0.1 -> proxied (the fake's echo)" \
        test "$(jq -r .path <<<"${lan_ok}" 2>/dev/null)" == /lan-check
    check "lan: headers in mode pass: X-Forwarded-For = the LAN client" \
        test "$(echo_header "${lan_ok}" X-Forwarded-For)" == 127.0.0.1
    check "lan: from 10.99.0.2 (private) -> proxied" \
        test "$(jq -r .path <<<"$(lan_get 10.99.0.2)" 2>/dev/null)" == /lan-check
    out="$(lan_get 198.51.100.7 -w ' %{http_code} %{content_type}')"
    check "lan: from 198.51.100.7 (public IPv4) -> 403 plain text naming the address" eval '
        [[ "${out}" == "403 Forbidden: this HTTPS port"*"came from 198.51.100.7."*" 403 text/plain"* ]]'
    out="$(lan_get 2001:db8::7 -w ' %{http_code}')"
    check "lan: from 2001:db8::7 (public IPv6) -> 403 naming the address" eval '
        [[ "${out}" == "403 Forbidden:"*"came from 2001:db8::7."*" 403" ]]'
    # shellcheck disable=SC2034 # used in an eval'd check
    out="$(lan_get 10.99.0.1 -w ' %{http_code}')"
    check "lan: from 10.99.0.1 (the container's default gateway: Docker's proxy) -> 403 explaining the hidden source" eval '
        [[ "${out}" == "403 Forbidden: this connection came from 10.99.0.1, the address of Docker"*"Connect over IPv4"*" 403" ]]'
    check "lan: refused sources never reached the upstream" \
        test "$(fexec sh -c 'grep -c "/lan-check" /tmp/up/requests.jsonl')" == 2
    # The mTLS port is untouched by the local-network site.
    check "lan: port 443 without a client certificate still refused in the handshake" mtls_is 000 "" ""
    check "lan: port 443 with alice's certificate -> proxied (200)" \
        mtls_is 200 /data/certs/mTLS-client-alice.crt /data/certs/mTLS-client-alice.key
    check "lan: port 443, SNI other.invalid, Host <domain>, no certificate -> no answer from the upstream" eval '
        test "$(cexec curl -sk --max-time 5 -o /dev/null -w "%{http_code}" --resolve other.invalid:443:127.0.0.1 -H "Host: ${DOMAIN}" https://other.invalid/)" == 000'
    check "lan: port 443 without SNI (IP address), Host <domain>, no certificate -> no answer" eval '
        test "$(cexec curl -sk --max-time 5 -o /dev/null -w "%{http_code}" -H "Host: ${DOMAIN}" https://127.0.0.1/)" == 000'
    check "lan: port 4443, Host other.invalid -> the upstream is not asked" eval '
        cexec curl -sk --max-time 5 -o /dev/null --resolve "${DOMAIN}:4443:127.0.0.1" -H "Host: other.invalid" "https://${DOMAIN}:4443/sni-host-check" &&
        ! fexec grep -F "/sni-host-check" /tmp/up/requests.jsonl >/dev/null'
    # A TLS session of the local-network port cannot be resumed on the mTLS
    # port (one session-ticket key in Caddy; Go refuses to resume a session
    # without client certificates where they are required).
    for v in tls1_3 tls1_2; do
        cexec rm -f "/tmp/lan-${v}.sess"
        # shellcheck disable=SC2034 # used in an eval'd check
        first="$(s_client 4443 "${v}" -sess_out "/tmp/lan-${v}.sess")"
        check "lan: ${v}: a session on 4443 (no certificate) with a ticket" eval '
            [[ "${first}" == "New, "*"HTTP/1.1 200"* ]] &&
            cexec sh -c "openssl sess_id -in /tmp/lan-${v}.sess -noout -text | grep -F \"TLS session ticket:\"" >/dev/null'
        # shellcheck disable=SC2034 # used in an eval'd check
        again="$(s_client 4443 "${v}" -sess_in "/tmp/lan-${v}.sess")"
        check "lan: ${v}: control - the session resumes on 4443 (Reused)" eval '[[ "${again}" == "Reused, "* ]]'
        # shellcheck disable=SC2034 # used in an eval'd check
        mtls_try="$(s_client 443 "${v}" -sess_in "/tmp/lan-${v}.sess")"
        check "lan: ${v}: the same session on 443 is not resumed, the handshake fails without a certificate" eval '
            [[ "${mtls_try}" != *"Reused, "* && "${mtls_try}" == *alert* && "${mtls_try}" != *"HTTP/1.1"* ]]'
    done
    check "lan: port 80 redirects with 301 to https://<domain>/ (port 443, not 4443)" \
        test "$(http80 -o /dev/null -w '%{http_code} %{redirect_url}' "http://${DOMAIN}/x?y=1")" == "301 https://${DOMAIN}/x?y=1"
    check "lan: dashboard card 'Local network' on: URL, local DNS, never forward, the refused gateway" eval '
        html="$(dashboard /)" && [[ "${html}" == *"data-state=\"on\""*"https://${DOMAIN}:9443/"* &&
        "${html}" == *"Never forward host port 9443"* && "${html}" == *"<code>10.99.0.1</code>"* ]]'
    # Revoking a client still takes effect at once on 443 with the LAN site.
    check "lan: POST revoke alice -> 303" \
        test "$(panel_post /api/clients/alice/revoke reason=keyCompromise)" == "303 http://127.0.0.1:8099${INGRESS_PREFIX}/?ok=Client+%27alice%27+revoked."
    check "lan: alice refused on 443 at once" mtls_is 000 /data/certs/mTLS-client-alice.crt /data/certs/mTLS-client-alice.key
    check "lan: the local-network port still answers (no certificate)" \
        test "$(jq -r .path <<<"$(lan_get 127.0.0.1)" 2>/dev/null)" == /lan-check
    check "lan: no Traceback, no failed validation in the log" eval 'logs_lack "Traceback" && logs_lack "failed validation"'
    check "lan: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
else
    fail "lan: add-on booted"
fi
show_log_on_failure "${before}"

# --- mTLS off with the local-network port: both sites without certificates,
#     the plain-HTTP site still redirects to 443 ------------------------------
log "lan-nomtls: mtls_enabled false, local-network host port 443"
before=${FAIL_COUNT}
SEED_NETWORK='{"80/tcp":8080,"443/tcp":8443,"4443/tcp":443}'
boot lan-nomtls "$(options home.example.com false none "")"
SEED_NETWORK='{"80/tcp":8080,"443/tcp":8443}'
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "lan-nomtls: add-on booted"
    check "lan-nomtls: LAN site rendered, no client_auth anywhere, no gateway to refuse (--network none)" eval '
        cexec grep -F "https://home.example.com:4443 {" /etc/caddy/Caddyfile >/dev/null &&
        ! cexec grep -E "client_auth|@docker_gateway|mTLS-CA.crl" /etc/caddy/Caddyfile >/dev/null &&
        logs_contain "LAN port:    https://home.example.com/ -"'
    check "lan-nomtls: caddy validate" caddy_validate
    check "lan-nomtls: every ACME issuer uses the sinkhole" issuers_only_sinkhole
    check "lan-nomtls: port 80 redirects with 301 to https://<domain>/" \
        test "$(cexec curl -s --max-time 5 --resolve home.example.com:80:127.0.0.1 -o /dev/null -w "%{http_code} %{redirect_url}" http://home.example.com/x)" \
        == "301 https://home.example.com/x"
    check "lan-nomtls: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
else
    fail "lan-nomtls: add-on booted"
fi
show_log_on_failure "${before}"
fi

# ==============================================================================
# 3. DNS providers (dummy tokens, public domain, ACME sinkhole)
# ==============================================================================
# caddy_env_has <VAR> <value>: the running Caddy process has VAR=value.
caddy_env_has() {
    cexec sh -c 'pid="$(pidof caddy)" && tr "\0" "\n" < "/proc/${pid}/environ" | grep -Fx -- "$0=$1" >/dev/null' "$1" "$2"
}
# caddy_env_only_allowed: the running Caddy's environment holds only the
# names of CADDY_ENV_NAMES (lib/dns-provider.sh, 2.3.0).
caddy_env_only_allowed() {
    local names
    names="$(cexec sh -c 'pid="$(pidof caddy)" && tr "\0" "\n" < "/proc/${pid}/environ" | cut -d= -f1')" || return 1
    [[ -n "${names}" ]] && ! grep -vxE 'PATH|HOME|TZ|XDG_CONFIG_HOME|XDG_DATA_HOME|DNS_API_TOKEN|DNS_AWS_ACCESS_KEY_ID|DNS_AWS_SECRET_ACCESS_KEY' \
        <<<"${names}" >/dev/null
}
dns_case() { # dns_case <provider> <token> <env-var=value...>
    local provider="$1" token="$2" kv secret_file_path
    shift 2
    log "dns-${provider}: booting (local-network port on: host port 9443)"
    before=${FAIL_COUNT}
    secret_file_path="$(secret_file "secret-dns-${provider}" "${token}")"
    SEED_NETWORK='{"80/tcp":8080,"443/tcp":8443,"4443/tcp":9443}'
    boot "dns-${provider}" "$(options home.example.com true "${provider}" "${token}" homeassistant "")"
    SEED_NETWORK='{"80/tcp":8080,"443/tcp":8443}'
    if ! wait_for "${BOOT_TIMEOUT}" booted; then
        fail "dns-${provider}: add-on booted (Caddy runs with the dns directive)"
        show_log_on_failure "${before}"
        return 0
    fi
    pass "dns-${provider}: add-on booted (Caddy runs with the dns directive)"
    check "dns-${provider}: Caddyfile renders 'dns ${provider}' with {env.*} placeholders" \
        eval "cexec grep -E '^[[:space:]]+dns ${provider} ' /etc/caddy/Caddyfile >/dev/null && cexec grep -F '{env.' /etc/caddy/Caddyfile >/dev/null"
    check "dns-${provider}: token not in the Caddyfile" \
        eval '! "${DOCKER}" exec -i "${CTR}" grep -F -f /dev/stdin /etc/caddy/Caddyfile <"${secret_file_path}" >/dev/null'
    # Explicit validation with the credentials exported exactly as the caddy
    # service does it (lib/dns-provider.sh).
    check "dns-${provider}: caddy validate with the module (pinned version)" \
        "${DOCKER}" exec -i "${CTR}" bash -c 'set -e; source /etc/s6-overlay/scripts/lib/dns-provider.sh
            token="$(cat)"; dns_provider_export "$0" "${token}"
            caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1' \
        "${provider}" <"${secret_file_path}"
    check "dns-${provider}: admin API config uses dns.providers.${provider} (one automation policy for both HTTPS sites)" \
        adapted "[.. | objects | select(.provider?.name? == \"${provider}\")] | length == 1"
    check "dns-${provider}: LAN site rendered with the same dns directive, without client_auth" eval '
        test "$(cexec grep -cE "^[[:space:]]+dns ${provider} " /etc/caddy/Caddyfile)" == 2 &&
        test "$(cexec grep -c "client_auth" /etc/caddy/Caddyfile)" == 1'
    check "dns-${provider}: two HTTPS servers (:443 with client auth, :4443 without), one policy for the domain" adapted '
        ([.apps.http.servers[] | select(.listen == [":443"]) | .tls_connection_policies[] | select(.client_authentication != null)] | length == 1)
        and ([.apps.http.servers[] | select(.listen == [":4443"]) | .tls_connection_policies[]? | select(.client_authentication != null)] | length == 0)
        and ([.apps.http.servers[] | select(.listen == [":4443"])] | length == 1)
        and ([.apps.tls.automation.policies[] | select((.subjects // []) | index("home.example.com"))] | length == 1)'
    check "dns-${provider}: every ACME issuer uses the sinkhole (no Let's Encrypt / ZeroSSL)" issuers_only_sinkhole
    for kv in "$@"; do
        check "dns-${provider}: Caddy's environment has ${kv%%=*}" caddy_env_has "${kv%%=*}" "${kv#*=}"
    done
    check "dns-${provider}: Caddy's environment holds nothing else (PATH, HOME, TZ, XDG_*, DNS_*)" caddy_env_only_allowed
    check "dns-${provider}: token not in the log" logs_lack_secret "${secret_file_path}"
    check "dns-${provider}: upstream_port unset, no Supervisor API -> homeassistant:8123" \
        eval 'logs_contain "Upstream:    homeassistant:8123 (Core'"'"'s port unknown" &&
        cexec grep -F "reverse_proxy homeassistant:8123 {" /etc/caddy/Caddyfile >/dev/null'
    check "dns-${provider}: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
    show_log_on_failure "${before}"
}
if smoke_case dns; then
dns_case cloudflare "${CF_TOKEN}" "DNS_API_TOKEN=${CF_TOKEN}"
dns_case route53 "${R53_KEY_ID}:${R53_SECRET}" \
    "DNS_AWS_ACCESS_KEY_ID=${R53_KEY_ID}" "DNS_AWS_SECRET_ACCESS_KEY=${R53_SECRET}"
dns_case hetzner "${HZ_TOKEN}" "DNS_API_TOKEN=${HZ_TOKEN}"
fi

# ==============================================================================
# 4. refused starts
# ==============================================================================
# bad_case <name> <options-json> <expected log text> [<secret file>]
bad_case() {
    local name="$1" opts="$2" expect="$3" secret="${4:-}"
    log "bad-${name}: booting"
    before=${FAIL_COUNT}
    boot "bad-${name}" "${opts}"
    check "bad-${name}: start refused: ${expect}" wait_for 60 logs_contain "${expect}"
    check "bad-${name}: container stopped" wait_for 30 exited
    if [[ -n "${secret}" ]]; then
        check "bad-${name}: secret not in the log" logs_lack_secret "${secret}"
    fi
    show_log_on_failure "${before}"
}
if smoke_case bad; then
bad_case route53-token "$(options home.example.com true route53 "${R53_SECRET//\//}")" \
    "For route53, dns_api_token must be ACCESS_KEY_ID:SECRET_ACCESS_KEY." \
    "$(secret_file secret-bad-route53 "${R53_SECRET//\//}")"
# A secret the Cloudflare module rejects as malformed (it quotes the token in
# its error): init-caddy must print it redacted.
CF_BAD="cf typo ${RANDOM}${RANDOM} secret"
bad_case cloudflare-token "$(options home.example.com true cloudflare "${CF_BAD}")" \
    "Generated Caddyfile failed validation" "$(secret_file secret-bad-cf "${CF_BAD}")"
check "bad-cloudflare-token: module error printed with <redacted>" \
    logs_contain "API token '<redacted>' appears invalid"
bad_case domain-port "$(options home.example.com:8443 true none "")" \
    "Option 'domain' must be a host name without scheme, port or path"
bad_case upstream-port "$(options home.example.com true none "" 192.0.2.10 "")" \
    "Option 'upstream_port' is required when upstream_host is not 'homeassistant'."
# B-1: never needs mTLS, for every upstream.
OPT_FORWARDED=never
bad_case never-nomtls "$(options home.example.com false none "")" \
    "forwarded_headers: never needs mtls_enabled: true. Without client certificates the add-on never hides visitor addresses"
check "bad-never-nomtls: the message names the alternatives (mTLS on, or auto with Home Assistant's reverse-proxy settings)" eval '
    logs_contain "Turn mTLS on (mtls_enabled: true), or set forwarded_headers to auto" &&
    logs_contain "Settings > System > Network > HTTP server > Reverse proxy"'
bad_case never-nomtls-other "$(options home.example.com false none "" 192.0.2.10 8080)" \
    "forwarded_headers: never needs mtls_enabled: true."
OPT_FORWARDED=auto
fi

# ==============================================================================
# 5. auth: header authentication (2.3.0)
# ==============================================================================
# A key, a wrong value and their variants are made per run and are obviously
# fake. None of them is ever on a command line: the options take the key
# from a file (OPT_HEADER_KEY_FILE), curl reads its headers from files in the
# container (-H @file), the log checks read their patterns from files.
rand_hex() { od -An -N16 -tx1 /dev/urandom | tr -d ' \n'; }
AUTH_KEY="fakekey.NOT-A-SECRET.$(rand_hex)"
AUTH_WRONG="fakewrong.NOT-A-SECRET.$(rand_hex)"
AUTH_KEY_RAW="$(raw_file key-auth "${AUTH_KEY}")"
AUTH_PATTERNS="$(secret_file pattern-auth "${AUTH_KEY}")"
printf '%s\n' "${AUTH_WRONG}" >>"${AUTH_PATTERNS}"
AUTH_NAME="X-Custom-PSK"
CERT_ALICE=(--cert /data/certs/mTLS-client-alice.crt --key /data/certs/mTLS-client-alice.key)
# shellcheck disable=SC2034 # used in eval'd checks
CERT_BOB=(--cert /data/certs/mTLS-client-bob.crt --key /data/certs/mTLS-client-bob.key)
# shellcheck disable=SC2034 # used in eval'd checks
CERT_CAROL=(--cert /data/certs/mTLS-client-carol.crt --key /data/certs/mTLS-client-carol.key)
# hdr_file <name> <header line...>: /tmp/h-<name> in the container (curl -H @file).
hdr_file() {
    local name="$1"
    shift
    printf '%s\n' "$@" | "${DOCKER}" exec -i "${CTR}" sh -c 'cat > "/tmp/h-$0"' "${name}"
}
# auth_headers: the header files of the auth cases (the key, the wrong value
# and their variants, a misspelt name, a websocket upgrade).
auth_headers() {
    local last="${AUTH_KEY: -1}" other=x
    [[ "${last}" == x ]] && other=y
    hdr_file ok "${AUTH_NAME}: ${AUTH_KEY}"
    hdr_file wrong "${AUTH_NAME}: ${AUTH_WRONG}"
    hdr_file lower "$(printf '%s' "${AUTH_NAME}" | tr '[:upper:]' '[:lower:]'): ${AUTH_KEY}"
    hdr_file onechar "${AUTH_NAME}: ${AUTH_KEY%?}${other}"
    hdr_file prefix "${AUTH_NAME}: ${AUTH_KEY%?}"
    hdr_file extra "${AUTH_NAME}: ${AUTH_KEY}x"
    # "Name;" makes curl send the header with an empty value.
    hdr_file empty "${AUTH_NAME};"
    hdr_file star "${AUTH_NAME}: *"
    hdr_file host "${AUTH_NAME}: {host}"
    hdr_file twice-wr "${AUTH_NAME}: ${AUTH_WRONG}" "${AUTH_NAME}: ${AUTH_KEY}"
    hdr_file twice-rw "${AUTH_NAME}: ${AUTH_KEY}" "${AUTH_NAME}: ${AUTH_WRONG}"
    hdr_file trailing "${AUTH_NAME}: ${AUTH_KEY} "
    hdr_file misspelt "X-Custom-PKS: ${AUTH_KEY}"
    hdr_file ws "Connection: Upgrade" "Upgrade: websocket" "Sec-WebSocket-Version: 13" \
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="
    hdr_file app "Authorization: Bearer smoke-ha-token" "Cookie: smoke=cookie-value"
}
# areq <path> [curl args...]: "<code>" of GET https://<domain><path> (port 443);
# 000: the TLS handshake failed. abody: the body.
areq() {
    local path="$1"
    shift
    cexec curl -sk --max-time 10 -o /dev/null -w '%{http_code}' --resolve "${DOMAIN}:443:127.0.0.1" \
        "$@" "https://${DOMAIN}${path}" 2>/dev/null || true
}
abody() {
    local path="$1"
    shift
    cexec curl -sk --max-time 10 --resolve "${DOMAIN}:443:127.0.0.1" "$@" "https://${DOMAIN}${path}" 2>/dev/null || true
}
# ws_code [curl args...]: the status of a websocket upgrade (HTTP/1.1).
ws_code() {
    cexec curl -sk --http1.1 --max-time 4 -o /dev/null -w '%{http_code}' --resolve "${DOMAIN}:443:127.0.0.1" \
        -H @/tmp/h-ws "$@" "https://${DOMAIN}/api/websocket" 2>/dev/null || true
}
# The SHA-256 of a certificate as Caddy reports it.
fp_of() { cexec sh -c 'openssl x509 -in "$0" -outform DER | sha256sum | cut -d" " -f1' "$1" 2>/dev/null; }
fp_listed() { cexec grep -F -- "$1" /etc/caddy/client-fingerprints.caddy >/dev/null 2>&1; }
# upstream_lacks_header <path>: the fake upstream received <path> (the last
# such request; the monitor's control requests come in between) without the
# header.
upstream_lacks_header() {
    fexec cat /tmp/up/requests.jsonl | jq -s -e --arg p "$1" \
        '[.[] | select(.path == $p)] | length > 0 and ((last.header_names | index("x-custom-psk")) == null)' >/dev/null
}
# The add-on's own reload path (caddyctl.reload: regenerate the list, then
# caddy reload --force), as the panel and the monitor call it.
addon_reload() {
    cexec /usr/lib/cert-mgr/.venv/bin/python3 -c 'import sys; sys.path.insert(0, "/usr/lib/cert-mgr")
import caddyctl
ok, message = caddyctl.reload()
print("ok" if ok else "failed: " + message.strip().splitlines()[-1])' 2>&1
}
# secrecy_checks <case>: the key and the wrong value are in no log line, no
# file but the key file (and the options/bashio cache this test wrote), no
# process command line or environment, no panel page or API answer.
secrecy_checks() {
    local c="$1" hits
    check "${c}: secrecy: neither the key nor the wrong value in the container log" logs_lack_secret "${AUTH_PATTERNS}"
    "${DOCKER}" exec -i "${CTR}" sh -c 'cat > /tmp/auth-patterns' <"${AUTH_PATTERNS}"
    # Regular files only (s6 keeps FIFOs in /run: grep would block on them).
    hits="$(cexec sh -c 'find /etc /run /root /data /config /tmp /var -xdev -type f -exec grep -lF -f /tmp/auth-patterns {} + 2>/dev/null' || true)"
    hits="$(printf '%s\n' "${hits}" | grep -vxE '/etc/caddy/header-auth.key|/data/options.json|/tmp/\.bashio/addons\.self\.options\.config\.cache|/tmp/auth-patterns|/tmp/h-[a-z-]+' || true)"
    check "${c}: secrecy: no file holds them but the key file (Caddyfile, snippets, /run/caddy-mtls, autosave.json, state)" \
        eval '[[ -z "${hits}" ]] || { log "files with the key: ${hits//$'"'"'\n'"'"'/ }"; false; }'
    check "${c}: secrecy: autosave.json exists and holds the {file.*} placeholder, not the key" eval '
        cexec grep -F "{file./etc/caddy/header-auth.key}" /root/.config/caddy/autosave.json >/dev/null &&
        ! cexec cat /root/.config/caddy/autosave.json | grep -F -f "${AUTH_PATTERNS}" >/dev/null'
    check "${c}: secrecy: no process command line or environment holds them" eval '
        ! cexec sh -c '"'"'for p in /proc/[0-9]*; do tr "\0" " " < "$p/cmdline"; echo; tr "\0" "\n" < "$p/environ"; done 2>/dev/null'"'"' |
            grep -F -f "${AUTH_PATTERNS}" >/dev/null'
    check "${c}: secrecy: no panel page or API answer holds them" eval '
        ! { for path in / /upstream /public-cert /api/state /api/upstream /api/public-cert; do dashboard "${path}"; done; } |
            grep -F -f "${AUTH_PATTERNS}" >/dev/null'
    check "${c}: secrecy: the key file is 0600 root" test "$(cexec stat -c '%a %U' /etc/caddy/header-auth.key)" == "600 root"
}
# auth_traffic <case>: the requests the secrecy checks follow - accepted,
# wrong value, the key under a misspelt name, a websocket upgrade, a 502
# (upstream down), a reload.
auth_traffic() {
    local c="$1"
    check "${c}: traffic: the key 200, a wrong value 403, the key under a misspelt name 403, websocket 101" eval '
        test "$(areq /t1 -H @/tmp/h-ok)" == 200 && test "$(areq /t2 -H @/tmp/h-wrong)" == 403 &&
        test "$(areq /t3 -H @/tmp/h-misspelt)" == 403 && test "$(ws_code -H @/tmp/h-ok)" == 101'
    fexec touch /tmp/up/down
    fake_restart || true
    check "${c}: traffic: upstream down -> 502 with the key (the error line of a 5xx carries the request)" \
        wait_for 15 eval 'test "$(areq /t4 -H @/tmp/h-ok)" == 502'
    areq /t5 --http1.1 -H @/tmp/h-ok >/dev/null
    areq /t6 -H @/tmp/h-misspelt -H @/tmp/h-wrong >/dev/null
    fexec rm -f /tmp/up/down
    wait_for 15 fake_up_ok || true
    check "${c}: traffic: a reload through the add-on's path (client added in the panel)" \
        test "$(panel_post /api/clients name=reload-check)" == "303 http://127.0.0.1:8099${INGRESS_PREFIX}/?ok=Client+%27reload-check%27+created."
}

if smoke_case auth; then
# --- mTLS + key: the gate, revocation, the forwarding switch, secrecy -------
log "auth: booting (mTLS, header key, access log, local-network port, a fake Home Assistant that trusts the proxy)"
before=${FAIL_COUNT}
OPT_HEADER_KEY_FILE="${AUTH_KEY_RAW}"
OPT_ACCESS_LOG=true
SEED_NETWORK='{"80/tcp":8080,"443/tcp":8443,"4443/tcp":9443}'
boot_fwd auth "$(options "${DOMAIN}" true none "" homeassistant 8124)" trust
SEED_NETWORK='{"80/tcp":8080,"443/tcp":8443}'
OPT_ACCESS_LOG=false
OPT_HEADER_KEY_FILE=""
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "auth: add-on booted"
    auth_headers
    check "auth: Caddyfile: certificate optional in the handshake (verify_if_given) with the trust pool and the leaf verifier" eval '
        cexec grep -F "mode verify_if_given" /etc/caddy/Caddyfile >/dev/null && ! cexec grep -F require_and_verify /etc/caddy/Caddyfile >/dev/null &&
        adapted "[.. | objects | select(.mode? == \"verify_if_given\")] | length == 1" &&
        adapted "[.. | objects | select(.verifier? == \"leaf\")] | length == 1"'
    check "auth: Caddyfile: the gate imports the list and reads the key from its file (the key is not in the Caddyfile)" eval '
        cexec grep -F "@caddy_mtls_gate_denied {" /etc/caddy/Caddyfile >/dev/null &&
        cexec grep -F "import /etc/caddy/client-fingerprints.caddy" /etc/caddy/Caddyfile >/dev/null &&
        cexec grep -F "header X-Custom-PSK {file./etc/caddy/header-auth.key}" /etc/caddy/Caddyfile >/dev/null &&
        cexec grep -F "not vars {file./etc/caddy/header-auth.key} \"\"" /etc/caddy/Caddyfile >/dev/null &&
        ! cexec cat /etc/caddy/Caddyfile | grep -F -f "${AUTH_PATTERNS}" >/dev/null'
    check "auth: Caddyfile: every log that can carry a request drops all request headers (default + 3 sites)" \
        test "$(cexec grep -c "request>headers delete" /etc/caddy/Caddyfile)" == 4
    check "auth: Caddyfile: the header removed after the gate on the public and the local-network site (request_header and header_up)" eval '
        test "$(cexec grep -c "request_header -X-Custom-PSK" /etc/caddy/Caddyfile)" == 2 &&
        test "$(cexec grep -c "header_up -X-Custom-PSK" /etc/caddy/Caddyfile)" == 2'
    # The order inside the public site's route: diagnosis (log_append), the
    # gate (static_response with the gate matcher), the header's removal,
    # the proxy last.
    # shellcheck disable=SC2016
    check "auth: admin API: the public route = log_append..., 403 gate, header removal, reverse_proxy (last)" adapted '
        [.apps.http.servers[] | select(.listen == [":443"]) | .. | objects | select(has("routes")) | .routes
         | select(any(.[]; .handle[0].handler? == "static_response" and ((.handle[0].status_code? // "") | tostring) == "403"))]
        | length == 1 and (.[0] | [.[] | .handle[] | .handler] | . as $h | (map(. == "static_response") | index(true)) as $g
            | $h[-1] == "reverse_proxy" and $h[$g + 1] == "headers" and ($h[:$g] | length > 0 and all(. == "log_append")))'
    check "auth: strict SNI-Host enforcement still on for :443" \
        logs_contain "enabling strict SNI-Host enforcement because TLS client auth is configured"
    check "auth: start log: on, the header name, the key length, the notice" eval '
        logs_contain "Header auth: on - header X-Custom-PSK, a key of ${#AUTH_KEY} characters; or one of 2 active client certificates" &&
        logs_contain "Header authentication is on: a request that carries the header X-Custom-PSK with the key is accepted without a client certificate. Whoever knows the key gets as far as Home Assistant"'
    check "auth: runtime.json: on, name, key length (no key)" \
        test "$(cexec jq -c .header_auth /run/caddy-mtls/runtime.json)" == "{\"enabled\":true,\"name\":\"X-Custom-PSK\",\"key_length\":${#AUTH_KEY}}"
    for v in http1.1 http2; do
        h="${v/http1.1/h1}"
        h="${h/http2/h2}"
        check "auth: ${h}: no certificate, no header -> the handshake completes, 403 with a text that does not name the header" eval '
            [[ "$(abody /m --"${v}" -w " %{http_code} %{http_version}")" == "403 Forbidden: this site needs a client certificate. 403 "* ]]'
        check "auth: ${h}: a wrong value -> 403" test "$(areq /m --"${v}" -H @/tmp/h-wrong)" == 403
        # shellcheck disable=SC2034 # used in eval'd checks
        echo_ok="$(abody /right-key --"${v}" -H @/tmp/h-ok -H @/tmp/h-app)"
        check "auth: ${h}: the right key -> 200 at the upstream, which did not get the header" eval '
            test "$(jq -r .path <<<"${echo_ok}" 2>/dev/null)" == /right-key && test -z "$(echo_header "${echo_ok}" X-Custom-PSK)" &&
            upstream_lacks_header /right-key'
        check "auth: ${h}: ... Authorization and Cookie arrive unchanged" eval '
            test "$(echo_header "${echo_ok}" Authorization)" == "Bearer smoke-ha-token" &&
            test "$(echo_header "${echo_ok}" Cookie)" == "smoke=cookie-value"'
        check "auth: ${h}: a client certificate without the header -> 200" test "$(areq /m --"${v}" "${CERT_ALICE[@]}")" == 200
        check "auth: ${h}: a client certificate with a wrong value -> 200" test "$(areq /m --"${v}" "${CERT_ALICE[@]}" -H @/tmp/h-wrong)" == 200
        check "auth: ${h}: the header name in lower case -> 200" test "$(areq /m --"${v}" -H @/tmp/h-lower)" == 200
        for variant in onechar prefix extra empty star host; do
            check "auth: ${h}: header value '${variant}' (one character changed / a prefix / one more character / empty / * / {host}) -> 403" \
                test "$(areq /m --"${v}" -H "@/tmp/h-${variant}")" == 403
        done
        # REPORT-I I-4: the header matcher accepts ANY of several values.
        check "auth: ${h}: the header twice, wrong then right -> 200 (any value matches; documented)" \
            test "$(areq /m --"${v}" -H @/tmp/h-twice-wr)" == 200
        check "auth: ${h}: the header twice, right then wrong -> 200 (documented)" \
            test "$(areq /m --"${v}" -H @/tmp/h-twice-rw)" == 200
    done
    # REPORT-I I-4: HTTP/1.1 drops trailing blanks of a header value (Go's
    # parser), HTTP/2 keeps them - curl sends the blank in both.
    check "auth: h1: the key with a trailing blank -> 200 (Go trims it on HTTP/1.1; documented)" \
        test "$(areq /m --http1.1 -H @/tmp/h-trailing)" == 200
    check "auth: h2: the key with a trailing blank -> 403 (HTTP/2 keeps it; documented)" \
        test "$(areq /m --http2 -H @/tmp/h-trailing)" == 403
    check "auth: websocket upgrade with the key -> 101, the upstream got it without the header" eval '
        test "$(ws_code -H @/tmp/h-ok)" == 101 && upstream_lacks_header /api/websocket &&
        fexec cat /tmp/up/requests.jsonl | jq -s -e "[.[] | select(.path == \"/api/websocket\")] | last.header_names | index(\"upgrade\") != null" >/dev/null'
    check "auth: websocket upgrade with a wrong value -> 403, without a header -> 403" eval '
        test "$(ws_code -H @/tmp/h-wrong)" == 403 && test "$(ws_code)" == 403'
    sleep 1
    check "auth: access log: no request headers, the field auth says how each request was let in or why not" eval '
        logs_contain "\"auth\": \"header key\"" && logs_contain "\"auth\": \"certificate\"" &&
        logs_contain "\"auth\": \"refused: no certificate, header absent\"" &&
        logs_contain "\"auth\": \"refused: no certificate, header present with a wrong value\"" &&
        ! "${DOCKER}" logs "${CTR}" 2>&1 | grep -F "handled request" | grep -F "\"headers\": {" >/dev/null &&
        ! "${DOCKER}" logs "${CTR}" 2>&1 | grep -F "handled request" | grep -iF "x-custom-psk" >/dev/null'
    # Fail closed: the key file emptied or removed in the running container.
    cexec sh -c ': > /etc/caddy/header-auth.key'
    check "auth: key file emptied -> an EMPTY header 403, the key 403, a certificate still 200" eval '
        test "$(areq /e -H @/tmp/h-empty)" == 403 && test "$(areq /e -H @/tmp/h-ok)" == 403 &&
        test "$(areq /e "${CERT_ALICE[@]}")" == 200'
    cexec rm -f /etc/caddy/header-auth.key
    check "auth: key file removed -> an EMPTY header 403, no header 403, a certificate still 200" eval '
        test "$(areq /e -H @/tmp/h-empty)" == 403 && test "$(areq /e)" == 403 &&
        test "$(areq /e "${CERT_ALICE[@]}")" == 200'
    "${DOCKER}" exec -i "${CTR}" sh -c 'umask 077; cat > /etc/caddy/header-auth.key' <"${AUTH_KEY_RAW}"
    check "auth: key file back -> the key 200 again (read per request, no reload)" test "$(areq /e -H @/tmp/h-ok)" == 200
    # The local-network site: no gate, but the header goes no further.
    # shellcheck disable=SC2034 # used in eval'd checks
    lan_echo="$(cexec curl -sk --max-time 10 --resolve "${DOMAIN}:4443:127.0.0.1" -H @/tmp/h-ok "https://${DOMAIN}:4443/lan-auth" 2>/dev/null)"
    check "auth: local-network site: a request with the header reaches the upstream without it" eval '
        test "$(jq -r .path <<<"${lan_echo}" 2>/dev/null)" == /lan-auth && test -z "$(echo_header "${lan_echo}" X-Custom-PSK)" &&
        upstream_lacks_header /lan-auth'
    check "auth: dashboard card on: the name and the key length, never the key" eval '
        html="$(dashboard /)" && [[ "${html}" == *"id=\"header-auth\""*"data-state=\"on\""* &&
        "${html}" == *"Header <code>X-Custom-PSK</code>; a key of ${#AUTH_KEY}"* && "${html}" == *"long-lived access token"* ]] &&
        ! dashboard / | grep -F -f "${AUTH_PATTERNS}" >/dev/null'

    # --- revocation: the leaf verifier in the handshake, the list in the gate --
    # shellcheck disable=SC2034 # used in eval'd checks
    alice_fp="$(fp_of /data/certs/mTLS-client-alice.crt)"
    # shellcheck disable=SC2034 # used in eval'd checks
    bob_fp="$(fp_of /data/certs/mTLS-client-bob.crt)"
    check "auth: the list = the SHA-256 of the active certificates (alice, bob), lower-case hex" eval '
        [[ "${alice_fp}" =~ ^[0-9a-f]{64}$ && "${bob_fp}" =~ ^[0-9a-f]{64}$ ]] && fp_listed "${alice_fp}" && fp_listed "${bob_fp}" &&
        ! cexec grep -F e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /etc/caddy/client-fingerprints.caddy >/dev/null'
    check "auth: alice and bob accepted (200)" eval '
        test "$(areq /r "${CERT_ALICE[@]}")" == 200 && test "$(areq /r "${CERT_BOB[@]}")" == 200'
    check "auth: POST revoke alice -> 303" \
        test "$(panel_post /api/clients/alice/revoke reason=keyCompromise)" == "303 http://127.0.0.1:8099${INGRESS_PREFIX}/?ok=Client+%27alice%27+revoked."
    check "auth: revoked alice -> the handshake fails (000)" test "$(areq /r "${CERT_ALICE[@]}")" == 000
    check "auth: revoked alice WITH the right key -> the handshake fails too (no fallback for a refused certificate)" \
        test "$(areq /r "${CERT_ALICE[@]}" -H @/tmp/h-ok)" == 000
    # shellcheck disable=SC2034 # used in an eval'd check
    alert="$(cexec sh -c 'printf "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" "$0" |
        openssl s_client -connect 127.0.0.1:443 -servername "$0" -cert /data/certs/mTLS-client-alice.crt \
            -key /data/certs/mTLS-client-alice.key -ign_eof 2>&1 | grep -E "alert|HTTP/1.1 [0-9]+" || true' "${DOMAIN}")"
    check "auth: revoked alice: a TLS alert (bad certificate), no HTTP answer" eval '[[ "${alert}" == *"alert bad certificate"* && "${alert}" != *"HTTP/1.1"* ]]'
    check "auth: no certificate + the right key -> 200 after the revocation; bob still 200" eval '
        test "$(areq /r -H @/tmp/h-ok)" == 200 && test "$(areq /r "${CERT_BOB[@]}")" == 200'
    cexec sh -c 'openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=alice -days 2 \
        -keyout /tmp/foreign.key -out /tmp/foreign.crt' >/dev/null 2>&1
    check "auth: a certificate of a foreign CA -> the handshake fails, with and without the key" eval '
        test "$(areq /r --cert /tmp/foreign.crt --key /tmp/foreign.key)" == 000 &&
        test "$(areq /r --cert /tmp/foreign.crt --key /tmp/foreign.key -H @/tmp/h-ok)" == 000'
    check "auth: alice's fingerprint left the list, bob's stayed" eval '! fp_listed "${alice_fp}" && fp_listed "${bob_fp}"'
    # shellcheck disable=SC2034 # used in an eval'd check
    list_before="$(cexec cat /etc/caddy/client-fingerprints.caddy)"
    check "auth: POST add carol -> 303" \
        test "$(panel_post /api/clients name=carol)" == "303 http://127.0.0.1:8099${INGRESS_PREFIX}/?ok=Client+%27carol%27+created."
    carol_fp="$(fp_of /data/certs/mTLS-client-carol.crt)"
    check "auth: carol accepted at once (the list was regenerated before the reload: its content changed, carol in it)" eval '
        [[ "$(cexec cat /etc/caddy/client-fingerprints.caddy)" != "${list_before}" ]] && fp_listed "${carol_fp}" &&
        test "$(areq /c "${CERT_CAROL[@]}")" == 200'
    # Drift: a list that lacks an active client refuses it at the gate,
    # although the handshake accepts it (both checks must agree).
    cexec sh -c 'printf "not vars {http.request.tls.client.fingerprint} %s\n" "$0" > /etc/caddy/client-fingerprints.caddy &&
        caddy reload --force --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1' "${carol_fp}"
    check "auth: drift: a list without bob -> bob's handshake succeeds, the gate answers 403; carol 200" eval '
        test "$(areq /d "${CERT_BOB[@]}")" == 403 && test "$(areq /d "${CERT_CAROL[@]}")" == 200'
    check "auth: drift: the add-on's reload regenerates the list from the folder -> bob 200 again" eval '
        test "$(addon_reload)" == ok && fp_listed "${bob_fp}" && test "$(areq /d "${CERT_BOB[@]}")" == 200'
    # The generator: only real certificate fingerprints (a copy of the folder).
    # shellcheck disable=SC2034 # used in an eval'd check
    gen_out="$(cexec sh -c 'rm -rf /tmp/fp-test && cp -r /data/certs/active /tmp/fp-test && : > /tmp/fp-test/empty.pem &&
        head -c 300 /data/certs/mTLS-client-bob.crt > /tmp/fp-test/truncated.pem &&
        cp /data/certs/mTLS-client-bob.key /tmp/fp-test/key.pem &&
        /usr/lib/cert-mgr/.venv/bin/python3 /usr/lib/cert-mgr/caddyctl.py fingerprints --folder /tmp/fp-test --output /tmp/fp-test.caddy 2>&1' || true)"
    check "auth: generator: an empty, a truncated and a non-certificate .pem give no entry (a warning each), never the empty-input hash" eval '
        [[ "${gen_out}" == *"empty.pem: left out"* && "${gen_out}" == *"truncated.pem: left out"* && "${gen_out}" == *"key.pem: left out"* ]] &&
        test "$(cexec sh -c "tail -n 1 /tmp/fp-test.caddy | wc -w")" == 5 &&
        ! cexec grep -F e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /tmp/fp-test.caddy >/dev/null'
    # Caddy's own leaf loader refuses a folder with such a file: the reload
    # fails and the running configuration stays (bob still in).
    cexec sh -c ': > /data/certs/active/broken.pem'
    # shellcheck disable=SC2034 # used in an eval'd check
    reload_out="$(addon_reload)"
    check "auth: an empty .pem in the live folder: Caddy refuses the reload (reported), the running configuration stays" eval '
        [[ "${reload_out}" == "failed: "*"broken.pem"* ]] && test "$(areq /b "${CERT_BOB[@]}")" == 200 && test "$(areq /b)" == 403'
    cexec rm -f /data/certs/active/broken.pem
    # Forwarding switch (2.2.0) in the key mode: rewrite + reload, the list
    # regenerated before that reload, the gate unchanged.
    # shellcheck disable=SC2034 # used in an eval'd check
    inode_before="$(cexec stat -c %i /etc/caddy/client-fingerprints.caddy)"
    fake_trust off
    fake_restart
    check "auth: forwarding switch pass -> strip (snippet rewritten, Caddy reloaded) in the key mode" \
        wait_for 20 eval 'snippet_is strip && [[ "$(cexec jq -r "\"\(.mode) \(.applied)\"" /data/upstream.json)" == "strip true" ]]'
    check "auth: ... the list was rewritten before that reload (a new file)" \
        eval '[[ "$(cexec stat -c %i /etc/caddy/client-fingerprints.caddy)" != "${inode_before}" ]]'
    echo_strip="$(abody /after-switch -H @/tmp/h-ok)"
    check "auth: after the switch: no certificate/no key 403; the key 200 without forwarding headers or the header" eval '
        test "$(areq /s)" == 403 && test "$(jq -r .path <<<"${echo_strip}" 2>/dev/null)" == /after-switch &&
        no_forwarding_headers "${echo_strip}" && test -z "$(echo_header "${echo_strip}" X-Custom-PSK)"'
    fake_trust on
    fake_restart
    wait_for 20 eval 'snippet_is pass' || true
    # No active client: the sentinel; the key still works.
    panel_post /api/clients/bob/revoke reason=superseded >/dev/null
    panel_post /api/clients/carol/revoke reason=superseded >/dev/null
    check "auth: no active client -> the sentinel; no certificate/no key 403, the key 200, bob refused in the handshake" eval '
        cexec grep -Fx "not vars {http.request.tls.client.fingerprint} no-active-client" /etc/caddy/client-fingerprints.caddy >/dev/null &&
        test "$(areq /n)" == 403 && test "$(areq /n -H @/tmp/h-ok)" == 200 && test "$(areq /n "${CERT_BOB[@]}")" == 000'
    auth_traffic auth
    secrecy_checks auth
    check "auth: no Traceback, no failed validation" eval 'logs_lack "Traceback" && logs_lack "failed validation"'
    check "auth: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
else
    fail "auth: add-on booted"
fi
show_log_on_failure "${before}"

# --- secrecy at log_level debug and trace (Caddy's config dump, bashio) -----
for level in debug trace; do
    log "auth-${level}: booting (mTLS, header key, log_level ${level})"
    before=${FAIL_COUNT}
    OPT_HEADER_KEY_FILE="${AUTH_KEY_RAW}"
    OPT_LOG_LEVEL="${level}"
    boot_fwd "auth-${level}" "$(options "${DOMAIN}" true none "" homeassistant 8124)" trust
    OPT_LOG_LEVEL=info
    OPT_HEADER_KEY_FILE=""
    if wait_for "${BOOT_TIMEOUT}" booted; then
        pass "auth-${level}: add-on booted"
        auth_headers
        auth_traffic "auth-${level}"
        check "auth-${level}: positive control: Caddy's debug config dump is in the log, with the {file.*} placeholder" eval '
            logs_contain "adjusted config" && logs_contain "{file./etc/caddy/header-auth.key}"'
        if [[ "${level}" == trace ]]; then
            check "auth-trace: bashio's trace output is off (it would print the options with every secret)" eval '
                logs_lack "bashio::jq" && logs_lack "bashio::config" && logs_lack "client_cert_password"'
        fi
        secrecy_checks "auth-${level}"
        check "auth-${level}: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
    else
        fail "auth-${level}: add-on booted"
    fi
    show_log_on_failure "${before}"
done

# --- mTLS off + key: the key is the only gate; no certificate is requested --
log "auth-nomtls: booting (mtls_enabled false, header key)"
before=${FAIL_COUNT}
OPT_HEADER_KEY_FILE="${AUTH_KEY_RAW}"
boot_fwd auth-nomtls "$(options "${DOMAIN}" false none "" homeassistant 8124)" trust
OPT_HEADER_KEY_FILE=""
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "auth-nomtls: add-on booted"
    auth_headers
    check "auth-nomtls: no client_auth, the gate without a certificate branch" eval '
        ! cexec grep -E "client_auth|client-fingerprints|caddy_mtls_diag" /etc/caddy/Caddyfile >/dev/null &&
        cexec grep -F "@caddy_mtls_gate_denied {" /etc/caddy/Caddyfile >/dev/null &&
        adapted "[.. | objects | select(has(\"client_authentication\"))] | length == 0"'
    check "auth-nomtls: no header -> 403 \"403 Forbidden\"; a wrong value 403" eval '
        [[ "$(abody /x -w " %{http_code}")" == "403 Forbidden 403" ]] && test "$(areq /x -H @/tmp/h-wrong)" == 403'
    # shellcheck disable=SC2034 # used in eval'd checks
    echo_nomtls="$(abody /nomtls-key -H @/tmp/h-ok)"
    check "auth-nomtls: the key -> 200 at the upstream, without the header" eval '
        test "$(jq -r .path <<<"${echo_nomtls}" 2>/dev/null)" == /nomtls-key && test -z "$(echo_header "${echo_nomtls}" X-Custom-PSK)"'
    # shellcheck disable=SC2034 # used in an eval'd check
    hello="$(cexec sh -c 'openssl s_client -connect 127.0.0.1:443 -servername "$0" </dev/null 2>&1' "${DOMAIN}" || true)"
    check "auth-nomtls: the server requests no client certificate" eval '[[ "${hello}" == *"No client certificate CA names sent"* ]]'
    check "auth-nomtls: the notice says the key is the only protection; the card warns" eval '
        logs_contain "Header auth: on - header X-Custom-PSK, a key of ${#AUTH_KEY} characters (mTLS off)" &&
        logs_contain "Header authentication is on without mTLS" &&
        [[ "$(dashboard /)" == *"<strong>mTLS is off:</strong> the key is the only protection"* ]]'
    check "auth-nomtls: forwarding headers passed on (mTLS off: never hidden, as in 2.2.0)" eval '
        test -n "$(echo_header "${echo_nomtls}" X-Forwarded-For)"'
    check "auth-nomtls: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
else
    fail "auth-nomtls: add-on booted"
fi
show_log_on_failure "${before}"

# --- refused starts: no message contains the key or a part of it ------------
# bad_auth <name> <key value> <expected text> [<header name>]
bad_auth() {
    local pattern value="${2%$'\n'}"
    # The value without a trailing line break, and a part of it (an empty
    # pattern line would match every line).
    pattern="$(secret_file "pattern-bad-auth-$1" "${value}")"
    printf '%s\n' "${value:4:16}" >>"${pattern}"
    OPT_HEADER_KEY_FILE="$(raw_file "key-bad-auth-$1" "$2")"
    OPT_HEADER_NAME="${4:-}"
    bad_case "auth-$1" "$(options "${DOMAIN}" true none "")" "$3" "${pattern}"
    OPT_HEADER_KEY_FILE=""
    OPT_HEADER_NAME=""
}
bad_auth short "${AUTH_KEY:0:31}" "header_auth_key has 31 characters; it needs 32 to 256"
check "bad-auth-short: the refusal says how to make a key" logs_contain "openssl rand -base64 32"
bad_auth blank "${AUTH_KEY:0:20} ${AUTH_KEY:20}" "header_auth_key contains a character that is not allowed"
bad_auth star "${AUTH_KEY}*" "header_auth_key contains a character that is not allowed"
bad_auth linebreak "${AUTH_KEY}"$'\n' "header_auth_key contains a character that is not allowed"
bad_auth name "${AUTH_KEY}" 'header_auth_name (8 characters) is not a header name for this add-on' X_Custom
bad_auth reserved "${AUTH_KEY}" 'header_auth_name is a header that browsers, Home Assistant or the proxy itself use' x-forwarded-for
# B-9: a key pasted into header_auth_name is not printed (only its length).
NAME_MARKER="fakename.NOT-A-SECRET.$(rand_hex)"
bad_case auth-key-as-name "$(OPT_HEADER_KEY_FILE="${AUTH_KEY_RAW}" OPT_HEADER_NAME="${NAME_MARKER}" options "${DOMAIN}" true none "")" \
    "header_auth_name (${#NAME_MARKER} characters) is not a header name for this add-on" \
    "$(secret_file pattern-name-marker "${NAME_MARKER}")"
fi

# ==============================================================================
# 6. custom: Caddyfile snippets for experts (2.3.0)
# ==============================================================================
# The files go into /config/caddy (the addon_config mapping) before the
# start (BOOT_CONFIG_HOOK). SMOKE_FIXTURES_DIR (optional): the configurations
# Caddy built for the integrity check are copied there (the unit tests'
# fixtures: tests/unit/fixtures/customconf/).
CUSTOM_CASE=""
# custom_files: write the files of CUSTOM_CASE into the given /config dir.
custom_files() {
    local dir="$1/caddy"
    mkdir -p "${dir}"
    case "${CUSTOM_CASE}" in
        ok|ok-strict)
            printf '%s\n' '# Harmless global options (smoke test).' 'servers {' '	protocols h1 h2' '}' >"${dir}/global.caddy"
            cat >"${dir}/site.caddy" <<'EOF'
# Harmless custom directives (smoke test); they all run after the gate.
header X-Custom-Site "yes"
request_header X-Custom-Req "from-snippet"
@hello path /custom/hello
respond @hello "hello from site.caddy" 200
redir /custom/old /custom/hello 302
rewrite /custom/rw /custom/strip/rw
handle_path /custom/strip/* {
	respond "stripped {path}" 200
}
handle_path /custom/files/* {
	root * /usr/lib/cert-mgr/static
	file_server
}
handle /custom/proxy/* {
	reverse_proxy 127.0.0.1:8124
}
route /custom/route/* {
	header X-Custom-Route "1"
	respond "route" 200
}
encode gzip
EOF
            # Written on Windows: CRLF line endings, and a byte-order mark.
            printf 'respond /lan-custom "lan custom" 200\r\n' >"${dir}/lan.caddy"
            printf '\xef\xbb\xbfother.caddy-mtls-smoke.localhost {\n\timport mtls\n\trespond "other site" 200\n}\n' >"${dir}/sites.caddy"
            ;;
        broken)
            printf '%s\n' 'servers {' '	protocols h1 h2' '}' >"${dir}/global.caddy"
            printf '%s\n' 'respond /custom/hello "hello" 200' 'import no_such_snippet' >"${dir}/site.caddy"
            printf '%s\n' 'respond /lan-custom "lan custom" 200' >"${dir}/lan.caddy"
            ;;
        directive) printf '%s\n' 'tls internal' >"${dir}/site.caddy" ;;
        imports) printf '%s\n' 'import /etc/caddy/Caddyfile' >"${dir}/site.caddy" ;;
        breakout-site) printf '}\nhandle /bypass/* {\n\trespond "BYPASS"\n}\nroute {\n' >"${dir}/site.caddy" ;;
        breakout-lan) printf '}\nhandle /bypass/* {\n\trespond "BYPASS"\n}\nroute {\n' >"${dir}/lan.caddy" ;;
        pathsite) printf '%s {\n\trespond "BYPASS"\n}\n' "${DOMAIN}/bypass/*" >"${dir}/sites.caddy" ;;
        merged-scheme) printf 'https://%s:443 {\n\trespond /bypass "BYPASS" 200\n}\n' "${DOMAIN}" >"${dir}/sites.caddy" ;;
        merged-port) printf '%s:443 {\n\trespond /bypass "BYPASS" 200\n}\n' "${DOMAIN}" >"${dir}/sites.caddy" ;;
        strict-sni) printf '%s\n' 'servers {' '	strict_sni_host insecure_off' '}' >"${dir}/global.caddy" ;;
        admin-off) printf '%s\n' 'admin off' >"${dir}/global.caddy" ;;
        admin-other) printf '%s\n' 'admin localhost:2020' >"${dir}/global.caddy" ;;
        storage) printf '%s\n' 'storage file_system {' '	root /tmp/elsewhere' '}' >"${dir}/global.caddy" ;;
        matcher) printf '%s\n' '@caddy_mtls_gate_denied path /nothing' 'respond /x "x" 200' >"${dir}/site.caddy" ;;
        double-close)
            printf '}\n}\nevil.caddy-mtls-smoke.localhost {\n\trespond "EVIL"\n}\n%s:8444 {\nroute {\n' "${DOMAIN}" >"${dir}/site.caddy" ;;
        mtls-off) printf 'other.caddy-mtls-smoke.localhost {\n\timport mtls\n\trespond "other site" 200\n}\n' >"${dir}/sites.caddy" ;;
        # B-1: other listeners (the reviewer's c43, c42, c14).
        port-admin) printf 'http://other.caddy-mtls-smoke.localhost:2019 {\n\trespond "x"\n}\n' >"${dir}/sites.caddy" ;;
        port-panel) printf 'http://other.caddy-mtls-smoke.localhost:8099 {\n\trespond "x"\n}\n' >"${dir}/sites.caddy" ;;
        bind) printf 'other.caddy-mtls-smoke.localhost {\n\tbind 127.0.0.1\n\trespond "other site"\n}\n' >"${dir}/sites.caddy" ;;
        # B-4: a certificate that covers the domain (c07); B-2: one that does
        # not, read again at every reload (c37).
        wildcert)
            gen_cert "${dir}" w '*.localhost'
            printf 'other.caddy-mtls-smoke.localhost {\n\ttls /config/caddy/w.crt /config/caddy/w.key\n\trespond "other"\n}\n' >"${dir}/sites.caddy"
            ;;
        livecert|norename)
            gen_cert "${dir}" o other.caddy-mtls-smoke.localhost
            printf 'other.caddy-mtls-smoke.localhost {\n\ttls /config/caddy/o.crt /config/caddy/o.key\n\trespond "other" 200\n}\n' >"${dir}/sites.caddy"
            ;;
        # B2-2: a snippet refers to named pipes (the reviewer's FIFO case):
        # Caddy's check would wait for ever.
        fifocert)
            mkfifo "${dir}/f.crt" "${dir}/f.key"
            printf 'other.caddy-mtls-smoke.localhost {\n\ttls /config/caddy/f.crt /config/caddy/f.key\n\trespond "other"\n}\n' >"${dir}/sites.caddy"
            ;;
        # B-6: refused with the real cause; a log that includes the access logs.
        keytype) printf '%s\n' 'key_type rsa2048' >"${dir}/global.caddy" ;;
        defsni) printf '%s\n' 'default_sni other.caddy-mtls-smoke.localhost' >"${dir}/global.caddy" ;;
        wild) printf '*.localhost {\n\trespond "wild"\n}\n' >"${dir}/sites.caddy" ;;
        logok)
            printf '%s\n' 'log mine {' '	output stdout' '	format filter {' '		wrap json' '		request>headers delete' '	}' \
                '	include http.log.access' '}' >"${dir}/global.caddy"
            ;;
        # B-5: lan.caddy while the local-network port is off.
        lanoff)
            printf '%s\n' 'respond /custom/hello "hello" 200' >"${dir}/site.caddy"
            printf '%s\n' 'this is { broken' >"${dir}/lan.caddy"
            ;;
        # B-8: the environment a snippet's {$VAR} sees.
        env)
            # shellcheck disable=SC2016 # Caddyfile placeholders
            printf '%s\n' 'header X-Env "[{$CADDY_ADMIN}]"' 'header X-Token "[{$SUPERVISOR_TOKEN}]"' 'header X-Tz "[{$TZ}]"' \
                >"${dir}/site.caddy"
            ;;
        ignored)
            printf '%s\n' 'respond /x "x" 200' >"${dir}/elsewhere.txt"
            ln -s elsewhere.txt "${dir}/site.caddy"
            head -c 300000 /dev/zero | tr '\0' '#' >"${dir}/lan.caddy"
            mkfifo "${dir}/global.caddy"
            printf '\n\t  \n' >"${dir}/sites.caddy"
            ;;
    esac
}
# gen_cert <dir> <name> <DNS name>: a throwaway self-signed certificate and
# key (<name>.crt, <name>.key) for a snippet's site.
gen_cert() {
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=$2 smoke (fake)" \
        -addext "subjectAltName=DNS:$3" -keyout "$1/$2.key" -out "$1/$2.crt" >/dev/null 2>&1
}
custom_state() { cexec jq -r "$1" /run/caddy-mtls/custom.json 2>/dev/null; }
# other_site [curl args]: "<body> <code>" of https://other.caddy-mtls-smoke.localhost/ (" 000": handshake failed).
other_site() {
    cexec curl -sk --max-time 10 -o - -w ' %{http_code}' --resolve "other.caddy-mtls-smoke.localhost:443:127.0.0.1" \
        "$@" https://other.caddy-mtls-smoke.localhost/ 2>/dev/null || true
}
# pids_with <command line prefix>: a process in the container runs it.
pids_with() {
    cexec sh -c 'for p in /proc/[0-9]*; do tr "\0" " " < "$p/cmdline" 2>/dev/null; echo; done' | grep -F -- "$1" >/dev/null
}
# flash_ok <text>: the panel's redirect after a change that worked.
flash_ok() { printf '303 http://127.0.0.1:8099%s/?ok=%s' "${INGRESS_PREFIX}" "$1"; }
# creq <path> [curl args]: "<code>" on the public site (443).
creq() { areq "$@"; }
# custom_boot <case> <mtls> [fwd]: boot with the case's files (key mode).
custom_boot() {
    CUSTOM_CASE="$1"
    BOOT_CONFIG_HOOK=custom_files
    OPT_HEADER_KEY_FILE="${AUTH_KEY_RAW}"
    if [[ "${3:-}" == fwd ]]; then
        boot_fwd "custom-$1" "$(options "${DOMAIN}" "$2" none "" homeassistant 8124)" trust
    else
        boot "custom-$1" "$(options "${DOMAIN}" "$2" none "")"
    fi
    OPT_HEADER_KEY_FILE=""
    BOOT_CONFIG_HOOK=""
}
save_fixture() { # save_fixture <case> <mode>
    [[ -n "${SMOKE_FIXTURES_DIR:-}" ]] || return 0
    mkdir -p "${SMOKE_FIXTURES_DIR}"
    "${DOCKER}" cp "${CTR}:/run/caddy-mtls/custom-adapted.json" "${SMOKE_FIXTURES_DIR}/$1.json" 2>/dev/null || true
    "${DOCKER}" cp "${CTR}:/run/caddy-mtls/custom-reference.json" "${SMOKE_FIXTURES_DIR}/$1.reference.json" 2>/dev/null || true
}
# reject_case <case> <mtls> <expected text in the state's error> [<bypass path> [<more checks>]]:
# the files are rejected, the add-on runs, and in the key mode a request
# without certificate and key gets 403 - on the bypass path too; <more
# checks>: a function with further checks before the stop.
reject_case() {
    local c="$1" expect="$3" path="${4:-/custom-check}" more="${5:-}"
    log "custom-${c}: booting"
    before=${FAIL_COUNT}
    SEED_NETWORK='{"80/tcp":8080,"443/tcp":8443,"4443/tcp":9443}'
    custom_boot "${c}" "$2"
    SEED_NETWORK='{"80/tcp":8080,"443/tcp":8443}'
    if wait_for "${BOOT_TIMEOUT}" booted; then
        pass "custom-${c}: add-on booted (the start is not refused)"
        save_fixture "${c}" "$([[ "$2" == true ]] && echo key || echo nomtls)"
        check "custom-${c}: rejected - $(cexec jq -r .error /run/caddy-mtls/custom.json 2>/dev/null | cut -c1-140)" eval '
            test "$(custom_state .state)" == rejected && [[ "$(custom_state .error)" == *"${expect}"* ]]'
        check "custom-${c}: nothing of the files is in use (no copies, no import in the Caddyfile)" eval '
            ! cexec grep -F /etc/caddy/custom/ /etc/caddy/Caddyfile >/dev/null &&
            test -z "$(cexec sh -c "ls -A /etc/caddy/custom 2>/dev/null")"'
        check "custom-${c}: without certificate and key -> 403 on ${path} and /" eval '
            wait_for 30 eval "test \"\$(creq \"${path}\")\" == 403" && test "$(creq /)" == 403'
        check "custom-${c}: the log has the warning block" logs_contain "Your custom Caddyfile snippets are NOT in use"
        check "custom-${c}: no fallback file kept (/etc/caddy/Caddyfile.own)" file_absent /etc/caddy/Caddyfile.own
        [[ -z "${more}" ]] || "${more}" "${c}"
        check "custom-${c}: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
    else
        fail "custom-${c}: add-on booted (the start is not refused)"
    fi
    show_log_on_failure "${before}"
}

if smoke_case custom; then
# --- all four kinds, harmless: accepted, each takes effect ------------------
log "custom-ok: booting (mTLS, header key, local-network port, harmless files of all four kinds)"
before=${FAIL_COUNT}
SEED_NETWORK='{"80/tcp":8080,"443/tcp":8443,"4443/tcp":9443}'
custom_boot ok true fwd
SEED_NETWORK='{"80/tcp":8080,"443/tcp":8443}'
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "custom-ok: add-on booted"
    auth_headers
    save_fixture ok key
    check "custom-ok: state loaded, the four files listed, the host folder named" eval '
        test "$(custom_state .state)" == loaded &&
        test "$(custom_state "[.files[].name] | join(\",\")")" == "global.caddy,site.caddy,lan.caddy,sites.caddy" &&
        test "$(custom_state .folder)" == "app_configs/local_caddy_mtls/caddy"'
    check "custom-ok: copies 0700/0600, byte for byte (CRLF and the byte-order mark kept: Caddy reads them)" eval '
        file_mode_is /etc/caddy/custom 700 && file_mode_is /etc/caddy/custom/site.caddy 600 &&
        cexec cmp -s /config/caddy/lan.caddy /etc/caddy/custom/lan.caddy &&
        cexec cmp -s /config/caddy/sites.caddy /etc/caddy/custom/sites.caddy'
    check "custom-ok: README.txt written in /config/caddy" eval '
        cexec grep -F "applied when the add-on STARTS" /config/caddy/README.txt >/dev/null'
    check "custom-ok: the add-on's own rendering kept as /etc/caddy/Caddyfile.own (no custom import, as the Caddyfile's mode)" eval '
        file_exists /etc/caddy/Caddyfile.own && ! cexec grep -F /etc/caddy/custom/ /etc/caddy/Caddyfile.own >/dev/null &&
        test "$(cexec stat -c %a /etc/caddy/Caddyfile.own)" == "$(cexec stat -c %a /etc/caddy/Caddyfile)"'
    check "custom-ok: the log lists each file and says changes need a restart" eval '
        logs_contain "Custom:      in use (checked by Caddy and by the add-on'"'"'s integrity check), from app_configs/local_caddy_mtls/caddy/ (addon_configs/local_caddy_mtls/caddy/ in apps that still use the old name):" &&
        logs_contain "caddy/site.caddy (" && logs_contain "caddy/sites.caddy (" &&
        logs_contain "Changes to these files take effect when the add-on restarts."'
    check "custom-ok: global.caddy took effect (protocols h1 h2 on the add-on's servers)" \
        adapted '[.apps.http.servers[] | select(.listen == [":443"]) | .protocols] == [["h1", "h2"]]'
    for p in /custom/hello /custom/strip/x /custom/files/app.css /custom/route/x /custom/proxy/x; do
        check "custom-ok: site.caddy content unreachable without certificate or key: ${p} -> 403" test "$(creq "${p}")" == 403
    done
    check "custom-ok: site.caddy with the key: respond, header, redirect, rewrite, handle_path, file_server, route" eval '
        [[ "$(abody /custom/hello -H @/tmp/h-ok -i)" == *"x-custom-site: yes"*"hello from site.caddy"* ]] &&
        [[ "$(abody /custom/old -H @/tmp/h-ok -o /dev/null -w "%{http_code} %{redirect_url}")" == "302 https://${DOMAIN}/custom/hello" ]] &&
        [[ "$(abody /custom/rw -H @/tmp/h-ok)" == "stripped /rw" ]] &&
        [[ "$(abody /custom/strip/x -H @/tmp/h-ok)" == "stripped /x" ]] &&
        test "$(creq /custom/files/app.css -H @/tmp/h-ok)" == 200 &&
        [[ "$(abody /custom/route/x -H @/tmp/h-ok -i)" == *"x-custom-route: 1"*"route"* ]]'
    check "custom-ok: site.caddy with a client certificate works too" test "$(creq /custom/hello "${CERT_ALICE[@]}")" == 200
    check "custom-ok: a snippet's own reverse_proxy gets the request without the header (removed before it), with its request_header" eval '
        test "$(creq /custom/proxy/x -H @/tmp/h-ok)" == 200 && upstream_lacks_header /custom/proxy/x &&
        fexec cat /tmp/up/requests.jsonl | jq -s -e "[.[] | select(.path == \"/custom/proxy/x\")] | last.header_names | index(\"x-custom-req\") != null" >/dev/null'
    check "custom-ok: lan.caddy (CRLF) took effect on the local-network site" eval '
        [[ "$(cexec curl -sk --max-time 10 --resolve "${DOMAIN}:4443:127.0.0.1" "https://${DOMAIN}:4443/lan-custom")" == "lan custom" ]]'
    other() { cexec curl -sk --max-time 10 -o - -w ' %{http_code}' --resolve "other.caddy-mtls-smoke.localhost:443:127.0.0.1" "$@" https://other.caddy-mtls-smoke.localhost/ 2>/dev/null || true; }
    check "custom-ok: sites.caddy (byte-order mark) with import mtls: no certificate -> refused in the handshake, alice -> served" eval '
        wait_for 30 eval "[[ \"\$(other "${CERT_ALICE[@]}")\" == \"other site 200\" ]]" && [[ "$(other)" == " 000" ]] &&
        [[ "$(other -H @/tmp/h-ok)" == " 000" ]]'
    check "custom-ok: the card lists the files, the folder, restart hint" eval '
        html="$(dashboard /)" && [[ "${html}" == *"id=\"custom-config\""*"data-state=\"loaded\""* &&
        "${html}" == *"<code>caddy/site.caddy</code>"* && "${html}" == *"app_configs/local_caddy_mtls/caddy/"* &&
        "${html}" == *"Restart the add-on to apply changes"* ]]'
    check "custom-ok: no notification; a leftover of an earlier run dismissed" eval '
        wait_for 30 supervisor_got "(.path | endswith(\"/dismiss\")) and .body.notification_id == \"caddy_mtls_custom_config\"" &&
        ! supervisor_got "(.path | endswith(\"/create\")) and .body.notification_id == \"caddy_mtls_custom_config\""'
    # Editing the files after the start changes nothing until a restart - not
    # even at a run-time reload (revoke bob), which succeeds.
    cexec sh -c 'printf "respond /custom/hello \"changed\" 200\nthis is { broken\n" > /config/caddy/site.caddy'
    check "custom-ok: a file edited (and broken) after the start; a reload (revoke bob) succeeds" \
        test "$(panel_post /api/clients/bob/revoke reason=superseded)" == "303 http://127.0.0.1:8099${INGRESS_PREFIX}/?ok=Client+%27bob%27+revoked."
    check "custom-ok: ... the running configuration still has the checked copy" eval '
        [[ "$(abody /custom/hello -H @/tmp/h-ok)" == "hello from site.caddy" ]] &&
        ! cexec grep -F changed /etc/caddy/custom/site.caddy >/dev/null'
    # The forwarding switch (2.2.0) with custom files loaded.
    fake_trust off
    fake_restart
    check "custom-ok: forwarding switch pass -> strip with custom files loaded (snippet rewritten, reload succeeded)" \
        wait_for 20 eval 'snippet_is strip && [[ "$(cexec jq -r "\"\(.mode) \(.applied)\"" /data/upstream.json)" == "strip true" ]]'
    check "custom-ok: after that reload: the gate 403, the key reaches site.caddy and the upstream" eval '
        test "$(creq /custom/hello)" == 403 && [[ "$(abody /custom/hello -H @/tmp/h-ok)" == "hello from site.caddy" ]] &&
        test "$(jq -r .path <<<"$(abody /after -H @/tmp/h-ok)" 2>/dev/null)" == /after'
    check "custom-ok: no Traceback, no failed validation" eval 'logs_lack "Traceback" && logs_lack "failed validation"'
    check "custom-ok: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
else
    fail "custom-ok: add-on booted"
fi
show_log_on_failure "${before}"

# --- the same files without a header key (the strict mode) -------------------
log "custom-ok-strict: booting (mTLS, no key, harmless files)"
before=${FAIL_COUNT}
CUSTOM_CASE=ok-strict
BOOT_CONFIG_HOOK=custom_files
SEED_NETWORK='{"80/tcp":8080,"443/tcp":8443,"4443/tcp":9443}'
boot custom-ok-strict "$(options "${DOMAIN}" true none "")"
SEED_NETWORK='{"80/tcp":8080,"443/tcp":8443}'
BOOT_CONFIG_HOOK=""
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "custom-ok-strict: add-on booted"
    save_fixture ok-strict strict
    check "custom-ok-strict: loaded; no certificate -> handshake refused; alice reaches site.caddy" eval '
        test "$(custom_state .state)" == loaded && test "$(creq /custom/hello)" == 000 &&
        [[ "$(abody /custom/hello "${CERT_ALICE[@]}")" == "hello from site.caddy" ]]'
    check "custom-ok-strict: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
else
    fail "custom-ok-strict: add-on booted"
fi
show_log_on_failure "${before}"

# --- a broken file: everything dropped, the add-on starts --------------------
log "custom-broken: booting (site.caddy imports a missing snippet; global.caddy and lan.caddy are fine)"
before=${FAIL_COUNT}
SEED_NETWORK='{"80/tcp":8080,"443/tcp":8443,"4443/tcp":9443}'
custom_boot broken true fwd
SEED_NETWORK='{"80/tcp":8080,"443/tcp":8443}'
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "custom-broken: add-on booted (the start is not refused)"
    auth_headers
    check "custom-broken: rejected; the message names the user's file (caddy/site.caddy:2), not the copy" eval '
        test "$(custom_state .state)" == rejected && [[ "$(custom_state .error)" == *"caddy/site.caddy:2"* ]] &&
        [[ "$(custom_state .error)" != *"/etc/caddy"* ]] && test "$(custom_state .error_file)" == site.caddy'
    check "custom-broken: the other files are not applied either (no protocols option, no lan.caddy respond)" eval '
        adapted "[.apps.http.servers[] | select(.listen == [\":443\"]) | .protocols] == [null]" &&
        [[ "$(cexec curl -sk --max-time 10 --resolve "${DOMAIN}:4443:127.0.0.1" "https://${DOMAIN}:4443/lan-custom")" != "lan custom" ]]'
    check "custom-broken: the add-on works with its own configuration (no key 403, the key 200)" eval '
        test "$(creq /x)" == 403 && test "$(creq /x -H @/tmp/h-ok)" == 200'
    check "custom-broken: the log has the warning block with the message" eval '
        logs_contain "Your custom Caddyfile snippets are NOT in use" && logs_contain "caddy/site.caddy:2"'
    check "custom-broken: the card is red with the message and what to do" eval '
        html="$(dashboard /)" && [[ "${html}" == *"id=\"custom-config\""*"data-state=\"rejected\""* &&
        "${html}" == *"Your custom files are NOT in use."* && "${html}" == *"caddy/site.caddy:2"* ]]'
    check "custom-broken: the notification is raised at the (fake) Supervisor" wait_for 30 supervisor_got \
        "(.path | endswith(\"/create\")) and .body.notification_id == \"caddy_mtls_custom_config\" and (.body.message | contains(\"caddy/site.caddy:2\"))"
    check "custom-broken: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
else
    fail "custom-broken: add-on booted (the start is not refused)"
fi
show_log_on_failure "${before}"

# --- ignored entries: a symlink, an oversized file, a FIFO, a blank file ----
log "custom-ignored: booting (symlink, 300 KB file, FIFO, blank file)"
before=${FAIL_COUNT}
SEED_NETWORK='{"80/tcp":8080,"443/tcp":8443,"4443/tcp":9443}'
custom_boot ignored true
SEED_NETWORK='{"80/tcp":8080,"443/tcp":8443}'
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "custom-ignored: add-on booted (a FIFO does not block the start)"
    check "custom-ignored: each ignored with a log line, nothing in use" eval '
        test "$(custom_state .state)" == none &&
        logs_contain "caddy/site.caddy is ignored: a symbolic link" &&
        logs_contain "caddy/lan.caddy is ignored: larger than 256 KiB" &&
        logs_contain "caddy/global.caddy is ignored: not a regular file" &&
        logs_contain "caddy/sites.caddy is ignored: empty"'
    check "custom-ignored: the card shows the ignored entries" eval '
        [[ "$(dashboard /)" == *"id=\"custom-config\""*"a symbolic link"* ]]'
    check "custom-ignored: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
else
    fail "custom-ignored: add-on booted (a FIFO does not block the start)"
fi
show_log_on_failure "${before}"

# --- rejected: the break-outs and other changes of the add-on's own blocks --
reject_case directive true "in one of your files"
reject_case imports true "may only import a snippet by its name"
reject_case breakout-site true "rule 1" /bypass/x
reject_case pathsite true "rule 2" /bypass/x
reject_case merged-scheme true "" /bypass
reject_case merged-port true "" /bypass
reject_case strict-sni true "rule 3"
reject_case matcher true "matcher is defined more than once"
reject_case double-close true "" /bypass
log "custom-breakout-lan: booting"
reject_case breakout-lan true "rule 1"
# mTLS off: "import mtls" fails - never a site without protection.
reject_case mtls-off false "mtls"

# --- global options that only lose to the add-on's own lines ----------------
for c in admin-off admin-other storage; do
    log "custom-${c}: booting"
    before=${FAIL_COUNT}
    custom_boot "${c}" true
    if wait_for "${BOOT_TIMEOUT}" booted; then
        pass "custom-${c}: add-on booted"
        save_fixture "${c}" key
        check "custom-${c}: the add-on's own setting wins ($(custom_state .state)): admin on 127.0.0.1:2019, storage /data/caddy, a reload works" eval '
            admin_up && adapted "(.admin.listen == \"127.0.0.1:2019\") and (.storage.root == \"/data/caddy\") and ((.admin.disabled // false) == false)" &&
            test "$(panel_post /api/clients name=carol)" == "303 http://127.0.0.1:8099${INGRESS_PREFIX}/?ok=Client+%27carol%27+created."'
        check "custom-${c}: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
    else
        fail "custom-${c}: add-on booted"
    fi
    show_log_on_failure "${before}"
done

# --- B-1: a site on another listener (admin 2019, panel 8099, bind) ----------
# revoke_applies <case>: the admin endpoint answers the panel's reloads, so a
# revocation through the panel ends alice's access (c43: the reload went to
# the user's site, reported success and was not applied).
revoke_applies() {
    check "custom-$1: alice admitted before the revocation (502: no upstream here)" test "$(creq /x "${CERT_ALICE[@]}")" == 502
    check "custom-$1: revoke alice through the panel -> applied: refused in the handshake" eval '
        test "$(panel_post /api/clients/alice/revoke reason=superseded)" == "$(flash_ok Client+%27alice%27+revoked.)" &&
        test "$(creq /x "${CERT_ALICE[@]}")" == 000'
    check "custom-$1: the admin endpoint is Caddy's own on 127.0.0.1:2019 (its config, not a site's answer)" \
        adapted '.admin.listen == "127.0.0.1:2019"'
}
reject_case port-admin true "listens on :2019" /custom-check revoke_applies
panel_answers() {
    check "custom-$1: the web interface answers on 8099 (dashboard, not a site's empty 200)" eval '
        [[ "$(dashboard /)" == *"id=\"custom-config\""*"data-state=\"rejected\""* ]]'
}
reject_case port-panel true "listens on :8099" /custom-check panel_answers
bind_off() {
    check "custom-$1: the domain on 127.0.0.1:443 is the add-on's site (403 without certificate and key)" \
        test "$(creq /x)" == 403
}
reject_case bind true "without bind" /custom-check bind_off

# --- B-4 / B-6: refused, with the real cause in the message ------------------
reject_case wildcert true "covers the add-on's own domain caddy-mtls-smoke.localhost (as *.localhost)"
reject_case keytype true "cannot be changed by a snippet"
reject_case defsni true "cannot be changed by a snippet"
reject_case wild true "a wildcard site that includes the add-on's name is not supported"

# --- B-6: a log that includes the access logs (with the header filter) ------
log "custom-logok: booting (global.caddy: log mine { include http.log.access; request>headers delete }, access_log on)"
before=${FAIL_COUNT}
OPT_ACCESS_LOG=true
custom_boot logok true
OPT_ACCESS_LOG=false
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "custom-logok: add-on booted"
    auth_headers
    save_fixture logok key
    check "custom-logok: loaded (the default log's added exclude is accepted)" test "$(custom_state .state)" == loaded
    # The added log's lines (JSON) for the test request.
    logok_lines() { "${DOCKER}" logs "${CTR}" 2>&1 | grep -F '{"level"' | grep -F /logok-check; }
    logok_seen() { logok_lines | grep -F '"request":{' >/dev/null; }
    check "custom-logok: the added log gets the access entries (JSON)" eval '
        test "$(creq /logok-check -H @/tmp/h-ok)" == 502 && wait_for 10 logok_seen'
    check "custom-logok: ... without request headers; the key in no log line" eval '
        ! logok_lines | grep -iF -e "\"headers\"" -e "x-custom-psk" >/dev/null && logs_lack_secret "${AUTH_PATTERNS}"'
    check "custom-logok: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
else
    fail "custom-logok: add-on booted"
fi
show_log_on_failure "${before}"

# --- B-5: lan.caddy while the local-network port is off ----------------------
log "custom-lanoff: booting (site.caddy fine, lan.caddy broken, local-network port off)"
before=${FAIL_COUNT}
custom_boot lanoff true
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "custom-lanoff: add-on booted"
    auth_headers
    check "custom-lanoff: loaded with site.caddy only; lan.caddy ignored (port off), not validated" eval '
        test "$(custom_state .state)" == loaded && test "$(custom_state "[.files[].name] | join(\",\")")" == site.caddy &&
        test "$(custom_state ".ignored[] | select(.name == \"lan.caddy\") | .reason")" == "the local-network port is off" &&
        logs_contain "Custom Caddyfile snippets: caddy/lan.caddy is ignored: the local-network port is off." &&
        ! cexec test -e /etc/caddy/custom/lan.caddy'
    check "custom-lanoff: the card names lan.caddy as ignored, site.caddy in use" eval '
        html="$(dashboard /)" && [[ "${html}" == *"id=\"custom-config\""*"data-state=\"loaded\""* &&
        "${html}" == *"the local-network port is off"* ]]'
    check "custom-lanoff: site.caddy took effect" test "$(abody /custom/hello -H @/tmp/h-ok)" == hello
    check "custom-lanoff: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
else
    fail "custom-lanoff: add-on booted"
fi
show_log_on_failure "${before}"

# --- B-8: one environment for start and reload --------------------------------
log "custom-env: booting (site.caddy shows {\$CADDY_ADMIN}, {\$SUPERVISOR_TOKEN}, {\$TZ}; a token in the container env)"
before=${FAIL_COUNT}
custom_boot env true fwd
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "custom-env: add-on booted"
    auth_headers
    env_headers() { abody /env -H @/tmp/h-ok -o /dev/null -D - | tr -d '\r' | grep -iE '^x-(env|token|tz):' | tr '[:upper:]' '[:lower:]' | sort | tr '\n' ' '; }
    check "custom-env: after the start: x-env [] x-token [] x-tz [europe/vienna]" \
        test "$(env_headers)" == "x-env: [] x-token: [] x-tz: [europe/vienna] "
    check "custom-env: a panel reload (add carol) works" \
        test "$(panel_post /api/clients name=carol)" == "$(flash_ok Client+%27carol%27+created.)"
    check "custom-env: after the panel reload: the same (no CADDY_ADMIN, no Supervisor token)" \
        test "$(env_headers)" == "x-env: [] x-token: [] x-tz: [europe/vienna] "
    check "custom-env: the token is in no running configuration" eval '
        ! cexec sh -c "curl -fsS --max-time 5 http://127.0.0.1:2019/config/" | grep -F "${SMOKE_SUPERVISOR_TOKEN}" >/dev/null'
    check "custom-env: Caddy's environment holds only PATH, HOME, TZ, XDG_* and DNS_* names" caddy_env_only_allowed
    check "custom-env: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
else
    fail "custom-env: add-on booted"
fi
show_log_on_failure "${before}"

# --- B-2: a file a snippet refers to breaks after the start (c37) -------------
# livecert_case key|default: sites.caddy loads o.crt/o.key; o.key is removed;
# revoking alice through the panel still ends her access (the reload falls
# back to the add-on's own configuration and drops the snippets).
livecert_case() {
    local m="$1" c="custom-livecert-$1"
    log "${c}: booting (sites.caddy loads /config/caddy/o.crt and o.key; ${m} mode)"
    before=${FAIL_COUNT}
    CUSTOM_CASE=livecert
    BOOT_CONFIG_HOOK=custom_files
    [[ "${m}" == key ]] && OPT_HEADER_KEY_FILE="${AUTH_KEY_RAW}"
    boot_fwd "${c}" "$(options "${DOMAIN}" true none "" homeassistant 8124)" trust
    OPT_HEADER_KEY_FILE=""
    BOOT_CONFIG_HOOK=""
    if ! wait_for "${BOOT_TIMEOUT}" booted; then
        fail "${c}: add-on booted"
        show_log_on_failure "${before}"
        return 0
    fi
    pass "${c}: add-on booted"
    [[ "${m}" == key ]] && auth_headers
    check "${c}: loaded; the add-on's own rendering kept as /etc/caddy/Caddyfile.own (no custom import); alice 200; the site served" eval '
        test "$(custom_state .state)" == loaded && file_exists /etc/caddy/Caddyfile.own &&
        ! cexec grep -F /etc/caddy/custom/ /etc/caddy/Caddyfile.own >/dev/null &&
        cexec grep -F /etc/caddy/custom/sites.caddy /etc/caddy/Caddyfile >/dev/null &&
        test "$(creq /x "${CERT_ALICE[@]}")" == 200 && [[ "$(other_site)" == "other 200" ]]'
    cexec rm /config/caddy/o.key
    local lines_before
    # shellcheck disable=SC2034 # used in an eval'd check
    lines_before="$(log_line_count)"
    check "${c}: o.key removed; revoke alice through the panel -> done, and the flash says the snippets were dropped" eval '
        r="$(panel_post /api/clients/alice/revoke reason=superseded)" &&
        [[ "${r}" == "303 http://127.0.0.1:8099${INGRESS_PREFIX}/?error=Caddy+could+not+reload+with+your+custom+files+while+applying+a+change+%28"*"+To+apply+the+change+the+add-on+dropped+them"*"&ok=Client+%27alice%27+revoked." ]]'
    check "${c}: alice refused in the handshake at once" test "$(creq /x "${CERT_ALICE[@]}")" == 000
    check "${c}: state rejected, dropped at run time, Caddy's cause named (o.key)" eval '
        test "$(custom_state .state)" == rejected && test "$(custom_state .dropped)" == reload &&
        [[ "$(custom_state .dropped_at)" =~ ^[0-9.]+$ ]] && [[ "$(custom_state .error)" == "Caddy could not reload with your custom files while applying a change ("*"o.key"*"). To apply the change the add-on dropped them; they are read again at the next start." ]]'
    check "${c}: the Caddyfile is the add-on's own now; no fallback file, no copies" eval '
        ! cexec grep -F /etc/caddy/custom/ /etc/caddy/Caddyfile >/dev/null && file_absent /etc/caddy/Caddyfile.own &&
        test -z "$(cexec sh -c "ls -A /etc/caddy/custom 2>/dev/null")"'
    check "${c}: the snippet's site is gone" eval '[[ "$(other_site)" != "other 200" ]]'
    check "${c}: the card is red and says why" eval '
        html="$(dashboard /)" && [[ "${html}" == *"id=\"custom-config\""*"data-state=\"rejected\""* &&
        "${html}" == *"Caddy could not reload with your custom files while applying a change"* ]]'
    check "${c}: the log says why (one WARNING line of cert-mgr)" eval '
        new_logs_contain "${lines_before}" "Caddy could not reload with your custom files while applying a change" &&
        test "$("${DOCKER}" logs "${CTR}" 2>&1 | grep -c "Caddy could not reload with your custom files")" == 1'
    check "${c}: the notification is raised (the state changed after the start)" wait_for 30 supervisor_got \
        "(.path | endswith(\"/create\")) and .body.notification_id == \"caddy_mtls_custom_config\" and (.body.message | contains(\"while applying a change\"))"
    check "${c}: the next reload works without a fallback: revoke bob -> plain ok, bob refused" eval '
        test "$(panel_post /api/clients/bob/revoke reason=superseded)" == "$(flash_ok Client+%27bob%27+revoked.)" &&
        test "$(creq /x "${CERT_BOB[@]}")" == 000 &&
        test "$("${DOCKER}" logs "${CTR}" 2>&1 | grep -c "Caddy could not reload with your custom files")" == 1'
    if [[ "${m}" == key ]]; then
        check "${c}: the gate still holds: no key 403, the key 200" eval '
            test "$(creq /x)" == 403 && test "$(creq /x -H @/tmp/h-ok)" == 200'
    else
        check "${c}: the gate still holds: no certificate -> refused in the handshake" test "$(creq /x)" == 000
    fi
    check "${c}: no Traceback" logs_lack "Traceback"
    check "${c}: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
    show_log_on_failure "${before}"
    [[ "${m}" == key ]] || return 0
    # A restart with the files in place (o.key restored): the snippets are
    # read again and loaded.
    "${DOCKER}" cp "${CTR}:/data" - >"${WORK}/data-livecert.tar"
    log "${c}-restart: new container with the previous /data, o.key back"
    before=${FAIL_COUNT}
    CUSTOM_CASE=livecert
    BOOT_CONFIG_HOOK=custom_files
    OPT_HEADER_KEY_FILE="${AUTH_KEY_RAW}"
    boot "${c}-restart" "$(options "${DOMAIN}" true none "")" "${WORK}/data-livecert.tar"
    OPT_HEADER_KEY_FILE=""
    BOOT_CONFIG_HOOK=""
    if wait_for "${BOOT_TIMEOUT}" booted; then
        pass "${c}-restart: add-on booted"
        check "${c}-restart: the snippets are loaded again; the site served; alice and bob stay refused" eval '
            test "$(custom_state .state)" == loaded && test "$(custom_state ".dropped // \"\"")" == "" &&
            file_exists /etc/caddy/Caddyfile.own && [[ "$(other_site)" == "other 200" ]] &&
            test "$(creq /x "${CERT_ALICE[@]}")" == 000 && test "$(creq /x "${CERT_BOB[@]}")" == 000'
        check "${c}-restart: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
    else
        fail "${c}-restart: add-on booted"
    fi
    show_log_on_failure "${before}"
}
livecert_case default
livecert_case key

# --- B-2: Caddy started again by s6 (it exited with 0) after o.key broke -----
log "custom-livecert-caddyrun: booting (sites.caddy loads o.crt and o.key)"
before=${FAIL_COUNT}
custom_boot livecert true
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "custom-livecert-caddyrun: add-on booted"
    save_fixture livecert key
    check "custom-livecert-caddyrun: loaded, the start skipped the caddy service's own check (marker consumed)" eval '
        test "$(custom_state .state)" == loaded && file_absent /run/caddy-mtls/caddyfile-validated'
    # B2-1: the add-on's reload path with an admin address nobody listens
    # on (its existing CADDY_ADMIN setting): Caddy is never reached - a
    # failure as before, no fallback, nothing dropped.
    unreachable_reload() {
        cexec env CADDY_ADMIN=127.0.0.1:2020 /usr/lib/cert-mgr/.venv/bin/python3 -c 'import sys
sys.path.insert(0, "/usr/lib/cert-mgr")
import caddyctl
r = caddyctl.reload_detailed()
print(r.reloaded, bool(r.dropped), "performing request" in r.caddy_error)' 2>/dev/null
    }
    check "custom-livecert-caddyrun: a reload that cannot reach the admin endpoint fails and drops nothing (B2-1)" eval '
        test "$(unreachable_reload)" == "False False True" && test "$(custom_state .state)" == loaded &&
        file_exists /etc/caddy/Caddyfile.own && cexec test -s /etc/caddy/custom/sites.caddy'
    cexec rm /config/caddy/o.key
    caddy_pid="$(cexec pidof caddy 2>/dev/null || true)"
    caddy_back() {
        local pid
        pid="$(cexec pidof caddy 2>/dev/null)" && [[ -n "${pid}" && "${pid}" != "${caddy_pid}" ]] && admin_up
    }
    check "custom-livecert-caddyrun: SIGTERM to Caddy alone -> s6 starts it again with the add-on's own configuration" eval '
        [[ -n "${caddy_pid}" ]] && cexec kill -TERM "${caddy_pid}" && wait_for 30 caddy_back && running'
    check "custom-livecert-caddyrun: state rejected (dropped when Caddy was started again), no fallback file, no copies" eval '
        test "$(custom_state .state)" == rejected && test "$(custom_state .dropped)" == restart &&
        [[ "$(custom_state .error)" == "Caddy could not load the configuration with your custom files when it was started again ("*"o.key"* ]] &&
        file_absent /etc/caddy/Caddyfile.own && ! cexec grep -F /etc/caddy/custom/ /etc/caddy/Caddyfile >/dev/null'
    check "custom-livecert-caddyrun: the log says so" logs_contain "Caddy could not load the configuration with your custom files when it was started again"
    # plain_error: the state's error has no colour code, level or time stamp.
    plain_error() {
        local err
        err="$(custom_state .error)" || return 1
        [[ "${err}" != *$'\e'* && "${err}" != *ERROR* && ! "${err}" =~ [0-9]{4}/[0-9]{2}/[0-9]{2} ]]
    }
    check "custom-livecert-caddyrun: Caddy's message without time stamp, level or colour codes (B2-3)" plain_error
    check "custom-livecert-caddyrun: the add-on works (alice 502: no upstream here; no certificate or key: 403); a reload works" eval '
        test "$(creq /x "${CERT_ALICE[@]}")" == 502 && test "$(creq /x)" == 403 &&
        test "$(panel_post /api/clients/bob/revoke reason=superseded)" == "$(flash_ok Client+%27bob%27+revoked.)" &&
        test "$(creq /x "${CERT_BOB[@]}")" == 000'
    check "custom-livecert-caddyrun: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
else
    fail "custom-livecert-caddyrun: add-on booted"
fi
show_log_on_failure "${before}"

# --- B2-5: the drop cannot replace the Caddyfile at an s6 restart -----------
# The Caddyfile made a directory: its validation fails and the rename onto
# it fails (EISDIR) - Caddy must start with the fallback file itself.
log "custom-norename: booting (sites.caddy loads o.crt and o.key)"
before=${FAIL_COUNT}
custom_boot norename true
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "custom-norename: add-on booted"
    auth_headers
    cexec sh -c 'rm /etc/caddy/Caddyfile && mkdir /etc/caddy/Caddyfile'
    caddy_pid="$(cexec pidof caddy 2>/dev/null || true)"
    caddy_back() {
        local pid
        pid="$(cexec pidof caddy 2>/dev/null)" && [[ -n "${pid}" && "${pid}" != "${caddy_pid}" ]] && admin_up
    }
    check "custom-norename: SIGTERM to Caddy alone -> Caddy runs again, with /etc/caddy/Caddyfile.own" eval '
        [[ -n "${caddy_pid}" ]] && cexec kill -TERM "${caddy_pid}" && wait_for 30 caddy_back && running &&
        pids_with "/usr/bin/caddy run --config /etc/caddy/Caddyfile.own"'
    check "custom-norename: the log says why; state rejected (restart), the fallback file still there" eval '
        logs_contain "The Caddyfile could not be replaced; Caddy starts with the add-on'"'"'s own configuration (/etc/caddy/Caddyfile.own)." &&
        test "$(custom_state .state)" == rejected && test "$(custom_state .dropped)" == restart &&
        file_exists /etc/caddy/Caddyfile.own'
    check "custom-norename: the gate holds (no certificate or key 403, the key 502: no upstream here)" eval '
        test "$(creq /x)" == 403 && test "$(creq /x -H @/tmp/h-ok)" == 502'
    check "custom-norename: a revocation through the panel falls back again and applies (alice refused)" eval '
        r="$(panel_post /api/clients/alice/revoke reason=superseded)" &&
        [[ "${r}" == "303 "*"&ok=Client+%27alice%27+revoked." ]] && test "$(creq /x "${CERT_ALICE[@]}")" == 000'
    check "custom-norename: clean docker stop (< 10 s, exit 0, no s6 warnings)" stop_cleanly
else
    fail "custom-norename: add-on booted"
fi
show_log_on_failure "${before}"

# --- B2-2: a snippet refers to named pipes: the check's time limit --------
# (The one case of the suite that waits for the 60 s limit.)
fifo_checks() {
    check "custom-$1: the card and the log name the time limit" eval '
        [[ "$(dashboard /)" == *"data-state=\"rejected\""*"did not finish checking the configuration with your custom files within 60 seconds"* ]] &&
        logs_contain "did not finish checking the configuration with your custom files within 60 seconds"'
    check "custom-$1: no process of the expired check is left" eval '! pids_with "/usr/bin/caddy validate" && ! pids_with "timeout -k"'
}
BOOT_TIMEOUT_SAVED="${BOOT_TIMEOUT}"
BOOT_TIMEOUT=$(( BOOT_TIMEOUT + 75 ))
reject_case fifocert true "Caddy did not finish checking the configuration with your custom files within 60 seconds. A file a snippet refers to probably cannot be read to its end (a named pipe, or a network folder that does not answer)." /custom-check fifo_checks
BOOT_TIMEOUT="${BOOT_TIMEOUT_SAVED}"
fi

printf '\n%d passed, %d failed\n' "${PASS_COUNT}" "${FAIL_COUNT}"
(( FAIL_COUNT == 0 ))
