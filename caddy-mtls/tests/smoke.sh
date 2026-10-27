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
#              the panel (health, dashboard, //, /api/state), the CA and the
#              seeded clients (files, modes, state.json), the Caddyfile and
#              Caddy's admin API (leaf verifier), the plain-HTTP site (CRL,
#              308 to https), real mTLS handshakes, client add / revoke /
#              regenerate through the panel (CRL, active/, Caddy reloaded: a
#              revoked certificate is rejected at once), the .p12 download,
#              the ingress allow-list (crafted Host header), the host-port log
#              line and no secrets in the log.
#   no-mtls    mtls_enabled: false renders and validates (public domain);
#              upstream_port unset: Home Assistant Core's port from the
#              (seeded) Supervisor info.
#   dns-*      one boot per DNS provider (cloudflare, route53, hetzner, dummy
#              tokens, public domain): the rendered `dns` directive passes
#              `caddy validate` and Caddy runs with it (the module syntax at the
#              pinned versions), the token stays out of the Caddyfile and the
#              log, and Caddy's environment carries the credentials.
#   bad-*      refused starts: route53 token without ":", a Cloudflare token
#              the module rejects (its error text quotes the token: it must be
#              redacted), a domain with a port, an upstream without a port.
#
# No external network traffic: every container runs with --network none and
# ACME_CA_URL points at a closed local port (http://127.0.0.1:9/directory);
# the checks also assert that no ACME issuer points elsewhere.
#
# Prints one PASS/FAIL line per check. Exit status: 0 all checks passed,
# 1 a check failed, 2 usage error. Containers are removed on exit.
# Env: DOCKER (default docker), SMOKE_BOOT_TIMEOUT (seconds, default 90).
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

PREFIX="caddy-mtls-smoke-$$"
WORK="$(mktemp -d)"
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
stop_cleanly() {
    "${DOCKER}" stop -t 30 "${CTR}" >/dev/null 2>&1 \
        && [[ "$("${DOCKER}" inspect -f '{{.State.Status}}' "${CTR}")" == exited ]]
}

# boot <name> <options-json>: create, seed and start a container (not waited for).
boot() {
    local name="$1" options="$2" dir="${WORK}/$1"
    CTR="${PREFIX}-${name}"
    mkdir -p "${dir}/data" "${dir}/tmp/.bashio"
    printf '%s\n' "${options}" >"${dir}/data/options.json"
    # bashio::config asks the Supervisor API, which does not exist here: seed
    # bashio's cache with the options (and the add-on info with the default
    # host ports, which init-caddy logs) so it never needs to.
    cp "${dir}/data/options.json" "${dir}/tmp/.bashio/addons.self.options.config.cache"
    printf '%s\n' '{"name":"Caddy mTLS Proxy","network":{"80/tcp":8080,"443/tcp":8443}}' \
        >"${dir}/tmp/.bashio/addons.self.info.cache"
    # Home Assistant Core's info (port), only when a case sets CORE_INFO.
    if [[ -n "${CORE_INFO:-}" ]]; then
        printf '%s\n' "${CORE_INFO}" >"${dir}/tmp/.bashio/core.info.cache"
    fi
    chmod -R go+rX "${dir}"
    CONTAINERS+=("${CTR}")
    "${DOCKER}" create --name "${CTR}" --network none \
        -e ACME_CA_URL="${ACME_SINKHOLE}" -e TZ=Europe/Vienna "${IMAGE}" >/dev/null
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
# (upstream default 127.0.0.1:8123; an empty port leaves upstream_port unset)
options() {
    jq -n --arg domain "$1" --argjson mtls "$2" --arg provider "$3" --arg token "$4" \
        --arg uhost "${5:-127.0.0.1}" --arg uport "${6-8123}" \
        --arg pass "${P12_PASSWORD}" '{
        domain: $domain, email: "smoke@example.com",
        upstream_host: $uhost, mtls_enabled: $mtls,
        ca_country: "AT", ca_state: "Styria", ca_locality: "Graz",
        ca_organization: "LinumIQ", ca_common_name: "Caddy mTLS smoke CA",
        client_names: ["alice", "bob"], client_cert_password: $pass,
        acme_dns_provider: $provider, dns_api_token: $token,
        log_level: "info", cert_expiry_warn_days: [30, 14, 7, 1],
        cert_check_interval_hours: 6}
        + (if $uport == "" then {} else {upstream_port: ($uport | tonumber)} end)'
}
command -v jq >/dev/null || { printf 'jq is required\n' >&2; exit 2; }
command -v tar >/dev/null || { printf 'tar is required\n' >&2; exit 2; }

P12_PASS_FILE="$(secret_file p12-pass "${P12_PASSWORD}")"

# ==============================================================================
# 1. main: mTLS on, internal issuer
# ==============================================================================
DOMAIN="caddy-mtls-smoke.localhost"
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
check "main: init-caddy logged the published host ports" \
    logs_contain "Host ports:  80/tcp -> 8080, 443/tcp -> 8443"
check "main: init-caddy logged the router forwarding hint" \
    logs_contain "forward external TCP 80 -> <this host>:8080 and TCP 443 -> <this host>:8443"
check "main: explicit upstream_port used (127.0.0.1:8123)" \
    eval 'logs_contain "Upstream:    127.0.0.1:8123 (option upstream_port)" &&
    cexec grep -F "reverse_proxy 127.0.0.1:8123 {" /etc/caddy/Caddyfile >/dev/null'

# --- panel --------------------------------------------------------------------
dashboard() { cexec curl -fsS --max-time 10 "http://127.0.0.1:8099$1" 2>/dev/null; }
check "main: dashboard HTML lists the seeded clients" \
    eval 'html="$(dashboard /)" && [[ "${html}" == *"Caddy mTLS"* && "${html}" == *alice* && "${html}" == *bob* ]]'
check "main: GET // (doubled ingress slash) serves the dashboard" \
    eval '[[ "$(dashboard //)" == *"Certificate Authority"* ]]'
check "main: static stylesheet served" eval 'dashboard /static/style.css >/dev/null'
check "main: /api/state lists alice + bob active, CA present" \
    test "$(cexec sh -c 'curl -fsS http://127.0.0.1:8099/api/state | jq -r "([.clients[] | select(.status == \"active\") | .name] | sort | join(\",\")), (.ca != null)"' 2>/dev/null | tr '\n' ' ')" == "alice,bob true "

# --- plain HTTP site (container port 80) ------------------------------------------
http80() { cexec curl -s --max-time 5 --resolve "${DOMAIN}:80:127.0.0.1" "$@" 2>/dev/null; }
check "main: port 80 serves /mTLS-CA.crl (= the CRL file)" eval '
    http80 -o /tmp/crl-http.pem "http://${DOMAIN}/mTLS-CA.crl" &&
    cexec cmp -s /tmp/crl-http.pem /data/certs/mTLS-CA.crl'
# `redir ... permanent` = 301 (CHANGELOG 1.2.5 said 308; unchanged here).
check "main: port 80 redirects other paths with 301 to https" \
    test "$(http80 -o /dev/null -w '%{http_code} %{redirect_url}' "http://${DOMAIN}/some/path?x=1")" \
    == "301 https://${DOMAIN}/some/path?x=1"

# --- mTLS handshakes (port 443, internal server certificate) ------------------------
# 502 = the client certificate was accepted and the request reached the (absent)
# upstream; 000 = the TLS handshake was refused.
mtls() { # mtls <cert> <key>  (empty: no client certificate)
    local args=()
    [[ -n "$1" ]] && args=(--cert "$1" --key "$2")
    cexec curl -sk --max-time 5 -o /dev/null -w '%{http_code}' --resolve "${DOMAIN}:443:127.0.0.1" \
        "${args[@]+"${args[@]}"}" "https://${DOMAIN}/" 2>/dev/null || true
}
mtls_is() { [[ "$(mtls "$2" "$3")" == "$1" ]]; }
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

# --- logs ---------------------------------------------------------------------------
check "main: cert-monitor started" logs_contain "cert-monitor starting"
check "main: client_cert_password not in the log" logs_lack_secret "${P12_PASS_FILE}"
check "main: no 'permission denied' / Traceback in the log" \
    eval 'logs_lack "ermission denied" && logs_lack "Traceback"'
check "main: clean docker stop" stop_cleanly
show_log_on_failure "${before}"

# ==============================================================================
# 2. no-mtls: mtls_enabled false (public domain, ACME sinkhole)
# ==============================================================================
log "no-mtls: booting (mtls_enabled: false)"
before=${FAIL_COUNT}
CORE_INFO='{"port": 80, "ssl": false}'
boot no-mtls "$(options home.example.com false none "" homeassistant "")"
CORE_INFO=""
if wait_for "${BOOT_TIMEOUT}" booted; then
    pass "no-mtls: add-on booted"
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
    check "no-mtls: clean docker stop" stop_cleanly
else
    fail "no-mtls: add-on booted"
fi
show_log_on_failure "${before}"

# ==============================================================================
# 3. DNS providers (dummy tokens, public domain, ACME sinkhole)
# ==============================================================================
# caddy_env_has <VAR> <value>: the running Caddy process has VAR=value.
caddy_env_has() {
    cexec sh -c 'pid="$(pidof caddy)" && tr "\0" "\n" < "/proc/${pid}/environ" | grep -Fx -- "$0=$1" >/dev/null' "$1" "$2"
}
dns_case() { # dns_case <provider> <token> <env-var=value...>
    local provider="$1" token="$2" kv secret_file_path
    shift 2
    log "dns-${provider}: booting"
    before=${FAIL_COUNT}
    secret_file_path="$(secret_file "secret-dns-${provider}" "${token}")"
    boot "dns-${provider}" "$(options home.example.com true "${provider}" "${token}" homeassistant "")"
    if ! wait_for "${BOOT_TIMEOUT}" booted; then
        fail "dns-${provider}: add-on booted (Caddy runs with the dns directive)"
        show_log_on_failure "${before}"
        return 0
    fi
    pass "dns-${provider}: add-on booted (Caddy runs with the dns directive)"
    check "dns-${provider}: Caddyfile renders 'dns ${provider}' with {env.*} placeholders" \
        eval "cexec grep -E '^ +dns ${provider} ' /etc/caddy/Caddyfile >/dev/null && cexec grep -F '{env.' /etc/caddy/Caddyfile >/dev/null"
    check "dns-${provider}: token not in the Caddyfile" \
        eval '! "${DOCKER}" exec -i "${CTR}" grep -F -f /dev/stdin /etc/caddy/Caddyfile <"${secret_file_path}" >/dev/null'
    # Explicit validation with the credentials exported exactly as the caddy
    # service does it (lib/dns-provider.sh).
    check "dns-${provider}: caddy validate with the module (pinned version)" \
        "${DOCKER}" exec -i "${CTR}" bash -c 'set -e; source /etc/s6-overlay/scripts/lib/dns-provider.sh
            token="$(cat)"; dns_provider_export "$0" "${token}"
            caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1' \
        "${provider}" <"${secret_file_path}"
    check "dns-${provider}: admin API config uses dns.providers.${provider}" \
        adapted "[.. | objects | select(.provider?.name? == \"${provider}\")] | length == 1"
    check "dns-${provider}: every ACME issuer uses the sinkhole (no Let's Encrypt / ZeroSSL)" issuers_only_sinkhole
    for kv in "$@"; do
        check "dns-${provider}: Caddy's environment has ${kv%%=*}" caddy_env_has "${kv%%=*}" "${kv#*=}"
    done
    check "dns-${provider}: token not in the log" logs_lack_secret "${secret_file_path}"
    check "dns-${provider}: upstream_port unset, no Supervisor API -> homeassistant:8123" \
        eval 'logs_contain "Upstream:    homeassistant:8123 (Core'"'"'s port unknown" &&
        cexec grep -F "reverse_proxy homeassistant:8123 {" /etc/caddy/Caddyfile >/dev/null'
    check "dns-${provider}: clean docker stop" stop_cleanly
    show_log_on_failure "${before}"
}
dns_case cloudflare "${CF_TOKEN}" "DNS_API_TOKEN=${CF_TOKEN}"
dns_case route53 "${R53_KEY_ID}:${R53_SECRET}" \
    "DNS_AWS_ACCESS_KEY_ID=${R53_KEY_ID}" "DNS_AWS_SECRET_ACCESS_KEY=${R53_SECRET}"
dns_case hetzner "${HZ_TOKEN}" "DNS_API_TOKEN=${HZ_TOKEN}"

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

printf '\n%d passed, %d failed\n' "${PASS_COUNT}" "${FAIL_COUNT}"
(( FAIL_COUNT == 0 ))
