# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.0] - 2026-11-28

### Added

- **Header authentication** (options `header_auth_name`, default
  `X-Custom-PSK`, and `header_auth_key`, default empty = off). For clients
  that cannot present a client certificate but can send one fixed header,
  such as a watch app: with a key set, the public site accepts a request
  that presents an active client certificate **or** carries the header with
  exactly the key; every other request gets `403 Forbidden`. A presented
  certificate is still checked in the TLS handshake as before (a revoked
  one ends the connection, also with the key), and the HTTP check accepts
  a certificate only by the fingerprint of an active one (a list
  regenerated from the allowlist before every reload). The key: 32-256
  characters of
  `A-Z a-z 0-9 . _ ~ + / = -`, never in the generated configuration, a log
  line or the web interface (Caddy reads it from a 0600 file per request).
  The header is removed before Home Assistant sees the request. While a key
  is set, the add-on's log lines carry no request headers; the access log
  says per request how it was let in or why not (field `auth`). Web
  interface: a card **Header authentication** with a key suggestion made in
  the browser. With `mtls_enabled: false` the key is the only protection
  (the log and the card say so).
- **Custom Caddyfile snippets for experts**: `global.caddy`, `site.caddy`,
  `lan.caddy` and `sites.caddy` in the add-on's configuration folder
  (`app_configs/<slug>/caddy/` - `addon_configs/...` in apps that still use
  the old name), imported at four fixed places (global
  options first, so the add-on's own win; the public and the local-network
  site after their access checks, before the proxy; further sites last;
  `import mtls` = the add-on's strict client certificate check; further
  sites only on the add-on's ports 80, 443 and 4443, without `bind`). Read
  at every start and used as checked copies (`lan.caddy` only while the
  local-network port is on); Caddy validates them and the add-on checks
  that its own sites stayed as it wrote them. If either rejects them, none
  is used and the add-on starts with its own configuration: a warning block
  in the log, a red card **Custom Caddy configuration** and a Home
  Assistant notification; a check that does not finish within 60 seconds
  (a referenced file that cannot be read to its end) counts as a rejection.
  Files the snippets refer to (a `tls` certificate and key, ...) are read
  by Caddy at every reload; if Caddy refuses the configuration with the
  snippets while the add-on applies a change such as a revocation, the
  add-on drops them until the next start and reloads with its own
  configuration, so that the change takes effect (the panel, the card and a
  notification say so).

### Changed

- Only for users who set `header_auth_key`: a visitor without a client
  certificate now completes the TLS handshake and gets `403 Forbidden`
  instead of a failed handshake; a browser that dismissed the certificate
  prompt shows that page. Without a key, nothing changes.
- Only for users who add custom files: see above. Without them, nothing
  changes.
- `log_level: trace` no longer turns on bashio's own trace output, which
  printed the add-on's whole options - `client_cert_password`,
  `dns_api_token` and now the header key included - into the log.
- Every Caddy process that reads the configuration - the checks at the
  start, Caddy itself and the reloads by the web interface and the monitor -
  runs with the same small environment: `PATH`, `HOME`, `TZ`, the `XDG_*`
  locations and the DNS provider credentials, nothing else. A custom
  snippet's `{$VAR}` therefore gets the same value at the start and at every
  reload, and no Caddy process has the Supervisor token (until now the
  reloads adapted the configuration in the web interface's environment,
  which has it).
- Caddy's admin endpoint and everything that talks to it use
  `127.0.0.1:2019` explicitly instead of `localhost:2019` (in the container
  `localhost` resolves to `::1` first, where the admin endpoint does not
  listen).

### Fixed

- The documentation of "Method 2: File Access" named a folder that exists
  only for a local copy: the copies are in `<slug>/certs/` of the app
  configuration folders (usually `2644ca2c_caddy_mtls` for this repository;
  the prefix depends on the exact repository address that was added), which
  appear as `app_configs` or under the earlier name `addon_configs`,
  depending on the app and its version; the content is the same. The web
  interface now names the exact folder.
- The `.p12` copy of a revoked client stayed in that folder for good; it is
  now removed at the next start.
- Test data no longer uses a real host name or address.

## [2.2.0] - 2026-11-27

### Fixed

- **"400: Bad Request" after selecting the client certificate.** Home
  Assistant answers every request that carries the visitor's address
  (`X-Forwarded-For`) with `400: Bad Request` unless it trusts the proxy -
  and the add-on always sent that header. A freshly configured add-on
  therefore showed a bare "400: Bad Request"; the explanation was only in
  the logs. Now the add-on asks Home Assistant at its start whether it
  accepts forwarded requests from the add-on (new option
  `forwarded_headers`, default `auto`):
  - Home Assistant trusts the add-on: visitor addresses are passed on, as
    before.
  - It does not, and mTLS is on (the default): the add-on removes the
    forwarding headers (`X-Forwarded-For`, `-Proto`, `-Host`, `X-Real-IP`,
    `Forwarded`). It works without any change in Home Assistant, which then
    sees every visitor under the add-on's own address (for example
    `172.30.33.3`); the web interface lists what that means (logins and
    notifications show that address; "local network only" users and
    webhooks also work for holders of a client certificate; IP bans after
    failed logins would hit everyone).
  - It does not, and mTLS is off: the addresses are still passed on (without
    client certificates no internet visitor may look like a local device),
    so the 400 stays - now explained in the web interface and in a Home
    Assistant notification.
  - `always` passes the addresses on as up to 2.1.3; `never` never does -
    and needs mTLS: with `mtls_enabled: false` and `forwarded_headers:
    never` the add-on refuses to start (every internet visitor would look
    like a local device), naming the alternatives.
- The add-on keeps watching Home Assistant (a request every 12 seconds that
  Home Assistant does not log, over a connection Home Assistant keeps open)
  and switches at run time, without a restart of its own, when Home
  Assistant restarts with changed settings - also when it restarts right
  after the add-on started, and also when it stops trusting the add-on (for
  example when it drops unconfirmed HTTP settings after 5 minutes): that is
  noticed at the next 12-second check, not after a minute. The header lines
  of the proxy live in an imported file that is rewritten, then Caddy
  reloads (open websocket connections reconnect). While Home Assistant
  trusts the add-on, the check repeats once a minute; while it does not,
  only at the start, after a Home Assistant restart and on **Check again** -
  each refused check writes one line into Home Assistant's log. While Home
  Assistant does not answer or restarts (also at the first start with Home
  Assistant still down) the add-on asks every 2.5 seconds, for the first 10
  minutes; after that every 12 seconds until it answers again. A slow
  answer is not "down": Home Assistant counts as unreachable only after a
  refused connection or two checks in a row without an answer within 5
  seconds. A test question that gets no answer in time is asked again every
  12 seconds, at most three times in a row (card "Too slow to decide"),
  then again only after a Home Assistant restart, the add-on's start or
  **Check again**.

### Added

- Web interface: a card **Home Assistant connection** - green while visitor
  addresses are passed on, blue while Home Assistant sees every visitor as
  the add-on (with the consequences), red while every request is answered
  400, Home Assistant does not answer, or Caddy could not be reloaded for a
  change ("Change not applied", with the error; the card then shows what
  Caddy still runs) - with the steps to let Home Assistant trust the add-on
  and a **Check again** button.
- A Home Assistant notification "Caddy mTLS: Home Assistant refuses the
  proxied requests" while every request is answered 400; it is dismissed
  when that is over.
- A Home Assistant notification "Caddy mTLS: Home Assistant no longer
  trusts the app - visitor addresses are hidden" when the add-on stops
  passing the addresses on while it runs because Home Assistant trusted it
  and no longer does, with what that means and how to restore the trust;
  dismissed when the addresses are passed on again and at the next start
  (none when the add-on simply starts that way or decides for the first
  time).
- `tests/real-core.sh`: checks the behaviour against a real Home Assistant
  Core 2026.11.3 (not part of CI).
- **HTTPS in the local network without a client certificate** (optional):
  container port `4443/tcp` serves the same domain with the same Let's
  Encrypt certificate and no client certificate, to private source
  addresses only (10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, fc00::/7,
  fe80::/10, ::1); everyone else gets `403 Forbidden` naming the address. It
  also refuses the add-on's Docker gateway address, under which Docker
  forwards IPv6 connections (and connections from the host itself) and
  hides their real source. Off by default: it is on exactly while the port
  has a host port (Network settings, **Show disabled ports**). Never forward
  it on the router. The web interface has a card **Local network** (off:
  how to turn it on; on: the address, the local DNS record, the warnings -
  with host port 443 also: the router must forward external 443 to the
  client-certificate port, never to host port 443). A TLS session of this
  port cannot be resumed on the client-certificate port. Devices that come
  through a VPN are refused there; they use the client-certificate address.

### Changed

- The steps for Home Assistant name its user interface: **Settings > System
  > Network > HTTP server > Reverse proxy** (Trust X-Forwarded-For, trusted
  proxy `172.30.33.0/24`, Save and restart, then confirm). Home Assistant
  2026.7 and later read the `http:` block of `configuration.yaml` only once
  and ignore a block added later; the documentation's block (now with
  `172.30.33.0/24`, the add-on network Home Assistant's own documentation
  uses) is for older versions.
- The log no longer prints the `http:` block at every start: one line while
  addresses are passed on, a short notice while Home Assistant sees every
  visitor as the add-on, the full block only while every request is
  answered 400.
- Installation step 4 (adding the add-on to Home Assistant's trusted
  proxies) is no longer required.
- The plain-HTTP site (port 80) is rendered always, also with
  `mtls_enabled: false` (then without the CRL): its redirect keeps pointing
  at `https://<domain>/` (port 443) with a second HTTPS site for the domain.
  With `mtls_enabled: false` the redirect is now `301` (was Caddy's automatic
  `308`).
- The add-on's log names all three host ports and the state of the
  local-network port.

## [2.1.3] - 2026-11-24

Security update. Nothing changes in the configuration, the certificates or
the web interface.

### Security

- **Caddy 2.11.9** (was 2.11.7) with golang.org/x/net 0.60.0: fixes four
  denial-of-service flaws in the HTTP/2 server that serves the add-on's
  HTTPS port (GO-2026-6603: memory exhaustion through trailers,
  GO-2026-6611: CPU load through repeated window updates, GO-2026-6612:
  flow-control accounting, GO-2026-6617: a crash from an HPACK race). With
  `mtls_enabled: true` (the default) only clients with a valid client
  certificate could reach them; with `mtls_enabled: false` anyone could.
  Caddy's own security fixes in 2.11.8 and 2.11.9 concern features the
  add-on does not use (PHP/FastCGI, `{host}`-based roots, the file matcher,
  rewrites) or are hardening without a known effect here (hop-by-hop
  headers in interim responses from the upstream; conflicting `client_auth`
  between site blocks, which cannot occur with the add-on's one HTTPS
  site).
- Go 1.27.4 for the Caddy build: fixes in net/http and in the Go toolchain;
  none is on a path the add-on uses, the binary is rebuilt with it.
- **FastAPI 0.163.2** (was 0.162.0): GHSA-f56c-v883-vx8r, quadratic
  processing of form parameters. The web interface's forms were affected;
  only Home Assistant administrators reach them (through ingress), and
  Starlette already limited a form to 1,000 fields.
- pydantic 2.14.3 (GHSA-qpmf-fgh3-ff25, GHSA-3r8g-cqwr-jr29) and
  opentelemetry-api 1.45.2 (GHSA-mf5v-w3w3-f6cg): the affected features
  are not used by the add-on.
- OpenSSL 3.5.9-r1 (CVE-2026-88822, CVE-2026-88823, CVE-2026-95691,
  CVE-2026-95692, CVE-2026-107496: QUIC, AES-GCM-SIV and CMS - not used by
  the add-on's certificate operations).
- libexpat 2.10.0 (CVE-2026-113351, CVE-2026-115506, CVE-2026-117610,
  CVE-2026-118370: XML parsing) and libffi 3.8.1 (an upstream security
  release for calls made through libffi, e.g. GHSA-fq46-69xf-x5gf), both
  from Alpine: the add-on parses no XML and does not use Python's `ctypes`,
  the only user of libffi in the image.

### Changed

| Component | 2.1.2 | 2.1.3 |
| --- | --- | --- |
| Base image `ghcr.io/hassio-addons/base` | 21.0.10 | 21.0.11 |
| Alpine | 3.24.3 | 3.24.4 |
| OpenSSL * | 3.5.9-r0 | 3.5.9-r1 or newer |
| libexpat * | 2.9.0 | 2.10.0 or newer |
| libffi * | 3.5.2 | 3.8.1 or newer |
| tzdata | 2026e | 2026f |
| Caddy | v2.11.7 | v2.11.9 |
| Go (Caddy build stage) | 1.27.3 | 1.27.4 |
| golang.org/x/net (in Caddy) | 0.59.0 | 0.60.0 |
| `caddy-dns/route53` | v1.6.2 | v1.6.3 (libdns/route53 v1.6.3) |
| `caddy-dns/cloudflare`, `caddy-dns/hetzner/v2` | v0.2.4, v2.0.1 | unchanged |
| FastAPI | 0.162.0 | 0.163.2 |
| pydantic / pydantic-core | 2.14.1 / 2.50.1 | 2.14.3 / 2.50.4 |
| python-multipart | 0.0.32 | 0.0.34 |
| opentelemetry-api, anyio, click | 1.45.1, 4.15.1, 8.5.0 | 1.45.2, 4.16.0, 8.5.1 |
| annotated-doc, typing-inspection | 0.0.5, 0.4.4 | 0.0.6, 0.4.5 |

\* From Alpine's package repository on the day the image is built: the
published image has the version shown or a newer one.

- The image's build log now lists the complete build information of the
  Caddy binary (Go version and every linked module), so each release can be
  checked against advisories.

## [2.1.2] - 2026-10-29

### Changed

- **Buttons are blue in both modes, as on shop.linumiq.com**: in dark mode
  the buttons of the web interface use the shop's lighter blue (`#60A4FA`,
  white text) instead of Anchor Blue; in light mode they stay Anchor Blue.
  Spark Orange stays for warnings such as "Renewal failing". Nothing else
  changes.

## [2.1.1] - 2026-10-28

### Removed

- The "state version N" line under the LinumIQ logo at the bottom of the web
  interface (an internal detail of the add-on's state file, not useful in the
  page). Nothing else changes.

## [2.1.0] - 2026-10-28

The certificate manager in the LinumIQ look. Nothing else changes: no new
options, the same state and certificates.

### Changed

- **LinumIQ look** for the web interface (certificate manager): the brand
  colours (Anchor Blue for buttons and links, Spark Orange for warnings such
  as "Renewal failing"), the brand fonts Roboto (headings) and Inter (text),
  and a light and a dark mode that follow the device's light/dark setting
  (`prefers-color-scheme`). The header shows the add-on's mark instead of an
  emoji, the footer the LinumIQ logo (a link to linumiq.com, opens in a new
  tab) above the state version. Fonts and logo are part of the add-on image
  (the fonts under the SIL Open Font License 1.1, see NOTICE): the web
  interface loads nothing from other hosts, it works offline in the LAN. The
  "Public certificate" card keeps its colour per state (green, orange, red,
  blue).
- **Icon and logo**: new add-on icon and logo in the add-on store (the
  LinumIQ ring with the add-on's symbol, in the brand colours, for light and
  dark backgrounds), replacing the text placeholders.
- One source for the look of both LinumIQ add-ons: `shared/ui` in the
  repository (stylesheet, fonts, logo, page layout), copied into the add-on
  by `scripts/sync-shared.sh` and checked in CI. The web interface's
  `static/style.css` is now `static/shared/linumiq.css` (shared) plus
  `static/app.css` (this add-on's own components), and
  `templates/index.html` extends the shared `templates/_layout.html` (the
  "Public certificate" card `_public_cert.html` stays a partial).
- Layout details: the values in the CA and CRL cards are no longer indented
  by the browser's default 40 px, the client buttons fill the width on
  phones, and every control has a focus ring in the brand blue.

## [2.0.1] - 2026-10-28

Fixes from the first real installation (Home Assistant OS 18.4, Supervisor
2026.10.4): a clean and fast stop, crashes visible to the Supervisor, a quiet
log, and the state of the Let's Encrypt certificate in the web interface and
as a notification.

### Fixed

- **A Caddy crash looked like a normal stop.** When Caddy exited for any
  reason, its s6 `finish` script shut the whole add-on down with exit code 0,
  so the Supervisor showed `stopped` (not `error`) and a Watchdog-enabled
  installation restarted it without ever showing an error. The add-on now
  stops only when Caddy really crashed, with Caddy's exit code (128 + signal
  when it was killed, e.g. 137): the Supervisor logs `App Caddy mTLS Proxy
  exited with non-zero exit code 137` and shows the error. A clean exit of
  Caddy alone (exit code 0) restarts Caddy instead. DOCS.md has a new
  troubleshooting entry for "Start although it is running / restarts by
  itself".
- **Unclean stop.** Every stop logged `s6-supervise cert-monitor: warning:
  finish script lifetime reached maximum value - sending it a SIGKILL`,
  `s6-ipcclient: fatal: unable to connect to .../s6rc-oneshot-runner/s:
  Connection refused` and `s6-rc: warning: unable to stop service
  init-caddy: command exited 111`. Causes: the `finish` scripts of the panel
  and the monitor slept 2 and 5 s (s6 kills a finish script after 5 s), and
  Caddy's `finish` script started a second shutdown (`s6-svscanctl -t`) that
  tore down the s6 supervision tree - the oneshot runner included - while
  s6-rc was still stopping the services. The sleeps and the second shutdown
  are gone: a stop takes about 3 s (was 5 s) without any warning.
- **Log spam.** Caddy's access log (`handled request`, about 1.5 KB per
  request - 692 lines in one minute while the Home Assistant frontend loaded
  through the proxy) is off by default (new option `access_log`); the health
  probes no longer log a line each (Caddy's `admin.api` logger is excluded,
  uvicorn's access log is off unless `log_level` is `debug` or `trace`);
  `openssl ca` no longer prints the "Certificate Details" of every issued
  client certificate (its output is shown only when it fails); the generated
  Caddyfile is formatted (`caddy fmt`), so Caddy no longer warns "Caddyfile
  input is not formatted" twice per start.
- **No information when the Let's Encrypt certificate could not be
  obtained.** See Added.

### Added

- **"Public certificate" card** at the top of the web interface, refreshed
  every 30 s: green with issuer, expiry and days left (and whether Caddy
  serves the certificate on port 443); red "No public certificate yet -
  `<domain>` is not reachable over HTTPS" with Let's Encrypt's last error,
  the result per challenge type and a checklist with the add-on's real host
  ports (router forwards external TCP 80 / 443 to them, the domain resolves
  to the public IP, nothing else answers on those ports, ...) and the hint
  to restart the add-on once fixed; yellow when a valid certificate exists
  but renewing it failed. Caddy writes its certificate events to
  `/data/caddy/log/acme.log` (JSON, 0600, rolled at 1 MB) for this; they
  stay in the add-on log as well.
- **Notification "Caddy mTLS: no public certificate for `<domain>`".** While
  there is no certificate (and during the first 30 minutes after a start)
  the `cert-monitor` service checks every minute; after two minutes without
  a certificate it raises a persistent notification with the last error and
  the checklist, and dismisses it when the certificate exists. The add-on
  log gets one line per change of this state.
- Option **`access_log`** (default `false`): Caddy's access log.

### Changed

- Health check: once a minute after the start period (was 30 s), 15 s
  timeout (was 10 s), unhealthy after 5 failures in a row (was 3); every 5 s
  during the 2-minute start period (`--start-interval`), so the add-on
  reaches the state `started` about 5 s after a start. The Supervisor's
  Watchdog restarts an unhealthy add-on - the probe is more tolerant now.
- `timeout: 60` (was 300): how long the Supervisor waits for a stop before
  it kills the container. Caddy gives open requests at most 10 s on a stop
  or reload (`grace_period`, was unlimited), the web interface 3 s.
- The web interface no longer serves FastAPI's `/openapi.json`.
- `cert-monitor` logs "Initial publication did not reach Home Assistant
  yet" once, not at every retry.

## [2.0.0] - 2026-10-27

Dependency refresh (base image, Python, Caddy and its DNS modules), new
default host ports, the upstream port taken from Home Assistant Core, and
fixes for DNS-01 challenges, for client certificate changes that did not
reach the running proxy and for the client certificate management - revoking,
"Regenerate CA", `client_names`, `client_cert_password`, expiry sensors and
client names (review 2026-10-27: H1, H2, M2-M7, L1).

### Breaking - what a 1.2.x user must know

- **New default host ports: 8080 (HTTP) and 8443 (HTTPS) instead of 80 and
  443.** Since Home Assistant 2026.8, new Home Assistant OS installations
  serve Home Assistant itself on ports 80 and 443, so an add-on cannot
  publish those ports there. Caddy still listens on 80/443 inside the add-on;
  the Caddyfile and the HTTP-to-HTTPS redirect are unchanged. **Installations
  that never customised the add-on's Network settings get the new host ports
  on update** - either set the host ports explicitly in the add-on's
  **Network** settings (`80/tcp` -> 80, `443/tcp` -> 443) *before* updating,
  or change the router's port forwarding afterwards (external TCP 80 -> host
  port 8080, external TCP 443 -> host port 8443). In the LAN the proxy is
  then `https://<domain>:8443`. The add-on log shows the published host
  ports on every start.
- **Hetzner DNS: a different API token.** The Hetzner DNS module moves to v2
  (Hetzner Console zones, Hetzner Cloud API); v1 used the deprecated DNS
  Console API. With `acme_dns_provider: hetzner`, replace `dns_api_token`
  by a Hetzner Cloud API token (Read & Write) of the project that holds the
  zone - see DOCS.md, Hetzner DNS Setup.

### Fixed

- **DNS-01 challenges never got the API token** (review 2026-10-27 H2).
  `init-caddy` exported
  `DNS_API_TOKEN` only in its own (oneshot) process, which does not reach the
  long-running Caddy service: Caddy started with an empty token - with
  Cloudflare it refused to start (`provision dns.providers.cloudflare: API
  token '' appears invalid`, reproduced with the 1.2.7 service script), with
  Route53 / Hetzner it had no credentials. The Caddy service now exports the
  credentials itself (`lib/dns-provider.sh`, shared with `init-caddy`); the
  Caddyfile still holds only `{env.*}` placeholders.
- **Route53 never validated** (review 2026-10-27 H2). The module (v1.6)
  accepts no positional
  argument, so the rendered `dns route53 {env.DNS_API_TOKEN}` failed with
  `wrong argument count`. `dns_api_token` (`ACCESS_KEY_ID:SECRET_ACCESS_KEY`)
  is now split at the first colon into `access_key_id` / `secret_access_key`;
  a token without a colon stops the start with a clear message.
- **Client changes take effect immediately (security; review 2026-10-27
  H1).** After adding,
  revoking or regenerating a client the panel ran `caddy reload`, which
  Caddy skipped (`config is unchanged`: the Caddyfile never changes, only the
  files in `/data/certs/active`). New clients were refused and **revoked or
  superseded certificates were still accepted until the add-on restarted**.
  The reload is now forced (`caddy reload --force`); the smoke test proves it
  with mTLS handshakes before and after each change and with Caddy's log
  (`stopped previous server`, never `config is unchanged`). This applies to
  "Regenerate CA" as well.
- **DNS tokens stay out of the log.** The output of the start-up `caddy
  validate` is printed with the DNS credentials replaced by `<redacted>`: the
  Cloudflare module quotes a token it considers malformed in its error
  message.
- **Default upstream on new Home Assistant OS installations.** With
  `upstream_host: homeassistant` the add-on used port 8123, but new
  installations (2026.8+) serve Core on port 80 (502 Bad Gateway). See
  Changed: `upstream_port`.
- `init-caddy` no longer aborts when `hostname -i` fails (no container
  network; bashio enables `pipefail`) - relevant for tests only.
- **Revoke and Regenerate failed for a certificate without the CA
  database's copy** (review 2026-10-27 M2). The panel revoked
  `ca-db/newcerts/<serial>.pem` and gave up ("Failed to revoke client") when
  that copy was missing, e.g. for certificates issued before 1.2.0. It now
  revokes the client's own `.crt` (`openssl ca -revoke` also takes a serial
  the database does not know yet); the database copy of the serial recorded
  in `state.json` is only the fallback when the `.crt` is missing. Without
  either, the client is still removed from the allowlist and marked revoked,
  with a warning that its serial cannot be listed in the CRL. Revoking a
  client that is already revoked is refused with a message.
- **"Regenerate CA" brought revoked clients back** (review 2026-10-27 M3).
  It re-issued every client in `state.json` - revoked ones included - as
  active, with a new valid bundle. Only active clients are re-issued now;
  revoked clients stay in the list as history (status, serial and reason
  under the old CA; their files are wiped with the rest), and their names
  stay taken.
- **README: the "Revoking Access" steps revoked nothing** (review 2026-10-27
  M4). Deleting the `/config` copy of the certificates and removing names
  from `client_names` left every certificate valid (the CA and the allowlist
  live in the add-on's own storage). The README now describes the panel:
  Revoke for one client, Regenerate CA to invalidate every bundle.
- **`client_names` was honoured only on the very first start** (review
  2026-10-27 M5), although the documentation and the option text say that
  new names are created at start-up. At every start, a listed name that
  `state.json` does not know now gets a client certificate. Removing a name
  revokes nothing (the panel revokes), and a name whose client was revoked
  is skipped with a warning - a revoked name is never issued again.
- **Client names are validated** (review 2026-10-27 L1). The option accepted
  any string: a space dropped the client from the allowlist (unquoted word
  splitting), a `/` stopped the start, a quote reached the inline JavaScript
  of the panel's Revoke button, and the panel accepted `.` and `..`, which
  browsers remove from URLs (such a client could never be revoked). The rule
  is now the same everywhere - 1-64 characters (letters, digits, `.`, `_`,
  `-`), not starting with a dot: the option's schema
  (`match(^[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}$)`), `init-caddy` (an invalid
  name is skipped with a warning instead of stopping the start) and the
  panel. The allowlist is rebuilt from a quoted array, and the Revoke
  confirmation reads the client name from a data attribute.
- **No expiry sensors for client names with `-` or `.`** (review 2026-10-27
  M6), e.g. the panel's own example `alice-phone`: the entity id contained
  the raw name, which Home Assistant rejects (400 "Invalid entity ID"), so
  the monitor logged a warning every interval instead. The entity id now
  uses a slug of the name - lowercase, every run of other characters
  becomes `_`: `alice-phone` -> `sensor.caddy_mtls_client_alice_phone_expiry`;
  names with the same slug are told apart by a short hash suffix. The
  friendly name keeps the raw client name.
- **Changing `client_cert_password` did not re-encrypt existing bundles**
  (security; review 2026-10-27 M7). A `.p12` kept the password it was
  issued with - for the clients created at the first start the public
  default `LinumIQ` - also in the `/config/certs` copy. At every start, the
  bundle of each active client that does not open with the current password
  is now re-exported from the client's key and certificate (one log line per
  bundle, never the password), and the `/config/certs` copy follows.
  openssl gets the password through its environment instead of its command
  line.

### Security

- **Python dependencies without known vulnerabilities**, from a hash-pinned
  `requirements.txt` (`pip --require-hashes --only-binary=:all:`) in a
  virtualenv (`/usr/lib/cert-mgr/.venv`) instead of Alpine's py3 packages:
  FastAPI 0.162.0, Starlette 1.10.0, uvicorn 0.54.0, python-multipart 0.0.32,
  Jinja2 3.1.6. The Alpine 3.23 packages (Starlette 0.47.2, python-multipart
  0.0.20) were affected by GHSA-86qp-5c8j-p5mr (`request.url.path` rebuilt
  from the `Host` header - the panel's `/_health` exemption of the ingress
  allow-list relies on it: with `Host: x/_health?` anything on the hassio
  network could download `.p12` bundles, create clients or wipe the CA;
  review 2026-10-27 M1, reproduced with 0.47.2), GHSA-7f5h-v6xp-fcq8 (Range
  header DoS) and further Starlette / python-multipart advisories; Alpine
  3.24 still ships `py3-starlette` 1.1.0, below the 1.3.1 minimum. Starlette
  1.10.0 closes the `Host` trick: the smoke test sends it to a panel that
  does not allow the caller and gets 403. (The guard itself is unchanged.)
- Caddy 2.11.7 (2.11.6 fixed GHSA-6365-7ppr-5r92, 2.11.7 fixed 2.11.6's
  stream regressions).
- The DNS provider modules are pinned to release tags (they were unpinned:
  every build compiled whatever was newest); Go's checksum database verifies
  them, and the build fails unless Caddy reports the pinned version and
  lists all three modules.
- Revoked client certificates are refused at once (see Fixed).

### Changed

| Component                  | 1.2.7                                   | 2.0.0                                                        |
| -------------------------- | --------------------------------------- | ------------------------------------------------------------ |
| Base image                 | `ghcr.io/hassio-addons/base:20.1.0`     | `ghcr.io/hassio-addons/base:21.0.10`                         |
| Alpine                     | 3.23.4                                  | 3.24.3                                                       |
| Python                     | 3.12.15 (Alpine packages)               | 3.14.8 (virtualenv)                                          |
| OpenSSL                    | 3.5.9                                   | 3.5.9                                                        |
| Caddy                      | v2.10.2                                 | v2.11.7                                                      |
| xcaddy                     | v0.4.4                                  | v0.4.7                                                       |
| Go (Caddy build stage)     | `golang:1.25.1-alpine`                  | `golang:1.27.3-alpine3.24` (pinned by index digest)          |
| `caddy-dns/cloudflare`     | unpinned (newest at build time)         | v0.2.4 (libdns/cloudflare v0.2.2)                            |
| `caddy-dns/route53`        | unpinned (newest at build time)         | v1.6.2 (libdns/route53 v1.6.2)                               |
| `caddy-dns/hetzner`        | unpinned v1 line (v1.0.0, DNS Console)  | `hetzner/v2` v2.0.1 (libdns/hetzner v2.0.1, Cloud API)       |
| libdns                     | v1.x                                    | v1.1.1                                                       |
| FastAPI                    | 0.121.2                                 | 0.162.0                                                      |
| Starlette                  | 0.47.2                                  | 1.10.0                                                       |
| pydantic / pydantic-core   | 2.12.3 / 2.41.4                         | 2.14.1 / 2.50.1                                              |
| uvicorn                    | 0.38.0                                  | 0.54.0                                                       |
| python-multipart           | 0.0.20                                  | 0.0.32                                                       |
| Jinja2                     | 3.1.6                                   | 3.1.6                                                        |
| s6-overlay (base image)    | 3.2.2.0                                 | 3.2.3.2                                                      |
| Default host ports         | 80, 443                                 | 8080, 8443                                                   |
| Default `upstream_port`    | 8123                                    | unset: Home Assistant Core's port (Supervisor), else 8123    |

(1.2.7's Python package versions are those of Alpine 3.23, which a 1.2.7
build gets.)

- **`upstream_port` is optional and has no default.** With
  `upstream_host: homeassistant` and no `upstream_port`, the add-on proxies
  to Home Assistant Core's own port as reported by the Supervisor API (80 on
  new Home Assistant OS installations, 8123 on older ones; 8123 when the API
  is unavailable) and logs the resolved upstream. Options saved before 2.0.0
  may contain `upstream_port: 8123`, which is still honoured. Any other
  `upstream_host` requires `upstream_port` (the start stops with a message).
- `domain` must be a bare host name: a value with a scheme, port or path
  (e.g. `home.example.com:8443`) stops the start with a message - it would
  make Caddy listen on an unpublished container port.
- The s6 `user` bundle moved from `/etc/s6-overlay/s6-rc.d/user` to
  `/etc/s6-overlay/user-bundles.d/user` (s6-overlay 3.2.3.2 in base 21.x
  rewrites a bundle left in `s6-rc.d` at every start); the build fails on a
  base image without `user-bundles.d` (base < 21).
- The panel (uvicorn) and the expiry monitor run with the virtualenv's
  interpreter; pip is removed from it, the code is precompiled and Python
  writes no bytecode at runtime. FastAPI 0.162 adds `opentelemetry-api` as a
  dependency (inactive unless configured).
- `init-caddy` logs the published host ports and a port-forwarding hint on
  every start (from the Supervisor API; warnings when `80/tcp` or `443/tcp`
  is disabled; silent outside Supervisor).
- `HEALTHCHECK` in exec form (hadolint 2.15, DL3025); same probes.
- `client_names` entries must match
  `^[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}$` (see Fixed, L1); Supervisor refuses
  options with any other name.
- Expiry sensors of clients whose name is not already a valid object id
  have a new entity id (see Fixed, M6).
- The libcrypto3/libssl3 lines stay: with base 21.0.10 they are a no-op
  today (the base image pins 3.5.9-r0, the current repository version), but
  keep the build working once Alpine ships a newer OpenSSL than the base
  image was built with.
- File permissions of everything copied into the image are normalised (they
  depended on the build checkout's umask).
- Test-only environment variable `ACME_CA_URL` (replaces the ACME
  directories of Let's Encrypt / ZeroSSL; Supervisor never sets it) - see
  DOCS.md, Running outside Home Assistant.

### Added

- `tests/smoke.sh <image>`: boots the image outside Supervisor without any
  network (panel, certificates and modes, `state.json`, Caddyfile and admin
  API, CRL over plain HTTP and the redirect, mTLS handshakes before and after
  client add / revoke / regenerate, revoking without the CA database's copy
  or without the `.crt`, "Regenerate CA" with revoked clients, invalid
  names, the `.p12` download, the ingress allow-list, two restarts as
  Supervisor does them - new and invalid `client_names`, a changed
  `client_cert_password` - `mtls_enabled: false`, one start per DNS
  provider, log hygiene).
- `tests/apparmor-smoke.sh <image> <apparmor.txt>`: boots the image confined
  by the profile in enforce mode, adds and revokes a client, restarts it with
  a new client name and a new `client_cert_password`, and fails on any
  AppArmor denial (kernel log and audit log).
- `tests/unit/test_monitor.py` (standard library only): entity-id slugs
  checked against Home Assistant's entity id rule, collisions, the
  notification thresholds, one monitor pass against a mocked Supervisor API.
- `requirements.in` / `requirements.txt` (hashes, generated with
  `pip-compile` on CPython 3.14) and a `.dockerignore`.
- DOCS.md: ports section, "Running outside Home Assistant (tests)",
  "Maintainers: Python dependencies".

## [1.2.7] - 2026-05-02

### Changed

- **Responsive, mobile-first web UI for the certificate manager**. The
  ingress panel has been fully redesigned with a clean card-based layout
  that works well on phones, tablets, and desktops. Client certificates
  are now shown as individual cards that stack vertically on small screens
  and expand to a three-column row on wider screens, replacing the
  previous horizontally-scrolling table. Other improvements include CSS
  custom-property design tokens, automatic dark-mode via
  `prefers-color-scheme`, touch-friendly controls (min 2.4 rem tap
  targets), a styled danger-zone disclosure for CA regeneration, improved
  accessible markup (`<dl>` for metadata, `aria-labelledby` on sections),
  and proper word-wrap for long fingerprints / serial numbers.

## [1.2.6] - 2026-05-02

### Added

- **Prominent startup reminder + documentation for HA Core's
  `trusted_proxies`**. Without `http.use_x_forwarded_for: true` and
  `trusted_proxies` covering the add-on's container IP (or the whole
  Supervisor docker network `172.30.32.0/23`), Home Assistant Core
  rejects every request forwarded through this add-on with
  `400 Bad Request`. The add-on now logs a copy-pasteable YAML snippet
  on every start (including the add-on's actual container IP) and the
  `DOCS.md` Installation section calls this out as a required step.

## [1.2.5] - 2026-05-02

### Fixed

- **Plain HTTP requests to the public domain now redirect to HTTPS**
  (308 Permanent Redirect) instead of returning `404 Not Found`. The
  explicit `http://${domain}` site that serves the CRL was previously
  responding 404 to every other path, including `/`, which made the
  add-on look broken when accessed via `http://`. ACME HTTP-01
  challenges are still handled by Caddy automatically and continue to
  work.
- **`cert-monitor` now publishes sensors as soon as Home Assistant
  Core is reachable**, instead of giving up for 6 hours after the
  first attempt. On startup, when the Supervisor proxy returns
  `502 Bad Gateway` (HA Core still booting), the monitor now retries
  with exponential backoff (5s → 10s → … → 5min cap) until the
  first publication succeeds, and only then switches to the
  configured `cert_check_interval_hours` cadence.

## [1.2.4] - 2026-04-30

### Changed

- **Certificate manager UI now shows friendly error and success banners**
  instead of returning a raw JSON `{"detail": "..."}` payload when an
  operation fails or succeeds. All mutation handlers (add / revoke /
  regenerate client, regenerate CA) now redirect back to the dashboard
  with the message rendered as a styled banner inside the ingress iframe.
- **Clearer message when adding a client whose name collides with a
  revoked certificate**: the form now reports
  _"A client named 'X' already exists and is revoked. Choose a different
  name to create a new client."_ instead of the previous opaque
  `client 'X' already exists` JSON error.
- Improved validation messages for empty / too-long / invalid client
  names, missing clients on revoke, regenerating a non-active client,
  and an unconfirmed CA regeneration.

## [1.2.3] - 2026-04-30

### Changed

- **Default option values updated** for the LinumIQ deployment:
  - `ca_country: AT` (was `US`)
  - `ca_state: Styria` (was `State`)
  - `ca_locality: Graz` (was `City`)
  - `ca_organization: LinumIQ` (was `Home Assistant`)
  - `client_cert_password: LinumIQ` (was `changeme`)
- **CA and client certificate validity raised to 300 years**
  (`109575` days, formerly `3650` days for the CA and `1826` days for
  client certs). Certificates issued after upgrading will inherit the
  new validity; existing certificates can be regenerated from the
  cert-manager UI to pick up the new lifetime. Notes:
  - The values remain overridable via the `CA_VALIDITY_DAYS` and
    `CLIENT_VALIDITY_DAYS` environment variables.
  - OpenSSL automatically switches the X.509 `notAfter` field from
    UTCTime to GeneralizedTime for dates beyond 2049, so the resulting
    certificate is RFC-5280 compliant.

## [1.2.2] - 2026-04-30

### Fixed

- **Cert-manager UI no longer breaks out of the Home Assistant ingress
  iframe** after creating, revoking, regenerating or rotating a client
  certificate (or regenerating the CA). The `303 See Other` response
  used a bare absolute `Location: /`, which the browser resolved at the
  HA root and replaced the iframe with the main HA dashboard. The
  redirect now respects the `X-Ingress-Path` header injected by
  Supervisor and points back at the dashboard inside the ingress
  prefix.

## [1.2.1] - 2026-04-30

### Fixed

- **AppArmor profile no longer fails to load on Home Assistant OS.**
  The 1.2.0 profile required AppArmor 4.x (used `abi <abi/4.0>`,
  `io_uring`, bare `capability`, `mount`, `ptrace` and `dbus`), which
  caused Supervisor to reject the profile on stock HA OS with
  `can't load profile ...: exit status 1`. The profile was rewritten
  against the AppArmor 3.x feature set used by mainstream community
  add-ons (explicit capability list, s6-overlay paths, ssl/share/config
  mappings).
- **Add-on linter** rejected the explicit `ingress_port: 8099` in
  `config.yaml` because 8099 is the Supervisor default for that key.
  Removed the redundant declaration.
- **Shellcheck CI job** now also excludes `SC1083` (s6 `finish` scripts
  are execlineb, not shell), `SC1091` (sourced files use absolute
  `/etc/...` paths) and `SC2016` (jq programs intentionally use single
  quotes), all of which are unavoidable in this codebase.

### Removed

- A 2.3 MB `core.5100` core dump was accidentally committed in 1.2.0.
  Removed from the repository and added a `.gitignore` rule for
  `core.*`, `__pycache__/` and `*.pyc`.

## [1.2.0] - 2026-04-29

### Added

- **Certificate Revocation List (CRL) support.** Each issued client
  certificate now carries a `crlDistributionPoints` extension pointing at
  `http://<domain>/mTLS-CA.crl`, and the add-on serves the CRL over plain
  HTTP from a dedicated site block. Revocations are recorded via
  `openssl ca` against an on-disk index database under
  `/data/certs/ca-db/`. The CRL is regenerated on every revocation and on
  every container restart, and Caddy is reloaded in-place via its admin
  API (now bound to `localhost:2019`) so changes take effect without
  dropping connections.
- **Certificate expiration notifications.** A new `cert-monitor` long-run
  service publishes per-certificate sensor entities to Home Assistant
  (`sensor.caddy_mtls_<slug>_expiry`, value = days remaining) via the
  Supervisor REST proxy and raises a persistent notification as the
  certificate crosses one of the configured warning thresholds (default
  30 / 14 / 7 / 1 days). Each (cert, threshold) pair fires at most once
  per cert lifetime; rotating the cert resets the state.
- **Web UI for certificate management.** A new FastAPI app
  (`cert-mgr` long-run, served on the ingress port) exposes a dashboard
  to add new clients, revoke existing ones, regenerate individual
  client certificates, download CA / CRL / `.p12` bundles and (with
  a typed `REGENERATE-CA` confirmation string) perform a full CA
  regeneration. All mutations call into the same shell helper library
  used by the init oneshot, then trigger `caddy reload` so the active
  client allowlist is updated atomically.
- New options: `cert_expiry_warn_days` (list of int, default
  `[30, 14, 7, 1]`) and `cert_check_interval_hours` (1-168, default 6).
- New Supervisor capabilities: `hassio_api: true` and
  `homeassistant_api: true` so the monitor can publish sensor states and
  notifications.

### Changed

- Client certificates are now issued through `openssl ca` with a proper
  serial database and `unique_subject = no`, allowing the same CN to be
  re-issued after revocation.
- The active client allowlist directory (`/data/certs/active/`) now
  contains `.pem` files (Caddy's `verifier leaf folder` loader requires
  this extension; previously `.crt` files were silently ignored).
- `/data/state.json` is the single source of truth for cert metadata,
  notification state and revocation history. It is updated atomically
  under a flock-protected jq pipeline.
- The container `HEALTHCHECK` now probes Caddy's local admin API and the
  cert-mgr ingress port instead of the public HTTPS port, so a
  transient ACME failure (or the brief startup window before the first
  certificate is issued) no longer marks the add-on unhealthy.

### Removed

- The legacy self-signed `mTLS-server.crt` / `/api/server/regenerate`
  code path. Caddy issues its own publicly-trusted TLS certificate via
  ACME, so the additional self-signed server certificate was unused. On
  upgrade, any pre-existing `.server` block is automatically pruned from
  `/data/state.json`.

### Fixed

- Cert metadata in `/data/state.json` now stores `not_before` /
  `not_after` as ISO-8601 UTC timestamps (parsed via
  `openssl x509 -dateopt iso_8601`). The previous busybox `date -d`
  call could not parse OpenSSL's `MMM DD HH:MM:SS YYYY GMT` format and
  emitted "Could not parse" warnings from `cert-monitor`.
- Web UI template referenced legacy field names
  (`state.ca.subject`, `state.server.subject`); now uses the actual
  `subject_cn` keys, so the dashboard renders correctly.
- HA's ingress proxy can forward the iframe root as `GET //` (doubled
  slash), which previously hit FastAPI's 404 handler. The
  `IngressOnlyMiddleware` now collapses runs of leading slashes so the
  dashboard renders on first load.
- Several edge cases in the CRL reason normalisation (`key_compromise`
  vs `keyCompromise`, etc).

## [1.1.1] - 2026-04-29

### Fixed

- AppArmor profile denied the shell interpreter read access to `/init`
  (and other s6-overlay scripts), causing the container to fail at
  startup with `/bin/sh: can't open '/init': Permission denied`. The
  profile now grants `rix` (read + inherited execute) on `/init`,
  `/bin/**`, `/usr/bin/**`, `/usr/sbin/**`, `/usr/lib/bashio/**`,
  `/run/{s6,s6-rc*,service}/**`, `/package/**`, `/command/**`,
  `/usr/bin/caddy` and `/usr/bin/bashio`.

## [1.0.0] - 2026-01-10

### Added

- Initial release of Caddy mTLS Proxy add-on
- Automatic HTTPS via Let's Encrypt
- Mutual TLS (mTLS) client certificate authentication
- Support for multiple client certificates
- Web interface for certificate download with QR codes
- DNS-01 ACME challenge support:
  - Cloudflare
  - AWS Route53
  - Hetzner DNS
- Configurable CA certificate subject fields
- Certificate files accessible via addon_config mapping
- Comprehensive documentation and import guides for:
  - iOS / iPadOS
  - Android
  - Windows
  - macOS
  - Linux (Firefox/Chrome)

### Security

- Client certificates use ECDSA (prime256v1) for strong security
- Certificates valid for 100 years
- Ingress endpoint restricted to Home Assistant proxy IP
- Admin API disabled for security

## [Unreleased]

### Planned

- Certificate revocation list (CRL) support
- Additional DNS providers based on user requests
- Certificate expiration notifications
- Web UI for certificate management (regenerate, revoke individual certs)

## [1.1.0] - 2026-04-28

### Changed

- **BREAKING (build only):** migrated to S6-overlay v3 on
  `ghcr.io/hassio-addons/base`; the single `run.sh` was split into a
  supervised `init-caddy` oneshot and a `caddy` longrun service. Existing
  add-on configuration and certificates under `/data` are preserved.
- Caddy is rebuilt against pinned `xcaddy v0.4.4` and Caddy `v2.10.2`.
- Default certificate validity reduced from 100 years to:
  - CA: 10 years (3650 days)
  - Server: 1 year (365 days)
  - Client: 5 years (1826 days)
- Server certificate now carries `extendedKeyUsage = serverAuth` only;
  client certificates carry `clientAuth` only.

### Added

- New `log_level` option (mapped onto Caddy's log level).
- Watchdog (`tcp://[HOST]:[PORT:443]`) so the Supervisor restarts the add-on
  if Caddy stops listening on 443.
- AppArmor profile (`apparmor.txt`) shipped and enabled by default.
- `/_health` endpoint on the ingress server (port 8099, internal only) for
  diagnostics.
- Pre-built multi-arch images published to
  `ghcr.io/linumiq/{arch}-addon-caddy-mtls`.
- `panel_admin: true` so the certificate download panel is restricted to
  Home Assistant administrators.
- Apache-2.0 license + `NOTICE` file at the repository root.

### Fixed

- Certificate generation errors are now caught and surfaced via
  `bashio::exit.nok` instead of silently continuing.
- DNS provider value is validated against the allowed list before any
  Caddyfile is rendered.
- Generated Caddyfile is validated with `caddy validate` before the longrun
  service is started, so invalid configuration aborts startup with a clear
  message instead of a service-restart loop.
- HTML on the certificate download page now escapes the configured domain
  and client names.

### Security

- Private key files (`*.key` and `*.p12`) are written with mode `600`.
- Pre-built images are pushed to GHCR over an authenticated workflow.
- Removed legacy `/run.sh`; entrypoint is the s6-overlay supervisor only.
