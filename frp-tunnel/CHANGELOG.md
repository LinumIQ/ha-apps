# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0] - 2026-10-13

Security release (platform audit 2026-10-12: H4, M3, M4, add-on lows; add-on
review 2026-10-13: M-2, L-6, L-8 to L-11).

### Breaking - what a 2.1.x user must know

- **The tunnel server's certificate is verified** (new advanced option
  `verify_server`, on by default). With a LinumIQ server that provides its
  certificate authority (contract v2.2) nothing needs to be done - the CA is
  pinned on the next start or **Refresh tunnel config**. If frpc then logs
  `certificate verify failed` / `x509: ...`, see DOCS.md, Troubleshooting.
  Only an explicit `verify_server: false` disables verification.
- **Verification fails closed.** Once the server has sent a CA, frpc is never
  started unverified: if the pinned CA no longer passes validation, the last
  valid one (`/data/frps-ca.pem`) is used, and without any valid CA frpc is
  not started at all (red banner in the panel; **Refresh tunnel config**
  fetches the current CA).
- **The tunnel token must be URL-safe** (`A-Z a-z 0-9 . _ ~ -`, 8-256
  characters). A token with other characters (or a server sending one) is
  treated as "not paired"; **Refresh tunnel config** fetches a new one. Tokens
  issued by the LinumIQ server (hex) are unaffected.
- **Pairing data is excluded from Home Assistant backups** (`backup_exclude`):
  the state file with the device and tunnel tokens, `frpc.toml`, the pinned CA
  and a pairing in progress. A restored backup starts **unpaired** - pair
  again and remove the old device in your LinumIQ account.
- Requests that change state (pairing, refresh, subdomain change, unpair) must
  be same-origin. Nothing changes in the Home Assistant UI; scripts that call
  the panel must send `Sec-Fetch-Site: same-origin`.
- The panel answers only the Supervisor's ingress proxy (172.30.32.2) by
  default - no longer loopback. Tooling inside the container (outside
  Supervisor) must set `ALLOWED_INGRESS_IPS` explicitly.
- `frpc.toml` is now `root:frpc` mode 640 (frpc runs as the unprivileged user
  `frpc`); the unused `addon_config` folder mapping was removed.
- Upgrading from 2.0.x: the notes of 2.1.0 below still apply - in particular
  `log_level: warn` must be changed to `warning`.

### Security

- **frps is authenticated (H4).** The server-provided `server_ca_pem` is
  accepted only if it consists of 1-8 PEM `CERTIFICATE` blocks, each exactly
  one DER-encoded X.509 **v3** certificate (no trailing bytes; OpenSSL's
  re-encoding must be byte-identical) with the basicConstraints extension
  `cA: TRUE` - private keys, leaf certificates, v1 roots, certificates
  without basicConstraints and junk are rejected. It is re-encoded, persisted
  in the state and written to `/data/frps-ca.pem` (atomic, `root:frpc` 0640).
  `frpc.toml` pins it with `transport.tls.trustedCaFile` and
  `transport.tls.serverName` (`server_name`, else `server_addr`). A response
  without a CA, with an invalid one, or with one that is expired / not yet
  valid while the pinned one is current never replaces or removes a pinned
  CA (no silent downgrade); the panel warns instead. Without any CA (older
  servers) or with `verify_server: false` the panel shows a permanent warning
  and the renderer logs one on every start.
- **Verification fails closed (L-9).** The CA is re-validated on every render.
  A pinned CA that fails (tampered state file, or a CA a laxer validator had
  accepted) falls back to the last valid CA frpc was given
  (`/data/frps-ca.pem`, yellow banner); with no valid CA at all - also when
  the server sent a CA but never a valid one (`server_ca_required`) - the
  renderer removes `frpc.toml`, exits 4 and the frpc service does **not**
  start frpc (red banner). Previously such a CA silently downgraded frpc to an
  unverified connection.
- **"Verified" means frpc logged in with the pinned CA (L-10).** frpc's output
  now passes through a log watcher (`frpclog.py`, unchanged in the add-on log)
  that records login results per configuration fingerprint
  (`/run/frp-mgr/frpc-status.json`). The panel shows *certificate verified*
  only after `login to server success` with exactly the current `frpc.toml` +
  CA; until then *waiting for frpc to log in*, and a red banner when logins
  with the pinned CA fail. Expired / not-yet-valid CAs are flagged (red when
  no certificate of the bundle is currently valid).
- **No Go-template injection into frpc (M-2).** frpc renders its whole
  configuration file as a Go `text/template` with the process environment as
  `.Envs`, and frpc inherited the add-on environment incl. `SUPERVISOR_TOKEN`:
  a tunnel token such as `{{ .Envs.SUPERVISOR_TOKEN }}` from a malicious or
  compromised backend (or `app_base` override) would have been expanded and
  sent to frps. The tunnel token is now restricted to `[A-Za-z0-9._~-]{8,256}`
  (the device token, only ever an HTTP bearer, keeps its header-safe rule);
  every string written into `frpc.toml` (server address, server name, token,
  subdomain, domain, local host, CA path, log level) is checked once more for
  `{{`, `}}` and backticks before rendering, and so is the whole file.
- **frpc runs with a scrubbed environment.** The frpc service starts it with
  `env -i PATH=/usr/bin:/bin HOME=/data [TZ]`, so frpc never sees
  `SUPERVISOR_TOKEN` or any other add-on variable (verified by the E2E
  harness via `/proc/<pid>/environ`).
- **Ingress allow-list without loopback (L-8).** `ALLOWED_INGRESS_IPS`
  defaults to `172.30.32.2` only: the unprivileged frpc user (or any other
  process in the container) can no longer drive the panel through
  `127.0.0.1:8099`. Loopback is accepted only when configured explicitly
  (E2E harness, smoke test - never under Supervisor).
- **Backend responses are size-limited (L-11).** The panel reads at most
  256 KiB of a device-API response; a larger one is rejected (error bodies are
  cut).
- **Ingress allow-list bypass fixed (M3).** The `/_health` exemption, which
  compared Starlette's `request.url.path` (rebuilt from the `Host` header,
  GHSA-86qp-5c8j-p5mr), is gone; a pure ASGI guard in front of every route
  (static files and 404s included) decides from the TCP peer only, and uvicorn
  runs with `--no-proxy-headers`. Regression tests send crafted `Host`
  headers.
- **Python dependencies without known vulnerabilities.** The panel now runs on
  plain Starlette 1.7.0 (FastAPI and pydantic removed) with python-multipart
  0.0.32, uvicorn 0.54.0 and Jinja2 3.1.6, installed from a hash-pinned
  `requirements.txt` (`pip --require-hashes --only-binary=:all:`) into a
  virtualenv instead of Alpine's py3 packages (Starlette 0.47.2: 5 advisories,
  python-multipart 0.0.20: 7 advisories, incl. the Range-header DoS).
- **CSRF protection for the panel.** Every POST must carry
  `Sec-Fetch-Site: same-origin` or a matching `Origin`.
- **Pairing codes stay out of URLs and logs (M4).** The code is no longer put
  into the redirect URL (`?ok=Pairing code ready: ...`, which also ended up in
  uvicorn's access log) nor into the add-on log; it is shown in the page body
  only, with an anti-phishing hint. The status card shows the masked e-mail of
  the paired account ("Paired with g\*\*\*@linumiq.com", from the server's
  `account_email_masked`), so a device paired with a foreign account is
  noticed.
- **AppArmor least privilege.** No `file,` catch-all, no `sys_admin`,
  `sys_ptrace`, `dac_override`, `dac_read_search` or `fsetid`; explicit rules
  for s6-overlay, bashio, the Python virtualenv, frpc and `/data`; signals and
  ptrace reads only within the add-on. Verified under enforcement (full E2E
  run and a CI smoke test with zero denials).
- **frpc runs unprivileged** (`s6-setuidgid frpc`); it cannot read the state
  file with the device token.
- `X-Ingress-Path` is validated before it is used in a redirect (no
  scheme-relative or dot-segment paths).
- File permissions of everything copied into the image are normalised (they
  depended on the build checkout's umask).

### Added

- Advanced option `verify_server` (bool, default on).
- **Automatic tunnel refresh (L-6).** A background thread of the panel
  re-fetches `GET /api/device/tunnel` exactly like **Refresh tunnel config**:
  at start-up, every 12-24 h (random jitter; retried after 1 h when the
  backend is unreachable) and after 3 consecutive frpc login failures with
  the current configuration (TLS verification or authentication - e.g. a CA
  or token rotated server-side; network errors do not count; at most every
  10 min, backing off to 6 h). This also keeps the device's `last_used_at`
  fresh against the server's 180-day inactivity expiry.
- Panel: TLS state of the tunnel server (verified for `<server_name>` after
  frpc's login, CA subject and expiry, or a warning/error), the paired
  account, warnings when the server stops sending its CA, sends an invalid
  one, or the pinned CA expired, and the last automatic refresh.
- `GET /api/status`: `tls_mode` (`verified`, `unverified`, `disabled`,
  `blocked`), `tls_verified`, `tls_login`, `frpc_logged_in_at`, `server_name`,
  `server_ca`, `tls_errors`, `tls_warnings`, `auto_refresh`,
  `account_email_masked`.
- E2E harness: `E2E_FRPS_CA_FILE` (asserts the pinned CA, `trustedCaFile` /
  `serverName`, a verified login and - `E2E_TLS_NEGATIVE` - that frpc refuses
  a certificate for the wrong name), `E2E_FRPS_SERVER_NAME`,
  `E2E_ACCOUNT_EMAIL_MASKED`, `E2E_CREATE_ARGS` (e.g. an AppArmor profile),
  and checks for CSRF, the crafted-`Host` bypass, pairing-code hygiene and the
  unprivileged frpc; frpc's environment (a dummy `SUPERVISOR_TOKEN` must not
  reach it), the default allow-list (a second container: user `frpc` gets 403
  on `127.0.0.1:8099`), `tls_verified` only after the verified login, the
  red `tls_login=failed` state with a wrong `serverName`, and fail-closed
  (no valid CA: frpc not started, `tls_mode=blocked`).
- `tests/apparmor-smoke.sh`: boots the image confined by `apparmor.txt` and
  fails on any denial (run in CI); also checks the frpc log watcher.

### Changed

- The panel's Python dependencies come from `requirements.txt` (hashes) in a
  virtualenv at `/usr/lib/frp-mgr/.venv`; Python writes no bytecode at runtime.
- Unit tests: `FRP_TESTS_REQUIRE_PANEL=1` replaces `FRP_TESTS_REQUIRE_FASTAPI`
  (still accepted).
- AppArmor: processes may read `/proc/<pid>/environ` of their own uid (the
  E2E harness checks frpc's scrubbed environment through it; nothing new is
  exposed).
- Repository: Dependabot also updates the panel's pip requirements
  (`requirements.in` -> hashed `requirements.txt`) and the Dockerfiles' base
  images; the Builder workflow also rebuilds on `.dockerignore` changes and
  rebuilds every add-on when the workflow itself changes.

## [2.1.0] - 2026-10-12

### Breaking - what a 2.0.x user must adjust

The option schema is stricter. Nothing changes for installations that only
set `log_level` to something other than `warn` and leave the advanced options
empty; no re-pairing is needed in any case. Otherwise:

- `log_level: warn` - select `warning`. Supervisor refuses `warn` (and in
  2.0.x it already broke the start).
- `server_addr`, `local_host` (if set) - only letters, digits, `.`, `-` and
  `:` are accepted by Supervisor: replace values containing an underscore
  (e.g. Docker names like `my_service`), a space, `/`, `%` or a scheme
  (`https://...`) by a DNS name without `_` or the IP address. Values that
  pass the schema but are not a host name / IP literal (a `:port` suffix, a
  trailing dot, `a..b`, a label starting/ending with `-`) are ignored by the
  add-on with a panel banner - remove the port (use `server_port` /
  `local_port`) or fix the name.
- `domain_base` (if set) - Supervisor requires at least two dot-separated
  labels of letters, digits and `-`: no leading `*.` or `.`, no trailing `.`,
  no `_`. An IP address, an all-numeric last label or a label starting/ending
  with `-` is ignored by the add-on (banner).
- `app_base`, `api_base` (if set) - URLs with user info (`user:pw@`), a
  query, a fragment or characters outside RFC 3986 are ignored by the add-on
  (banner); an invalid `app_base` blocks pairing, refresh and subdomain
  changes until it is fixed (no silent fallback to production).

`server_port`, `local_port` and empty options are unaffected. See DOCS.md,
"Upgrading from 2.0.x".

### Security

- The pairing panel validates the complete `POST /api/device/code` response
  before storing or rendering it (previously a malicious or compromised
  backend - or anyone able to tamper with a plain-http `app_base` - could
  inject script into the Home Assistant ingress page through the
  verification link or the polling interval): `user_code` `XXXX-XXXX`,
  URL-safe `device_code`, integer `interval` 1-60 s and `expires_in`
  1-3600 s, and verification links that are https (http only for an http
  `app_base`) on exactly `app_base`'s host. Anything else rejects the pairing
  with a clear error. A stored pairing from an older version is re-validated
  before it is shown. Templates keep autoescaping on; the interval reaches
  JavaScript only via `|int|tojson`.
- HTTP redirects are no longer followed (urllib would have replayed the
  device token's `Authorization` header to the redirect target); a 3xx is
  reported as an error. A malformed device token is refused instead of sent.
- Backend error texts and other untrusted strings are sanitised before they
  reach a log line or a banner (CR/LF, control and bidi characters removed,
  length-limited) and known secrets are redacted - an invalid header value
  could previously echo the device token into the log and the panel.
- Host validation rejects IPv6 zone IDs (`fe80::1%...`, Python accepts any
  text after `%`); base URLs with user info are rejected.
- frpc is started only from a valid pairing: the frpc service runs frpc only
  when the renderer exits 0, deletes a leftover `frpc.toml` when the state is
  missing, corrupt or incomplete, and shares a lock with the panel. Unpair
  removes the state first, stops frpc and waits, then removes `frpc.toml`,
  and reports a failed server-side revocation instead of claiming success.
- The `frpc` release tarball is verified against a SHA-256 pinned per
  architecture in the Dockerfile (build fails on mismatch).

### Added

- **Server-provided tunnel settings** (dashboard contract v2.1): the
  `server_addr`, `server_port` and new `domain_base` values returned by
  `GET`/`POST /api/device/tunnel` are validated and persisted in
  `/data/frp-state.json` and used for `frpc.toml`. Precedence per setting:
  add-on option (only when explicitly set) > server-provided value > built-in
  default. Servers that do not return `domain_base` keep working
  (`domain_base` then falls back to `server_addr`, as before).
- **Refresh tunnel config** action in the panel: re-fetches subdomain, token
  and server settings from the account and restarts frpc only if something
  changed. The panel also performs this refresh once in the background on
  every add-on start (best effort), so a token rotated from the dashboard or a
  moved frps endpoint is picked up automatically.
- `GET /api/status` (ingress only): machine-readable panel state without any
  secrets (used by the E2E harness).
- "Choose a subdomain" card when the device is approved but the account has no
  tunnel yet (previously a dead end).
- End-to-end harness `tests/e2e/run.sh` that runs the add-on image outside
  Supervisor against a real (or dev) LinumIQ stack, plus unit tests under
  `tests/unit/`. CI runs them on the host and - including the FastAPI panel
  flows - inside the freshly built amd64 image; shellcheck now also covers the
  s6 `run`/`finish` scripts.
- "Invalid add-on configuration" banner (and `option_errors` in
  `GET /api/status`): options that fail the add-on's own validation are no
  longer ignored silently.

### Changed

- `frpc.toml` is now re-rendered from the persisted state on **every frpc
  (re)start** by `/usr/lib/frp-mgr/config.py` instead of being written only
  once at pairing time; manual edits are overwritten. The frp tunnel token is
  now stored in the state file (chmod 600) - existing 2.0.x installs are
  migrated automatically from their `frpc.toml`, no re-pairing needed.
- The frpc <-> frps connection explicitly sets `transport.tls.enable = true`
  (frpc >= 0.50 already defaulted to TLS; frps accepts TLS clients by default).
- frpc's log level now follows the `log_level` option (was always `info`).
- Add-on options are read from `/data/options.json` instead of through
  `bashio::config`, which needs the Supervisor API; the image now also runs
  outside Supervisor (E2E tests).
- The device token is persisted as soon as it is issued, so a failing tunnel
  fetch right after approval can be recovered with **Refresh** instead of
  requiring a new pairing.
- Backend errors (e.g. `'<name>' is reserved`) are shown verbatim; the local
  reserved-subdomain pre-check matches the server's built-in list.
- Stricter option schema for `log_level`, `server_addr`, `domain_base` and
  `local_host` (see "Breaking" above); every option and server value is
  validated again before it is written to `frpc.toml`.
- "frpc status" only reports `running` when the frpc process itself is up,
  and it is reported in every state (it used to say `stopped` whenever the
  device was not paired, even if frpc was running).

### Fixed

- `log_level: warn` (offered by the 2.0.x schema) made the add-on fail to
  start, because the base image only knows `warning`. The option now offers
  the base image's levels (`trace`, `debug`, `info`, `notice`, `warning`,
  `error`, `fatal`); if you had picked `warn`, select `warning`.
- A pairing poll no longer stops on a transient network error.
- After unpairing (or with a `frpc.toml` left over without a valid state
  file) frpc could keep or start running with the old token while the panel
  showed "stopped".

## [2.0.1] - 2026-06-01

### Added

- `domain_base` advanced override: the public tunnel hostname suffix
  (`subdomain.<domain_base>`) can now be set independently of the frps
  control address (`server_addr`). Defaults to `server_addr`, so production
  behaviour is unchanged; useful for dev stacks where the public domain
  (e.g. `dev.linumiq.net`) differs from the frps control host.

## [2.0.0] - 2026-06-01

### Added

- **Browser-based device pairing** via OAuth2 Device Authorization Grant.
  No more manual token/subdomain configuration — open the ingress panel,
  click "Start Pairing", approve the device in your browser, and the
  tunnel auto-configures.
- **Ingress management panel** (FastAPI + Jinja2) served on the
  Supervisor ingress port. Shows connection status, public URL, frpc
  health, and provides controls to change subdomain or unpair.
- New `frp-mgr` s6 service running the FastAPI panel alongside frpc.
- Auto-polling JavaScript in the pairing UI polls the token endpoint
  until the user approves, then writes `/data/frpc.toml` and starts frpc
  automatically.
- Advanced override options for development/E2E testing:
  `app_base`, `api_base`, `server_addr`, `server_port`, `local_host`,
  `local_port`.

### Changed

- **BREAKING**: Removed user-facing `token`, `subdomain`, `server_addr`,
  `server_port`, `local_host`, `local_port` options. Tunnel configuration
  is now driven entirely by the device-authorization flow via the ingress
  panel.
- `frpc/run` now waits for `/data/frpc.toml` to exist before starting
  (no more blocking on missing config).
- `frpc/finish` no longer brings down the whole add-on container; it
  restarts frpc after a short delay.
- Python dependencies added: `py3-fastapi`, `py3-jinja2`,
  `py3-python-multipart`, `uvicorn` (Alpine packages, no pip).
- AppArmor profile extended to allow Python execution.

## [1.0.0] - 2026-05-21

### Added

- Initial release. Wraps upstream `frpc` v0.65.0 in a Home Assistant
  add-on. Renders `/data/frpc.toml` from the add-on options
  (`server_addr`, `server_port`, `token`, `subdomain`, `local_host`,
  `local_port`, `log_level`) and runs a single long-lived `frpc`
  process under s6-overlay v3. Designed to register with the LinumIQ
  tunneling service (frps + auth-webhook), but works with any frps
  instance that accepts the token format produced by the dashboard.
