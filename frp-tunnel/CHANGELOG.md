# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
