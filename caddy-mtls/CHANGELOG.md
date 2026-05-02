# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
