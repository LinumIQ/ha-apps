# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
