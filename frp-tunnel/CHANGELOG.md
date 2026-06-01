# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
