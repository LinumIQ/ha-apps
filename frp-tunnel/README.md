# FRP Tunnel for Home Assistant

[![Home Assistant Add-on](https://img.shields.io/badge/Home%20Assistant-Add--on-blue.svg)](https://www.home-assistant.io/addons/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](../LICENSE)

A Home Assistant add-on that runs the upstream
[`fatedier/frp`](https://github.com/fatedier/frp) **client** (`frpc`) to
expose your local Home Assistant instance over a persistent reverse tunnel
to a remote frps server — by default the LinumIQ tunneling service at
`linumiq.net`.

## Features

- **Zero-config pairing**: Open the ingress panel, click a button, approve
  in your browser — done. No manual tokens or subdomain config.
- **Outbound-only, TLS-encrypted connection** to frps (no inbound
  port-forwarding required); the frps certificate is **verified** against the
  certificate authority provided by your LinumIQ account's server.
- **Least privilege**: frpc runs as an unprivileged user under a strict
  AppArmor profile; pairing secrets are never put into Home Assistant backups.
- **Stable public URL**: `https://<subdomain>.linumiq.net`.
- **Server-managed settings**: the frps endpoint and public domain come from
  your LinumIQ account and are re-applied on every restart or refresh.
- **Ingress management panel**: view connection status and the paired
  account, change subdomain, refresh the tunnel configuration, unpair — all
  from within Home Assistant.
- **Pinned upstream `frpc` v0.65.0**.
- **s6-overlay v3** with auto-restart on crash.
- **Tested**: unit tests, an AppArmor smoke test and an end-to-end harness
  that pairs a real container against a LinumIQ stack (`tests/`).

## Quick Start

1. Sign up at [app.linumiq.net](https://app.linumiq.net) (or create an
   account during the pairing flow).
2. Add this repository to your Home Assistant add-on store and install
   the **FRP Tunnel** add-on.
3. Open the add-on's **Web UI** from the sidebar.
4. Click **Start Pairing**, then open the link shown on screen.
5. Sign in and approve the device.
6. Your Home Assistant is now reachable at your public URL!

See [DOCS.md](DOCS.md) for the full configuration reference and
troubleshooting guide.
