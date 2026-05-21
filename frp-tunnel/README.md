# FRP Tunnel for Home Assistant

[![Home Assistant Add-on](https://img.shields.io/badge/Home%20Assistant-Add--on-blue.svg)](https://www.home-assistant.io/addons/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](../LICENSE)

A Home Assistant add-on that runs the upstream
[`fatedier/frp`](https://github.com/fatedier/frp) **client** (`frpc`) to
expose your local Home Assistant instance over a persistent reverse tunnel
to a remote frps server - by default the LinumIQ tunneling service at
`linumiq.net`.

## Features

- Outbound-only connection (no inbound port-forwarding required)
- Single per-tunnel **token** authenticated by the frps auth plugin
- Stable public URL: `https://<subdomain>.linumiq.net`
- Pinned upstream `frpc` v0.65.0
- s6-overlay v3 with auto-restart on crash

## Quick Start

1. Sign up at `https://app.linumiq.net`, claim a subdomain, and copy
   the generated 64-char token.
2. Add this repository to your Home Assistant add-on store and install
   the **FRP Tunnel** add-on.
3. Fill in the options:
   ```yaml
   server_addr: linumiq.net
   server_port: 7000
   token: <paste the 64-char token>
   subdomain: <your claimed subdomain>
   local_host: homeassistant
   local_port: 8123
   log_level: info
   ```
4. Start the add-on. The log should show `start proxy success`.
5. Visit `https://<subdomain>.linumiq.net` from anywhere.

See [DOCS.md](DOCS.md) for full configuration reference.
