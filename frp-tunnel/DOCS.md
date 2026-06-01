# FRP Tunnel - Documentation

This add-on exposes your local Home Assistant instance to the public
internet via a persistent reverse tunnel (`frpc`) connected to the
LinumIQ tunneling service at `linumiq.net`.

**No manual tokens or configuration files are needed.** The add-on
includes an ingress management panel that walks you through a secure
browser-based device-pairing flow (OAuth2 Device Authorization Grant).
Once paired, your Home Assistant is reachable at
`https://<subdomain>.linumiq.net`.

## Quick Start

1. Install the **FRP Tunnel** add-on from the add-on store.
2. Open the add-on's **Web UI** (the "FRP Tunnel" entry in the sidebar).
3. Click **Start Pairing**.
4. A pairing code (e.g. `XXXX-XXXX`) and a link appear. Open the link in
   any browser.
5. Sign in to your LinumIQ account (or create one via the signup page).
6. Approve the device when prompted.
7. Return to the add-on panel — your tunnel is live!

You can change the subdomain or unpair the device from the same panel
at any time.

## How It Works

- The ingress panel calls `POST /api/device/code` on the LinumIQ web app
  to obtain a per-session device code and user-facing verification code.
- You approve the device in your browser at the verification URL.
- The panel polls `POST /api/device/token` with the device code until
  the backend returns a long-lived `device_token`.
- The panel then fetches the tunnel configuration (`GET /api/device/tunnel`
  with the device token) — subdomain, frp tunnel token, server details.
- The panel writes a complete `/data/frpc.toml` and triggers `frpc` to
  start.
- `frpc` connects to the remote `frps` server, authenticates with the
  per-tunnel token, and registers the HTTP proxy under your subdomain.

## Generated `frpc.toml`

The panel generates `/data/frpc.toml` automatically. Example:

```toml
serverAddr = "linumiq.net"
serverPort = 7000
loginFailExit = false

[metadatas]
token = "<per-tunnel token>"

[log]
to = "console"
level = "info"

[[proxies]]
name = "<your subdomain>"
type = "http"
customDomains = ["<your subdomain>.linumiq.net"]
localIP = "homeassistant"
localPort = 8123
```

The file is owned by the add-on and chmod 600. Do not edit it by hand;
use the panel to change the subdomain or unpair.

## Configuration Options

### User-facing

| Option      | Type | Default  | Description                                       |
| ----------- | ---- | -------- | ------------------------------------------------- |
| `log_level` | enum | `info`   | frpc log verbosity: `trace`, `debug`, `info`, `warn`, `error`. |

### Advanced (development / E2E testing)

These are optional overrides that let you point the add-on at a
development or staging backend. In production you should leave them
unset — the defaults point at the live LinumIQ service.

| Option        | Type   | Production Default                  | Description                      |
| ------------- | ------ | ----------------------------------- | -------------------------------- |
| `app_base`    | URL    | `https://app.linumiq.net`           | Web app for browser pairing.     |
| `api_base`    | URL    | `https://api.linumiq.net`           | Backend API for device flow.     |
| `server_addr` | string | `linumiq.net`                       | frps control hostname.           |
| `server_port` | port   | `7000`                              | frps control port.               |
| `domain_base` | string | `linumiq.net`                       | Public domain suffix for the tunnel host (`<subdomain>.<domain_base>`). Defaults to `server_addr`; only differs when the public vhost and frps control endpoint live on separate hosts/ports (e.g. dev). |
| `local_host`  | string | `homeassistant`                     | Local service hostname.          |
| `local_port`  | port   | `8123`                              | Local service port.              |

## Troubleshooting

- **Pairing link doesn't open**: The link opens `app.linumiq.net`. Make
  sure your browser has internet access. If you're on a restricted
  network, type the verification URL manually.
- **"authorization_pending" for a long time**: The pairing code expires
  after a few minutes. Click **Restart Pairing** to get a fresh code.
- **"no tunnel found" after approving**: This is unusual — the backend
  should auto-create a tunnel on first pairing. Try clicking **Change
  Subdomain** to pick one manually.
- **Public URL returns 502**: Home Assistant Core is not reachable at
  the configured `local_host:local_port` from inside the container.
  Verify `local_host` resolves (`homeassistant` works on the Supervisor
  network; if you are using a different setup, set the advanced override).
- **Frequent frpc reconnects**: Check network connectivity to
  `server_addr:server_port`.
