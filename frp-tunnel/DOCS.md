# FRP Tunnel - Documentation

This add-on runs the upstream `frpc` client (pinned to v0.65.0) inside a
Home Assistant add-on container. It opens a single outbound TCP control
connection to a remote `frps` server, registers one HTTP proxy bound to
`<subdomain>.<server_addr>`, and forwards public requests back to your
local Home Assistant instance.

It is designed to be paired with the LinumIQ tunneling service
(`linumiq.net`), where the frps auth plugin validates the per-tunnel
token against the central database and rejects any attempt to claim a
subdomain you do not own. It will also work against any standard frps
server that accepts the same token format.

## Configuration

| Option        | Type             | Default         | Description                                                                                       |
| ------------- | ---------------- | --------------- | ------------------------------------------------------------------------------------------------- |
| `server_addr` | string           | `linumiq.net`   | Hostname or IP of the frps server.                                                                |
| `server_port` | port (1-65535)   | `7000`          | TCP control port of frps.                                                                         |
| `token`       | password         | _required_      | Per-tunnel token. Get this from the LinumIQ dashboard after claiming a subdomain.                 |
| `subdomain`   | string           | _required_      | The subdomain you claimed. 3-32 chars, lowercase a-z, 0-9, '-' (not starting/ending with '-').    |
| `local_host`  | string           | `homeassistant` | Hostname/IP of the service to expose.                                                             |
| `local_port`  | port (1-65535)   | `8123`          | Port of the service to expose.                                                                    |
| `log_level`   | enum             | `info`          | frpc log verbosity: `trace`, `debug`, `info`, `warn`, `error`.                                    |

The schema rejects malformed subdomains via a regex `match()` constraint,
and the service script re-validates the same regex at startup so a bad
value can never reach `frpc` even if the schema is bypassed.

## Generated `frpc.toml`

The add-on regenerates `/data/frpc.toml` from the options on every start
(any manual edits are lost). The rendered file looks like this:

```toml
serverAddr = "linumiq.net"
serverPort = 7000
loginFailExit = false

# The frps auth HTTP plugin reads the per-user token from metadatas.token.
# Do NOT use [auth] method = "token" — that field is not seen by the plugin.
[metadatas]
token = "<your token>"

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

The `proxy_name` must equal the claimed subdomain - the frps auth plugin
enforces this on the `NewProxy` op.

## Troubleshooting

- **`auth webhook denied`** in the add-on log: the token is wrong,
  inactive, or does not match the subdomain. Re-copy the token from the
  dashboard.
- **`start proxy success`** but the public URL returns 502: Home
  Assistant is not reachable on `local_host:local_port` from inside the
  add-on. Check that `local_host` resolves (`homeassistant` only works
  on the Supervisor network).
- **Frequent reconnects**: increase `log_level` to `debug` and check
  network connectivity to `server_addr:server_port`.
