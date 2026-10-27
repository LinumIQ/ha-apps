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
7. Return to the add-on panel - your tunnel is live!

You can change the subdomain, refresh the tunnel configuration or unpair
the device from the same panel at any time.

## How It Works

- The ingress panel calls `POST /api/device/code` on the LinumIQ web app
  to obtain a per-session device code and user-facing verification code.
- You approve the device in your browser at the verification URL.
- The panel polls `POST /api/device/token` with the device code until
  the backend returns a long-lived `device_token` (stored immediately).
- The panel then fetches the tunnel configuration (`GET /api/device/tunnel`
  with the device token): `subdomain`, the per-tunnel frp `token`, the
  server settings `server_addr`, `server_port` and `domain_base`, the
  `server_name` and certificate authority (`server_ca_pem`) of the tunnel
  server, and your account's masked e-mail address (`account_email_masked`).
- Everything is validated and persisted in `/data/frp-state.json`; the panel
  renders `/data/frpc.toml` (and `/data/frps-ca.pem`) and restarts `frpc`.
- `frpc` connects to the remote `frps` server over TLS, **verifies its
  certificate** against the pinned certificate authority, authenticates with
  the per-tunnel token, and registers the HTTP proxy for
  `<subdomain>.<domain_base>`.
- The panel shows which account the add-on is paired with ("Paired with
  g\*\*\*@example.com"): if that is not your account, unpair immediately.

### Where the tunnel settings come from

The LinumIQ server tells the add-on which frps endpoint and public domain to
use, so the server can move them without an add-on update. For each of
`server_addr`, `server_port` and `domain_base` the add-on uses, in order:

1. the **add-on option** (advanced override), but only if you explicitly set
   it to a non-empty, valid value;
2. the **server-provided value** stored at pairing / refresh time;
3. the **built-in default** (`linumiq.net`, `7000`; `domain_base` falls back
   to `server_addr` and then to `linumiq.net`).

Older servers that do not send `domain_base` keep working through the
fallback. Invalid server values are ignored (and logged) rather than written
to `frpc.toml`. The add-on log shows the effective values and their origin on
every start, e.g.
`server=linumiq.net:7000 (addr from server, port from server), domain_base=linumiq.net (from server)`.

**Why an explicitly set option beats the server value.** The options are
empty by default, so on a normal installation the server-provided values
always apply. Someone who *does* set `server_addr`, `server_port` or
`domain_base` has deliberately pointed the add-on somewhere else - a
development stack, a staging frps, or the end-to-end test harness pinning the
endpoint it is about to verify - and the server they pair with must not be
able to silently undo that. Clearing the option hands control back to the
server. (The platform design document, DESIGN.md section 4, words this as
"options remain as fallbacks for very old servers", i.e. server value over
option; the add-on intentionally implements *explicit option > server value >
default* instead, which is identical for every installation that leaves the
options unset.)

### Which port of Home Assistant the tunnel forwards to

The tunnel forwards to Home Assistant itself (`local_host` `homeassistant`).
Since Home Assistant 2026.8 a **new** Home Assistant OS installation serves
Home Assistant on port **80**; existing installations keep their port (8123
or whatever is set under **Settings > System > Network**). The add-on
therefore asks the Supervisor for Home Assistant's port
(`GET http://supervisor/core/info`, which needs the read-only Supervisor API
access the add-on declares with `hassio_api`) and uses, in order:

1. the `local_port` **option**, if you set it;
2. **Home Assistant's port as the Supervisor reports it** - only while
   `local_host` is `homeassistant` (another `local_host` is a different
   service, whose port the Supervisor does not know);
3. the default **8123** - when the Supervisor API is not available (a
   warning is logged; outside Supervisor, e.g. in the E2E harness, no request
   is made at all).

The renderer asks on every frpc (re)start, the panel at most every 5 minutes
(every minute while the API is unavailable). The log shows the result, e.g.
`local=homeassistant:80 (port from supervisor)`; the panel's *Forwarding* row
adds "Home Assistant's port, reported by the Supervisor". After changing Home
Assistant's port, restart the add-on (or click **Refresh tunnel config**
after a few minutes).

### Re-rendering and refresh

`/data/frpc.toml` is regenerated from the state file and the options every
time `frpc` (re)starts, so a changed server value or option takes effect on
the next restart. **Refresh tunnel config** in the panel re-fetches the
tunnel settings from your account (and restarts `frpc` only when something
changed). Use it after renaming your subdomain in the LinumIQ dashboard: the
rename rotates the tunnel token.

The panel also refreshes **automatically**, exactly like the button:

- once whenever the add-on starts;
- every 12-24 hours (a random time in that window, so installations do not
  all call the server at once; after a failed attempt - server unreachable -
  again after one hour). This also keeps your device marked as in use: the
  LinumIQ server expires devices that have not been seen for 180 days;
- after 3 consecutive failed logins of `frpc` with the current configuration
  that reached the tunnel server (certificate verification or authentication
  failed - typically because the server rotated its certificate authority or
  the tunnel token). Network errors (server unreachable) do not count. This
  trigger fires at most every 10 minutes and backs off to every 6 hours while
  the failures continue.

The panel's status card shows the time and result of the last automatic
refresh ("Config refresh").

### Transport encryption and server verification (TLS)

The generated configuration sets `transport.tls.enable = true`, so the control
connection to frps and all proxied traffic between the add-on and the LinumIQ
server are TLS-encrypted.

Since 2.2.0 frpc also **verifies the tunnel server** (`verify_server`, on by
default). The LinumIQ server sends the certificate authority (CA) that signed
the frps certificate and the name the certificate is issued for
(`server_ca_pem`, `server_name`) over the authenticated HTTPS device API. The
add-on accepts only X.509 CA certificates (no private keys, no leaf
certificates, nothing else in the PEM), stores the CA in the state file,
writes it to `/data/frps-ca.pem` and pins it in `frpc.toml`
(`transport.tls.trustedCaFile`, `transport.tls.serverName`). frpc then only
talks to an frps whose certificate chains to that CA and is valid for that
name - an attacker on the network path can no longer impersonate the server,
read the tunnel token or the proxied Home Assistant traffic.

- **Only real CA certificates are pinned.** Each certificate must be exactly
  one DER-encoded X.509 v3 certificate (no trailing data) with the
  basicConstraints extension `CA:TRUE`; leaf certificates, X.509 v1 roots and
  certificates without basicConstraints are rejected, like private keys or
  anything else in the PEM. Certificates that are expired or not yet valid
  are flagged in the panel.
- **The CA is never silently dropped.** If a later response does not contain
  a CA (for example after a server rollback), contains an invalid one, or one
  that is expired / not yet valid while the pinned one is still valid, the
  add-on keeps the last known CA and the panel shows a yellow warning. A new
  valid CA from the server (rotation) replaces the old one and restarts frpc.
- **Verification fails closed.** The pinned CA is validated again every time
  `frpc.toml` is rendered. If it no longer passes (a damaged or tampered state
  file), frpc keeps verifying against the last valid CA it was given
  (`/data/frps-ca.pem`, yellow banner). If there is no valid CA at all - also
  when the server sent a CA but never a valid one - **frpc is not started**:
  the log says `frpc is NOT started: no valid certificate authority for the
  tunnel server` and the panel shows a red banner. The add-on never falls back
  to an unverified connection once the server has asked for verification;
  **Refresh tunnel config** fetches the current CA.
- **Older servers** (before contract v2.2) send no CA. The connection is then
  encrypted but not verified, and the panel says so in a yellow banner; the
  next **Refresh tunnel config** after the server update pins the CA.
- **`verify_server: false`** (advanced option) turns verification off
  explicitly - only for troubleshooting or a development frps without that
  CA. The panel shows a permanent warning while it is off.
- An explicit `server_addr` override does not change the certificate name:
  frpc still expects the server-provided `server_name`.

The panel's "Tunnel server" row shows the state:

- *TLS, certificate verified for `<server_name>`; CA `<subject>` until
  `<date>`; frpc logged in `<time>`* - only after frpc has actually logged in
  to the tunnel server with exactly the pinned CA and the current
  configuration (frpc's log output is watched for `login to server success`);
- *TLS, CA pinned for `<server_name>` - waiting for frpc to log in with it*;
- *TLS, login with the CA pinned for `<server_name>` failed* (plus a red
  banner with frpc's error, e.g. `x509: certificate signed by unknown
  authority`);
- *frpc not started: no valid CA for the tunnel server* (fail closed, see
  above);
- *TLS, certificate not verified* (no CA from the server, or
  `verify_server: false`).

Your browser's connection to `https://<subdomain>.linumiq.net` always uses a
publicly trusted certificate.

## Generated `frpc.toml`

Example (production):

```toml
# Generated by the FRP Tunnel add-on from /data/frp-state.json and the
# add-on options. Re-rendered on every frpc (re)start: do not edit.
serverAddr = "linumiq.net"
serverPort = 7000
loginFailExit = false

# Encrypt the frpc <-> frps connection (control + proxied traffic).
transport.tls.enable = true
# Verify the frps certificate: it must chain to the CA provided by the
# LinumIQ server (pinned in the state file) and be valid for serverName.
transport.tls.trustedCaFile = "/data/frps-ca.pem"
transport.tls.serverName = "<server_name from the LinumIQ server>"

# Per-tunnel credential, validated by the frps auth plugin (metas.token).
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
localPort = 8123  # Home Assistant's port from the Supervisor (80 on new installations)
```

frpc runs as the unprivileged system user `frpc`: `frpc.toml` and
`frps-ca.pem` are `root:frpc` mode 640 (frpc can read, not change them); the
state file with the device token is `root` mode 600 and unreadable for frpc.
Tokens are never written to the log and never returned by the panel.

frpc processes this file as a Go template (`{{ ... }}` actions, with access to
frpc's environment variables) before it parses it. The add-on therefore never
writes `{{`, `}}` or a backtick into it: every value is restricted to host
name / token characters, and the renderer checks every field and the whole
file once more before writing it. frpc is also started with an empty
environment (`PATH`, `HOME` and `TZ` only), so it never sees the add-on's
Supervisor API token.

## Configuration Options

### User-facing

| Option      | Type | Default | Description |
| ----------- | ---- | ------- | ----------- |
| `log_level` | enum | `info`  | Log verbosity of the add-on and of frpc: `trace`, `debug`, `info`, `notice`, `warning`, `error`, `fatal`. |

### Advanced (development / E2E testing)

These are optional overrides that let you point the add-on at a
development or staging backend. In production you should leave them
unset - the defaults point at the live LinumIQ service, and the server
provides `server_addr`, `server_port` and `domain_base`.

| Option        | Type   | Default                   | Description |
| ------------- | ------ | ------------------------- | ----------- |
| `verify_server` | bool | `true` (when unset)       | Verify the frps certificate against the CA provided by the LinumIQ server. Only an explicit `false` disables it (see [Transport encryption and server verification](#transport-encryption-and-server-verification-tls)). |
| `app_base`    | URL    | `https://app.linumiq.net` | Web app for browser pairing and the device API. |
| `api_base`    | URL    | `https://api.linumiq.net` | Backend (Supabase) API base URL. |
| `server_addr` | host   | server value, else `linumiq.net` | frps control host name or IP. |
| `server_port` | port   | server value, else `7000` | frps control port. |
| `domain_base` | domain | server value, else `server_addr` | Public domain suffix for the tunnel host (`<subdomain>.<domain_base>`). |
| `local_host`  | host   | `homeassistant`           | Local service host name or IP. |
| `local_port`  | port   | Home Assistant's port from the Supervisor (80 on new installations since 2026.8), else `8123` | Local service port. Set it only if the tunnel must forward elsewhere; see [Which port of Home Assistant the tunnel forwards to](#which-port-of-home-assistant-the-tunnel-forwards-to). |

An override is only applied when it is set to a non-empty value; clear the
field to go back to the server-provided value.

### Validation of options

Supervisor checks the option schema before the add-on starts (an invalid
value - e.g. `log_level: warn` - is refused with a message in the add-on's
Configuration tab / the Supervisor log, and the add-on does not start). The
add-on then validates every value again, more strictly (host names per
RFC 1123, IP literals without IPv6 zone IDs, `domain_base` with at least two
labels, http(s) URLs without user info, query or fragment). A value that
fails this second check never crashes the add-on: it is ignored (the next
precedence layer applies), logged as `Invalid add-on option: ...`, and the
panel shows a red **Invalid add-on configuration** banner naming the option
and what a valid value looks like. An invalid `app_base` (or an unreadable
`/data/options.json`) additionally blocks every call to the LinumIQ backend
(pairing, refresh, subdomain change and the server-side part of unpair),
because falling back to the production URL would silently pair a test
installation with production. Fix the option and restart the add-on.

### Upgrading from 2.0.x

Only installations that set the affected options need to change anything
(re-pairing is never needed - the tunnel token is migrated automatically):

| Option | Must be changed if it is ... | Refused by |
| ------ | ---------------------------- | ---------- |
| `log_level` | `warn` - select `warning` (2.0.x offered `warn`, which already broke the start). | Supervisor |
| `server_addr`, `local_host` | containing anything but letters, digits, `.`, `-` and `:` - e.g. an underscore (Docker names such as `my_service`), a space, `/`, `%` or a scheme (`https://...`). Use a DNS name without `_` or the IP address. | Supervisor |
| `server_addr`, `local_host` | not a valid host name / IP although it passes the schema - e.g. with a port (`host:8123`; use `server_port` / `local_port`), a trailing dot, an empty label (`a..b`) or a label starting/ending with `-`. | add-on (banner, value ignored) |
| `domain_base` | not at least two dot-separated labels of letters, digits and `-` - e.g. a single label, a leading `*.` or `.`, a trailing `.`, an underscore. | Supervisor |
| `domain_base` | an IP address, ending in an all-numeric label, or with a label that starts/ends with `-` or is longer than 63 characters. | add-on (banner, value ignored) |
| `app_base`, `api_base` | containing user info (`https://user:pw@...`), a query, a fragment or characters outside RFC 3986. | add-on (banner; an invalid `app_base` blocks backend calls) |

`server_port`, `local_port` and unset options are unaffected.

### Using the development stack

The LinumIQ development environment runs next to production with its own
dashboard, API, frps port and tunnel domain. A dev-stack server already
advertises its frps port and tunnel domain during pairing, so pointing the
add-on at the dev dashboard is enough:

```yaml
app_base: "https://app-dev.linumiq.net"
api_base: "https://api-dev.linumiq.net"
```

To pin the values explicitly (for example against a dev server that does not
yet send them), also set:

```yaml
server_addr: "linumiq.net"
server_port: 7001
domain_base: "dev.linumiq.net"
```

Pairing then happens at `https://app-dev.linumiq.net/activate` and the tunnel
is published at `https://<subdomain>.dev.linumiq.net`. After switching between
environments, unpair and pair again: device tokens are per environment.

## Backups and restore

Home Assistant backups of this add-on do **not** contain the pairing data
(`backup_exclude` in `config.yaml`): the device token and tunnel token
(`frp-state.json`), `frpc.toml`, the pinned CA (`frps-ca.pem`) and a pairing
in progress are left out, so a backup file never carries credentials for your
tunnel. The add-on options are still backed up.

After restoring a backup (or restoring onto a new machine) the add-on starts
**unpaired**: open the panel and pair again. The device token of the old
installation is not revoked by the restore - remove the old device in your
LinumIQ account (or click **Unpair** on the old installation before you
retire it).

## Security notes

- **Ingress only.** The panel answers only the Supervisor's ingress proxy
  (172.30.32.2), decided from the TCP peer address - never from `Host`,
  `X-Forwarded-*` or the request path (2.1.x exempted `/_health`, which a
  crafted `Host` header could abuse to reach every endpoint from another
  container: Starlette GHSA-86qp-5c8j-p5mr). Static files and unknown paths
  are behind the same check. Since 2.2.0 not even loopback is accepted, so no
  process inside the add-on container - in particular the unprivileged frpc
  user - can drive the panel through `127.0.0.1:8099`. (`ALLOWED_INGRESS_IPS`
  exists only for running the image outside Supervisor, e.g. the E2E harness;
  the container environment cannot be set under Supervisor.)
- **CSRF.** Every state-changing request (pairing, refresh, subdomain change,
  unpair) must be same-origin: `Sec-Fetch-Site: same-origin`, or - for
  browsers without Fetch Metadata - an `Origin` that names the requested host.
  Home Assistant ingress keeps the panel on your Home Assistant origin, so
  nothing changes for you; another web site can no longer make your browser
  unpair or re-pair the add-on. Scripts that drive the panel (e.g. the E2E
  harness) must send `Sec-Fetch-Site: same-origin`.
- **Pairing codes.** The pairing code is a short-lived approval credential:
  it is shown only in the panel page - never in a URL (browser history,
  access logs) or the add-on log. Approve a code only on `app.linumiq.net`
  (your `app_base`), signed in to your own account, and only if you started
  that pairing yourself; never approve a code someone else sent you. The
  panel shows the masked e-mail of the account the device is paired with.
- **Least privilege.** frpc runs as an unprivileged user with a scrubbed
  environment; the AppArmor profile (`apparmor.txt`) allows only the files,
  programs, capabilities (`chown`, `fowner`, `kill`, `setgid`, `setuid`) and
  signals the add-on needs; no host folders are mapped.
- **No template injection into frpc.** frpc expands Go template actions such
  as `{{ .Envs.NAME }}` anywhere in its configuration file. The tunnel token
  must consist of `A-Z a-z 0-9 . _ ~ -` (8-256 characters), host names and
  domains of DNS characters, and the renderer refuses `{{`, `}}` and
  backticks in every field and in the finished file - so a malicious or
  compromised backend cannot make frpc send environment variables to frps.
  frpc's environment contains nothing secret anyway.

- **Untrusted pairing data.** Everything the backend returns from
  `POST /api/device/code` is validated before it is stored or shown in the
  ingress page: `user_code` must be `XXXX-XXXX` (A-Z, 0-9); `device_code`
  16-512 URL-safe characters (`A-Z a-z 0-9 . _ ~ -`); `interval` an integer
  1-60 s and `expires_in` an integer 1-3600 s (defaults 5 / 600 when
  omitted); `verification_uri` / `verification_uri_complete` must consist of
  RFC 3986 characters, use `https` (`http` only when `app_base` itself is an
  `http` development URL), carry no user info, and their host must equal
  `app_base`'s host. Anything else rejects the pairing with
  *"Pairing rejected: the server sent an invalid pairing response (...)"*.
  The page escapes every value (Jinja autoescape, nothing is marked safe) and
  embeds the polling interval in JavaScript only through `tojson`.
- **Tokens.** The device token and the tunnel token are never logged, never
  returned by the panel and never part of an error message: backend error
  texts are reduced to one printable line (CR/LF, control and bidi characters
  removed, max. 200-300 characters) with known secrets redacted. The panel
  never follows HTTP redirects, so the device token is only ever sent to
  `app_base`; a malformed device token is refused instead of being sent.
  Backend responses larger than 256 KiB are rejected.
- **frpc only runs from a valid pairing.** The frpc service starts frpc only
  when the renderer has just read a valid pairing from `/data/frp-state.json`
  (exit 0). Without one (no, corrupt or incomplete state) a leftover
  `/data/frpc.toml` is deleted and the service waits. The panel and the
  renderer share a lock file (`/data/.frp-state.lock`). **Unpair** removes the
  state file first, stops frpc and waits for it, then removes `frpc.toml`,
  and finally revokes the device token server-side; if the server does not
  confirm the revocation, the panel says so (local data is removed anyway).
  The panel always shows the real frpc status and warns if frpc runs while
  the device is not paired.
- **Supply chain.** The `frpc` binary is downloaded from the official
  fatedier/frp release and verified against a SHA-256 pinned per
  architecture in the `Dockerfile`; the build fails on a mismatch. The panel's
  Python dependencies (Starlette, uvicorn, Jinja2, python-multipart and their
  dependencies - no FastAPI/pydantic since 2.2.0) are pinned with hashes in
  `requirements.txt` and installed with `pip --require-hashes
  --only-binary=:all:` into a virtualenv; pip itself is not part of the image.

## Troubleshooting

- **Pairing link doesn't open**: The link opens `app.linumiq.net` (or your
  `app_base`). Make sure your browser has internet access. If you're on a
  restricted network, type the verification URL manually.
- **"authorization_pending" for a long time**: The pairing code expires
  after ten minutes. Click **Restart Pairing** to get a fresh code.
- **"Choose a subdomain" after approving**: your account has no tunnel yet.
  Pick a subdomain in the panel. If the server rejects it (for example
  `'<name>' is reserved` or already taken), the panel shows the server's
  reason - choose another one.
- **Backend not reachable during pairing**: the panel keeps polling and
  recovers automatically. If the device was approved but the tunnel could not
  be fetched, click **Refresh**.
- **Public URL returns 502**: Home Assistant Core is not reachable at
  `local_host:local_port` from inside the add-on container. The panel's
  *Forwarding* row and the log (`local=...:<port> (port from ...)`) show what
  the tunnel uses. `homeassistant` works on the Supervisor network. The port
  is Home Assistant's own port as the Supervisor reports it (80 on new Home
  Assistant OS installations since 2026.8, otherwise usually 8123); if the
  log says `Cannot read Home Assistant's port from the Supervisor API ...;
  using local_port 8123` while Home Assistant listens elsewhere, or if a
  `local_port` option is set to an old value, set `local_port` to Home
  Assistant's port (**Settings > System > Network**) or clear the option.
  For other setups set the advanced overrides. If Home Assistant itself
  serves HTTPS (an `ssl_certificate` in its configuration), the tunnel
  cannot forward to it (frpc forwards plain HTTP).
- **"certificate verify failed", "x509: certificate signed by unknown
  authority" or "x509: certificate is valid for ..., not ..." in the log**:
  frpc refused the tunnel server because its certificate does not match the
  pinned CA / `server_name`. Most often the LinumIQ server has rotated its
  certificate authority: click **Refresh tunnel config** to fetch the current
  one. If the panel also shows *"The LinumIQ server no longer sends the tunnel
  server's certificate authority"*, the server side is being changed - wait
  and refresh again, or contact support. If you set `server_addr` to a
  different (e.g. development) frps, its certificate must still be issued by
  the CA of the server you paired with; for a development frps without it set
  `verify_server: false` temporarily. Never turn verification off because of
  this error on a production installation without knowing why it happened -
  it is exactly what an attacker in your network would cause.
- **Yellow "Tunnel server not fully verified" banner**: the server provided no
  CA (older server), verification is switched off (`verify_server: false`),
  the server sent an unusable CA (the last valid one stays pinned), or frpc
  cannot reach the tunnel server - the banner says which. Click **Refresh
  tunnel config** once the server provides a (new) CA.
- **Red "Tunnel server verification failed" banner**: either frpc could not
  log in with the pinned CA (the banner shows frpc's error; the add-on
  re-fetches the configuration automatically after repeated failures - or
  click **Refresh tunnel config**), the pinned CA has expired, or **frpc is
  not started** because no valid CA is known although the server requires
  verification (log: `frpc is NOT started: no valid certificate authority for
  the tunnel server`). Click **Refresh tunnel config**; if the server still
  sends no valid CA, contact LinumIQ support. `verify_server: false` would
  start frpc without verification - only do that if you know why the CA is
  missing.
- **"Tunnel server: waiting for frpc to log in with it"**: the CA is pinned,
  but frpc has not logged in with the current configuration yet (just
  started, or the tunnel server is unreachable). The row turns into
  "certificate verified" with the first successful login.
- **"Paired with" shows an e-mail address that is not yours**: the device was
  approved by another account (for example after you approved a code someone
  sent you). Click **Unpair** immediately and pair again.
- **Add-on unpaired after restoring a backup**: expected - pairing data is not
  included in backups. Pair again (see [Backups and restore](#backups-and-restore)).
- **"Forbidden: cross-site request"**: a POST to the panel did not come from
  the panel page itself (missing `Sec-Fetch-Site: same-origin` / matching
  `Origin`). Open the panel through Home Assistant (sidebar or the add-on's
  *Open Web UI*); scripts must send `Sec-Fetch-Site: same-origin`.
- **frpc keeps reconnecting / "login to the server failed"**: check
  connectivity to the frps endpoint shown in the panel ("Tunnel server") and
  in the log line `frpc.toml rendered: server=...`. If the token was rotated
  (e.g. the subdomain was renamed in the dashboard), click **Refresh tunnel
  config**; if the device was revoked, **Unpair** and pair again.
- **Wrong public domain or port after a server change**: click **Refresh
  tunnel config** (or restart the add-on), and make sure no stale advanced
  override (`server_addr`, `server_port`, `domain_base`) is set - an
  explicitly set option always wins over the server value.
- **Add-on does not start after upgrading with `log_level: warn`**: select
  `warning` instead (`warn` is not a valid base-image level). See
  [Upgrading from 2.0.x](#upgrading-from-20x) for the other options whose
  accepted values became stricter.
- **"Invalid add-on configuration" banner**: an option failed the add-on's
  validation and is ignored (see [Validation of options](#validation-of-options)).
  Correct it in the Configuration tab and restart the add-on.
- **"Pairing rejected: the server sent an invalid pairing response"**: the
  backend's answer failed validation (see [Security notes](#security-notes)).
  Most often the verification link points to a different host than
  `app_base` - e.g. a development dashboard whose public URL setting differs
  from the URL configured as `app_base`. Use the dashboard's public URL as
  `app_base`.
- **"... answered with a redirect; redirects are not followed"**: `app_base`
  is not the final URL of the dashboard (for example `http://` instead of
  `https://`). Set it to the URL the redirect points to.
- **"Device unpaired locally ... the server did not confirm that the device
  token was revoked"**: the tunnel is stopped and all local pairing data is
  gone, but the backend could not be reached or refused the revocation. The
  token can no longer be used by this add-on; remove the device in your
  LinumIQ account if the problem persists.

## Running outside Home Assistant (E2E tests)

`tests/e2e/run.sh` builds the image, runs it without Supervisor against a
LinumIQ stack, pairs it through the panel's HTTP endpoints and checks the
whole path up to the public URL. See [tests/e2e/README.md](tests/e2e/README.md).
Unit tests: `python3 -m unittest discover -s frp-tunnel/tests/unit` (the
panel tests are skipped unless the dependencies from `requirements.txt` are
installed); CI runs them with the pinned dependencies on the host and inside
the freshly built amd64 image against the installed code, and boots the image
under the AppArmor profile (`tests/apparmor-smoke.sh`, fails on any denial).
See the tests README for the commands.

## Maintainers: Python dependencies

`requirements.in` lists the panel's direct dependencies (with the security
minimums); `requirements.txt` is generated from it with hashes by
`pip-compile` in the image's Python version (base image 21.0.10: Alpine 3.24,
CPython 3.14) - the command is in the header of `requirements.in`. The image
build fails if a downloaded wheel does not match its hash.

## Maintainers: publishing to GHCR

`config.yaml` intentionally has no `image:` key yet, so Supervisor builds the
add-on locally from the `Dockerfile`. The repository's **Builder** workflow
test-builds every change; when a GitHub **release** is published it builds and
pushes `ghcr.io/linumiq/{arch}-addon-frp-tunnel:<version>` (`aarch64`, `amd64`).
Once the first release exists (and the GHCR package is public), add

```yaml
image: "ghcr.io/linumiq/{arch}-addon-frp-tunnel"
```

to `config.yaml` so that Supervisor pulls the prebuilt image. From then on every
version bump in `config.yaml` must be released before users can update.
