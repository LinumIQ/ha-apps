# Caddy mTLS Proxy - Documentation

This add-on provides a Caddy reverse proxy with mutual TLS (mTLS) authentication for Home Assistant. It automatically obtains SSL certificates from Let's Encrypt and generates client certificates for secure access.

## Features

- 🔒 **Automatic HTTPS** via Let's Encrypt
- 🔐 **mTLS Authentication** - require client certificates for access
- 📱 **Easy Certificate Distribution** - dedicated download page (admin-only ingress panel)
- 🌐 **DNS-01 Challenge Support** - for when port 80 is unavailable
- 👥 **Multiple Client Certificates** - generate certificates for each user/device
- 🛠️ **Web Certificate Manager** - add, revoke and regenerate certificates from the ingress UI
- ♻️ **Certificate Revocation List (CRL)** - revoked clients are rejected on the next handshake without restarts
- 📅 **Expiration Notifications** - per-cert sensors and persistent notifications as expiry approaches
- 🚦 **Public certificate status** - the web UI shows whether the Let's Encrypt certificate exists; if not, the last error and a port-forwarding checklist (plus a Home Assistant notification)
- 🏠 **HTTPS at home without a client certificate** (since 2.2.0, optional) - a second port for the local network, same domain and certificate, for private addresses only
- 🔁 **Works without editing Home Assistant** (since 2.2.0) - the add-on asks Home Assistant whether it trusts it as a reverse proxy and adapts; the web UI shows what Home Assistant sees and how to pass real visitor addresses on

## Requirements

### Network Requirements

1. **Domain Name**: You need a domain name pointing to your Home Assistant's public IP
2. **Port Forwarding**: On your router, forward external TCP port **80 to port
   8080** and external TCP port **443 to port 8443** of your Home Assistant
   host (the add-on's default host ports, see below)
3. **Firewall**: Ensure the external ports 80 and 443 are open

### Ports: 8080 and 8443 on the host (since 2.0.0)

Inside the add-on, Caddy listens on ports 80 (HTTP) and 443 (HTTPS). Since
Home Assistant 2026.8, **new Home Assistant OS installations serve Home
Assistant itself on ports 80 and 443** (Settings > System > Network; existing
installations keep their port, usually 8123), so an add-on cannot publish
those ports there. The add-on therefore publishes them on the host as **8080**
and **8443** by default:

| Inside the add-on | Default host port | Port forwarding on the router            |
| ----------------- | ----------------- | ---------------------------------------- |
| `80/tcp` (HTTP)   | `8080`            | external TCP 80 -> `<HA host>:8080`      |
| `443/tcp` (HTTPS) | `8443`            | external TCP 443 -> `<HA host>:8443`     |
| `4443/tcp` (HTTPS, local network, since 2.2.0) | none (off) | **never** - see [HTTPS in your local network](#https-in-your-local-network-without-a-client-certificate-since-220) |

- You can change the host ports in the add-on's **Network** settings, e.g.
  back to 80 and 443 on an installation where Home Assistant itself does not
  use them. The add-on log shows the published host ports on every start.
- `domain` is the bare host name (`home.example.com`), never with a port:
  only the host-side mapping changes, the public ports stay 80 and 443.
- The **public** ports stay 80 and 443: Let's Encrypt's HTTP-01 challenge
  always connects to port 80, the CRL URL in every client certificate is
  `http://<domain>/mTLS-CA.crl` (port 80), and the HTTP-to-HTTPS redirect
  points to `https://<domain>/` (port 443) - all of them reach the add-on
  through the router's port forwarding.
- **In your LAN**, either use the public URL (if your router supports NAT
  loopback / hairpin NAT) or `https://<domain>:8443` with `<domain>`
  resolving to the Home Assistant host (local DNS or hosts file) - both with
  a client certificate - or turn on the
  [local-network port](#https-in-your-local-network-without-a-client-certificate-since-220),
  which needs none. The certificate and the mTLS site are bound to the
  domain name, so `https://<ip-address>:8443` does not work. A plain-HTTP
  request to `http://<domain>:8080/` is redirected to `https://<domain>/` -
  port 443, i.e. the router path.

### HTTPS in your local network without a client certificate (since 2.2.0)

At home you may not want to install a client certificate on every device
(a wall tablet, a guest's phone). The add-on can serve the same Home
Assistant over HTTPS **without a client certificate** on a second port,
container port `4443/tcp`, for devices in your local network only. It uses
the same domain and the same Let's Encrypt certificate.

Why a second port and not "no certificate needed from the LAN" on the main
port: the address the add-on sees for a connection depends on your router
and on Docker; where it is wrong, such a rule would let the internet in
without a certificate. A separate port that your router does not forward
keeps the internet path certificate-only.

**Turn it on:**

1. Open **Settings > Apps > Caddy mTLS Proxy > Configuration**.
2. In the **Network** card, turn on **Show disabled ports** (a port without
   a host port counts as disabled and is hidden otherwise).
3. Enter a free host port for `4443/tcp`, for example `9443`. Keep the host
   ports of `80/tcp` and `443/tcp` as they are - do **not** use **Reset to
   defaults**, which also sets them back to 8080/8443.
4. Select **Save**, then restart the add-on.

The add-on's web interface (card **Local network**) and its log then show
the address, e.g. `https://home.example.com:9443/`. Without a host port the
port is off; there is no option for it.

**Make the name work at home.** The certificate is issued for your domain,
so the address must be `https://home.example.com:9443/`, not
`https://192.168.1.10:9443/` (the browser would refuse the certificate). In
your local network the name has to lead to the Home Assistant host: add a
local DNS record that points `home.example.com` to the host's **IPv4**
address (an A record) - in your router's DNS settings, in AdGuard Home (DNS
rewrites), in Pi-hole (Local DNS records) or in the Dnsmasq app (`hosts`).
Use the IPv4 address: if a device connects over IPv6 (for example because
the name also has a public AAAA record that your DNS passes on), the
connection either does not reach the add-on or arrives under an address
that hides the device, and the add-on answers it with a 403 that says to use
IPv4. Check what your devices get with `nslookup home.example.com`.

**Tip:** where host port 443 is free on your Home Assistant host (not on new
Home Assistant OS installations, which serve Home Assistant itself on 443),
give `4443/tcp` the host port 443: at home `https://home.example.com/` then
opens without a certificate, and away the same URL asks for one. **Before
you do, look at your router's port forwarding:** external TCP 443 must go to
the host port of `443/tcp` (the client-certificate port, 8443 by default),
never to host port 443 itself, which would then be the port without client
certificates. Installations from before 2.0.0 used host port 443 for
`443/tcp`, so an old forwarding rule may still point there. The card **Local
network** repeats this warning while the port uses host port 443.

**Only local addresses.** The port answers only connections from private
addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8,
169.254.0.0/16, fc00::/7, fe80::/10, ::1). Every other connection gets
`403 Forbidden` with the address the add-on saw. It also refuses the
add-on's Docker gateway address (for example `172.30.32.1`): Docker
forwards IPv6 connections to an add-on without IPv6, and connections from
the host itself, from that address, which hides where they really come
from - possibly from the internet. This rule is a second line of defence,
not the boundary:

- **Never forward this port on your router.** It needs no client
  certificate.
- A published port is reachable over IPv6 wherever your router's IPv6
  firewall lets connections in, without any port forwarding: keep your
  router's IPv6 firewall on (most routers block incoming IPv6 connections
  by default).

### Port 80 Availability

Let's Encrypt's HTTP-01 challenge requires that external TCP port 80 reaches
the add-on's HTTP port (host port 8080 by default). If you cannot forward
port 80:

- Use the DNS-01 challenge by configuring a DNS provider (Cloudflare, Route53, or Hetzner)
- Ensure no other service is using the external port 80

## Installation

1. Add this repository to your Home Assistant add-on store
2. Install the "Caddy mTLS Proxy" add-on
3. Configure the required options (see Configuration section)
4. Start the add-on
5. Open the add-on's web interface (Home Assistant sidebar): the card
   **Home Assistant connection** shows whether Home Assistant gets the
   visitors' own addresses, and how to change that (see
   [Home Assistant Core Configuration](#home-assistant-core-configuration)).
   Until 2.1.x this step was a requirement: without it, every request was
   answered `400: Bad Request`. Since 2.2.0 the add-on works without it.

## Home Assistant Core Configuration

The add-on forwards each request to Home Assistant. A reverse proxy normally
adds the visitor's address to the request (the header `X-Forwarded-For`), so
that Home Assistant can show and check the real address. Home Assistant
accepts that header **only from a proxy it trusts**; from any other proxy it
answers every request with **`400: Bad Request`** and writes a line such as
`A request from a reverse proxy was received from 172.30.33.3, but your HTTP
integration is not set-up for reverse proxies` into its log.

### What the add-on does (option `forwarded_headers`, since 2.2.0)

| `forwarded_headers` | Visitor addresses | Home Assistant needs to trust the add-on |
| ------------------- | ----------------- | ---------------------------------------- |
| `auto` (default)    | passed on if Home Assistant trusts the add-on; otherwise (with mTLS) removed | no |
| `always`            | always passed on  | yes - otherwise every request is answered `400: Bad Request` |
| `never`             | never passed on - **only with mTLS on** | no |

**`never` needs mTLS** (`mtls_enabled: true`), for every upstream. Without
client certificates the visitors are anyone on the internet; if the add-on
hid their addresses, each of them would look like a device in your local
network to Home Assistant. With `mtls_enabled: false` and
`forwarded_headers: never` the add-on refuses to start and says so in its
log; use `auto` and let Home Assistant trust the add-on, or turn mTLS on.

With `auto`, the add-on asks Home Assistant at every start whether it
accepts forwarded requests from the add-on (a request with and one without
the header):

- **Home Assistant trusts the add-on**: visitor addresses are passed on.
  Home Assistant sees each visitor's own address (logins, notifications,
  "local network only" users, IP bans work per visitor).
- **Home Assistant does not trust the add-on, mTLS on** (the default): the
  add-on removes the forwarding headers. It works, and **Home Assistant sees
  every visitor under the add-on's own address** (for example
  `172.30.33.3`). Visitors on the public port have a client certificate,
  and visitors on the [local-network port](#https-in-your-local-network-without-a-client-certificate-since-220)
  come from private addresses, so this is an acceptable default, but it
  has consequences, which the web interface lists:
  - Logins, the "Login attempt failed" notifications and Home Assistant's
    logs show the add-on's address instead of the visitor's.
  - Home Assistant counts that address as a device in your local network:
    users marked **Can only log in from the local network** can log in, and
    webhooks marked **Only accessible from the local network** accept
    requests, from every device with a client certificate.
  - If you set a limit of login attempts (IP banning), too many failed
    logins ban the add-on's address - that is everyone who uses the add-on -
    until you delete it from `ip_bans.yaml` and restart Home Assistant.
  - If you use the trusted networks login provider and its networks include
    the add-on's address, every device with a client certificate logs in
    without a password.
- **Home Assistant does not trust the add-on, mTLS off**: the addresses are
  still passed on, so every request is answered `400: Bad Request`. Without
  client certificates the visitors are anyone on the internet; they must
  never look like a device in your local network. The web interface and a
  Home Assistant notification say what to do.
- **Home Assistant does not answer** (for example while it starts - at boot
  the add-on starts before Home Assistant): the add-on keeps the last known
  mode and decides as soon as Home Assistant answers. While Home Assistant
  does not answer or restarts, the add-on asks every 2.5 seconds, so few
  requests are answered 400 before it decides; after 10 minutes without an
  answer it asks every 12 seconds until Home Assistant answers again. A
  Home Assistant that is only slow (no answer within 5 seconds) counts as
  "does not answer" after two unanswered questions in a row, or at once
  when the connection is refused; a pause of up to about 15 seconds changes
  nothing. If only the test question (the one with a visitor address) gets
  no answer within 5 seconds, the add-on asks it again every 12 seconds;
  after three such questions in a row it stops and the card says **Too slow
  to decide**, until Home Assistant restarts, the add-on starts or you
  select **Check again**.

The add-on keeps watching: it asks Home Assistant every 12 seconds with a
request that Home Assistant does not log, over a connection that Home
Assistant keeps open. When Home Assistant restarts (which is how a changed
HTTP setting takes effect - and how it drops unconfirmed settings after 5
minutes), that connection breaks; the add-on then asks again whether Home
Assistant trusts it and switches without a restart of its own (Caddy
reloads its configuration; open websocket connections, for example of the
Home Assistant app, reconnect). While Home Assistant trusts the add-on it
also asks once a minute, which Home Assistant does not log. While Home
Assistant does not trust it, the add-on asks only at its start, after a
Home Assistant restart (or after Home Assistant did not answer twice in a
row) and when you select **Check again** - **each of these questions writes
one line into Home Assistant's log** (the one quoted above). An upstream
other than Home Assistant that closes idle connections itself is not
watched for restarts: after changing its trusted proxies, select **Check
again** (or restart the add-on).

When the add-on stops passing visitor addresses on while it runs (Home
Assistant trusted it and no longer does; not when it decides for the first
time, for example after a start while Home Assistant was down), it raises
a Home Assistant notification
**"Caddy mTLS: Home Assistant no longer trusts the app - visitor addresses
are hidden"** with what that means and how to restore the trust. The
notification disappears when the addresses are passed on again (and at the
add-on's next start). If Caddy cannot be reloaded for a change, the card
turns red ("Change not applied", with the error), shows what Caddy still
runs, and the add-on retries.

### Passing the real visitor addresses on (recommended)

Let Home Assistant trust the add-on as a reverse proxy. **Home Assistant
2026.7 and later** keep these settings in the user interface:

1. In Home Assistant, open **Settings > System > Network**.
2. In the **HTTP server** card, open **Reverse proxy**, turn on **Trust
   X-Forwarded-For** and add `172.30.33.0/24` to **Trusted proxies** (the
   network of the add-ons on Home Assistant OS; the add-on's web interface
   shows the exact value for your installation).
3. Select **Save**, then **Save and restart**.
4. When Home Assistant is back, select **Confirm** in the dialog **Confirm
   new HTTP server configuration** within 5 minutes. Otherwise Home
   Assistant restores the previous settings and restarts again.

The add-on notices the restart and switches to passing the addresses on; or
select **Check again** in its web interface.

> **Home Assistant 2026.7 and later read the `http:` block of
> `configuration.yaml` only once**: at the first start of 2026.7 or later
> they import it (as a change to confirm within 5 minutes) and from then on
> ignore it - a block added later only brings the repair "HTTP YAML
> configuration is ignored after migration". Use the steps above.

**Home Assistant before 2026.7**: add this to `/config/configuration.yaml`
(merge it into an existing `http:` section) and restart Home Assistant:

```yaml
http:
  use_x_forwarded_for: true
  trusted_proxies:
    - 172.30.33.0/24
```

Up to 2.1.x this documentation suggested `172.30.32.0/23` (Supervisor's
whole network, which includes `172.30.33.0/24`); an existing entry with that
network works as well.

## Configuration

### Required Options

| Option   | Description                                       | Example             |
| -------- | ------------------------------------------------- | ------------------- |
| `domain` | Your domain name (host name only: no port, path) | `home.example.com`  |
| `email`  | Email for Let's Encrypt                           | `admin@example.com` |

### Optional Options

| Option                      | Default          | Description                                                                                                             |
| --------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `upstream_host`             | `homeassistant`  | Backend service hostname                                                                                                |
| `upstream_port`             | (unset)          | Backend service port. Unset with `upstream_host: homeassistant`: Home Assistant Core's own port, read from the Supervisor (80 on new Home Assistant OS installations since 2026.8, 8123 on older ones). Required for any other `upstream_host` |
| `mtls_enabled`              | `true`           | Enable client certificate authentication                                                                                |
| `client_names`              | `["user"]`       | Client certificate names; a name the add-on does not know yet gets a certificate at every start (see [Adding New Users](#adding-new-users)) |
| `client_cert_password`      | `LinumIQ`        | Password for .p12 files - set your own; changing it re-encrypts the existing bundles at the next start (see [Changing the certificate password](#changing-the-certificate-password)) |
| `log_level`                 | `info`           | Add-on / Caddy log verbosity (`trace`, `debug`, `info`, `notice`, `warning`, `error`, `fatal`); `debug` and `trace` also turn the access logs on |
| `access_log`                | `false`          | Log every proxied request (Caddy's access log, ~1.5 KB per request); see [Logs](#logs)                                  |
| `forwarded_headers`         | `auto`           | Whether Home Assistant gets each visitor's own address (`auto`, `always`, `never`; `never` only with `mtls_enabled: true`); see [Home Assistant Core Configuration](#home-assistant-core-configuration) |
| `cert_expiry_warn_days`     | `[30, 14, 7, 1]` | List of days-before-expiry thresholds at which to fire a notification (one notification per crossed threshold per cert) |
| `cert_check_interval_hours` | `6`              | How often the `cert-monitor` service polls certificate metadata and publishes sensor states (`1`-`168`)                 |

### Upstream port (since 2.0.0)

With the default `upstream_host: homeassistant` and no `upstream_port`, the
add-on proxies to Home Assistant Core's own port as reported by the
Supervisor - 80 on new Home Assistant OS installations (2026.8 and later),
8123 on older ones; the log shows the resolved upstream on every start. If
you saved the add-on options before 2.0.0, they may contain
`upstream_port: 8123`; remove it to follow Core's port, or keep it if Core
really listens there. Without the Supervisor API (tests) 8123 is assumed. The
proxy talks plain HTTP to the upstream.

### CA Certificate Options

| Option            | Default                  | Description             |
| ----------------- | ------------------------ | ----------------------- |
| `ca_country`      | `AT`                     | Two-letter country code |
| `ca_state`        | `Styria`                 | State or province       |
| `ca_locality`     | `Graz`                   | City name               |
| `ca_organization` | `LinumIQ`                | Organization name       |
| `ca_common_name`  | `Home Assistant mTLS CA` | CA certificate name     |

### DNS Challenge Options (Optional)

Use these options when port 80 is not available:

| Option              | Default | Description                                              |
| ------------------- | ------- | -------------------------------------------------------- |
| `acme_dns_provider` | `none`  | DNS provider: `none`, `cloudflare`, `route53`, `hetzner` |
| `dns_api_token`     | (empty) | API token for the DNS provider                           |

The token never appears in the generated Caddyfile: Caddy reads it from the
add-on's environment (`{env.*}` placeholders). If the Caddyfile check at
start-up fails, its output is printed with the token replaced by
`<redacted>` (the Cloudflare module quotes a token it considers malformed in
its error message).

#### Cloudflare Setup

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens)
2. Create a new API token with permissions:
   - Zone > Zone > Read
   - Zone > DNS > Edit
3. Copy the token to `dns_api_token`

#### AWS Route53 Setup

1. Create an IAM user with the following policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "route53:ListResourceRecordSets",
        "route53:GetChange",
        "route53:ChangeResourceRecordSets"
      ],
      "Resource": [
        "arn:aws:route53:::hostedzone/YOUR_ZONE_ID",
        "arn:aws:route53:::change/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["route53:ListHostedZonesByName", "route53:ListHostedZones"],
      "Resource": "*"
    }
  ]
}
```

2. Set `dns_api_token` to `ACCESS_KEY_ID:SECRET_ACCESS_KEY` (the access key
   ID, a colon, the secret access key). The add-on splits it at the first
   colon and passes both parts to Caddy's `route53` module (`access_key_id` /
   `secret_access_key`). Before 2.0.0 this format was rendered as a single
   positional argument, which the module rejects.

#### Hetzner DNS Setup

Since 2.0.0 the add-on uses the Hetzner module v2, which manages DNS zones in
the **Hetzner Console** through the Hetzner Cloud API. The previous module
(v1) used the deprecated DNS Console API (`dns.hetzner.com`) and its tokens
no longer work with the add-on.

1. Make sure the zone is managed in the [Hetzner Console](https://console.hetzner.cloud/)
   (zones from the old DNS Console have to be moved there)
2. In the project that holds the zone, go to **Security > API tokens** and
   create a token with **Read & Write** permission
3. Copy the token to `dns_api_token`

## Downloading Client Certificates

### Method 1: Web Interface (Recommended)

1. Open the add-on's web UI from the Home Assistant sidebar (admin only)
2. Click the download button for each client certificate

> The download links are served through Home Assistant Ingress and require an
> authenticated admin session. There are intentionally no QR codes: a QR
> scanned from another device would land on a session-less request and be
> rejected.

### Method 2: File Access

At every start (with mTLS on) the add-on copies these files into the `certs`
folder of its own configuration folder in Home Assistant:

- `mTLS-CA.crt` - the CA certificate,
- `mTLS-CA.crl` - the certificate revocation list,
- `mTLS-client-<name>.p12` - the bundle of each **active** client.

The folder is `app_configs/<slug>/certs/`. The slug ends in `_caddy_mtls`:
it is `2644ca2c_caddy_mtls` when you added the repository as
`https://github.com/LinumIQ/ha-apps`, and `local_caddy_mtls` for a local
copy in the `local_apps` (formerly `addons`) folder. The web interface shows
the exact folder under **Client certificates**. To reach it:

- **Samba share** app: the share `app_configs`, folder
  `<slug>/certs/` (the old share name `addon_configs` still works);
- **Terminal & SSH** app: `/app_configs/<slug>/certs/` (before version 10.5
  of that app: `/addon_configs/<slug>/certs/`);
- **File editor** app: `/app_configs/<slug>/certs/`, only with its option
  `enforce_basepath: false`.

Older versions of Home Assistant (Supervisor before 2026.7) call the folder
`addon_configs` instead of `app_configs`.

The copy is refreshed only when the add-on starts: a client you create,
regenerate or revoke in the web interface, and a regenerated CA, show up there
after the next restart. Since 2.3.0 the bundle of a client that is no longer
active is removed from the folder at the start (before, it stayed there).
The copies are for download only: deleting them revokes nothing.

## Installing Client Certificates

### iOS / iPadOS

1. Download the .p12 file (tap download link)
2. Go to **Settings → Profile Downloaded**
3. Tap **Install** and enter your device passcode
4. Enter the certificate password when prompted
5. Go to **Settings → General → About → Certificate Trust Settings**
6. Enable full trust for the CA certificate

### Android

1. Download the .p12 file
2. Go to **Settings → Security → Encryption & credentials**
3. Tap **Install a certificate → VPN & app user certificate**
4. Select the downloaded .p12 file
5. Enter the certificate password
6. Name the certificate and tap OK

### Windows

1. Download the .p12 file
2. Double-click the file to open the Certificate Import Wizard
3. Select **Current User** and click Next
4. Click Next to confirm the file path
5. Enter the certificate password
6. Select **Automatically select the certificate store**
7. Click Finish

### macOS

1. Download the .p12 file
2. Double-click to open in Keychain Access
3. Select **login** keychain
4. Enter the certificate password when prompted
5. The certificate will be added to your keychain

### Linux (Firefox)

1. Download the .p12 file
2. Open Firefox and go to **Settings → Privacy & Security → Certificates**
3. Click **View Certificates → Your Certificates** tab
4. Click **Import** and select the .p12 file
5. Enter the certificate password

### Linux (Chrome/Chromium)

1. Download the .p12 file
2. Go to **Settings → Privacy and security → Security → Manage certificates**
3. Click **Import** and select the .p12 file
4. Enter the certificate password

## Public certificate status (since 2.0.1)

The first card of the web interface shows the state of the server
certificate that Caddy gets from Let's Encrypt for your `domain` (the one
browsers see; not the mTLS client certificates). It reloads itself every
30 seconds:

- **Valid** (green): issuer, expiry date and days left, and whether Caddy
  serves this certificate on port 443 right now. Caddy renews it
  automatically.
- **Requesting** (blue): the add-on has just started and Caddy is asking
  Let's Encrypt for a certificate - usually less than a minute.
- **Missing** (red): no certificate yet (or the stored one expired) -
  `<domain>` is not reachable over HTTPS. The card shows Let's Encrypt's
  last error with its time (for example `connection: 203.0.113.7: Fetching
  http://<domain>/.well-known/acme-challenge/...: Connection refused` when
  the router does not forward port 80 yet), the result of each challenge
  type, and a checklist with **this add-on's real host ports**: the router
  forwards external TCP 80 to `<HA host>:8080` and TCP 443 to
  `<HA host>:8443` (or the ports you set in the Network settings), the domain
  resolves to your public IP address, no other device answers on those
  ports, Home Assistant itself does not use host ports 80/443 if you gave
  them to the add-on, and the connection has a public IPv4 address (no
  carrier-grade NAT / DS-Lite). Caddy retries on its own with growing delays
  (1, 2, 2, 5, 10 minutes, ...); **after fixing the forwarding, restart the
  add-on to retry immediately**.
- **Renewal failing** (yellow): the certificate is still valid, but Caddy
  could not renew it - the same error and checklist; fix it before the
  certificate expires.

While there is no certificate, the `cert-monitor` service checks every
minute (also during the first 30 minutes after every start) and, after two
minutes without a certificate, raises a Home Assistant notification **"Caddy
mTLS: no public certificate for `<domain>`"** with the last error and the
same checklist. It dismisses the notification as soon as the certificate
exists. The add-on log gets one line when the state changes, e.g. `No public
certificate for <domain> after 2 minutes - last error: ...` and later
`Public certificate for <domain>: Let's Encrypt (E7), valid until ...`.

Sources: the certificate in Caddy's storage
(`/data/caddy/certificates/<issuer>/<domain>/<domain>.crt`) and Caddy's
certificate events, which it also writes to `/data/caddy/log/acme.log` (JSON,
readable only inside the add-on, rotated at 1 MB). Only events since the
current start count.

## Web Certificate Manager

The ingress panel exposes a dashboard with the following capabilities (all
require an authenticated Home Assistant admin session and are restricted to
the Supervisor ingress IP):

- **Public certificate** - the card described in
  [Public certificate status](#public-certificate-status-since-201).
- **Home Assistant connection** (since 2.2.0) - whether Home Assistant
  accepts this add-on as a reverse proxy and sees each visitor's address,
  or sees every visitor as the add-on (and what that means), or answers
  every request `400: Bad Request` (red, also a Home Assistant
  notification), or does not answer at all; with the steps to change it and
  **Check again**. See
  [Home Assistant Core Configuration](#home-assistant-core-configuration).

- **Add a client** - issues a new client certificate, adds it to the
  active allowlist and reloads Caddy in-place. A name has 1-64 characters
  (letters, digits, `.`, `_`, `-`) and does not start with a dot - the same
  rule as for `client_names`. A name that already exists (also a revoked
  one) is rejected with an error message.
- **Revoke a client** - revokes the cert in the CA database, regenerates
  the CRL, removes the client from the active allowlist and reloads
  Caddy. Subsequent handshakes from that client are rejected.
- **Regenerate a client** - revokes the old serial (it remains in the
  CRL) and issues a fresh certificate under the same name.
- **Regenerate the CA** - destructive: a new CA, new certificates for the
  active clients; every existing client bundle stops working. Revoked
  clients stay revoked (they stay in the list as history and are not
  re-issued). Requires you to type `REGENERATE-CA` in the confirmation
  field; any other value is rejected with an error message.
- **Downloads** - CA certificate, CRL and per-client `.p12` bundles.

## Adding New Users

The recommended path is the Web Certificate Manager (above): no restart is
needed. The `client_names` option works as well - at every start, the
add-on issues a certificate for each listed name it does not know yet:

1. Go to the add-on configuration
2. Add new names to the `client_names` list
3. Restart the add-on
4. Download the new certificates from the web interface

Names have 1-64 characters (letters, digits, `.`, `_`, `-`) and do not
start with a dot; Supervisor refuses the configuration otherwise. The
option never revokes anything: removing a name keeps its certificate valid
(use **Revoke** in the panel), and a listed name whose client was revoked
is skipped with a warning in the log - a revoked name is never issued
again, so pick a new name for a replacement device.

## Changing the certificate password

`client_cert_password` protects the `.p12` bundles (the default `LinumIQ` is
public - set your own). After you change it, the add-on checks at the next
start whether each active client's bundle opens with the new password and
re-encrypts every one that does not (the log shows one line per bundle);
the copies in the add-on's `certs` folder (`app_configs/<slug>/certs/`, see
[Method 2: File Access](#method-2-file-access)) are refreshed too. Download the bundles again and give your users the new password -
bundles they downloaded before keep the old one.

## Certificate Revocation

### Revoking a single client (recommended)

Use the **Revoke** button in the Web Certificate Manager. The client is
removed from the allowlist of accepted certificates and Caddy is reloaded
immediately, so its next connection is refused; its serial is added to the
CRL served at `http://<your-domain>/mTLS-CA.crl`.

### Revoking all client certificates

If you have lost control of the CA itself (e.g. compromised key), use
**Regenerate CA** in the Web Certificate Manager (typed confirmation
required). This creates a new CA, invalidates every existing client
bundle and issues new certificates for the **active** clients - download
and distribute them again. Revoked clients stay revoked; revoke the clients
you want to drop for good before regenerating the CA.

Deleting files in the add-on's `certs` folder (`app_configs/<slug>/certs/`)
or removing names from `client_names` revokes nothing: that folder only holds
copies for download.

## Expiration Notifications

When the add-on starts, a `cert-monitor` long-run service publishes a
sensor entity per certificate to Home Assistant via the Supervisor
proxy:

- `sensor.caddy_mtls_ca_expiry`
- `sensor.caddy_mtls_client_<slug>_expiry` for each active client

Home Assistant entity ids allow only lowercase letters, digits and single
underscores, so `<slug>` is the client name in lowercase with every run of
other characters replaced by `_` (no `_` at the start or end): `alice-phone`
and `Alice.Phone` become `alice_phone`, i.e.
`sensor.caddy_mtls_client_alice_phone_expiry`. If two clients end up with the
same slug, the one created later gets a short hash of its name appended
(`Alice.Phone` after `alice-phone`: `alice_phone_1dbb0f`). The friendly name
shows the client name as it is.

The sensor value is the number of days remaining until the certificate
expires (`unit_of_measurement: d`), with the exact `not_after` timestamp
in the attributes. Use these in automations / Lovelace cards.

Whenever a certificate's days-remaining first drops to or below one of
the `cert_expiry_warn_days` thresholds, a persistent notification is
raised in Home Assistant. Each (certificate, threshold) pair fires at
most once - rotating the certificate (which changes its serial) resets
the state.

## Troubleshooting

### "400: Bad Request"

A bare page with `400: Bad Request` (after selecting the client certificate)
comes from Home Assistant, not from the add-on: Home Assistant received the
visitor's address from a proxy it does not trust. Open the add-on's web
interface: the card **Home Assistant connection** is red and says why -
`forwarded_headers: always`, or mTLS is off (then the add-on never hides the
visitor addresses). Let Home Assistant trust the add-on (see
[Passing the real visitor addresses on](#passing-the-real-visitor-addresses-on-recommended)),
or with mTLS on set `forwarded_headers` to `auto`. With mTLS off,
`forwarded_headers: never` is no way out - the add-on refuses to start with
it ([why](#what-the-add-on-does-option-forwarded_headers-since-220)). If the
card says **Change not applied**, Caddy could not be reloaded for a change of
the forwarding mode: the card shows the error and what Caddy still runs; the
add-on retries, and a restart of the add-on applies it as well. Up to 2.1.x
this was the answer to every request until Home Assistant trusted the
add-on; since 2.2.0 `forwarded_headers: auto` avoids it.

### No public certificate / "not reachable over HTTPS"

Open the add-on's web interface: the **Public certificate** card shows the
last error from Let's Encrypt and a checklist with the host ports to forward
(see [Public certificate status](#public-certificate-status-since-201)).
`connection` errors such as `Connection refused` or `Timeout during connect`
mean Let's Encrypt could not reach the add-on through the router; `dns`
errors mean the domain does not resolve to your public IP address. Restart
the add-on after fixing it - Caddy would otherwise wait for its next retry.

### The add-on shows "Start" although it is running / restarts by itself

Home Assistant offers **Stop** only while the add-on is in the state
`started`. It derives the state from Docker:

- `startup` right after every (re)start, until the first successful health
  check - the add-on page shows **Start** during this time. The health check
  probes Caddy's admin API and the web interface; during the first two
  minutes Docker runs it every 5 seconds, so this normally lasts 5 seconds.
- `started` after the first successful health check. A failing health check
  (since 2.0.1: 5 failures in a row, checked once a minute) leaves the state
  at `started`, but marks the add-on **unhealthy**.
- `stopped` (exit code 0) or `error` (any other exit code) when the
  container has ended.

So a page that switches between Start and Stop means that the add-on really
restarts. The usual reason is the **Watchdog** switch on the add-on's Info
page: the Supervisor restarts an add-on that is unhealthy or has stopped on
its own. Look at **Settings > System > Logs > Supervisor** for lines such as

- `Watchdog found app Caddy mTLS Proxy is unhealthy, restarting...`
- `Watchdog found app Caddy mTLS Proxy exited with code 137, restarting...`
  and `App Caddy mTLS Proxy exited with non-zero exit code 137` (a crash)
- `Watchdog found app Caddy mTLS Proxy is stopped, restarting...` (the
  container ended with exit code 0 without a stop request - up to 2.0.0 also
  after a Caddy crash)

and at the add-on log for the reason (a new start begins with the banner
`App: Caddy mTLS Proxy`). Since 2.0.1 a Caddy crash ends the add-on with
Caddy's exit code (128 + signal number when it was killed, e.g. 137), so
the Supervisor shows `error` instead of a normal stop; before, a crash looked
like a stop (exit code 0) and was restarted silently by the Watchdog.

### Stopping takes long or logs s6 warnings

A stop takes a few seconds: s6 stops Caddy (which gives open requests up to
10 seconds), the web interface and the monitor, then the init service. The
Supervisor waits up to 60 seconds (`timeout` in the add-on configuration)
before it kills the container. Warnings such as `finish script lifetime
reached maximum value` or `unable to stop service init-caddy: command exited
111` appeared on every stop up to 2.0.0 and are fixed in 2.0.1.

### The local-network port answers "403 Forbidden"

The port answers private addresses only. The message names the address the
add-on saw. A public address means the connection did not come from your
local network - or came over IPv6 with a public address: let the domain
resolve to the host's IPv4 address in your local DNS. "The address of
Docker" means Docker hid the real address (an IPv6 connection, or one from
the Home Assistant host itself): connect over IPv4 from another device.
Devices that come through a VPN (for example Tailscale, whose addresses
100.64.0.0/10 are not private, or a VPN app on the same host, whose
connections arrive under Docker's address) are refused as well: they use
the client-certificate address `https://<domain>/`.

### "Connection refused" errors

- Ensure the external ports 80 and 443 are forwarded to the add-on's host
  ports - **8080 and 8443 by default** since 2.0.0 (the add-on log shows the
  published host ports on every start; see
  [Ports](#ports-8080-and-8443-on-the-host-since-200))
- After updating from 1.x: an installation whose Network settings were never
  customised now publishes 8080/8443 instead of 80/443 - adjust the port
  forwarding or set the host ports back in the add-on's **Network** settings
- Check that no other service is using these host ports
- Verify your domain points to the correct IP

### "Certificate not trusted" on clients

- Make sure you've installed the CA certificate (not just the client certificate)
- On iOS, enable full trust for the CA in Certificate Trust Settings
- On Android, you may need to enable the certificate in your browser settings

### Let's Encrypt rate limits

- Let's Encrypt has rate limits (50 certificates per domain per week)
- If you hit limits, wait before requesting new certificates
- Use staging environment for testing (not currently exposed in this add-on)

### DNS-01 challenge failures

- Verify your API token has the correct permissions
- Check that the domain is managed by the selected DNS provider
- Wait a few minutes for DNS propagation

## Running outside Home Assistant (tests)

The image can be started without Supervisor (this is what the smoke tests in
`tests/` do):

- Supervisor normally provides `/data/options.json` and the Supervisor API.
  Outside it, copy an `options.json` into `/data` **and** into bashio's cache
  `/tmp/.bashio/addons.self.options.config.cache` (bashio reads the options
  from there instead of asking the API). Without a Supervisor token the
  add-on logs `Host ports: unknown (no Supervisor API)` and the expiry
  monitor publishes nothing.
- `ACME_CA_URL` (environment variable, test-only - Supervisor offers no way to
  set it): replaces the ACME directories of Let's Encrypt and ZeroSSL, as the
  global `acme_ca` option and, with a DNS provider, as the site's `ca`. The
  smoke tests point it at a closed local port (`http://127.0.0.1:9/directory`)
  so that no request leaves the container; it is also useful with a local
  test CA such as Pebble. Only plain `http(s)://` URLs are accepted.
- `ALLOWED_INGRESS_IPS` (environment variable, default `172.30.32.2,127.0.0.1`):
  the client addresses the certificate manager panel answers.
- `SUPERVISOR_URL` (environment variable, test-only, default
  `http://supervisor`): where the `cert-monitor` sends sensors and
  notifications; with `SUPERVISOR_TOKEN` the smoke tests point it at a fake
  Supervisor inside the container (`tests/fake-supervisor.py`).
  `CERT_MONITOR_PUBLIC_CERT_GRACE_SECONDS` (default 120) and
  `CERT_MONITOR_FAST_INTERVAL_SECONDS` (default 60) shorten the public
  certificate notification's delay and check interval for the tests.
- `CADDY_MTLS_UPSTREAM_CONTROL_SECONDS` (default 12),
  `CADDY_MTLS_UPSTREAM_TEST_SECONDS` (default 60) and
  `CADDY_MTLS_UPSTREAM_FAST_SECONDS` (default 2.5) (environment variables,
  test-only): how often the monitor watches Home Assistant (a request without
  forwarding headers, which Home Assistant does not log), how often it
  repeats the test request while Home Assistant trusts the add-on under
  `forwarded_headers: auto`, and how often it watches while nothing has been
  decided and Home Assistant does not answer.
- Without the Supervisor API the add-on reaches `homeassistant:8123`
  (`upstream_port` unset) only where a host of that name exists; the tests
  set `upstream_host`/`upstream_port` or provide the name.

Tests (all but the unit tests need docker; run them against an image built
from this directory):

```sh
docker build --build-arg BUILD_FROM=ghcr.io/hassio-addons/base:21.0.11 \
    --build-arg BUILD_ARCH=amd64 -t caddy-mtls-test caddy-mtls
caddy-mtls/tests/smoke.sh caddy-mtls-test
caddy-mtls/tests/apparmor-smoke.sh caddy-mtls-test caddy-mtls/apparmor.txt
python3 -m unittest discover -s caddy-mtls/tests/unit -v
# not in CI (pulls Home Assistant Core, about 2 GB; about 10 minutes):
caddy-mtls/tests/real-core.sh caddy-mtls-test [ghcr.io/linumiq/amd64-addon-caddy-mtls:2.1.3]
```

- `tests/smoke.sh <image>` boots the image several times with
  `--network none` (no external traffic): the panel, the CA and client
  certificates, real mTLS handshakes before and after adding, revoking and
  regenerating clients (also without the CA database's copy or the `.crt`),
  "Regenerate CA", the CRL, the plain-HTTP site, two restarts as Supervisor
  does them (a new container with the previous `/data`: new and invalid
  `client_names`, a changed `client_cert_password`), `mtls_enabled: false`,
  one start per DNS provider (dummy tokens; the rendered `dns` directive must
  pass `caddy validate` and Caddy must run with it), the log hygiene (no
  access log by default, silent health probes, `access_log: true`), the
  "Public certificate" card in all states and its notification at a fake
  Supervisor, clean stops (< 10 s, exit code 0, no s6 warnings) and a Caddy
  crash (the add-on ends with exit code 137). For `forwarded_headers` it
  runs a fake Home Assistant (`tests/fake-upstream.py`: refuses
  `X-Forwarded-For` with `400: Bad Request` unless told to trust the proxy,
  echoes the request headers otherwise) in a container whose network
  namespace the add-on shares: the start probe, the headers that arrive in
  each mode (spoofed client headers included), the switch at run time in
  both directions (after a "restart" of the fake and by the periodic test),
  the number of refused requests (= Home Assistant log lines) per phase,
  "Check again", the card in every state, both notifications, a failed
  reload (red card, what Caddy really runs, one ERROR line, the repair), the
  last known mode while the upstream is down, `always`, `never` and `auto`
  without mTLS, `never` without mTLS refused at the start, the texts for an
  upstream that is not Home Assistant.
  Prints PASS/FAIL per check; exit 0 = all passed, 1 = a check failed,
  2 = usage error.
- `tests/apparmor-smoke.sh <image> <apparmor.txt>` (needs root or sudo and an
  AppArmor kernel) loads the profile in enforce mode, boots the image under
  it, adds and revokes a client, shows the "Public certificate" card, raises
  and dismisses the notification at a fake Supervisor, restarts it with a new
  client name and a new `client_cert_password` and fails on any AppArmor
  denial (kernel log and, if auditd runs, the audit log).
- `tests/unit/` (standard library only, also run by CI): the expiry
  monitor's entity ids and notification thresholds, the public certificate
  state (Caddy's log events, storage, checklist) and the notification's
  state machine with a mocked Supervisor; the forwarding headers
  (`upstream.py`: the probe's classification against a fake Home Assistant
  on 127.0.0.1, the decision for every combination of option, mTLS and the
  last result, the snippet, the state file, the trusted-proxy suggestion,
  the monitor's cadence and noise rules over a simulated day, the
  notification); the panel's templates (with Jinja2, inside the image).
- `tests/real-core.sh <image> [<2.1.x image>]` (not in CI) runs Home
  Assistant Core 2026.11.3 on an `--internal` Docker network as
  `homeassistant:8123`, onboards a test user and checks against it: 2.1.x
  answered `400: Bad Request`; `always` is red with a notification; `auto`
  loads the page through the mTLS port with the add-on's address in Core's
  log; an `http:` block in `configuration.yaml` is ignored by Core (repair
  "yaml_still_present_after_migration"); the reverse-proxy settings set
  through Core's own API (what **Settings > System > Network > HTTP server**
  does) make the running add-on switch to passing addresses on, with the
  client's real address in Core's log; removing them switches back; the
  websocket (`/api/websocket`) works through the proxy in both modes. With
  the monitor's default intervals: the first start with Core down (the
  switch within 5 s of Core's first answer, no "addresses hidden"
  notification), a Core restart right after the add-on's start, trust
  removed while passing addresses on (noticed within one control interval,
  the "addresses hidden" notification), Core paused
  for 15 s (nothing happens) and for 40 s (unreachable, no 502 claim). It
  counts the lines that each phase writes into Core's log.
  `REALCORE_PREFIX`, `REALCORE_SUBNET` and `REALCORE_EVIDENCE` set the name
  prefix, the test network and a directory for the logs.

## Maintainers: Python dependencies

`requirements.in` lists the panel's direct dependencies (with the security
minimums); `requirements.txt` is generated from it with hashes by
`pip-compile` in the image's Python version - the command is in the header of
`requirements.in`. The image installs it into a virtualenv
(`/usr/lib/cert-mgr/.venv`) with `pip --require-hashes --only-binary=:all:`;
the build fails if a downloaded wheel does not match its hash. Alpine's
`py3-*` packages are not used (Alpine 3.24's `py3-starlette` 1.1.0 is below
the 1.3.1 security minimum).

## Logs

View add-on logs in Home Assistant:

1. Go to **Settings → Add-ons → Caddy mTLS Proxy**
2. Click the **Log** tab

What the log shows with the default `log_level: info` (since 2.0.1):

- the start-up (options, certificates, the published host ports), Caddy's
  messages including every certificate event (obtaining, renewing, errors),
  warnings and errors, and one line per change of the public certificate
  state;
- **not** every request: Caddy's access log (`handled request`, about
  1.5 KB per request - opening the Home Assistant frontend through the proxy
  makes several hundred) is off unless `access_log: true`; the health checks
  (Caddy's admin API, the web interface) and the web interface's own
  requests are not logged; `openssl` no longer prints each issued client
  certificate.

`log_level: debug` (or `trace`) turns all of these on again, including the
access logs.

## Support

For issues and feature requests, please visit:
https://github.com/LinumIQ/ha-apps/issues
