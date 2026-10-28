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
  resolving to the Home Assistant host (local DNS or hosts file). The
  certificate and the mTLS site are bound to the domain name, so
  `https://<ip-address>:8443` does not work. A plain-HTTP request to
  `http://<domain>:8080/` is redirected to `https://<domain>/` - port 443,
  i.e. the router path.

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
4. **Add the add-on to Home Assistant Core's trusted reverse proxies**
   (see [Home Assistant Core Configuration](#home-assistant-core-configuration)
   below) - without this, requests proxied through this add-on will be
   rejected with `400 Bad Request` by Home Assistant Core.
5. Start the add-on

## Home Assistant Core Configuration

Because this add-on terminates TLS and forwards requests to Home Assistant
Core, you must tell Home Assistant Core to trust the add-on as a reverse
proxy. Otherwise Home Assistant rejects the forwarded requests with
`400 Bad Request` (and silently logs `Received X-Forwarded-For header from
untrusted proxy`).

Add the following to `/config/configuration.yaml` (the file is editable
via the **File editor**, **Studio Code Server**, or **Samba** add-ons) and
restart Home Assistant Core:

```yaml
http:
  use_x_forwarded_for: true
  trusted_proxies:
    # Supervisor's internal Docker network. Covers this add-on regardless
    # of which IP the Supervisor assigns to it on each restart.
    - 172.30.32.0/23
```

If you already have an `http:` section, merge the two keys into it
instead of duplicating the section. The exact container IP of this
add-on is also printed in the add-on log on every start, in case you
prefer to whitelist a specific address instead of the whole Supervisor
network.

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
| `log_level`                 | `info`           | Add-on / Caddy log verbosity (`trace`, `debug`, `info`, `notice`, `warning`, `error`, `fatal`)                          |
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

Certificates are also available at:

- `/addon_configs/local_caddy_mtls/certs/` (via Samba or SSH add-ons)

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

## Web Certificate Manager

The ingress panel exposes a dashboard with the following capabilities (all
require an authenticated Home Assistant admin session and are restricted to
the Supervisor ingress IP):

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
the copies in the add-on's `certs` folder in `/addon_configs/` are refreshed
too. Download the bundles again and give your users the new password -
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

Deleting files in the add-on's `certs` folder in `/addon_configs/` or
removing names from `client_names` revokes nothing: that folder only holds
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

Tests (both need docker; run them against an image built from this directory):

```sh
docker build --build-arg BUILD_FROM=ghcr.io/hassio-addons/base:21.0.10 \
    --build-arg BUILD_ARCH=amd64 -t caddy-mtls-test caddy-mtls
caddy-mtls/tests/smoke.sh caddy-mtls-test
caddy-mtls/tests/apparmor-smoke.sh caddy-mtls-test caddy-mtls/apparmor.txt
python3 -m unittest discover -s caddy-mtls/tests/unit -v
```

- `tests/smoke.sh <image>` boots the image several times with
  `--network none` (no external traffic): the panel, the CA and client
  certificates, real mTLS handshakes before and after adding, revoking and
  regenerating clients (also without the CA database's copy or the `.crt`),
  "Regenerate CA", the CRL, the plain-HTTP site, two restarts as Supervisor
  does them (a new container with the previous `/data`: new and invalid
  `client_names`, a changed `client_cert_password`), `mtls_enabled: false`,
  one start per DNS provider (dummy tokens; the rendered `dns` directive must
  pass `caddy validate` and Caddy must run with it) and the log hygiene.
  Prints PASS/FAIL per check; exit 0 = all passed, 1 = a check failed,
  2 = usage error.
- `tests/apparmor-smoke.sh <image> <apparmor.txt>` (needs root or sudo and an
  AppArmor kernel) loads the profile in enforce mode, boots the image under
  it, adds and revokes a client, restarts it with a new client name and a new
  `client_cert_password` and fails on any AppArmor denial (kernel log and,
  if auditd runs, the audit log).
- `tests/unit/` (standard library only, also run by CI): the expiry
  monitor's entity ids and notification thresholds.

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

## Support

For issues and feature requests, please visit:
https://github.com/LinumIQ/ha-apps/issues
