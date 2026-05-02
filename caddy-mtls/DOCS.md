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
2. **Port Forwarding**: Forward ports 80 and 443 from your router to Home Assistant
3. **Firewall**: Ensure ports 80 and 443 are open

### Port 80 Availability

Let's Encrypt requires port 80 for the HTTP-01 challenge. If port 80 is not available:

- Use the DNS-01 challenge by configuring a DNS provider (Cloudflare, Route53, or Hetzner)
- Ensure no other service is using port 80

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

| Option   | Description             | Example             |
| -------- | ----------------------- | ------------------- |
| `domain` | Your domain name        | `home.example.com`  |
| `email`  | Email for Let's Encrypt | `admin@example.com` |

### Optional Options

| Option                      | Default          | Description                                                                                                             |
| --------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `upstream_host`             | `homeassistant`  | Backend service hostname                                                                                                |
| `upstream_port`             | `8123`           | Backend service port                                                                                                    |
| `mtls_enabled`              | `true`           | Enable client certificate authentication                                                                                |
| `client_names`              | `["user"]`       | List of client certificate names                                                                                        |
| `client_cert_password`      | `LinumIQ`        | Password for .p12 files                                                                                                 |
| `log_level`                 | `info`           | Add-on / Caddy log verbosity (`trace`, `debug`, `info`, `notice`, `warning`, `error`, `fatal`)                          |
| `cert_expiry_warn_days`     | `[30, 14, 7, 1]` | List of days-before-expiry thresholds at which to fire a notification (one notification per crossed threshold per cert) |
| `cert_check_interval_hours` | `6`              | How often the `cert-monitor` service polls certificate metadata and publishes sensor states (`1`-`168`)                 |

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

2. Set `dns_api_token` to `ACCESS_KEY_ID:SECRET_ACCESS_KEY`

#### Hetzner DNS Setup

1. Go to [Hetzner DNS Console](https://dns.hetzner.com/settings/api-token)
2. Create a new API token
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
  active allowlist and reloads Caddy in-place. Names must match
  `[A-Za-z0-9._-]+`. Duplicate names are rejected with HTTP 409.
- **Revoke a client** - revokes the cert in the CA database, regenerates
  the CRL, removes the client from the active allowlist and reloads
  Caddy. Subsequent handshakes from that client are rejected.
- **Regenerate a client** - revokes the old serial (it remains in the
  CRL) and issues a fresh certificate under the same name.
- **Regenerate the CA** - destructive: invalidates every existing
  client certificate. Requires you to type `REGENERATE-CA` in the
  confirmation field; any other value returns HTTP 400.
- **Downloads** - CA certificate, CRL and per-client `.p12` bundles.

## Adding New Users

The recommended path is the Web Certificate Manager (above). The legacy
`client_names` option is still honoured: any name listed there is
ensured at start-up. To add a user permanently via configuration:

1. Go to the add-on configuration
2. Add new names to the `client_names` list
3. Restart the add-on
4. Download the new certificates from the web interface

## Certificate Revocation

### Revoking a single client (recommended)

Use the **Revoke** button in the Web Certificate Manager. The client's
serial is added to the CRL served at
`http://<your-domain>/mTLS-CA.crl` and Caddy is reloaded immediately.

### Revoking all client certificates

If you have lost control of the CA itself (e.g. compromised key), use
**Regenerate CA** in the Web Certificate Manager (typed confirmation
required). This rotates the CA, invalidates every existing client
certificate, and re-issues fresh certs for
client bundles.

## Expiration Notifications

When the add-on starts, a `cert-monitor` long-run service publishes a
sensor entity per certificate to Home Assistant via the Supervisor
proxy:

- `sensor.caddy_mtls_ca_expiry`
- `sensor.caddy_mtls_client_<name>_expiry`

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

- Ensure ports 80 and 443 are properly forwarded
- Check that no other service is using these ports
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

## Logs

View add-on logs in Home Assistant:

1. Go to **Settings → Add-ons → Caddy mTLS Proxy**
2. Click the **Log** tab

## Support

For issues and feature requests, please visit:
https://github.com/LinumIQ/ha-apps/issues
