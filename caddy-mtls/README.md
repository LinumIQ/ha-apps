# Caddy mTLS Proxy for Home Assistant

[![Home Assistant Add-on](https://img.shields.io/badge/Home%20Assistant-Add--on-blue.svg)](https://www.home-assistant.io/addons/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](../LICENSE)

A Home Assistant add-on that provides a Caddy reverse proxy with mutual TLS (mTLS) authentication. Secure your Home Assistant with client certificates and automatic HTTPS via Let's Encrypt.

## Features

- 🔒 **Automatic HTTPS** - Let's Encrypt certificates with automatic renewal
- 🔐 **mTLS Authentication** - Require client certificates for access
- 📱 **Easy Distribution** - Web interface with QR codes for mobile certificate download
- 🌐 **DNS Challenge Support** - Cloudflare, Route53, and Hetzner for when port 80 is unavailable
- 👥 **Multiple Users** - Generate individual certificates for each user/device
- 🏠 **Home Assistant Native** - Full integration with HA add-on system

## Quick Start

[![Open your Home Assistant instance and show the add add-on repository dialog with a specific repository URL pre-filled.](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2FLinumIQ%2Fha-apps)

1. **Add the repository** to your Home Assistant add-on store (use the button above)
2. **Install** the "Caddy mTLS Proxy" add-on
3. **Configure** your domain and email:
   ```yaml
   domain: home.example.com
   email: your@email.com
   ```
4. **Start** the add-on
5. **Download** client certificates from the add-on web interface

## Configuration

```yaml
# Required
domain: home.example.com
email: admin@example.com

# Upstream (default: Home Assistant Core; without upstream_port the add-on
# uses Core's own port as reported by the Supervisor)
upstream_host: homeassistant
# upstream_port: 8123

# mTLS settings
mtls_enabled: true
client_names:
  - john-phone
  - john-laptop
  - mary-tablet
client_cert_password: your-secure-password

# CA certificate details
ca_country: AT
ca_state: Styria
ca_locality: Graz
ca_organization: LinumIQ
ca_common_name: Home Assistant mTLS CA

# DNS challenge (optional, for when port 80 is blocked)
acme_dns_provider: none # or: cloudflare, route53, hetzner
dns_api_token: ""
```

## Network Requirements

Caddy listens on ports 80 and 443 inside the add-on; on the Home Assistant
host they are published as **8080** and **8443** by default (since 2.0.0:
new Home Assistant OS installations, 2026.8 and later, serve Home Assistant
itself on ports 80 and 443). Forward the public ports from your router:

- **External TCP 80 -> host port 8080**: Let's Encrypt HTTP-01 challenge
  (unless using a DNS challenge), the CRL URL and the redirect to HTTPS
- **External TCP 443 -> host port 8443**: HTTPS traffic with mTLS
- **Domain**: Must point to your Home Assistant's public IP

The host ports can be changed in the add-on's **Network** settings (e.g. back
to 80/443 where Home Assistant does not use them). In the LAN, use
`https://<domain>:8443` (or the public URL with NAT loopback). See
[DOCS.md](DOCS.md#ports-8080-and-8443-on-the-host-since-200).

## Certificate Management

### Adding Users

Add names to the `client_names` list and restart the add-on:

```yaml
client_names:
  - existing-user
  - new-user # Added
```

### Revoking Access

To revoke all certificates:

1. Stop the add-on
2. Delete `/addon_configs/local_caddy_mtls/certs/`
3. Remove revoked users from `client_names`
4. Restart the add-on

## Documentation

See [DOCS.md](DOCS.md) for detailed documentation including:

- DNS provider setup (Cloudflare, Route53, Hetzner)
- Certificate installation guides for all platforms
- Troubleshooting tips

## Architecture

```
Internet → Router:443 → host:8443 → Caddy :443 (mTLS) → Home Assistant:8123
Internet → Router:80  → host:8080 → Caddy :80  (HTTP-01, CRL, redirect to https)
                                       ↓
                                 Let's Encrypt
```

## License

Apache License 2.0 - see [LICENSE](../LICENSE) and [NOTICE](../NOTICE) at the
repository root for details.

## Contributing

Contributions are welcome! Please open an issue or pull request on GitHub.

## Credits

- [Caddy](https://caddyserver.com/) - The HTTP/2 web server with automatic HTTPS
- [Home Assistant](https://www.home-assistant.io/) - Open source home automation
