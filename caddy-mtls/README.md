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

1. **Add the repository** to your Home Assistant add-on store
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

# Upstream (default: Home Assistant)
upstream_host: homeassistant
upstream_port: 8123

# mTLS settings
mtls_enabled: true
client_names:
  - john-phone
  - john-laptop
  - mary-tablet
client_cert_password: your-secure-password

# CA certificate details
ca_country: US
ca_state: California
ca_locality: San Francisco
ca_organization: My Home
ca_common_name: Home Assistant mTLS CA

# DNS challenge (optional, for when port 80 is blocked)
acme_dns_provider: none # or: cloudflare, route53, hetzner
dns_api_token: ""
```

## Network Requirements

- **Port 80**: Required for Let's Encrypt HTTP-01 challenge (unless using DNS challenge)
- **Port 443**: HTTPS traffic with mTLS
- **Domain**: Must point to your Home Assistant's public IP

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
Internet → Router:443 → Caddy (mTLS) → Home Assistant:8123
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
