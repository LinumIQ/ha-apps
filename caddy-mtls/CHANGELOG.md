# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-10

### Added

- Initial release of Caddy mTLS Proxy add-on
- Automatic HTTPS via Let's Encrypt
- Mutual TLS (mTLS) client certificate authentication
- Support for multiple client certificates
- Web interface for certificate download with QR codes
- DNS-01 ACME challenge support:
  - Cloudflare
  - AWS Route53
  - Hetzner DNS
- Configurable CA certificate subject fields
- Certificate files accessible via addon_config mapping
- Comprehensive documentation and import guides for:
  - iOS / iPadOS
  - Android
  - Windows
  - macOS
  - Linux (Firefox/Chrome)

### Security

- Client certificates use ECDSA (prime256v1) for strong security
- Certificates valid for 100 years
- Ingress endpoint restricted to Home Assistant proxy IP
- Admin API disabled for security

## [Unreleased]

### Planned

- Certificate revocation list (CRL) support
- Additional DNS providers based on user requests
- Certificate expiration notifications
- Web UI for certificate management (regenerate, revoke individual certs)
