# LinumIQ Home Assistant Add-ons

A repository of community-maintained Home Assistant add-ons by [LinumIQ](https://github.com/LinumIQ).

## Add-ons

### [Caddy mTLS Proxy](./caddy-mtls)

![Supports aarch64 Architecture][aarch64-shield]
![Supports amd64 Architecture][amd64-shield]

Caddy reverse proxy with mutual TLS (mTLS) client certificate authentication and
automatic HTTPS via Let's Encrypt. Secure your Home Assistant with strong client
certificate authentication and automatic certificate provisioning.

## Installation

Click the button below to add this repository to your Home Assistant instance:

[![Open your Home Assistant instance and show the add add-on repository dialog with a specific repository URL pre-filled.](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2FLinumIQ%2Fha-apps)

Or add it manually:

1. In Home Assistant, navigate to **Settings → Add-ons → Add-on Store**.
2. Click the three-dot menu (⋮) in the top right and select **Repositories**.
3. Add the URL of this repository:
   ```
   https://github.com/LinumIQ/ha-apps
   ```
4. Click **Add**, then close the dialog.
5. The LinumIQ add-ons should now appear in the add-on store.

## License

Source code in this repository is licensed under the [Apache License 2.0](LICENSE).
See the [NOTICE](NOTICE) file for required attributions.

## Contributing

Issues and pull requests are welcome. Please open an issue describing the
problem or proposed change before submitting a large change.

[aarch64-shield]: https://img.shields.io/badge/aarch64-yes-green.svg
[amd64-shield]: https://img.shields.io/badge/amd64-yes-green.svg
