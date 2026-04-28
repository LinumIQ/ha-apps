# LinumIQ Home Assistant Add-ons

A repository of community-maintained Home Assistant add-ons by [LinumIQ](https://github.com/LinumIQ).

## Add-ons

### [Caddy mTLS Proxy](./caddy-mtls)

![Supports aarch64 Architecture][aarch64-shield]
![Supports amd64 Architecture][amd64-shield]
![Supports armv7 Architecture][armv7-shield]
![Supports i386 Architecture][i386-shield]

Caddy reverse proxy with mutual TLS (mTLS) client certificate authentication and
automatic HTTPS via Let's Encrypt. Secure your Home Assistant with strong client
certificate authentication and automatic certificate provisioning.

## Installation

1. In Home Assistant, navigate to **Settings → Add-ons → Add-on Store**.
2. Click the three-dot menu (⋮) in the top right and select **Repositories**.
3. Add the URL of this repository:
   ```
   https://github.com/LinumIQ/home-assistant-addons
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
[armv7-shield]: https://img.shields.io/badge/armv7-yes-green.svg
[i386-shield]: https://img.shields.io/badge/i386-yes-green.svg
