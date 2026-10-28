# LinumIQ Home Assistant Add-ons

A repository of community-maintained Home Assistant add-ons by [LinumIQ](https://github.com/LinumIQ).

## Add-ons

### [Caddy mTLS Proxy](./caddy-mtls)

![Supports aarch64 Architecture][aarch64-shield]
![Supports amd64 Architecture][amd64-shield]

Caddy reverse proxy with mutual TLS (mTLS) client certificate authentication and
automatic HTTPS via Let's Encrypt. Secure your Home Assistant with strong client
certificate authentication and automatic certificate provisioning.

### [FRP Tunnel](./frp-tunnel)

![Supports aarch64 Architecture][aarch64-shield]
![Supports amd64 Architecture][amd64-shield]

Exposes Home Assistant at `https://<subdomain>.linumiq.net` through an
outbound-only, TLS-encrypted [frp](https://github.com/fatedier/frp) reverse
tunnel to the LinumIQ tunneling service - no port forwarding required. Pair the
add-on with your LinumIQ account from its ingress panel with a browser-based
device-authorization flow; no tokens or configuration files to copy.

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

## Releases (maintainers)

Each add-on is released on its own. Publish a GitHub release whose tag is
`<add-on directory>-v<version>`, with `<version>` exactly the `version` in that
add-on's `config.yaml` - e.g. `caddy-mtls-v2.0.0` or `frp-tunnel-v2.3.1`. The
**Builder** workflow then builds and pushes only that add-on, as
`ghcr.io/linumiq/{aarch64,amd64}-addon-<add-on directory>:<version>`; a tag
whose version does not match `config.yaml` fails the workflow. A tag without an
add-on prefix (such as the caddy-mtls tags `v1.1.0` ... `v1.2.7` from before
the per-add-on scheme) keeps the old behaviour and builds every add-on. A
version that is already in GHCR is skipped, never pushed again, so re-running a
release workflow is safe.

What users get depends on the add-on's `config.yaml`:

- **caddy-mtls** has an `image:` key: Supervisor pulls the prebuilt image, so
  users see a new version only after its release has been published (and the
  workflow has pushed the image). Merge a version bump and release it together.
- **frp-tunnel** has an `image:` key too (since 2.3.1, added on 2026-10-28):
  the same rule applies - release every version bump as
  `frp-tunnel-v<version>`; a bump on `main` without its release shows users an
  update whose image pull fails (see
  [frp-tunnel/DOCS.md](frp-tunnel/DOCS.md#maintainers-publishing-to-ghcr)).

## Development

Both add-ons' ingress panels share one look (the LinumIQ brand: colours,
Roboto and Inter, light and dark mode) from one source in this repository:

- [`shared/ui/`](shared/ui) - the shared panel UI: `static/linumiq.css`
  (design tokens and every generic component), `static/fonts/` (self-hosted
  Roboto and Inter, latin + latin-ext, licences and `SOURCES.md`),
  `static/brand/linumiq-logo.png` (the footer logo) and
  `templates/_layout.html` (the Jinja2 base template of both panels). Each
  panel keeps its own `static/app.css` and `templates/index.html`. Tools for
  maintainers (logo rendering, font download, offline previews and
  screenshots of every panel state) are described in
  [`shared/ui/README.md`](shared/ui/README.md).
- [`shared/brand/`](shared/brand) - the brand sources of the add-ons' icons
  and logos (SVG, with the script that renders `icon.png` / `logo.png`); see
  [`shared/brand/README.md`](shared/brand/README.md). Each add-on's
  `shared/brand/<add-on>/icon.svg` is also the mark in its panel header.

An add-on image is built from its own directory only, so the shared files are
**copied** into the add-ons by [`scripts/sync-shared.sh`](scripts/sync-shared.sh):
`shared/ui/static/` to `<add-on>/rootfs/usr/lib/<panel>/static/shared/`,
`shared/ui/templates/_layout.html` to `.../templates/_layout.html` and
`shared/brand/<add-on>/icon.svg` to `.../static/brand/icon.svg` (`<panel>` is
`frp-mgr` resp. `cert-mgr`). Never edit the copies (they start with a
`GENERATED` comment): edit `shared/`, run `scripts/sync-shared.sh` and commit
the source and the copies together. CI ("Shared UI in sync") runs
`scripts/sync-shared.sh --check`, which fails and lists the stale files when
a copy differs.

## License

Source code in this repository is licensed under the [Apache License 2.0](LICENSE).
See the [NOTICE](NOTICE) file for required attributions; the bundled fonts
Roboto and Inter are licensed under the SIL Open Font License 1.1.

The LinumIQ name and logo and the add-on icons are trademarks of LinumIQ and
not covered by the code licence.

## Contributing

Issues and pull requests are welcome. Please open an issue describing the
problem or proposed change before submitting a large change.

[aarch64-shield]: https://img.shields.io/badge/aarch64-yes-green.svg
[amd64-shield]: https://img.shields.io/badge/amd64-yes-green.svg
