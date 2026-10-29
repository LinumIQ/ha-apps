# Shared panel UI (LinumIQ look)

The single source of the look of both add-on ingress panels (FRP Tunnel's
pairing panel, Caddy mTLS's certificate manager). `scripts/sync-shared.sh`
copies it into the add-ons; see "Development" in the repository README.

| Path | What | Copied to (per add-on) |
| --- | --- | --- |
| `static/linumiq.css` | design tokens (light + dark), base, typography, header, cards, buttons, forms, flashes, status badges, definition lists, code, disclosure, footer, spinner, responsive rules | `static/shared/linumiq.css` |
| `static/fonts/` | Roboto + Inter (woff2, latin + latin-ext), `OFL-*.txt`, `SOURCES.md` | `static/shared/fonts/` |
| `static/brand/linumiq-logo.png` | footer logo, 360x99 (2x of 180 px) | `static/shared/brand/` |
| `templates/_layout.html` | Jinja2 base template (blocks: `title`, `head_extra`, `header`, `app_name`, `app_subtitle`, `flashes`, `content`, `footer_extra`, `scripts`) | `templates/_layout.html` |
| `brand-source/linumiq-logo-reference.png` | the owner's LinumIQ logo (1920x529), source of the footer logo | - |
| `tools/`, `preview/`, `package.json` | maintainer tools (below) | - |

Each panel adds its own `static/app.css` (app components; it may set
`--container-max` and `--meta-label-width` and uses the tokens) and its
`templates/index.html` (`{% extends "_layout.html" %}`); its mark
`static/brand/icon.svg` comes from `shared/brand/<add-on>/icon.svg`.

Rules: every URL stays relative (`static/...` in templates, `fonts/...` in
the CSS) because the panels live under Home Assistant's ingress path, and
nothing is loaded from another host (no Google Fonts, no CDN; the unit and
smoke tests check this). Theme: light by default, dark with
`prefers-color-scheme: dark`; `data-theme="light"` / `"dark"` on `<html>`
forces one. The header of `linumiq.css` lists the deliberate deviations from
the brand specification (panel type scale, warning text colour, semantic
colours), the button rule and the contrast exceptions.

Buttons are blue in both modes, as on https://shop.linumiq.com (the owner's
rule of 2026-10-29): `.btn` is Anchor Blue `#0883DA` with white text in light
mode and the shop's button blue `#60A4FA` with white text in dark mode;
`.btn-secondary` (outlined) and `.btn-danger` (destructive, red) are the
other two. No button is orange: Spark Orange is for highlights, warnings,
badges and stripes. The white button text is the one contrast exception,
3.99:1 on `#0883DA` (prescribed by the brand) and 2.56:1 on `#60A4FA` (the
shop's colour, the owner's reference); every other text pair is >= 4.5:1.

## Tools (maintainers; not part of the images)

    cd shared/ui && npm install        # sharp + Playwright, pinned in package-lock.json

- **Footer logo**: `npm run logo` renders `static/brand/linumiq-logo.png` from
  `brand-source/` with sharp; `npm run logo:check` re-renders it and fails if
  the committed file differs (dimensions, channels, pixels; the bytes are
  identical with the pinned sharp).
- **Fonts**: `python3 tools/fetch-fonts.py` downloads Roboto (400/600/700)
  and Inter (400/500/600) from Google Fonts' CSS API with a current browser
  User-Agent, keeps the latin and latin-ext subsets (variable fonts: one file
  per subset), the OFL licences from the fonts' repositories (pinned commits)
  and writes `SOURCES.md` (URLs, date, sizes, sha256). Copy changed
  `unicode-range`s it prints into the `@font-face` rules of `linumiq.css`.
- **Previews**: `preview/render-previews.py` renders every state of both
  panels offline from fixture contexts (frp-tunnel: unpaired, invalid
  options, pairing, pairing expired, approved without tunnel, paired, change
  dialog, TLS warning, TLS error; caddy-mtls: certificate ok, danger zone
  open, missing, renewal failing, pending with an empty state) into
  `preview/out/` (git-ignored). Needs Jinja2, e.g. a virtualenv with
  `pip install --require-hashes -r frp-tunnel/requirements.txt`.
- **Screenshots**: `npx playwright install chromium` once, then
  `node preview/screenshot.mjs [<dir>]` serves `preview/out/` the way the
  ingress proxy lays it out and captures each state at 400 and 1100 px in
  light and dark as `<app>-<state>-<width>-<mode>.png`. It also checks every
  capture (no request leaves 127.0.0.1, Roboto and Inter loaded, no
  horizontal scrolling, text contrast >= 4.5:1 / 3:1 for large text, no
  orange button and every `.btn` in the mode's blue, the `data-theme`
  switch) and writes `report.json`; exit 1 on a failed check.

Run `scripts/sync-shared.sh` after every change here (the preview script
refuses to run on stale copies).
