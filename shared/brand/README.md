# LinumIQ brand assets for the add-ons

This directory holds the sources of the add-on icons and logos. The PNGs that Home Assistant
shows are generated from them by `render.mjs`.

| Source (edit these) | Generated (commit, never edit) |
| --- | --- |
| `frp-tunnel/icon.svg` | `../../frp-tunnel/icon.png` (256x256 RGBA) |
| `caddy-mtls/icon.svg` | `../../caddy-mtls/icon.png` (256x256 RGBA) |
| `logo.mjs` + `<addon>/icon.svg` | `<addon>/logo.svg` (500x200), then `../../<addon>/logo.png` (500x200 RGBA) |
| `render.mjs`, `package.json`, `package-lock.json` | `node_modules/` (git-ignored) |

The panels also show `<addon>/icon.svg` in their header. The shared-UI sync copies it into each
add-on, because an image build only sees its own add-on directory. Keep it self-contained: no
external references, no fonts, no `<text>`.

## Family rules

- **Colours:** only Anchor Blue `#0883DA` and Spark Orange `#FF9D0B`, plus transparency. Nothing
  else: no white, black, greys, gradients or other hues. The secondary element of a mark is Anchor
  Blue at `stroke-opacity="0.7"`. Where that translucent blue crosses orange it blends, as the
  handle does in the LinumIQ logo.
- **Background:** transparent. Every mark must work on light and on dark backgrounds, because Home
  Assistant shows both themes. The sheets in the coordination evidence check `#FFFFFF` and
  `#0F172A`.
- **No text in icons.** The logos carry the add-on name, which is exactly `name:` of
  `config.yaml` (`logo.mjs` asserts it). The name is set in Roboto Bold, Anchor Blue, and
  converted to outlines. Gotham Rounded (the LinumIQ logo font) is not used outside the
  company logo, and the LinumIQ wordmark is not reproduced.
- **Frame:** every icon uses the LinumIQ ring (below) in Anchor Blue. The ring is the
  "LinumIQ app" signature. The L and the magnifier handle of the company logo are not reused.
- **Symbol:** one app-specific symbol inside the ring, drawn in the same stroke language
  (stroke 9.42 in the 256 viewBox, round caps and joins). The main element is orange; the
  secondary element is translucent blue. Keep it to two or three strokes, so it reads at 48 px
  (Home Assistant's add-on list) and is still recognisable at 24 px.

## The LinumIQ ring (family constant)

The ring was measured from `shop-favicon-1920.png`, the favicon of shop.linumiq.com (ring, L and
handle). Edges were found with sub-pixel accuracy along 601 rays from the centre, skipping the
handle, and a rounded-square model was fitted by least squares.

The result is two concentric rounded squares, rotated by 45 degrees, with circular-arc corners.
Corners point up, down, left and right; the straight edges face the diagonals. The fit is within
RMS 0.10 to 0.12 px and at most 0.38 px at 1920 px. The inner contour is the outer one offset
inwards by 210 px (half-side 210.1, radius 210.4). "Half-side" below is the distance from the centre to a straight edge (the apothem).

| Centreline | Favicon (1920 px, centre 960,960) | Icon (256 viewBox, centre 128,128, scale 0.125) |
| --- | --- | --- |
| Outer contour: half-side / corner radius | 829.0 / 603.3 | 103.63 / 75.41 |
| Inner contour: half-side / corner radius | 618.9 / 392.9 | 77.37 / 49.11 |
| Stroke width (both) | 75.35 | 9.42 |
| Outer extent of the ring | 0..1920 | 8..248 |
| Straight-edge half-length (outer / inner) | 225.7 / 226.0 | 28.22 / 28.26 |

Free space for the symbol inside the inner contour: 72.66 from the centre towards the straight
edges (diagonals) and 84.35 towards the corners (axes). Keep about 10 units of clearance.

In SVG the closed ring is two `<rect>` elements with `rx`, inside
`transform="rotate(45 128 128)"`. A ring with a gap is two `<path>` elements written for the
local right edge and rotated into place. `frp-tunnel/icon.svg` uses `rotate(-45)` to put the gap
in the up-right edge.

**Overlay check.** The icon ring was rendered back at favicon scale (viewBox `8 8 240 240` at
1920 px) and compared with the favicon's blue mask, excluding the handle wedge at 15 to 75
degrees. IoU is 0.99828: 1,068 of 621,954 ring pixels differ, all of them anti-aliased edge
pixels. The mean coverage difference is 0.0011.

## The marks

### frp-tunnel: "route"

An orange node in the centre stands for Home Assistant. An orange path leaves it, runs out
through a gap in the up-right ring wall, and ends in a translucent-blue node outside the ring,
which stands for the LinumIQ tunnel server. This is what the add-on does: an outbound tunnel
from inside the home network to the public side.

The broken ring gives the mark a silhouette that stays distinct at 24 px. It echoes how the
logo's handle breaks out of the ring without reusing the handle.

Geometry is in the local frame `translate(128 128) rotate(-45)`, with x along the up-right
diagonal:

- inner node: r 16 at the origin
- path: from x 16 to x 118
- outer node: r 14 at x 132
- ring gap: cap centres 18 off the path axis

The path's round end runs under the translucent node's stroke; that overlap is the blend.

### caddy-mtls: "keys"

Two keys point in opposite directions: an orange key on top pointing right, and a
translucent-blue key below pointing left. Both sides present a key, which is what mutual TLS
means: the server and the client each prove themselves with a certificate.

Checkpoint 2 tuning for the 48 px render: bows r 17 (was 14), and the teeth turned outward,
away from the other key. In the first drawing they pointed at the other key's bow with 2.6 units
of clearance. Teeth sit at the tip (length 15) and 18 units in (length 12).

| Clearance | Units |
| --- | --- |
| Bows to the inner contour | 11.4 |
| Teeth to the inner contour | 13.5 |
| Between the keys | 9.6 |

The keys do not overlap. Each key is a single `<path>`, so the translucent one is painted once,
with no darker spot at its joints.

The three other candidates per add-on are in the coordination evidence (checkpoint 1, with
rationale):

- frp-tunnel: chain links and tunnel portal
- caddy-mtls: padlock and shield

## Logos

The canvas is 500x200 with a transparent background, twice the "around 250x100" that Home
Assistant recommends.

- **Mark:** on the left, `icon.svg` scaled by 0.58333 (`translate(25.33 25.33)`), so the ring is
  140 px high, 30 px from the left edge and vertically centred (y 30..170).
- **Name:**
  - Position: 28 px right of the ring (x 198, aligned on the ink rather than the side bearing).
  - Type: Roboto Bold 48 px, leading 56, Anchor Blue fill.
  - Vertical centring: the text block is centred between the cap top of the first line and
    the last baseline.
- **Line breaks:**
  - "FRP Tunnel" fits on one line.
  - "Caddy mTLS Proxy" breaks after "mTLS". One line would need 32 px type, and both logos use
    the same size.

`logo.mjs` writes `<addon>/logo.svg` from `<addon>/icon.svg`, so editing an icon means
re-running it. The outlines come from opentype.js 1.3.4: `getPath(...).toPathData(2)`, with
kerning.

## Regenerating

```sh
cd shared/brand
npm ci --ignore-scripts              # exact pins from package-lock.json (no install scripts needed)
node render.mjs                      # icon.svg / logo.svg -> the four PNGs
node render.mjs --check              # verify the committed PNGs (see below)
node render.mjs --census             # verify the colours of the committed PNGs
```

After changing an `icon.svg`, regenerate the logos before rendering. This needs the font file
(it is not committed; only its outlines are):

```sh
curl -LO https://github.com/googlefonts/roboto-2/releases/download/v2.138/roboto-unhinted.zip
sha256sum roboto-unhinted.zip   # 70f64c718510a601fbcf752aafe644314dacaeb85474dc689c89787c4a72a728
unzip -j roboto-unhinted.zip Roboto-Bold.ttf
node logo.mjs --font Roboto-Bold.ttf           # refuses any other file: sha256 must be
                                               # 2ca2b3bfc2c2d43fa8f2b7227982d735fd537ecf113a4c56cc2d292bcc3106c8
node logo.mjs --font Roboto-Bold.ttf --check   # fails if a committed logo.svg differs
node render.mjs
```

`render.mjs` uses `@resvg/resvg-js` 2.6.2 with no fonts loaded; the sources contain outlines
only. `sharp` 0.35.5 is used only to decode PNGs for `--check` and `--census`.

**Determinism.** The output is byte-deterministic on linux-x64 with the pinned versions: three
runs in separate processes from different working directories produced identical files. Other
platforms have not been tested.

`--check` renders into a temp directory and fails on any of these:

- a missing PNG
- dimensions other than 256x256 or 500x200
- an IHDR other than 8-bit RGBA (colour type 6)
- any pixel channel that differs by more than 1

It prints `byte-identical` when the bytes match. When the bytes differ but the pixels are within
±1 (another renderer build), it says so explicitly.

`--census` decodes the committed PNGs and checks every pixel with alpha above 0. Its colour must
lie on the RGB segment from Spark Orange to Anchor Blue: pure orange, pure blue, or a blend of
blue over orange. Anti-aliasing changes only alpha. The tolerance is 2 + 255/alpha, to allow for
8-bit un-premultiplication. It reports blue, orange, blend and off-line counts and fails on any
off-line pixel.

**CI.** The `Lint` workflow (`.github/workflows/lint.yml`) runs the job `brand-assets`
("Brand assets (render check + colour census)") on every push and pull request to `main`. On
ubuntu-latest with Node 22 it runs, in `shared/brand`:

```sh
npm ci --ignore-scripts
node render.mjs --check
node render.mjs --census
```

A changed SVG without re-rendered PNGs, or a PNG with a stray colour, fails the build. The job
does not run `logo.mjs --check`, because that needs the Roboto download. Run it locally
whenever you change an `icon.svg` or `logo.mjs`.

## Licence note (Roboto)

The names in the logos are glyph outlines from **Roboto Bold, version 2.138**:

- File: `Roboto-Bold.ttf` in `roboto-unhinted.zip`
- Release: https://github.com/googlefonts/roboto-2/releases/tag/v2.138 (the official
  googlefonts/roboto repository, now named roboto-2)
- sha256 of the zip: `70f64c718510a601fbcf752aafe644314dacaeb85474dc689c89787c4a72a728`
- sha256 of the TTF: `2ca2b3bfc2c2d43fa8f2b7227982d735fd537ecf113a4c56cc2d292bcc3106c8`

Roboto 2.138 is licensed under the Apache License, Version 2.0, the same licence as this
repository. The font file itself is not redistributed here; only the outlines of the glyphs
used in the two names are, as paths in `<addon>/logo.svg` and the rendered `logo.png`.
