#!/usr/bin/env node
// Renders the brand SVG sources to the PNGs Home Assistant shows (see README.md):
//   shared/brand/<addon>/icon.svg -> <addon>/icon.png  256x256 RGBA
//   shared/brand/<addon>/logo.svg -> <addon>/logo.png  500x200 RGBA
//
//   node render.mjs           write the four PNGs
//   node render.mjs --check   render into a temp dir and compare with the committed PNGs:
//                             fails on a missing file, other dimensions or PNG type, or any
//                             pixel channel off by more than 1; reports byte identity
//   node render.mjs --census  pixel census of the committed PNGs: every visible pixel must be
//                             Anchor Blue, Spark Orange or a blend of the two (fails otherwise)
import { Resvg } from '@resvg/resvg-js';
import sharp from 'sharp';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..', '..');
const ADDONS = ['frp-tunnel', 'caddy-mtls'];
const TARGETS = ADDONS.flatMap((addon) => [
  { src: join(HERE, addon, 'icon.svg'), out: join(addon, 'icon.png'), w: 256, h: 256 },
  { src: join(HERE, addon, 'logo.svg'), out: join(addon, 'logo.png'), w: 500, h: 200 },
]);
const BLUE = [0x08, 0x83, 0xda], ORANGE = [0xff, 0x9d, 0x0b];

function render(t) {
  const svg = readFileSync(t.src, 'utf8');
  // no text in the sources (outlines only), so no fonts are loaded at all
  const img = new Resvg(svg, { fitTo: { mode: 'width', value: t.w }, font: { loadSystemFonts: false } }).render();
  if (img.width !== t.w || img.height !== t.h) throw new Error(`${t.src}: rendered ${img.width}x${img.height}, expected ${t.w}x${t.h}`);
  return img.asPng();
}

// PNG header: signature + IHDR (width, height, bit depth, colour type)
function ihdr(buf) {
  if (buf.length < 33 || buf.readUInt32BE(0) !== 0x89504e47 || buf.toString('latin1', 12, 16) !== 'IHDR') throw new Error('not a PNG');
  return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20), bitDepth: buf[24], colourType: buf[25] };
}

async function rawRGBA(buf) {
  const { data, info } = await sharp(buf).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  return { data, info };
}

async function check() {
  const tmp = mkdtempSync(join(tmpdir(), 'ha-apps-brand-'));
  let failed = false;
  try {
    for (const t of TARGETS) {
      const fresh = render(t);
      writeFileSync(join(tmp, t.out.replace('/', '-')), fresh);
      let cur;
      try { cur = readFileSync(join(REPO, t.out)); } catch { console.error(`MISSING  ${t.out}`); failed = true; continue; }
      const a = ihdr(cur), b = ihdr(fresh);
      if (a.width !== t.w || a.height !== t.h || a.bitDepth !== 8 || a.colourType !== 6) {
        console.error(`BAD      ${t.out}: ${a.width}x${a.height} depth ${a.bitDepth} colour type ${a.colourType} (want ${t.w}x${t.h}, 8-bit RGBA = type 6)`);
        failed = true; continue;
      }
      if (Buffer.compare(cur, fresh) === 0) { console.log(`ok       ${t.out} ${a.width}x${a.height} RGBA, byte-identical`); continue; }
      const [x, y] = [await rawRGBA(cur), await rawRGBA(fresh)];
      let maxDiff = 0;
      for (let i = 0; i < x.data.length; i++) maxDiff = Math.max(maxDiff, Math.abs(x.data[i] - y.data[i]));
      if (b.width !== a.width || b.height !== a.height || maxDiff > 1) {
        console.error(`DIFFERS  ${t.out}: max channel difference ${maxDiff} (re-run node render.mjs and commit)`);
        failed = true;
      } else console.log(`ok       ${t.out} ${a.width}x${a.height} RGBA, pixels within 1, bytes differ (other renderer build?)`);
    }
  } finally { rmSync(tmp, { recursive: true, force: true }); }
  return failed;
}

// Every pixel with alpha > 0 must lie on the RGB segment Spark Orange -> Anchor Blue
// (anti-aliasing only changes alpha; translucent blue over orange blends along the segment).
// Tolerance covers 8-bit un-premultiplication: 2 + 255 / alpha per channel distance.
async function census() {
  let failed = false;
  const seg = BLUE.map((v, i) => v - ORANGE[i]);
  const segLen2 = seg.reduce((s, v) => s + v * v, 0);
  for (const t of TARGETS) {
    const { data, info } = await rawRGBA(readFileSync(join(REPO, t.out)));
    const c = { transparent: 0, blue: 0, orange: 0, blend: 0, blendOpaque: 0, off: 0, offOpaque: 0, opaque: 0, maxDistOpaque: 0 };
    for (let i = 0; i < info.width * info.height; i++) {
      const a = data[i * 4 + 3];
      if (a === 0) { c.transparent++; continue; }
      const p = [data[i * 4], data[i * 4 + 1], data[i * 4 + 2]];
      const tt = Math.min(1, Math.max(0, p.reduce((s, v, k) => s + (v - ORANGE[k]) * seg[k], 0) / segLen2));
      const dist = Math.hypot(...p.map((v, k) => v - (ORANGE[k] + tt * seg[k])));
      const opaque = a >= 128;
      if (opaque) { c.opaque++; c.maxDistOpaque = Math.max(c.maxDistOpaque, dist); }
      if (dist > 2 + 255 / a) { c.off++; if (opaque) c.offOpaque++; continue; }
      if (tt >= 0.99) c.blue++; else if (tt <= 0.01) c.orange++; else { c.blend++; if (opaque) c.blendOpaque++; }
    }
    const ok = c.off === 0;
    if (!ok) failed = true;
    console.log(`${ok ? 'ok      ' : 'OFF-HUE '} ${t.out.padEnd(20)} ${info.width}x${info.height}: transparent ${c.transparent}, blue ${c.blue}, orange ${c.orange}, blend ${c.blend} (alpha>=128: ${c.blendOpaque}), off-line ${c.off} (alpha>=128: ${c.offOpaque} of ${c.opaque}, max distance ${c.maxDistOpaque.toFixed(2)})`);
  }
  return failed;
}

const mode = process.argv[2];
let failed = false;
if (mode === '--check') failed = await check();
else if (mode === '--census') failed = await census();
else if (mode === undefined) {
  for (const t of TARGETS) { const png = render(t); writeFileSync(join(REPO, t.out), png); console.log(`wrote    ${t.out} (${png.length} bytes)`); }
} else { console.error('usage: node render.mjs [--check | --census]'); process.exit(2); }
process.exit(failed ? 1 : 0);
