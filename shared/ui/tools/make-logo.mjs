#!/usr/bin/env node
// Renders the LinumIQ logo of the panels' footer (maintainers only).
//
//   brand-source/linumiq-logo-reference.png (1920x529, RGBA, the owner's logo)
//     -> static/brand/linumiq-logo.png      (360 px wide = 2x of the 180 px
//                                             display width, RGBA, optimised)
//
//   npm install && npm run logo           (in shared/ui; then scripts/sync-shared.sh)
//   npm run logo:check                    re-renders into memory and compares
//
// --check fails when the committed PNG differs in dimensions, channels or
// decoded pixels from a fresh render; it also says whether the bytes are
// identical (they are with the pinned sharp version: libvips + libspng are
// deterministic).
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import sharp from "sharp";

const here = path.dirname(fileURLToPath(import.meta.url));
const SOURCE = path.join(here, "..", "brand-source", "linumiq-logo-reference.png");
const TARGET = path.join(here, "..", "static", "brand", "linumiq-logo.png");
const WIDTH = 360;

async function render() {
  return sharp(SOURCE)
    .ensureAlpha()
    .resize({ width: WIDTH, kernel: "lanczos3" })
    .png({ compressionLevel: 9, adaptiveFiltering: true, palette: false })
    .toBuffer();
}

async function decode(buf) {
  const { data, info } = await sharp(buf).raw().toBuffer({ resolveWithObject: true });
  return { data, info };
}

const fresh = await render();
if (process.argv.includes("--check")) {
  let committed;
  try {
    committed = await readFile(TARGET);
  } catch {
    console.error(`missing: ${path.relative(process.cwd(), TARGET)} (run npm run logo)`);
    process.exit(1);
  }
  const [a, b] = await Promise.all([decode(fresh), decode(committed)]);
  const same = a.info.width === b.info.width && a.info.height === b.info.height
    && a.info.channels === b.info.channels && a.data.equals(b.data);
  console.log(`${path.basename(TARGET)}: committed ${b.info.width}x${b.info.height}x${b.info.channels}, `
    + `fresh ${a.info.width}x${a.info.height}x${a.info.channels}; pixels ${same ? "identical" : "DIFFER"}; `
    + `bytes ${fresh.equals(committed) ? "identical" : "differ"} (${committed.length} B)`);
  process.exit(same ? 0 : 1);
}
await writeFile(TARGET, fresh);
const { info } = await decode(fresh);
console.log(`wrote ${path.relative(process.cwd(), TARGET)}: ${info.width}x${info.height}, ${info.channels} channels, ${fresh.length} bytes`);
