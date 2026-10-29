#!/usr/bin/env node
// Screenshots of the rendered panel previews (maintainer tool).
//
//   python3 shared/ui/preview/render-previews.py     (first; needs Jinja2)
//   cd shared/ui && npm install && npx playwright install chromium
//   node preview/screenshot.mjs [<output directory>]
//
// Serves preview/out/ on 127.0.0.1 the way Home Assistant's ingress proxy
// lays the panel out (each page at /<app>/<state>/, its static files below
// it, POST pair/poll answered from the manifest), then captures every page at
// 400 and 1100 px width in light and dark (prefers-color-scheme emulation)
// as full-page PNGs named <app>-<state>-<width>-<mode>.png (default output:
// preview/out/screenshots/).
//
// Each capture is also checked, and the findings go to report.json next to
// the PNGs (exit 1 if any check fails):
//   - no request leaves 127.0.0.1 (no Google Fonts, no CDN);
//   - the bundled Roboto and Inter faces are loaded;
//   - no horizontal scrolling (scrollWidth <= viewport width) and no
//     element sticking out to the right;
//   - text contrast: every visible text against its composited background,
//     >= 4.5:1 (>= 3:1 for large text); the white text of the blue .btn is
//     reported separately as the documented exception (on Anchor Blue
//     3.99:1 in light mode, on the shop's #60A4FA 2.56:1 in dark mode);
//   - buttons are blue, never orange (the owner's rule of 2026-10-29, as on
//     shop.linumiq.com): no visible button has an orange background, and
//     every .btn (not hovered or pressed) is Anchor Blue in light mode and
//     #60A4FA in dark mode; orange is left to warnings, badges and stripes;
//   - the theme switch: data-theme="light" on <html> wins over a dark
//     preference, data-theme="dark" over a light one (first page only).
import { createServer } from "node:http";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const here = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(here, "out");
const target = path.resolve(process.argv[2] ?? path.join(OUT, "screenshots"));
const WIDTHS = [400, 1100];
const MODES = ["light", "dark"];
// The background of .btn per mode (linumiq.css --color-button).
const BUTTON_BLUE = { light: "rgb(8, 131, 218)", dark: "rgb(96, 164, 250)" };
const TYPES = {
  ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml",
  ".png": "image/png", ".woff2": "font/woff2", ".txt": "text/plain; charset=utf-8", ".md": "text/plain; charset=utf-8",
};

const manifest = JSON.parse(await readFile(path.join(OUT, "manifest.json"), "utf8"));
const byPath = new Map(manifest.pages.map((p) => [p.path, p]));

// --- the preview server -----------------------------------------------------
const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  const m = url.pathname.match(/^\/([^/]+)\/([^/]+)\/(.*)$/);
  const page = m && byPath.get(`/${m[1]}/${m[2]}/`);
  try {
    if (!page) throw new Error("no such page");
    if (req.method === "POST" && m[3] === "pair/poll") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(page.poll ?? { status: "pending" }));
      return;
    }
    if (req.method === "POST") {
      res.writeHead(303, { location: page.path });
      res.end();
      return;
    }
    const rel = m[3] === "" ? `${m[2]}.html` : m[3];
    if (rel.includes("..") || !(rel === `${m[2]}.html` || rel.startsWith("static/"))) throw new Error("outside");
    const file = path.join(OUT, m[1], rel);
    const body = await readFile(file);
    res.writeHead(200, { "content-type": TYPES[path.extname(file)] ?? "application/octet-stream" });
    res.end(body);
  } catch {
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("not found");
  }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const base = `http://127.0.0.1:${server.address().port}`;

// --- checks run inside the page ----------------------------------------------
function audit() {
  const parse = (c) => {
    const m = c.match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    const v = m[1].split(/[,\s/]+/).filter(Boolean).map(Number);
    return [v[0], v[1], v[2], v.length > 3 ? v[3] : 1];
  };
  const over = (fg, bg) => [0, 1, 2].map((i) => fg[i] * fg[3] + bg[i] * (1 - fg[3])).concat(1);
  const lum = (c) => {
    const [r, g, b] = c.slice(0, 3).map((x) => {
      x /= 255;
      return x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4;
    });
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };
  const ratio = (a, b) => {
    const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
    return (x + 0.05) / (y + 0.05);
  };
  const background = (el) => {
    const layers = [];
    for (let e = el; e; e = e.parentElement) {
      const c = parse(getComputedStyle(e).backgroundColor);
      if (c && c[3] > 0) layers.push(c);
      if (c && c[3] >= 1) break;
    }
    let bg = [255, 255, 255, 1];
    for (const layer of layers.reverse()) bg = over(layer, bg);
    return bg;
  };
  const describe = (el) => {
    const cls = el.className && typeof el.className === "string" ? `.${el.className.trim().split(/\s+/).join(".")}` : "";
    return `${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ""}${cls}`;
  };
  const low = [];
  const exceptions = [];
  let checked = 0;
  for (const el of document.querySelectorAll("body *")) {
    if (!el.getClientRects().length) continue;
    const text = [...el.childNodes].filter((n) => n.nodeType === 3).map((n) => n.textContent).join("").trim();
    if (!text) continue;
    const style = getComputedStyle(el);
    if (style.visibility === "hidden" || el.closest(".visually-hidden")) continue;
    checked += 1;
    const bg = background(el);
    const fg = over(parse(style.color), bg);
    const r = ratio(fg, bg);
    const size = parseFloat(style.fontSize);
    const large = size >= 24 || (size >= 18.66 && Number(style.fontWeight) >= 700);
    const need = large ? 3 : 4.5;
    if (r + 0.005 < need) {
      const entry = { element: describe(el), text: text.slice(0, 60), ratio: Number(r.toFixed(2)), need,
                      color: style.color, background: `rgb(${bg.slice(0, 3).map(Math.round).join(", ")})` };
      (el.closest(".btn") ? exceptions : low).push(entry);
    }
  }
  // Buttons: blue in both modes, never orange (hue 15-50 degrees, saturated, bright).
  const orange = ([r, g, b]) => {
    const max = Math.max(r, g, b), min = Math.min(r, g, b);
    if (max < 128 || max - min < 0.5 * max || max !== r) return false;
    const hue = (60 * (g - b)) / (max - min);
    return hue >= 15 && hue <= 50;
  };
  const buttons = [];
  for (const el of document.querySelectorAll('button, input[type="submit"], .btn, .btn-secondary, .btn-danger')) {
    if (!el.getClientRects().length || el.closest(".visually-hidden")) continue;
    const bg = background(el);
    buttons.push({ element: describe(el), text: el.textContent.trim().replace(/\s+/g, " ").slice(0, 40),
                   background: `rgb(${bg.slice(0, 3).map(Math.round).join(", ")})`, orange: orange(bg),
                   primary: el.matches(".btn") && !el.matches(":hover, :active") });
  }
  const vw = document.documentElement.clientWidth;
  const sticking = [];
  for (const el of document.querySelectorAll("body *")) {
    const rect = el.getBoundingClientRect();
    if (rect.width && rect.right > vw + 0.5 && !el.closest(".visually-hidden")) {
      sticking.push(`${describe(el)} right=${Math.round(rect.right)}`);
    }
  }
  const faces = [...document.fonts].filter((f) => f.status === "loaded").map((f) => `${f.family} ${f.weight}`);
  return {
    checked, low, exceptions, buttons, scrollWidth: document.documentElement.scrollWidth, viewport: vw,
    sticking: sticking.slice(0, 10), faces: [...new Set(faces)],
    headingFont: getComputedStyle(document.querySelector("h1")).fontFamily,
  };
}

// --- capture -----------------------------------------------------------------
await mkdir(target, { recursive: true });
const browser = await chromium.launch();
const report = [];
let failed = 0;
for (const page of manifest.pages) {
  for (const width of WIDTHS) {
    for (const mode of MODES) {
      const context = await browser.newContext({ viewport: { width, height: 800 }, colorScheme: mode });
      const tab = await context.newPage();
      const external = [];
      tab.on("request", (r) => { if (!r.url().startsWith(base)) external.push(r.url()); });
      await tab.goto(`${base}${page.path}`, { waitUntil: "networkidle" });
      if (page.click) await tab.click(page.click);
      if (page.wait_for_text) await tab.getByText(page.wait_for_text).waitFor();
      await tab.evaluate(() => document.fonts.ready);
      // Stills: the spinner and the live dot at their first frame.
      await tab.addStyleTag({ content: "*, *::before, *::after { animation: none !important; }" });
      const result = await tab.evaluate(audit);
      const name = `${page.app}-${page.state}-${width}-${mode}.png`;
      await tab.screenshot({ path: path.join(target, name), fullPage: true });
      const problems = [];
      if (external.length) problems.push(`external requests: ${external.join(", ")}`);
      if (result.scrollWidth > width) problems.push(`horizontal scrolling: ${result.scrollWidth} > ${width}`);
      if (result.sticking.length) problems.push(`elements beyond the right edge: ${result.sticking.join("; ")}`);
      if (result.low.length) problems.push(`low contrast: ${result.low.map((l) => `${l.element} "${l.text}" ${l.ratio}`).join("; ")}`);
      const orangeButtons = result.buttons.filter((b) => b.orange);
      if (orangeButtons.length) problems.push(`orange buttons: ${orangeButtons.map((b) => `${b.element} "${b.text}" ${b.background}`).join("; ")}`);
      const offBlue = result.buttons.filter((b) => b.primary && b.background !== BUTTON_BLUE[mode]);
      if (offBlue.length) problems.push(`.btn not ${BUTTON_BLUE[mode]}: ${offBlue.map((b) => `${b.element} "${b.text}" ${b.background}`).join("; ")}`);
      for (const face of ["Roboto", "Inter"]) {
        if (!result.faces.some((f) => f.includes(face))) problems.push(`${face} not loaded`);
      }
      failed += problems.length ? 1 : 0;
      report.push({ file: name, ...result, external, problems });
      console.log(`${problems.length ? "FAIL" : "ok  "}  ${name}${problems.length ? `  ${problems.join(" | ")}` : ""}`);
      await context.close();
    }
  }
}
// Theme switch on the root element (first page).
const themes = [];
for (const [mode, theme, bg, scheme] of [["dark", "light", "rgb(229, 246, 253)", "light"],
                                         ["light", "dark", "rgb(15, 23, 42)", "dark"],
                                         ["dark", null, "rgb(15, 23, 42)", "dark"],
                                         ["light", null, "rgb(229, 246, 253)", "light"]]) {
  const context = await browser.newContext({ colorScheme: mode });
  const tab = await context.newPage();
  await tab.goto(`${base}${manifest.pages[0].path}`, { waitUntil: "networkidle" });
  const got = await tab.evaluate((t) => {
    if (t) document.documentElement.dataset.theme = t;
    const root = getComputedStyle(document.documentElement);
    return { bg: getComputedStyle(document.body).backgroundColor, scheme: root.colorScheme };
  }, theme);
  const ok = got.bg === bg && got.scheme === scheme;
  themes.push({ preference: mode, dataTheme: theme, ...got, ok });
  console.log(`${ok ? "ok  " : "FAIL"}  theme: prefers ${mode}, data-theme=${theme ?? "(none)"} -> ${got.bg}, color-scheme ${got.scheme}`);
  failed += ok ? 0 : 1;
  await context.close();
}
await browser.close();
server.close();
await writeFile(path.join(target, "report.json"), JSON.stringify({ screenshots: report, themes }, null, 2) + "\n");
const exceptions = new Set(report.flatMap((r) => r.exceptions.map((e) => `${e.text} ${e.ratio}:1 on ${e.background}`)));
const buttonCount = report.reduce((n, r) => n + r.buttons.length, 0);
const blueCount = report.reduce((n, r) => n + r.buttons.filter((b) => b.primary).length, 0);
const orangeCount = report.reduce((n, r) => n + r.buttons.filter((b) => b.orange).length, 0);
console.log(`\n${report.length} screenshots in ${target}; ${failed} failed check(s).`);
console.log(`Buttons: ${buttonCount} visible, ${orangeCount} orange; ${blueCount} .btn checked against ${Object.values(BUTTON_BLUE).join(" / ")}.`);
console.log(`Documented exceptions (white text on the blue .btn): ${[...exceptions].join("; ") || "none"}`);
process.exit(failed ? 1 : 0);
