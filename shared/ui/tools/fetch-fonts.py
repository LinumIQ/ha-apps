#!/usr/bin/env python3
"""Download the self-hosted panel fonts (maintainers only; needs network).

Fetches Roboto (400, 600, 700) and Inter (400, 500, 600) from Google Fonts'
CSS API the way a current browser would (modern User-Agent: woff2, one file
per unicode subset), keeps only the latin and latin-ext subsets and writes
into shared/ui/static/fonts/:

  roboto-latin.woff2, roboto-latin-ext.woff2, inter-latin.woff2,
  inter-latin-ext.woff2     the font files exactly as served (both families
                            are variable fonts, axis wght 100-900: Google
                            serves the same file for every requested weight of
                            a subset)
  OFL-Roboto.txt, OFL-Inter.txt
                            the licences (SIL Open Font License 1.1) from the
                            fonts' source repositories, pinned to a commit
  SOURCES.md                URLs, retrieval date, sha256 and size of every file

and prints the unicode ranges served for each subset; they are copied into the
@font-face rules of shared/ui/static/linumiq.css by hand (check them after an
update), then run scripts/sync-shared.sh.

    python3 shared/ui/tools/fetch-fonts.py [--date YYYY-MM-DD]

Standard library only. The panels never load anything from Google at runtime.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import re
import sys
import urllib.request
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "static" / "fonts"
#: Any current browser UA works; with an old or unknown one Google serves TTF.
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/141.0.0.0 Safari/537.36"
)
CSS_URL = (
    "https://fonts.googleapis.com/css2?family=Roboto:wght@400;600;700"
    "&family=Inter:wght@400;500;600&display=swap"
)
SUBSETS = ("latin", "latin-ext")
#: Licence files of the fonts' source repositories (Google Fonts' METADATA.pb
#: names googlefonts/roboto-classic at this commit for Roboto v3.015, licence
#: "OFL"; rsms/inter is Inter's home).
LICENCES = {
    "OFL-Roboto.txt": "https://raw.githubusercontent.com/googlefonts/roboto-classic/"
                      "91d5d3e5b81efa04a77925cc609fdcdd7ee663d1/OFL.txt",
    "OFL-Inter.txt": "https://raw.githubusercontent.com/rsms/inter/"
                     "353b61b9f4430d5f420d56605a6e7993e0941470/LICENSE.txt",
}
FACE_RE = re.compile(r"/\*\s*(?P<subset>[\w-]+)\s*\*/\s*@font-face\s*\{(?P<body>[^}]*)\}", re.S)


def get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (fixed https URLs)
        return resp.read()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--date", default=dt.date.today().isoformat(), help="retrieval date for SOURCES.md")
    args = parser.parse_args()

    css = get(CSS_URL).decode()
    faces: dict[tuple[str, str], dict[str, set]] = {}
    for match in FACE_RE.finditer(css):
        subset, body = match["subset"], match["body"]
        if subset not in SUBSETS:
            continue
        family = re.search(r"font-family:\s*'([^']+)'", body)[1].lower()
        face = faces.setdefault((family, subset), {"src": set(), "range": set(), "weight": set()})
        face["src"].add(re.search(r"src:\s*url\(([^)]+)\)\s*format\('woff2'\)", body)[1])
        face["range"].add(re.search(r"unicode-range:\s*([^;]+);", body)[1].strip())
        face["weight"].add(re.search(r"font-weight:\s*([^;]+);", body)[1].strip())
    expected = {(f, s) for f in ("roboto", "inter") for s in SUBSETS}
    if set(faces) != expected:
        print(f"unexpected CSS: got {sorted(faces)}", file=sys.stderr)
        return 1

    OUT.mkdir(parents=True, exist_ok=True)
    rows = []
    for (family, subset), face in sorted(faces.items()):
        if len(face["src"]) != 1 or len(face["range"]) != 1:
            print(f"{family} {subset}: one file per weight (not a variable font?): {face}", file=sys.stderr)
            return 1
        url = next(iter(face["src"]))
        name = f"{family}-{subset}.woff2"
        data = get(url)
        if data[:4] != b"wOF2":
            print(f"{url}: not a woff2 file", file=sys.stderr)
            return 1
        (OUT / name).write_bytes(data)
        rows.append((name, url, data))
        print(f"{name}: weights {', '.join(sorted(face['weight']))}; unicode-range: {next(iter(face['range']))}")
    for name, url in LICENCES.items():
        data = get(url)
        (OUT / name).write_bytes(data)
        rows.append((name, url, data))

    lines = [
        "# Panel fonts - sources",
        "",
        "Self-hosted copies, served by the panels from `static/shared/fonts/`;",
        "nothing is loaded from Google at runtime. Written by",
        "`shared/ui/tools/fetch-fonts.py`; the `@font-face` rules are in",
        "`shared/ui/static/linumiq.css`.",
        "",
        f"Retrieved {args.date} from Google Fonts' CSS API (modern browser User-Agent):",
        f"`{CSS_URL}`.",
        "Both families are variable fonts (one axis, `wght` 100-900, in the served files); Google",
        "serves the same file for every requested weight of a unicode subset. Only the `latin`",
        "and `latin-ext` subsets are kept.",
        "",
        "- Roboto 3.015 (Google Fonts `ofl/roboto`, source github.com/googlefonts/roboto-classic):",
        "  SIL Open Font License 1.1, `OFL-Roboto.txt`.",
        "- Inter 4.001 (Google Fonts `ofl/inter`, source github.com/rsms/inter): SIL Open Font",
        "  License 1.1, `OFL-Inter.txt`.",
        "",
        "| File | Bytes | SHA-256 | Source URL |",
        "| --- | ---: | --- | --- |",
    ]
    for name, url, data in rows:
        lines.append(f"| `{name}` | {len(data)} | `{hashlib.sha256(data).hexdigest()}` | {url} |")
    (OUT / "SOURCES.md").write_text("\n".join(lines) + "\n")
    print(f"wrote {len(rows)} files and SOURCES.md to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
