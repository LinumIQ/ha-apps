# Panel fonts - sources

Self-hosted copies, served by the panels from `static/shared/fonts/`;
nothing is loaded from Google at runtime. Written by
`shared/ui/tools/fetch-fonts.py`; the `@font-face` rules are in
`shared/ui/static/linumiq.css`.

Retrieved 2026-10-28 from Google Fonts' CSS API (modern browser User-Agent):
`https://fonts.googleapis.com/css2?family=Roboto:wght@400;600;700&family=Inter:wght@400;500;600&display=swap`.
Both families are variable fonts (one axis, `wght` 100-900, in the served files); Google
serves the same file for every requested weight of a unicode subset. Only the `latin`
and `latin-ext` subsets are kept.

- Roboto 3.015 (Google Fonts `ofl/roboto`, source github.com/googlefonts/roboto-classic):
  SIL Open Font License 1.1, `OFL-Roboto.txt`.
- Inter 4.001 (Google Fonts `ofl/inter`, source github.com/rsms/inter): SIL Open Font
  License 1.1, `OFL-Inter.txt`.

| File | Bytes | SHA-256 | Source URL |
| --- | ---: | --- | --- |
| `inter-latin.woff2` | 48256 | `3100e775e8616cd2611beecfa23a4263d7037586789b43f035236a2e6fbd4c62` | https://fonts.gstatic.com/s/inter/v20/UcC73FwrK3iLTeHuS_nVMrMxCp50SjIa1ZL7.woff2 |
| `inter-latin-ext.woff2` | 85068 | `34b9c504cab7a73e37b746343a449132e56cf7b5481af2cb81dc74dcff25c956` | https://fonts.gstatic.com/s/inter/v20/UcC73FwrK3iLTeHuS_nVMrMxCp50SjIa25L7SUc.woff2 |
| `roboto-latin.woff2` | 43136 | `1404ca348bd75ef836f4dd8b6f2cc719458642d1237c368296b2fc652dca47dc` | https://fonts.gstatic.com/s/roboto/v51/KFO7CnqEu92Fr1ME7kSn66aGLdTylUAMa3yUBA.woff2 |
| `roboto-latin-ext.woff2` | 29392 | `cedb374b05a35034cf96db185db4eeb8f8ce49e1a56197673702ff11b5533d6e` | https://fonts.gstatic.com/s/roboto/v51/KFO7CnqEu92Fr1ME7kSn66aGLdTylUAMa3KUBGEe.woff2 |
| `OFL-Roboto.txt` | 4394 | `061402327a96aadb0bfb694a960ed289ecd38d383e396243831ab81feb109c41` | https://raw.githubusercontent.com/googlefonts/roboto-classic/91d5d3e5b81efa04a77925cc609fdcdd7ee663d1/OFL.txt |
| `OFL-Inter.txt` | 4380 | `262481e844521b326f5ecd053e59b98c8b2da78c8ee1bdbb6e8174305e54935a` | https://raw.githubusercontent.com/rsms/inter/353b61b9f4430d5f420d56605a6e7993e0941470/LICENSE.txt |
