# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501  SVG path data reads best one shape per line.
"""Generate the brand assets in docs/brand from one mascot definition.

Scout, the meerkat sentinel, is drawn once here. Every logo variant (mark,
icon, horizontal lockups, mascot, social card) is composed from it so the
artwork never drifts. Colors come from docs/brand/tokens.json, the same file
the email renderer is tested against.

Usage: python scripts/render_brand.py   (or: make brand)
PNG exports need Google Chrome or Chromium (headless); SVGs are written without it.
"""

import json
import pathlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
BRAND = ROOT / "docs" / "brand"
TOKENS = json.loads((BRAND / "tokens.json").read_text())
C = TOKENS["color"]
M = TOKENS["mascot"]
SANS = TOKENS["font"]["sans"].replace('"', "'")

FUR, SHADE, CREAM, UMBER = M["fur"], M["shade"], M["cream"], M["umber"]
NIGHT, SIGNAL = C["night"], C["signal"]


def mascot(look: str = "click") -> str:
    """Scout standing on watch, in a 0 0 472 512 box, feet at y=460."""
    pupil_dx, pupil_dy = (4, -4) if look == "click" else (0, 0)
    return f"""
  <path d="M300 420 C 352 428 380 446 396 478" fill="none" stroke="{SHADE}" stroke-width="20" stroke-linecap="round"/>
  <path d="M389 463 C 392 468 395 473 397 479" fill="none" stroke="{UMBER}" stroke-width="20" stroke-linecap="round"/>
  <path d="M208 200 C 194 236 174 272 170 324 C 164 396 186 446 236 452 C 286 446 308 396 302 324 C 298 272 278 236 264 200 Z" fill="{FUR}"/>
  <path d="M236 248 C 210 258 198 300 198 342 C 198 404 212 434 236 438 C 260 434 274 404 274 342 C 274 300 262 258 236 248 Z" fill="{CREAM}"/>
  <ellipse cx="194" cy="430" rx="30" ry="24" fill="{SHADE}"/>
  <ellipse cx="278" cy="430" rx="30" ry="24" fill="{SHADE}"/>
  <ellipse cx="200" cy="456" rx="26" ry="10" fill="{UMBER}"/>
  <ellipse cx="272" cy="456" rx="26" ry="10" fill="{UMBER}"/>
  <path d="M196 262 C 190 292 202 308 222 316" fill="none" stroke="{SHADE}" stroke-width="22" stroke-linecap="round"/>
  <path d="M276 262 C 282 292 270 308 250 316" fill="none" stroke="{SHADE}" stroke-width="22" stroke-linecap="round"/>
  <ellipse cx="226" cy="320" rx="11" ry="8" fill="{UMBER}"/>
  <ellipse cx="246" cy="320" rx="11" ry="8" fill="{UMBER}"/>
  <circle cx="170" cy="126" r="18" fill="{SHADE}"/>
  <circle cx="302" cy="126" r="18" fill="{SHADE}"/>
  <circle cx="172" cy="127" r="8" fill="{UMBER}"/>
  <circle cx="300" cy="127" r="8" fill="{UMBER}"/>
  <path d="M236 74 C 282 74 304 104 302 140 C 300 176 270 214 236 222 C 202 214 172 176 170 140 C 168 104 190 74 236 74 Z" fill="{FUR}"/>
  <path d="M236 84 C 229 100 229 118 236 134 C 243 118 243 100 236 84 Z" fill="{SHADE}"/>
  <ellipse cx="236" cy="194" rx="22" ry="20" fill="{CREAM}"/>
  <ellipse cx="208" cy="148" rx="18" ry="23" transform="rotate(-18 208 148)" fill="{UMBER}"/>
  <ellipse cx="264" cy="148" rx="18" ry="23" transform="rotate(18 264 148)" fill="{UMBER}"/>
  <circle cx="{209 + pupil_dx}" cy="{148 + pupil_dy}" r="9" fill="#0b0f17"/>
  <circle cx="{265 + pupil_dx}" cy="{148 + pupil_dy}" r="9" fill="#0b0f17"/>
  <circle cx="{212 + pupil_dx}" cy="{145 + pupil_dy}" r="3.5" fill="#ffffff"/>
  <circle cx="{268 + pupil_dx}" cy="{145 + pupil_dy}" r="3.5" fill="#ffffff"/>
  <path d="M227 202 Q 236 196 245 202 Q 241 211 236 212 Q 231 211 227 202 Z" fill="{UMBER}"/>
  <path d="M236 212 L 236 218" stroke="{UMBER}" stroke-width="3" stroke-linecap="round"/>"""


def click(x: float, y: float, scale: float = 1.0) -> str:
    """The amber click ripple with a pointer: what Scout watches for."""
    return f"""
  <g transform="translate({x} {y}) scale({scale})">
    <circle r="34" fill="none" stroke="{SIGNAL}" stroke-width="5" opacity="0.45"/>
    <circle r="18" fill="none" stroke="{SIGNAL}" stroke-width="5"/>
    <path d="M0 0 L 0 56 L 14 43 L 25 68 L 36 63 L 25 39 L 44 39 Z" fill="{C["paper"]}" stroke="{NIGHT}" stroke-width="5" stroke-linejoin="round"/>
  </g>"""


def badge(inner: str, ident: str) -> str:
    """Night rounded square with the amber dawn glow and the mound."""
    return f"""
  <defs>
    <clipPath id="{ident}-clip"><rect width="512" height="512" rx="112"/></clipPath>
    <radialGradient id="{ident}-dawn" cx="0.5" cy="0.5" r="0.5">
      <stop offset="0" stop-color="{SIGNAL}" stop-opacity="0.34"/>
      <stop offset="1" stop-color="{SIGNAL}" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <g clip-path="url(#{ident}-clip)">
    <rect width="512" height="512" fill="{NIGHT}"/>
    <circle cx="236" cy="200" r="190" fill="url(#{ident}-dawn)"/>
    <ellipse cx="236" cy="500" rx="230" ry="70" fill="{C["night_raised"]}"/>
    {inner}
  </g>"""


def svg(view_box: str, body: str, title: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{view_box}" '
        f'role="img" aria-label="{title}">\n  <title>{title}</title>{body}\n</svg>\n'
    )


def mark() -> str:
    return badge(mascot(), "mark") + click(378, 70)


def icon() -> str:
    """Head and shoulders crop for favicons and avatars (32 px and below)."""
    inner = f'<g transform="translate(-160 -40) scale(1.75)">{mascot()}</g>'
    return badge(inner, "icon") + click(400, 92, 1.25)


def wordmark(x: int, y: int, size: int, ink: str) -> str:
    return (
        f'<text x="{x}" y="{y}" font-family="{SANS}" font-size="{size}" '
        f'font-weight="800" letter-spacing="-1">'
        f'<tspan fill="{ink}">ClickOps</tspan>'
        f'<tspan fill="{SIGNAL}" dx="{size // 4}">Sentinel</tspan></text>'
    )


def horizontal(ink: str, sub: str) -> str:
    return (
        f'<g transform="scale(0.25)">{mark()}</g>'
        + wordmark(152, 66, 52, ink)
        + f'<text x="154" y="104" font-family="{SANS}" font-size="20" '
        f'font-weight="500" fill="{sub}">{TOKENS["voice"]["tagline"]}</text>'
    )


def social() -> str:
    """1280 x 640 card for the GitHub social preview and link unfurls."""
    return (
        '<defs><radialGradient id="social-dawn" cx="0.5" cy="0.5" r="0.5">'
        f'<stop offset="0" stop-color="{SIGNAL}" stop-opacity="0.30"/>'
        f'<stop offset="1" stop-color="{SIGNAL}" stop-opacity="0"/></radialGradient></defs>'
        f'<rect width="1280" height="640" fill="{NIGHT}"/>'
        '<circle cx="1000" cy="260" r="300" fill="url(#social-dawn)"/>'
        f'<ellipse cx="1000" cy="660" rx="380" ry="110" fill="{C["night_raised"]}"/>'
        f'<g transform="translate(764 72) scale(1.1)">{mascot()}{click(400, 60)}</g>'
        + wordmark(80, 290, 84, "#ffffff")
        + f'<text x="84" y="356" font-family="{SANS}" font-size="32" '
        f'font-weight="500" fill="{C["mist"]}">{TOKENS["voice"]["tagline"]}</text>'
        f'<text x="84" y="420" font-family="{SANS}" font-size="24" '
        f'fill="{C["slate"]}">{TOKENS["voice"]["promise"]}</text>'
    )


ASSETS = {
    "logo-mark.svg": ("0 0 512 512", mark),
    "logo-icon.svg": ("0 0 512 512", icon),
    "mascot.svg": ("0 0 472 512", lambda: mascot() + click(400, 60)),
    "logo-horizontal-dark.svg": ("0 0 560 128", lambda: horizontal("#ffffff", C["mist"])),
    "logo-horizontal-light.svg": ("0 0 560 128", lambda: horizontal(NIGHT, C["slate"])),
    "social-card.svg": ("0 0 1280 640", social),
}

PNG_EXPORTS = {
    "logo-mark.svg": [("logo-mark-512.png", 512, 512)],
    "logo-icon.svg": [("logo-icon-64.png", 64, 64), ("favicon-32.png", 32, 32)],
    "social-card.svg": [("social-card.png", 1280, 640)],
}

CHROME_PATHS = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "google-chrome",
    "chromium",
)


def chrome() -> str | None:
    for candidate in CHROME_PATHS:
        if pathlib.Path(candidate).exists() or shutil.which(candidate):
            return candidate
    return None


def export_png(browser: str, source: pathlib.Path, target: pathlib.Path, width: int, height: int):
    """Headless Chrome renders the SVG text with real fonts, unlike ImageMagick."""
    with tempfile.TemporaryDirectory() as tmp:
        page = pathlib.Path(tmp) / "page.html"
        page.write_text(
            '<html><body style="margin:0;background:transparent;">'
            f'<img src="{source.as_uri()}" width="{width}" height="{height}" '
            'style="display:block;"></body></html>'
        )
        subprocess.run(
            [
                browser,
                "--headless=new",
                "--hide-scrollbars",
                "--disable-gpu",
                "--default-background-color=00000000",
                "--allow-file-access-from-files",
                f"--window-size={width},{height}",
                f"--screenshot={target}",
                page.as_uri(),
            ],
            check=True,
            capture_output=True,
        )


def main() -> None:
    title = "ClickOps Sentinel: Scout the meerkat on watch, spotting a click"
    for name, (view_box, build) in ASSETS.items():
        (BRAND / name).write_text(svg(view_box, build(), title))
        print(f"wrote docs/brand/{name}")
    browser = chrome()
    if not browser:
        print("Chrome not found, skipping PNG exports")
        return
    for source, targets in PNG_EXPORTS.items():
        for target, width, height in targets:
            export_png(browser, BRAND / source, BRAND / target, width, height)
            print(f"wrote docs/brand/{target}")


if __name__ == "__main__":
    main()
