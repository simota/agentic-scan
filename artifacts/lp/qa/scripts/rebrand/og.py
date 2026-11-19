"""Render the Open Graph images (1200x630 PNG) for the English and Japanese pages.

usage: python3 og.py <site-dir> [chrome-executable]

Writes <site-dir>/assets/og.png and <site-dir>/assets/og-ja.png. The ledger
lines are the real output of the hero's jq command on each language's sample.
"""
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

SEV = {"High": "#f2a19a", "Medium": "#e8bf7a", "Low": "#a9c3e6", "Info": "#b3aea4"}

PAGES = {
    "og.png": {
        "lang": "en",
        "title": ["Findings you can check,", "without touching your code."],
        "kicker": "for Claude Code · Codex · Antigravity",
        "cap": "security-scan bundled sample",
        "rows": [
            ("F-001", "High", "Valid", "src/api/orders.py:42"),
            ("F-002", "Medium", "Likely", "src/api/util.py:7"),
            ("F-003", "Low", "-", "deploy/php.ini:9"),
            ("F-004", "High", "FalsePositive", "src/api/reports.py:88"),
        ],
    },
    "og-ja.png": {
        "lang": "ja",
        "title": ["コードに触れずに、", "裏の取れた指摘を。"],
        "kicker": "for Claude Code · Codex · Antigravity",
        "cap": "security-scan の同梱サンプル",
        "rows": [
            ("F-001", "High", "Valid", "src/api/orders.py:42"),
            ("D-001", "High", "Unverified", "package-lock.json:18"),
            ("F-002", "Medium", "Likely", "src/api/pagination.py:7"),
            ("F-003", "Low", "Unverified", "deploy/php.ini:9"),
            ("F-004", "High", "FalsePositive", "src/api/reports.py:88"),
            ("F-005", "Low", "Valid", "src/api/middleware.py:23"),
            ("F-006", "Info", "Unverified", "docs/logging.md:12"),
        ],
    },
}

CSS = """
* { box-sizing: border-box; margin: 0; }
body { width: 1200px; height: 630px; background: #12161c; color: #e9ecf0; padding: 52px 64px;
  font-family: "Hiragino Sans", "Hiragino Kaku Gothic ProN", "Noto Sans JP", system-ui, sans-serif;
  display: flex; flex-direction: column; }
.mono { font-family: ui-monospace, "SF Mono", Menlo, Consolas, "Hiragino Sans", monospace; }
.top { display: flex; align-items: center; justify-content: space-between; }
.mark { display: flex; align-items: center; gap: 14px; font-size: 30px; font-weight: 700; }
.perm { background: #e9ecf0; color: #12161c; border-radius: 4px; padding: 0 9px; font-size: 22px; line-height: 1.5; }
.kicker { font-size: 19px; color: #a7b0bb; }
h1 { margin: 36px 0 32px; font-size: 52px; line-height: 1.2; font-weight: 800; letter-spacing: -0.01em; }
h1 span { display: block; }
.term { border: 1px solid #2b333d; border-radius: 6px; background: #0a0d11; overflow: hidden; }
.cap { display: flex; justify-content: space-between; padding: 11px 20px; border-bottom: 1px solid #2b333d; font-size: 16px; color: #a7b0bb; }
.cap span:last-child { color: #a9c3e6; }
table { border-collapse: collapse; font-size: 18px; width: 100%; }
td { padding: 6px 0 6px 20px; white-space: nowrap; }
td:nth-child(3) { padding-left: 28px; }
td:last-child { padding: 6px 20px 6px 36px; color: #a7b0bb; width: 100%; }
tr.fp { background: #1a2638; }
.fp .v { color: #a9c3e6; font-weight: 700; }
"""


def page(spec):
    rows = "".join(
        f"<tr class='{'fp' if v == 'FalsePositive' else ''}'><td>{i}</td>"
        f"<td style='color:{SEV[s]};font-weight:700'>{s}</td><td class='v'>{v}</td><td>{loc}</td></tr>"
        for i, s, v, loc in spec["rows"])
    title = "".join(f"<span>{line}</span>" for line in spec["title"])
    return (f"<!doctype html><html lang='{spec['lang']}'><head><meta charset='utf-8'><style>{CSS}</style></head><body>"
            f"<div class='top'><p class='mark mono'><span class='perm'>r--</span>agentic-scan</p>"
            f"<p class='kicker mono'>{spec['kicker']}</p></div><h1>{title}</h1>"
            f"<div class='term mono'><p class='cap'><span>{spec['cap']}</span>"
            f"<span>12 skills · read-only · dashboard + report</span></p><table>{rows}</table></div></body></html>")


def main():
    site = Path(sys.argv[1])
    launch = {"executable_path": sys.argv[2]} if len(sys.argv) > 2 else {}
    with sync_playwright() as p:
        browser = p.chromium.launch(**launch)
        for name, spec in PAGES.items():
            pg = browser.new_page(viewport={"width": 1200, "height": 630})
            pg.set_content(page(spec))
            pg.screenshot(path=str(site / "assets" / name))
            pg.close()
        browser.close()


if __name__ == "__main__":
    main()
