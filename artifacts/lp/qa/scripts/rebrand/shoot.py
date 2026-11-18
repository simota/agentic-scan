"""Capture the LP at several widths and record layout checks.

usage: python3 shoot.py <url> <outdir> [--full] [--dark]
"""
import json
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

url, out = sys.argv[1], Path(sys.argv[2])
full = "--full" in sys.argv
schemes = ["light", "dark"] if "--dark" in sys.argv else ["light"]
widths = [320, 375, 768, 1024, 1440, 1920]
out.mkdir(parents=True, exist_ok=True)
report = {}

with sync_playwright() as p:
    browser = p.chromium.launch(channel="chrome")
    for scheme in schemes:
        for w in widths:
            h = 812 if w < 768 else (1024 if w < 1440 else 900)
            ctx = browser.new_context(viewport={"width": w, "height": h}, color_scheme=scheme, device_scale_factor=1)
            page = ctx.new_page()
            errors = []
            page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
            page.on("pageerror", lambda e: errors.append(str(e)))
            failed = []
            page.on("requestfailed", lambda r: failed.append(r.url))
            page.goto(url, wait_until="networkidle")
            page.wait_for_timeout(900)
            info = page.evaluate("""() => {
              const doc = document.documentElement;
              const vis = (sel) => { const el = document.querySelector(sel); if (!el) return null; const r = el.getBoundingClientRect(); return {top: Math.round(r.top), bottom: Math.round(r.bottom), left: Math.round(r.left), right: Math.round(r.right)}; };
              const over = [...document.querySelectorAll('body *')].filter(el => { const r = el.getBoundingClientRect(); return r.right > doc.clientWidth + 1 && getComputedStyle(el).position !== 'fixed' && !el.closest('.term-body'); }).slice(0, 8).map(el => el.tagName + '.' + el.className);
              const imgs = [...document.images].filter(i => i.complete && i.naturalWidth === 0 && i.loading !== 'lazy').map(i => i.src);
              return {scrollW: doc.scrollWidth, clientW: doc.clientWidth, h1: vis('h1'), cta: vis('.cta-row .btn'), term: vis('.term-hero'), overflow: over, brokenImgs: imgs, height: doc.scrollHeight};
            }""")
            info["errors"] = errors
            info["failed"] = failed
            report[f"{scheme}-{w}"] = info
            name = f"{scheme}-{w}"
            page.screenshot(path=str(out / f"{name}-first.png"))
            if full:
                page.evaluate("""() => document.querySelectorAll('img[loading=lazy]').forEach(i => { i.loading = 'eager'; })""")
                page.evaluate("""async () => { for (let y = 0; y < document.documentElement.scrollHeight; y += 400) { window.scrollTo(0, y); await new Promise(r => setTimeout(r, 60)); } window.scrollTo(0, 0); }""")
                page.wait_for_timeout(500)
                page.screenshot(path=str(out / f"{name}-full.png"), full_page=True)
            ctx.close()
    browser.close()

(out / "layout.json").write_text(json.dumps(report, indent=1, ensure_ascii=False))
for k, v in report.items():
    flag = "OK " if v["scrollW"] <= v["clientW"] and not v["errors"] and not v["overflow"] else "BAD"
    print(flag, k, "scrollW", v["scrollW"], "/", v["clientW"], "h1", v["h1"], "cta.bottom", (v["cta"] or {}).get("bottom"), "term.top", (v["term"] or {}).get("top"), "overflow", v["overflow"], "errors", v["errors"], "failed", v["failed"])
