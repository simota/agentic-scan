import json
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

url, out = sys.argv[1], Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
res = {}
with sync_playwright() as p:
    b = p.chromium.launch(channel="chrome")
    ctx = b.new_context(viewport={"width": 1440, "height": 900})
    ctx.grant_permissions(["clipboard-read", "clipboard-write"], origin=url.rstrip("/"))
    pg = ctx.new_page()
    errs = []
    pg.on("console", lambda m: errs.append(m.text) if m.type == "error" else None)
    pg.on("pageerror", lambda e: errs.append(str(e)))
    pg.goto(url, wait_until="networkidle")

    # anchors: every in-page link resolves to an element
    res["anchors"] = pg.evaluate("""() => [...document.querySelectorAll('a[href^="#"]')].map(a => [a.getAttribute('href'), !!document.querySelector(a.getAttribute('href'))]).filter(x => !x[1])""")
    pg.click(".bar .btn-quiet"); pg.wait_for_timeout(800)
    res["install_in_view"] = pg.evaluate("() => { const r = document.querySelector('#install').getBoundingClientRect(); return r.top >= 0 && r.top < innerHeight; }")

    # copy buttons
    copies = []
    for i, btn in enumerate(pg.locator("[data-copy]").all()):
        btn.scroll_into_view_if_needed(); btn.click(); pg.wait_for_timeout(200)
        clip = pg.evaluate("navigator.clipboard.readText()")
        copies.append({"expected": btn.get_attribute("data-copy"), "clipboard": clip, "label": btn.inner_text()})
    res["copy"] = [c["expected"] == c["clipboard"] for c in copies]
    res["copy_label"] = [c["label"] for c in copies]
    res["toast"] = pg.locator(".toast").inner_text()

    # tabs with keyboard
    pg.locator("#tab-sec").focus(); pg.keyboard.press("ArrowRight"); pg.wait_for_timeout(100)
    res["tab_after_right"] = pg.evaluate("() => [document.activeElement.id, document.querySelector('#panel-ux').hidden, document.querySelector('#panel-sec').hidden]")
    pg.keyboard.press("End"); res["tab_end"] = pg.evaluate("() => document.activeElement.id")
    pg.keyboard.press("Home"); res["tab_home"] = pg.evaluate("() => document.activeElement.id")

    # faq
    d = pg.locator("details").first; d.locator("summary").click()
    res["faq_open"] = d.evaluate("el => el.open")

    # focus ring visible on first tab stop
    pg.goto(url, wait_until="networkidle"); pg.keyboard.press("Tab"); pg.keyboard.press("Tab")
    res["focus2"] = pg.evaluate("() => { const e = document.activeElement; const s = getComputedStyle(e); return [e.className || e.tagName, s.outlineStyle, s.outlineWidth]; }")
    pg.screenshot(path=str(out / "focus-1440.png"), clip={"x": 0, "y": 0, "width": 1440, "height": 120})
    res["errors"] = errs
    ctx.close()

    # reduced motion: ledger lines are visible immediately
    ctx = b.new_context(viewport={"width": 375, "height": 812}, reduced_motion="reduce")
    pg = ctx.new_page(); pg.goto(url, wait_until="domcontentloaded")
    res["reduced_motion_opacity"] = pg.evaluate("() => [...document.querySelectorAll('.term-hero .ln')].map(l => getComputedStyle(l).opacity)")
    ctx.close()

    # no JS: all panels readable, copy buttons harmless
    ctx = b.new_context(viewport={"width": 1440, "height": 900}, java_script_enabled=False)
    pg = ctx.new_page(); pg.goto(url, wait_until="networkidle")
    res["nojs_panels_visible"] = pg.evaluate("() => [...document.querySelectorAll('.panel')].map(p => p.offsetHeight > 0)")
    ctx.close()
    b.close()

(out / "interactions.json").write_text(json.dumps(res, indent=1, ensure_ascii=False))
print(json.dumps(res, ensure_ascii=False, indent=1))
