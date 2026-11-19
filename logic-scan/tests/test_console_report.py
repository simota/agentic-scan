"""console-triage layer: lane assignment, the normalized model, and the dashboard slots.

Lanes come from the existing rules only: an excluded verdict, then a closed
status, then action(). The browser tests are opt-in
(LOGIC_SCAN_BROWSER_TEST=1, with Python Playwright; CHROME=<executable>
picks a browser other than Playwright's own).
"""
import copy
import json
import os
import re
import unittest

from test_logic_scan import by_id, render, sample

BROWSER = os.environ.get("LOGIC_SCAN_BROWSER_TEST") == "1"


def lane_doc():
    """The sample (two fix_now, two pin_first, one excluded) plus a verify_first and a closed record."""
    doc = sample()
    check = dict(copy.deepcopy(by_id(doc, "F-003")), id="F-006", confidence="Suspected")
    fixed = dict(copy.deepcopy(by_id(doc, "F-002")), id="F-007", severity="Info", status="Fixed",
                 category="Error paths and defaults")
    doc["findings"] += [check, fixed]
    return doc


def console_data(html):
    return json.loads(re.search(r"id='console-data'>(.*?)</script>", html)[1])


class ConsoleModelTest(unittest.TestCase):
    def test_lanes_follow_existing_action_and_exclusion_rules(self):
        doc = lane_doc()
        cm = render.console_model(doc, "en")
        lanes = {f["id"]: f["lane"] for f in cm["findings"]}
        self.assertEqual(lanes, {"F-001": "pin_first", "F-002": "fix_now", "F-003": "fix_now",
                                 "F-004": "pin_first", "F-005": "excluded", "F-006": "verify_first",
                                 "F-007": "closed"})
        # Open lanes are exactly action(); nothing is re-derived.
        for f in doc["findings"]:
            if f.get("status", "Open") == "Open" and not render.is_excluded(f):
                self.assertEqual(lanes[f["id"]], render.action(f), f["id"])
        self.assertEqual([lane["key"] for lane in cm["lanes"]],
                         ["fix_now", "pin_first", "verify_first", "closed", "excluded"])
        self.assertEqual([lane["label"] for lane in cm["lanes"]][:3],
                         ["READY TO FIX", "COORDINATE THE CHANGE", "VERIFY FIRST"])
        self.assertEqual(cm["counts"], {"open": 5, "closed": 1, "excluded": 1, "total": 7})

    def test_an_excluded_record_is_excluded_whatever_its_status(self):
        doc = lane_doc()
        by_id(doc, "F-005")["status"] = "Fixed"
        cm = render.console_model(doc, "ja")
        fp = next(f for f in cm["findings"] if f["id"] == "F-005")
        self.assertEqual(fp["lane"], "excluded")
        self.assertTrue(fp["excluded"] and not fp["open"])
        self.assertEqual(fp["status_label"], render.LABELS["ja"]["excluded"])

    def test_inspector_fields_and_perspective_lamps(self):
        doc = lane_doc()
        cm = render.console_model(doc, "en")
        f1 = next(f for f in cm["findings"] if f["id"] == "F-001")
        src = by_id(doc, "F-001")
        self.assertEqual(f1["where"][0], {"label": "location", "value": ", ".join(src["location"]), "mono": True})
        self.assertEqual(f1["evidence"]["text"], src["validation"]["evidence"])
        # The counterexample is shown with the evidence it supports.
        self.assertIn(f"counterexample: {render.field_text(src, 'counterexample', 'en')}", f1["evidence"]["notes"])
        self.assertEqual(f1["fix"], src["fix"])
        self.assertEqual(f1["anchor"], render.anchor(src))
        self.assertEqual(f1["guidance"], render.DASH["en"]["pin_first_note"])
        self.assertEqual(f1["tags"], [src["change"], src["effort"], src["confidence"]])
        # Every perspective in reference order; lit while an open record names it.
        self.assertEqual([p["name"] for p in cm["perspectives"]], list(render.PERSPECTIVES))
        lamps = {p["name"]: (p["tone"], p["on"]) for p in cm["perspectives"]}
        self.assertEqual(lamps["Numbers and money"], ("high", True))
        self.assertEqual(lamps["Error paths and defaults"], ("ink", False))  # closed only
        self.assertEqual(lamps["Boundaries and ranges"], ("muted", False))
        self.assertEqual({v["key"] for v in cm["verdicts"] if v["excluded"]}, set(render.EXCLUDED))


class ConsoleDashboardTest(unittest.TestCase):
    def test_model_is_embedded_and_slots_are_present(self):
        doc = lane_doc()
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                html = render.render_html(doc, lang)
                self.assertEqual(console_data(html), render.console_model(doc, lang))
                for slot in ("severity", "verdicts", "perspectives", "board", "inspector"):
                    self.assertIn(f"data-cx='{slot}'", html, slot)
                # Only the page script runs; the renderer is inside it, pinned by the CSP hash.
                scripts = re.findall(r"<script(?: [^>]*)?>", html)
                self.assertEqual([s for s in scripts if "application/json" not in s], ["<script>"])
                self.assertTrue(render.JS.startswith(render.report_style.console_js()))
                self.assertIn("AgenticConsole.mount(", render.JS)
                self.assertNotIn(".innerHTML", render.JS)
                self.assertIn(f"script-src {render.csp_hash(render.JS)}", html)
                self.assertTrue(render.CSS.endswith(render.report_style.console_css()))

    def test_band_reads_without_javascript_and_the_console_waits_for_it(self):
        doc = lane_doc()
        html = render.render_html(doc, "en")
        band = html[html.index("<header class='cx-band'>"):html.index("</header>")]
        self.assertIn(f"<h1 id='cx-title'>{render.html_text(doc['meta']['project'])}</h1>", band)
        self.assertEqual(re.findall(r"<dd>(\d+)</dd>", band), ["5", "1", "1"])
        self.assertIn("href=\"report.md\"", band)
        self.assertIn("id='theme'", band)
        self.assertEqual(html.count("<h1"), 1)
        self.assertNotIn("class='appbar'", html)
        self.assertIn("<div class='cx' id='console' data-js hidden>", html)
        # The console sits before the shell; the register opens <main>.
        self.assertLess(html.index("id='console'"), html.index("<div class='shell'>"))
        self.assertTrue(html.split("<main>", 1)[1].startswith("<section id='findings'"))

    def test_existing_outputs_are_kept(self):
        html = render.render_html(lane_doc(), "en")
        for marker in ("id='priority-section'", "class='copy-finding'", "id='register-list'",
                       "id='decisions-section'", "id='coverage'", "id='plan'", "id='charts'", "class='facet'"):
            self.assertIn(marker, html, marker)

    def test_empty_record_still_has_every_lane(self):
        doc = sample()
        doc["findings"], doc["plan"] = [], []
        cm = render.console_model(doc, "en")
        self.assertEqual(len(cm["lanes"]), 5)
        self.assertEqual(cm["counts"], {"open": 0, "closed": 0, "excluded": 0, "total": 0})
        self.assertIn("data-cx='board'", render.render_html(doc, "en"))


@unittest.skipUnless(BROWSER, "opt-in Chromium test (LOGIC_SCAN_BROWSER_TEST=1)")
class ConsoleBrowserTest(unittest.TestCase):
    def page(self, width=1280):
        from playwright.sync_api import sync_playwright
        manager = sync_playwright().start()
        self.addCleanup(manager.stop)
        exe = os.environ.get("CHROME")
        browser = manager.chromium.launch(**({"executable_path": exe} if exe else {}), headless=True, timeout=15000)
        self.addCleanup(browser.close)
        page = browser.new_page(viewport={"width": width, "height": 800})
        page.set_default_timeout(10000)
        page.route("**/*", lambda route: route.abort())
        return page

    def test_board_selects_into_inspector_and_copies(self):
        page = self.page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        d = render.DASH["en"]
        page.goto("about:blank")
        page.set_content(render.render_html(lane_doc(), "en"), wait_until="domcontentloaded")
        self.assertTrue(page.locator("#console").is_visible())
        counts = {key: page.locator(f"[data-lane='{key}'] .cx-card").count()
                  for key in ("fix_now", "pin_first", "verify_first", "closed", "excluded")}
        self.assertEqual(counts, {"fix_now": 2, "pin_first": 2, "verify_first": 1, "closed": 1, "excluded": 1})
        self.assertEqual(page.locator(".cx-card[aria-pressed='true']").get_attribute("data-id"), "F-002")
        page.locator(".cx-card[data-id='F-007']").click()
        insp = page.locator("[data-cx='inspector']")
        self.assertIn("F-007", insp.inner_text())
        heads = insp.locator("h4").evaluate_all("els => els.map(e => e.firstChild.textContent)")
        self.assertEqual(heads, [d["cx_where_h"], d["cx_evidence_h"], d["cx_fix_h"]])
        page.evaluate("document.addEventListener('copy', e => { window.copied = e.target.value; })")
        insp.get_by_role("button", name=d["cx_copy"], exact=True).click()
        insp.get_by_role("button", name=d["copied"], exact=True).wait_for()
        self.assertTrue(page.evaluate("window.copied").startswith("## F-007"))
        self.assertEqual(errors, [])

    def test_console_fits_360px_without_horizontal_scroll(self):
        page = self.page(360)
        page.goto("about:blank")
        page.set_content(render.render_html(lane_doc(), "ja"), wait_until="domcontentloaded")
        self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), 360)


if __name__ == "__main__":
    unittest.main()
