"""console-triage layer: lane assignment, the normalized model and the dashboard slots.

Lanes come from the existing rules only: an excluded verdict, then a closed
status, then action() for what is still open. architecture-scan writes no
assessment.html or PDF, so the band and the slots are checked in dashboard.html.
The browser tests are opt-in: ARCHITECTURE_SCAN_BROWSER_TEST=1 and CHROME=<executable>.
"""
import json
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from test_architecture_scan import complete_doc, finding, findings, render

BROWSER = os.environ.get("ARCHITECTURE_SCAN_BROWSER_TEST") == "1"


def lane_doc():
    doc = complete_doc()
    valid = {"verdict": "Valid", "method": "static", "evidence": "job.py:58"}
    doc["findings"] = [
        finding("A-001", rule="R-01"),                                          # Valid, Confirmed
        finding("A-002", "Medium", confidence="Suspected"),                    # Valid, not Confirmed
        finding("A-003", "Low", validation={"verdict": "Likely", "method": "static", "evidence": "x.py:1"}),
        finding("A-004", "Low", status="Fixed", status_note="merged", validation=valid),
        finding("A-005", "Info", status="Accepted", status_note="owner accepted", validation=valid),
        finding("A-006", validation={"verdict": "FalsePositive", "method": "static", "evidence": "guarded"}),
        finding("A-007", "Info", status="Fixed", status_note="gone",
                validation={"verdict": "NotApplicable", "method": "static", "evidence": "removed"}),
    ]
    findings.validate(doc, complete=True)
    return doc


def console_data(html):
    return json.loads(re.search(r"<script type='application/json' id='console-data'>(.*?)</script>", html, re.S)[1])


class ConsoleModelTests(unittest.TestCase):
    def test_lanes_follow_existing_action_and_exclusion_rules(self):
        doc = lane_doc()
        cm = render.console_model(doc, "en")
        lanes = {f["id"]: f["lane"] for f in cm["findings"]}
        self.assertEqual(lanes, {"A-001": "fix_now", "A-002": "verify_first", "A-003": "verify_first",
                                 "A-004": "closed", "A-005": "closed",
                                 "A-006": "excluded", "A-007": "excluded"})
        # Open lanes are exactly action(); nothing is re-derived.
        for f in doc["findings"]:
            if render.is_excluded(f):
                self.assertEqual(lanes[f["id"]], "excluded")
            elif f.get("status", "Open") != "Open":
                self.assertEqual(lanes[f["id"]], "closed")
            else:
                self.assertEqual(lanes[f["id"]], render.action(f))
        self.assertEqual([lane["key"] for lane in cm["lanes"]], ["fix_now", "verify_first", "closed", "excluded"])
        self.assertEqual(cm["counts"], {"open": 3, "closed": 2, "excluded": 2, "total": 7})
        for lang, expected in (
            ("en", ["PLAN THE FIX", "VERIFY FIRST", "CLOSED", "EXCLUDED"]),
            ("ja", ["PLAN THE FIX / 修正を計画", "VERIFY FIRST / 先に検証",
                    "CLOSED / 対応済・受容", "EXCLUDED / 誤検知・除外"]),
        ):
            self.assertEqual([lane["label"] for lane in render.console_model(doc, lang)["lanes"]], expected)

    def test_the_open_lanes_hold_the_priority_queue(self):
        # Every finding the priority queue shows sits in an open lane under its own action label.
        doc = lane_doc()
        cm = render.console_model(doc, "en")
        queue = "".join(render.html_priority(doc, "en", {f["id"]: f.get("status", "Open") for f in doc["findings"]}))
        shown = re.findall(r"<h3><a href=\"#finding-(a-\d+)\">", queue)
        self.assertEqual(sorted(shown), ["a-001", "a-002", "a-003"])
        self.assertEqual(sorted(f["anchor"][len("finding-"):] for f in cm["findings"] if f["open"]), sorted(shown))

    def test_console_model_is_embedded_and_inspector_fields_keep_their_order(self):
        html = render.render_html(lane_doc(), "en")
        cm = console_data(html)
        self.assertEqual(cm, render.console_model(lane_doc(), "en"))
        first = next(f for f in cm["findings"] if f["id"] == "A-001")
        self.assertEqual([row["label"] for row in first["where"]],
                         [render.LABELS["en"][k] for k in ("location", "category", "rule", "blast_radius")])
        self.assertEqual(first["where"][0], {"label": "location", "value": "worker/refunds/job.py:58", "mono": True})
        self.assertEqual(first["evidence"], {"text": "job.py:58", "method": "static", "notes": []})
        self.assertEqual(first["fix"], "Call BillingService.adjust()")
        self.assertEqual(first["guidance"], render.DASH["en"]["fix_now_note"])
        self.assertIn(f"id='{first['anchor']}'", html)
        fp = next(f for f in cm["findings"] if f["id"] == "A-006")
        self.assertTrue(fp["excluded"] and not fp["open"])
        self.assertEqual(fp["status_label"], render.LABELS["en"]["excluded"])
        self.assertEqual(fp["evidence"]["notes"], [render.DASH["en"]["excluded_note"]])
        # Every perspective is a lamp, lit while an open finding names it.
        lamps = {p["name"]: (p["tone"], p["on"]) for p in cm["perspectives"]}
        self.assertEqual(list(lamps), list(findings.PERSPECTIVES))
        self.assertEqual(lamps["Domain model and data ownership"], ("high", True))
        self.assertTrue(all(v == ("muted", False) for k, v in lamps.items() if k != "Domain model and data ownership"))
        self.assertEqual({v["key"] for v in cm["verdicts"] if v["excluded"]}, set(findings.EXCLUDED))
        for slot in ("severity", "verdicts", "perspectives", "board", "inspector"):
            self.assertRegex(html, rf"data-cx='{slot}'")
        # The console is shown by the script, as the filters are; the band reads without it.
        self.assertIn("<div class='cx' id='console' data-js hidden>", html)
        self.assertIn("<li data-js hidden><a href=\"#triage\">", html)
        # Still one page script, opening with the renderer; the CSP hashes the concatenated text.
        scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
        self.assertEqual(scripts, [render.JS])
        self.assertTrue(render.JS.startswith(render.report_style.console_js()))
        self.assertIn("AgenticConsole.mount(JSON.parse(byId('console-data').textContent)", render.JS)
        self.assertIn(render.csp_hash(render.JS), html)
        self.assertIn(render.csp_hash(render.CSS), html)
        self.assertNotIn(".innerHTML", render.JS)

    def test_the_band_holds_the_one_h1_and_reads_without_the_script(self):
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                html = render.render_html(lane_doc(), lang)
                band = re.search(r"<header class='cx-band'>.*?</header>", html, re.S)[0]
                self.assertEqual(re.findall(r"<h1[^>]*>(.*?)</h1>", html), ["demo"])
                self.assertIn("<h1 id='cx-title'>demo</h1>", band)
                self.assertEqual(re.findall(r"<dd>(\d+)</dd>", band), ["3", "2", "2"])
                self.assertIn("href=\"report.md\"", band)
                self.assertIn("id='theme'", band)
                self.assertIn(render.overview_headline(lane_doc(), lang, {f["id"]: f.get("status", "Open")
                                                                          for f in lane_doc()["findings"]}), band)
                # The register leads main; the console sits between the band and the shell.
                self.assertLess(html.index("class='cx-band'"), html.index("id='console'"))
                self.assertLess(html.index("id='console'"), html.index("<div class='shell'>"))
                main = html.split("<main>", 1)[1]
                self.assertTrue(main.startswith("<section id='findings'"))

    def test_recorded_text_reaches_the_model_without_bidi_controls(self):
        doc = lane_doc()
        doc["findings"][0]["title"] = "Refund ‮evil⁦x"
        doc["meta"]["project"] = "demo‮"
        html = render.render_html(doc, "en")
        self.assertNotRegex(html, "[‪-‮⁦-⁩]")
        self.assertEqual(console_data(html)["findings"][0]["title"], "Refund [U+202E]evil[U+2066]x")

    def test_empty_run_still_has_every_lane_and_an_empty_readout(self):
        doc = {**complete_doc(), "findings": []}
        cm = render.console_model(doc, "en")
        self.assertEqual(cm["counts"], {"open": 0, "closed": 0, "excluded": 0, "total": 0})
        self.assertEqual(len(cm["lanes"]), 4)
        html = render.render_html(doc, "en")
        self.assertIn("id='triage'", html)
        self.assertEqual(re.findall(r"<dd>(\d+)</dd>", re.search(r"<header class='cx-band'>.*?</header>", html, re.S)[0]),
                         ["0", "0", "0"])


class ConsoleBrowserTests(unittest.TestCase):
    def start_browser(self):
        exe = os.environ.get("CHROME") or shutil.which("chromium") or shutil.which("google-chrome")
        if not exe:
            self.fail("Required Chrome/Chromium not installed; set CHROME to its executable")
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.fail("Required Playwright for Python is not installed")
        manager = sync_playwright().start()
        self.addCleanup(manager.stop)
        browser = manager.chromium.launch(executable_path=exe, headless=True, timeout=15000)
        self.addCleanup(browser.close)
        page = browser.new_page(service_workers="block")
        page.set_default_timeout(10000)
        return page

    def open(self, page, lang):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        path = Path(d) / "dashboard.html"
        path.write_text(render.render_html(lane_doc(), lang), encoding="utf-8")
        page.goto(path.as_uri())

    @unittest.skipUnless(BROWSER, "opt-in Chromium interaction test")
    def test_browser_board_selects_into_inspector_and_copies(self):
        page = self.start_browser()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("console", lambda msg: errors.append(msg.text) if msg.type == "error" else None)
        d = render.DASH["en"]
        self.open(page, "en")
        self.assertTrue(page.locator("#console").is_visible())
        self.assertEqual(page.locator("[data-lane='fix_now'] .cx-card").count(), 1)
        self.assertEqual(page.locator("[data-lane='verify_first'] .cx-card").count(), 2)
        self.assertEqual(page.locator("[data-lane='excluded'] .cx-card").count(), 2)
        self.assertEqual(page.locator(".cx-card[aria-pressed='true']").get_attribute("data-id"), "A-001")
        page.locator(".cx-card[data-id='A-004']").click()
        insp = page.locator("[data-cx='inspector']")
        self.assertIn("A-004", insp.inner_text())
        heads = insp.locator("h4").evaluate_all("els => els.map(e => e.firstChild.textContent)")
        self.assertEqual(heads, [d["cx_where_h"], d["cx_evidence_h"], d["cx_fix_h"]])
        page.evaluate("document.addEventListener('copy', e => { window.copied = e.target.value; })")
        insp.get_by_role("button", name=d["cx_copy"], exact=True).click()
        insp.get_by_role("button", name=d["copied"], exact=True).wait_for()
        self.assertTrue(page.evaluate("window.copied").startswith("## A-004 · "))
        # "Open in register" opens the finding's details through the register's own hash handler.
        insp.get_by_role("link", name=d["cx_open_record"], exact=True).click()
        # A selector wait, not wait_for_function: the page's CSP forbids string evaluation.
        page.locator("#finding-a-004 details[open]").wait_for(state="attached")
        self.assertEqual(errors, [])

    @unittest.skipUnless(BROWSER, "opt-in Chromium mobile test")
    def test_browser_console_fits_360px_without_horizontal_scroll(self):
        page = self.start_browser()
        page.set_viewport_size({"width": 360, "height": 800})
        self.open(page, "ja")
        self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), 360)


if __name__ == "__main__":
    unittest.main()
