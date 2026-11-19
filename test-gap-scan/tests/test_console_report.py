"""Console model, dashboard and printable assessment integration."""
import copy
import json
import os
from pathlib import Path
import re
import tempfile
import unittest

from test_test_scan import findings, render, sample



LANES = ["fix_now", "pin_first", "verify_first", "closed", "excluded"]


def lane_doc():
    doc = sample()
    original = doc["findings"][0]
    doc["findings"] = []
    for n, severity, status, verdict, testability in (
        (1, "High", "Open", "Valid", "Direct"),
        (2, "Medium", "Open", "Valid", "Seam"),
        (3, "Low", "Open", "Likely", "Direct"),
        (4, "Low", "Fixed", "Valid", "Direct"),
        (5, "Low", "Accepted", "Valid", "Direct"),
        (6, "High", "Open", "FalsePositive", "Direct"),
        (7, "Info", "Fixed", "NotApplicable", "Direct"),
    ):
        f = copy.deepcopy(original)
        f.update(id=f"F-{n:03d}", severity=severity, status=status, testability=testability,
                 confidence="Confirmed", fix="Synthetic fix direction", location=["src/demo.py:1", "lib/demo.py:2"])
        f["validation"].update(verdict=verdict, evidence="Synthetic evidence")
        doc["findings"].append(f)
    del doc["findings"][0]["status"]
    return doc


class ConsoleReportTests(unittest.TestCase):
    def model(self, doc, lang="en"):
        dashboard = render.render_html(doc, lang)
        data = re.search(r"<script type='application/json' id='labels'>(.*?)</script>", dashboard)[1]
        return json.loads(data)["console"]

    def test_console_model_slots_and_inspector_fields(self):
        doc = lane_doc()
        dashboard = render.render_html(doc, "en")
        cm = self.model(doc)
        self.assertEqual(cm, render.console_model(doc, "en"))
        for slot in ("ident", "readout", "severity", "verdicts", "perspectives", "board", "inspector"):
            self.assertIn(f"data-cx='{slot}'", dashboard)
        self.assertIn("<main><section id='findings'", dashboard)
        self.assertIn("href='assessment.html'", dashboard)
        js = re.findall(r"<script>(.*?)</script>", dashboard, re.S)
        self.assertEqual(len(js), 1)
        self.assertIn("window.AgenticConsole.mount", js[0])
        self.assertNotIn(".innerHTML", js[0])
        card = next(f for f in cm["findings"] if f["id"] == "F-001")
        finding = next(f for f in doc["findings"] if f["id"] == "F-001")
        self.assertEqual(card["where"][0]["label"], cm["labels"]["location"])
        self.assertEqual(card["where"][0]["value"], "\n".join(["src/demo.py:1", "lib/demo.py:2"]))
        self.assertEqual(card["evidence"]["text"], finding["validation"]["evidence"])
        self.assertEqual(card["fix"], finding["fix"])
        self.assertIn(f"id='{card['anchor']}'", dashboard)
        lamp = next(p for p in cm["perspectives"] if p["name"] == finding["category"])
        self.assertEqual((lamp["on"], lamp["tone"]), (True, "high"))
        self.assertEqual({v["key"] for v in cm["verdicts"] if v["excluded"]}, set(findings.EXCLUDED))

    def test_assessment_counts_tiles_and_lane_order(self):
        doc = lane_doc()
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                html = render.render_assessment_html(doc, lang)
                self.assertIn("class='cx-doc'", html)
                self.assertNotIn("<script", html)
                self.assertEqual(html.count("<h1"), 1)
                self.assertEqual(re.findall(r"<dd>(\d+)</dd>", html), ["3", "2", "2"])
                self.assertEqual(re.findall(r"data-lane='([^']+)'", html), LANES)
                tiles = dict(re.findall(r"data-severity='([^']+)'.*?<span class='cx-cells' aria-hidden='true'>(.*?)</span>", html))
                self.assertEqual(list(tiles), list(findings.SEVERITIES))
                actual = {key: (cells.count("<i"), cells.count("class='cx-on'")) for key, cells in tiles.items()}
                self.assertEqual(actual, {"High": (1, 1), "Medium": (1, 1), "Low": (3, 1), "Info": (0, 0)})
                priority, closed = html.split("id='priority-queue'", 1)[1].split("id='closed-lanes'", 1)
                for card in self.model(doc, lang)["findings"]:
                    link = f"href='#{card['anchor']}'"
                    self.assertIn(link, priority if card["open"] else closed)
                    self.assertIn(f"id='{card['anchor']}'", html)
                    if not card["open"]:
                        self.assertNotIn(link, priority)

    def test_empty_assessment_keeps_all_lanes_and_tiles(self):
        doc = lane_doc()
        doc["findings"] = []
        html = render.render_assessment_html(doc, "en")
        self.assertEqual(re.findall(r"data-lane='([^']+)'", html), LANES)
        self.assertEqual(re.findall(r"<dd>(\d+)</dd>", html), ["0", "0", "0"])
        self.assertEqual(html.count("data-severity="), len(findings.SEVERITIES))

    @unittest.skipUnless(os.environ.get("TEST_GAP_SCAN_BROWSER_TEST") == "1", "opt-in Chromium test")
    def test_browser_card_inspector_copy_mobile_and_pdf(self):
        from playwright.sync_api import expect, sync_playwright

        playwright = sync_playwright().start()
        self.addCleanup(playwright.stop)
        browser = playwright.chromium.launch(executable_path=os.environ.get("CHROME") or None,
                                             headless=True, timeout=15000)
        self.addCleanup(browser.close)
        page = browser.new_page(viewport={"width": 360, "height": 800})
        page.set_default_timeout(10000)
        page.add_init_script("Object.defineProperty(navigator, 'clipboard', {value: undefined})")
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))

        with tempfile.TemporaryDirectory() as folder:
            dashboard = Path(folder) / "dashboard.html"
            assessment = Path(folder) / "assessment.html"
            doc = lane_doc()
            dashboard.write_text(render.render_html(doc, "ja"), encoding="utf-8")
            assessment.write_text(render.render_assessment_html(doc, "ja"), encoding="utf-8")
            page.goto(dashboard.as_uri())
            data = page.locator("#labels").text_content()
            model = json.loads(data)["console"]
            labels = model["labels"]
            finding_id = "F-006"
            card = next(f for f in model["findings"] if f["id"] == finding_id)
            page.locator(f'.cx-card[data-id="{finding_id}"]').click()
            inspector = page.locator('[data-cx="inspector"]')
            self.assertIn(finding_id, inspector.inner_text())
            heads = inspector.locator("h4").evaluate_all("heads => heads.map(h => h.firstChild.textContent)")
            self.assertEqual(heads, [labels["where_h"], labels["evidence_h"], labels["fix_h"]])
            page.evaluate("document.addEventListener('copy', event => { window.copied = event.target.value; })")
            inspector.get_by_role("button", name=labels["copy"], exact=True).click()
            inspector.get_by_role("button", name=labels["copied"], exact=True).wait_for()
            self.assertTrue(page.evaluate("window.copied").startswith(f"## {finding_id}"))
            self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), 360)
            inspector.get_by_role("link", name=labels["open_record"]).click()
            record = page.locator(f"#{card['anchor']}")
            expect(record).to_be_visible()
            expect(record.locator("details")).to_have_js_property("open", True)
            self.assertEqual(page.locator("h1").count(), 1)
            self.assertEqual(errors, [])

            page.goto(assessment.as_uri())
            page.emulate_media(media="print", color_scheme="dark")
            self.assertEqual(page.locator("html").evaluate("el => getComputedStyle(el).colorScheme"), "light")
            self.assertEqual(page.locator(".cx-band").evaluate("el => getComputedStyle(el).printColorAdjust"),
                             "exact")
            self.assertTrue(page.pdf(print_background=True, prefer_css_page_size=True).startswith(b"%PDF-"))

    def test_lane_assignments_follow_existing_rules(self):
        doc = lane_doc()
        cm = self.model(doc)
        self.assertEqual([lane["key"] for lane in cm["lanes"]], LANES)
        self.assertEqual(cm["counts"], {"open": 3, "closed": 2, "excluded": 2, "total": 7})
        cards = {f["id"]: f["lane"] for f in cm["findings"]}
        self.assertEqual([cards[f"F-{n:03d}"] for n in range(1, 8)],
                         ["fix_now", "pin_first", "verify_first", "closed", "closed", "excluded", "excluded"])
        for f in doc["findings"]:
            expected = ("excluded" if render.is_excluded(f) else
                        render.action(f) if f.get("status", "Open") == "Open" else "closed")
            self.assertEqual(cards[f["id"]], expected)
