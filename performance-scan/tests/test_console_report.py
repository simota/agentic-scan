"""Console model, dashboard and printable assessment integration."""
from html import unescape
import json
import os
from pathlib import Path
import re
import tempfile
import unittest

from support import complete_doc, finding, findings, render



LANES = ["open", "closed", "excluded"]


def lane_doc():
    doc = complete_doc()
    doc["findings"] = [
        finding("P-003", "Medium"),
        finding("P-001", "High"),
        finding("P-004", "Low", status="Fixed"),
        finding("P-005", "Low", status="Accepted"),
        finding("P-006", "High", validation={"verdict": "FalsePositive", "method": "static"}),
        finding("P-007", "Info", status="Fixed", validation={"verdict": "NotApplicable", "method": "static"}),
    ]
    return doc


class ConsoleReportTests(unittest.TestCase):
    def model(self, doc, lang="en"):
        dashboard = render.render_html(doc, lang)
        data = re.search(r"<template id='data'>(.*?)</template>", dashboard)[1]
        return json.loads(unescape(data))["console"]

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
        card = next(f for f in cm["findings"] if f["id"] == "P-001")
        finding = next(f for f in doc["findings"] if f["id"] == "P-001")
        self.assertEqual(card["where"][0]["label"], cm["labels"]["location"])
        self.assertEqual(card["where"][0]["value"], "\n".join(["app/orders/serializers.py:42"]))
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
                self.assertEqual(re.findall(r"<dd>(\d+)</dd>", html), ["2", "2", "2"])
                self.assertEqual(re.findall(r"data-lane='([^']+)'", html), LANES)
                tiles = dict(re.findall(r"data-severity='([^']+)'.*?<span class='cx-cells' aria-hidden='true'>(.*?)</span>", html))
                self.assertEqual(list(tiles), list(findings.SEVERITIES))
                actual = {key: (cells.count("<i"), cells.count("class='cx-on'")) for key, cells in tiles.items()}
                self.assertEqual(actual, {"High": (1, 1), "Medium": (1, 1), "Low": (2, 0), "Info": (0, 0)})
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

    @unittest.skipUnless(os.environ.get("PERFORMANCE_SCAN_BROWSER_TEST") == "1", "opt-in Chromium test")
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
            data = page.locator("#data").evaluate("element => element.content.textContent")
            model = json.loads(data)["console"]
            labels = model["labels"]
            finding_id = "P-006"
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
            expect(record).to_have_js_property("open", True)
            self.assertEqual(page.locator("h1").count(), 1)
            self.assertEqual(errors, [])

            page.goto(assessment.as_uri())
            page.emulate_media(media="print", color_scheme="dark")
            self.assertEqual(page.locator("html").evaluate("el => getComputedStyle(el).colorScheme"), "light")
            self.assertEqual(page.locator(".cx-band").evaluate("el => getComputedStyle(el).printColorAdjust"),
                             "exact")
            self.assertTrue(page.pdf(print_background=True, prefer_css_page_size=True).startswith(b"%PDF-"))

    def test_lane_assignments_and_existing_open_order(self):
        doc = lane_doc()
        cm = self.model(doc)
        self.assertEqual([lane["key"] for lane in cm["lanes"]], LANES)
        self.assertEqual(cm["counts"], {"open": 2, "closed": 2, "excluded": 2, "total": 6})
        cards = {f["id"]: f["lane"] for f in cm["findings"]}
        for f in doc["findings"]:
            expected = ("excluded" if render.is_excluded(f) else
                        "open" if findings.finding_status(f) == "Open" else "closed")
            self.assertEqual(cards[f["id"]], expected)
        order = ["P-003", "P-001"]
        self.assertEqual([f["id"] for f in cm["findings"] if f["open"]], order)
        priority = render.render_assessment_html(doc, "en").split("id='closed-lanes'", 1)[0]
        self.assertEqual(re.findall(r"<a href='#finding-p-\d+'>(P-\d+)</a>", priority), order)
