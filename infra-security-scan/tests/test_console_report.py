"""Console-triage contract for the dashboard and printable assessment."""
import json
import os
import re
import shutil
import unittest

from test_report_views import SAMPLE, SAMPLE_JA, pages, render

BROWSER = os.environ.get("INFRA_SECURITY_SCAN_BROWSER_TEST") == "1"


class ConsoleReportTest(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(SAMPLE.read_text(encoding="utf-8"))

    def test_lanes_follow_existing_exclusion_and_order_rules(self):
        findings = self.data["findings"]
        findings[0]["validation"]["evidence"] += " Also covers I-001."
        findings[-1]["validation"]["verdict"] = "NotApplicable"
        findings.reverse()
        fs = render.ordered(findings)
        covered = render.covered_by(self.data)
        self.assertIn("I-001", covered)

        cm = render.console_model(self.data, render.LABELS["en"], "en", fs, covered)
        expected = [(f["id"], "excluded" if render.is_excluded(f) else "open") for f in fs]
        self.assertEqual([(f["id"], f["lane"]) for f in cm["findings"]], expected)
        self.assertEqual([lane["key"] for lane in cm["lanes"]], ["open", "excluded"])
        self.assertEqual(cm["counts"], {"open": 7, "closed": 0, "excluded": 2, "total": 9})
        for finding in cm["findings"]:
            self.assertEqual(finding["open"], finding["lane"] == "open")
            self.assertEqual(finding["excluded"], finding["lane"] == "excluded")
        by_id = {f["id"]: f for f in cm["findings"]}
        self.assertEqual(by_id["I-001"]["lane"], "open")
        self.assertEqual(by_id["I-001"]["evidence"]["notes"], ["Covered by: F-001"])

    def test_dashboard_embeds_the_model_slots_and_one_executable_script(self):
        dashboard, _ = pages(SAMPLE, "en")
        raw = re.search(r'<script type="application/json" id="data">(.*?)</script>', dashboard).group(1)
        cm = json.loads(raw)["console"]
        self.assertEqual(cm["meta"]["title"], self.data["meta"]["project"])
        first = cm["findings"][0]
        recorded = self.data["findings"][0]
        self.assertEqual(first["id"], "F-001")
        self.assertEqual(first["anchor"], first["id"])
        self.assertRegex(dashboard, r'<tr class="row" id="F-001"')
        self.assertEqual(first["where"][0]["value"], recorded["location"])
        self.assertEqual(first["evidence"]["text"], recorded["validation"]["evidence"])
        self.assertEqual(first["fix"], recorded["fix"])
        lamps = {p["name"]: (p["tone"], p["on"]) for p in cm["perspectives"]}
        self.assertEqual(lamps["Data protection"], ("high", True))
        self.assertEqual(lamps["Governance and guardrails"], ("muted", False))
        for slot in ("ident", "readout", "severity", "verdicts", "perspectives", "board", "inspector"):
            self.assertIn(f'data-cx="{slot}"', dashboard)
        scripts = re.findall(r"<script>(.*?)</script>", dashboard, re.S)
        self.assertEqual(len(scripts), 1)
        self.assertIn("AgenticConsole.mount(D.console", scripts[0])
        self.assertNotIn(".innerHTML", scripts[0])
        self.assertRegex(dashboard, r'<main>\s*<section id="findings"')

    def test_assessment_band_tiles_and_lanes(self):
        for source, lang in ((SAMPLE, "en"), (SAMPLE_JA, "ja")):
            with self.subTest(lang=lang):
                _, report = pages(source, lang)
                self.assertIn(f'<html lang="{lang}" class="cx-doc">', report)
                self.assertNotIn("<script", report)
                self.assertEqual(report.count("<h1 "), 1)
                band = re.search(r'<body>\s*<header class="cx-band">(.*?)</header>', report, re.S).group(1)
                data = json.loads(source.read_text(encoding="utf-8"))
                ordered = render.ordered(data["findings"])
                opened = [f for f in ordered if not render.is_excluded(f)]
                excluded = [f for f in ordered if render.is_excluded(f)]
                self.assertEqual(re.findall(r"<dd>(\d+)</dd>", band), [str(len(opened)), "0", str(len(excluded))])
                tiles = re.findall(r'data-severity="([^"]+)">(.*?)</div>', report)
                self.assertEqual([key for key, _ in tiles], list(render.SEVERITIES))
                for key, tile in tiles:
                    self.assertEqual(tile.count('<i class="cx-on"></i>'), sum(f["severity"] == key for f in opened))
                    self.assertNotIn("<i></i>", tile)
                triage = re.search(r'<section id="triage-lanes">(.*?)</section>', report, re.S).group(1)
                self.assertEqual(re.findall(r'data-lane="([^"]+)"', triage), ["open", "excluded"])
                for key, records in (("open", opened), ("excluded", excluded)):
                    lane = re.search(fr'id="lane-{key}".*?</div>', triage, re.S).group()
                    links = re.findall(r'<a href="#([^"]+)">', lane)
                    self.assertEqual(links, [f["id"] for f in records])
                    for identifier in links:
                        self.assertRegex(report, fr'<article class="[^"]+" id="{identifier}">')

    def test_empty_assessment_keeps_both_lanes_and_all_tiles(self):
        report = render.render_assessment(render.empty_record(), render.LABELS["en"], "en", {})
        self.assertEqual(re.findall(r'data-lane="([^"]+)"', report), ["open", "excluded"])
        self.assertEqual(report.count('<p class="small">None</p>'), 2)
        self.assertEqual(report.count('<span class="cx-n">0</span>'), 4)

    def start_browser(self):
        from playwright.sync_api import sync_playwright

        exe = os.environ.get("CHROME") or shutil.which("chromium") or shutil.which("google-chrome")
        if not exe:
            self.fail("Set CHROME to the Chrome or Chromium executable")
        manager = sync_playwright().start()
        self.addCleanup(manager.stop)
        browser = manager.chromium.launch(executable_path=exe, headless=True, timeout=15000)
        self.addCleanup(browser.close)
        page = browser.new_page(service_workers="block")
        page.route("**/*", lambda route: route.abort())
        page.set_default_timeout(10000)
        return page

    @unittest.skipUnless(BROWSER, "opt-in Chromium interaction test")
    def test_browser_selects_a_card_copies_markdown_and_opens_the_register(self):
        dashboard, _ = pages(SAMPLE, "en")
        page = self.start_browser()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.set_content(dashboard, wait_until="domcontentloaded")
        self.assertEqual(page.locator(".cx-band h1").count(), 1)
        self.assertEqual(page.locator(".cx-card[aria-pressed='true']").get_attribute("data-id"), "F-001")
        page.locator("[data-lane='excluded'] .cx-card[data-id='F-003']").click()
        inspector = page.locator("[data-cx='inspector']")
        self.assertIn("F-003", inspector.inner_text())
        labels = render.LABELS["en"]
        headings = inspector.locator("h4").evaluate_all("elements => elements.map(el => el.firstChild.textContent)")
        self.assertEqual(headings, [labels["cx_where_h"], labels["cx_evidence_h"], labels["cx_fix_h"]])
        page.evaluate("document.addEventListener('copy', e => { window.copied = e.target.value; })")
        inspector.get_by_role("button", name=labels["cx_copy"], exact=True).click()
        inspector.get_by_role("button", name=labels["copied"], exact=True).wait_for()
        expected = json.loads(re.search(r'<script type="application/json" id="md">(.*?)</script>', dashboard).group(1))
        self.assertEqual(page.evaluate("window.copied"), expected["F-003"])
        page.locator("#f-q").fill("No match here")
        inspector.get_by_role("link", name=labels["cx_open_record"]).click()
        page.locator("#F-003-detail").wait_for()
        self.assertEqual(errors, [])

    @unittest.skipUnless(BROWSER, "opt-in Chromium mobile test")
    def test_browser_console_fits_360px_without_horizontal_scroll(self):
        dashboard, _ = pages(SAMPLE_JA, "ja")
        page = self.start_browser()
        page.set_viewport_size({"width": 360, "height": 800})
        page.set_content(dashboard, wait_until="domcontentloaded")
        page.locator(".cx-card").first.wait_for()
        self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), 360)
