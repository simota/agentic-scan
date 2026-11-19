"""Offline console report checks and opt-in Chromium interaction checks."""
import json
import os
import re
import unittest
from pathlib import Path

from test_bug_scan import common, render, sample
from scan_report_kit import pdf, report

BROWSER = os.environ.get("BUG_SCAN_BROWSER_TEST") == "1"
LANES = ["with_fix", "without_fix", "closed", "excluded"]


class ConsoleReportTests(unittest.TestCase):
    def setUp(self):
        self.record, self.surfaces, self.history = sample()
        findings = self.record["findings"]
        findings[1].pop("fix")
        findings[5]["status"] = "Accepted"
        findings[6]["status"] = "Verified"
        findings[7].update(status="Triaged", validation=dict(verdict="FalsePositive", method="review"))
        findings.append(dict(id="BG-009", title="Out of scope", status="Open",
                             validation=dict(verdict="NotApplicable", method="review")))

    def output(self, lang="en"):
        return render.build(self.record, self.surfaces, self.history, lang)

    def test_lanes_follow_existing_status_exclusion_and_action(self):
        data = render.to_common(self.record, self.surfaces, "en")
        cm = render.console_model(self.record, data, "en")
        self.assertEqual([lane["key"] for lane in cm["lanes"]], LANES)
        self.assertEqual(cm["counts"], dict(open=5, closed=2, excluded=2, total=9))
        self.assertEqual({f["id"]: f["lane"] for f in cm["findings"]},
                         {"BG-001": "with_fix", "BG-002": "without_fix", "BG-003": "with_fix",
                          "BG-004": "with_fix", "BG-005": "with_fix", "BG-006": "closed",
                          "BG-007": "closed", "BG-008": "excluded", "BG-009": "excluded"})
        expected = report.priority(data["findings"])
        self.assertEqual([f["id"] for f in cm["findings"]], [f["id"] for f in expected])
        for source, item in zip(expected, cm["findings"]):
            with self.subTest(id=item["id"]):
                self.assertEqual(item["excluded"], source.get("excluded", False))
                self.assertEqual(item["open"], source["status"] == "Open" and not item["excluded"])
                if item["open"]:
                    self.assertEqual(item["lane"] == "with_fix", "action" in source)

    def test_dashboard_embeds_model_and_keeps_register_anchors(self):
        dashboard, _ = self.output()
        payload = json.loads(re.search(r'<script id="data" type="application/json">(.*?)</script>', dashboard).group(1))
        cm = payload["console"]
        self.assertEqual(cm["meta"]["skill"], "bug-scan")
        self.assertEqual(cm["meta"]["title"], self.record["meta"]["project"])
        self.assertEqual({f["id"]: f["anchor"] for f in cm["findings"]},
                         {f["id"]: f["anchor"] for f in payload["findings"]})
        first = next(f for f in cm["findings"] if f["id"] == "BG-001")
        original = self.record["findings"][0]
        self.assertEqual(first["where"], [dict(label="Location", value=first["location"], mono=True)])
        self.assertEqual(first["evidence"], dict(text=original["validation"]["evidence"], method=original["validation"]["method"]))
        self.assertEqual(first["fix"], original["fix"])
        self.assertEqual({v["key"] for v in cm["verdicts"] if v["excluded"]}, set(common.EXCLUDED))
        lamps = {p["name"].split()[0]: (p["on"], p["tone"]) for p in cm["perspectives"]}
        self.assertEqual({key: lamps[key] for key in ("BP01", "BP04", "BP11")},
                         {"BP01": (False, "muted"), "BP04": (False, "ink"), "BP11": (True, "high")})
        for slot in ("ident", "readout", "severity", "verdicts", "perspectives", "board", "inspector"):
            self.assertEqual(dashboard.count(f'data-cx="{slot}"'), 1)
        scripts = re.findall(r"<script(?:[^>]*)>(.*?)</script>", dashboard, re.S)
        self.assertEqual(len(scripts), 3)
        self.assertIn("AgenticConsole.mount(D.console", scripts[1])
        self.assertNotIn(".innerHTML", scripts[1])

    def test_printable_report_band_tiles_and_anchored_lanes(self):
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                _, document = self.output(lang)
                self.assertIn('class="cx-doc"', document)
                self.assertNotIn("<script", document)
                self.assertEqual(document.count("<h1>"), 1)
                band = re.search(r"<header class='cx-band'>.*?</header>", document, re.S).group()
                self.assertEqual(re.findall(r"<dd>(\d+)</dd>", band), ["5", "2", "2"])
                self.assertIn(report.esc(render.TEXT[lang]["title"]), band)
                tiles = re.findall(r"data-severity='(\w+)'.*?<span class='cx-cells'[^>]*>(.*?)</span>", document, re.S)
                self.assertEqual({key: (cells.count("<i"), cells.count("cx-on")) for key, cells in tiles},
                                 {"High": (1, 1), "Medium": (2, 2), "Low": (1, 1), "Info": (3, 1)})
                lanes = re.findall(r"<section id='lane-(\w+)' data-lane='\1'.*?</section>", document, re.S)
                self.assertEqual(lanes, LANES)
                expected = [["BG-001", "BG-003", "BG-004", "BG-005"], ["BG-002"], ["BG-006", "BG-007"], ["BG-008", "BG-009"]]
                for key, ids in zip(lanes, expected):
                    lane = re.search(rf"<section id='lane-{key}'.*?</section>", document, re.S).group()
                    links = re.findall(r"<a href='#(finding-\d+)'>(BG-\d+)</a>", lane)
                    self.assertEqual([fid for _, fid in links], ids)
                    for anchor, _ in links:
                        self.assertRegex(document, rf"<article [^>]+id='{anchor}'")
                queue = document.split('id="priority-queue"', 1)[1].split('id="closed-lanes"', 1)[0]
                self.assertNotRegex(queue, r"BG-00[6-9]")

    def test_empty_reports_keep_all_lanes_and_tiles(self):
        self.record = {"meta": self.record["meta"]}
        _, document = self.output()
        self.assertEqual(document.count("data-severity="), 4)
        self.assertEqual(document.count(report.CONSOLE_LABELS["en"]["lane_empty"]), 4)
        self.assertNotIn("<a href='#finding-", document)

    def browser_page(self, **options):
        from playwright.sync_api import sync_playwright

        manager = sync_playwright().start()
        self.addCleanup(manager.stop)
        executable = os.environ.get("CHROME") or next((p for p in pdf.CHROME_CANDIDATES if Path(p).is_file()), None)
        browser = manager.chromium.launch(executable_path=executable, chromium_sandbox=True, timeout=15000)
        self.addCleanup(browser.close)
        page = browser.new_page(service_workers="block", **options)
        page.set_default_timeout(10000)
        page.route("**/*", lambda route: route.abort())
        return page

    @unittest.skipUnless(BROWSER, "set BUG_SCAN_BROWSER_TEST=1 to run Chromium checks")
    def test_browser_selects_inspects_copies_and_opens_register(self):
        page = self.browser_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.set_content(self.output()[0], wait_until="domcontentloaded")
        self.assertEqual(page.locator("h1").count(), 1)
        self.assertEqual(page.locator(".cx-card[aria-pressed=true]").get_attribute("data-id"), "BG-001")
        page.locator("[data-lane=excluded] .cx-card[data-id=BG-008]").click()
        inspector = page.locator("[data-cx=inspector]")
        headings = inspector.locator("h4").evaluate_all("elements => elements.map(el => el.firstChild.textContent)")
        self.assertEqual(headings, ["Where", "Evidence", "Fix direction"])
        page.evaluate("""Object.defineProperty(navigator, 'clipboard', {value: undefined});
            document.addEventListener('copy', e => { window.copied = e.target.value; });""")
        inspector.get_by_role("button", name="Copy finding Markdown", exact=True).click()
        inspector.get_by_role("button", name="Copied", exact=True).wait_for()
        self.assertTrue(page.evaluate("window.copied").startswith("## BG-008"))
        inspector.get_by_role("link", name="Open in register", exact=True).click()
        row = page.locator("#finding-8 .finding-toggle")
        row.wait_for()
        self.assertEqual(row.get_attribute("aria-expanded"), "true")
        self.assertEqual(errors, [])

    @unittest.skipUnless(BROWSER, "set BUG_SCAN_BROWSER_TEST=1 to run Chromium checks")
    def test_browser_fits_360px(self):
        page = self.browser_page(viewport={"width": 360, "height": 800})
        page.set_content(self.output("ja")[0], wait_until="domcontentloaded")
        page.locator(".cx-card[aria-pressed=true]").wait_for()
        self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), 360)
