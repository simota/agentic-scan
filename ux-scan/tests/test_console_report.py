"""console-triage layer: lane assignment, the embedded model, and the new panels.

Lanes come from the existing rules only: an excluded verdict, then a closed
status, then next_action(), which also gives to_common() its next action. The
browser tests are opt-in (UX_SCAN_BROWSER_TEST=1, CHROME=<executable>).
"""

import contextlib
import copy
import io
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "ux-scan" / "scripts"))

import render  # noqa: E402

SAMPLE = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
FLOWS = json.loads((ROOT / "examples" / "flows.sample.json").read_text(encoding="utf-8"))
BROWSER = os.environ.get("UX_SCAN_BROWSER_TEST") == "1"
LANES = ["fix", "verify", "closed", "excluded"]


def lane_record():
    """The sample with one Fixed, one Accepted and one fixless Valid record added to its mix."""
    data = copy.deepcopy(SAMPLE)
    data["limitations"].append("report.pdf not produced: no engine in this test")
    by_id = {f["id"]: f for f in data["findings"]}
    by_id["U-020"]["status"] = "Fixed"
    by_id["U-021"]["status"] = "Accepted"
    by_id["U-019"]["fix"] = ""
    return data


def embedded(page):
    return json.loads(re.search(r'<script id="data" type="application/json">(.*?)</script>', page, re.S).group(1))


def section(page, start, end="</section>"):
    at = page.index(start)
    return page[at:page.index(end, at)]


class ConsoleReportTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.dir = Path(temp.name)
        shutil.copytree(ROOT / "examples" / "evidence", self.dir / "evidence")
        (self.dir / "flows.json").write_text(json.dumps(FLOWS), encoding="utf-8")

    def render(self, data, lang="en"):
        out = self.dir / ("out-" + lang)
        (self.dir / "findings.json").write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            code = render.main([str(self.dir / "findings.json"), "--out", str(out), "--lang", lang, "--no-pdf"])
        self.assertEqual(code, 0, err.getvalue())
        return ((out / "dashboard.html").read_text(encoding="utf-8"), (out / "report.html").read_text(encoding="utf-8"))

    def model(self, data, lang="en"):
        common = render.report.validate(render.to_common(data, lang, FLOWS))
        return common, render.console_model(data, common, lang, FLOWS)

    def test_lanes_follow_the_next_action_and_exclusion_rules(self):
        data = lane_record()
        common, cm = self.model(data)
        lanes = {f["id"]: f["lane"] for f in cm["findings"]}
        self.assertEqual([lane["key"] for lane in cm["lanes"]], LANES)
        self.assertEqual({i for i, lane in lanes.items() if lane == "verify"}, {"U-018", "U-019", "U-022"})
        self.assertEqual({i for i, lane in lanes.items() if lane == "closed"}, {"U-020", "U-021"})
        self.assertEqual({i for i, lane in lanes.items() if lane == "excluded"}, {"U-026"})
        # Open lanes are exactly the next action each card already shows; nothing is re-derived.
        T = render.LABELS["en"]
        for f in common["findings"]:
            expected = {"fix": T["fix"], "verify": T["verify"]}.get(lanes[f["id"]])
            self.assertEqual(f.get("action", {}).get("label"), expected, f["id"])
        for f in data["findings"]:
            if lanes[f["id"]] in ("fix", "verify"):
                self.assertEqual(lanes[f["id"]], render.next_action(f))
        self.assertEqual(cm["counts"], {"open": 23, "closed": 2, "excluded": 1, "total": 26})

    def test_console_model_is_embedded_and_inspector_text_comes_from_the_record(self):
        data = lane_record()
        dashboard, _ = self.render(data)
        payload = embedded(dashboard)
        cm = payload["console"]
        source = next(f for f in data["findings"] if f["id"] == "U-001")
        card = next(f for f in cm["findings"] if f["id"] == "U-001")
        self.assertEqual(card["where"][0], {"label": render.report.LABELS["en"]["location"],
                                            "value": source["location"], "mono": True})
        self.assertEqual(card["evidence"]["text"], source["validation"]["evidence"])
        self.assertEqual(card["fix"], source["fix"])
        self.assertEqual(card["anchor"], next(f["anchor"] for f in payload["findings"] if f["id"] == "U-001"))
        verify = next(f for f in cm["findings"] if f["id"] == "U-018")
        self.assertEqual(verify["guidance"], render.LABELS["en"]["verify_text"])
        fp = next(f for f in cm["findings"] if f["id"] == "U-026")
        self.assertTrue(fp["excluded"] and not fp["open"])
        # No finding names a perspective, so every lamp stays unlit.
        self.assertEqual(len(cm["perspectives"]), len(SAMPLE["perspectives"]))
        self.assertEqual({(p["tone"], p["on"]) for p in cm["perspectives"]}, {("muted", False)})
        self.assertEqual({v["key"] for v in cm["verdicts"] if v["excluded"]}, {"FalsePositive", "NotApplicable"})
        for slot in ("ident", "readout", "severity", "verdicts", "perspectives", "board", "inspector"):
            self.assertIn(f'data-cx="{slot}"', dashboard, slot)
        self.assertEqual(dashboard.count("<h1"), 0)  # the band's h1 is drawn by console.js
        scripts = re.findall(r"<script>(.*?)</script>", dashboard, re.S)
        self.assertEqual(len(scripts), 1)
        self.assertIn("AgenticConsole.mount(D.console", scripts[0])
        self.assertNotIn(".innerHTML", scripts[0])
        # The register comes first in main; the old summary, priority list, coverage and legend stay.
        main = dashboard[dashboard.index("<main>"):]
        self.assertLess(main.index('id="findings"'), main.index('id="overview"'))
        for kept in ('id="priority"', 'id="coverage"', 'id="lists"', 'id="levels"', 'href="#triage"'):
            self.assertIn(kept, dashboard)
        # The companion pages are linked from the band's tools.
        tools = section(dashboard, '<div class="cx-tools">', "</div>")
        self.assertIn('href="evidence.html"', tools)

    def test_report_has_band_tiles_and_lanes_in_order(self):
        data = lane_record()
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                _, page = self.render(data, lang)
                self.assertIn('<html lang="%s" class="cx-doc">' % lang, page)
                self.assertNotIn("<script", page)
                band = section(page, "<header class='cx-band'>", "</header>")
                self.assertEqual(re.findall(r"<dd>(\d+)</dd>", band), ["23", "2", "1"])
                self.assertEqual(page.count("<h1"), 1)
                tiles = re.findall(r"data-severity='(\w+)'>.*?<span class='cx-cells' aria-hidden='true'>(.*?)</span>", page)
                self.assertEqual([sev for sev, _ in tiles], ["High", "Medium", "Low", "Info"])
                cells = {sev: (body.count("<i class='cx-on'>"), body.count("<i></i>")) for sev, body in tiles}
                self.assertEqual(cells, {"High": (6, 0), "Medium": (12, 0), "Low": (3, 2), "Info": (2, 0)})
                self.assertEqual(re.findall(r"data-lane='(\w+)'", page), LANES)
                queue = section(page, '<section id="priority-queue">')
                self.assertEqual(re.findall(r"data-lane='(\w+)'", queue), LANES[:2])
                self.assertIn(">U-019<", section(page, "id='lane-verify'", "</table>"))
                closed = section(page, "<section id='closed-lanes'>")
                for finished in ("U-020", "U-021", "U-026"):
                    self.assertNotIn(f">{finished}<", queue)
                    self.assertIn(f">{finished}<", closed)
                # The level legend still sits before the priority queue.
                self.assertLess(page.index('<section id="levels">'), page.index('<section id="priority-queue">'))

    def start_browser(self):
        exe = os.environ.get("CHROME") or shutil.which("chromium") or shutil.which("google-chrome")
        if not exe:
            self.fail("Required Chrome/Chromium not installed; set CHROME to its executable")
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.fail("Required Playwright not installed")
        manager = sync_playwright().start()
        self.addCleanup(manager.stop)
        browser = manager.chromium.launch(executable_path=exe, headless=True, timeout=15000)
        self.addCleanup(browser.close)
        page = browser.new_page(service_workers="block")
        page.set_default_timeout(10000)
        page.route("**/*", lambda route: route.abort())
        return page

    @unittest.skipUnless(BROWSER, "opt-in Chromium interaction test")
    def test_browser_board_selects_into_inspector_and_copies(self):
        page, errors = self.start_browser(), []
        page.on("pageerror", lambda error: errors.append(str(error)))
        dashboard, _ = self.render(lane_record())
        labels = render.report.LABELS["en"]
        page.set_content(dashboard, wait_until="domcontentloaded")
        self.assertEqual(page.locator("[data-lane='verify'] .cx-card").count(), 3)
        self.assertEqual(page.locator("[data-lane='closed'] .cx-card").count(), 2)
        self.assertEqual(page.locator(".cx-card[aria-pressed='true']").get_attribute("data-id"), "U-001")
        page.locator(".cx-card[data-id='U-020']").click()
        insp = page.locator("[data-cx='inspector']")
        self.assertIn("U-020", insp.inner_text())
        heads = insp.locator("h4").evaluate_all("els => els.map(e => e.firstChild.textContent)")
        self.assertEqual(heads, [labels["cx_where_h"], labels["cx_evidence_h"], labels["cx_fix_h"]])
        page.evaluate("document.addEventListener('copy', e => { window.copied = e.target.value; })")
        insp.get_by_role("button", name=labels["cx_copy"], exact=True).click()
        insp.get_by_role("button", name=labels["copied"], exact=True).wait_for()
        self.assertTrue(page.evaluate("window.copied").startswith("## U-020"))
        self.assertEqual(page.locator("[data-cx='readout'] dd").all_inner_texts(), ["23", "2", "1"])
        self.assertEqual(errors, [])

    @unittest.skipUnless(BROWSER, "opt-in Chromium mobile test")
    def test_browser_console_fits_360px_without_horizontal_scroll(self):
        page = self.start_browser()
        page.set_viewport_size({"width": 360, "height": 800})
        dashboard, _ = self.render(lane_record(), "ja")
        page.set_content(dashboard, wait_until="domcontentloaded")
        self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), 360)


if __name__ == "__main__":
    unittest.main()
