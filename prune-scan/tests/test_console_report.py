"""console-triage layer: lane assignment, the embedded model, and the new panels.

Lanes come from the existing rules only: an excluded verdict, then a closed
status, then subtraction_groups(); Unlikely, which no group takes, has its own
lane. The browser tests are opt-in (PRUNE_SCAN_BROWSER_TEST=1, CHROME=<executable>).
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
sys.path.insert(0, str(ROOT / "skills" / "prune-scan" / "scripts"))

import render  # noqa: E402

SAMPLE = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
UNITS = json.loads((ROOT / "examples" / "units.sample.json").read_text(encoding="utf-8"))
BROWSER = os.environ.get("PRUNE_SCAN_BROWSER_TEST") == "1"
LANES = ["now", "reduce", "decide", "unlikely", "closed", "excluded"]


def lane_record():
    """The sample with one Fixed, one Accepted and one Unlikely record added to its mix."""
    data = copy.deepcopy(SAMPLE)
    by_id = {f["id"]: f for f in data["findings"]}
    by_id["P-030"]["status"] = "Fixed"
    by_id["P-031"]["status"] = "Accepted"
    by_id["P-024"]["validation"]["verdict"] = "Unlikely"
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

    def render(self, data, lang="en"):
        out = self.dir / ("out-" + lang)
        (self.dir / "findings.json").write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        (self.dir / "units.json").write_text(json.dumps(UNITS, ensure_ascii=False), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            code = render.main([str(self.dir / "findings.json"), "--out", str(out), "--lang", lang, "--no-pdf"])
        self.assertEqual(code, 0, err.getvalue())
        return ((out / "dashboard.html").read_text(encoding="utf-8"), (out / "report.html").read_text(encoding="utf-8"))

    def model(self, data, lang="en"):
        checked = render.check_findings(copy.deepcopy(data), render.check_units(copy.deepcopy(UNITS)))
        common = render.report.validate(render.to_common(checked, lang, UNITS))
        return checked, common, render.console_model(checked, common, lang, UNITS)

    def test_lanes_follow_the_subtraction_groups_and_exclusion_rules(self):
        data, common, cm = self.model(lane_record())
        lanes = {f["id"]: f["lane"] for f in cm["findings"]}
        self.assertEqual([lane["key"] for lane in cm["lanes"]], LANES)
        # The three open lanes are exactly the subtraction summary's groups; nothing is re-derived.
        now, reduce, decide = render.subtraction_groups(data["findings"])
        for key, ids in (("now", now), ("reduce", reduce), ("decide", decide)):
            self.assertEqual(sorted(i for i, lane in lanes.items() if lane == key), sorted(ids), key)
        self.assertEqual({i for i, lane in lanes.items() if lane == "unlikely"}, {"P-024"})
        self.assertEqual({i for i, lane in lanes.items() if lane == "closed"}, {"P-030", "P-031"})
        self.assertEqual({i for i, lane in lanes.items() if lane == "excluded"}, {"P-038"})
        # The lane agrees with the next action to_common() already gives each card.
        T = render.LABELS["en"]
        for f in common["findings"]:
            action = f.get("action", {}).get("label")
            expected = {"now": T["subtract"], "reduce": T["subtract"], "decide": T["verify"]}.get(lanes[f["id"]])
            self.assertEqual(action, expected, f["id"])
        self.assertEqual(cm["counts"], {"open": 35, "closed": 2, "excluded": 1, "total": 38})

    def test_console_model_is_embedded_and_inspector_text_comes_from_the_record(self):
        data = lane_record()
        dashboard, _ = self.render(data)
        payload = embedded(dashboard)
        cm = payload["console"]
        source = next(f for f in data["findings"] if f["id"] == "P-001")
        card = next(f for f in cm["findings"] if f["id"] == "P-001")
        self.assertEqual(card["lane"], "now")
        self.assertEqual(card["where"][0], {"label": render.LABELS["en"]["element"], "value": source["element"]})
        self.assertEqual(card["evidence"]["text"], source["validation"]["evidence"])
        self.assertTrue(card["fix"].startswith(render.ACTIONS["en"][source["subtraction"]["action"]] + ": "))
        self.assertEqual(card["anchor"], next(f["anchor"] for f in payload["findings"] if f["id"] == "P-001"))
        decide = next(f for f in cm["findings"] if f["lane"] == "decide")
        self.assertEqual(decide["guidance"], render.LABELS["en"]["verify_text"])
        fp = next(f for f in cm["findings"] if f["id"] == "P-038")
        self.assertTrue(fp["excluded"] and not fp["open"])
        # No finding names a perspective, so every lamp stays unlit.
        self.assertTrue(cm["perspectives"])
        self.assertEqual({(p["tone"], p["on"]) for p in cm["perspectives"]}, {("muted", False)})
        self.assertEqual({v["key"] for v in cm["verdicts"] if v["excluded"]}, {"FalsePositive", "NotApplicable"})
        for slot in ("ident", "readout", "severity", "verdicts", "perspectives", "board", "inspector"):
            self.assertIn(f'data-cx="{slot}"', dashboard, slot)
        self.assertEqual(dashboard.count("<h1"), 0)  # the band's h1 is drawn by console.js
        scripts = re.findall(r"<script>(.*?)</script>", dashboard, re.S)
        self.assertEqual(len(scripts), 1)
        self.assertIn("AgenticConsole.mount(D.console", scripts[0])
        self.assertNotIn(".innerHTML", scripts[0])
        # The register comes first in main; the old summary, priority list and coverage stay.
        main = dashboard[dashboard.index("<main>"):]
        self.assertLess(main.index('id="findings"'), main.index('id="overview"'))
        for kept in ('id="priority"', 'id="coverage"', 'id="lists"', "id='levels'", 'href="#triage"'):
            self.assertIn(kept, dashboard)

    def test_report_has_band_tiles_and_lanes_in_order(self):
        data = lane_record()
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                _, page = self.render(data, lang)
                self.assertIn('<html lang="%s" class="cx-doc">' % lang, page)
                self.assertNotIn("<script", page)
                band = section(page, "<header class='cx-band'>", "</header>")
                self.assertEqual(re.findall(r"<dd>(\d+)</dd>", band), ["35", "2", "1"])
                self.assertEqual(page.count("<h1"), 1)
                tiles = re.findall(r"data-severity='(\w+)'>.*?<span class='cx-cells' aria-hidden='true'>(.*?)</span>", page)
                self.assertEqual([sev for sev, _ in tiles], ["High", "Medium", "Low", "Info"])
                cells = {sev: (body.count("<i class='cx-on'>"), body.count("<i></i>")) for sev, body in tiles}
                self.assertEqual(cells, {"High": (5, 0), "Medium": (9, 0), "Low": (20, 2), "Info": (1, 0)})
                self.assertEqual(re.findall(r"data-lane='(\w+)'", page), LANES)
                queue = section(page, '<section id="priority-queue">')
                self.assertEqual(re.findall(r"data-lane='(\w+)'", queue), LANES[:4])
                for finished in ("P-030", "P-031", "P-038"):
                    self.assertNotIn(f">{finished}<", queue)
                closed = section(page, "<section id='closed-lanes'>")
                for finished in ("P-030", "P-031", "P-038"):
                    self.assertIn(f">{finished}<", closed)
                self.assertIn(">P-024<", section(page, "id='lane-unlikely'", "</table>"))

    def test_report_without_findings_keeps_every_lane_and_tile(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = []
        _, page = self.render(data)
        self.assertIn(render.report.LABELS["en"]["no_open"], section(page, '<section id="priority-queue">'))
        closed = section(page, "<section id='closed-lanes'>")
        self.assertEqual(closed.count(render.report.LABELS["en"]["cx_lane_empty"]), 2)
        self.assertEqual(len(re.findall(r"data-severity='", page)), 4)

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
        self.assertEqual(page.locator("[data-lane='unlikely'] .cx-card").count(), 1)
        self.assertEqual(page.locator("[data-lane='closed'] .cx-card").count(), 2)
        self.assertEqual(page.locator(".cx-card[aria-pressed='true']").get_attribute("data-id"), "P-001")
        page.locator(".cx-card[data-id='P-030']").click()
        insp = page.locator("[data-cx='inspector']")
        self.assertIn("P-030", insp.inner_text())
        heads = insp.locator("h4").evaluate_all("els => els.map(e => e.firstChild.textContent)")
        self.assertEqual(heads, [labels["cx_where_h"], labels["cx_evidence_h"], labels["cx_fix_h"]])
        page.evaluate("document.addEventListener('copy', e => { window.copied = e.target.value; })")
        insp.get_by_role("button", name=labels["cx_copy"], exact=True).click()
        insp.get_by_role("button", name=labels["copied"], exact=True).wait_for()
        self.assertTrue(page.evaluate("window.copied").startswith("## P-030"))
        self.assertEqual(page.locator("[data-cx='readout'] dd").all_inner_texts(), ["35", "2", "1"])
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
