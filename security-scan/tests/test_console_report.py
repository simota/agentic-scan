"""console-triage layer: lane assignment, the normalized model, and the new panels.

Lanes come from the existing rules only: an excluded verdict, then a closed
status, then action_kind() through the report queue. The browser tests are
opt-in like the others (SECURITY_SCAN_BROWSER_TEST=1, CHROME=<executable>).
"""
import os
import unittest

import test_report_outputs as base

BROWSER = os.environ.get("SECURITY_SCAN_BROWSER_TEST") == "1"


class ConsoleReportTests(unittest.TestCase):
    # The report fixtures and browser setup of test_report_outputs, without its tests.
    setUpClass = base.ReportOutputTests.__dict__["setUpClass"]
    setUp = base.ReportOutputTests.setUp
    finding, report, with_verification = base.ReportOutputTests.finding, base.ReportOutputTests.report, base.ReportOutputTests.with_verification
    output, payload, start_browser = base.ReportOutputTests.output, base.ReportOutputTests.payload, base.ReportOutputTests.start_browser

    def lane_report(self):
        data = self.report([
            self.finding("F-ready", verdict="Valid"),
            self.finding("F-check", severity="Medium", verdict="Likely"),
            self.finding("F-fixed", severity="Low", status="Fixed", verdict="Valid"),
            self.finding("F-accepted", severity="Low", status="Accepted", verdict="Unverified"),
            self.finding("F-fp", verdict="FalsePositive"),
            self.finding("F-na", severity="Info", status="Fixed", verdict="NotApplicable"),
            self.finding("D-001", severity="Info"),
        ], perspectives=[{"name": "Synthetic review", "result": "recorded"},
                         {"name": "Untouched area", "result": "not in scope"}])
        return self.with_verification(data, {"F-ready"})

    def test_lanes_follow_existing_action_and_exclusion_rules(self):
        data = self.lane_report()
        model = self.renderer.report_model(data)
        cm = self.renderer.console_model(data, model, self.renderer.LABELS["en"])
        lanes = {f["id"]: f["lane"] for f in cm["findings"]}
        self.assertEqual(lanes, {"F-ready": "fix_now", "F-check": "verify_first", "D-001": "verify_first",
                                 "F-fixed": "closed", "F-accepted": "closed",
                                 "F-fp": "excluded", "F-na": "excluded"})
        # Open lanes are exactly the report queue's actions; nothing is re-derived.
        self.assertEqual({item["finding"]["id"]: item["action"] for item in model["queue"]},
                         {k: v for k, v in lanes.items() if v in ("fix_now", "verify_first")})
        for f in data["findings"]:
            if f["status"] == "Open" and f["verdict"] not in self.renderer.EXCLUDED:
                self.assertEqual(lanes[f["id"]], self.renderer.action_kind(f, model["verification"][f["id"]]))
        self.assertEqual([lane["key"] for lane in cm["lanes"]], ["fix_now", "verify_first", "closed", "excluded"])
        self.assertEqual(cm["counts"], {"open": 3, "closed": 2, "excluded": 2, "total": 7})

    def test_console_model_is_embedded_and_inspector_fields_keep_their_order(self):
        data = self.lane_report()
        dashboard, _ = self.output(data)
        cm = self.payload(dashboard)["console"]
        ready = next(f for f in cm["findings"] if f["id"] == "F-ready")
        self.assertEqual([row["label"] for row in ready["where"]][:1], ["Location"])
        self.assertEqual(ready["evidence"]["text"], "Synthetic evidence for Valid")
        self.assertEqual(ready["fix"], "Synthetic fix direction")
        self.assertEqual(ready["anchor"], self.payload(dashboard)["anchors"]["F-ready"])
        fp = next(f for f in cm["findings"] if f["id"] == "F-fp")
        self.assertTrue(fp["excluded"] and not fp["open"])
        self.assertEqual(fp["status_label"], self.renderer.LABELS["en"]["excluded_short"])
        lamps = {p["name"]: (p["tone"], p["on"]) for p in cm["perspectives"]}
        self.assertEqual(lamps, {"Synthetic review": ("high", True), "Untouched area": ("muted", False)})
        verdicts = {v["key"]: v["excluded"] for v in cm["verdicts"]}
        self.assertEqual({k for k, v in verdicts.items() if v}, {"FalsePositive", "NotApplicable"})
        for slot in ("ident", "readout", "severity", "verdicts", "perspectives", "board", "inspector"):
            self.assertTrue(dashboard.find(**{"data-cx": slot}), slot)
        # Still exactly the data script and one page script, with the renderer inside it.
        scripts = [s for s in dashboard.find_all("script") if s.attrs.get("id") != "data"]
        self.assertEqual(len(scripts), 1)
        self.assertIn("AgenticConsole.mount(D.console", scripts[0].text())
        self.assertNotIn(".innerHTML", scripts[0].text())

    def test_assessment_has_band_tiles_and_four_lanes_in_order(self):
        data = self.lane_report()
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                _, assessment = self.output(data, lang)
                self.assertIn("cx-doc", assessment.find("html").attrs["class"])
                self.assertFalse(assessment.find_all("script"))
                band = assessment.find("header", **{"class": "cx-band"})
                self.assertEqual([dd.text() for dd in band.find_all("dd")], ["3", "2", "2"])
                tiles = {t.attrs["data-severity"]: t for t in assessment.find_all() if "data-severity" in t.attrs}
                self.assertEqual(list(tiles), ["High", "Medium", "Low", "Info"])
                # One cell per included record (excluded F-fp / F-na are not counted); filled = open.
                cells = {k: [i.attrs.get("class") for i in t.find_all("i")] for k, t in tiles.items()}
                self.assertEqual(cells, {"High": ["cx-on"], "Medium": ["cx-on"], "Low": [None, None], "Info": ["cx-on"]})
                lanes = [e.attrs["data-lane"] for e in assessment.find(id="triage-lanes").find_all()
                         if "data-lane" in e.attrs]
                self.assertEqual(lanes, ["fix_now", "verify_first", "closed", "excluded"])
                text = {key: assessment.find(id="lane-" + key).text() for key in lanes}
                self.assertIn("F-ready", text["fix_now"])
                self.assertIn("F-check", text["verify_first"])
                self.assertIn("F-fixed", text["closed"])
                self.assertIn("F-na", text["excluded"])
                self.assertNotIn("F-fixed", assessment.find(id="priority-queue").text())

    def test_empty_report_still_renders_every_lane_and_tile(self):
        _, assessment = self.output(self.report([]))
        for key in ("closed", "excluded"):
            self.assertIn(self.renderer.LABELS["en"]["cx_lane_empty"], assessment.find(id="lane-" + key).text())
        self.assertEqual(len([e for e in assessment.find_all() if "data-severity" in e.attrs]), 4)

    @unittest.skipUnless(BROWSER, "opt-in Chromium interaction test")
    def test_browser_board_selects_into_inspector_and_copies(self):
        page = self.start_browser()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        labels = self.renderer.LABELS["en"]
        page.goto("about:blank")
        page.set_content(self.renderer.render_dashboard(self.lane_report(), labels, "en"), wait_until="domcontentloaded")
        self.assertEqual(page.locator("[data-lane='fix_now'] .cx-card").count(), 1)
        self.assertEqual(page.locator("[data-lane='excluded'] .cx-card").count(), 2)
        self.assertEqual(page.locator(".cx-card[aria-pressed='true']").get_attribute("data-id"), "F-ready")
        page.locator(".cx-card[data-id='F-fixed']").click()
        insp = page.locator("[data-cx='inspector']")
        self.assertIn("F-fixed", insp.inner_text())
        heads = insp.locator("h4").evaluate_all("els => els.map(e => e.firstChild.textContent)")
        self.assertEqual(heads, [labels["cx_where_h"], labels["cx_evidence_h"], labels["cx_fix_h"]])
        page.evaluate("document.addEventListener('copy', e => { window.copied = e.target.value; })")
        insp.get_by_role("button", name=labels["cx_copy"], exact=True).click()
        insp.get_by_role("button", name=labels["copied"], exact=True).wait_for()
        self.assertTrue(page.evaluate("window.copied").startswith("## F-fixed"))
        self.assertEqual(page.locator("[data-cx='readout'] dd").all_inner_texts(), ["3", "2", "2"])
        self.assertEqual(errors, [])

    @unittest.skipUnless(BROWSER, "opt-in Chromium mobile test")
    def test_browser_console_fits_360px_without_horizontal_scroll(self):
        page = self.start_browser()
        page.set_viewport_size({"width": 360, "height": 800})
        page.goto("about:blank")
        page.set_content(self.renderer.render_dashboard(self.lane_report(), self.renderer.LABELS["ja"], "ja"),
                         wait_until="domcontentloaded")
        self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), 360)

if __name__ == "__main__":
    unittest.main()
