"""console-triage layer: lane assignment, normalized model, CSP, and dashboard slots.

Lanes come from the existing rules only: excluded verdicts (FalsePositive /
NotApplicable), then closed statuses (Fixed / Accepted), then Open in the
recorded order. Browser tests are opt-in (PRIVACY_SCAN_BROWSER_TEST=1,
CHROME=<executable>).
"""
from base64 import b64encode
from hashlib import sha256
import json
import os
import re
import unittest

from test_privacy_scan import complete_doc, finding, findings, render

BROWSER = os.environ.get("PRIVACY_SCAN_BROWSER_TEST") == "1"


def extract_payload(html):
    match = re.search(r"<script id='data' type='application/json'>(.*?)</script>", html, re.S)
    assert match is not None, "missing embedded data script"
    return json.loads(match.group(1))


class ConsoleReportTests(unittest.TestCase):
    def lane_doc(self):
        doc = complete_doc()
        doc["findings"] = [
            finding("PV-001", "High", category="Logs, telemetry and errors",
                    validation={"verdict": "Valid", "method": "static", "evidence": "api/app.py:22"}),
            finding("PV-002", "Medium", category="Client-side tracking", status="Open",
                    validation={"verdict": "Likely", "method": "static", "evidence": "web/main.tsx:9"}),
            finding("PV-003", "Low", category="Retention and deletion", status="Fixed",
                    validation={"verdict": "Valid", "method": "static", "evidence": "close.py:31"}),
            finding("PV-004", "Low", category="Storage protection", status="Accepted",
                    validation={"verdict": "Unverified", "method": "static", "evidence": "store.py:8"}),
            finding("PV-005", "High", category="Third-party sharing", status="Open",
                    validation={"verdict": "FalsePositive", "method": "static", "evidence": "scrubbed"}),
            finding("PV-006", "Info", category="Data subject rights", status="Fixed",
                    validation={"verdict": "NotApplicable", "method": "static", "evidence": "n/a"}),
        ]
        return doc

    def test_lanes_follow_existing_status_and_exclusion_rules(self):
        doc = self.lane_doc()
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                cm = render.console_model(doc, lang)
                lanes = {f["id"]: f["lane"] for f in cm["findings"]}
                self.assertEqual(lanes, {
                    "PV-001": "open", "PV-002": "open",
                    "PV-003": "closed", "PV-004": "closed",
                    "PV-005": "excluded", "PV-006": "excluded",
                })
                for rec in doc["findings"]:
                    expected = ("excluded" if findings.excluded(rec)
                                else "closed" if rec.get("status", "Open") != "Open"
                                else "open")
                    self.assertEqual(lanes[rec["id"]], expected)
                self.assertEqual([f["id"] for f in cm["findings"]], [f["id"] for f in doc["findings"]])
                self.assertEqual([lane["key"] for lane in cm["lanes"]], ["open", "closed", "excluded"])
                self.assertEqual(cm["counts"], {"open": 2, "closed": 2, "excluded": 2, "total": 6})
                if lang == "ja":
                    self.assertEqual(cm["lanes"][0]["label"], "OPEN / 未解決")

    def test_console_model_is_embedded_slots_exist_and_csp_matches_concatenated_assets(self):
        doc = self.lane_doc()
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                html = render.render_html(doc, lang)
                self.assertIn("<html lang='" + lang + "' class='app-shell'>", html)
                cm = extract_payload(html)["console"]
                first = next(f for f in cm["findings"] if f["id"] == "PV-001")
                self.assertEqual([row["label"] for row in first["where"]][:1], [render.LABELS[lang]["location"]])
                self.assertEqual(first["evidence"]["text"], "api/app.py:22")
                self.assertEqual(first["fix"], "Turn body capture off")
                self.assertEqual(first["anchor"], "finding-PV-001")
                self.assertIn("id='finding-PV-001'", html)

                fp = next(f for f in cm["findings"] if f["id"] == "PV-005")
                self.assertTrue(fp["excluded"] and not fp["open"])
                self.assertEqual(fp["status_label"], render.LABELS[lang]["excluded"])

                lamps = {p["name"]: (p["tone"], p["on"]) for p in cm["perspectives"]}
                self.assertEqual(lamps[render.perspective_name(render.LABELS[lang], "Logs, telemetry and errors")],
                                 ("high", True))
                self.assertEqual(lamps[render.perspective_name(render.LABELS[lang], "Retention and deletion")],
                                 ("ink", False))
                self.assertEqual(lamps[render.perspective_name(render.LABELS[lang], "Third-party sharing")],
                                 ("accent", False))
                self.assertEqual(lamps[render.perspective_name(render.LABELS[lang], "Location and transfers")],
                                 ("muted", False))

                verdicts = {v["key"]: v["excluded"] for v in cm["verdicts"]}
                self.assertEqual({k for k, v in verdicts.items() if v}, {"FalsePositive", "NotApplicable"})

                for slot in ("ident", "readout", "severity", "verdicts", "perspectives", "board", "inspector"):
                    self.assertIn(f"data-cx='{slot}'", html)

                scripts = re.findall(r"<script(?:\s[^>]*)?>(.*?)</script>", html, re.S)
                self.assertEqual(len(scripts), 2)
                page_script = re.search(r"<script>(.*?)</script>", html, re.S).group(1)
                self.assertIn("AgenticConsole.mount(D.console", page_script)
                self.assertNotIn(".innerHTML", page_script)

                policy = re.search(r"<meta http-equiv='Content-Security-Policy' content=\"([^\"]+)\">", html).group(1)
                style = re.search(r"<style>(.*?)</style>", html, re.S).group(1)
                directives = dict(d.strip().split(" ", 1) for d in policy.split(";"))
                style_hash = "'sha256-" + b64encode(sha256(style.encode("utf-8")).digest()).decode("ascii") + "'"
                script_hash = "'sha256-" + b64encode(sha256(page_script.encode("utf-8")).digest()).decode("ascii") + "'"
                self.assertIn(style_hash, directives["style-src"].split())
                self.assertIn(script_hash, directives["script-src"].split())

    def test_empty_report_still_embeds_all_lanes_and_severities(self):
        doc = complete_doc()
        doc["findings"] = []
        html = render.render_html(doc, "en")
        cm = extract_payload(html)["console"]
        self.assertEqual(cm["counts"], {"open": 0, "closed": 0, "excluded": 0, "total": 0})
        self.assertEqual([lane["key"] for lane in cm["lanes"]], ["open", "closed", "excluded"])
        self.assertEqual(cm["severities"], ["High", "Medium", "Low", "Info"])

    @unittest.skipUnless(BROWSER, "opt-in Chromium interaction test")
    def test_browser_board_selects_into_inspector_and_fits_360px(self):
        from playwright.sync_api import sync_playwright
        chrome = os.environ.get("CHROME")
        with sync_playwright() as p:
            browser = p.chromium.launch(executable_path=chrome) if chrome else p.chromium.launch()
            try:
                page = browser.new_page()
                errors = []
                page.on("pageerror", lambda err: errors.append(str(err)))
                labels = render.LABELS["en"]
                page.set_content(render.render_html(self.lane_doc(), "en"), wait_until="domcontentloaded")
                self.assertEqual(page.locator("[data-lane='open'] .cx-card").count(), 2)
                self.assertEqual(page.locator("[data-lane='closed'] .cx-card").count(), 2)
                self.assertEqual(page.locator("[data-lane='excluded'] .cx-card").count(), 2)
                self.assertEqual(page.locator(".cx-card[aria-pressed='true']").get_attribute("data-id"), "PV-001")
                page.locator(".cx-card[data-id='PV-003']").click()
                insp = page.locator("[data-cx='inspector']")
                self.assertIn("PV-003", insp.inner_text())
                heads = insp.locator("h4").evaluate_all("els => els.map(e => e.firstChild.textContent)")
                self.assertEqual(heads, [labels["cx_where_h"], labels["cx_evidence_h"], labels["cx_fix_h"]])
                self.assertEqual(insp.locator(".cx-copy").count(), 0)
                self.assertEqual(page.locator("[data-cx='readout'] dd").all_inner_texts(), ["2", "2", "2"])
                self.assertEqual(errors, [])

                page.set_viewport_size({"width": 360, "height": 800})
                page.set_content(render.render_html(self.lane_doc(), "ja"), wait_until="domcontentloaded")
                self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), 360)
            finally:
                browser.close()


if __name__ == "__main__":
    unittest.main()
