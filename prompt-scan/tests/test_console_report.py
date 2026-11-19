"""console-triage layer: lane assignment, normalized model, and static/interactive views.

Lanes follow existing rules only: excluded verdicts, then closed statuses, then
dashboard_model()'s action(). Browser tests are opt-in (PROMPT_SCAN_BROWSER_TEST=1,
CHROME=<executable>).
"""
from html.parser import HTMLParser
import json
import os
import re
import unittest

from helpers import clone, record, render, sample

BROWSER = os.environ.get("PROMPT_SCAN_BROWSER_TEST") == "1"
VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}


class Node:
    def __init__(self, tag, attrs=None):
        self.tag = tag
        self.attrs = dict(attrs or ())
        self.children = []

    def text(self):
        return "".join(c if isinstance(c, str) else c.text() for c in self.children)

    def find_all(self, tag=None, **attrs):
        out = []
        for c in self.children:
            if isinstance(c, Node):
                if (tag is None or c.tag == tag) and all(c.attrs.get(k) == v for k, v in attrs.items()):
                    out.append(c)
                out.extend(c.find_all(tag, **attrs))
        return out

    def find(self, tag=None, **attrs):
        matches = self.find_all(tag, **attrs)
        return matches[0] if matches else None


class TreeParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = Node("document")
        self.stack = [self.root]

    def handle_starttag(self, tag, attrs):
        node = Node(tag, attrs)
        self.stack[-1].children.append(node)
        if tag not in VOID_TAGS:
            self.stack.append(node)

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        self.stack[-1].children.append(data)


def parse_html(text):
    parser = TreeParser()
    parser.feed(text)
    return parser.root


def make_finding(fid, *, kind="defect", severity="High", confidence="Confirmed", status="Open",
                 verdict="Valid", evidence="Verified in review.", method="static trace"):
    return {
        "id": fid, "kind": kind, "severity": severity, "confidence": confidence,
        "category": "Variables and assembly", "title": f"Finding {fid}",
        "location": f"app/llm/{fid.lower()}.py:10", "prompt": "P-01",
        "symptom": f"Symptom for {fid}", "cause": f"Cause for {fid}",
        "impact": f"Impact for {fid}", "fix": f"Fix direction for {fid}",
        "validation": {"verdict": verdict, "evidence": evidence, "method": method},
        "status": status,
    }


class ConsoleReportTests(unittest.TestCase):
    def lane_report(self):
        data = clone(sample("en"))
        data["eval_runs"] = []
        data["findings"] = [
            make_finding("F-001", severity="High", confidence="Confirmed", status="Open", verdict="Valid"),
            make_finding("F-002", kind="improvement", severity="Medium", confidence="Model-dependent",
                         status="Open", verdict="Likely"),
            make_finding("F-003", severity="Low", confidence="Confirmed", status="Fixed", verdict="Valid"),
            make_finding("F-004", severity="Low", confidence="Suspected", status="Accepted",
                         verdict="Unverified", evidence=""),
            make_finding("F-005", severity="High", confidence="Confirmed", status="Open", verdict="FalsePositive"),
            make_finding("F-006", severity="Info", confidence="Confirmed", status="Fixed", verdict="NotApplicable"),
            make_finding("L-001", severity="Info", confidence="Suspected", status="Open",
                         verdict="Unverified", evidence="", method="inventory.py lint"),
        ]
        record.validate_data(data)
        return data

    def render_pages(self, data, lang="en"):
        L = render.LABELS[lang]
        dash = render.render_dashboard(data, L, lang, {})
        rep = render.render_report_html(data, L, lang, {})
        return parse_html(dash), parse_html(rep), dash, rep

    def payload(self, dashboard_text):
        match = re.search(r'<script id="data" type="application/json">(.*?)</script>', dashboard_text, re.S)
        self.assertIsNotNone(match)
        return json.loads(match.group(1))

    def test_lanes_follow_existing_action_and_exclusion_rules(self):
        data = self.lane_report()
        model = render.dashboard_model(data)
        cm = render.console_model(data, model, render.LABELS["en"])
        lanes = {f["id"]: f["lane"] for f in cm["findings"]}
        self.assertEqual(lanes, {
            "F-001": "fix_now", "F-002": "verify_first", "L-001": "verify_first",
            "F-003": "closed", "F-004": "closed",
            "F-005": "excluded", "F-006": "excluded",
        })
        self.assertEqual({item["id"]: item["action"] for item in model["queue"]},
                         {k: v for k, v in lanes.items() if v in ("fix_now", "verify_first")})
        self.assertEqual([lane["key"] for lane in cm["lanes"]], ["fix_now", "verify_first", "closed", "excluded"])
        self.assertEqual(cm["counts"], {"open": 3, "closed": 2, "excluded": 2, "total": 7})

    def test_console_model_is_embedded_and_inspector_fields_keep_their_order(self):
        data = self.lane_report()
        dashboard, _, dash_text, _ = self.render_pages(data, "en")
        payload = self.payload(dash_text)
        cm = payload["console"]
        ready = next(f for f in cm["findings"] if f["id"] == "F-001")
        self.assertEqual([row["label"] for row in ready["where"]][:1], ["Location"])
        self.assertEqual(ready["evidence"]["text"], "Verified in review.")
        self.assertEqual(ready["fix"], "Fix direction for F-001")
        self.assertEqual(ready["anchor"], payload["anchors"]["F-001"])
        self.assertEqual(ready["tags"], ["Defect", "Confirmed"])
        imp = next(f for f in cm["findings"] if f["id"] == "F-002")
        self.assertEqual(imp["tags"], ["Improvement", "Model-dependent"])
        fp = next(f for f in cm["findings"] if f["id"] == "F-005")
        self.assertTrue(fp["excluded"] and not fp["open"])
        self.assertEqual(fp["status_label"], render.LABELS["en"]["excluded_short"])
        self.assertTrue(all(p["tone"] == "muted" and not p["on"] for p in cm["perspectives"]))
        verdicts = {v["key"]: v["excluded"] for v in cm["verdicts"]}
        self.assertEqual({k for k, v in verdicts.items() if v}, {"FalsePositive", "NotApplicable"})
        for slot in ("ident", "readout", "severity", "verdicts", "perspectives", "board", "inspector"):
            self.assertIsNotNone(dashboard.find(**{"data-cx": slot}), slot)
        # Only the band draws <h1>; no static <h1> remains in the dashboard template.
        self.assertEqual(dashboard.find_all("h1"), [])
        # Still exactly the data script and one page script, with the console renderer inlined.
        scripts = [s for s in dashboard.find_all("script") if s.attrs.get("id") != "data"]
        self.assertEqual(len(scripts), 1)
        self.assertIn("AgenticConsole.mount(D.console", scripts[0].text())
        self.assertNotIn(".innerHTML", scripts[0].text())

    def test_report_has_band_tiles_and_four_lanes_in_order(self):
        data = self.lane_report()
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                _, report, _, _ = self.render_pages(data, lang)
                self.assertIn("cx-doc", report.find("html").attrs.get("class", ""))
                self.assertEqual(report.find_all("script"), [])
                band = report.find("header", **{"class": "cx-band"})
                self.assertIsNotNone(band)
                self.assertEqual([dd.text() for dd in band.find_all("dd")], ["3", "2", "2"])
                tiles = {t.attrs["data-severity"]: t for t in report.find_all() if "data-severity" in t.attrs}
                self.assertEqual(list(tiles), ["High", "Medium", "Low", "Info"])
                cells = {k: [i.attrs.get("class") for i in t.find_all("i")] for k, t in tiles.items()}
                self.assertEqual(cells, {"High": ["cx-on"], "Medium": ["cx-on"], "Low": [None, None], "Info": ["cx-on"]})
                triage = report.find(id="triage-lanes")
                lanes = [e.attrs["data-lane"] for e in triage.find_all() if "data-lane" in e.attrs]
                self.assertEqual(lanes, ["fix_now", "verify_first", "closed", "excluded"])
                text = {key: report.find(id="lane-" + key).text() for key in lanes}
                self.assertIn("F-001", text["fix_now"])
                self.assertIn("F-002", text["verify_first"])
                self.assertIn("F-003", text["closed"])
                self.assertIn("F-006", text["excluded"])
                pq_text = report.find(id="priority-queue").text()
                self.assertNotIn("F-003", pq_text)
                self.assertNotIn("F-005", pq_text)

    def test_empty_report_still_renders_every_lane_and_tile(self):
        data = clone(sample("en"))
        data["findings"] = []
        data["eval_runs"] = []
        _, report, _, _ = self.render_pages(data, "en")
        for key in ("closed", "excluded"):
            self.assertIn(render.LABELS["en"]["cx_lane_empty"], report.find(id="lane-" + key).text())
        self.assertEqual(len([e for e in report.find_all() if "data-severity" in e.attrs]), 4)

    def _start_browser(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            self.skipTest(f"playwright not installed: {exc}")
        pw = sync_playwright().start()
        self.addCleanup(pw.stop)
        launch_kwargs = {"headless": True}
        if os.environ.get("CHROME"):
            launch_kwargs["executable_path"] = os.environ["CHROME"]
        browser = pw.chromium.launch(**launch_kwargs)
        self.addCleanup(browser.close)
        return browser.new_page()

    @unittest.skipUnless(BROWSER, "opt-in Chromium interaction test")
    def test_browser_board_selects_into_inspector_and_copies(self):
        page = self._start_browser()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        labels = {**render.LABELS["en"], **render.DASH_LABELS["en"]}
        page.goto("about:blank")
        page.set_content(render.render_dashboard(self.lane_report(), render.LABELS["en"], "en", {}),
                         wait_until="domcontentloaded")
        self.assertEqual(page.locator("[data-lane='fix_now'] .cx-card").count(), 1)
        self.assertEqual(page.locator("[data-lane='excluded'] .cx-card").count(), 2)
        self.assertEqual(page.locator(".cx-card[aria-pressed='true']").get_attribute("data-id"), "F-001")
        page.locator(".cx-card[data-id='F-003']").click()
        insp = page.locator("[data-cx='inspector']")
        self.assertIn("F-003", insp.inner_text())
        heads = insp.locator("h4").evaluate_all("els => els.map(e => e.firstChild.textContent)")
        self.assertEqual(heads, [labels["cx_where_h"], labels["cx_evidence_h"], labels["cx_fix_h"]])
        page.evaluate("document.addEventListener('copy', e => { window.copied = e.target.value; })")
        insp.get_by_role("button", name=labels["cx_copy"], exact=True).click()
        insp.get_by_role("button", name=labels["copied"], exact=True).wait_for()
        self.assertTrue(page.evaluate("window.copied").startswith("## F-003"))
        self.assertEqual(page.locator("[data-cx='readout'] dd").all_inner_texts(), ["3", "2", "2"])
        self.assertEqual(errors, [])

    @unittest.skipUnless(BROWSER, "opt-in Chromium mobile test")
    def test_browser_console_fits_360px_without_horizontal_scroll(self):
        page = self._start_browser()
        page.set_viewport_size({"width": 360, "height": 800})
        page.goto("about:blank")
        page.set_content(render.render_dashboard(self.lane_report(), render.LABELS["ja"], "ja", {}),
                         wait_until="domcontentloaded")
        self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), 360)


if __name__ == "__main__":
    unittest.main()
