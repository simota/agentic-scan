"""Regression checks for verdicts visible before opening finding details."""
from html.parser import HTMLParser
import re
import unittest

from test_architecture_scan import complete_doc, finding, findings, render


class DashboardText(HTMLParser):
    """Collect the visible overview and each collapsed finding's label."""

    def __init__(self, source):
        super().__init__()
        self.overview = []
        self.summaries = []
        self.before_findings = True
        self.in_summary = False
        self.ignored = False
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        if tag in ("style", "script"):
            self.ignored = True
        elif tag == "details":
            self.before_findings = False
        elif tag == "summary":
            self.in_summary = True
            self.summaries.append([])

    def handle_endtag(self, tag):
        if tag in ("style", "script"):
            self.ignored = False
        elif tag == "summary":
            self.in_summary = False

    def handle_data(self, value):
        if not self.ignored:
            if self.before_findings:
                self.overview.append(value)
            if self.in_summary:
                self.summaries[-1].append(value)


class RenderVerdictTests(unittest.TestCase):
    def doc_with_verdicts(self, verdicts):
        doc = complete_doc()
        doc["findings"] = [
            finding(f"A-{i:03d}", "High", title=f"Finding {i}", validation={
                "verdict": verdict, "method": "static", "evidence": "worker/job.py:58",
            })
            for i, verdict in enumerate(verdicts, 1)
        ]
        findings.validate(doc, complete=True)
        return doc

    def assert_overview_counts(self, doc, expected, high, excluded):
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                markdown = render.render_markdown(doc, lang).split("\n## ", 1)[0]
                parsed = DashboardText(render.render_html(doc, lang))
                html = " ".join(parsed.overview)
                for overview in (markdown, html):
                    for verdict, count in expected.items():
                        self.assertRegex(overview, rf"\b{verdict}\s+{count}\b")
                    self.assertRegex(overview, rf"\bHigh\s+{high}\b")
                    self.assertRegex(overview, rf"{render.LABELS[lang]['excluded']}\s+{excluded}\b")

    def test_all_verdicts_are_counted_separately_from_active_severity(self):
        doc = self.doc_with_verdicts(findings.VERDICTS)
        self.assert_overview_counts(doc, {v: 1 for v in findings.VERDICTS}, high=4, excluded=2)

    def test_finding_headings_identify_verdicts_including_exclusions(self):
        doc = self.doc_with_verdicts(findings.VERDICTS)
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                markdown = render.render_markdown(doc, lang)
                headings = re.findall(r"^### (.+)$", markdown, re.MULTILINE)
                parsed = DashboardText(render.render_html(doc, lang))
                self.assertEqual(len(headings), len(findings.VERDICTS))
                self.assertEqual(len(parsed.summaries), len(findings.VERDICTS))
                for verdict, heading, summary in zip(findings.VERDICTS, headings, parsed.summaries):
                    self.assertIn(f"[{verdict}]", heading)
                    self.assertIn(verdict, " ".join(summary))

    def test_empty_run_has_zero_verdict_and_severity_counts(self):
        self.assert_overview_counts(self.doc_with_verdicts([]),
                                    {v: 0 for v in findings.VERDICTS}, high=0, excluded=0)

    def test_excluded_only_run_has_zero_active_severity_and_retains_verdicts(self):
        doc = self.doc_with_verdicts(findings.EXCLUDED)
        expected = {v: int(v in findings.EXCLUDED) for v in findings.VERDICTS}
        self.assert_overview_counts(doc, expected, high=0, excluded=2)


class RegisterOrderTests(unittest.TestCase):
    def test_excluded_findings_sort_after_the_rest_in_both_orders(self):
        # A ruled-out High never sorts between the findings to act on, as in
        # renumber's IDs and report.md, whichever order the register uses.
        doc = complete_doc()
        doc["findings"] = [
            finding("A-001", "Medium"), finding("A-002", "Low", status="Fixed"),
            finding("A-003", "High", validation={"verdict": "FalsePositive", "method": "static",
                                                 "evidence": "job.py:58 is guarded"})]
        findings.validate(doc, complete=True)
        dashboard = render.render_html(doc, "en")
        for key, expected in (("p", ["a-001", "a-002", "a-003"]),
                              ("s", ["a-001", "a-002", "a-003"])):
            with self.subTest(order=key):
                ranks = dict(re.findall(rf"id='finding-(a-[0-9]{{3}})'[^>]* data-{key}='([0-9]+)'",
                                        dashboard))
                self.assertEqual(sorted(ranks, key=lambda fid: int(ranks[fid])), expected)


if __name__ == "__main__":
    unittest.main()
