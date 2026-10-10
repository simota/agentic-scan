"""Report and dashboard structure: sections, tables, fallbacks and language labels."""
import json
import tempfile
import unittest
from pathlib import Path

from support import complete_doc, finding, findings, render, run_main


class ReportLayoutTests(unittest.TestCase):
    def test_index_excluded_section_method_and_budget_links(self):
        doc = complete_doc()
        doc["meta"]["method"] = "Static review"
        doc["findings"][0]["budget"] = "B-01"
        doc["findings"].append(finding("P-003", "High", budget="B-01", validation={
            "verdict": "NotApplicable", "method": "static", "evidence": "x.py:3"}))
        report = render.render_markdown(doc, "en")
        self.assertIn("| Method | Static review |", report)
        self.assertIn("| ID | Severity | Confidence | Verdict | Title | Location |", report)
        self.assertIn("| P-003 | High | Confirmed | NotApplicable |", report)
        findings_part, excluded_part = report.split("## Excluded findings")
        self.assertNotIn("### P-003", findings_part)
        self.assertIn("### P-003 [NotApplicable] ", excluded_part)
        self.assertNotIn("**status:**", excluded_part.split("## Performance budgets")[0])
        budget = next(line for line in report.splitlines() if line.startswith("| B-01 |"))
        self.assertTrue(budget.endswith(" | P-001 |"))
        html = render.render_html(doc, "en")
        self.assertIn("<td>P-001</td>", html)
        self.assertEqual(html.count("<dt>status</dt>"), 2)

    def test_report_lists_every_perspective_in_canonical_order(self):
        doc = complete_doc()
        doc["perspectives"] = list(reversed(doc["perspectives"][1:]))
        report = render.render_markdown(doc, "en")
        rows = [line.split(" | ")[0][2:] for line in report.splitlines()
                if line.startswith("| ") and line.split(" | ")[0][2:] in findings.PERSPECTIVES]
        self.assertEqual(rows, list(findings.PERSPECTIVES))
        self.assertIn("| Database access | — |  |", report)

    def test_dashboard_perspective_table_has_headers_and_no_blank_evidence(self):
        doc = complete_doc()
        doc["findings"][1]["validation"] = {"verdict": "Likely", "method": "static"}
        html = render.render_html(doc, "ja")
        self.assertIn("<th scope='col'>状態</th><th scope='col'>メモ</th>", html)
        self.assertEqual(html.count("<dt>evidence</dt>") + html.count("<dt>根拠</dt>"), 1)

    def test_blank_reference_titles_and_commits_fall_back_to_visible_text(self):
        doc = complete_doc()
        doc["meta"]["commit"] = ""
        doc["findings"][0]["references"] = [{"title": " ", "url": "https://example.test/doc"}]
        report = render.render_markdown(doc, "en")
        html = render.render_html(doc, "en")
        self.assertIn("| Revision | UNKNOWN |", report)
        self.assertIn("[https&#58;//example.test/doc](<https://example.test/doc>)", report)
        self.assertIn(" · UNKNOWN · ", html)
        self.assertIn(">https://example.test/doc</a>", html)

    def test_report_labels_follow_the_language_and_name_the_perspective(self):
        doc = complete_doc()
        report = render.render_markdown(doc, "ja")
        self.assertIn("| 範囲 | repo root |", report)
        self.assertIn("| 観点 | 状態 | メモ |", report)
        self.assertNotIn("| Scope |", report)
        self.assertIn("- **観点:** Database access (DB1)", report)
        del doc["findings"][0]["step"]
        report = render.render_markdown(doc, "en")
        self.assertIn("| Scope | repo root |", report)
        self.assertIn("- **perspective:** Database access\n", report)
        self.assertIn("· Database access (DB1)</span>", render.render_html(complete_doc(), "en"))


class AllExcludedLayoutTests(unittest.TestCase):
    def test_an_all_excluded_record_does_not_say_none_under_its_index(self):
        doc = complete_doc()
        for f in doc["findings"]:
            f["validation"] = {"verdict": "NotApplicable", "method": "static", "evidence": "a.py:1"}
        doc["findings"][0]["location"] = ["a.py:3", "c.py:4"]
        report = render.render_markdown(doc, "en")
        findings_part = report.split("## Findings")[1].split("## Excluded findings")[0]
        self.assertNotIn("None.", findings_part)
        self.assertIn("| a.py:3 (+1) |", findings_part)


class LanguageNoteTests(unittest.TestCase):
    def test_overriding_the_record_language_is_noted(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "findings.json"
            source.write_text(json.dumps(complete_doc()), encoding="utf-8")
            code, _, err = run_main(render.main, source, "--out", directory, "--lang", "ja")
            self.assertEqual(code, 0)
            self.assertEqual(err, "render: note: labels in ja, but the record's text is in en\n")
            code, _, err = run_main(render.main, source, "--out", directory, "--lang", "en")
            self.assertEqual((code, err), (0, ""))



class BlankOptionalFieldTests(unittest.TestCase):
    def test_blank_optional_fields_and_commit_are_not_rendered_blank(self):
        doc = complete_doc()
        doc["meta"]["commit"] = "   "
        doc["findings"][0].update(contrast="", budget=" ")
        report, html = render.render_markdown(doc, "en"), render.render_html(doc, "en")
        self.assertIn("| Revision | UNKNOWN |", report)
        self.assertIn(" · UNKNOWN · ", html)
        self.assertNotIn("**contrast:**", report)
        self.assertNotIn("**budget:**", report)
        self.assertNotIn("<dt>contrast</dt>", html)

if __name__ == "__main__":
    unittest.main()
