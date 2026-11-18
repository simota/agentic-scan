"""issues.py: one draft per finding, following templates/issue.<lang>.md."""
from copy import deepcopy
import os
from pathlib import Path
import re
import stat
import tempfile
import unittest

from support import SKILL, complete_doc, finding, issues, run_main, write_record

MEASUREMENT = {
    "environment": "local synthetic data",
    "before": {"command": "pytest -q tests/test_q.py", "result": "52 queries",
               "log": "```\nqueries=52"},
    "after": {"command": "pytest -q tests/test_q.py", "result": "3 queries", "log": "queries=3"},
}


def template_headings(lang):
    text = (SKILL / "templates" / f"issue.{lang}.md").read_text(encoding="utf-8")
    return re.findall(r"^## (.+)$", text, re.MULTILINE)


def headings(text):
    return re.findall(r"^## (.+)$", text, re.MULTILINE)


class Drafts(unittest.TestCase):
    def run_issues(self, doc, *args):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        record = write_record(Path(self.tmp.name) / "run", "findings.json", doc)
        self.out = Path(self.tmp.name) / "issues"
        return run_main(issues.main, record, "--out", self.out, *args)

    def test_every_open_included_finding_gets_one_private_draft(self):
        doc = complete_doc()
        doc["findings"].append(finding("P-003", "Low", status="Fixed"))
        doc["findings"].append(finding("P-004", "Low", status="Accepted"))
        doc["findings"].append(finding("P-005", "Medium", validation={
            "verdict": "FalsePositive", "method": "static", "evidence": "app/a.py:1"}))
        code, out, err = self.run_issues(doc)
        self.assertEqual(code, 0, err)
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), ["P-001.md", "P-002.md"])
        self.assertIn("[High] Order list loads items per order (P-001)", out)
        self.assertEqual(stat.S_IMODE((self.out / "P-001.md").stat().st_mode), 0o600)
        code, _, _ = self.run_issues(doc, "--include-accepted", "--min-severity", "Low")
        self.assertEqual(sorted(p.name for p in self.out.iterdir()),
                         ["P-001.md", "P-002.md", "P-004.md"])

    def test_sections_follow_the_template_in_both_languages(self):
        doc = complete_doc()
        doc["findings"][0].update(measurement=MEASUREMENT, contrast="GET /x keeps it",
                                  budget="B-01",
                                  references=[{"title": "Docs", "url": "https://example.org/d"}],
                                  confidence="Environment-dependent")
        doc["findings"][0]["validation"]["verdict"] = "Likely"
        for lang in ("en", "ja"):
            text = issues.render_issue(doc["findings"][0], doc, lang)
            self.assertEqual(headings(text), template_headings(lang), lang)
        minimal = issues.render_issue(doc["findings"][1], doc, "en")
        expected = [h for h in template_headings("en")
                    if h not in ("Measurement log", "References", "Open questions")]
        self.assertEqual(headings(minimal), expected)

    def test_draft_content_comes_from_the_record_and_stays_inert(self):
        doc = complete_doc()
        f = doc["findings"][0]
        f.update(title="Rows | <img src=x> [x](https://evil.example) @owner",
                 location=["app/a|b.py:3", "app/c.py:4"], budget="B-01",
                 request="1. Seed N=100 rows. 2. GET /api/orders", measurement=MEASUREMENT)
        doc["decisions"] = ["Confirm max rows (P-001)", "Unrelated (P-0011)"]
        text = issues.render_issue(f, doc, "en")
        self.assertNotIn("<img", text)
        self.assertNotIn("](https://", text)
        self.assertNotIn("@owner", text)
        self.assertIn("`app/a\\|b.py:3`<br>`app/c.py:4`", text)
        self.assertIn("- **Violated budget:** B-01 — constant queries", text)
        self.assertIn("1\\. Seed N=100 rows.\n\n2\\. GET /api/orders", text)
        self.assertIn("Confirm max rows (P-001)", text)
        self.assertNotIn("Unrelated", text)
        self.assertIn("````text\n$ pytest -q tests/test_q.py\n```\nqueries=52\n````", text)
        self.assertIn("| Assessed revision | UNKNOWN |", text)

    def test_open_questions_list_each_line_naming_the_id_once_in_record_order(self):
        doc = complete_doc()
        doc["decisions"] = ["P-001 and again P-001", "xP-001 glued", "P-0011 longer",
                            "（P-001）全角", "P-002 only"]
        doc["limitations"] = ["P-001: not measured", "P-001 and again P-001"]
        t = issues.LABELS["en"]
        expected = ["P-001 and again P-001", "（P-001）全角", "P-001: not measured",
                    "P-001 and again P-001"]
        self.assertEqual(issues.open_questions(doc["findings"][0], doc, t), expected)
        # One index serves every draft of the record and gives the same answers.
        index = issues.record_index(doc)
        self.assertEqual(issues.open_questions(doc["findings"][0], doc, t, index), expected)
        self.assertEqual(issues.render_issue(doc["findings"][1], doc, "en", index),
                         issues.render_issue(doc["findings"][1], doc, "en"))
        self.assertIn("- P-002 only", issues.render_issue(doc["findings"][1], doc, "en", index))

    def test_selected_ids_and_refusals(self):
        doc = complete_doc()
        doc["findings"].append(finding("P-003", "Low", validation={
            "verdict": "NotApplicable", "method": "static", "evidence": "app/a.py:1"}))
        code, _, err = self.run_issues(doc, "--id", "P-002")
        self.assertEqual((code, [p.name for p in self.out.iterdir()]), (0, ["P-002.md"]), err)
        for ident, message in (("P-009", "no such finding"), ("P-003", "NotApplicable")):
            code, _, err = self.run_issues(doc, "--id", ident)
            self.assertEqual(code, 2)
            self.assertIn(message, err)
            self.assertFalse(self.out.exists())

    def test_existing_drafts_are_kept_without_force(self):
        doc = complete_doc()
        self.run_issues(doc)
        record = Path(self.tmp.name) / "run" / "findings.json"
        (self.out / "P-001.md").write_text("edited by hand", encoding="utf-8")
        code, _, err = run_main(issues.main, record, "--out", self.out)
        self.assertEqual(code, 2)
        self.assertIn("--force", err)
        self.assertEqual((self.out / "P-001.md").read_text(encoding="utf-8"), "edited by hand")
        code, _, _ = run_main(issues.main, record, "--out", self.out, "--force")
        self.assertEqual(code, 0)
        self.assertIn("## Summary", (self.out / "P-001.md").read_text(encoding="utf-8"))

    def test_the_run_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            record = write_record(directory, "findings.json", complete_doc())
            before = sorted(os.listdir(directory))
            code, _, err = run_main(issues.main, record, "--out", directory)
            self.assertEqual(code, 2)
            self.assertIn("three run outputs", err)
            self.assertEqual(sorted(os.listdir(directory)), before)

    def test_nothing_selected_writes_nothing(self):
        doc = complete_doc()
        doc["findings"] = [deepcopy(doc["findings"][1])]
        code, out, _ = self.run_issues(doc, "--min-severity", "High")
        self.assertEqual(code, 0)
        self.assertIn("nothing written", out)
        self.assertFalse(self.out.exists())


if __name__ == "__main__":
    unittest.main()
