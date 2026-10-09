"""Regressions for record consistency in the run contract and report rendering."""
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

from test_privacy_scan import SKILL, complete_doc, finding, findings, render


def build(directory, doc, lang=None):
    out = Path(directory) / "output"
    out.mkdir()
    (out / "findings.json").write_text(json.dumps(doc), encoding="utf-8")
    args = [str(out / "findings.json"), "--out", str(out)]
    if lang:
        args += ["--lang", lang]
    with redirect_stdout(io.StringIO()):
        assert render.main(args) == 0
    return out


class StaleOutputTests(unittest.TestCase):
    def test_merging_after_rendering_makes_the_reports_stale(self):
        with tempfile.TemporaryDirectory() as directory:
            out = build(directory, complete_doc())
            self.assertEqual(findings.contract_problems(out), [])
            fragment = Path(directory) / "fragment.json"
            fragment.write_text(json.dumps({"checked_ok": ["Exports read every store"]}),
                                encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(findings.main(
                    ["merge", str(out / "findings.json"), str(fragment)]), 0)
            problems = findings.contract_problems(out)
            self.assertEqual(len(problems), 1)
            self.assertIn("stale outputs", problems[0])
            with redirect_stdout(io.StringIO()):
                self.assertEqual(render.main([str(out / "findings.json"), "--out", str(out)]), 0)
            self.assertEqual(findings.contract_problems(out), [])

    def test_language_override_is_accepted_but_mixed_languages_are_not(self):
        with tempfile.TemporaryDirectory() as directory:
            doc = complete_doc()
            out = build(directory, doc, lang="ja")
            self.assertEqual(findings.contract_problems(out), [])
            (out / "dashboard.html").write_text(render.render_html(doc, "en"), encoding="utf-8")
            self.assertTrue(any("stale outputs" in p for p in findings.contract_problems(out)))

    def test_hand_edited_report_is_stale(self):
        with tempfile.TemporaryDirectory() as directory:
            out = build(directory, complete_doc())
            with (out / "report.md").open("a", encoding="utf-8") as stream:
                stream.write("\nAdded by hand\n")
            self.assertTrue(any("stale outputs" in p for p in findings.contract_problems(out)))

    def test_check_runs_as_a_script(self):
        with tempfile.TemporaryDirectory() as directory:
            out = build(directory, complete_doc())
            result = subprocess.run(
                [sys.executable, "-I", str(SKILL / "scripts" / "findings.py"), "check", str(out)],
                capture_output=True, text=True, env={"PYTHONDONTWRITEBYTECODE": "1"})
            self.assertEqual(result.returncode, 0, result.stderr)


class RecordConsistencyTests(unittest.TestCase):
    def problems(self, doc):
        with tempfile.TemporaryDirectory() as directory:
            return findings.contract_problems(build(directory, doc))

    def test_cited_commitments_must_exist_in_the_ledger(self):
        doc = complete_doc()
        doc["findings"][0]["commitment"] = "C-07"
        self.assertIn("findings[0].commitment: C-07 is not in the commitments ledger",
                      self.problems(doc))
        doc["findings"][0]["commitment"] = "C-01"
        self.assertEqual(self.problems(doc), [])
        # Free text is not a ledger ID and stays allowed.
        doc["findings"][0]["commitment"] = "none in the ledger"
        self.assertEqual(self.problems(doc), [])

    def test_reported_findings_need_an_applied_perspective(self):
        for status in ("N/A", "not checked"):
            with self.subTest(status=status):
                doc = complete_doc()
                for p in doc["perspectives"]:
                    if p["name"] == doc["findings"][0]["category"]:
                        p["status"] = status
                problems = self.problems(doc)
                self.assertTrue(any(p.startswith("findings[0].category") and status in p
                                    for p in problems), problems)
                # A finding excluded with evidence does not claim the perspective found a gap.
                doc["findings"][0]["validation"] = {
                    "verdict": "FalsePositive", "method": "static", "evidence": "scrubber at app.py:30"}
                doc["findings"][1]["validation"] = copy.deepcopy(doc["findings"][0]["validation"])
                self.assertEqual(self.problems(doc), [])


class RenderConsistencyTests(unittest.TestCase):
    def test_table_headers_follow_the_report_language(self):
        doc = complete_doc()
        markdown = render.render_markdown(doc, "ja")
        html = render.render_html(doc, "ja")
        self.assertIn("| ID | 約束 | 出典 | ステータス |", markdown)
        self.assertIn("| 観点 | ステータス | メモ |", markdown)
        self.assertNotIn("| Source |", markdown)
        self.assertIn("<thead><tr><th>ID</th><th>約束</th><th>出典</th><th>ステータス</th></tr></thead>",
                      html)
        self.assertIn("<th>観点</th>", html)
        self.assertIn("| ID | Commitment | Source | Status |", render.render_markdown(doc, "en"))

    def test_perspectives_use_the_reference_order_in_both_reports(self):
        doc = complete_doc()
        doc["perspectives"].reverse()
        markdown = render.render_markdown(doc, "en")
        html = render.render_html(doc, "en")
        for text in (markdown.split("## Perspective coverage", 1)[1],
                     html.split("<h2>Perspective coverage</h2>", 1)[1]):
            positions = [text.index(name) for name in findings.PERSPECTIVES]
            self.assertEqual(positions, sorted(positions))

    def test_blank_reference_titles_fall_back_to_the_url(self):
        doc = complete_doc()
        doc["findings"][0]["references"] = [{"title": " ", "url": "https://example.com/policy"}]
        self.assertIn("[https://example.com/policy](<https://example.com/policy>)",
                      render.render_markdown(doc, "en"))
        self.assertIn('<a href="https://example.com/policy">https://example.com/policy</a>',
                      render.render_html(doc, "en"))

    def test_blank_optional_fields_add_no_rows(self):
        doc = complete_doc()
        doc["meta"]["commit"] = " "
        doc["findings"] = [finding(contrast="", commitment=" ",
                                   validation={"verdict": "Likely", "method": "static",
                                               "evidence": ""})]
        markdown = render.render_markdown(doc, "en")
        html = render.render_html(doc, "en")
        for label in ("contrast", "commitment", "evidence"):
            self.assertNotIn(f"**{label}:**", markdown)
            self.assertNotIn(f"<dt>{label}</dt>", html)
        self.assertIn("| Revision | UNKNOWN |", markdown)
        self.assertIn("<dt>Revision</dt><dd>UNKNOWN</dd>", html)


if __name__ == "__main__":
    unittest.main()
