"""Budget references, optional descriptive fields and localised report labels."""
import contextlib
import io
import re
import tempfile
import unittest
from pathlib import Path

from test_performance_scan import complete_doc, findings, render


def contract_problems(doc):
    with tempfile.TemporaryDirectory() as directory:
        out = Path(directory)
        (out / "findings.json").write_text(findings.json.dumps(doc), encoding="utf-8")
        for name in ("report.md", "dashboard.html"):
            (out / name).write_text("x", encoding="utf-8")
        return findings.contract_problems(out)


class CrossReferenceTests(unittest.TestCase):
    def test_check_requires_finding_budgets_to_name_ledger_entries(self):
        doc = complete_doc()
        doc["findings"][0]["budget"] = "B-01"
        doc["findings"][1]["budget"] = ""
        self.assertEqual(contract_problems(doc), [])
        doc["findings"][1]["budget"] = "B-99"
        self.assertEqual(contract_problems(doc), ["P-002.budget: B-99 is not in budgets"])

    def test_check_requires_a_nonblank_reason_for_unchecked_budgets(self):
        doc = complete_doc()
        doc["budgets"][0].update(status="not checked", reason=" ")
        self.assertEqual(contract_problems(doc), ["B-01: a not-checked budget needs a reason"])
        # Merging still accepts the blank reason so a later fragment can fill it.
        findings.validate(doc)

    def test_optional_descriptive_fields_must_have_their_documented_types(self):
        cases = (
            (lambda d: d["meta"].update(method=1), "meta.method"),
            (lambda d: d["findings"][0].update(step=5), "findings[0].step"),
            (lambda d: d["budgets"][0].update(family="NET"), "budgets[0].family"),
            (lambda d: d["budgets"][0].update(family=None), "budgets[0].family"),
        )
        for change, where in cases:
            with self.subTest(where=where):
                doc = complete_doc()
                change(doc)
                with self.assertRaisesRegex(findings.SchemaError, "^" + re.escape(where)):
                    findings.validate(doc)
        doc = complete_doc()
        doc["meta"]["method"] = "Static review"
        doc["budgets"][0]["family"] = "QRY"
        findings.validate(doc, complete=True)

    def test_report_labels_follow_the_language_and_name_the_perspective(self):
        doc = complete_doc()
        report = render.render_markdown(doc, "ja")
        self.assertIn("| 範囲 | repo root |", report)
        self.assertIn("| | 状態 | メモ |", report)
        self.assertNotIn("| Scope |", report)
        self.assertIn("- **観点:** Database access (DB1)", report)
        del doc["findings"][0]["step"]
        report = render.render_markdown(doc, "en")
        self.assertIn("| Scope | repo root |", report)
        self.assertIn("- **perspective:** Database access\n", report)
        self.assertIn("· Database access (DB1)</span>", render.render_html(complete_doc(), "en"))


class RenderAndMergeFollowups(unittest.TestCase):
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

    def test_dollar_signs_cannot_start_math(self):
        self.assertEqual(render.markdown_text("$x+y$"), "\\$x+y\\$")

    def test_report_lists_every_perspective_in_canonical_order(self):
        doc = complete_doc()
        doc["perspectives"] = list(reversed(doc["perspectives"][1:]))
        report = render.render_markdown(doc, "en")
        rows = [line.split(" | ")[0][2:] for line in report.splitlines()
                if line.startswith("| ") and line.split(" | ")[0][2:] in findings.PERSPECTIVES]
        self.assertEqual(rows, list(findings.PERSPECTIVES))
        self.assertIn("| Database access | — |  |", report)

    def test_each_fragment_must_complete_the_findings_it_adds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "a.json", root / "b.json"
            record = complete_doc()["findings"][0]
            first.write_text(findings.json.dumps({"findings": [{"id": "P-001", "title": "t"}]}),
                             encoding="utf-8")
            record.pop("title")
            second.write_text(findings.json.dumps({"findings": [record]}), encoding="utf-8")
            target = root / "findings.json"
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(findings.main(["merge", str(target), str(first), str(second)]), 1)
            self.assertIn("a.json: findings[0]: missing severity", err.getvalue())
            self.assertFalse(target.exists())

    def test_check_refuses_text_that_render_cannot_encode(self):
        doc = complete_doc()
        doc["findings"][0]["title"] = "\ud800"
        problems = contract_problems(doc)
        self.assertEqual(len(problems), 1)
        self.assertIn("surrogates not allowed", problems[0])

    def test_error_messages_truncate_large_values(self):
        doc = complete_doc()
        doc["findings"][0]["severity"] = "x" * 10000
        with self.assertRaises(findings.SchemaError) as caught:
            findings.validate(doc)
        self.assertLess(len(str(caught.exception)), 200)


if __name__ == "__main__":
    unittest.main()
