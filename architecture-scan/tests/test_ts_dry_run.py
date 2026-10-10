"""Findings from running the skill on a TypeScript monorepo."""
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from contextlib import redirect_stdout

from test_architecture_scan import SKILL, complete_doc, finding, findings, render


class ScopedPackageTests(unittest.TestCase):
    def test_a_word_initial_at_stays_readable_and_an_address_does_not_link(self):
        self.assertEqual(render.markdown_inline("uses @rv8/domain"), "uses @rv8/domain")
        self.assertIn("@rv8/x", render.markdown_code("import x from '@rv8/x'"))
        self.assertIn("&#64;<!-- -->", render.markdown_inline("mail bob@example.com"))
        self.assertIn("&#64;<!-- -->", render.markdown_code("ssh deploy@host"))


class TemplateCountTests(unittest.TestCase):
    def test_counts_print_every_template_placeholder(self):
        doc = complete_doc()
        doc["findings"] = [finding("A-001", "High"), finding("A-002", "High"),
                           finding("A-003", "Low"), finding("A-004", "Low")]
        doc["findings"][1]["validation"] = {"verdict": "Likely", "method": "static", "evidence": "x"}
        doc["findings"][3]["validation"].update(verdict="FalsePositive", evidence="a.py:1")
        counts = findings.template_counts(doc)
        self.assertEqual(counts["n_high"], 2)
        self.assertEqual(counts["n_high_valid"], 1)
        self.assertEqual(counts["n_low"], 1)
        self.assertEqual(counts["n_excluded"], 1)
        self.assertEqual((counts["n_likely"], counts["n_unverified"], counts["n_unlikely"]), (1, 0, 0))
        for lang in ("en", "ja"):
            text = (SKILL / "templates" / f"report.{lang}.md").read_text(encoding="utf-8")
            used = set(re.findall(r"\{\{(n_[a-z_]+)\}\}", text))
            self.assertEqual(used - set(counts), set(), lang)

    def test_counts_command_prints_name_value_lines(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "findings.json"
            path.write_text(json.dumps(complete_doc()), encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(findings.main(["counts", str(path)]), 0)
            self.assertIn("n_high=1\n", out.getvalue())
            self.assertIn("n_low_valid=1\n", out.getvalue())


class TemplateMappingTests(unittest.TestCase):
    def test_issue_templates_explain_the_fields_that_do_not_copy_verbatim(self):
        for lang in ("en", "ja"):
            text = (SKILL / "templates" / f"issue.{lang}.md").read_text(encoding="utf-8")
            head = text.split("-->", 1)[0]
            for field in ("{{location}}", "{{step}}", "{{rule}}", "{{trace}}"):
                self.assertIn(field, head, (lang, field))


if __name__ == "__main__":
    unittest.main()
