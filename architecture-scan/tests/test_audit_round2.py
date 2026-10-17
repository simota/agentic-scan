"""Second full review: the sample, the drafting templates and the zero-findings caveat."""
import json
import re
import unittest

from test_architecture_scan import REPO, SKILL, complete_doc, findings, render

SAMPLE = REPO / "examples" / "findings.sample.json"


class SampleTests(unittest.TestCase):
    """The sample is what an agent imitates, so it follows the rules it demonstrates."""

    def setUp(self):
        self.doc = json.loads(SAMPLE.read_text(encoding="utf-8"))

    def test_meta_method_names_every_analysis_tool(self):
        for f in self.doc["findings"]:
            if "analysis" in f:
                with self.subTest(finding=f["id"]):
                    self.assertIn(f["analysis"]["tool"], self.doc["meta"]["method"])

    def test_every_high_and_medium_trace_step_cites_a_line(self):
        for f in self.doc["findings"]:
            if f["severity"] not in ("High", "Medium"):
                continue
            steps = [s for s in re.split(r"(?:^|(?<=\.)\s+)\d+\.\s+", f["trace"]) if s]
            for step in steps:
                with self.subTest(finding=f["id"], step=step):
                    self.assertTrue(findings.cites_line(step), step)


class TemplateTests(unittest.TestCase):
    def test_ja_templates_use_the_dashboards_word_for_severity(self):
        self.assertEqual(render.DASH["ja"]["severity"], "重大度")
        for name in ("issue.ja.md", "report.ja.md"):
            with self.subTest(template=name):
                text = (SKILL / "templates" / name).read_text(encoding="utf-8")
                self.assertNotIn("深刻度", text)
                self.assertIn("重大度", text)

    def test_issue_templates_say_how_to_fill_missing_commit_and_titles(self):
        for lang in ("ja", "en"):
            with self.subTest(lang=lang):
                text = (SKILL / "templates" / f"issue.{lang}.md").read_text(encoding="utf-8")
                header = text.split("-->", 1)[0]
                self.assertIn("{{meta.commit}}: ", header)
                self.assertIn("UNKNOWN", header)
                self.assertIn("{{references[].title}}: ", header)


class ZeroFindingsCaveatTests(unittest.TestCase):
    def test_report_says_zero_findings_proves_nothing(self):
        for lang in ("ja", "en"):
            caveat = render.markdown_inline(render.DASH[lang]["no_findings"])
            with self.subTest(lang=lang, case="no findings"):
                doc = complete_doc()
                doc["findings"] = []
                self.assertIn(caveat, render.render_markdown(doc, lang))
            with self.subTest(lang=lang, case="only excluded"):
                doc = complete_doc()
                for f in doc["findings"]:
                    f["validation"] = {"verdict": "FalsePositive", "method": "static",
                                       "evidence": "a.py:1 delegates"}
                self.assertIn(caveat, render.render_markdown(doc, lang))
            with self.subTest(lang=lang, case="included findings"):
                self.assertNotIn(caveat, render.render_markdown(complete_doc(), lang))


if __name__ == "__main__":
    unittest.main()
