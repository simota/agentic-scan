"""Second full review: the sample, the drafting templates and the zero-findings caveat."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

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


FINDINGS_PY = SKILL / "scripts" / "findings.py"


def run_findings(*args):
    return subprocess.run([sys.executable, str(FINDINGS_PY), *map(str, args)],
                          capture_output=True, text=True, timeout=30)


class PairWriteTests(unittest.TestCase):
    """findings-schema.md: a write error keeps the previous pair."""

    def write_failing_second(self, d):
        """Write report.md, then fail replacing dashboard.html."""
        real = os.replace

        def replace(src, dst):
            if Path(dst).name == "dashboard.html":
                raise OSError(16, "Device or resource busy")
            return real(src, dst)

        with mock.patch.object(findings.os, "replace", side_effect=replace):
            with self.assertRaises(OSError):
                findings._atomic_write_all({d / "report.md": b"new report",
                                            d / "dashboard.html": b"new dashboard"})

    def test_a_failed_second_replacement_restores_the_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "report.md").write_bytes(b"old report")
            (d / "dashboard.html").write_bytes(b"old dashboard")
            self.write_failing_second(d)
            self.assertEqual((d / "report.md").read_bytes(), b"old report")
            self.assertEqual((d / "dashboard.html").read_bytes(), b"old dashboard")
            self.assertEqual(sorted(p.name for p in d.iterdir()), ["dashboard.html", "report.md"])

    def test_a_first_render_that_fails_leaves_no_half_pair(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            self.write_failing_second(d)
            self.assertEqual(list(d.iterdir()), [])

    def test_a_successful_write_leaves_no_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "report.md").write_bytes(b"old")
            findings._atomic_write_all({d / "report.md": b"new", d / "dashboard.html": b"new"})
            self.assertEqual(sorted(p.name for p in d.iterdir()), ["dashboard.html", "report.md"])
            self.assertEqual((d / "report.md").read_bytes(), b"new")


class MergeInputTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "mkfifo"), "no FIFOs on this platform")
    def test_a_fifo_record_is_refused_instead_of_blocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            os.mkfifo(d / "findings.json")
            (d / "frag.json").write_text(json.dumps({"checked_ok": ["x"]}), encoding="utf-8")
            result = run_findings("merge", d / "findings.json", d / "frag.json")
            self.assertEqual(result.returncode, 1)
            self.assertIn("not a regular file", result.stderr)

    def test_a_fragment_read_error_names_the_file_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "nan.json").write_text('{"checked_ok": [NaN]}', encoding="utf-8")
            result = run_findings("merge", d / "findings.json", d / "nan.json")
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stderr.count("nan.json"), 1, result.stderr)

    def test_deeply_nested_meta_extras_are_refused(self):
        def nested(depth):
            value = []
            for _ in range(depth - 1):
                value = [value]
            return value

        doc = complete_doc()
        doc["meta"]["context"] = nested(findings.META_DEPTH)
        findings.validate(doc)
        doc["meta"]["context"] = nested(findings.META_DEPTH + 1)
        with self.assertRaisesRegex(findings.SchemaError, "meta.context: nested more than"):
            findings.validate(doc)
        doc["meta"]["context"] = nested(8000)
        with self.assertRaises(findings.SchemaError):
            findings.validate(doc)


if __name__ == "__main__":
    unittest.main()
