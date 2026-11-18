"""Second full review: the sample, the drafting templates and the zero-findings caveat."""
import copy
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from test_architecture_scan import REPO, SKILL, complete_doc, finding, findings, render

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
                findings.atomic_write_all({d / "report.md": b"new report",
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

    def test_a_failed_backup_leaves_no_file_behind(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "report.md").write_bytes(b"old report")
            (d / "dashboard.html").write_bytes(b"old dashboard")
            real = findings.os.link

            def link(src, dst):
                if Path(src).name == "dashboard.html":
                    raise PermissionError(1, "Operation not permitted")
                return real(src, dst)

            def copy2(src, dst):
                Path(dst).write_bytes(b"part")
                raise OSError(28, "No space left on device")

            with mock.patch.object(findings.os, "link", side_effect=link), \
                    mock.patch.object(findings.shutil, "copy2", side_effect=copy2):
                with self.assertRaises(OSError):
                    findings.atomic_write_all({d / "report.md": b"new", d / "dashboard.html": b"new"})
            self.assertEqual(sorted(p.name for p in d.iterdir()), ["dashboard.html", "report.md"])
            self.assertEqual((d / "report.md").read_bytes(), b"old report")

    def test_a_successful_write_leaves_no_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "report.md").write_bytes(b"old")
            findings.atomic_write_all({d / "report.md": b"new", d / "dashboard.html": b"new"})
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


class RunContractTests(unittest.TestCase):
    """Claims of the run contract that no test held before (found by mutation testing)."""

    def build(self, doc):
        out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, out)
        (out / "findings.json").write_text(json.dumps(doc), encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(render.main([str(out / "findings.json"), "--out", str(out)]), 0)
        return out

    def problems(self, doc):
        return "\n".join(findings.contract_problems(self.build(doc)))

    def test_one_severity_is_numbered_in_path_order(self):
        doc = complete_doc()
        doc["findings"] = [finding("A-001", location=["z/late.py:1"], rule="R-01"),
                           finding("A-002", location=["a/early.py:9"])]
        self.assertIn("then path and line", self.problems(doc))
        renumbered, _ = findings.renumber(doc)
        self.assertNotIn("then path and line", self.problems(renumbered))

    def test_excluded_findings_out_of_severity_order_get_an_accurate_reason(self):
        doc = complete_doc()
        excluded = {"verdict": "FalsePositive", "method": "static", "evidence": "a.py:1 delegates"}
        doc["findings"] += [finding("A-003", "Low", validation=dict(excluded)),
                            finding("A-004", "High", validation=dict(excluded))]
        self.assertIn("by severity, then path", self.problems(doc))

    def test_an_invisible_reason_on_a_closed_rule_is_no_reason(self):
        doc = complete_doc()
        doc["rules"][0]["reason"] = "\u00ad"
        self.assertNotIn("a reason explains", self.problems(doc))
        doc["rules"][0]["reason"] = "provisional: traced by unit 2"
        self.assertIn("a reason explains", self.problems(doc))

    def test_an_invisible_reason_does_not_explain_a_not_checked_rule(self):
        doc = complete_doc()
        doc["rules"].append({"id": "R-02", "statement": "s", "source": "adr",
                             "status": "not checked", "reason": "\u200b"})
        self.assertIn("R-02", self.problems(doc))

    def test_a_missing_output_is_named(self):
        out = self.build(complete_doc())
        (out / "report.md").unlink()
        self.assertIn("missing output: report.md", findings.contract_problems(out))

    def test_empty_checked_ok_and_limitations_are_refused(self):
        for key, message in (("limitations", "limitations: state"), ("checked_ok", "checked_ok: list")):
            with self.subTest(key=key):
                doc = complete_doc()
                doc[key] = []
                self.assertIn(message, self.problems(doc))

    def test_evidence_may_name_the_location_by_its_file_name(self):
        doc = complete_doc()
        doc["findings"][1] = finding("A-002", "Low", location=["bin/server:9"], validation={
            "verdict": "Valid", "method": "static", "evidence": "server:9 opens the pool"})
        self.assertNotIn("A-002", self.problems(doc))

    def test_a_range_ending_past_the_file_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "a.py").write_text("x\n" * 10, encoding="utf-8")
            doc = {"findings": [finding(location=["a.py:3-11"])]}
            self.assertIn("line 11 is past", "\n".join(findings.location_problems(doc, tmp)))
            doc = {"findings": [finding(location=["a.py:3-10"])]}
            self.assertEqual(findings.location_problems(doc, tmp), [])


class SchemaRefusalTests(unittest.TestCase):
    """Each bad value is refused with its field named, never accepted or a traceback."""

    CASES = [
        ("meta.project", lambda d: d["meta"].pop("project")),
        ("meta.lang", lambda d: d["meta"].update(lang="fr")),
        ("title", lambda d: d["findings"][0].update(title=" ")),
        ("confidence", lambda d: d["findings"][0].update(confidence="Sure")),
        ("category", lambda d: d["findings"][0].update(category="Security")),
        ("location", lambda d: d["findings"][0].update(location=[])),
        ("validation.verdict", lambda d: d["findings"][0]["validation"].update(verdict="Maybe")),
        ("validation.method", lambda d: d["findings"][0]["validation"].update(method="guess")),
        ("validation: must be an object", lambda d: d["findings"][0].update(validation="Valid")),
        ("analysis: unknown keys ['reslt']", lambda d: d["findings"][0].update(
            analysis={"tool": "t", "command": "c", "reslt": "r"})),
        ("references[0]", lambda d: d["findings"][0].update(references=["https://e.example"])),
        ("references[0].url", lambda d: d["findings"][0].update(references=[{"title": "x"}])),
        ("top level", lambda d: d.update(notes="x")),
        ("statement", lambda d: d["rules"][0].update(statement="")),
        ("status", lambda d: d["rules"][0].update(status="fine")),
        ("perspectives", lambda d: d["perspectives"].append(
            {"name": "Security", "status": "applied", "note": "x"})),
        ("status", lambda d: d["perspectives"][0].update(status="done")),
        ("note", lambda d: d["perspectives"][0].pop("note")),
        ("checked_ok", lambda d: d.update(checked_ok=["\x01"])),
    ]

    def test_each_bad_value_is_a_schema_error_naming_its_field(self):
        findings.validate(complete_doc(), complete=True)
        for field, change in self.CASES:
            with self.subTest(field=field):
                doc = copy.deepcopy(complete_doc())
                change(doc)
                with self.assertRaises(findings.SchemaError) as caught:
                    findings.validate(doc, complete=True)
                self.assertIn(field, str(caught.exception))


class HandEditTests(unittest.TestCase):
    def test_two_findings_with_one_id_are_refused(self):
        doc = complete_doc()
        doc["findings"][1]["id"] = "A-001"
        with self.assertRaisesRegex(findings.SchemaError, r"findings\[1\]\.id: duplicate A-001"):
            findings.validate(doc)

    def test_a_dotfile_with_a_long_name_is_a_file(self):
        self.assertTrue(findings.cites_line(".a_very_long_dotfile_name:3"))
        self.assertFalse(findings.cites_line("a_very_long_name_without_dot:3"))


if __name__ == "__main__":
    unittest.main()
