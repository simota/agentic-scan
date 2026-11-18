"""Regression coverage for safe record encoding and output file checks."""
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_architecture_scan import complete_doc, findings, render


class FindingsIntegrityTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def write_json(self, name, value):
        path = self.tmp / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_unencodable_fragment_preserves_existing_record(self):
        for surrogate in ("\ud800", "\udfff"):
            with self.subTest(codepoint=ord(surrogate)):
                target = self.write_json("findings.json", complete_doc())
                before = target.read_bytes()
                fragment = self.write_json("fragment.json", {
                    "findings": [{"id": "A-001", "title": "Invalid " + surrogate}],
                })
                errors = io.StringIO()
                with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                    result = findings.main(["merge", str(target), str(fragment)])
                self.assertEqual(result, 1)
                self.assertIn("refused:", errors.getvalue())
                self.assertEqual(target.read_bytes(), before)

    def test_unencodable_fragment_does_not_create_target(self):
        fragment = self.write_json("fragment.json", {"meta": {"project": "\ud800"}})
        target = self.tmp / "findings.json"
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result = findings.main(["merge", str(target), str(fragment)])
        self.assertEqual(result, 1)
        self.assertFalse(target.exists())

    def test_valid_unicode_remains_readable_and_round_trips(self):
        value = "日本語のレビュー 🔎"
        fragment = self.write_json("fragment.json", {"meta": {"project": value}})
        target = self.tmp / "findings.json"
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result = findings.main(["merge", str(target), str(fragment)])
        self.assertEqual(result, 0)
        self.assertIn(value, target.read_text(encoding="utf-8"))
        self.assertEqual(findings.read_json(target)["meta"]["project"], value)

    def test_invalid_utf8_input_is_refused_without_changing_target(self):
        target = self.write_json("findings.json", complete_doc())
        before = target.read_bytes()
        fragment = self.tmp / "fragment.json"
        fragment.write_bytes(b'{"meta":{"project":"\xff"}}')
        errors = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(errors):
            result = findings.main(["merge", str(target), str(fragment)])
        self.assertEqual(result, 1)
        self.assertIn(str(fragment), errors.getvalue())
        self.assertEqual(target.read_bytes(), before)

    def test_invalid_utf8_record_cannot_render_or_pass_contract(self):
        target = self.tmp / "findings.json"
        target.write_bytes(b'{"meta":{"project":"\xff"}}')
        out = self.tmp / "rendered"
        errors = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(errors):
            result = render.main([str(target), "--out", str(out)])
        self.assertEqual(result, 2)
        self.assertIn(str(target), errors.getvalue())
        self.assertFalse(out.exists())
        for name in ("report.md", "dashboard.html"):
            (self.tmp / name).write_text("previous output", encoding="utf-8")
        problems = findings.contract_problems(self.tmp)
        self.assertTrue(any("findings.json" in problem for problem in problems), problems)

    def test_unencodable_record_preserves_rendered_outputs(self):
        doc = complete_doc()
        doc["findings"][0]["title"] = "Invalid \ud800"
        target = self.write_json("findings.json", doc)
        report, dashboard = self.tmp / "report.md", self.tmp / "dashboard.html"
        report.write_text("previous report", encoding="utf-8")
        dashboard.write_text("previous dashboard", encoding="utf-8")
        errors = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(errors):
            result = render.main([str(target), "--out", str(self.tmp)])
        self.assertEqual(result, 2)
        self.assertIn(str(target), errors.getvalue())
        self.assertEqual(report.read_text(encoding="utf-8"), "previous report")
        self.assertEqual(dashboard.read_text(encoding="utf-8"), "previous dashboard")
        self.assertTrue(findings.contract_problems(self.tmp))

    def test_required_output_directories_fail_contract(self):
        for name in sorted(findings.OUTPUTS):
            with self.subTest(name=name):
                out = self.tmp / name.replace(".", "-")
                out.mkdir()
                for output in findings.OUTPUTS:
                    path = out / output
                    if output == name:
                        path.mkdir()
                    elif output == "findings.json":
                        path.write_text(json.dumps(complete_doc()), encoding="utf-8")
                    else:
                        path.write_text("previous output", encoding="utf-8")
                errors = io.StringIO()
                with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                    result = findings.main(["check", str(out), "--allow", name])
                self.assertEqual(result, 1)
                self.assertIn(name, errors.getvalue())

    def test_explicitly_allowed_extra_directory_remains_valid(self):
        target = self.write_json("findings.json", complete_doc())
        with redirect_stdout(io.StringIO()):
            self.assertEqual(render.main([str(target), "--out", str(self.tmp)]), 0)
        (self.tmp / "notes").mkdir()
        self.assertEqual(findings.contract_problems(self.tmp, ["notes"]), [])

    def optional_string_documents(self, value):
        doc = complete_doc()
        doc["findings"][0]["validation"].update(verdict="Likely", evidence=value)
        yield "validation.evidence", doc
        doc = complete_doc()
        doc["findings"][0]["references"] = [{"title": value, "url": "https://example.com"}]
        yield "references[0].title", doc
        doc = complete_doc()
        doc["meta"]["commit"] = value
        yield "meta.commit", doc
        doc = complete_doc()
        doc["rules"][0]["reason"] = value
        yield "rules[0].reason", doc

    def test_optional_rendered_values_must_be_strings(self):
        for value in (None, 1, [], [1], {}, False):
            for field, doc in self.optional_string_documents(value):
                with self.subTest(field=field, value=value):
                    with self.assertRaisesRegex(findings.SchemaError, re.escape(field)):
                        findings.validate(doc, complete=True)

    def test_invalid_optional_values_cannot_replace_rendered_outputs(self):
        out = self.tmp / "rendered"
        out.mkdir()
        for field, doc in self.optional_string_documents([1]):
            with self.subTest(field=field):
                target = self.write_json("findings.json", doc)
                report, dashboard = out / "report.md", out / "dashboard.html"
                report.write_text("previous report", encoding="utf-8")
                dashboard.write_text("previous dashboard", encoding="utf-8")
                errors = io.StringIO()
                with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                    result = render.main([str(target), "--out", str(out)])
                self.assertEqual(result, 2)
                self.assertIn(field, errors.getvalue())
                self.assertEqual(report.read_text(encoding="utf-8"), "previous report")
                self.assertEqual(dashboard.read_text(encoding="utf-8"), "previous dashboard")

    def test_invalid_optional_values_cannot_merge_or_pass_contract(self):
        out = self.tmp / "out"
        out.mkdir()
        for name in ("report.md", "dashboard.html"):
            (out / name).write_text("previous output", encoding="utf-8")
        for field, doc in self.optional_string_documents([1]):
            with self.subTest(field=field):
                target = self.write_json("findings.json", complete_doc())
                before = target.read_bytes()
                fragment = self.write_json("fragment.json", doc)
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    result = findings.main(["merge", str(target), str(fragment)])
                self.assertEqual(result, 1)
                self.assertEqual(target.read_bytes(), before)
                (out / "findings.json").write_text(json.dumps(doc), encoding="utf-8")
                problems = findings.contract_problems(out)
                self.assertTrue(any(field in problem for problem in problems), problems)

    def test_optional_strings_allow_omission_and_empty_values(self):
        for verdict in ("Likely", "Unverified", "Unlikely"):
            with self.subTest(verdict=verdict):
                doc = complete_doc()
                validation = doc["findings"][0]["validation"]
                validation["verdict"] = verdict
                del validation["evidence"]
                doc["findings"][0]["references"] = [{"url": "https://example.com"}]
                findings.validate(doc, complete=True)
                validation["evidence"] = ""
                doc["findings"][0]["references"][0]["title"] = ""
                doc["meta"]["commit"] = ""
                doc["rules"][0]["reason"] = ""
                findings.validate(doc, complete=True)


if __name__ == "__main__":
    unittest.main()
