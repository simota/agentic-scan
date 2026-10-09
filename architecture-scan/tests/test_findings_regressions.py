"""Regression coverage for the finding and perspective validation boundaries."""
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_architecture_scan import complete_doc, findings, render


class FindingsRegressionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def write_json(self, name, value):
        path = self.tmp / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_analysis_shape_is_checked_for_both_methods(self):
        valid = {"tool": "rg", "command": "rg BillingService worker/", "result": "No calls found"}
        invalid = [(None, "analysis"), ([], "analysis"), ({}, "analysis.tool")]
        for key in valid:
            missing = dict(valid)
            del missing[key]
            invalid.append((missing, f"analysis.{key}"))
            invalid.append(({**valid, key: "  "}, f"analysis.{key}"))
            invalid.append(({**valid, key: 1}, f"analysis.{key}"))
        for method in ("static", "analysed"):
            for analysis, field in invalid:
                with self.subTest(method=method, analysis=analysis):
                    doc = complete_doc()
                    doc["findings"][0]["validation"]["method"] = method
                    doc["findings"][0]["analysis"] = analysis
                    with self.assertRaisesRegex(findings.SchemaError, field):
                        findings.validate(doc, complete=True)

    def test_valid_analysis_is_rendered_for_both_methods(self):
        for method in ("static", "analysed"):
            with self.subTest(method=method):
                doc = complete_doc()
                doc["findings"][0]["validation"]["method"] = method
                doc["findings"][0]["analysis"] = {
                    "tool": "rg", "command": "rg BillingService worker/", "result": "No calls found",
                }
                findings.validate(doc, complete=True)
                self.assertIn("No calls found", render.render_markdown(doc, "en"))
                self.assertIn("No calls found", render.render_html(doc, "en"))

    def test_invalid_static_analysis_merge_preserves_existing_record(self):
        target = self.write_json("findings.json", complete_doc())
        before = target.read_bytes()
        fragment = self.write_json("fragment.json", {
            "findings": [{"id": "A-001", "analysis": {}}],
        })
        errors = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(errors):
            result = findings.main(["merge", str(target), str(fragment)])
        self.assertEqual(result, 1)
        self.assertIn("analysis.tool", errors.getvalue())
        self.assertEqual(target.read_bytes(), before)

    def test_invalid_static_analysis_render_returns_schema_error(self):
        doc = complete_doc()
        doc["findings"][0]["analysis"] = {}
        target = self.write_json("findings.json", doc)
        out = self.tmp / "rendered"
        errors = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(errors):
            result = render.main([str(target), "--out", str(out)])
        self.assertEqual(result, 2)
        self.assertIn("analysis.tool", errors.getvalue())
        self.assertFalse(out.exists())

    def test_invalid_static_analysis_fails_contract_check(self):
        doc = complete_doc()
        doc["findings"][0]["analysis"] = None
        self.write_json("findings.json", doc)
        for name in ("report.md", "dashboard.html"):
            (self.tmp / name).write_text("previous output", encoding="utf-8")
        problems = findings.contract_problems(self.tmp)
        self.assertTrue(any("analysis" in problem for problem in problems), problems)

    def test_duplicate_perspectives_in_one_fragment_are_refused(self):
        first = {"name": "Coupling", "status": "not checked", "note": "not read"}
        second = {"name": "Coupling", "status": "applied", "note": "read"}
        for replace_later in (False, True):
            with self.subTest(replace_later=replace_later):
                target = self.write_json("findings.json", complete_doc())
                before = target.read_bytes()
                fragment = self.write_json("duplicate.json", {"perspectives": [first, second]})
                paths = [str(fragment)]
                if replace_later:
                    paths.append(str(self.write_json("replacement.json", {"perspectives": [second]})))
                errors = io.StringIO()
                with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                    result = findings.main(["merge", str(target), *paths])
                self.assertEqual(result, 1)
                self.assertIn("perspectives", errors.getvalue())
                self.assertIn("duplicate", errors.getvalue())
                self.assertEqual(target.read_bytes(), before)

    def test_duplicate_perspectives_in_complete_record_are_rejected(self):
        doc = complete_doc()
        duplicate = copy.deepcopy(doc["perspectives"][2])
        duplicate.update(status="not checked", note="not read")
        doc["perspectives"].append(duplicate)
        with self.assertRaisesRegex(findings.SchemaError, r"perspectives.*duplicate.*Coupling"):
            findings.validate(doc, complete=True)

    def test_duplicate_perspectives_cannot_render_or_pass_contract(self):
        doc = complete_doc()
        doc["perspectives"].append({"name": "Coupling", "status": "not checked", "note": "not read"})
        target = self.write_json("findings.json", doc)
        out = self.tmp / "rendered"
        errors = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(errors):
            result = render.main([str(target), "--out", str(out)])
        self.assertEqual(result, 2)
        self.assertIn("duplicate", errors.getvalue())
        self.assertFalse(out.exists())
        for name in ("report.md", "dashboard.html"):
            (self.tmp / name).write_text("previous output", encoding="utf-8")
        problems = findings.contract_problems(self.tmp)
        self.assertTrue(any("duplicate" in problem for problem in problems), problems)


if __name__ == "__main__":
    unittest.main()
