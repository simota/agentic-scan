"""Regression coverage for strict JSON numbers throughout finding records."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_architecture_scan import complete_doc, findings, render


class FindingsNumericTests(unittest.TestCase):
    TOKENS = ("NaN", "Infinity", "-Infinity", "1e9999", "-1e9999")

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.out = self.tmp / "out"
        self.out.mkdir()
        self.target = self.out / "findings.json"

    def write_json(self, path, value):
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def nonfinite_text(self, token):
        doc = complete_doc()
        doc["meta"]["extra"] = {"measurements": [0, "NONFINITE_VALUE"]}
        return json.dumps(doc).replace('"NONFINITE_VALUE"', token)

    def test_nonfinite_numbers_are_rejected_even_in_nested_extra_fields(self):
        for token in self.TOKENS:
            with self.subTest(token=token):
                self.target.write_text(self.nonfinite_text(token), encoding="utf-8")
                with self.assertRaises(findings.SchemaError) as caught:
                    findings.read_json(self.target)
                self.assertIn(str(self.target), str(caught.exception))

    def test_nonfinite_later_fragment_preserves_the_entire_batch(self):
        first = self.write_json(self.tmp / "first.json", complete_doc())
        fragment = self.tmp / "nonfinite.json"
        for token in self.TOKENS:
            for existing in (False, True):
                with self.subTest(token=token, existing=existing):
                    self.target.unlink(missing_ok=True)
                    if existing:
                        doc = complete_doc()
                        doc["meta"]["project"] = "previous project"
                        self.write_json(self.target, doc)
                    before = self.target.read_bytes() if existing else None
                    fragment.write_text(self.nonfinite_text(token), encoding="utf-8")
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        result = findings.main(
                            ["merge", str(self.target), str(first), str(fragment)])
                    self.assertEqual(result, 1)
                    self.assertIn(str(fragment), stderr.getvalue())
                    self.assertEqual(stdout.getvalue(), "")
                    if existing:
                        self.assertEqual(self.target.read_bytes(), before)
                    else:
                        self.assertFalse(self.target.exists())

    def test_nonfinite_existing_record_cannot_merge_render_or_pass_contract(self):
        fragment = self.write_json(self.tmp / "fragment.json", {
            "meta": {"project": "updated"},
        })
        for token in self.TOKENS:
            with self.subTest(token=token):
                self.target.write_text(self.nonfinite_text(token), encoding="utf-8")
                before = self.target.read_bytes()
                report, dashboard = self.out / "report.md", self.out / "dashboard.html"
                report.write_text("previous report", encoding="utf-8")
                dashboard.write_text("previous dashboard", encoding="utf-8")
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    merge_result = findings.main(["merge", str(self.target), str(fragment)])
                    render_result = render.main([str(self.target), "--out", str(self.out)])
                    check_result = findings.main(["check", str(self.out)])
                self.assertEqual(merge_result, 1)
                self.assertEqual(render_result, 2)
                self.assertEqual(check_result, 1)
                self.assertIn(str(self.target), stderr.getvalue())
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(self.target.read_bytes(), before)
                self.assertEqual(report.read_text(encoding="utf-8"), "previous report")
                self.assertEqual(dashboard.read_text(encoding="utf-8"), "previous dashboard")

    def test_finite_numbers_and_constant_names_as_text_still_round_trip(self):
        doc = complete_doc()
        doc["meta"]["extra"] = {
            "numbers": [0, -1, 1.5, 1e300, -1e300],
            "names": list(self.TOKENS),
        }
        fragment = self.write_json(self.tmp / "fragment.json", doc)
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = findings.main(["merge", str(self.target), str(fragment)])
        self.assertEqual(result, 0, stderr.getvalue())
        self.assertEqual(findings.read_json(self.target), doc)


if __name__ == "__main__":
    unittest.main()
