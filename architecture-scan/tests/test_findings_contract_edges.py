"""Regression coverage for complete IDs and lossless record input."""
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import tempfile
import unittest

from test_architecture_scan import complete_doc, findings, render


class FindingsContractEdgeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def write_json(self, name, value):
        path = self.tmp / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def newline_id_documents(self):
        for key in ("findings", "rules"):
            doc = complete_doc()
            doc[key][0]["id"] += "\n"
            yield key, doc

    def test_ids_must_match_the_entire_string(self):
        for key, doc in self.newline_id_documents():
            with self.subTest(key=key):
                with self.assertRaisesRegex(findings.SchemaError, key + r"\[0\]\.id"):
                    findings.validate(doc, complete=True)

    def test_newline_ids_cannot_append_duplicates_during_merge(self):
        for key, doc in self.newline_id_documents():
            with self.subTest(key=key):
                target = self.write_json("findings.json", complete_doc())
                before = target.read_bytes()
                fragment = self.write_json("fragment.json", {key: [doc[key][0]]})
                errors = io.StringIO()
                with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                    result = findings.main(["merge", str(target), str(fragment)])
                self.assertEqual(result, 1)
                self.assertIn(key, errors.getvalue())
                self.assertEqual(target.read_bytes(), before)

    def test_newline_ids_preserve_existing_rendered_outputs(self):
        for key, doc in self.newline_id_documents():
            with self.subTest(key=key):
                target = self.write_json("findings.json", doc)
                report = self.tmp / "report.md"
                dashboard = self.tmp / "dashboard.html"
                report.write_text("previous report", encoding="utf-8")
                dashboard.write_text("previous dashboard", encoding="utf-8")
                errors = io.StringIO()
                with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                    result = render.main([str(target), "--out", str(self.tmp)])
                self.assertEqual(result, 2)
                self.assertIn(key, errors.getvalue())
                self.assertEqual(report.read_text(encoding="utf-8"), "previous report")
                self.assertEqual(dashboard.read_text(encoding="utf-8"), "previous dashboard")

    def test_newline_rule_id_cannot_pass_contract_check(self):
        doc = complete_doc()
        doc["rules"][0]["id"] += "\n"
        self.write_json("findings.json", doc)
        for name in ("report.md", "dashboard.html"):
            (self.tmp / name).write_text("previous output", encoding="utf-8")
        errors = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(errors):
            result = findings.main(["check", str(self.tmp)])
        self.assertEqual(result, 1)
        self.assertIn("rules[0].id", errors.getvalue())

    def test_valid_id_boundaries_remain_accepted(self):
        for finding_id in ("A-001", "A-999"):
            for rule_id in ("R-01", "R-99", "R-100"):
                with self.subTest(finding_id=finding_id, rule_id=rule_id):
                    doc = complete_doc()
                    doc["findings"][0]["id"] = finding_id
                    doc["rules"][0]["id"] = rule_id
                    findings.validate(doc, complete=True)

    def duplicate_key_inputs(self):
        doc = complete_doc()
        yield "findings", json.dumps(doc)[:-1] + ', "findings": []}'
        # Keys are compared after JSON escape decoding, including nested objects.
        doc["findings"][0]["validation"]["verdict"] = "DUPLICATE_VERDICT"
        yield "verdict", json.dumps(doc).replace(
            '"DUPLICATE_VERDICT"', '"Valid", "\\u0076erdict": "Unverified"')

    def test_duplicate_keys_in_later_fragments_preserve_entire_batch(self):
        for key, value in self.duplicate_key_inputs():
            for existing in (False, True):
                with self.subTest(key=key, existing=existing):
                    target = self.tmp / "findings.json"
                    if target.exists():
                        target.unlink()
                    if existing:
                        self.write_json(target.name, complete_doc())
                    before = target.read_bytes() if existing else None
                    first_doc = complete_doc()
                    first_doc["meta"]["project"] = "updated in first fragment"
                    first = self.write_json("first.json", first_doc)
                    fragment = self.tmp / "duplicate.json"
                    fragment.write_text(value, encoding="utf-8")
                    errors = io.StringIO()
                    with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                        result = findings.main(["merge", str(target), str(first), str(fragment)])
                    self.assertEqual(result, 1)
                    self.assertIn(str(fragment), errors.getvalue())
                    self.assertIn(f"duplicate object key {key!r}", errors.getvalue())
                    if existing:
                        self.assertEqual(target.read_bytes(), before)
                    else:
                        self.assertFalse(target.exists())

    def test_duplicate_keys_in_existing_record_refuse_merge(self):
        for key, value in self.duplicate_key_inputs():
            with self.subTest(key=key):
                target = self.tmp / "findings.json"
                target.write_text(value, encoding="utf-8")
                before = target.read_bytes()
                fragment = self.write_json("fragment.json", {"meta": {"project": "updated"}})
                errors = io.StringIO()
                with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                    result = findings.main(["merge", str(target), str(fragment)])
                self.assertEqual(result, 1)
                self.assertIn(str(target), errors.getvalue())
                self.assertIn(f"duplicate object key {key!r}", errors.getvalue())
                self.assertEqual(target.read_bytes(), before)

    def test_duplicate_keys_cannot_render_or_pass_contract(self):
        for key, value in self.duplicate_key_inputs():
            with self.subTest(key=key):
                target = self.tmp / "findings.json"
                target.write_text(value, encoding="utf-8")
                report = self.tmp / "report.md"
                dashboard = self.tmp / "dashboard.html"
                report.write_text("previous report", encoding="utf-8")
                dashboard.write_text("previous dashboard", encoding="utf-8")
                errors = io.StringIO()
                with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                    result = render.main([str(target), "--out", str(self.tmp)])
                self.assertEqual(result, 2)
                self.assertIn(str(target), errors.getvalue())
                self.assertIn(f"duplicate object key {key!r}", errors.getvalue())
                self.assertEqual(report.read_text(encoding="utf-8"), "previous report")
                self.assertEqual(dashboard.read_text(encoding="utf-8"), "previous dashboard")
                errors = io.StringIO()
                with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                    result = findings.main(["check", str(self.tmp)])
                self.assertEqual(result, 1)
                self.assertIn(str(target), errors.getvalue())
                self.assertIn(f"duplicate object key {key!r}", errors.getvalue())

    def test_repeated_keys_in_separate_objects_remain_valid(self):
        doc = complete_doc()
        target = self.write_json("findings.json", doc)
        self.assertEqual(findings.read_json(target), doc)
        fragment = self.write_json("fragment.json", {
            "findings": [{"id": "A-001", "status": "Fixed"},
                         {"id": "A-002", "status": "Accepted"}],
        })
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result = findings.main(["merge", str(target), str(fragment)])
        self.assertEqual(result, 0)
        self.assertEqual([f["status"] for f in findings.read_json(target)["findings"]],
                         ["Fixed", "Accepted"])


if __name__ == "__main__":
    unittest.main()
