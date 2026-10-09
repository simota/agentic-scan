"""Regression coverage for fragment boundaries and source-location paths."""
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import tempfile
import unittest

from test_architecture_scan import complete_doc, finding, findings, render


class FindingsFollowupTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def write_json(self, name, value):
        path = self.tmp / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def run_merge(self, target, *fragments):
        paths = [self.write_json(f"fragment-{i}.json", fragment)
                 for i, fragment in enumerate(fragments)]
        errors = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(errors):
            result = findings.main(["merge", str(target), *map(str, paths)])
        return result, errors.getvalue()

    def test_malformed_existing_records_are_refused_without_tracebacks(self):
        cases = (
            ([], "top level"),
            (None, "top level"),
            ({"meta": None}, "meta"),
            ({"checked_ok": None}, "checked_ok"),
            ({"perspectives": [None]}, "perspectives"),
        )
        fragment = {
            "meta": {"project": "demo"},
            "checked_ok": ["no cycles"],
            "perspectives": [{"name": "Coupling", "status": "applied", "note": "read"}],
        }
        for doc, field in cases:
            with self.subTest(doc=doc):
                target = self.write_json("findings.json", doc)
                before = target.read_bytes()
                result, errors = self.run_merge(target, fragment)
                self.assertEqual(result, 1)
                self.assertIn("refused:", errors)
                self.assertIn(field, errors)
                self.assertEqual(target.read_bytes(), before)

    def test_new_finding_must_be_complete_in_its_first_fragment(self):
        for existing in (False, True):
            with self.subTest(existing=existing):
                target = self.tmp / f"findings-{existing}.json"
                if existing:
                    target = self.write_json(target.name, complete_doc())
                before = target.read_bytes() if existing else None
                result, errors = self.run_merge(
                    target,
                    {"findings": [{"id": "A-003"}]},
                    {"findings": [finding("A-003", "Low")]},
                )
                self.assertEqual(result, 1)
                self.assertIn("missing severity", errors)
                if existing:
                    self.assertEqual(target.read_bytes(), before)
                else:
                    self.assertFalse(target.exists())

    def test_later_fragment_cannot_hide_an_invalid_update(self):
        target = self.write_json("findings.json", complete_doc())
        before = target.read_bytes()
        result, errors = self.run_merge(
            target,
            {"findings": [{"id": "A-001", "status": "Unknown"}]},
            {"findings": [{"id": "A-001", "status": "Fixed"}]},
        )
        self.assertEqual(result, 1)
        self.assertIn("status", errors)
        self.assertEqual(target.read_bytes(), before)

    def test_invalid_later_fragment_preserves_the_entire_previous_record(self):
        target = self.write_json("findings.json", complete_doc())
        before = target.read_bytes()
        result, errors = self.run_merge(
            target,
            {"findings": [{"id": "A-001", "status": "Fixed"}]},
            {"findings": [{"id": "A-002", "severity": "Critical"}]},
        )
        self.assertEqual(result, 1)
        self.assertIn("severity", errors)
        self.assertEqual(target.read_bytes(), before)

    def test_complete_findings_can_receive_partial_updates_in_one_batch(self):
        target = self.tmp / "findings.json"
        result, errors = self.run_merge(
            target,
            {"findings": [finding()], "limitations": ["static only"]},
            {"findings": [{"id": "A-001", "status": "Fixed"}],
             "limitations": ["static only", "deployment not observed"]},
        )
        self.assertEqual(result, 0, errors)
        doc = findings.read_json(target)
        self.assertEqual(doc["findings"][0]["status"], "Fixed")
        self.assertEqual(doc["findings"][0]["title"], finding()["title"])
        self.assertEqual(doc["limitations"], ["static only", "deployment not observed"])

    def test_locations_accept_spaces_and_colons_in_paths(self):
        locations = [
            ".github/workflows/Integration Tests.yml:12",
            "My Project/src/module.py:10-24",
            "src/path:with:colons.py:5",
            r"C:\repo\src\My Module.py:3-8",
            "src/請求 処理.py:12",
        ]
        for location in [*locations, locations]:
            with self.subTest(location=location):
                findings.validate({"findings": [finding(location=location)]})

    def test_locations_must_end_at_a_line_number_and_stay_on_one_line(self):
        for location in ("src/my file.py", ":10", "src/my file.py:line",
                         "src/module.py:5\n", "src/module.py:5\r\n",
                         "src/my file.py:5\n", "src/my\nfile.py:5",
                         "src/my\rfile.py:5", "src/my file.py:5-12-extra"):
            with self.subTest(location=location):
                with self.assertRaisesRegex(findings.SchemaError, "location"):
                    findings.validate({"findings": [finding(location=location)]})

    def test_paths_with_spaces_round_trip_through_merge_render_and_check(self):
        doc = complete_doc()
        locations = [".github/workflows/Integration Tests.yml:12",
                     r"C:\repo\src\My Module.py:3-8"]
        doc["findings"][0]["location"] = locations
        out = self.tmp / "out"
        out.mkdir()
        target = out / "findings.json"
        result, errors = self.run_merge(target, doc)
        self.assertEqual(result, 0, errors)
        self.assertEqual(findings.read_json(target)["findings"][0]["location"], locations)
        errors = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(errors):
            result = render.main([str(target), "--out", str(out)])
        self.assertEqual(result, 0, errors.getvalue())
        self.assertEqual(findings.contract_problems(out), [])


if __name__ == "__main__":
    unittest.main()
