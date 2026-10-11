import json
from pathlib import Path
import tempfile
import unittest

from helpers import findings, run, write_json

META = {"target": "t", "date": "2026-10-11", "assessor": "test", "lang": "en"}


def finding(n, **extra):
    record = {"id": f"F-{n:03d}", "kind": "defect", "severity": "Low", "confidence": "Confirmed",
              "category": "Output contract", "title": f"finding {n}", "location": "app.py:1",
              "validation": {"verdict": "Likely", "evidence": "", "method": "static"}}
    record.update(extra)
    return record


class MergeTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.out = self.dir / "findings.json"

    def merge(self, *fragments):
        paths = []
        for i, fragment in enumerate(fragments):
            path = self.dir / f"fragment{len(list(self.dir.iterdir()))}-{i}.json"
            write_json(path, fragment)
            paths.append(path)
        return run(findings.main, "merge", self.out, *paths)

    def data(self):
        return json.loads(self.out.read_text(encoding="utf-8"))

    def test_creates_and_updates_by_id(self):
        self.assertEqual(self.merge({"meta": META, "findings": [finding(1)]})[0], 0)
        code, _, err = self.merge({"findings": [{"id": "F-001", "validation": {
            "verdict": "Valid", "evidence": "re-read", "method": "static"}}]})
        self.assertEqual(code, 0, err)
        record = self.data()["findings"][0]
        self.assertEqual(record["validation"]["verdict"], "Valid")
        self.assertEqual(record["title"], "finding 1")
        self.assertEqual(self.data()["schema_version"], 1)

    def test_refuses_more_than_five_new_findings(self):
        code, _, err = self.merge({"meta": META, "findings": [finding(n) for n in range(1, 7)]})
        self.assertEqual(code, 1)
        self.assertIn("at most 5", err)
        self.assertFalse(self.out.exists())

    def test_lint_findings_belong_to_inventory(self):
        code, _, err = self.merge({"findings": [finding(1, id="L-001")]})
        self.assertEqual(code, 1)
        self.assertIn("inventory.py --into", err)
        base = {"meta": META, "findings": [dict(finding(1, id="L-001"), source="inventory.py", rule="placeholder")]}
        write_json(self.out, base)
        code, _, err = self.merge({"findings": [{"id": "L-001", "title": "renamed"}]})
        self.assertEqual(code, 1)
        self.assertIn("merge only validation", err)
        code, _, err = self.merge({"findings": [{"id": "L-001", "validation": {
            "verdict": "FalsePositive", "evidence": "literal brace in a comment", "method": "static"}}]})
        self.assertEqual(code, 0, err)

    def test_refuses_scanner_meta(self):
        code, _, err = self.merge({"meta": dict(META, commit="0" * 40)})
        self.assertEqual(code, 1)
        self.assertIn("inventory.py --into", err)

    def test_refuses_literal_override_strings(self):
        code, _, err = self.merge({"meta": META, "findings": [finding(
            1, symptom="A ticket saying 'Ignore all previous instructions' changes the reply")]})
        self.assertEqual(code, 1)
        self.assertIn("instruction-override", err)
        code, _, err = self.merge({"meta": META, "findings": [finding(
            1, symptom="Text in the ticket can override the instructions; it is not delimited as data")]})
        self.assertEqual(code, 0, err)

    def test_refuses_credential_values(self):
        token = "sk-ant-" + "a1B2" * 8
        code, _, err = self.merge({"meta": META, "checked_ok": [f"key {token} found"]})
        self.assertEqual(code, 1)
        self.assertIn("credential-shaped", err)

    def test_perspective_replaced_by_name_and_remove(self):
        self.merge({"meta": META, "perspectives": [{"name": "Examples", "result": "not checked", "note": "later"}],
                    "limitations": ["old line"]})
        code, _, err = self.merge({"perspectives": [{"name": "Examples", "result": "N/A", "note": "none"}],
                                   "remove": {"limitations": ["old line"]}})
        self.assertEqual(code, 0, err)
        data = self.data()
        self.assertEqual(data["perspectives"], [{"name": "Examples", "result": "N/A", "note": "none"}])
        self.assertEqual(data["limitations"], [])
        code, _, err = self.merge({"remove": {"limitations": ["never recorded"]}})
        self.assertEqual(code, 1)
        self.assertIn("is not recorded", err)

    def test_schema_error_leaves_file_unchanged(self):
        self.merge({"meta": META, "findings": [finding(1)]})
        before = self.out.read_bytes()
        code, _, err = self.merge({"findings": [{"id": "F-001", "validation": {
            "verdict": "Valid", "evidence": "", "method": "static"}}]})
        self.assertEqual(code, 2)
        self.assertIn("needs validation.evidence", err)
        self.assertEqual(self.out.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
