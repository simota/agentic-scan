"""Merge diagnostics: which fragment, finding and field a refusal names."""
import json
import tempfile
import unittest
from pathlib import Path

from support import complete_doc, finding, findings, run_main


class MergeMessageTests(unittest.TestCase):
    def test_errors_name_the_finding_and_the_invalid_existing_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, fragment = root / "findings.json", root / "b.json"
            target.write_text(json.dumps(complete_doc()), encoding="utf-8")
            record = finding("P-099")
            del record["workload"]
            fragment.write_text(json.dumps({"findings": [record]}), encoding="utf-8")
            code, _, err = run_main(findings.main, "merge", target, fragment)
            self.assertEqual(code, 1)
            self.assertIn("b.json: findings[2]: missing workload (finding 'P-099')", err)

            target.write_text(json.dumps({"findings": [{"id": "P-001"}]}), encoding="utf-8")
            fragment.write_text("{}", encoding="utf-8")
            code, _, err = run_main(findings.main, "merge", target, fragment)
            self.assertEqual(code, 1)
            self.assertIn(f"refused: {target}: findings[0]: missing title", err)

    def test_list_items_are_checked_before_deduplication(self):
        doc = {"checked_ok": ["a"]}
        findings.merge(doc, {"checked_ok": ["a", "b", "b"]}, "f.json")
        self.assertEqual(doc["checked_ok"], ["a", "b"])
        with self.assertRaisesRegex(findings.SchemaError, r"^f\.json\.checked_ok\[0\]"):
            findings.merge(doc, {"checked_ok": [["unhashable"]]}, "f.json")

    def test_each_fragment_must_complete_the_findings_it_adds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "a.json", root / "b.json"
            record = complete_doc()["findings"][0]
            first.write_text(json.dumps({"findings": [{"id": "P-001", "title": "t"}]}),
                             encoding="utf-8")
            record.pop("title")
            second.write_text(json.dumps({"findings": [record]}), encoding="utf-8")
            target = root / "findings.json"
            code, _, err = run_main(findings.main, "merge", target, first, second)
            self.assertEqual(code, 1)
            self.assertIn("a.json: findings[0]: missing severity", err)
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
