import json
import os
from pathlib import Path
import stat
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

    def test_scanner_fields_refused_on_known_findings_too(self):
        self.merge({"meta": META, "findings": [finding(1)]})
        code, _, err = self.merge({"findings": [{"id": "F-001", "rule": "placeholder"}]})
        self.assertEqual(code, 1)
        self.assertIn("belong to inventory.py", err)

    def test_write_keeps_permissions_and_creates_private_files(self):
        self.merge({"meta": META})
        self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o600)
        os.chmod(self.out, 0o640)
        self.merge({"checked_ok": ["x"]})
        self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o640)

    def test_too_deep_fragment_is_an_input_error(self):
        path = self.dir / "deep.json"
        path.write_text('{"meta":' + "[" * 100000 + "]" * 100000 + "}", encoding="utf-8")
        code, _, err = run(findings.main, "merge", self.out, path)
        self.assertEqual(code, 2, err)
        self.assertIn("error:", err)

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

    def test_renumber_orders_by_severity_then_location_and_follows_references(self):
        excluded = {"verdict": "FalsePositive", "evidence": "handled in code", "method": "static"}
        self.merge({"meta": META, "findings": [
            finding(1, location="b.py:9", proposal={"before": "error F-002", "after": "error F-002 or F-004"},
                    references=[{"title": "F-002 docs", "url": "https://example.com/F-002"}]),
            finding(2, severity="High", location="z.py:1", cause="same root as F-004"),
            finding(3, severity="High", location="a.py:5", validation=excluded),
            finding(4, location="b.py:2"),
        ], "next_steps": ["fix F-002 first, then F-001"]})
        write_json(self.dir / "eval.json", {"eval_runs": [
            {"id": "E-001", "finding": "F-002", "model": "m", "date": "2026-10-12", "cases": 1, "passed": 1,
             "failed": 0}]})
        self.assertEqual(run(findings.main, "merge", self.out, self.dir / "eval.json")[0], 0)
        code, out, err = run(findings.main, "renumber", self.out)
        self.assertEqual(code, 0, err)
        data = self.data()
        # High z.py, then Low b.py:2 before b.py:9; the excluded High goes last.
        self.assertEqual([(f["id"], f["location"]) for f in data["findings"]],
                         [("F-001", "z.py:1"), ("F-002", "b.py:2"), ("F-003", "b.py:9"), ("F-004", "a.py:5")])
        self.assertEqual(data["findings"][0]["cause"], "same root as F-002")
        self.assertEqual(data["eval_runs"][0]["finding"], "F-001")
        self.assertEqual(data["next_steps"], ["fix F-001 first, then F-003"])
        # Quoted prompt text and links are not finding references.
        self.assertEqual(data["findings"][2]["proposal"], {"before": "error F-002", "after": "error F-002 or F-004"})
        self.assertEqual(data["findings"][2]["references"][0]["url"], "https://example.com/F-002")
        # A reference's title is prose and follows the new numbers.
        self.assertEqual(data["findings"][2]["references"][0]["title"], "F-001 docs")
        code, out, _ = run(findings.main, "renumber", self.out)
        self.assertEqual(code, 0)
        self.assertIn("already in order", out)


if __name__ == "__main__":
    unittest.main()
