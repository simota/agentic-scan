"""Correcting a recorded mistake through merge, and refusing ID collisions."""
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_architecture_scan import complete_doc, finding, findings


class MergeCorrectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.target = self.tmp / "findings.json"
        self.target.write_text(json.dumps(complete_doc()), encoding="utf-8")

    def merge(self, fragment):
        path = self.tmp / "fragment.json"
        path.write_text(json.dumps(fragment), encoding="utf-8")
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = findings.main(["merge", str(self.target), str(path)])
        return code, err.getvalue()

    def record(self):
        return findings.read_json(self.target)

    def test_null_removes_optional_keys(self):
        self.assertEqual(self.merge({
            "meta": {"commit": "abc"},
            "findings": [{"id": "A-001", "contrast": "x", "step": "DM2"}],
            "rules": [{"id": "R-01", "reason": "r", "family": "OWN"}]})[0], 0)
        self.assertEqual(self.merge({
            "meta": {"commit": None},
            "findings": [{"id": "A-001", "contrast": None, "step": None}],
            "rules": [{"id": "R-01", "reason": None, "family": None}]})[0], 0)
        doc = self.record()
        self.assertNotIn("commit", doc["meta"])
        self.assertFalse({"contrast", "step"} & set(doc["findings"][0]))
        self.assertFalse({"reason", "family"} & set(doc["rules"][0]))

    def test_null_cannot_remove_a_required_key(self):
        before = self.target.read_bytes()
        for fragment, field in (({"findings": [{"id": "A-001", "trace": None}]}, "A-001.trace"),
                                ({"rules": [{"id": "R-01", "status": None}]}, "R-01.status"),
                                ({"meta": {"lang": None}}, "meta.lang")):
            with self.subTest(field=field):
                code, err = self.merge(fragment)
                self.assertEqual(code, 1)
                self.assertIn(field, err)
                self.assertIn("required", err)
                self.assertEqual(self.target.read_bytes(), before)

    def test_new_records_drop_null_optional_keys(self):
        self.assertEqual(self.merge({"findings": [finding("A-003", "Low", contrast=None)]})[0], 0)
        self.assertNotIn("contrast", self.record()["findings"][2])

    def test_remove_replaces_a_list_item_in_one_fragment(self):
        self.assertEqual(self.merge({"next_steps": ["Owner to confirm A-001"]})[0], 0)
        self.assertEqual(self.merge({"remove": {"next_steps": ["Owner to confirm A-001"]},
                                     "next_steps": ["Owner to confirm A-002"]})[0], 0)
        self.assertEqual(self.record()["next_steps"], ["Owner to confirm A-002"])

    def test_remove_refuses_unknown_text_and_other_keys(self):
        before = self.target.read_bytes()
        for removals, message in (({"limitations": ["not there"]}, "not recorded"),
                                  ({"findings": ["A-001"]}, "only"),
                                  (["limitations"], "object"),
                                  ({"limitations": "delivery semantics not observed"}, "list")):
            with self.subTest(removals=removals):
                code, err = self.merge({"remove": removals})
                self.assertEqual(code, 1)
                self.assertIn(message, err)
                self.assertEqual(self.target.read_bytes(), before)

    def test_removing_a_required_list_item_still_fails_check_not_merge(self):
        self.assertEqual(self.merge({"remove": {"checked_ok": ["no cycles"]}})[0], 0)
        self.assertEqual(self.record()["checked_ok"], [])

    def test_complete_record_with_a_taken_id_is_a_collision(self):
        before = self.target.read_bytes()
        other = finding("A-001", "Low", title="Another unit's finding", location="web/a.ts:4")
        code, err = self.merge({"findings": [other]})
        self.assertEqual(code, 1)
        self.assertIn("already holds", err)
        self.assertEqual(self.target.read_bytes(), before)

    def test_resending_or_correcting_the_same_finding_is_not_a_collision(self):
        same = finding("A-001", "Medium")
        self.assertEqual(self.merge({"findings": [same]})[0], 0)
        retitled = finding("A-001", "Medium", title="Sharper title")
        self.assertEqual(self.merge({"findings": [retitled]})[0], 0)
        self.assertEqual(self.merge({"findings": [{"id": "A-001", "title": "x",
                                                   "location": "y.py:1"}]})[0], 0)
        self.assertEqual(self.record()["findings"][0]["title"], "x")


if __name__ == "__main__":
    unittest.main()
