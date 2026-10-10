"""Review regressions for record containers and rule identity."""
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_architecture_scan import complete_doc, findings, render


class FindingsReviewTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def write_json(self, name, value):
        path = self.tmp / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def malformed_collections(self):
        for key in ("findings", "rules", "perspectives", "references"):
            for value in ({}, "", None, 1):
                doc = complete_doc()
                if key == "references":
                    doc["findings"][0][key] = value
                else:
                    doc[key] = value
                yield key, value, doc

    def test_record_collections_must_be_lists(self):
        for key, value, doc in self.malformed_collections():
            with self.subTest(key=key, value=value):
                with self.assertRaisesRegex(findings.SchemaError, key + ".*must be a list"):
                    findings.validate(doc, complete=True)

    def test_empty_lists_and_omitted_optional_collections_remain_valid(self):
        for key in ("findings", "rules", "perspectives"):
            with self.subTest(key=key):
                doc = complete_doc()
                doc[key] = []
                findings.validate(doc, complete=True)
                del doc[key]
                findings.validate(doc, complete=True)
        doc = complete_doc()
        doc["findings"][0]["references"] = []
        findings.validate(doc, complete=True)
        findings.validate({})

    def test_null_references_remove_the_optional_key(self):
        doc = complete_doc()
        doc["findings"][0]["references"] = [{"url": "https://example.com"}]
        target = self.write_json("findings.json", doc)
        fragment = self.write_json("fragment.json", {
            "findings": [{"id": "A-001", "references": None}],
        })
        with redirect_stdout(io.StringIO()):
            self.assertEqual(findings.main(["merge", str(target), str(fragment)]), 0)
        self.assertNotIn("references", findings.read_json(target)["findings"][0])

    def test_invalid_reference_merge_preserves_existing_record(self):
        for value in ({}, "", 1):
            with self.subTest(value=value):
                target = self.write_json("findings.json", complete_doc())
                before = target.read_bytes()
                fragment = self.write_json("fragment.json", {
                    "findings": [{"id": "A-001", "references": value}],
                })
                errors = io.StringIO()
                with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                    result = findings.main(["merge", str(target), str(fragment)])
                self.assertEqual(result, 1)
                self.assertIn("references", errors.getvalue())
                self.assertEqual(target.read_bytes(), before)

    def test_invalid_collections_cannot_render(self):
        for index, (key, value, doc) in enumerate(self.malformed_collections()):
            with self.subTest(key=key, value=value):
                target = self.write_json("findings.json", doc)
                out = self.tmp / f"rendered-{index}"
                errors = io.StringIO()
                with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                    result = render.main([str(target), "--out", str(out)])
                self.assertEqual(result, 2)
                self.assertIn(key, errors.getvalue())
                self.assertFalse(out.exists())

    def test_invalid_collections_fail_contract_check(self):
        for name in ("report.md", "dashboard.html"):
            (self.tmp / name).write_text("previous output", encoding="utf-8")
        for key, value, doc in self.malformed_collections():
            with self.subTest(key=key, value=value):
                self.write_json("findings.json", doc)
                problems = findings.contract_problems(self.tmp)
                self.assertTrue(any(key in problem and "must be a list" in problem
                                    for problem in problems), problems)

    def test_duplicate_rule_ids_are_rejected(self):
        doc = complete_doc()
        duplicate = copy.deepcopy(doc["rules"][0])
        duplicate.update(statement="a contradictory rule", status="holds")
        doc["rules"].append(duplicate)
        with self.assertRaisesRegex(findings.SchemaError, r"rules.*duplicate.*R-01"):
            findings.validate(doc, complete=True)

    def test_duplicate_rules_cannot_render_or_pass_contract(self):
        doc = complete_doc()
        doc["rules"].append(copy.deepcopy(doc["rules"][0]))
        target = self.write_json("findings.json", doc)
        errors = io.StringIO()
        out = self.tmp / "rendered"
        with redirect_stdout(io.StringIO()), redirect_stderr(errors):
            result = render.main([str(target), "--out", str(out)])
        self.assertEqual(result, 2)
        self.assertIn("duplicate", errors.getvalue())
        self.assertFalse(out.exists())
        for name in ("report.md", "dashboard.html"):
            (self.tmp / name).write_text("previous output", encoding="utf-8")
        problems = findings.contract_problems(self.tmp)
        self.assertTrue(any("duplicate" in problem for problem in problems), problems)

    def test_merging_into_duplicate_rules_is_refused_without_changes(self):
        doc = complete_doc()
        doc["rules"].append(copy.deepcopy(doc["rules"][0]))
        target = self.write_json("findings.json", doc)
        before = target.read_bytes()
        fragment = self.write_json("fragment.json", {
            "rules": [{"id": "R-01", "status": "holds"}],
        })
        errors = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(errors):
            result = findings.main(["merge", str(target), str(fragment)])
        self.assertEqual(result, 1)
        self.assertIn("rules", errors.getvalue())
        self.assertEqual(target.read_bytes(), before)

    def test_unhashable_fragment_ids_are_refused_without_changes(self):
        for key in ("findings", "rules"):
            for value in ([], {}):
                with self.subTest(key=key, value=value):
                    target = self.write_json("findings.json", complete_doc())
                    before = target.read_bytes()
                    fragment = self.write_json("fragment.json", {key: [{"id": value}]})
                    errors = io.StringIO()
                    with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                        result = findings.main(["merge", str(target), str(fragment)])
                    self.assertEqual(result, 1)
                    self.assertIn(key, errors.getvalue())
                    self.assertEqual(target.read_bytes(), before)

    def test_optional_finding_strings_reject_wrong_types_before_rendering(self):
        for key in ("contrast", "rule"):
            for index, value in enumerate(([1], {}, None, 1)):
                with self.subTest(key=key, value=value):
                    doc = complete_doc()
                    doc["findings"][0][key] = value
                    with self.assertRaisesRegex(findings.SchemaError, key + ".*string"):
                        findings.validate(doc, complete=True)
                    target = self.write_json("findings.json", doc)
                    out = self.tmp / f"rendered-{key}-{index}"
                    errors = io.StringIO()
                    with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                        result = render.main([str(target), "--out", str(out)])
                    self.assertEqual(result, 2)
                    self.assertIn(key, errors.getvalue())
                    self.assertFalse(out.exists())

    def test_empty_optional_strings_remain_valid(self):
        doc = complete_doc()
        doc["findings"][0].update(contrast="", rule="")
        doc["meta"]["method"] = ""
        findings.validate(doc, complete=True)

    def test_optional_meta_method_must_be_a_string(self):
        for value in ([1], {}, None, 1):
            with self.subTest(value=value):
                doc = complete_doc()
                doc["meta"]["method"] = value
                with self.assertRaisesRegex(findings.SchemaError, r"meta.method.*string"):
                    findings.validate(doc, complete=True)

    def test_not_checked_rule_needs_nonblank_string_reason(self):
        for name in ("report.md", "dashboard.html"):
            (self.tmp / name).write_text("previous output", encoding="utf-8")
        for value in ("", " \n ", None, 1, [], ["not accessible"]):
            with self.subTest(value=value):
                doc = complete_doc()
                doc["rules"][0].update(status="not checked", reason=value)
                self.write_json("findings.json", doc)
                problems = findings.contract_problems(self.tmp)
                self.assertTrue(any("R-01" in problem and "reason" in problem
                                    for problem in problems), problems)

    def test_not_checked_reason_can_be_added_in_a_later_fragment(self):
        target = self.write_json("findings.json", complete_doc())
        first = self.write_json("first.json", {"rules": [{"id": "R-01", "status": "not checked"}],
                                               "findings": [{"id": "A-001", "rule": None}]})
        second = self.write_json("second.json", {"rules": [{"id": "R-01", "reason": "No access"}]})
        for fragment in (first, second):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(findings.main(["merge", str(target), str(fragment)]), 0)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(render.main([str(target), "--out", str(self.tmp)]), 0)
        self.assertEqual(findings.contract_problems(self.tmp, ["first.json", "second.json"]), [])


if __name__ == "__main__":
    unittest.main()
