"""Defects found by a full review of the scripts, docs and Makefile."""
import copy
import unittest

from test_architecture_scan import complete_doc, findings


class RuleReplacementTests(unittest.TestCase):
    def test_a_replaced_rule_keeps_its_place_in_the_ledger(self):
        doc = complete_doc()
        first = copy.deepcopy(doc["rules"][0])
        doc["rules"] = [dict(first, id=rid) for rid in ("R-01", "R-05", "R-06")]
        replacement = dict(first, id="R-05", statement="billing is the only writer")
        findings.merge(doc, {"remove": {"rules": ["R-05"]}, "rules": [replacement]}, "f")
        self.assertEqual([r["id"] for r in doc["rules"]], ["R-01", "R-05", "R-06"])
        self.assertEqual(doc["rules"][1]["statement"], "billing is the only writer")

    def test_a_new_rule_without_a_removal_is_still_appended(self):
        doc = complete_doc()
        rule = dict(copy.deepcopy(doc["rules"][0]), id="R-99")
        findings.merge(doc, {"rules": [rule]}, "f")
        self.assertEqual(doc["rules"][-1]["id"], "R-99")


class StepNumberTests(unittest.TestCase):
    def test_a_step_with_thousands_of_digits_is_a_schema_error(self):
        doc = complete_doc()
        doc["findings"][0]["step"] = doc["findings"][0].get("step", "CP1")[:2] + "1" * 5000
        with self.assertRaisesRegex(findings.SchemaError, r"step: .* must be a hunt step ID"):
            findings.validate(doc)


if __name__ == "__main__":
    unittest.main()
