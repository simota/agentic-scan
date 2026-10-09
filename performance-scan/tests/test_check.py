"""Run-contract rules that ``findings.py check`` enforces beyond the schema."""
import tempfile
import unittest
from pathlib import Path

from support import complete_doc, contract_problems, finding, findings


class CheckRuleTests(unittest.TestCase):
    def test_excluded_findings_come_last_and_are_not_ranked(self):
        excluded = {"verdict": "FalsePositive", "method": "static", "evidence": "x.py:1"}
        doc = complete_doc()
        doc["findings"] = [finding("P-001", "Low"), finding("P-002", "High", validation=excluded)]
        self.assertEqual(contract_problems(doc), [])
        doc["findings"] = [finding("P-001", "Low", validation=excluded), finding("P-002", "High")]
        self.assertEqual(contract_problems(doc), [
            "P-002: excluded findings (P-001) must be numbered after all others"])
        doc["findings"] = [finding("P-001", "Low"), finding("P-002", "High")]
        self.assertEqual(contract_problems(doc), [
            "findings must be numbered in severity order (High first): P-002 (High) follows "
            "P-001 (Low)"])

    def test_definitive_evidence_suspected_valid_and_holding_budgets(self):
        doc = complete_doc()
        doc["findings"][0]["validation"]["evidence"] = "looks fine"
        doc["findings"][1].update(confidence="Suspected")
        doc["findings"][0]["budget"] = "B-01"
        doc["budgets"][0]["status"] = "holds"
        self.assertEqual(contract_problems(doc), [
            "P-001.validation.evidence: Valid evidence must cite a path:line",
            "P-002: a Suspected finding cannot be Valid; confirm the code link "
            "(Confirmed or Environment-dependent) or record Likely",
            "B-01: status holds, but P-001 is a Valid, unfixed violation of it"])
        doc["findings"][0]["status"] = "Accepted"  # an accepted cost still violates it
        self.assertIn("B-01: status holds, but P-001 is a Valid, unfixed violation of it",
                      contract_problems(doc))
        doc["findings"][0]["status"] = "Fixed"
        doc["findings"][0]["validation"]["evidence"] = "C:\\app\\x.py:12 shows it"
        doc["findings"][1]["validation"]["verdict"] = "Likely"
        self.assertEqual(contract_problems(doc), [])

    def test_required_lists_and_unique_ids(self):
        doc = complete_doc()
        doc["limitations"], doc["checked_ok"] = [], []
        self.assertEqual(contract_problems(doc), [
            "limitations: state what static reading cannot show",
            "checked_ok: list what was examined and held"])
        doc = complete_doc()
        doc["findings"][1]["id"] = "P-001"
        with self.assertRaisesRegex(findings.SchemaError, r"duplicate P-001"):
            findings.validate(doc)

    def test_check_names_a_path_that_is_not_a_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "findings.json"
            path.write_text("{}", encoding="utf-8")
            for target in (path, Path(directory) / "missing"):
                self.assertEqual(findings.contract_problems(target), [f"not a directory: {target}"])

    def test_check_refuses_text_that_render_cannot_encode(self):
        doc = complete_doc()
        doc["findings"][0]["title"] = "\ud800"
        problems = contract_problems(doc)
        self.assertEqual(len(problems), 1)
        self.assertIn("surrogates not allowed", problems[0])


class CrossReferenceTests(unittest.TestCase):
    def test_check_requires_finding_budgets_to_name_ledger_entries(self):
        doc = complete_doc()
        doc["findings"][0]["budget"] = "B-01"
        doc["findings"][1]["budget"] = ""
        self.assertEqual(contract_problems(doc), [])
        doc["findings"][1]["budget"] = "B-99"
        self.assertEqual(contract_problems(doc), ["P-002.budget: 'B-99' is not in budgets"])

    def test_check_requires_a_nonblank_reason_for_unchecked_budgets(self):
        doc = complete_doc()
        doc["budgets"][0].update(status="not checked", reason=" ")
        self.assertEqual(contract_problems(doc), ["B-01: a not-checked budget needs a reason"])
        # Merging still accepts the blank reason so a later fragment can fill it.
        findings.validate(doc)


class CitationTests(unittest.TestCase):
    def test_evidence_must_name_a_file_position(self):
        cites = ["app/orders/views.py:18 lacks prefetch", "app/orders/views.py#L18",
                 "views.py：18", "C:\\app\\x.py:12", "Makefile:12 sets -O0", "src/main:40"]
        not_cites = ["confirmed against https://staging.example:8080/api/orders",
                     "measured locally at 12:30", "ratio 1:10", "redis at localhost:6379",
                     "views.py line 18"]
        for text in cites:
            self.assertTrue(findings.cites_location(text), text)
        for text in not_cites:
            self.assertFalse(findings.cites_location(text), text)


if __name__ == "__main__":
    unittest.main()
