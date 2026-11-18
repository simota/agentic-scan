"""findings.py set: the owner's triage after a run, and check's Accepted rule."""
import json
from pathlib import Path
import tempfile
import unittest

from support import complete_doc, contract_problems, findings, finding, run_cli, run_main


def write(directory, doc):
    path = Path(directory) / "findings.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


class SetStatus(unittest.TestCase):
    def test_fixed_changes_only_the_named_findings(self):
        with tempfile.TemporaryDirectory() as d:
            path = write(d, complete_doc())
            code, out, _ = run_main(findings.main, "set", path, "P-001", "--status", "Fixed")
            self.assertEqual(code, 0)
            self.assertIn("P-001: Open -> Fixed", out)
            doc = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(doc["findings"][0]["status"], "Fixed")
            self.assertNotIn("status", doc["findings"][1])

    def test_accepted_needs_a_decision_and_prefixes_the_ids(self):
        with tempfile.TemporaryDirectory() as d:
            doc = complete_doc()
            # A question naming the finding is not its acceptance.
            doc["decisions"] = ["Confirm the page size (P-002)"]
            path = write(d, doc)
            before = path.read_bytes()
            code, _, err = run_main(findings.main, "set", path, "P-002", "--status", "Accepted")
            self.assertEqual(code, 1)
            self.assertIn("Accepted needs --decision for P-002", err)
            self.assertEqual(path.read_bytes(), before)
            code, _, _ = run_main(findings.main, "set", path, "P-001", "P-002", "--status",
                                  "Accepted", "--decision", "Owner accepts until Q3")
            self.assertEqual(code, 0)
            doc = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(doc["decisions"][-1], "P-001, P-002: Owner accepts until Q3")
            # Re-accepting needs no new decision and adds no duplicate.
            code, out, _ = run_main(findings.main, "set", path, "P-002", "--status", "Accepted")
            self.assertEqual(code, 0)
            self.assertIn("(unchanged)", out)

    def test_a_decision_naming_only_some_ids_is_refused(self):
        doc = complete_doc()
        with self.assertRaisesRegex(findings.SchemaError, "names P-001 but not P-002"):
            findings.set_status(doc, ["P-001", "P-002"], "Accepted", "P-001 is fine")
        self.assertNotIn("status", doc["findings"][0])

    def test_unknown_excluded_and_malformed_ids_change_nothing(self):
        doc = complete_doc()
        doc["findings"].append(finding("P-003", "Low", validation={
            "verdict": "FalsePositive", "method": "static", "evidence": "a.py:1"}))
        with tempfile.TemporaryDirectory() as d:
            path = write(d, doc)
            before = path.read_bytes()
            for ids, message in ((["P-009"], "no such finding"),
                                 (["P-001", "P-003"], "excluded as FalsePositive"),
                                 (["p1"], "not a finding ID")):
                code, _, err = run_main(findings.main, "set", path, *ids, "--status", "Fixed")
                self.assertEqual(code, 1, ids)
                self.assertIn(message, err)
                self.assertEqual(path.read_bytes(), before)

    def test_render_keeps_the_outputs_current_and_the_contract_passes(self):
        with tempfile.TemporaryDirectory() as d:
            path = write(d, complete_doc())
            self.assertEqual(run_cli("render.py", path, "--out", d).returncode, 0)
            result = run_cli("findings.py", "set", path, "P-002", "--status", "Accepted",
                             "--decision", "Owner accepts the low-volume cost", "--render")
            self.assertEqual(result.returncode, 0, result.stderr)
            report = (Path(d) / "report.md").read_text(encoding="utf-8")
            self.assertIn("P-002: Owner accepts the low-volume cost", report)
            self.assertEqual(findings.contract_problems(Path(d)), [])


class AcceptedNeedsDecision(unittest.TestCase):
    def test_check_requires_a_decisions_line_naming_each_accepted_finding(self):
        doc = complete_doc()
        doc["findings"][1]["status"] = "Accepted"
        self.assertEqual(contract_problems(doc), [
            "P-002: Accepted, but no decisions line names it; record who accepted the cost "
            "and why (findings.py set --decision)"])
        doc["decisions"] = ["Owner accepts P-0021"]  # a longer number is another ID
        self.assertEqual(len(contract_problems(doc)), 1)
        doc["decisions"] = ["P-002: owner accepts the cost"]
        self.assertEqual(contract_problems(doc), [])


if __name__ == "__main__":
    unittest.main()
