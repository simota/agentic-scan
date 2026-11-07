"""compare.py --carry: keeping the owner's Accepted triage across a re-scan."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from support import (REPO, compare, complete_doc, contract_problems, finding, findings,
                     run_cli, write_record)


def accepted_baseline():
    old = complete_doc()
    old["meta"]["commit"] = "abc1234"
    old["findings"][1]["status"] = "Accepted"
    old["decisions"] = ["P-002: owner accepts the cost; revisit with P-001 and P-007"]
    return old


class Carry(unittest.TestCase):
    def test_a_persisting_acceptance_is_carried_with_ids_rewritten(self):
        old = accepted_baseline()
        new = deepcopy(old)
        new["findings"][1]["status"] = "Open"
        new["decisions"] = []
        # Renumbered in the new run: a new High comes first, so P-001 is now
        # P-002 and the accepted P-002 is now P-003.
        new["findings"] = [finding("P-001", "High", category="Caching", step="CA1",
                                   title="Permissions reloaded per request",
                                   location=["app/auth/perms.py:3"]),
                           deepcopy(old["findings"][0]), deepcopy(old["findings"][1])]
        new["findings"][1]["id"], new["findings"][2]["id"] = "P-002", "P-003"
        new["findings"][2].update(status="Open", location=["app/orders/serializers.py:50"])
        result = compare.carry(old, new, "en")
        self.assertEqual([(e["baseline_id"], e["current_id"]) for e in result["carried"]],
                         [("P-002", "P-003")])
        self.assertEqual(result["fragment"], {
            "findings": [{"id": "P-003", "status": "Accepted"}],
            "decisions": ["Carried from the baseline (abc1234, 2026-10-09): P-003: owner "
                          "accepts the cost; revisit with P-002 and baseline-P-007"]})
        merged = findings.merge(deepcopy(new), result["fragment"], "carry")
        self.assertEqual(contract_problems(merged), [])

    def test_escalated_fixed_excluded_and_already_accepted_are_not_carried(self):
        old = accepted_baseline()
        new = deepcopy(old)
        new["findings"][1].update(severity="High", status="Open")
        new["findings"][0], new["findings"][1] = new["findings"][1], new["findings"][0]
        new["findings"][0]["id"], new["findings"][1]["id"] = "P-001", "P-002"
        result = compare.carry(old, new, "en")
        self.assertEqual(result["carried"], [])
        self.assertEqual(result["skipped"][0]["reason"],
                         {"kind": "escalated", "old": "Low", "new": "High"})
        self.assertEqual(result["fragment"], {"findings": [], "decisions": []})
        for status in ("Fixed", "Accepted"):
            new = deepcopy(old)
            new["findings"][1]["status"] = status
            self.assertEqual(compare.carry(old, new, "en")["carried"], [])

    def test_an_acceptance_without_a_decision_asks_to_confirm_it(self):
        old = accepted_baseline()
        old["decisions"] = []
        new = deepcopy(old)
        new["findings"][1]["status"] = "Open"
        decisions = compare.carry(old, new, "ja")["fragment"]["decisions"]
        self.assertEqual(len(decisions), 1)
        self.assertTrue(decisions[0].startswith("P-002: ベースライン（abc1234, 2026-10-09）"))

    def test_cli_writes_the_fragment_outside_both_run_directories(self):
        with tempfile.TemporaryDirectory() as d:
            old = write_record(Path(d) / "old", "findings.json", accepted_baseline())
            current = deepcopy(accepted_baseline())
            current["findings"][1]["status"] = "Open"
            new = write_record(Path(d) / "new", "findings.json", current)
            refused = run_cli("compare.py", old, new, "--carry", Path(d) / "new" / "carry.json")
            self.assertEqual(refused.returncode, 2)
            self.assertFalse((Path(d) / "new" / "carry.json").exists())
            out = Path(d) / "scratch" / "carry.json"
            result = run_cli("compare.py", old, new, "--carry", out, "--format", "json")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["carry"]["carried"][0]["current_id"],
                             "P-002")
            self.assertEqual(run_cli("findings.py", "merge", new, out).returncode, 0)
            merged = json.loads(new.read_text(encoding="utf-8"))
            self.assertEqual(merged["findings"][1]["status"], "Accepted")

    def test_the_sample_carries_its_accepted_finding(self):
        with tempfile.TemporaryDirectory() as d:
            run = Path(d) / "run"
            run.mkdir()
            shutil.copy(REPO / "examples" / "findings.sample.json", run / "findings.json")
            fragment = Path(d) / "carry.json"
            result = run_cli("compare.py", REPO / "examples" / "findings.sample.baseline.json",
                             run / "findings.json", "--carry", fragment)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("## Carried acceptances", result.stdout)
            self.assertEqual(run_cli("findings.py", "merge", run / "findings.json",
                                     fragment).returncode, 0)
            self.assertEqual(run_cli("render.py", run / "findings.json", "--out",
                                     run).returncode, 0)
            self.assertEqual(findings.contract_problems(run), [])


if __name__ == "__main__":
    unittest.main()
