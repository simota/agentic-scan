"""compare.py: matching findings across runs, the buckets, budgets, perspectives and the gate."""
from copy import deepcopy
import json
import tempfile
import unittest

from support import compare, complete_doc, finding, run_cli, run_main, write_record


def entries(result, bucket):
    return [(e["baseline_id"], e["current_id"]) for e in result["findings"][bucket]]


class Matching(unittest.TestCase):
    def test_identical_records_persist_unchanged_and_note_the_shared_revision(self):
        doc = complete_doc()
        doc["meta"]["commit"] = "abc1234"
        result = compare.compare(doc, deepcopy(doc))
        self.assertEqual(entries(result, "persisting"), [("P-001", "P-001"), ("P-002", "P-002")])
        self.assertFalse(any(e["changes"] for e in result["findings"]["persisting"]))
        for bucket in ("new", "resolved", "unchecked"):
            self.assertEqual(result["findings"][bucket], [])
        self.assertEqual([n["kind"] for n in result["notes"]], ["same_commit"])

    def test_renumbered_ids_and_moved_lines_still_match(self):
        old = complete_doc()
        new = deepcopy(old)
        moved = new["findings"][0]
        moved["id"] = "P-002"
        moved["location"] = ["app/orders/serializers.py:57"]
        new["findings"][1]["id"] = "P-001"
        result = compare.compare(old, new)
        self.assertIn(("P-001", "P-002"), entries(result, "persisting"))
        self.assertEqual(result["findings"]["new"], [])

    def test_another_category_is_another_root_cause(self):
        old = complete_doc()
        old["findings"] = [finding()]
        new = deepcopy(old)
        new["findings"][0].update(category="Caching", step="CA1")
        result = compare.compare(old, new)
        self.assertEqual(entries(result, "new"), [(None, "P-001")])
        self.assertEqual(entries(result, "resolved"), [("P-001", None)])

    def test_a_similar_title_matches_after_the_file_moved(self):
        old = complete_doc()
        old["findings"] = [finding()]
        new = deepcopy(old)
        new["findings"][0]["location"] = "app/orders/api/serializers.py:10"
        result = compare.compare(old, new)
        self.assertEqual(entries(result, "persisting"), [("P-001", "P-001")])
        self.assertIn("files", result["findings"]["persisting"][0]["changes"])

    def test_unrelated_title_in_another_file_does_not_match(self):
        old = complete_doc()
        old["findings"] = [finding()]
        new = deepcopy(old)
        new["findings"][0].update(location="app/billing/invoices.py:3",
                                  title="Invoice totals recomputed per line")
        result = compare.compare(old, new)
        self.assertEqual(entries(result, "new"), [(None, "P-001")])


class Buckets(unittest.TestCase):
    def setUp(self):
        self.old = complete_doc()
        self.new = deepcopy(self.old)

    def test_absent_finding_is_resolved_only_when_its_perspective_was_applied(self):
        del self.new["findings"][1]
        result = compare.compare(self.old, self.new)
        self.assertEqual(entries(result, "resolved"), [("P-002", None)])
        for status in ("not checked", "N/A"):
            self.new["perspectives"][0]["status"] = status
            result = compare.compare(self.old, self.new)
            self.assertEqual(result["findings"]["resolved"], [])
            self.assertEqual(entries(result, "unchecked"), [("P-002", None)])
            self.assertEqual(result["findings"]["unchecked"][0]["reason"]["status"], status)

    def test_fixed_and_excluded_findings_are_resolved_with_the_reason(self):
        self.new["findings"][0]["status"] = "Fixed"
        self.new["findings"][1]["validation"] = {"verdict": "FalsePositive", "method": "static",
                                                 "evidence": "app/x.py:1 caps it"}
        result = compare.compare(self.old, self.new)
        reasons = [e["reason"]["kind"] for e in result["findings"]["resolved"]]
        self.assertEqual(reasons, ["fixed", "excluded"])
        self.assertEqual(result["counts"]["current"], {"High": 0, "Medium": 0, "Low": 0, "Info": 0})

    def test_a_finding_fixed_in_the_baseline_that_returns_is_new(self):
        self.old["findings"][0]["status"] = "Fixed"
        result = compare.compare(self.old, self.new)
        self.assertEqual(entries(result, "new"), [("P-001", "P-001")])
        self.assertEqual(result["findings"]["new"][0]["reason"]["kind"], "reappeared")

    def test_changes_are_listed_and_escalation_flagged(self):
        self.old["findings"][1].update(severity="Low")
        self.new["findings"][1].update(severity="High", confidence="Environment-dependent",
                                       status="Accepted")
        changed = compare.compare(self.old, self.new)["findings"]["persisting"]
        entry = next(e for e in changed if e["baseline_id"] == "P-002")
        self.assertTrue(entry["escalated"])
        self.assertEqual(entry["changes"]["severity"], {"from": "Low", "to": "High"})
        self.assertEqual(entry["changes"]["status"], {"from": "Open", "to": "Accepted"})
        self.assertIn("confidence", entry["changes"])

    def test_budgets_match_by_statement_then_id_and_report_status_changes(self):
        self.old["budgets"].append({"id": "B-02", "statement": "Small pages",
                                    "source": "baseline", "status": "holds"})
        self.new["budgets"] = [
            {"id": "B-07", "statement": "Constant  QUERIES", "source": "baseline",
             "status": "holds"},
            {"id": "B-02", "statement": "Pages stay small", "source": "baseline",
             "status": "violated"},
            {"id": "B-03", "statement": "Fresh", "source": "baseline", "status": "holds"}]
        rows = compare.compare(self.old, self.new)["budgets"]
        self.assertIn({"baseline_id": "B-01", "current_id": "B-07", "statement": "Constant  QUERIES",
                       "from": "violated", "to": "holds"}, rows)
        self.assertIn({"baseline_id": "B-02", "current_id": "B-02", "statement": "Pages stay small",
                       "from": "holds", "to": "violated"}, rows)
        self.assertIn({"baseline_id": None, "current_id": "B-03", "statement": "Fresh",
                       "from": None, "to": "holds"}, rows)

    def test_perspective_and_scope_changes(self):
        self.new["perspectives"][3]["status"] = "N/A"
        self.new["meta"]["scope"] = "orders API only"
        result = compare.compare(self.old, self.new)
        self.assertEqual(result["perspectives"],
                         [{"name": self.old["perspectives"][3]["name"], "from": "applied",
                           "to": "N/A"}])
        self.assertEqual(result["notes"][0]["kind"], "scope_differs")


class Gate(unittest.TestCase):
    def run_compare(self, old, new, *args):
        with tempfile.TemporaryDirectory() as directory:
            return run_main(compare.main, write_record(directory, "old.json", old),
                            write_record(directory, "new.json", new), *args)

    def test_new_open_finding_at_the_threshold_fails(self):
        old = complete_doc()
        new = deepcopy(old)
        new["findings"].insert(1, finding("P-002", "Medium", category="Memory", step="ME1",
                                          title="Export holds every row",
                                          location="app/export.py:9"))
        new["findings"][2]["id"] = "P-003"
        code, out, err = self.run_compare(old, new, "--fail-on", "Medium")
        self.assertEqual(code, 1)
        self.assertIn("P-002", err)
        self.assertIn("## New (1)", out)
        code, _, err = self.run_compare(old, new, "--fail-on", "High")
        self.assertEqual(code, 0, err)
        self.assertIn("gate passed", err)

    def test_accepted_or_escalated_findings(self):
        old = complete_doc()
        new = deepcopy(old)
        new["findings"][1]["severity"] = "High"
        code, _, err = self.run_compare(old, new, "--fail-on", "High")
        self.assertEqual(code, 1)
        self.assertIn("P-002", err)
        new["findings"][1]["status"] = "Accepted"
        code, _, _ = self.run_compare(old, new, "--fail-on", "High")
        self.assertEqual(code, 0)

    def test_json_output_carries_the_gate(self):
        doc = complete_doc()
        code, out, _ = self.run_compare(doc, doc, "--format", "json", "--fail-on", "Info")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["gate"], {"fail_on": "Info", "tripped": []})
        self.assertEqual(set(data["findings"]), {"new", "resolved", "unchecked", "persisting"})


class Output(unittest.TestCase):
    def test_markdown_escapes_record_text_and_uses_the_requested_labels(self):
        old = complete_doc()
        new = deepcopy(old)
        new["findings"][0]["title"] = "[click](https://evil.example) <b>|x|</b> @team"
        new["findings"][0]["location"] = "app/orders/serializers.py:42"
        text = compare.render_markdown(compare.compare(old, new), "en")
        self.assertNotIn("](https://", text)
        self.assertNotIn("<b>", text)
        self.assertNotIn("@team", text)
        self.assertIn("&#124;x&#124;", text)
        ja = compare.render_markdown(compare.compare(old, new), "ja")
        self.assertIn("## 継続 (2)", ja)

    def test_invalid_input_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as directory:
            good = write_record(directory, "good.json", complete_doc())
            bad = write_record(directory, "bad.json", {"meta": {}})
            result = run_cli("compare.py", good, bad)
        self.assertEqual(result.returncode, 2)
        self.assertIn("bad.json", result.stderr)

    def test_the_sample_baseline_compares_with_the_sample(self):
        from support import REPO
        result = run_cli("compare.py", REPO / "examples" / "findings.sample.baseline.json",
                         REPO / "examples" / "findings.sample.json", "--fail-on", "High")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("## Resolved (2)", result.stdout)
        self.assertIn("verdict Unverified → Likely", result.stdout)


if __name__ == "__main__":
    unittest.main()
