import json
from pathlib import Path
import tempfile
import unittest

from helpers import EXAMPLES, clone, compare, findings, run, sample, write_json


def by_class(result, cls):
    return sorted(e["id"] or e["baseline_id"] for e in result[cls])


class CompareTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.base = sample()

    def run_compare(self, current, *args, baseline=None):
        write_json(self.dir / "base.json", baseline or self.base)
        write_json(self.dir / "cur.json", current)
        return run(compare.main, self.dir / "base.json", self.dir / "cur.json", *args)

    def test_identical_reviews_persist_everything(self):
        result = compare.compare(self.base, clone(self.base))
        self.assertEqual(result["summary"], {"new": 0, "reopened": 0, "persisting": 12, "resolved": 0, "dismissed": 0})
        self.assertTrue(all(not e["changes"] for e in result["persisting"]))

    def test_renumbered_moved_and_reworded_findings_still_match(self):
        cur = clone(self.base)
        f1 = next(f for f in cur["findings"] if f["id"] == "F-001")
        f1.update(id="F-099", location="app/llm/answer.py:16", title=f1["title"] + " at render time")
        result = compare.compare(self.base, cur)
        moved = next(e for e in result["persisting"] if e["id"] == "F-099")
        self.assertEqual(moved["baseline_id"], "F-001")
        self.assertEqual(result["summary"]["new"], 0)

    def test_a_review_in_the_other_language_matches_by_location(self):
        result = compare.compare(sample("ja"), self.base)
        self.assertEqual(result["summary"]["persisting"], 12)

    def test_classes(self):
        cur = clone(self.base)
        fs = cur["findings"]
        fs[:] = [f for f in fs if f["id"] != "F-003"]
        next(f for f in fs if f["id"] == "F-002")["severity"] = "Medium"
        next(f for f in fs if f["id"] == "F-005")["validation"] = {
            "verdict": "FalsePositive", "evidence": "delimited upstream", "method": "static"}
        fs.append(dict(clone(fs[0]), id="F-020", category="Examples", title="No example of a refusal"))
        base = clone(self.base)
        next(f for f in base["findings"] if f["id"] == "F-006")["validation"] = {
            "verdict": "NotApplicable", "evidence": "x", "method": "static"}
        result = compare.compare(base, cur)
        self.assertEqual(by_class(result, "new"), ["F-020"])
        self.assertEqual(by_class(result, "resolved"), ["F-003"])
        self.assertEqual(by_class(result, "dismissed"), ["F-005"])
        self.assertEqual(by_class(result, "reopened"), ["F-006"])
        changed = next(e for e in result["persisting"] if e["id"] == "F-002")
        self.assertEqual(changed["changes"], {"severity": ["High", "Medium"]})

    def test_an_unrelated_finding_in_the_same_file_and_perspective_is_not_paired(self):
        cur = clone(self.base)
        f2 = next(f for f in cur["findings"] if f["id"] == "F-002")
        f2.update(title="Completely different concern about streaming", location="app/llm/answer.py:5")
        result = compare.compare(self.base, cur)
        self.assertIn("F-002", by_class(result, "new"))
        self.assertIn("F-002", by_class(result, "resolved"))

    def test_lint_findings_match_by_rule_and_title_not_by_id(self):
        cur = clone(self.base)
        for f in cur["findings"]:
            if f["id"] == "L-001":
                f["id"] = "L-002"
            elif f["id"] == "L-002":
                f["id"] = "L-001"
        result = compare.compare(self.base, cur)
        pairs = {e["id"]: e["baseline_id"] for e in result["persisting"] if e["id"].startswith("L-")}
        self.assertEqual(pairs, {"L-001": "L-002", "L-002": "L-001", "L-003": "L-003", "L-004": "L-004"})

    def test_markdown_and_json_outputs(self):
        code, out, err = self.run_compare(clone(self.base))
        self.assertEqual(code, 0, err)
        self.assertIn("0 new, 0 reopened, 12 persisting", out)
        code, out, _ = self.run_compare(clone(self.base), "--json")
        self.assertEqual(json.loads(out)["tool"], "compare.py")
        code, out, _ = self.run_compare(clone(self.base), "--lang", "ja")
        self.assertIn("新規 0 件", out)

    def test_fail_on_counts_only_new_and_reopened_findings(self):
        cur = clone(self.base)
        code, _, _ = self.run_compare(cur, "--fail-on", "High")
        self.assertEqual(code, 0, "known High findings are not a regression")
        cur["findings"].append(dict(clone(cur["findings"][0]), id="F-030", category="Safety and refusal",
                                    title="New high defect"))
        code, _, err = self.run_compare(cur, "--fail-on", "High")
        self.assertEqual(code, 1)
        self.assertIn("F-030", err)
        low = clone(self.base)
        low["findings"].append(dict(clone(low["findings"][0]), id="F-030", severity="Low",
                                    category="Safety and refusal", title="New low defect"))
        self.assertEqual(self.run_compare(low, "--fail-on", "Medium")[0], 0)

    def test_accepted_fragment_carries_acceptance_into_the_new_review(self):
        base = clone(self.base)
        next(f for f in base["findings"] if f["id"] == "F-007")["status"] = "Accepted"
        cur = clone(self.base)
        next(f for f in cur["findings"] if f["id"] == "F-007")["id"] = "F-077"
        for f in cur["findings"]:
            if f["id"] == "F-008":
                f["id"] = "F-007"
        cur_path = self.dir / "cur.json"
        frag = self.dir / "accepted.json"
        code, _, err = self.run_compare(cur, "--accepted-fragment", frag, "--out", self.dir / "cmp.md", baseline=base)
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(frag.read_text()), {"findings": [{"id": "F-077", "status": "Accepted"}]})
        self.assertEqual(run(findings.main, "merge", cur_path, frag)[0], 0)
        merged = json.loads(cur_path.read_text())
        self.assertEqual(next(f for f in merged["findings"] if f["id"] == "F-077")["status"], "Accepted")

    def test_refuses_to_overwrite_a_compared_file_and_reports_schema_errors(self):
        write_json(self.dir / "base.json", self.base)
        code, _, err = run(compare.main, self.dir / "base.json", self.dir / "base.json", "--out", self.dir / "base.json")
        self.assertEqual(code, 2)
        self.assertIn("compared files", err)
        write_json(self.dir / "bad.json", {"findings": [{"id": "X"}]})
        code, _, err = run(compare.main, self.dir / "bad.json", EXAMPLES / "findings.sample.json")
        self.assertEqual(code, 2)
        self.assertIn("findings[0].id", err)

    def test_credential_shaped_text_is_masked(self):
        cur = clone(self.base)
        cur["findings"][0]["title"] = "key sk-ant-" + "a" * 30 + " leaked"
        _, out, _ = self.run_compare(cur)
        self.assertNotIn("a" * 30, out)


if __name__ == "__main__":
    unittest.main()
