"""plan.py: an ordered removal plan from a settled record, the hand-off to the removal request."""

import contextlib
import copy
import hashlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import plan  # noqa: E402

SAMPLE = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
SAMPLE_JA = json.loads((ROOT / "examples" / "findings.sample.ja.json").read_text(encoding="utf-8"))
UNITS = json.loads((ROOT / "examples" / "units.sample.json").read_text(encoding="utf-8"))


def by_id(record, fid):
    return next(f for f in record["findings"] if f["id"] == fid)


class Plans(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        (self.tmp / "units.json").write_text(json.dumps(UNITS), encoding="utf-8")

    def plan(self, record, *extra):
        target = self.tmp / "findings.json"
        target.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = plan.main([str(target), "--json", str(self.tmp / "plan.json"), *map(str, extra)])
        self.assertEqual(code, 0, err.getvalue())
        return json.loads((self.tmp / "plan.json").read_text(encoding="utf-8")), out.getvalue()

    def test_sample_plan_groups_and_orders(self):
        result, text = self.plan(SAMPLE)
        steps = [s["id"] for s in result["steps"]]
        now = [s["id"] for s in result["steps"] if s["wave"] == "now"]
        reduce = [s["id"] for s in result["steps"] if s["wave"] == "reduce"]
        self.assertEqual(len(now), 25)
        self.assertEqual(reduce, ["P-005", "P-014", "P-027"])
        self.assertEqual(steps[:len(now)], now)  # Remove-now steps come first.
        # "Remove after P-010": the dependency moves P-006 below P-010, keeping severity order otherwise.
        self.assertEqual(now[:6], ["P-001", "P-002", "P-004", "P-007", "P-010", "P-006"])
        p006 = next(s for s in result["steps"] if s["id"] == "P-006")
        self.assertEqual(p006["after"], ["P-010"])
        self.assertEqual(p006["files"], ["package.json", "web/src/pages/Item.tsx"])
        p020 = next(s for s in result["steps"] if s["id"] == "P-020")
        self.assertEqual(p020["with"], ["P-003"])  # "stripe goes with P-003": shown, not reordered.
        p001 = next(s for s in result["steps"] if s["id"] == "P-001")
        self.assertEqual((p001["after"], p001["related"]), ([], ["P-009"]))
        self.assertEqual([d["id"] for d in result["decide"]],
                         ["P-003", "P-008", "P-009", "P-012", "P-021", "P-022", "P-024", "P-025"])
        decide = {d["id"]: d for d in result["decide"]}
        self.assertTrue(decide["P-003"]["question"][0].startswith("P-003: confirm the Stripe webhook"))
        self.assertEqual(result["blocked"], [])
        self.assertEqual(result["kept"], {"Excluded": 1})  # P-037 FalsePositive.
        self.assertEqual(result["shared_files"]["package.json"], ["P-006", "P-018", "P-019"])
        raw = (self.tmp / "findings.json").read_bytes()
        self.assertEqual(result["record"]["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertIn("- [ ] 6. **P-006** · Medium · Dependency moment — `package.json:15`", text)
        self.assertIn("  - Coordinate with: P-003 (still to decide)", text)
        self.assertIn("## Decide with a human first (8)", text)

    def test_steps_wait_for_undecided_or_kept_prerequisites(self):
        record = copy.deepcopy(SAMPLE)
        by_id(record, "P-016")["risk"] = "Remove after P-003, once the webhook is gone."
        by_id(record, "P-017")["risk"] = "Only after P-016."  # Waits through another step.
        by_id(record, "P-026")["risk"] = "After P-023."
        by_id(record, "P-023")["status"] = "Accepted"
        by_id(record, "P-028")["risk"] = "After P-029."
        by_id(record, "P-029")["status"] = "Fixed"  # A Fixed prerequisite is satisfied.
        result, text = self.plan(record)
        blocked = {b["id"]: b["waits_for"] for b in result["blocked"]}
        self.assertEqual(sorted(blocked), ["P-016", "P-017", "P-026"])
        self.assertTrue(blocked["P-016"][0].startswith("P-003 is still to decide"))
        self.assertEqual(blocked["P-017"], blocked["P-016"])
        self.assertIn("P-023 is kept (Accepted", blocked["P-026"][0])
        self.assertIn("P-028", [s["id"] for s in result["steps"]])
        self.assertNotIn("P-016", [s["id"] for s in result["steps"]])
        self.assertEqual(next(d for d in result["decide"] if d["id"] == "P-003")["unblocks"], ["P-016", "P-017"])
        self.assertEqual(result["kept"], {"Accepted": 1, "Fixed": 1, "Excluded": 1})
        self.assertIn("## Waits for a decision (3)", text)

    def test_reduce_prerequisite_moves_a_removal_into_the_later_wave(self):
        record = copy.deepcopy(SAMPLE)
        by_id(record, "P-002")["risk"] = "After P-005."
        result, _ = self.plan(record)
        reduce = [s["id"] for s in result["steps"] if s["wave"] == "reduce"]
        self.assertEqual(reduce, ["P-005", "P-002", "P-014", "P-027"])

    def test_cycles_are_reported_not_dropped(self):
        record = copy.deepcopy(SAMPLE)
        by_id(record, "P-028")["risk"] = "After P-029."
        by_id(record, "P-029")["risk"] = "After P-028."
        result, _ = self.plan(record)
        blocked = {b["id"]: b["waits_for"] for b in result["blocked"]}
        self.assertEqual(sorted(blocked), ["P-028", "P-029"])
        self.assertIn("cycle with P-029", blocked["P-028"][0])

    def test_unit_filter_names_prerequisites_outside(self):
        result, text = self.plan(SAMPLE, "--unit", "UN-05")
        units = {s["unit_ref"] for s in result["steps"] + result["decide"]}
        self.assertEqual(units, {"UN-05"})
        p006 = next(s for s in result["steps"] if s["id"] == "P-006")
        self.assertEqual(p006["first_outside"], ["P-010"])
        self.assertIn("P-010 first (outside the selected units)", text)
        self.assertIn("Units: UN-05.", text)

    def test_japanese_ordering_prose(self):
        result, text = self.plan(SAMPLE_JA, "--lang", "ja")
        p006 = next(s for s in result["steps"] if s["id"] == "P-006")
        self.assertEqual(p006["after"], ["P-010"])  # "P-010 の後に行わないと"
        p007 = next(s for s in result["steps"] if s["id"] == "P-007")
        self.assertEqual(p007["with"], ["P-024"])  # "P-024 の移行で併せて削除"
        self.assertIn("## 今すぐ削除 (25)", text)
        self.assertIn("  - 前提: P-010", text)

    def test_references_ignore_paths_shaped_like_ids(self):
        record = copy.deepcopy(SAMPLE)
        by_id(record, "P-028")["risk"] = "After docs/P-029.md is read; see P-030."
        result, _ = self.plan(record)
        p028 = next(s for s in result["steps"] if s["id"] == "P-028")
        self.assertEqual((p028["after"], p028["related"]), ([], ["P-030"]))

    def test_markdown_code_spans_survive_backticks(self):
        self.assertEqual(plan.code("a`b"), "``a`b``")
        self.assertEqual(plan.code("`x"), "`` `x ``")

    def test_out_writes_markdown_and_refuses_inputs(self):
        target = self.tmp / "findings.json"
        target.write_text(json.dumps(SAMPLE), encoding="utf-8")
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            self.assertEqual(plan.main([str(target), "--out", str(self.tmp / "plan.md")]), 0)
            self.assertEqual(plan.main([str(target), "--out", str(target)]), 2)
            self.assertEqual(plan.main([str(target), "--out", str(self.tmp / "units.json")]), 2)
            self.assertEqual(plan.main([str(target), "--out", str(self.tmp / "p"), "--json", str(self.tmp / "p")]), 2)
            self.assertEqual(plan.main([str(target), "--unit", "UN-99"]), 2)
            self.assertEqual(plan.main([str(self.tmp / "missing.json")]), 2)
        self.assertTrue((self.tmp / "plan.md").read_text(encoding="utf-8").startswith("# Removal plan: Larder"))
        self.assertIn("overwrite an input", err.getvalue())
        self.assertIn("UN-99", err.getvalue())
        self.assertEqual(json.loads(target.read_text(encoding="utf-8")), SAMPLE)

    def test_directory_argument_reads_its_findings(self):
        (self.tmp / "findings.json").write_text(json.dumps(SAMPLE), encoding="utf-8")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(plan.main([str(self.tmp)]), 0)
        self.assertTrue(out.getvalue().startswith("# Removal plan"))


if __name__ == "__main__":
    unittest.main()
