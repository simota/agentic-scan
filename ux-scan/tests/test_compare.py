"""compare.py: matching findings across two reviews and the --fail-on gate."""

import contextlib
import copy
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "ux-scan" / "scripts"))

import compare  # noqa: E402
import findings  # noqa: E402

SAMPLE = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
FLOWS = (ROOT / "examples" / "flows.sample.json").read_text(encoding="utf-8")


def by_id(data, fid):
    return next(f for f in data["findings"] if f["id"] == fid)


def later_review():
    """The sample re-reviewed: renumbered ids, moved lines, one fix, one new finding and one resolved."""
    data = copy.deepcopy(SAMPLE)
    data["meta"]["date"] = "2026-11-01"
    data["findings"] = [f for f in data["findings"] if f["id"] != "U-003"]  # resolved
    by_id(data, "U-001")["status"] = "Fixed"
    by_id(data, "U-007")["severity"] = "High"
    by_id(data, "U-004")["location"] = "src/components/TaskList.tsx:21"
    by_id(data, "U-006")["title"] = "The 480px sidebar overflows a 360px phone viewport"
    by_id(data, "U-012")["validation"]["verdict"] = "NotApplicable"
    by_id(data, "U-010")["location"] = "src/forms/SignupForm.tsx:11"  # the file moved
    new = copy.deepcopy(by_id(data, "U-012"))
    new.update(id="U-027", title="Archive list has no empty state", perspective="FB1",
               location="src/pages/Archive.tsx:5", severity="Medium")
    new["validation"]["verdict"] = "Valid"
    new.pop("occurrences", None)
    data["findings"].append(new)
    # Shuffle the ids, as a fresh review numbers them independently.
    for i, f in enumerate(reversed(data["findings"]), 1):
        f["id"] = f"U-{i:03d}"
    data["summary"] = ""
    data["next_steps"] = []
    data["findings"] = findings.renumber(data, findings.renumber_map(data["findings"]))["findings"]
    return data


class CompareTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.base = self.record("before", SAMPLE)
        self.cur = self.record("after", later_review())

    def record(self, name, data):
        directory = self.dir / name
        directory.mkdir()
        (directory / "flows.json").write_text(FLOWS, encoding="utf-8")
        path = directory / "findings.json"
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return path

    def run_compare(self, *args, base=None, cur=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = compare.main([str(base or self.base), str(cur or self.cur), "--out", "-", *args])
        return code, stdout.getvalue(), stderr.getvalue()

    def result(self, *args):
        code, out, err = self.run_compare("--format", "json", *args)
        self.assertIn(code, (0, 1), err)
        return json.loads(out)

    def changes(self, result, name):
        return sorted((item["baseline"] or {}).get("title") or item["current"]["title"]
                      for item in result["changes"] if item["change"] == name)

    def test_a_review_compared_with_itself_has_no_changes(self):
        code, out, _ = self.run_compare("--fail-on", "Info", cur=self.base)
        self.assertEqual(code, 0)
        self.assertIn("counted, not listed", out)
        same = json.loads(self.run_compare("--format", "json", cur=self.base)[1])
        self.assertEqual(same["unchanged"], same["counts"]["persisting"])
        self.assertEqual(sum(same["counts"].values()), same["unchanged"])
        self.assertTrue(all(not item["notes"] for item in same["changes"]))

    def test_matches_across_renumbering_line_moves_retitles_and_moved_files(self):
        result = self.result()
        self.assertEqual(self.changes(result, "resolved"), ["Task rows open only on mouse click"])
        self.assertEqual(self.changes(result, "fixed"), ["Saving a new task discards the typed title"])
        self.assertEqual(self.changes(result, "new"), ["Archive list has no empty state"])
        self.assertEqual(self.changes(result, "ruled_out"), ["Task list has no loading, empty or error state"])
        self.assertEqual(result["counts"]["regressed"], 0)
        raised = next(item for item in result["changes"] if item["baseline"] and item["baseline"]["id"] == "U-007")
        self.assertEqual(raised["change"], "persisting")
        self.assertIn("severity raised: Medium -> High", raised["notes"])
        moved = next(item for item in result["changes"] if item["baseline"] and item["baseline"]["id"] == "U-010")
        self.assertTrue(any(note.startswith("moved ") for note in moved["notes"]))
        # The retitled sidebar finding and the delete button on a moved line are the same findings.
        persisting = {item["baseline"]["id"] for item in result["changes"] if item["change"] == "persisting"}
        self.assertTrue({"U-004", "U-006"} <= persisting)
        self.assertEqual(result["open"]["baseline"]["High"], 6)
        self.assertEqual(result["open"]["current"]["High"], 5)

    def test_regressions_and_carried_acceptance(self):
        base = copy.deepcopy(SAMPLE)
        by_id(base, "U-005")["status"] = "Fixed"
        by_id(base, "U-009")["status"] = "Accepted"
        result = json.loads(self.run_compare("--format", "json", base=self.record("b2", base), cur=self.base)[1])
        self.assertEqual(self.changes(result, "regressed"),
                         ["Deleting a task is immediate, with no confirmation or undo"])
        accepted = next(item for item in result["changes"] if item["baseline"]["id"] == "U-009")
        self.assertTrue(any("carry the acceptance forward" in note for note in accepted["notes"]))

    def test_gate_trips_on_new_regressed_or_raised_findings_at_or_above_the_severity(self):
        code, _, err = self.run_compare("--fail-on", "High")
        self.assertEqual(code, 1)
        self.assertIn("gate tripped at High", err)
        result = self.result("--fail-on", "Medium")
        blocking = {by_id(json.loads(self.cur.read_text()), fid)["title"] for fid in result["gate"]["blocking"]}
        self.assertEqual(blocking, {"Archive list has no empty state", "Viewport meta disables pinch zoom"})
        self.assertEqual(self.run_compare("--fail-on", "High", cur=self.base)[0], 0)

    def test_markdown_lists_changes_by_kind_in_both_languages(self):
        code, out, _ = self.run_compare("--fail-on", "Medium")
        self.assertEqual(code, 1)
        self.assertIn("## New (1)", out)
        self.assertIn("## Resolved (confirm with after evidence) (1)", out)
        self.assertIn("| High | 6 | 5 | -1 |", out)
        self.assertIn("**Gate:** tripped", out)
        ja = self.run_compare("--lang", "ja")[1]
        self.assertIn("UX診断の比較", ja)
        self.assertIn("## 新規 (1)", ja)

    def test_writes_a_file_and_refuses_to_replace_inputs_or_review_outputs(self):
        out = self.dir / "progress.md"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(compare.main([str(self.base), str(self.cur), "--out", str(out)]), 0)
        self.assertIn("# Tasklane", out.read_text(encoding="utf-8"))
        with contextlib.redirect_stderr(io.StringIO()):
            for target in (self.base, self.cur.with_name("report.html"), self.cur.with_name("flows.json")):
                self.assertEqual(compare.main([str(self.base), str(self.cur), "--out", str(target)]), 2, target)

    def test_refuses_an_invalid_record(self):
        bad = copy.deepcopy(SAMPLE)
        bad["findings"][0]["status"] = "Done"
        code, _, err = self.run_compare(base=self.record("bad", bad))
        self.assertEqual(code, 2)
        self.assertIn("status", err)


if __name__ == "__main__":
    unittest.main()
