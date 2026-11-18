"""The seeded detection benchmark: ground truth resolves and the scorer counts correctly."""
import importlib.util
from pathlib import Path
import re
import unittest

REPO = Path(__file__).resolve().parents[1]
BENCH = REPO / "benchmarks"
spec = importlib.util.spec_from_file_location("bench_score", BENCH / "score.py")
score = importlib.util.module_from_spec(spec)
spec.loader.exec_module(score)


def finding(fid, path, line, step="BD1", verdict="Valid"):
    return {"id": fid, "step": step, "title": fid, "location": [f"{path}:{line}"],
            "validation": {"verdict": verdict}}


TRUTHS = sorted(BENCH.glob("ground-truth*.json"))


class GroundTruthTests(unittest.TestCase):
    def test_every_anchor_resolves_to_one_line(self):
        self.assertGreaterEqual(len(TRUTHS), 2)
        for path in TRUTHS:
            truth = score.load_truth(path)
            self.assertGreaterEqual(len(truth["cases"]), 10, path.name)
            self.assertGreaterEqual(len(truth["decoys"]), 5, path.name)
            ids = [entry["id"] for entry in truth["cases"] + truth["decoys"]]
            self.assertEqual(len(ids), len(set(ids)), path.name)

    def test_sites_of_different_entries_cannot_be_confused(self):
        for path in TRUTHS:
            truth = score.load_truth(path)
            reach = 2 * truth["line_tolerance"]
            sites = sorted((site["file"], site["line"], entry["id"])
                           for entry in truth["cases"] + truth["decoys"] for site in entry["sites"])
            for (file_a, line_a, id_a), (file_b, line_b, id_b) in zip(sites, sites[1:]):
                if file_a == file_b and id_a != id_b:
                    self.assertGreater(line_b - line_a, reach, f"{path.name}: {id_a} and {id_b}")

    def test_case_steps_are_logic_scan_steps(self):
        text = (REPO / "skills" / "logic-scan" / "reference" / "perspectives.md").read_text(encoding="utf-8")
        known = set(re.findall(r"^\| ([A-Z]{2}[0-9]+) \|", text, re.MULTILINE))
        for path in TRUTHS:
            for case in score.load_truth(path)["cases"]:
                for step in case["steps"]:
                    self.assertIn(step, known, f"{path.name} {case['id']}")

    def test_fixtures_do_not_hint_at_their_defects(self):
        hint = re.compile(r"(?i)\b(bug|seeded|defect|wrong|incorrect|fixme|todo|hack|GT-|DC-)")
        for fixture in BENCH.glob("fixture-*"):
            for path in fixture.rglob("*"):
                if path.is_file() and path.suffix in {".py", ".md", ".js", ".json"}:
                    self.assertIsNone(hint.search(path.read_text(encoding="utf-8")), path)


class ScoreTests(unittest.TestCase):
    def setUp(self):
        self.truth = score.load_truth()

    def at(self, entry, offset=0):
        site = entry["sites"][0]
        return site["file"], site["line"] + offset

    def test_one_finding_per_case_is_full_recall_and_no_false_positive(self):
        found = [finding(f"F-{n:03d}", "shop-app/" + self.at(case)[0], self.at(case)[1], case["steps"][0])
                 for n, case in enumerate(self.truth["cases"], 1)]
        result = score.score({"findings": found}, self.truth)
        self.assertEqual(result["recall"], 1.0)
        self.assertEqual(result["step_correct"], len(self.truth["cases"]))
        self.assertEqual(result["decoys_flagged"], 0)
        self.assertEqual(result["unseeded"], [])

    def test_tolerance_bounds_a_match(self):
        case = self.truth["cases"][0]
        path, line = self.at(case)
        near = score.score({"findings": [finding("F-001", path, line + 2)]}, self.truth)
        far = score.score({"findings": [finding("F-001", path, line + 3)]}, self.truth)
        self.assertEqual(near["detected"], 1)
        self.assertEqual(far["detected"], 0)

    def test_a_range_covering_the_anchor_matches(self):
        path, line = self.at(self.truth["cases"][0])
        found = {"findings": [{"id": "F-001", "location": f"{path}:{line - 10}-{line + 10}"}]}
        self.assertEqual(score.score(found, self.truth)["detected"], 1)

    def test_a_decoy_hit_is_a_false_positive_and_excluded_verdicts_are_ignored(self):
        path, line = self.at(self.truth["decoys"][0])
        result = score.score({"findings": [finding("F-001", path, line),
                                           finding("F-002", path, line, verdict="FalsePositive")]}, self.truth)
        self.assertEqual(result["decoys_flagged"], 1)
        self.assertEqual(result["decoy_results"][0]["flagged_by"], ["F-001"])
        self.assertEqual(result["findings"], 1)

    def test_a_finding_elsewhere_is_unseeded(self):
        result = score.score({"findings": [finding("F-001", "shop/config.py", 1)]}, self.truth)
        self.assertEqual(result["detected"], 0)
        self.assertEqual([u["id"] for u in result["unseeded"]], ["F-001"])


if __name__ == "__main__":
    unittest.main()
