"""sarif.py: one SARIF 2.1.0 result per finding to act on, at the line where the subtraction starts."""

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
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import sarif  # noqa: E402

SAMPLE = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
UNITS = json.loads((ROOT / "examples" / "units.sample.json").read_text(encoding="utf-8"))


def by_id(log, fid):
    return next(r for r in log["runs"][0]["results"] if r["properties"]["findingId"] == fid)


def uri(location):
    return location["physicalLocation"]["artifactLocation"]["uri"]


class Sarif(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        (self.tmp / "units.json").write_text(json.dumps(UNITS), encoding="utf-8")

    def export(self, record, *extra):
        (self.tmp / "findings.json").write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sarif.main([str(self.tmp / "findings.json"), *map(str, extra)])
        self.err = err.getvalue()
        return code, json.loads(out.getvalue()) if code == 0 and "--out" not in extra else None

    def test_actionable_findings_become_results_at_their_location(self):
        code, log = self.export(copy.deepcopy(SAMPLE))
        self.assertEqual(code, 0)
        self.assertEqual(log["version"], "2.1.0")
        run = log["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "prune-scan")
        self.assertEqual(run["automationDetails"]["id"], "prune-scan/")
        kept = [f["id"] for f in SAMPLE["findings"] if f["validation"]["verdict"] not in sarif.LEFT_OUT_VERDICTS]
        self.assertEqual([r["properties"]["findingId"] for r in run["results"]], kept)
        self.assertNotIn("P-038", kept)  # The sample's FalsePositive.
        rules = {r["id"] for r in run["tool"]["driver"]["rules"]}
        for f, r in zip((f for f in SAMPLE["findings"] if f["id"] in kept), run["results"]):
            self.assertEqual(r["ruleId"], f["perspective"])
            self.assertIn(r["ruleId"], rules)
            self.assertEqual(r["level"], sarif.LEVELS[f["severity"]])
        leaderboard = by_id(log, "P-007")
        path, line = "server/app.py", 40
        loc = leaderboard["locations"][0]["physicalLocation"]
        self.assertEqual((loc["artifactLocation"]["uri"], loc["region"]["startLine"]), (path, line))
        self.assertEqual(loc["artifactLocation"]["uriBaseId"], "SRCROOT")
        self.assertEqual(leaderboard["properties"]["subtraction"]["action"], "remove")
        self.assertIn("Remove:", leaderboard["message"]["text"])

    def test_levels_map_every_severity(self):
        self.assertEqual(sarif.LEVELS, {"High": "error", "Medium": "warning", "Low": "note", "Info": "note"})

    def test_occurrences_and_entry_point_become_related_locations(self):
        record = copy.deepcopy(SAMPLE)
        f = next(f for f in record["findings"] if f["id"] == "P-007")
        f["occurrences"] = [f["location"], "server/leaderboard.py:5", "server/leaderboard.py:5", "web/a.tsx:3-9"]
        ep = next(e for e in UNITS["entry_points"] if e["id"] == f["entry_ref"])
        f["location"] = "server/leaderboard.py:1"
        _, log = self.export(record)
        related = by_id(log, "P-007")["relatedLocations"]
        self.assertEqual([uri(r) for r in related],
                         ["server/app.py", "server/leaderboard.py", "web/a.tsx", ep["location"].rsplit(":", 1)[0]])
        self.assertEqual([r["id"] for r in related], [1, 2, 3, 4])
        self.assertEqual(related[2]["physicalLocation"]["region"], {"startLine": 3, "endLine": 9})
        self.assertIn(ep["id"], related[3]["message"]["text"])

    def test_left_out_and_suppressed(self):
        record = copy.deepcopy(SAMPLE)
        f1, f2, f3 = (next(f for f in record["findings"] if f["id"] == i) for i in ("P-001", "P-002", "P-008"))
        f1["status"] = "Fixed"
        f2["status"] = "Accepted"
        f3["validation"]["verdict"] = "Unlikely"
        _, log = self.export(record, "--min-severity", "Medium")
        ids = [r["properties"]["findingId"] for r in log["runs"][0]["results"]]
        self.assertNotIn("P-001", ids)
        self.assertNotIn("P-008", ids)
        self.assertTrue(all(r["properties"]["severity"] in ("High", "Medium") for r in log["runs"][0]["results"]))
        self.assertEqual(by_id(log, "P-002")["suppressions"][0]["status"], "accepted")

    def test_the_fingerprint_survives_renumbering_and_moves(self):
        _, a = self.export(copy.deepcopy(SAMPLE))
        record = copy.deepcopy(SAMPLE)
        f = record["findings"][0]
        f["location"], f["occurrences"] = "moved/elsewhere.py:1", []
        f["title"] = "  " + f["title"].upper().replace(" ", "   ")
        _, b = self.export(record)
        first = lambda log: log["runs"][0]["results"][0]["partialFingerprints"]  # noqa: E731
        self.assertEqual(first(a), first(b))
        self.assertIn("pruneScan/v1", first(a))

    def test_repo_binds_srcroot_and_refuses_output_inside_it(self):
        repo = self.tmp / "repo"
        repo.mkdir()
        _, log = self.export(copy.deepcopy(SAMPLE), "--repo", repo)
        self.assertEqual(log["runs"][0]["originalUriBaseIds"]["SRCROOT"]["uri"], repo.resolve().as_uri() + "/")
        code, _ = self.export(copy.deepcopy(SAMPLE), "--repo", repo, "--out", repo / "prune.sarif")
        self.assertEqual(code, 2)
        self.assertIn("outside the reviewed repository", self.err)
        self.assertFalse((repo / "prune.sarif").exists())

    def test_out_writes_the_log_and_never_an_input(self):
        out = self.tmp / "prune.sarif"
        code, _ = self.export(copy.deepcopy(SAMPLE), "--out", out)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["version"], "2.1.0")
        before = (self.tmp / "findings.json").read_bytes()
        code, _ = self.export(copy.deepcopy(SAMPLE), "--out", self.tmp / "findings.json")
        self.assertEqual(code, 2)
        self.assertEqual((self.tmp / "findings.json").read_bytes(), before)

    def test_an_invalid_record_exits_2(self):
        record = copy.deepcopy(SAMPLE)
        record["findings"][0]["severity"] = "Critical"
        code, _ = self.export(record)
        self.assertEqual(code, 2)
        self.assertIn("severity", self.err)


if __name__ == "__main__":
    unittest.main()
