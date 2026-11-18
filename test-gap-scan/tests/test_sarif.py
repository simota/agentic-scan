"""sarif.py: one SARIF result per finding to act on."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "test-gap-scan" / "scripts"))
import sarif  # noqa: E402

SAMPLE = json.loads((REPO / "examples" / "findings.sample.json").read_text(encoding="utf-8"))


def export(doc, *extra):
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "findings.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = sarif.main([str(path), *extra])
    return code, json.loads(out.getvalue()) if code == 0 else None


class SarifTests(unittest.TestCase):
    def test_actionable_findings_become_results_at_their_first_location(self):
        code, log = export(copy.deepcopy(SAMPLE))
        self.assertEqual(code, 0)
        self.assertEqual(log["version"], "2.1.0")
        run = log["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "test-gap-scan")
        active = [f for f in SAMPLE["findings"] if f["validation"]["verdict"] not in sarif.LEFT_OUT_VERDICTS]
        self.assertEqual([r["properties"]["findingId"] for r in run["results"]], [f["id"] for f in active])
        first = run["results"][0]
        path, line = SAMPLE["findings"][0]["location"][0].rsplit(":", 1)
        self.assertEqual(first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], path)
        start, _, end = line.partition("-")
        region = first["locations"][0]["physicalLocation"]["region"]
        self.assertEqual((region["startLine"], region.get("endLine")), (int(start), int(end) if end else None))
        self.assertEqual(len(first["relatedLocations"]), len(SAMPLE["findings"][0]["location"]) - 1)
        self.assertIn("asserts", first["properties"])
        self.assertEqual(first["level"], sarif.LEVELS[SAMPLE["findings"][0]["severity"]])

    def test_fixed_and_below_threshold_are_left_out_and_accepted_is_suppressed(self):
        doc = copy.deepcopy(SAMPLE)
        doc["findings"][0]["status"] = "Fixed"
        doc["findings"][1]["status"] = "Accepted"
        _, log = export(doc, "--min-severity", "Medium")
        results = log["runs"][0]["results"]
        ids = [r["properties"]["findingId"] for r in results]
        self.assertNotIn(doc["findings"][0]["id"], ids)
        self.assertTrue(all(r["properties"]["severity"] in ("High", "Medium") for r in results))
        accepted = next(r for r in results if r["properties"]["findingId"] == doc["findings"][1]["id"])
        self.assertEqual(accepted["suppressions"][0]["status"], "accepted")

    def test_the_fingerprint_survives_renumbering(self):
        _, a = export(copy.deepcopy(SAMPLE))
        doc = copy.deepcopy(SAMPLE)
        doc["findings"][0]["location"] = ["moved/elsewhere.py:1"]
        _, b = export(doc)
        self.assertEqual(a["runs"][0]["results"][0]["partialFingerprints"],
                         b["runs"][0]["results"][0]["partialFingerprints"])
        self.assertEqual(list(a["runs"][0]["results"][0]["partialFingerprints"]), ["testGapScan/v1"])

    def test_cited_idiom_ledger_entries_go_under_properties(self):
        _, log = export(copy.deepcopy(SAMPLE))
        cited = next(f for f in SAMPLE["findings"] if f.get("convention"))
        result = next(r for r in log["runs"][0]["results"]
                      if r["properties"]["findingId"] == cited["id"])
        ledger = {c["id"]: c for c in SAMPLE["conventions"]}
        self.assertEqual(result["properties"]["testIdioms"],
                         [{"id": cited["convention"], "idiom": ledger[cited["convention"]]["idiom"],
                           "source": ledger[cited["convention"]]["source"]}])
        self.assertEqual(result["properties"]["testability"], cited["testability"])


if __name__ == "__main__":
    unittest.main()
