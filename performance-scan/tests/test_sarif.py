"""sarif.py: SARIF 2.1.0 export of a record for code scanning and editors."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from support import REPO, SKILL, complete_doc, finding, import_module, run_cli, write_record

sarif = import_module(SKILL / "scripts" / "sarif.py", "perf_sarif")


def results(doc, **kwargs):
    return sarif.to_sarif(doc, **kwargs)["runs"][0]["results"]


class Shape(unittest.TestCase):
    def test_active_findings_become_results_with_rules_levels_and_locations(self):
        doc = complete_doc()
        doc["findings"][1].update(step="", location=["src/a b/x:y.py:3-9"])
        doc["findings"].append(finding("P-003", "Low", status="Fixed"))
        doc["findings"].append(finding("P-004", "Info", validation={
            "verdict": "FalsePositive", "method": "static", "evidence": "a.py:1"}))
        out = sarif.to_sarif(doc)
        self.assertEqual(out["version"], "2.1.0")
        run = out["runs"][0]
        self.assertEqual([r["properties"]["findingId"] for r in run["results"]],
                         ["P-001", "P-002"])
        self.assertEqual([r["level"] for r in run["results"]], ["error", "note"])
        self.assertEqual([rule["id"] for rule in run["tool"]["driver"]["rules"]], ["DB1", "DB"])
        self.assertEqual(run["tool"]["driver"]["rules"][0]["name"], "N+1")
        for r in run["results"]:
            self.assertEqual(run["tool"]["driver"]["rules"][r["ruleIndex"]]["id"], r["ruleId"])
        location = run["results"][1]["locations"][0]["physicalLocation"]
        self.assertEqual(location["artifactLocation"],
                         {"uri": "src/a%20b/x%3Ay.py", "uriBaseId": "%SRCROOT%"})
        self.assertEqual(location["region"], {"startLine": 3, "endLine": 9})
        self.assertTrue(run["results"][0]["message"]["text"].startswith(
            "Order list loads items per order (P-001)\n"))

    def test_every_hunt_step_has_a_description(self):
        steps = sarif.hunt_steps()
        self.assertEqual(set(steps), set(sarif.STEP_PERSPECTIVES))
        self.assertTrue(all(not text.startswith("*") for text in steps.values()))

    def test_absolute_and_windows_paths_are_file_uris(self):
        self.assertEqual(sarif.artifact_location("./app/x.py"),
                         {"uri": "app/x.py", "uriBaseId": "%SRCROOT%"})
        self.assertEqual(sarif.artifact_location("/srv/app/x.py"), {"uri": "file:///srv/app/x.py"})
        self.assertEqual(sarif.artifact_location("C:\\app\\x.py"), {"uri": "file:///C:/app/x.py"})

    def test_record_text_cannot_form_embedded_links(self):
        doc = complete_doc()
        doc["findings"][0]["title"] = "[click](https://evil.example) \\[x](1) \u202e"
        text = results(doc)[0]["message"]["text"]
        self.assertNotIn("[click]", text)
        self.assertIn("\\[click\\](https://evil.example)", text)
        self.assertIn("\\\\\\[x\\](1)", text)
        self.assertIn("\\u202e", text)

    def test_accepted_findings_are_suppressed_with_their_decision(self):
        doc = complete_doc()
        doc["findings"][1]["status"] = "Accepted"
        doc["decisions"] = ["P-002: owner accepts it", "Unrelated"]
        suppressed = results(doc)[1]["suppressions"]
        self.assertEqual(suppressed, [{"kind": "external", "status": "accepted",
                                       "justification": "P-002: owner accepts it"}])
        self.assertNotIn("suppressions", results(doc)[0])

    def test_fingerprints_ignore_ids_and_lines_and_min_severity_filters(self):
        doc = complete_doc()
        moved = deepcopy(doc)
        moved["findings"][0].update(id="P-009", location=["app/orders/serializers.py:99"])
        key = sarif.FINGERPRINT
        self.assertEqual(results(doc)[0]["partialFingerprints"][key],
                         results(moved)[0]["partialFingerprints"][key])
        self.assertEqual(len(results(doc, min_severity="High")), 1)

    def test_baseline_state_follows_the_comparison(self):
        old = complete_doc()
        old["findings"] = [finding()]
        new = complete_doc()
        new["findings"][0]["severity"] = "High"
        new["findings"][1].update(category="Caching", step="CA1", title="Reloads config")
        states = [r["baselineState"] for r in results(new, baseline=old)]
        self.assertEqual(states, ["unchanged", "new"])
        new["findings"][0]["confidence"] = "Environment-dependent"
        self.assertEqual(results(new, baseline=old)[0]["baselineState"], "updated")


class Cli(unittest.TestCase):
    def test_the_sample_exports_and_the_run_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "scan" / "perf.sarif"
            result = run_cli("sarif.py", REPO / "examples" / "findings.sample.json", "--out", out,
                             "--baseline", REPO / "examples" / "findings.sample.baseline.json")
            self.assertEqual(result.returncode, 0, result.stderr)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(len(doc["runs"][0]["results"]), 3)
            record = write_record(Path(d) / "run", "findings.json", complete_doc())
            refused = run_cli("sarif.py", record, "--out", Path(d) / "run" / "perf.sarif")
            self.assertEqual(refused.returncode, 2)
            self.assertFalse((Path(d) / "run" / "perf.sarif").exists())
            bad = write_record(d, "bad.json", {"meta": {}})
            self.assertEqual(run_cli("sarif.py", bad, "--out", out).returncode, 2)


if __name__ == "__main__":
    unittest.main()
