"""sarif.py: findings.json as a SARIF 2.1.0 log for code scanning and editors."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "infra-scan" / "scripts"))
import sarif  # noqa: E402

SAMPLE = ROOT / "examples" / "findings.sample.json"
SAMPLE_JA = ROOT / "examples" / "findings.sample.ja.json"


def sample(path=SAMPLE):
    return json.loads(path.read_text(encoding="utf-8"))


def results(log):
    return log["runs"][0]["results"]


def by_id(log):
    return {r["properties"]["id"]: r for r in results(log)}


class StructureTest(unittest.TestCase):
    def test_log_shape_and_rules(self):
        log = sarif.build(sample())
        self.assertEqual(log["version"], "2.1.0")
        run = log["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        ids = [r["id"] for r in rules]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids, sorted(ids))
        for r in results(log):
            self.assertIn(r["ruleId"], ids)
            self.assertIn(r["level"], ("error", "warning", "note"))
            self.assertTrue(r["message"]["text"])
        self.assertEqual(run["properties"]["project"], sample()["meta"]["project"])

    def test_every_finding_is_a_result_by_default(self):
        data = sample()
        self.assertEqual(sorted(by_id(sarif.build(data))), sorted(f["id"] for f in data["findings"]))

    def test_baseline_rule_metadata_and_review_rules(self):
        log = sarif.build(sample())
        rules = {r["id"]: r for r in log["runs"][0]["tool"]["driver"]["rules"]}
        self.assertEqual(rules["AWS-NET-001"]["shortDescription"]["text"],
                         "Security group allows internet ingress to an admin or data port")
        self.assertIn("external/cwe/cwe-284", rules["AWS-NET-001"]["properties"]["tags"])
        self.assertTrue(rules["AWS-NET-001"]["properties"]["controls"])
        self.assertEqual(by_id(log)["F-001"]["ruleId"], "review/data-protection")

    def test_rule_severity_is_its_worst_result(self):
        data = sample()
        data["findings"] = [f for f in data["findings"] if f["id"] in ("F-001", "F-002")]
        for f, sev in zip(data["findings"], ("Low", "High")):
            f["severity"], f["category"] = sev, "Data protection"
        rule = sarif.build(data)["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertEqual(rule["properties"]["security-severity"], "8.0")
        self.assertEqual(rule["defaultConfiguration"]["level"], "error")

    def test_location_region_and_logical_resources(self):
        r = by_id(sarif.build(sample()))["F-001"]
        loc = r["locations"][0]
        self.assertEqual(loc["physicalLocation"]["artifactLocation"],
                         {"uri": "envs/prod/gcp/storage.tf", "uriBaseId": "%SRCROOT%"})
        self.assertEqual(loc["physicalLocation"]["region"], {"startLine": 27})
        self.assertEqual(loc["logicalLocations"][0]["fullyQualifiedName"],
                         "google_storage_bucket_iam_member.exports_public")

    def test_ranges_spaces_and_snapshots(self):
        self.assertEqual(sarif.physical("env prod/main.tf:3-9"),
                         {"artifactLocation": {"uri": "env%20prod/main.tf", "uriBaseId": "%SRCROOT%"},
                          "region": {"startLine": 3, "endLine": 9}})
        self.assertEqual(sarif.physical("@snapshots/exports/sg.json:4")["artifactLocation"],
                         {"uri": "exports/sg.json", "uriBaseId": "SNAPSHOTS"})
        self.assertIsNone(sarif.physical("no line here"))

    def test_attack_paths_become_code_flows(self):
        r = by_id(sarif.build(sample()))["F-001"]
        flow = r["codeFlows"][0]
        self.assertTrue(flow["message"]["text"].startswith("AP-04"))
        steps = flow["threadFlows"][0]["locations"]
        self.assertTrue(steps)
        for step in steps:
            self.assertTrue(step["location"]["message"]["text"])
        cited = [s["location"]["physicalLocation"] for s in steps if "physicalLocation" in s["location"]]
        self.assertTrue(cited)
        self.assertNotIn("artifactLocation", steps[0]["location"])  # nested under physicalLocation


class IdentityTest(unittest.TestCase):
    def test_fingerprint_survives_renumbering_and_line_moves(self):
        data = sample()
        before = {r["properties"]["id"]: r["partialFingerprints"]["infraScan/v1"] for r in results(sarif.build(data))}
        moved = copy.deepcopy(data)
        f = next(x for x in moved["findings"] if x["id"] == "F-001")
        f["id"] = "F-900"
        f["location"] = f["location"].rsplit(":", 1)[0] + ":99"
        for a in moved["attack_paths"]:
            a["findings"] = ["F-900" if i == "F-001" else i for i in a.get("findings", [])]
        after = by_id(sarif.build(moved))["F-900"]["partialFingerprints"]["infraScan/v1"]
        self.assertEqual(before["F-001"], after)

    def test_fingerprints_differ_between_root_causes(self):
        prints = [r["partialFingerprints"]["infraScan/v1"] for r in results(sarif.build(sample()))]
        self.assertEqual(len(prints), len(set(prints)))


class SelectionTest(unittest.TestCase):
    def test_excluded_and_covered_are_suppressed(self):
        data = sample()
        log = by_id(sarif.build(data))
        excluded = [f["id"] for f in data["findings"]
                    if f["validation"]["verdict"] in ("FalsePositive", "NotApplicable")]
        self.assertTrue(excluded)
        for fid in excluded:
            s = log[fid]["suppressions"][0]
            self.assertEqual((s["kind"], s["status"]), ("external", "accepted"))
            self.assertIn("Excluded after triage", s["justification"])
        data["findings"][0]["validation"]["evidence"] += " Root cause of I-001."
        covered = by_id(sarif.build(data))["I-001"]["suppressions"][0]["justification"]
        self.assertIn(data["findings"][0]["id"], covered)

    def test_counted_only_and_min_severity(self):
        data = sample()
        counted = by_id(sarif.build(data, counted_only=True))
        self.assertFalse(any(r.get("suppressions") for r in counted.values()))
        high = results(sarif.build(data, min_severity="High"))
        self.assertTrue(high)
        self.assertEqual({r["properties"]["severity"] for r in high}, {"High"})


class TextTest(unittest.TestCase):
    def test_credentials_are_redacted_and_mask_hides_accounts(self):
        data = sample()
        key = "AKIA" + "Q" * 16
        data["findings"][0]["impact"] = f"Key {key} in account 123456789012 at 10.1.2.3"
        text = json.dumps(sarif.build(data, masked=True))
        self.assertNotIn(key, text)
        self.assertNotIn("123456789012", text)
        self.assertNotIn("10.1.2.3", text)
        self.assertIn("<account-id>", text)
        self.assertIn("123456789012", json.dumps(sarif.build(data)))

    def test_markdown_carries_no_raw_html(self):
        data = sample()
        data["findings"][0]["fix"] = "Remove <script>alert(1)</script> ‮"
        md = by_id(sarif.build(data))[data["findings"][0]["id"]]["message"]["markdown"]
        self.assertNotIn("<script>", md)
        self.assertNotIn("‮", md)

    def test_japanese_labels(self):
        log = sarif.build(sample(SAMPLE_JA), lang="ja")
        text = results(log)[0]["message"]["text"]
        self.assertIn("深刻度", text)
        rules = log["runs"][0]["tool"]["driver"]["rules"]
        self.assertTrue(any("レビューの検出事項" in r["shortDescription"]["text"] for r in rules))


class CliTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="sarif-test-")
        self.tmp = Path(self._tmp.name)
        self.out = self.tmp / "out"
        self.out.mkdir()
        (self.out / "findings.json").write_text(SAMPLE.read_text(encoding="utf-8"), encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def test_writes_a_log_to_scratch(self):
        target = self.tmp / "scratch" / "infra.sarif"
        self.assertEqual(sarif.main([str(self.out / "findings.json"), "--out", str(target)]), 0)
        self.assertEqual(json.loads(target.read_text(encoding="utf-8"))["version"], "2.1.0")

    def test_refuses_the_output_directory_and_symlinks(self):
        self.assertEqual(sarif.main([str(self.out / "findings.json"), "--out", str(self.out / "x.sarif")]), 1)
        self.assertFalse((self.out / "x.sarif").exists())
        real = self.tmp / "real.sarif"
        real.write_text("{}", encoding="utf-8")
        link = self.tmp / "link.sarif"
        os.symlink(real, link)
        self.assertEqual(sarif.main([str(self.out / "findings.json"), "--out", str(link)]), 1)
        self.assertEqual(real.read_text(encoding="utf-8"), "{}")
        (self.tmp / "dir.sarif").mkdir()
        self.assertEqual(sarif.main([str(self.out / "findings.json"), "--out", str(self.tmp / "dir.sarif")]), 1)

    def test_schema_error_exits_2(self):
        bad = self.tmp / "bad.json"
        bad.write_text(json.dumps({"schema_version": 1, "findings": [{"id": "F-1"}]}), encoding="utf-8")
        self.assertEqual(sarif.main([str(bad), "--out", str(self.tmp / "a.sarif")]), 2)


if __name__ == "__main__":
    unittest.main()
