"""An I-* quotes the configuration it was found in. Text the scanner wrote is
not the reviewer's prose: a renumber leaves it alone, it holds no stale
reference, and the contract does not ask the reviewer to reword it."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-scan" / "scripts"))
import contract_check  # noqa: E402
import findings  # noqa: E402
import iac_scan  # noqa: E402
import render  # noqa: E402

# A module pinned to a branch named like a finding ID: PS-001 quotes the ref.
MODULE = 'module "vpc" {\n  source = "git::https://example.com/org/vpc.git?ref=F-123"\n}\n'


def call(main, *argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = main([str(a) for a in argv])
    return code, out.getvalue()


class ScannerOwnedTextTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo, self.out = self.root / "repo", self.root / "out"
        self.repo.mkdir()
        self.record = self.out / "findings.json"

    def scan(self, *extra):
        code, out = call(iac_scan.main, self.repo, "--out", self.out / "iac.json", "--into", self.record, *extra)
        self.assertEqual(code, 0, out)
        return json.loads(self.record.read_text(encoding="utf-8"))

    def review(self, fid, baseline):
        """Merge one review finding on an attack path and triage every I-*."""
        fragment = self.root / "review.json"
        fragment.write_text(json.dumps({
            "meta": {"project": "example", "scope": "test", "date": "2026-10-26", "assessor": "test", "axis": "confirmed"},
            "perspectives": [{"name": n, "status": "Applied"} for n in render.perspective_names()],
            "attack_paths": [{"id": "AP-01", "entry": "Internet", "target": "Network", "status": "open",
                              "edges": ["Module from a branch (main.tf:2)"], "findings": [fid]}],
            "findings": [{
                "id": fid, "title": "Unpinned module", "severity": "Low", "confidence": "Confirmed",
                "category": "Pipeline and state", "provider": "aws", "resources": ["module.vpc"],
                "location": "main.tf:2", "actor": "Module author", "path": "1. Branch ref (main.tf:2)",
                "impact": "Module may change", "fix": "Pin a tag", "regression": "Require ?ref=v*",
                "contrast": "none", "attack_paths": ["AP-01"],
                "validation": {"verdict": "Valid", "evidence": "main.tf:2"},
            }] + [{"id": f["id"], "validation": {"verdict": "Unlikely", "evidence": "triaged by the test"}}
                  for f in baseline["findings"]],
        }), encoding="utf-8")
        code, out = call(findings.main, "merge", self.record, fragment)
        self.assertEqual(code, 0, out)

    def assert_contract_passes(self):
        code, out = call(render.main, self.record, "--out", self.out, "--no-pdf")
        self.assertEqual(code, 0, out)
        code, out = call(contract_check.main, self.out, "--no-pdf")
        self.assertEqual(code, 0, out)

    def scanner_detail(self):
        data = json.loads(self.record.read_text(encoding="utf-8"))
        return next(f["detail"] for f in data["findings"] if f["id"].startswith("I-"))

    def test_an_id_quoted_by_the_scanner_is_not_a_stale_reference(self):
        (self.repo / "main.tf").write_text(MODULE, encoding="utf-8")
        baseline = self.scan()
        self.assertIn("F-123", self.scanner_detail())
        self.review("F-901", baseline)
        code, out = call(findings.main, "status", self.record)
        self.assertEqual(code, 0, out)
        self.assertNotIn("dangling", out.split("\n", 1)[1])
        code, out = call(findings.main, "renumber", self.record)
        self.assertEqual(code, 0, out)
        self.assertIn("ref=F-123", self.scanner_detail())
        self.assert_contract_passes()

    def test_renumber_does_not_rewrite_scanner_text(self):
        (self.repo / "main.tf").write_text(MODULE, encoding="utf-8")
        baseline = self.scan()
        self.review("F-123", baseline)  # a provisional ID that the scanner happens to quote
        code, out = call(findings.main, "renumber", self.record)
        self.assertEqual(code, 0, out)
        self.assertIn("ref=F-123", self.scanner_detail())
        self.assert_contract_passes()

    def test_a_triage_still_follows_a_renumber(self):
        (self.repo / "main.tf").write_text(MODULE, encoding="utf-8")
        baseline = self.scan()
        self.review("F-901", baseline)
        fragment = self.root / "triage.json"
        fragment.write_text(json.dumps({"findings": [{"id": baseline["findings"][0]["id"], "validation": {
            "verdict": "Valid", "evidence": "same root cause as F-901"}}]}), encoding="utf-8")
        self.assertEqual(call(findings.main, "merge", self.record, fragment)[0], 0)
        code, out = call(findings.main, "renumber", self.record)
        self.assertEqual(code, 0, out)
        data = json.loads(self.record.read_text(encoding="utf-8"))
        triage = next(f for f in data["findings"] if f["id"].startswith("I-"))
        self.assertEqual(triage["validation"]["evidence"], "same root cause as F-001")
        self.assert_contract_passes()

    def test_a_scanned_resource_address_is_not_a_payload(self):
        # Plan JSON keeps for_each keys in the address; this one is an IP.
        snapshots = self.root / "snapshots"
        snapshots.mkdir()
        (self.repo / "main.tf").write_text(MODULE, encoding="utf-8")
        rule = {"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"],
                "ipv6_cidr_blocks": [], "security_groups": [], "self": False, "prefix_list_ids": [],
                "description": ""}
        (snapshots / "plan.json").write_text(json.dumps({
            "format_version": "1.2", "terraform_version": "1.6.0", "planned_values": {"root_module": {"resources": [{
                "address": 'aws_security_group.admin["169.254.169.254"]', "mode": "managed",
                "type": "aws_security_group", "name": "admin", "index": "169.254.169.254",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "values": {"name": "admin", "ingress": [rule], "egress": []}}]}}}), encoding="utf-8")
        baseline = self.scan("--snapshots", snapshots)
        self.assertTrue(any("169.254.169.254" in r for f in baseline["findings"] for r in f["resources"]))
        self.review("F-901", baseline)
        self.assertEqual(call(findings.main, "renumber", self.record)[0], 0)
        self.assert_contract_passes()

    def test_reviewer_text_on_a_baseline_finding_is_still_checked(self):
        (self.repo / "main.tf").write_text(MODULE, encoding="utf-8")
        baseline = self.scan()
        self.review("F-901", baseline)
        fragment = self.root / "triage.json"
        fragment.write_text(json.dumps({"findings": [{"id": baseline["findings"][0]["id"], "validation": {
            "verdict": "Valid", "evidence": "see F-950"}}]}), encoding="utf-8")
        self.assertEqual(call(findings.main, "merge", self.record, fragment)[0], 0)
        code, out = call(findings.main, "status", self.record)
        self.assertEqual(code, 1, out)
        self.assertIn("dangling  F-950", out)


if __name__ == "__main__":
    unittest.main()
