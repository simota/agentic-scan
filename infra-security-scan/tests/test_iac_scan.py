"""Offline tests for scripts/iac_scan.py: parser, baseline rules, output safety."""
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "infra-scan" / "scripts"))
import iac_scan  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
SEV = iac_scan.SEV_RANK


def rules_in(path):
    return {h["rule"] for h in iac_scan.run(path).hits}


def run_main(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = iac_scan.main(argv)
    return code, out.getvalue(), err.getvalue()


class TempDir(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="iac-scan-test-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, rel, text):
        path = self.tmp / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path


class HclParserTest(unittest.TestCase):
    TEXT = '''
# leading comment { not a block
resource "aws_security_group" "x" {
  name = "a-${var.env}-{b}"   /* comment { */
  tags = { Name = "x", "Team" = "ops" }
  ingress {
    cidr_blocks = ["0.0.0.0/0", var.extra] // trailing { comment
    from_port   = 22
  }
  policy = <<-EOT
    {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
  EOT
  rule = jsonencode({
    Statement = [{ Effect = "Allow", Action = ["s3:*"] }]
  })
  ref = aws_s3_bucket.x.id
  cond = var.a == "b" ? 1 : 2
}
module "m" {
  source = "./m"
}
'''

    def test_blocks_attributes_and_literals(self):
        blocks = iac_scan.parse_hcl(self.TEXT)
        self.assertEqual([(b.type, b.labels) for b in blocks],
                         [("resource", ["aws_security_group", "x"]), ("module", ["m"])])
        view = iac_scan.HclView(blocks[0])
        self.assertEqual(blocks[0].line, 3)
        self.assertIs(view.get("name"), iac_scan.UNKNOWN)
        self.assertEqual(view.get("tags"), {"Name": "x", "Team": "ops"})
        ingress = view.blocks("ingress")
        self.assertEqual(len(ingress), 1)
        self.assertEqual(ingress[0].get("cidr_blocks"), ["0.0.0.0/0", iac_scan.UNKNOWN])
        self.assertEqual(ingress[0].get("from_port"), 22)
        self.assertEqual(ingress[0].line("from_port"), 8)
        self.assertEqual(json.loads(view.get("policy"))["Statement"][0]["Action"], "*")
        self.assertEqual(view.get("rule"), {"Statement": [{"Effect": "Allow", "Action": ["s3:*"]}]})
        self.assertIs(view.get("ref"), iac_scan.UNKNOWN)
        self.assertIs(view.get("cond"), iac_scan.UNKNOWN)
        self.assertEqual(iac_scan.HclView(blocks[1]).get("source"), "./m")


class RuleTest(TempDir):
    EXPECTED_BAD = {
        "aws": {"AWS-NET-001", "AWS-S3-001", "AWS-S3-002", "AWS-S3-003", "AWS-IAM-001",
                "AWS-IAM-002", "AWS-IAM-003", "AWS-IAM-004", "AWS-IAM-005", "AWS-RDS-001",
                "AWS-RDS-002", "AWS-EC2-001", "AWS-EBS-001", "AWS-LAMBDA-001", "AWS-LAMBDA-002",
                "AWS-CT-001", "AWS-KMS-001", "AWS-EKS-001", "AWS-SNAP-001", "AWS-CF-001", "SEC-001", "PS-001",
                "PS-002", "PS-003"},
        "gcp": {"GCP-NET-001", "GCP-IAM-001", "GCP-IAM-002", "GCP-IAM-003", "GCP-IAM-004",
                "GCP-GCS-001", "GCP-SQL-001", "GCP-GCE-001", "GCP-GCE-002", "GCP-GKE-001",
                "GCP-WIF-001", "GCP-GCS-002"},
        "plan": {"AWS-NET-001", "AWS-S3-001", "AWS-S3-002"},
        "k8s": {"K8S-001", "K8S-002", "K8S-003"},
        "snapshots": {"AWS-NET-001", "GCP-IAM-001", "GCP-IAM-002"},
        "cfn": {"AWS-NET-001", "AWS-S3-001", "AWS-IAM-001", "AWS-IAM-003", "AWS-RDS-001"},
    }

    def copy(self, *rels):
        for rel in rels:
            dest = self.tmp / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(FIXTURES / rel, dest)

    def test_bad_fixtures_fire_every_rule(self):
        for name, expected in self.EXPECTED_BAD.items():
            with self.subTest(fixture=name):
                d = self.tmp / name
                files = [p for p in (FIXTURES / name).iterdir() if p.name != "good.tf"]
                d.mkdir()
                for p in files:
                    shutil.copy(p, d / p.name)
                self.assertEqual(rules_in(d), expected)

    def test_good_fixtures_are_silent(self):
        for rel in ("aws/good.tf", "gcp/good.tf"):
            with self.subTest(fixture=rel):
                d = self.tmp / rel.split("/")[0]
                d.mkdir()
                shutil.copy(FIXTURES / rel, d / "main.tf")
                self.assertEqual(iac_scan.run(d).hits, [])

    def test_every_rule_is_exercised(self):
        fired = set().union(*self.EXPECTED_BAD.values()) | {"SEC-002"}
        self.assertEqual(fired, set(iac_scan.RULES))

    def test_each_rule_names_a_known_perspective(self):
        table = (ROOT / "skills" / "infra-scan" / "reference" / "perspectives.md").read_text(encoding="utf-8")
        for rule, meta in iac_scan.RULES.items():
            self.assertIn(f"| {meta[2]} |", table, rule)

    def test_whole_fixture_tree(self):
        scan = iac_scan.run(FIXTURES)
        self.assertTrue({"terraform", "plan", "cloudformation", "kubernetes", "snapshot"}
                        <= {f["kind"] for f in scan.files})
        self.assertIn("module.site.aws_s3_bucket_acl.site", {r["address"] for r in scan.resources})
        self.assertTrue(any(n.startswith("remote module not read: module.vpc") for n in scan.not_run))

    def test_plan_location_is_the_resource_address_line(self):
        scan = iac_scan.run(FIXTURES / "plan")
        hit = next(h for h in scan.hits if h["rule"] == "AWS-NET-001")
        lines = (FIXTURES / "plan" / "plan.json").read_text().splitlines()
        self.assertIn('"aws_security_group.db"', lines[hit["line"] - 1])

    def test_local_state_for_production_root(self):
        self.write("envs/prod/main.tf", 'resource "aws_s3_bucket" "x" {\n  bucket = "x"\n}\n')
        self.write("modules/x/main.tf", 'resource "aws_s3_bucket" "y" {\n  bucket = "y"\n}\n')
        hits = [h for h in iac_scan.run(self.tmp).hits if h["rule"] == "PS-002"]
        self.assertEqual([(h["file"], h["severity"]) for h in hits], [("envs/prod/main.tf", "Low")])

    def test_cloudformation_yaml_in_the_subset_gets_the_json_rules(self):
        self.write("stack.yaml", "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Bucket:\n"
                                 "    Type: AWS::S3::Bucket\n    Properties:\n      AccessControl: PublicRead\n")
        scan = iac_scan.run(self.tmp)
        self.assertEqual([(r["address"], r["line"]) for r in scan.resources], [("cfn:Bucket", 4)])
        self.assertEqual([(h["rule"], h["line"]) for h in scan.hits], [("AWS-S3-001", 4)])
        self.assertEqual(scan.not_run, [])

    def test_cloudformation_yaml_with_short_form_tags_is_inventoried_not_ruled(self):
        self.write("stack.yaml", "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n    Properties:\n"
                                 "      BucketName: !Ref Name\n      AccessControl: PublicRead\n")
        scan = iac_scan.run(self.tmp)
        self.assertEqual([(r["address"], r["line"]) for r in scan.resources], [("cfn:Bucket", 3)])
        self.assertEqual(scan.hits, [])
        self.assertTrue(any(n.startswith("cloudformation yaml: rules not applied") for n in scan.not_run))

    def test_unknown_values_never_hit(self):
        self.write("main.tf", '''resource "aws_security_group" "x" {
  ingress {
    from_port   = var.port
    to_port     = var.port
    protocol    = "tcp"
    cidr_blocks = var.cidrs
  }
}
resource "aws_instance" "x" {
  metadata_options {
    http_tokens = var.tokens
  }
}
resource "aws_iam_policy" "x" {
  policy = data.aws_iam_policy_document.missing.json
}
''')
        self.assertEqual(iac_scan.run(self.tmp).hits, [])


class OutputTest(TempDir):
    def secrets(self):
        key_id = "AKIA" + "QWERTYUIOPASDFGH"
        header = "-----BEGIN " + "RSA PRIVATE KEY-----"
        password = "example-" + "literal-value-9"
        state_secret = "state-" + "secret-value-7"
        self.write("repo/main.tf", f'provider "aws" {{\n  access_key = "{key_id}"\n}}\n'
                                   f'resource "aws_db_instance" "x" {{\n  password = "{password}"\n'
                                   '  storage_encrypted = true\n}\n')
        self.write("repo/keys/deploy.pem", f"{header}\nMIIEexamplebody\n-----END RSA PRIVATE KEY-----\n")
        self.write("repo/terraform.tfstate", json.dumps({"outputs": {"pw": {"value": state_secret}}}))
        return [key_id, password, state_secret, "MIIEexamplebody"]

    def test_secret_values_never_reach_output(self):
        values = self.secrets()
        out, findings = self.tmp / "out" / "iac.json", self.tmp / "out" / "findings.json"
        code, stdout, _ = run_main([str(self.tmp / "repo"), "--out", str(out), "--into", str(findings)])
        self.assertEqual(code, 0)
        text = out.read_text() + findings.read_text() + stdout
        for value in values:
            self.assertNotIn(value, text)
        data = json.loads(findings.read_text())
        sec = {f["rule"]: f for f in data["findings"]}
        self.assertEqual(sec["SEC-001"]["confidence"], "Confirmed")
        self.assertEqual(sec["SEC-002"]["confidence"], "Confirmed")
        details = " ".join(f["detail"] for f in data["findings"])
        self.assertIn("AWS access key ID", details)
        self.assertIn("private key", details)
        self.assertIn("PS-003", sec)

    def test_into_replaces_only_baseline_findings(self):
        shutil.copytree(FIXTURES / "k8s", self.tmp / "repo")
        target = self.write("out/findings.json", json.dumps({
            "schema_version": 1, "meta": {"project": "p"},
            "findings": [{"id": "F-001", "title": "kept"}, {"id": "I-009", "title": "stale"}],
            "limitations": ["kept too"]}))
        code, _, _ = run_main([str(self.tmp / "repo"), "--into", str(target)])
        self.assertEqual(code, 0)
        data = json.loads(target.read_text())
        ids = [f["id"] for f in data["findings"]]
        self.assertEqual(ids[0], "F-001")
        self.assertNotIn("I-009", ids)
        self.assertEqual(ids[1:], [f"I-{n:03d}" for n in range(1, len(ids))])
        self.assertEqual(data["meta"]["project"], "p")
        self.assertIn("commit", data["meta"])
        self.assertEqual(data["limitations"], ["kept too"])
        self.assertEqual(data["inventory"]["by_provider"], {"kubernetes": 3})
        for key in ("attack_paths", "perspectives", "checked_ok", "decisions", "next_steps"):
            self.assertEqual(data[key], [])

    def test_ids_contiguous_and_severity_ordered(self):
        findings = iac_scan.build_findings(iac_scan.run(FIXTURES).hits)
        self.assertEqual([f["id"] for f in findings], [f"I-{n:03d}" for n in range(1, len(findings) + 1)])
        ranks = [SEV[f["severity"]] for f in findings]
        self.assertEqual(ranks, sorted(ranks))
        for f in findings:
            self.assertEqual(f["validation"], {"verdict": "Unverified", "evidence": ""})
            self.assertRegex(f["location"], r"^[^\s:]+:\d+$")
            self.assertIn(f["provider"], {"aws", "gcp", "azure", "kubernetes", "multi"})
        self.assertEqual(len({(f["rule"], f["location"].split(":")[0]) for f in findings}), len(findings))

    def test_symlinks_are_skipped_and_recorded(self):
        self.write("real/main.tf", 'resource "aws_iam_access_key" "x" {\n  user = "x"\n}\n')
        (self.tmp / "repo").mkdir()
        os.symlink(self.tmp / "real" / "main.tf", self.tmp / "repo" / "link.tf")
        os.symlink(self.tmp / "real", self.tmp / "repo" / "linkdir")
        scan = iac_scan.run(self.tmp / "repo")
        self.assertEqual(scan.hits, [])
        self.assertEqual(sorted(scan.not_run), ["symlink skipped: link.tf", "symlink skipped: linkdir"])

    def test_unreadable_repo_exits_2(self):
        code, _, err = run_main([str(self.tmp / "missing")])
        self.assertEqual(code, 2)
        self.assertIn("not a readable directory", err)

    def test_corrupt_findings_json_exits_2(self):
        (self.tmp / "repo").mkdir()
        target = self.write("findings.json", "{not json")
        code, _, _ = run_main([str(self.tmp / "repo"), "--into", str(target)])
        self.assertEqual(code, 2)
        self.assertEqual(target.read_text(), "{not json")


if __name__ == "__main__":
    unittest.main()
