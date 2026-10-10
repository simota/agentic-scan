"""Regressions from the adversarial review of the round-5 changes."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-scan" / "scripts"))
import contract_check  # noqa: E402
import iac_scan  # noqa: E402
import redaction  # noqa: E402

SECRET = "Sup3r" + "S3cretValue"


def scan(files, snapshots=None):
    with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as snap:
        for name, text in files.items():
            path = Path(tmp) / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text if isinstance(text, str) else json.dumps(text, indent=1), encoding="utf-8")
        for name, doc in (snapshots or {}).items():
            (Path(snap) / name).write_text(json.dumps(doc, indent=1), encoding="utf-8")
        return iac_scan.run(tmp, [snap] if snapshots else ())


def found(result):
    return sorted({(h["rule"], h["address"], h["severity"]) for h in result.hits})


class ReviewTest(unittest.TestCase):
    def test_base64_tag(self):
        template = """Resources:
  Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              AWS: '*'
            Action: sts:AssumeRole
  Lt:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateData:
        UserData: !Base64 |
          #!/bin/bash
          echo hi
"""
        self.assertEqual([r for r, _, _ in found(scan({"t.yaml": template}))], ["AWS-EC2-001", "AWS-IAM-003"])

    def test_codebuild_secret_references_and_flags(self):
        cfn = {"Resources": {"Build": {"Type": "AWS::CodeBuild::Project", "Properties": {"Environment": {
            "EnvironmentVariables": [
                {"Name": "DOCKERHUB_PASSWORD", "Type": "SECRETS_MANAGER", "Value": "ci/dockerhub:password"},
                {"Name": "NPM_TOKEN", "Type": "PARAMETER_STORE", "Value": "/ci/npm/token"},
                {"Name": "ENABLE_TOKEN", "Value": "false"}]}}}}}
        hcl = '''resource "aws_codebuild_project" "p" {
  environment {
    environment_variable {
      name  = "DOCKERHUB_PASSWORD"
      value = "/ci/dockerhub/password"
      type  = "PARAMETER_STORE"
    }
  }
}
'''
        self.assertEqual(found(scan({"cb.json": cfn, "cb.tf": hcl})), [])

    def test_plan_dynamic_blocks_keep_their_unknowns(self):
        doc = {"planned_values": {"root_module": {"resources": [{
                   "address": "google_compute_firewall.fw", "mode": "managed", "type": "google_compute_firewall",
                   "name": "fw", "values": {"allow": [{"protocol": "tcp"}], "source_ranges": ["0.0.0.0/0"]}}]}},
               "resource_changes": [{"address": "google_compute_firewall.fw",
                                     "change": {"after_unknown": {"allow": [{"ports": True}]}}}],
               "configuration": {"root_module": {"resources": [{
                   "address": "google_compute_firewall.fw", "expressions": {"source_ranges": {}}}]}}}
        result = scan({"plan.json": doc})
        self.assertEqual(result.hits, [])

    def test_pab_scope(self):
        acl = 'resource "aws_s3_bucket_acl" "a" {\n  provider = aws.customer\n  bucket = "b"\n  acl = "public-read"\n}\n'
        account = ('resource "aws_s3_account_public_access_block" "acct" {\n  ignore_public_acls = true\n'
                   '  restrict_public_buckets = true\n}\n')
        conditional = ('resource "aws_s3_bucket_public_access_block" "p" {\n  count = var.harden ? 1 : 0\n'
                       '  bucket = "c"\n  ignore_public_acls = true\n}\n'
                       'resource "aws_s3_bucket_acl" "c" {\n  bucket = "c"\n  acl = "public-read"\n}\n')
        self.assertEqual(found(scan({"a.tf": acl + account}))[0][2], "High")
        self.assertEqual(found(scan({"a.tf": conditional}))[0][2], "High")

    def test_data_policy_binding_cites_its_own_file(self):
        result = scan({"data.tf": 'data "google_iam_policy" "p" {\n  binding {\n    role = '
                                  '"roles/iam.serviceAccountTokenCreator"\n    members = ["group:g@example.com"]\n  }\n}\n',
                       "main.tf": 'resource "google_project_iam_policy" "p" {\n'
                                  '  policy_data = data.google_iam_policy.p.policy_data\n}\n'})
        self.assertEqual([(h["rule"], h["file"], h["line"]) for h in result.hits], [("GCP-IAM-004", "data.tf", 2)])

    def test_removed_default_pool_and_admin_for_each(self):
        result = scan({"m.tf": '''resource "google_container_cluster" "c" {
  remove_default_node_pool = true
  node_config {
    disk_size_gb = 20
  }
  private_cluster_config {
    enable_private_endpoint = true
  }
  workload_identity_config {
    workload_pool = "p.svc.id.goog"
  }
}
resource "aws_iam_role_policy_attachment" "x" {
  for_each   = setsubtract(toset(var.extra), ["arn:aws:iam::aws:policy/AdministratorAccess"])
  role       = "r"
  policy_arn = each.value
}
'''})
        self.assertEqual(result.hits, [])

    def test_aws_managed_policy_documents_are_not_findings(self):
        doc = {"Policies": [{"PolicyName": "AWSLambda_FullAccess", "Arn": "arn:aws:iam::aws:policy/AWSLambda_FullAccess",
                             "AttachmentCount": 1, "PolicyVersionList": [{"IsDefaultVersion": True, "Document": {
                                 "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]}}]}]}
        self.assertEqual(scan({"main.tf": "\n"}, {"aws-iam.json": doc}).hits, [])

    def test_scanner_detail_does_not_block_the_contract(self):
        data = json.loads((REPO / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
        baseline = next(f for f in data["findings"] if f["id"].startswith("I-"))
        baseline["detail"] = "http_tokens = optional; rm -rf /"
        with tempfile.TemporaryDirectory() as out:
            problems = contract_check.check(data, out, pdf=False)
        self.assertFalse([p for p in problems if "exploit string" in p], problems)

    def test_command_line_forms(self):
        for line in (f"curl -uadmin:{SECRET} http://x", f"sshpass -p{SECRET} ssh h", f'args: ["-u", "admin:{SECRET}"]',
                     f'command: ["docker", "login", "-p", "{SECRET}"]'):
            self.assertNotIn(SECRET, redaction.scrub_line(line, "yaml"), line)
        for line in ("docker run -u 1000:1000 img", "--user 1000:1000", "openssl enc -pbkdf2 -in f"):
            self.assertEqual(redaction.scrub_line(line, "yaml"), line)


class CodexReviewTest(unittest.TestCase):
    def test_flag_like_prefix_is_still_a_secret(self):
        template = {"Resources": {"Db": {"Type": "AWS::RDS::DBInstance", "Properties": {
            "MasterUserPassword": "12345" + "abcSECRET", "StorageEncrypted": True}}}}
        self.assertEqual([r for r, _, _ in found(scan({"t.json": template}))], ["SEC-001"])

    def test_sam_globals_merge_maps(self):
        template = {"Transform": "AWS::Serverless-2016-10-31",
                    "Globals": {"Function": {"Environment": {"Variables": {"DB_PASSWORD": SECRET}}}},
                    "Resources": {"Fn": {"Type": "AWS::Serverless::Function", "Properties": {
                        "Environment": {"Variables": {"MODE": "prod"}}}}}}
        self.assertEqual([r for r, _, _ in found(scan({"t.json": template}))], ["SEC-001"])
        self.assertEqual(iac_scan.sam_merge({"a": {"x": 1, "y": 2}, "b": 1}, {"a": {"y": 3}}),
                         {"a": {"x": 1, "y": 3}, "b": 1})

    def test_contract_compares_every_scanner_field(self):
        data = json.loads((REPO / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
        baseline = [dict(f) for f in data["findings"] if f["id"].startswith("I-")]
        with tempfile.TemporaryDirectory() as out:
            (Path(out) / "iac.json").write_text(json.dumps({"tool": "iac_scan", "commit": data["meta"].get("commit"),
                                                            "findings": baseline}), encoding="utf-8")
            self.assertEqual(contract_check.baseline_problems(data, Path(out) / "iac.json"), [])
            # A reviewer may grade and triage...
            data["findings"][[f["id"] for f in data["findings"]].index(baseline[0]["id"])]["severity"] = "Info"
            self.assertEqual(contract_check.baseline_problems(data, Path(out) / "iac.json"), [])
            # ...but not rewrite what the scanner found.
            data["findings"][[f["id"] for f in data["findings"]].index(baseline[0]["id"])]["detail"] = "forged"
            problems = contract_check.baseline_problems(data, Path(out) / "iac.json")
            self.assertTrue(problems and baseline[0]["id"] in problems[0], problems)


if __name__ == "__main__":
    unittest.main()
