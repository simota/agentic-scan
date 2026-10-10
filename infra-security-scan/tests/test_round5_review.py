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
        for line in ("docker run -u 1000:1000 img", 'command: ["docker", "run", "--user", "1000:1000"]',
                     "openssl enc -pbkdf2 -in f"):
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


class CodexSecondReviewTest(unittest.TestCase):
    def test_value_before_name_and_fields_between(self):
        result = scan({"e.tf": f'''resource "kubernetes_deployment" "d" {{
  env {{
    value = "{SECRET}"
    name  = "DB_PASSWORD"
  }}
  env {{
    name       = "API_TOKEN"
    value_from = "x"
    value      = "{SECRET}"
  }}
}}
resource "aws_ecs_task_definition" "t" {{
  container_definitions = jsonencode([{{ environment = [{{ value = "{SECRET}", name = "AUTH_TOKEN" }}] }}])
}}
'''})
        self.assertEqual(sorted(h["detail"] for h in result.hits),
                         ["literal value for API_TOKEN", "literal value for AUTH_TOKEN", "literal value for DB_PASSWORD"])

    def test_retained_default_pool_without_node_config(self):
        base = 'resource "google_container_cluster" "c" {{\n{body}  private_cluster_config {{\n' \
               '    enable_private_endpoint = true\n  }}\n  workload_identity_config {{\n' \
               '    workload_pool = "p.svc.id.goog"\n  }}\n}}\n'
        kept = scan({"c.tf": base.format(body="  initial_node_count = 1\n")})
        self.assertEqual([h["rule"] for h in kept.hits], ["GCP-GCE-001"])
        removed = scan({"c.tf": base.format(body="  initial_node_count = 1\n  remove_default_node_pool = true\n")})
        self.assertEqual(removed.hits, [])
        inline = scan({"c.tf": base.format(body="  node_pool {\n    name = \"a\"\n  }\n")})
        self.assertEqual([h["rule"] for h in inline.hits], ["GCP-GCE-001"])

    def test_terragrunt_backend_only_from_loaded_files(self):
        unit = 'include "root" {\n  path = find_in_parent_folders("root.hcl")\n}\n'
        backend = 'remote_state {\n  backend = "s3"\n  config = {\n    encrypt = true\n  }\n}\n'
        app = 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'
        unrelated = scan({"prod/unused.hcl": backend, "prod/app/terragrunt.hcl": unit, "prod/app/main.tf": app})
        self.assertIn("PS-002", [h["rule"] for h in unrelated.hits])
        included = scan({"root.hcl": backend, "prod/app/terragrunt.hcl": unit, "prod/app/main.tf": app})
        self.assertNotIn("PS-002", [h["rule"] for h in included.hits])

    def test_instance_metadata_options(self):
        template = {"Resources": {"Vm": {"Type": "AWS::EC2::Instance", "Properties": {
            "MetadataOptions": {"HttpTokens": "required"}}},
            "Old": {"Type": "AWS::EC2::Instance", "Properties": {"MetadataOptions": {"HttpTokens": "optional"}}}}}
        self.assertEqual(found(scan({"t.json": template})), [("AWS-EC2-001", "cfn:Old", "Medium")])


class CodexThirdReviewTest(unittest.TestCase):
    def test_reference_type_belongs_to_its_own_entry(self):
        result = scan({"cb.tf": f'''resource "aws_codebuild_project" "p" {{
  environment {{
    environment_variable {{
      name  = "DB_PASSWORD"
      value = "{SECRET}"
    }}
    environment_variable {{ name = "NPM_TOKEN", value = "/ci/npm", type = "PARAMETER_STORE" }}
  }}
}}
'''})
        self.assertEqual([h["detail"] for h in result.hits], ["literal value for DB_PASSWORD"])

    def test_no_argument_include_finds_terragrunt_hcl_only(self):
        unit = 'include {\n  path = find_in_parent_folders()\n}\n'
        backend = 'remote_state {\n  backend = "s3"\n  config = {\n    encrypt = true\n  }\n}\n'
        app = 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'
        stray = scan({"root.hcl": backend, "terragrunt.hcl": "locals {}\n",
                      "prod/app/terragrunt.hcl": unit, "prod/app/main.tf": app})
        self.assertIn("PS-002", [h["rule"] for h in stray.hits])
        parent = scan({"terragrunt.hcl": backend, "prod/app/terragrunt.hcl": unit, "prod/app/main.tf": app})
        self.assertNotIn("PS-002", [h["rule"] for h in parent.hits])

    def test_intrinsic_metadata_options_are_unresolved(self):
        template = {"Resources": {"Vm": {"Type": "AWS::EC2::Instance", "Properties": {"MetadataOptions": {
            "Fn::If": ["Strict", {"HttpTokens": "required"}, {"HttpEndpoint": "disabled"}]}}}}}
        result = scan({"t.json": template})
        self.assertEqual(result.hits, [])
        self.assertTrue([n for n in result.not_run if "MetadataOptions is not a literal" in n])


class CodexFourthReviewTest(unittest.TestCase):
    def test_numeric_basic_auth_is_a_password(self):
        self.assertEqual(redaction.scrub_line("curl -u 123:456 https://host"), "curl -u 123:[redacted] https://host")

    def test_sam_global_lists_are_prepended(self):
        template = {"Transform": "AWS::Serverless-2016-10-31",
                    "Globals": {"Function": {"Policies": ["AdministratorAccess"]}},
                    "Resources": {"Fn": {"Type": "AWS::Serverless::Function", "Properties": {
                        "Policies": ["AWSLambdaBasicExecutionRole"]}}}}
        self.assertEqual([r for r, _, _ in found(scan({"t.json": template}))], ["AWS-IAM-001"])

    def test_empty_dynamic_block_keeps_its_unknowns(self):
        doc = {"planned_values": {"root_module": {"resources": [{
                   "address": "google_compute_firewall.fw", "mode": "managed", "type": "google_compute_firewall",
                   "name": "fw", "values": {"allow": [], "source_ranges": ["0.0.0.0/0"]}}]}},
               "resource_changes": [{"address": "google_compute_firewall.fw",
                                     "change": {"after_unknown": {"allow": True}}}],
               "configuration": {"root_module": {"resources": [{
                   "address": "google_compute_firewall.fw", "expressions": {"source_ranges": {}}}]}}}
        result = scan({"plan.json": doc})
        self.assertEqual(result.hits, [])
        self.assertTrue([n for n in result.not_run if "google_compute_firewall.fw" in n], result.not_run)


class CodexFifthReviewTest(unittest.TestCase):
    def test_one_line_objects_with_fields_between(self):
        result = scan({"cb.tf": f'''resource "aws_codebuild_project" "p" {{
  environment_variables = [{{ name = "DB_PASSWORD", type = "PLAINTEXT", value = "{SECRET}" }}, {{ name = "API_TOKEN", type = "PARAMETER_STORE", value = "/ci/token" }}, {{ type = "PLAINTEXT", value = "{SECRET}", name = "AUTH_TOKEN" }}]
}}
'''})
        self.assertEqual(sorted(h["detail"] for h in result.hits),
                         ["literal value for AUTH_TOKEN", "literal value for DB_PASSWORD"])

    def test_uncreated_org_policy_enforces_nothing(self):
        result = scan({"gcs.tf": '''resource "google_project_organization_policy" "ubla" {
  count      = 0
  project    = "p"
  constraint = "storage.uniformBucketLevelAccess"
  boolean_policy {
    enforced = true
  }
}
resource "google_storage_bucket" "b" {
  project                     = "p"
  uniform_bucket_level_access = false
  public_access_prevention    = "enforced"
}
'''})
        self.assertEqual([h["rule"] for h in result.hits], ["GCP-GCS-001"])


class CodexSixthReviewTest(unittest.TestCase):
    BUCKET = 'resource "google_storage_bucket" "b" {\n  project = "proj-x"\n  uniform_bucket_level_access = false\n' \
             '  public_access_prevention = "enforced"\n}\n'
    FOLDER = 'resource "google_folder_organization_policy" "f" {\n  folder = "folders/123"\n' \
             '  constraint = "storage.uniformBucketLevelAccess"\n  boolean_policy {\n    enforced = true\n  }\n}\n'

    def test_folder_policy_covers_only_projects_in_the_folder(self):
        self.assertEqual([h["rule"] for h in scan({"g.tf": self.BUCKET + self.FOLDER}).hits], ["GCP-GCS-001"])
        project = 'resource "google_project" "x" {\n  project_id = "proj-x"\n  folder_id = "folders/123"\n}\n'
        self.assertEqual(scan({"g.tf": self.BUCKET + self.FOLDER + project}).hits, [])

    def test_read_terragrunt_config_is_not_an_include(self):
        backend = 'remote_state {\n  backend = "s3"\n  config = {\n    encrypt = true\n  }\n}\n'
        app = 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'
        read_only = 'locals {\n  common = read_terragrunt_config(find_in_parent_folders("root.hcl"))\n}\n'
        result = scan({"root.hcl": backend, "prod/app/terragrunt.hcl": read_only, "prod/app/main.tf": app})
        self.assertIn("PS-002", [h["rule"] for h in result.hits])
        assigned = read_only + "remote_state = local.common.remote_state\n"
        result = scan({"root.hcl": backend, "prod/app/terragrunt.hcl": assigned, "prod/app/main.tf": app})
        self.assertNotIn("PS-002", [h["rule"] for h in result.hits])


class CodexSeventhReviewTest(unittest.TestCase):
    def test_comment_after_secret_name(self):
        result = scan({"e.tf": f'''resource "kubernetes_deployment" "d" {{
  env {{
    name  = "DB_PASSWORD" # application credential
    value = "{SECRET}"
  }}
  env {{
    name  = "API_TOKEN" // ci token
    value = "{SECRET}"
  }}
}}
'''})
        self.assertEqual(sorted(h["detail"] for h in result.hits),
                         ["literal value for API_TOKEN", "literal value for DB_PASSWORD"])

    def test_remote_state_inside_a_block_is_not_a_backend(self):
        app = 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'
        nested = 'locals {\n  remote_state = read_terragrunt_config("other.hcl")\n}\n'
        result = scan({"prod/app/terragrunt.hcl": nested, "prod/app/main.tf": app})
        self.assertIn("PS-002", [h["rule"] for h in result.hits])

    def test_intrinsic_launch_template_data_is_unresolved(self):
        template = {"Resources": {"Lt": {"Type": "AWS::EC2::LaunchTemplate", "Properties": {"LaunchTemplateData": {
            "Fn::If": ["Strict", {"MetadataOptions": {"HttpTokens": "required"}}, {"ImageId": "ami-1"}]}}}}}
        result = scan({"t.json": template})
        self.assertEqual(result.hits, [])
        self.assertTrue([n for n in result.not_run if "LaunchTemplateData is not a literal" in n], result.not_run)


class CodexEighthReviewTest(unittest.TestCase):
    def test_quoted_command_line_passwords_are_redacted_whole(self):
        rest = "Sup3r" + "Secret"
        for line in (f'curl -u "admin:pfx {rest}" https://host',
                     f"curl -u 'admin:pfx {rest}' https://host",
                     f'CMD ["curl", "-u", "admin:pfx {rest}", "https://host"]',
                     f'command = "curl -u \\"admin:pfx {rest}\\" https://host"',
                     f'docker login -p "pfx {rest}" registry',
                     f'openssl pkcs12 -passout "pass:pfx {rest}" -in key.p12',
                     f'sshpass -p "pfx {rest}" ssh host',
                     f'redis-cli -a "pfx {rest}"'):
            self.assertNotIn(rest, redaction.scrub_line(line, "shell"), line)
        self.assertEqual(redaction.scrub_line('curl -u "admin:pfx x" https://host', "shell"),
                         'curl -u "admin:[redacted]" https://host')

    def test_unresolved_policy_project_covers_only_the_same_expression(self):
        policy = 'resource "google_project_organization_policy" "p" {\n  project = var.policy_project\n' \
                 '  constraint = "storage.uniformBucketLevelAccess"\n  boolean_policy {\n    enforced = true\n  }\n}\n'
        bucket = 'resource "google_storage_bucket" "b" {{\n{project}  uniform_bucket_level_access = false\n' \
                 '  public_access_prevention = "enforced"\n}}\n'
        other = scan({"g.tf": policy + bucket.format(project='  project = "other-project"\n')})
        self.assertEqual([h["rule"] for h in other.hits], ["GCP-GCS-001"])
        same = scan({"g.tf": policy + bucket.format(project="  project = var.policy_project\n")})
        self.assertEqual(same.hits, [])

    def test_intrinsic_http_endpoint_is_unresolved(self):
        template = {"Resources": {"Vm": {"Type": "AWS::EC2::Instance", "Properties": {"MetadataOptions": {
            "HttpEndpoint": {"Fn::If": ["C", "disabled", "disabled"]}, "HttpTokens": "optional"}}}}}
        result = scan({"t.json": template})
        self.assertEqual(result.hits, [])
        self.assertTrue([n for n in result.not_run if "HttpEndpoint not a literal" in n], result.not_run)


if __name__ == "__main__":
    unittest.main()
