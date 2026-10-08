"""Equivalent Terraform literals and IAM action patterns keep the same rules."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "infra-scan" / "scripts"))
import iac_scan  # noqa: E402


class ScanCase(unittest.TestCase):
    def scan(self, text, filename="main.tf"):
        with tempfile.TemporaryDirectory(prefix="iac-rule-equivalence-") as tmp:
            (Path(tmp) / filename).write_text(text, encoding="utf-8")
            return iac_scan.run(tmp)


class TerraformBooleanTest(ScanCase):
    # name, resource type, body, unsafe bool, rule, omitted bool is unsafe
    CASES = (
        ("rds_public", "aws_db_instance", '''
  publicly_accessible = VALUE
  storage_encrypted = true
''', True, "AWS-RDS-001", False),
        ("rds_encryption", "aws_db_instance", '''
  publicly_accessible = false
  storage_encrypted = VALUE
''', False, "AWS-RDS-002", True),
        *[(name, type_, '''
  block_public_acls = VALUE
  block_public_policy = VALUE
  ignore_public_acls = VALUE
  restrict_public_buckets = VALUE
''', False, "AWS-S3-002", True) for name, type_ in (
            ("s3_bucket", "aws_s3_bucket_public_access_block"),
            ("s3_account", "aws_s3_account_public_access_block"))],
        ("ebs", "aws_ebs_volume", '''
  encrypted = VALUE
''', False, "AWS-EBS-001", True),
        ("cloudtrail", "aws_cloudtrail", '''
  is_multi_region_trail = VALUE
  enable_log_file_validation = VALUE
''', False, "AWS-CT-001", True),
        ("kms", "aws_kms_key", '''
  enable_key_rotation = VALUE
''', False, "AWS-KMS-001", True),
        ("eks", "aws_eks_cluster", '''
  vpc_config {
    endpoint_public_access = VALUE
    public_access_cidrs = ["0.0.0.0/0"]
  }
''', True, "AWS-EKS-001", True),
        ("firewall", "google_compute_firewall", '''
  disabled = VALUE
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports = ["22"]
  }
''', False, "GCP-NET-001", True),
        ("gcs", "google_storage_bucket", '''
  uniform_bucket_level_access = VALUE
  public_access_prevention = "enforced"
''', False, "GCP-GCS-001", True),
        ("sql_public_ip", "google_sql_database_instance", '''
  settings {
    ip_configuration {
      ipv4_enabled = VALUE
      require_ssl = false
    }
  }
''', True, "GCP-SQL-001", False),
        ("sql_tls", "google_sql_database_instance", '''
  settings {
    ip_configuration {
      ipv4_enabled = true
      require_ssl = VALUE
    }
  }
''', False, "GCP-SQL-001", True),
        ("gke_abac", "google_container_cluster", '''
  enable_legacy_abac = VALUE
  private_cluster_config {
    enable_private_endpoint = true
  }
  workload_identity_config {
    workload_pool = "example.svc.id.goog"
  }
''', True, "GCP-GKE-001", False),
        ("gke_endpoint", "google_container_cluster", '''
  private_cluster_config {
    enable_private_endpoint = VALUE
  }
  workload_identity_config {
    workload_pool = "example.svc.id.goog"
  }
''', False, "GCP-GKE-001", True),
        ("backend", None, '''terraform {
  backend "s3" {
    bucket = "example-state"
    encrypt = VALUE
  }
}
''', False, "PS-002", True),
    )

    def config(self, type_, body, value):
        if value is None:
            body = "\n".join(line for line in body.splitlines() if "VALUE" not in line)
        else:
            body = body.replace("VALUE", value)
        return f'resource "{type_}" "app" {{\n{body}}}\n' if type_ else body

    def test_quoted_and_native_bools_have_identical_findings(self):
        for name, type_, body, unsafe, rule, _ in self.CASES:
            for value in (True, False):
                with self.subTest(case=name, value=value):
                    literal = json.dumps(value)
                    native = self.scan(self.config(type_, body, literal))
                    quoted = self.scan(self.config(type_, body, json.dumps(literal)))
                    self.assertEqual([hit["rule"] for hit in native.hits],
                                     [rule] if value is unsafe else [])
                    self.assertEqual(quoted.hits, native.hits)
                    self.assertEqual(quoted.not_run, native.not_run)
                    self.assertEqual(quoted.not_run, [])

    def test_unresolved_or_invalid_bools_do_not_apply_missing_defaults(self):
        for name, type_, body, _, _, _ in self.CASES:
            for value in ("var.flag", '"TRUE"', '"false "', '"0"', '"yes"',
                          "0", "1", "[]", "{}"):
                with self.subTest(case=name, value=value):
                    scan = self.scan(self.config(type_, body, value))
                    self.assertEqual(scan.hits, [])
                    self.assertEqual(scan.not_run, [])

    def test_null_and_omitted_bools_keep_the_existing_defaults(self):
        for name, type_, body, _, rule, missing_unsafe in self.CASES:
            for value in (None, "null"):
                with self.subTest(case=name, value=value):
                    scan = self.scan(self.config(type_, body, value))
                    self.assertEqual([hit["rule"] for hit in scan.hits],
                                     [rule] if missing_unsafe else [])
                    self.assertEqual(scan.not_run, [])

    def test_unknown_sibling_does_not_hide_a_known_off_flag(self):
        scan = self.scan('''resource "aws_s3_bucket_public_access_block" "app" {
  block_public_acls = "false"
  block_public_policy = var.pending
  ignore_public_acls = "true"
  restrict_public_buckets = "true"
}
''')
        self.assertEqual([(hit["rule"], hit["detail"]) for hit in scan.hits],
                         [("AWS-S3-002", "off: block_public_acls")])

    def test_boolean_looking_policy_and_metadata_values_stay_strings(self):
        text = '''data "aws_iam_policy_document" "transport" {
  statement {
    actions = ["s3:GetObject"]
    resources = ["*"]
    condition {
      test = "Bool"
      variable = "aws:SecureTransport"
      values = ["false"]
    }
  }
}
resource "google_compute_instance" "app" {
  metadata = {
    "serial-port-enable" = "true"
    "block-project-ssh-keys" = "false"
  }
}
'''
        scan = self.scan(text)
        self.assertEqual(scan.policy_docs[(".", "transport")][0]["conditions"],
                         [("Bool", "aws:SecureTransport", ["false"])])
        view = iac_scan.HclView(iac_scan.parse_hcl(text)[1])
        self.assertEqual(view.get("metadata"), {"serial-port-enable": "true",
                                                "block-project-ssh-keys": "false"})
        self.assertEqual([hit["rule"] for hit in scan.hits], ["GCP-GCE-002"])

    def test_equality_expressions_remain_unevaluated(self):
        scan = self.scan('''resource "aws_db_instance" "app" {
  publicly_accessible = "true" == true
  storage_encrypted = true
}
''')
        self.assertEqual(scan.hits, [])


class PassRoleActionTest(ScanCase):
    FORMATS = ("terraform", "plan", "cloudformation")

    def policy(self, statement, format_="terraform", replacements=None):
        policy = {"Version": "2012-10-17", "Statement": [statement]}
        if format_ == "terraform":
            body = json.dumps(policy)
            for before, after in (replacements or {}).items():
                body = body.replace(json.dumps(before), after)
            return self.scan('resource "aws_iam_policy" "app" {\n'
                             f'  policy = jsonencode({body})\n' + '}\n')
        if format_ == "plan":
            document = {"planned_values": {"root_module": {"resources": [{
                "address": "aws_iam_policy.app", "mode": "managed", "type": "aws_iam_policy",
                "values": {"policy": json.dumps(policy)},
            }]}}}
        else:
            document = {"Resources": {"Policy": {
                "Type": "AWS::IAM::ManagedPolicy", "Properties": {"PolicyDocument": policy},
            }}}
        return self.scan(json.dumps(document), "policy.json")

    def statement(self, action):
        return {"Effect": "Allow", "Action": action, "Resource": "*"}

    def test_action_wildcards_grant_passrole_in_every_format(self):
        for format_ in self.FORMATS:
            for action in ("iam:PassRole", "IAM:PASSROLE", "iam:PassRole*", "iam:Pass?ole",
                           "iam:*Role", "iam:P*", "iam:*", "iam:Pass*",
                           ["iam:GetRole", "iam:Pass?ole"]):
                with self.subTest(format=format_, action=action):
                    scan = self.policy(self.statement(action), format_)
                    self.assertEqual([hit["rule"] for hit in scan.hits], ["AWS-IAM-002"])
                    self.assertEqual(scan.not_run, [])

    def test_full_admin_permission_keeps_the_primary_rule(self):
        for format_ in self.FORMATS:
            for action in ("*", "*:*", ["iam:PassRole*", "*"]):
                with self.subTest(format=format_, action=action):
                    scan = self.policy(self.statement(action), format_)
                    self.assertEqual([hit["rule"] for hit in scan.hits], ["AWS-IAM-001"])

    def test_nonmatching_or_unsupported_actions_do_not_grant_passrole(self):
        for format_ in self.FORMATS:
            for action in ("iam:GetRole", "iam:PassRoleSuffix", "iam:PassRol[e]",
                           "iam:PassRol?e", [], None, {"Ref": "AllowedActions"}):
                with self.subTest(format=format_, action=action):
                    scan = self.policy(self.statement(action), format_)
                    self.assertEqual(scan.hits, [])
                    self.assertEqual(scan.not_run, [])

    def test_effect_resource_and_not_action_keep_their_boundaries(self):
        statements = [
            {"Effect": "Deny", "Action": "iam:PassRole*", "Resource": "*"},
            {"Effect": "Allow", "Action": "iam:PassRole*",
             "Resource": "arn:aws:iam::111122223333:role/app"},
            {"Effect": "Allow", "NotAction": "iam:PassRole*", "Resource": "*"},
            {"Effect": "Allow", "Resource": "*"},
        ]
        for format_ in self.FORMATS:
            for statement in statements:
                with self.subTest(format=format_, statement=statement):
                    self.assertEqual(self.policy(statement, format_).hits, [])

    def test_unknown_action_is_not_a_truthy_match(self):
        for action in ("pending", ["pending", "iam:GetRole"]):
            with self.subTest(action=action):
                scan = self.policy(self.statement(action), replacements={"pending": "var.action"})
                self.assertEqual(scan.hits, [])
                self.assertEqual(scan.not_run, [])
        scan = self.policy(self.statement(["pending", "iam:Pass?ole"]),
                           replacements={"pending": "var.action"})
        self.assertEqual([hit["rule"] for hit in scan.hits], ["AWS-IAM-002"])


if __name__ == "__main__":
    unittest.main()
