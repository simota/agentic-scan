"""Rule false negatives and false positives found in the seventh review."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "infra-scan" / "scripts"))
import iac_scan  # noqa: E402

OPEN_SSH = '''resource "aws_security_group" "ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''


def scan(files):
    with tempfile.TemporaryDirectory(prefix="iac-rule-gaps-") as tmp:
        for name, text in files.items():
            path = Path(tmp) / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text if isinstance(text, str) else json.dumps(text, indent=2), encoding="utf-8")
        return iac_scan.run(tmp)


def hits(files):
    return sorted((h["rule"], h["address"], h["line"]) for h in scan(files).hits)


def rules(files):
    return {h["rule"] for h in scan(files).hits}


class TerraformRuleTest(unittest.TestCase):
    def test_heredoc_marker_with_a_dash_does_not_swallow_resources(self):
        text = ('resource "aws_instance" "i" {\n  user_data = <<USER-DATA\necho "{ unbalanced\nUSER-DATA\n'
                '  metadata_options {\n    http_tokens = "required"\n  }\n}\n' + OPEN_SSH)
        result = scan({"main.tf": text})
        self.assertIn("aws_security_group.ssh", [r["address"] for r in result.resources])
        self.assertIn("AWS-NET-001", {h["rule"] for h in result.hits})

    def test_allow_with_not_principal_is_public(self):
        policy = ('resource "aws_s3_bucket_policy" "p" {\n  bucket = "b"\n  policy = jsonencode({\n'
                  '    Statement = [{Effect = "Allow", NotPrincipal = {AWS = "arn:aws:iam::111122223333:root"},\n'
                  '      Action = "s3:GetObject", Resource = "*"}]\n  })\n}\n')
        self.assertIn("AWS-S3-003", rules({"main.tf": policy}))
        doc = ('data "aws_iam_policy_document" "d" {\n  statement {\n    actions = ["s3:GetObject"]\n'
               '    resources = ["*"]\n    not_principals {\n      type = "AWS"\n'
               '      identifiers = ["arn:aws:iam::111122223333:root"]\n    }\n  }\n}\n'
               'resource "aws_s3_bucket_policy" "p" {\n  bucket = "b"\n'
               '  policy = data.aws_iam_policy_document.d.json\n}\n')
        self.assertIn("AWS-S3-003", rules({"main.tf": doc}))

    def test_open_condition_keys_do_not_narrow_principal_star(self):
        template = ('data "aws_iam_policy_document" "d" {\n  statement {\n    actions = ["s3:GetObject"]\n'
                    '    resources = ["*"]\n    principals {\n      type = "*"\n      identifiers = ["*"]\n'
                    '    }\n    condition {\n      test = "%s"\n      variable = "%s"\n'
                    '      values = ["%s"]\n    }\n  }\n}\n'
                    'resource "aws_s3_bucket_policy" "p" {\n  bucket = "b"\n'
                    '  policy = "${ data.aws_iam_policy_document.d.minified_json }"\n}\n')
        self.assertIn("AWS-S3-003", rules({"main.tf": template % ("Bool", "aws:SecureTransport", "true")}))
        self.assertNotIn("AWS-S3-003", rules({"main.tf": template % (
            "StringEquals", "aws:PrincipalOrgID", "o-example")}))

    def test_google_iam_policy_resources_are_checked(self):
        text = ('resource "google_storage_bucket_iam_policy" "p" {\n  bucket = "b"\n'
                '  policy_data = jsonencode({bindings = [{role = "roles/storage.objectViewer",\n'
                '    members = ["allUsers"]}]})\n}\n')
        self.assertIn("GCP-IAM-001", rules({"main.tf": text}))
        plan = {"format_version": "1.2", "planned_values": {"root_module": {"resources": [{
            "address": "google_project_iam_policy.p", "mode": "managed", "type": "google_project_iam_policy",
            "values": {"project": "p", "policy_data": json.dumps(
                {"bindings": [{"role": "roles/owner", "members": ["user:a@example.com"]}]})}}]}}}
        self.assertIn("GCP-IAM-002", rules({"plan.json": plan}))

    def test_default_security_group_ingress_is_checked(self):
        self.assertIn("AWS-NET-001", rules({"main.tf": OPEN_SSH.replace(
            '"aws_security_group"', '"aws_default_security_group"')}))

    def test_instance_from_launch_template_is_not_called_imdsv1(self):
        result = scan({"main.tf": 'resource "aws_instance" "i" {\n  launch_template {\n'
                                  '    id = aws_launch_template.t.id\n  }\n}\n'})
        self.assertEqual(result.hits, [])
        self.assertTrue(any("launch template" in n for n in result.not_run))

    def test_inherited_or_serverless_encryption_is_not_flagged(self):
        for body in ('engine_mode = "serverless"', 'snapshot_identifier = "snap"',
                     'replication_source_identifier = "arn"'):
            with self.subTest(body=body):
                self.assertEqual(rules({"main.tf": f'resource "aws_rds_cluster" "c" {{\n  {body}\n}}\n'}), set())
        self.assertEqual(rules({"main.tf": 'resource "aws_rds_cluster" "c" {\n  engine = "aurora"\n}\n'}),
                         {"AWS-RDS-002"})

    def test_custom_key_store_keys_need_no_rotation(self):
        self.assertEqual(rules({"main.tf": 'resource "aws_kms_key" "k" {\n'
                                           '  custom_key_store_id = "cks-1234"\n}\n'}), set())

    def test_cloud_sql_without_ip_configuration_uses_the_defaults(self):
        self.assertIn("GCP-SQL-001", rules({"main.tf": 'resource "google_sql_database_instance" "d" {\n'
                                                       '  settings {\n    tier = "x"\n  }\n}\n'}))

    def test_firewall_protocol_spellings(self):
        for proto in ('6', '"TCP"'):
            with self.subTest(proto=proto):
                text = ('resource "google_compute_firewall" "f" {\n  source_ranges = ["0.0.0.0/0"]\n'
                        f'  allow {{\n    protocol = {proto}\n    ports = ["22"]\n  }}\n}}\n')
                self.assertIn("GCP-NET-001", rules({"main.tf": text}))

    def test_registry_submodule_without_version(self):
        text = 'module "u" {\n  source = "terraform-aws-modules/iam/aws//modules/iam-user"\n}\n'
        self.assertIn("PS-001", rules({"main.tf": text}))

    def test_gke_authorized_networks_open_to_the_internet(self):
        text = ('resource "google_container_cluster" "c" {\n  workload_identity_config {\n'
                '    workload_pool = "p.svc.id.goog"\n  }\n  master_authorized_networks_config {\n'
                '    cidr_blocks {\n      cidr_block = "0.0.0.0/0"\n    }\n  }\n}\n')
        self.assertEqual(hits({"main.tf": text}), [("GCP-GKE-001", "google_container_cluster.c", 5)])

    def test_default_alias_is_the_default_service_account(self):
        text = ('resource "google_compute_instance_template" "t" {\n  service_account {\n'
                '    email  = "default"\n    scopes = ["cloud-platform"]\n  }\n}\n')
        self.assertIn("GCP-GCE-001", rules({"main.tf": text}))

    def test_count_zero_and_empty_for_each_are_never_created(self):
        for meta in ("count = 0", "for_each = {}", "for_each = []"):
            with self.subTest(meta=meta):
                self.assertEqual(rules({"main.tf": f'resource "aws_ebs_volume" "v" {{\n  {meta}\n'
                                                   '  encrypted = false\n}\n'}), set())


class CloudFormationAndSnapshotTest(unittest.TestCase):
    def test_resource_line_is_its_own_key_not_a_ref(self):
        doc = '''{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Policy": {
      "Type": "AWS::S3::BucketPolicy",
      "Properties": {
        "Bucket": {"Ref": "Bucket"},
        "PolicyDocument": {"Statement": []}
      }
    },
    "Bucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {"AccessControl": "PublicRead"}
    }
  }
}
'''
        self.assertEqual(hits({"t.json": doc}), [("AWS-S3-001", "cfn:Bucket", 11)])

    def test_cfn_rds_and_public_access_block_match_terraform(self):
        def template(resources):
            return {"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources}
        aurora = {"Type": "AWS::RDS::DBInstance", "Properties": {"DBClusterIdentifier": {"Ref": "C"}}}
        self.assertEqual(rules({"t.json": template({"I": aurora})}), set())
        cluster = {"Type": "AWS::RDS::DBCluster", "Properties": {"StorageEncrypted": False}}
        self.assertEqual(rules({"t.json": template({"C": cluster})}), {"AWS-RDS-002"})
        bucket = {"Type": "AWS::S3::Bucket",
                  "Properties": {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True}}}
        result = scan({"t.json": template({"B": bucket})})
        self.assertEqual([h["detail"] for h in result.hits],
                         ["off: BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets"])

    def test_security_group_snapshot_line_is_the_groups_own(self):
        doc = {"SecurityGroups": [
            {"IpPermissions": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                                "UserIdGroupPairs": [{"GroupId": "sg-0db"}]}], "GroupId": "sg-0app"},
            {"IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}], "GroupId": "sg-0db"}]}
        text = json.dumps(doc, indent=2)
        expected = text.split("\n").index('      "GroupId": "sg-0db"') + 1
        self.assertEqual(hits({"aws-sg.json": text}), [("AWS-NET-001", "snapshot:sg-0db", expected)])

    def test_policy_files_get_identity_and_trust_rules(self):
        admin = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        # Alone, the file may be an SCP or a permissions boundary: noted, not flagged.
        result = scan({"policies/admin.json": admin})
        self.assertEqual(result.hits, [])
        self.assertTrue(any("review by hand: policies/admin.json" in n for n in result.not_run))
        # Read by an IAM policy resource, it is that resource's identity policy.
        tf = ('resource "aws_iam_policy" "admin" {\n  name = "admin"\n'
              '  policy = file("${path.module}/policies/admin.json")\n}\n')
        result = scan({"policies/admin.json": admin, "main.tf": tf})
        self.assertEqual([(h["rule"], h["file"], h["line"]) for h in result.hits],
                         [("AWS-IAM-001", "main.tf", 3)])
        self.assertFalse(any("admin.json" in n for n in result.not_run))
        trust = {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
                                "Principal": {"Federated": "arn:aws:iam::111122223333:oidc-provider/"
                                                           "token.actions.githubusercontent.com"},
                                "Condition": {"StringEquals": {
                                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}}]}
        self.assertEqual(rules({"trust.json": trust}), {"AWS-IAM-004"})
        anyone = {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": "*"}}]}
        self.assertEqual(rules({"trust.json": anyone}), {"AWS-IAM-003"})
        bucket = {"Statement": [
            {"Effect": "Deny", "NotPrincipal": {"AWS": "arn:aws:iam::111122223333:root"}, "Action": "*",
             "Resource": "arn:aws:s3:::b/*"},
            {"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "arn:aws:s3:::b/*",
             "Condition": {"Bool": {"aws:SecureTransport": "true"}}}]}
        self.assertEqual(rules({"bucket-policy.json": bucket}), {"AWS-S3-003"})


class KubernetesJsonTest(unittest.TestCase):
    def test_kubectl_json_exports_get_kubernetes_rules(self):
        pods = {"apiVersion": "v1", "kind": "List", "items": [{
            "apiVersion": "v1", "kind": "Pod", "metadata": {"name": "a", "namespace": "n"},
            "spec": {"hostPID": True, "containers": [{"name": "c", "securityContext": {"privileged": True}}]}}]}
        text = json.dumps(pods, indent=2)
        lines = text.split("\n")
        expected = sorted(("K8S-001", "k8s:Pod/n/a", n + 1) for n, line in enumerate(lines)
                          if '"hostPID"' in line or '"privileged"' in line)
        self.assertEqual(hits({"k8s-pods.json": text}), expected)
        binding = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
                   "metadata": {"name": "x"}, "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
                   "subjects": [{"kind": "Group", "name": "system:authenticated"}]}
        self.assertEqual(rules({"k8s-rbac.json": binding}), {"K8S-002"})


class DeepJsonTest(unittest.TestCase):
    def test_deep_kubernetes_json_is_noted_not_a_crash(self):
        text = '{"apiVersion": "v1", "kind": "ConfigMap", "data": ' + "[" * 5000 + "]" * 5000 + "}"
        try:
            json.loads(text)
        except RecursionError:
            self.skipTest("this Python's json module rejects the nesting itself")
        self.assertTrue(any("nested too deeply" in n for n in scan({"cm.json": text}).not_run))


class YamlKeyTest(unittest.TestCase):
    def test_boolean_spelled_keys_stay_strings(self):
        pod = ("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n  labels:\n    y: \"1\"\n    on: x\n"
               "    null: z\nspec:\n  hostNetwork: true\n  containers:\n  - name: c\n    image: x\n"
               "    securityContext:\n      privileged: true\n")
        result = scan({"pod.yaml": pod})
        self.assertEqual(result.not_run, [])
        self.assertEqual(sorted((h["rule"], h["line"]) for h in result.hits),
                         [("K8S-001", 10), ("K8S-001", 15)])

    def test_plain_keys_may_contain_colons(self):
        pod = ("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n  annotations:\n    example.com/a:b: x\n"
               "spec:\n  hostNetwork: true\n  containers:\n  - name: c\n    image: x\n")
        result = scan({"pod.yaml": pod})
        self.assertEqual(result.not_run, [])
        self.assertEqual([(h["rule"], h["line"]) for h in result.hits], [("K8S-001", 8)])



class SecretAttributeNameTest(unittest.TestCase):
    def test_pre_shared_keys_and_kms_plaintext_are_literal_secrets(self):
        value = "quiet" + "meadowlark"
        result = scan({"main.tf": f'resource "aws_kms_ciphertext" "c" {{\n  key_id = "k"\n  plaintext = "{value}"\n}}\n'
                                  f'resource "aws_vpn_connection" "v" {{\n  tunnel1_preshared_key = "{value}"\n}}\n',
                       "vpn.json": {"Resources": {"Vpn": {"Type": "AWS::EC2::VPNConnection", "Properties": {
                           "VpnTunnelOptionsSpecifications": [{"PreSharedKey": value}]}}}}})
        self.assertEqual(sorted((h["file"], h["line"]) for h in result.hits if h["rule"] == "SEC-001"),
                         [("main.tf", 3), ("main.tf", 6), ("vpn.json", 3)])
        # A one-line object holds secret-named keys as well as a block does.
        result = scan({"fn.tf": 'resource "aws_lambda_function" "f" {\n'
                                f'  environment {{ variables = {{ LOG = "x", DB_PASSWORD = "{value}" }} }}\n}}\n'
                                f'locals {{\n  db = {{ api_token = "{value}" }}\n}}\n'})
        self.assertEqual([(h["rule"], h["line"], h["detail"]) for h in result.hits],
                         [("SEC-001", 2, "literal value assigned to DB_PASSWORD"),
                          ("SEC-001", 5, "literal value assigned to api_token")])
        self.assertEqual(scan({"ok.tf": 'locals {\n  db = { password = var.pw, token_ttl = "300" }\n}\n'}).hits, [])
        # A comment that shows the shape is not configuration.
        self.assertEqual(scan({"c.tf": '# e.g. variables = { DB_PASSWORD = "changeme-in-comment" }\n'
                                       'locals {\n  a = 1 // { api_token = "in-a-comment" }\n}\n'}).hits, [])
        # CodeBuild's type = "PLAINTEXT" names a kind, not a secret.
        self.assertEqual(scan({"cb.tf": 'locals {\n  type = "PLAINTEXT"\n}\n'}).hits, [])


if __name__ == "__main__":
    unittest.main()
