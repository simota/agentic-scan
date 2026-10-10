"""Precision and recall cases from an audit on realistic secure and vulnerable code."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "infra-scan" / "scripts"))
import iac_scan  # noqa: E402


def scan(files):
    with tempfile.TemporaryDirectory(prefix="iac-audit-") as tmp:
        for name, text in files.items():
            path = Path(tmp) / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text if isinstance(text, str) else json.dumps(text, indent=2), encoding="utf-8")
        return iac_scan.run(tmp)


def rules(files):
    return sorted({h["rule"] for h in scan(files).hits})


def cfn(resources):
    return {"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources}


class SecureCodeIsQuietTest(unittest.TestCase):
    def test_secret_like_names_that_hold_no_secret(self):
        text = ('resource "aws_cognito_user_pool_client" "c" {\n  token_validity_units {\n'
                '    access_token  = "minutes"\n    id_token      = "minutes"\n    refresh_token = "days"\n  }\n}\n'
                'resource "google_cloud_run_v2_service" "s" {\n  template {\n    containers {\n      env {\n'
                '        value_source {\n          secret_key_ref {\n            secret  = "billing-db-password"\n'
                '            version = "latest"\n          }\n        }\n      }\n    }\n  }\n}\n')
        self.assertEqual(rules({"main.tf": text}), [])
        self.assertEqual(rules({"README.md": "export AWS_ACCESS_KEY_ID=AKIA" + "IOSFODNN7EXAMPLE\n"}), [])

    def test_local_emulator_provider(self):
        text = ('provider "aws" {\n  access_key = "test"\n  secret_key = "test"\n'
                '  skip_credentials_validation = true\n  endpoints {\n    s3 = "http://localhost:4566"\n  }\n}\n')
        self.assertNotIn("PS-003", rules({"main.tf": text}))

    def test_kubernetes_bootstrap_rbac(self):
        export = {"apiVersion": "v1", "kind": "List", "items": [
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
             "metadata": {"name": "cluster-admin", "labels": {"kubernetes.io/bootstrapping": "rbac-defaults"}},
             "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
             "subjects": [{"kind": "Group", "name": "system:masters"}]},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
             "metadata": {"name": "system:discovery", "labels": {"kubernetes.io/bootstrapping": "rbac-defaults"}},
             "roleRef": {"kind": "ClusterRole", "name": "system:discovery"},
             "subjects": [{"kind": "Group", "name": "system:authenticated"}]}]}
        self.assertEqual(rules({"rbac.json": export}), [])

    def test_google_service_agent_grants(self):
        text = ('resource "google_project_iam_member" "pubsub" {\n  project = "p"\n'
                '  role    = "roles/iam.serviceAccountTokenCreator"\n'
                '  member  = "serviceAccount:service-${data.google_project.p.number}@gcp-sa-pubsub.iam.gserviceaccount.com"\n}\n')
        self.assertEqual(rules({"main.tf": text}), [])

    def test_dns_only_gke_endpoint(self):
        text = ('resource "google_container_cluster" "c" {\n  workload_identity_config {\n    workload_pool = "p.svc.id.goog"\n  }\n'
                '  control_plane_endpoints_config {\n    ip_endpoints_config {\n      enabled = false\n    }\n  }\n}\n')
        self.assertEqual(rules({"main.tf": text}), [])

    def test_permissions_boundary_is_not_a_grant(self):
        text = ('resource "aws_iam_policy" "boundary" {\n  policy = jsonencode({Statement = [\n'
                '    {Effect = "Allow", Action = "*", Resource = "*"},\n'
                '    {Effect = "Deny", Action = "iam:*", Resource = "*"}]})\n}\n'
                'resource "aws_iam_role" "r" {\n  assume_role_policy = "{}"\n'
                '  permissions_boundary = aws_iam_policy.boundary.arn\n}\n')
        result = scan({"main.tf": text})
        self.assertEqual(result.hits, [])
        self.assertTrue(any("permissions boundary" in n for n in result.not_run))

    def test_permissions_boundary_in_a_plan_uses_configuration_references(self):
        policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        plan = {"format_version": "1.2", "planned_values": {"root_module": {"child_modules": [{
            "address": "module.app", "resources": [
                {"address": "module.app.aws_iam_policy.b", "mode": "managed", "type": "aws_iam_policy",
                 "values": {"policy": json.dumps(policy)}},
                {"address": "module.app.aws_iam_role.r", "mode": "managed", "type": "aws_iam_role",
                 "values": {"assume_role_policy": "{}"}}]}]}},
            "configuration": {"root_module": {"module_calls": {"app": {"module": {"resources": [
                {"address": "aws_iam_role.r", "expressions": {"permissions_boundary": {
                    "references": ["aws_iam_policy.b.arn", "aws_iam_policy.b"]}}}]}}}}}}
        self.assertEqual(rules({"plan.json": plan}), [])

    def test_account_defaults_cover_omitted_settings(self):
        text = ('resource "aws_ec2_instance_metadata_defaults" "d" {\n  http_tokens = "required"\n}\n'
                'resource "aws_ebs_encryption_by_default" "d" {\n  enabled = true\n}\n'
                'resource "aws_instance" "i" {\n  ami = "ami-1"\n}\n'
                'resource "aws_ebs_volume" "v" {\n  size = 1\n}\n')
        self.assertEqual(rules({"main.tf": text}), [])
        explicit = text.replace('size = 1', 'encrypted = false')
        self.assertEqual(rules({"main.tf": explicit}), ["AWS-EBS-001"])

    def test_restores_and_inherited_bucket_protection(self):
        self.assertEqual(rules({"main.tf": 'resource "aws_db_instance" "d" {\n  restore_to_point_in_time {\n'
                                           '    source_db_instance_identifier = "src"\n  }\n}\n'}), [])
        org = ('resource "google_org_policy_policy" "pap" {\n  name = "organizations/1/policies/'
               'storage.publicAccessPrevention"\n  parent = "organizations/1"\n  spec {\n    rules {\n'
               '      enforce = "TRUE"\n    }\n  }\n}\n'
               'resource "google_storage_bucket" "b" {\n  uniform_bucket_level_access = true\n'
               '  public_access_prevention = "inherited"\n}\n')
        self.assertEqual(rules({"main.tf": org}), [])

    def test_terragrunt_generates_the_backend(self):
        files = {"live/prod/net/main.tf": 'resource "aws_vpc" "v" {}\n',
                 "live/terragrunt.hcl": 'remote_state {\n  backend = "s3"\n}\n'}
        self.assertEqual(rules(files), [])


class VulnerableCodeIsCaughtTest(unittest.TestCase):
    def test_firewall_without_sources_or_with_computed_direction(self):
        text = ('resource "google_compute_firewall" "f" {\n  network = "n"\n'
                '  allow {\n    protocol = "tcp"\n    ports = ["22"]\n  }\n}\n')
        self.assertEqual(rules({"main.tf": text}), ["GCP-NET-001"])
        plan = {"format_version": "1.2", "planned_values": {"root_module": {"resources": [{
            "address": "google_compute_firewall.f", "mode": "managed", "type": "google_compute_firewall",
            "values": {"source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "tcp", "ports": ["0-65535"]}]}}]}},
            "resource_changes": [{"address": "google_compute_firewall.f",
                                  "change": {"actions": ["create"], "after_unknown": {"direction": True}}}]}
        self.assertEqual(rules({"plan.json": plan}), ["GCP-NET-001"])

    def test_s3_grants_to_all_users(self):
        text = ('resource "aws_s3_bucket_acl" "a" {\n  bucket = "b"\n  access_control_policy {\n    grant {\n'
                '      grantee {\n        type = "Group"\n        uri  = "http://acs.amazonaws.com/groups/global/AllUsers"\n'
                '      }\n      permission = "READ"\n    }\n    owner {\n      id = "x"\n    }\n  }\n}\n')
        self.assertEqual(rules({"main.tf": text}), ["AWS-S3-001"])

    def test_github_trust_through_a_provider_reference(self):
        text = ('resource "aws_iam_role" "r" {\n  assume_role_policy = jsonencode({Statement = [{\n'
                '    Effect = "Allow", Action = "sts:AssumeRoleWithWebIdentity",\n'
                '    Principal = {Federated = aws_iam_openid_connect_provider.github.arn},\n'
                '    Condition = {StringEquals = {"token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"}}}]})\n}\n')
        self.assertEqual(rules({"main.tf": text}), ["AWS-IAM-004"])
        doc = cfn({"R": {"Type": "AWS::IAM::Role", "Properties": {"AssumeRolePolicyDocument": {"Statement": [{
            "Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
            "Principal": {"Federated": {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:oidc-provider/"
                                                   "token.actions.githubusercontent.com"}},
            "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}}]}}}})
        self.assertEqual(rules({"t.json": doc}), ["AWS-IAM-004"])

    def test_admin_policy_with_an_interpolated_partition(self):
        text = ('resource "aws_iam_role_policy_attachment" "a" {\n  role = "r"\n'
                '  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AdministratorAccess"\n}\n')
        self.assertEqual(rules({"main.tf": text}), ["AWS-IAM-001"])
        doc = cfn({"U": {"Type": "AWS::IAM::User", "Properties": {
            "ManagedPolicyArns": [{"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/AdministratorAccess"}]}}})
        self.assertEqual(rules({"t.json": doc}), ["AWS-IAM-001"])

    def test_cloudformation_parity(self):
        doc = cfn({"K": {"Type": "AWS::KMS::Key", "Properties": {}},
                   "T": {"Type": "AWS::CloudTrail::Trail", "Properties": {"IsLogging": True}},
                   "V": {"Type": "AWS::EC2::Volume", "Properties": {"Size": 1}},
                   "E": {"Type": "AWS::EKS::Cluster", "Properties": {"ResourcesVpcConfig": {"SubnetIds": ["s"]}}},
                   "A": {"Type": "AWS::IAM::AccessKey", "Properties": {"UserName": "u"}},
                   "Q": {"Type": "AWS::SQS::QueuePolicy", "Properties": {"PolicyDocument": {"Statement": [
                       {"Effect": "Allow", "Principal": "*", "Action": "sqs:SendMessage", "Resource": "*"}]}}},
                   "R": {"Type": "AWS::Redshift::Cluster", "Properties": {"PubliclyAccessible": True}},
                   "C": {"Type": "AWS::CloudFront::Distribution", "Properties": {"DistributionConfig": {
                       "DefaultCacheBehavior": {"ViewerProtocolPolicy": "allow-all"}}}}})
        self.assertEqual(rules({"t.json": doc}), ["AWS-CF-001", "AWS-CT-001", "AWS-EBS-001", "AWS-EKS-001",
                                                  "AWS-IAM-005", "AWS-KMS-001", "AWS-RDS-001", "AWS-S3-003"])

    def test_new_terraform_rules(self):
        files = {
            "policy.tf": ('resource "aws_sqs_queue_policy" "q" {\n  queue_url = "u"\n  policy = jsonencode({Statement = [\n'
                          '    {Effect = "Allow", Principal = "*", Action = "sqs:SendMessage", Resource = "*"}]})\n}\n'),
            "data.tf": 'resource "aws_redshift_cluster" "r" {\n  publicly_accessible = true\n}\n',
            "snap.tf": 'resource "aws_db_snapshot" "s" {\n  shared_accounts = ["all"]\n}\n',
            "gcs.tf": ('resource "google_storage_bucket_acl" "a" {\n  bucket = "b"\n'
                       '  role_entity = ["READER:allUsers"]\n}\n'
                       'resource "google_bigquery_dataset" "d" {\n  dataset_id = "d"\n'
                       '  access {\n    role = "READER"\n    special_group = "allAuthenticatedUsers"\n  }\n}\n'),
            "cf.tf": ('resource "aws_cloudfront_distribution" "d" {\n  viewer_certificate {\n'
                      '    acm_certificate_arn = "arn"\n    minimum_protocol_version = "TLSv1"\n  }\n}\n'),
            "ec2.tf": ('resource "aws_instance" "i" {\n  metadata_options {\n    http_tokens = "required"\n  }\n'
                       '  root_block_device {\n    encrypted = false\n  }\n}\n'),
        }
        self.assertEqual(rules(files), ["AWS-CF-001", "AWS-EBS-001", "AWS-RDS-001", "AWS-S3-003",
                                        "AWS-SNAP-001", "GCP-GCS-002"])

    def test_dangerous_capabilities_and_rollouts(self):
        pod = ("apiVersion: argoproj.io/v1alpha1\nkind: Rollout\nmetadata:\n  name: r\nspec:\n  template:\n"
               "    spec:\n      containers:\n      - name: c\n        image: x\n        securityContext:\n"
               "          capabilities:\n            add: [\"NET_ADMIN\", \"SYS_ADMIN\"]\n")
        self.assertEqual(rules({"r.yaml": pod}), ["K8S-001"])

    def test_plan_unknowns_report_only_attributes_rules_read(self):
        plan = {"format_version": "1.2", "planned_values": {"root_module": {"resources": [{
            "address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "values": {"bucket": "b"}}]}},
            "resource_changes": [{"address": "aws_s3_bucket.b",
                                  "change": {"actions": ["create"], "after_unknown": {"id": True, "arn": True}}}]}
        self.assertEqual(scan({"plan.json": plan}).not_run, [])


if __name__ == "__main__":
    unittest.main()


class ReviewRegressionTest(unittest.TestCase):
    """Precision fixes must not hide real issues (found by a review of this branch)."""

    def test_unrelated_policy_with_the_same_name_is_still_admin(self):
        files = {"modules/boundary/main.tf": ('resource "aws_iam_policy" "this" {\n  policy = jsonencode({Statement = [\n'
                                              '    {Effect = "Allow", Action = "*", Resource = "*"}]})\n}\n'
                                              'resource "aws_iam_role" "r" {\n  assume_role_policy = "{}"\n'
                                              '  permissions_boundary = aws_iam_policy.this.arn\n}\n'),
                 "modules/admin/main.tf": ('resource "aws_iam_policy" "this" {\n  policy = jsonencode({Statement = [\n'
                                           '    {Effect = "Allow", Action = "*", Resource = "*"}]})\n}\n'
                                           'output "arn" {\n  value = aws_iam_policy.this.arn\n}\n')}
        hits = [(h["rule"], h["file"]) for h in scan(files).hits]
        self.assertEqual(hits, [("AWS-IAM-001", "modules/admin/main.tf")])

    def test_boundary_also_attached_elsewhere_is_admin(self):
        text = ('resource "aws_iam_policy" "admin" {\n  policy = jsonencode({Statement = [\n'
                '    {Effect = "Allow", Action = "*", Resource = "*"}]})\n}\n'
                'resource "aws_iam_role" "r" {\n  assume_role_policy = "{}"\n'
                '  permissions_boundary = aws_iam_policy.admin.arn\n}\n'
                'module "x" {\n  source = "./x"\n  custom_role_policy_arns = [aws_iam_policy.admin.arn]\n}\n')
        self.assertIn("AWS-IAM-001", rules({"main.tf": text}))

    def test_non_literal_cloudformation_type_is_skipped(self):
        result = scan({"t.json": cfn({"X": {"Type": ["AWS::S3::Bucket"]}})})
        self.assertTrue(any("non-literal Type" in n for n in result.not_run))

    def test_long_tokens_and_mixed_example_lines(self):
        texts = ['note = "glpat-' + "a1B2" * 7 + '"\n',
                 'keys = ["AKIA' + 'IOSFODNN7EXAMPLE", "AKIA' + "Q7" * 8 + '"]\n']
        for text in texts:
            with self.subTest(text=text[:12]):
                self.assertIn("SEC-001", rules({"main.tf": text}))

    def test_bare_secret_key_with_a_passphrase_is_still_a_secret(self):
        text = ('resource "github_repository_webhook" "w" {\n  configuration {\n'
                '    secret = "correct-horse-battery-staple"\n  }\n}\n')
        self.assertIn("SEC-001", rules({"main.tf": text}))

    def test_service_agent_exemption_is_narrow(self):
        mixed = ('resource "google_project_iam_binding" "b" {\n  project = "p"\n  role = "roles/editor"\n'
                 '  members = ["user:contractor@example.com", "serviceAccount:1@cloudservices.gserviceaccount.com"]\n}\n')
        self.assertIn("GCP-IAM-002", rules({"main.tf": mixed}))
        build = ('resource "google_project_iam_member" "m" {\n  project = "p"\n  role = "roles/owner"\n'
                 '  member = "serviceAccount:1@cloudbuild.gserviceaccount.com"\n}\n')
        self.assertIn("GCP-IAM-002", rules({"main.tf": build}))
        agent_owner = build.replace("cloudbuild", "cloudservices")
        self.assertIn("GCP-IAM-002", rules({"main.tf": agent_owner}))

    def test_vpc_opensearch_domain_policy_is_not_public(self):
        text = ('resource "aws_opensearch_domain" "d" {\n  vpc_options {\n    subnet_ids = ["s"]\n  }\n'
                '  access_policies = jsonencode({Statement = [{Effect = "Allow", Principal = {AWS = "*"},\n'
                '    Action = "es:*", Resource = "*"}]})\n}\n')
        self.assertEqual(rules({"main.tf": text}), [])

    def test_project_level_prevention_covers_only_its_module(self):
        files = {"project-a/main.tf": ('resource "google_project_organization_policy" "p" {\n  project = "a"\n'
                                       '  constraint = "storage.publicAccessPrevention"\n'
                                       '  boolean_policy {\n    enforced = true\n  }\n}\n'),
                 "project-b/main.tf": ('resource "google_storage_bucket" "b" {\n'
                                       '  uniform_bucket_level_access = true\n}\n')}
        self.assertEqual(rules(files), ["GCP-GCS-001"])
