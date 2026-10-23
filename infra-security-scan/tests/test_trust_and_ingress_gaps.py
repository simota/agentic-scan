"""GitHub OIDC trust behind neutral names, conditions any caller satisfies,
for_each ingress and unread policy statements: each is a hit or a not_run line,
never silence."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "infra-scan" / "scripts"))
import iac_scan  # noqa: E402


def scan(files):
    with tempfile.TemporaryDirectory(prefix="iac-trust-ingress-") as tmp:
        for name, text in files.items():
            path = Path(tmp) / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return iac_scan.run(tmp)


def hits(text):
    return sorted((h["rule"], h["address"]) for h in scan({"main.tf": text}).hits)


def trust(principal, condition=""):
    return f'''resource "aws_iam_role" "ci" {{
  assume_role_policy = jsonencode({{
    Statement = [{{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = {{ Federated = {principal} }}
      {condition}
    }}]
  }})
}}
'''


def public(condition, kind="trust"):
    if kind == "trust":
        return f'''resource "aws_iam_role" "r" {{
  assume_role_policy = jsonencode({{
    Statement = [{{ Effect = "Allow", Principal = {{ AWS = "*" }}, Action = "sts:AssumeRole",
                   Condition = {condition} }}]
  }})
}}
'''
    return f'''resource "aws_s3_bucket_policy" "b" {{
  bucket = "data-bucket"
  policy = jsonencode({{
    Statement = [{{ Effect = "Allow", Principal = "*", Action = "s3:GetObject",
                   Resource = "arn:aws:s3:::data-bucket/*", Condition = {condition} }}]
  }})
}}
'''


GITHUB_PROVIDER = '''resource "aws_iam_openid_connect_provider" "this" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}
'''


class GithubTrustTest(unittest.TestCase):
    def test_a_provider_reference_resolves_to_its_url(self):
        self.assertEqual(hits(GITHUB_PROVIDER + trust("aws_iam_openid_connect_provider.this.arn")),
                         [("AWS-IAM-004", "aws_iam_role.ci")])

    def test_a_policy_document_principal_resolves_to_its_url(self):
        doc = '''data "aws_iam_policy_document" "t" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.this.arn]
    }
  }
}
resource "aws_iam_role" "ci" {
  assume_role_policy = data.aws_iam_policy_document.t.json
}
'''
        self.assertEqual(hits(GITHUB_PROVIDER + doc), [("AWS-IAM-004", "aws_iam_role.ci")])

    def test_an_interpolated_provider_arn_is_github(self):
        arn = '"arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"'
        self.assertEqual(hits(trust(arn)), [("AWS-IAM-004", "aws_iam_role.ci")])
        pinned = 'Condition = { StringEquals = { "token.actions.githubusercontent.com:sub" = "repo:org/app:ref:refs/heads/main" } }'
        self.assertEqual(hits(trust(arn, pinned)), [])

    def test_another_oidc_provider_is_not_github(self):
        eks = '''resource "aws_iam_openid_connect_provider" "this" {
  url            = "https://oidc.eks.eu-west-1.amazonaws.com/id/EXAMPLE"
  client_id_list = ["sts.amazonaws.com"]
}
'''
        self.assertEqual(hits(eks + trust("aws_iam_openid_connect_provider.this.arn")), [])

    def test_a_github_enterprise_issuer(self):
        arn = '"arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com/octo-enterprise"'
        any_repo = ('Condition = { StringLike = { "token.actions.githubusercontent.com/octo-enterprise:sub" = '
                    '"repo:*" } }')
        self.assertEqual(hits(trust(arn, any_repo)), [("AWS-IAM-004", "aws_iam_role.ci")])
        pinned = any_repo.replace('"repo:*"', '"repo:octo/app:ref:refs/heads/main"')
        self.assertEqual(hits(trust(arn, pinned)), [])


class OpenConditionTest(unittest.TestCase):
    def test_for_all_values_holds_for_a_caller_without_the_key(self):
        cond = '{ "ForAllValues:StringEquals" = { "aws:PrincipalOrgID" = ["o-abc123"] } }'
        self.assertEqual(hits(public(cond)), [("AWS-IAM-003", "aws_iam_role.r")])
        self.assertEqual(hits(public(cond, "bucket")), [("AWS-S3-003", "aws_s3_bucket_policy.b")])
        self.assertEqual(hits(public('{ StringEquals = { "aws:PrincipalOrgID" = "o-abc123" } }')), [])

    def test_patterns_any_account_or_organization_matches(self):
        for cond in ('{ ArnLike = { "aws:PrincipalArn" = "arn:aws:iam::*:role/deployer" } }',
                     '{ StringLike = { "aws:PrincipalArn" = "arn:aws:iam::*:*" } }',
                     '{ StringLike = { "aws:PrincipalOrgID" = "o-*" } }'):
            with self.subTest(cond=cond):
                self.assertEqual(hits(public(cond)), [("AWS-IAM-003", "aws_iam_role.r")])
        for cond in ('{ ArnLike = { "aws:PrincipalArn" = "arn:aws:iam::111111111111:role/*" } }',
                     '{ StringLike = { "aws:PrincipalOrgID" = "o-abc123" } }'):
            with self.subTest(cond=cond):
                self.assertEqual(hits(public(cond)), [])


class IngressTest(unittest.TestCase):
    def test_for_each_ports_are_checked_per_element(self):
        text = '''resource "aws_security_group_rule" "admin" {
  for_each          = toset(["22", "3389"])
  type              = "ingress"
  from_port         = each.value
  to_port           = each.value
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "sg-1"
}
resource "aws_vpc_security_group_ingress_rule" "db" {
  for_each          = { postgres = 5432 }
  security_group_id = "sg-1"
  ip_protocol       = "tcp"
  from_port         = each.value
  to_port           = each.value
  cidr_ipv4         = "0.0.0.0/0"
}
resource "aws_vpc_security_group_ingress_rule" "web" {
  for_each          = toset(["443"])
  security_group_id = "sg-1"
  ip_protocol       = "tcp"
  from_port         = each.value
  to_port           = each.value
  cidr_ipv4         = "0.0.0.0/0"
}
resource "google_compute_firewall" "admin" {
  for_each      = toset(["22"])
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = [each.value]
  }
}
'''
        self.assertEqual(hits(text), [("AWS-NET-001", "aws_security_group_rule.admin"),
                                      ("AWS-NET-001", "aws_security_group_rule.admin"),
                                      ("AWS-NET-001", "aws_vpc_security_group_ingress_rule.db"),
                                      ("GCP-NET-001", "google_compute_firewall.admin")])

    def test_unresolved_ports_open_to_the_world_are_named(self):
        text = '''resource "aws_security_group_rule" "unk" {
  type              = "ingress"
  from_port         = var.port
  to_port           = var.port
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "sg-1"
}
resource "google_compute_firewall" "unk" {
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = var.ports
  }
}
resource "aws_security_group_rule" "internal" {
  type              = "ingress"
  from_port         = var.port
  to_port           = var.port
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/8"]
  security_group_id = "sg-1"
}
'''
        result = scan({"main.tf": text})
        self.assertEqual(result.hits, [])
        named = [line for line in result.not_run if "unresolved protocol or ports" in line]
        self.assertEqual(len(named), 2, result.not_run)
        self.assertTrue(any("aws_security_group_rule.unk" in line for line in named))
        self.assertTrue(any("google_compute_firewall.unk" in line for line in named))

    def test_an_empty_eks_public_access_list_takes_the_open_default(self):
        text = '''resource "aws_eks_cluster" "c" {
  vpc_config {
    subnet_ids             = ["subnet-1"]
    endpoint_public_access = true
    public_access_cidrs    = []
  }
}
'''
        self.assertEqual(hits(text), [("AWS-EKS-001", "aws_eks_cluster.c")])


class ServiceAgentTest(unittest.TestCase):
    def test_a_templated_agent_in_members_reads_like_member(self):
        agent = '"serviceAccount:service-${data.google_project.p.number}@gcp-sa-pubsub.iam.gserviceaccount.com"'
        binding = '''resource "google_project_iam_binding" "b" {{
  project = "p"
  role    = "roles/iam.serviceAccountTokenCreator"
  members = [{members}]
}}
'''
        result = scan({"main.tf": binding.format(members=agent)})
        self.assertEqual((result.hits, result.not_run), ([], []))
        mixed = binding.format(members=agent + ', "user:dev@example.com"')
        self.assertEqual(hits(mixed), [("GCP-IAM-004", "google_project_iam_binding.b")])


class PolicyStatementTest(unittest.TestCase):
    def test_statements_not_written_as_literals_are_named(self):
        text = '''resource "aws_s3_bucket_policy" "p" {
  bucket = "b"
  policy = jsonencode({ Statement = concat(local.base, [{ Effect = "Allow", Principal = "*", Action = "s3:*" }]) })
}
resource "aws_iam_policy" "q" {
  policy = jsonencode({ Statement = [local.admin_statement] })
}
'''
        result = scan({"main.tf": text})
        named = [line for line in result.not_run if line.startswith("policy statements not resolved")]
        self.assertEqual(len(named), 2, result.not_run)


if __name__ == "__main__":
    unittest.main()
