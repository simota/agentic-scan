"""Baseline rules over resource types and condition forms they used to miss."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "infra-scan" / "scripts"))
import iac_scan  # noqa: E402


def scan(files):
    with tempfile.TemporaryDirectory(prefix="iac-rule-coverage-") as tmp:
        for name, text in files.items():
            path = Path(tmp) / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return iac_scan.run(tmp)


def hits(files):
    return sorted((h["rule"], h["address"], h["severity"]) for h in scan(files).hits)


def trust(name, condition):
    policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole", "Condition": condition}]}
    return f'resource "aws_iam_role" "{name}" {{\n  assume_role_policy = <<EOF\n{json.dumps(policy)}\nEOF\n}}\n'


class ConditionTest(unittest.TestCase):
    def test_arn_equals_with_a_wildcard_account_does_not_narrow(self):
        text = trust("equals", {"ArnEquals": {"aws:PrincipalArn": "arn:aws:iam::*:role/deployer"}})
        text += trust("pinned", {"ArnEquals": {"aws:PrincipalArn": "arn:aws:iam::111122223333:role/deployer"}})
        self.assertEqual(hits({"main.tf": text}), [("AWS-IAM-003", "aws_iam_role.equals", "High")])

    def test_interpolated_source_arn_narrows(self):
        policy = ('{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", '
                  '"Action": "sqs:SendMessage", "Resource": "*", '
                  '"Condition": {"%s": {"aws:SourceArn": "%s"}}}]}')
        text = ""
        for name, op, arn in (("topic", "ArnEquals", "${aws_sns_topic.t.arn}"),
                              ("like", "ArnLike", "${aws_sns_topic.t.arn}"),
                              ("data", "ArnEquals", "${data.aws_sns_topic.t.arn}"),
                              ("anyone", "ArnEquals", "arn:aws:sns:us-east-1:*:${var.topic}"),
                              ("input", "ArnLike", "${var.source_arn}")):
            text += (f'resource "aws_sqs_queue_policy" "{name}" {{\n  queue_url = "q"\n  policy = <<EOF\n'
                     f'{policy % (op, arn)}\nEOF\n}}\n')
        self.assertEqual(hits({"main.tf": text}), [("AWS-S3-003", "aws_sqs_queue_policy.anyone", "High"),
                                                   ("AWS-S3-003", "aws_sqs_queue_policy.input", "High")])

    def test_caller_set_keys_do_not_narrow(self):
        text = trust("tag", {"StringEquals": {"aws:PrincipalTag/team": "platform"}})
        text += trust("session", {"StringEquals": {"sts:RoleSessionName": "deploy"}})
        # Request tags and a source identity also need sts:TagSession /
        # sts:SetSourceIdentity, which this statement does not allow.
        text += trust("request", {"StringEquals": {"aws:RequestTag/team": "platform"}})
        text += trust("source", {"StringEquals": {"sts:SourceIdentity": "deployer"}})
        text += trust("org", {"StringEquals": {"aws:PrincipalTag/team": "platform",
                                                "aws:PrincipalOrgID": "o-abc123def4"}})
        self.assertEqual(hits({"main.tf": text}), [("AWS-IAM-003", "aws_iam_role.session", "High"),
                                                   ("AWS-IAM-003", "aws_iam_role.tag", "High")])


class ResourceTypeTest(unittest.TestCase):
    def test_public_object_acl(self):
        text = ('resource "aws_s3_object" "index" {\n  bucket = "site"\n  key = "index.html"\n'
                '  acl = "public-read"\n}\n'
                'resource "aws_s3_bucket_object" "legacy" {\n  bucket = "site"\n  key = "a"\n'
                '  acl = "public-read-write"\n}\n'
                'resource "aws_s3_object" "private" {\n  bucket = "site"\n  key = "b"\n  acl = "private"\n}\n')
        self.assertEqual(hits({"main.tf": text}), [("AWS-S3-001", "aws_s3_bucket_object.legacy", "High"),
                                                   ("AWS-S3-001", "aws_s3_object.index", "High")])

    def test_object_acl_under_a_public_access_block_is_low(self):
        text = ('resource "aws_s3_bucket" "site" {}\n'
                'resource "aws_s3_bucket_public_access_block" "site" {\n  bucket = aws_s3_bucket.site.id\n'
                '  block_public_acls = true\n  block_public_policy = true\n  ignore_public_acls = true\n'
                '  restrict_public_buckets = true\n}\n'
                'resource "aws_s3_object" "index" {\n  bucket = aws_s3_bucket.site.id\n  key = "i"\n'
                '  acl = "public-read"\n}\n')
        self.assertEqual(hits({"main.tf": text}), [("AWS-S3-001", "aws_s3_object.index", "Low")])

    def test_separate_kms_key_policy(self):
        policy = json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "kms:*", "Resource": "*"}]})
        text = ('resource "aws_kms_key" "k" {\n  enable_key_rotation = true\n}\n'
                f'resource "aws_kms_key_policy" "k" {{\n  key_id = aws_kms_key.k.id\n  policy = <<EOF\n{policy}\nEOF\n}}\n')
        self.assertEqual(hits({"main.tf": text}), [("AWS-S3-003", "aws_kms_key_policy.k", "High")])

    def test_exclusive_policy_attachments_with_administrator_access(self):
        text = ('resource "aws_iam_role_policy_attachments_exclusive" "x" {\n  role_name = "r"\n'
                '  policy_arns = ["arn:aws:iam::aws:policy/ReadOnlyAccess", '
                '"arn:aws:iam::aws:policy/AdministratorAccess"]\n}\n'
                'resource "aws_iam_user_policy_attachments_exclusive" "ro" {\n  user_name = "u"\n'
                '  policy_arns = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]\n}\n')
        self.assertEqual(hits({"main.tf": text}),
                         [("AWS-IAM-001", "aws_iam_role_policy_attachments_exclusive.x", "High")])

    def test_aws_workload_identity_provider_is_medium(self):
        text = ('resource "google_iam_workload_identity_pool_provider" "aws" {\n'
                '  workload_identity_pool_id = "p"\n  workload_identity_pool_provider_id = "aws"\n'
                '  aws {\n    account_id = "111122223333"\n  }\n}\n'
                'resource "google_iam_workload_identity_pool_provider" "gh" {\n'
                '  workload_identity_pool_id = "p"\n  workload_identity_pool_provider_id = "gh"\n'
                '  oidc {\n    issuer_uri = "https://token.actions.githubusercontent.com"\n  }\n}\n')
        found = scan({"main.tf": text}).hits
        by_address = {h["address"]: h for h in found}
        self.assertEqual(by_address["google_iam_workload_identity_pool_provider.aws"]["severity"], "Medium")
        self.assertIn("AWS provider", by_address["google_iam_workload_identity_pool_provider.aws"]["detail"])
        self.assertEqual(by_address["google_iam_workload_identity_pool_provider.gh"]["severity"], "High")


class UnresolvedIngressTest(unittest.TestCase):
    def test_variable_and_parameter_cidrs_on_admin_ports_are_named(self):
        tf = ('variable "ssh_cidr" {}\nresource "aws_security_group" "ssh" {\n  ingress {\n'
              '    from_port = 22\n    to_port = 22\n    protocol = "tcp"\n    cidr_blocks = [var.ssh_cidr]\n'
              '  }\n  ingress {\n    from_port = 443\n    to_port = 443\n    protocol = "tcp"\n'
              '    cidr_blocks = [var.ssh_cidr]\n  }\n}\n')
        cfn = ('AWSTemplateFormatVersion: "2010-09-09"\nParameters:\n  SSHLocation:\n    Type: String\n'
               'Resources:\n  Sg:\n    Type: AWS::EC2::SecurityGroup\n    Properties:\n'
               '      GroupDescription: ssh\n      SecurityGroupIngress:\n        - IpProtocol: tcp\n'
               '          FromPort: 22\n          ToPort: 22\n          CidrIp: !Ref SSHLocation\n')
        result = scan({"main.tf": tf, "sg.yaml": cfn})
        self.assertEqual(result.hits, [])
        notes = [n for n in result.not_run if n.startswith("AWS-NET-001: source CIDR unresolved")]
        self.assertEqual(len(notes), 2, result.not_run)
        self.assertTrue(any("aws_security_group.ssh" in n for n in notes))
        self.assertTrue(any("cfn:Sg" in n for n in notes))

    def test_vpc_and_subnet_cidrs_are_not_inputs(self):
        sources = ("module.vpc.vpc_cidr_block", "data.aws_vpc.x.cidr_block", "aws_vpc.main.cidr_block",
                   "aws_subnet.p[0].cidr_block")
        tf = 'resource "aws_security_group" "db" {\n' + "".join(
            f'  ingress {{\n    from_port = 5432\n    to_port = 5432\n    protocol = "tcp"\n'
            f'    cidr_blocks = [{src}]\n  }}\n' for src in sources) + "}\n"
        tf += ('resource "aws_security_group_rule" "all" {\n  type = "ingress"\n  security_group_id = "sg"\n'
               '  from_port = 0\n  to_port = 65535\n  protocol = "tcp"\n'
               '  cidr_blocks = module.vpc.private_subnets_cidr_blocks\n}\n')
        cfn = ('AWSTemplateFormatVersion: "2010-09-09"\nResources:\n  Sg:\n    Type: AWS::EC2::SecurityGroup\n'
               '    Properties:\n      GroupDescription: db\n      SecurityGroupIngress:\n'
               '        - IpProtocol: tcp\n          FromPort: 5432\n          ToPort: 5432\n'
               '          CidrIp: !GetAtt Vpc.CidrBlock\n')
        result = scan({"main.tf": tf, "sg.yaml": cfn})
        self.assertEqual([n for n in result.not_run if n.startswith("AWS-NET-001")], [])


if __name__ == "__main__":
    unittest.main()
