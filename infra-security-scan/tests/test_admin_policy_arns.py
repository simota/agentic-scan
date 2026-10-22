"""Only the AWS-managed AdministratorAccess ARN proves administrator access."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "infra-scan" / "scripts"))
import iac_scan  # noqa: E402


class AdministratorPolicyArnTest(unittest.TestCase):
    TRUST = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": "sts:AssumeRole",
        "Principal": {"Service": "ec2.amazonaws.com"},
    }]}

    def scan(self, arn, form):
        if form == "attachment":
            name = "main.tf"
            text = 'resource "aws_iam_role_policy_attachment" "app" {\n' + \
                   '  role = "app"\n  policy_arn = ' + json.dumps(arn) + '\n}\n'
        elif form == "role":
            name = "main.tf"
            text = 'resource "aws_iam_role" "app" {\n' + \
                   '  assume_role_policy = jsonencode(' + json.dumps(self.TRUST) + ')\n' + \
                   '  managed_policy_arns = ' + json.dumps([arn]) + '\n}\n'
        else:
            name = "stack.json"
            text = json.dumps({"Resources": {"App": {"Type": "AWS::IAM::Role", "Properties": {
                "AssumeRolePolicyDocument": self.TRUST, "ManagedPolicyArns": [arn],
            }}}})
        with tempfile.TemporaryDirectory(prefix="iac-admin-arn-") as tmp:
            (Path(tmp) / name).write_text(text, encoding="utf-8")
            return iac_scan.run(tmp)

    def test_customer_managed_policy_name_does_not_prove_its_permissions(self):
        for partition in ("aws", "aws-cn", "aws-us-gov"):
            for form in ("attachment", "role", "cloudformation"):
                with self.subTest(partition=partition, form=form):
                    arn = f"arn:{partition}:iam::111122223333:policy/AdministratorAccess"
                    scan = self.scan(arn, form)
                    self.assertEqual(scan.hits, [])

    def test_aws_managed_administrator_policy_is_detected_in_each_partition(self):
        for partition in ("aws", "aws-cn", "aws-us-gov", "aws-iso", "aws-iso-b"):
            for form in ("attachment", "role", "cloudformation"):
                with self.subTest(partition=partition, form=form):
                    arn = f"arn:{partition}:iam::aws:policy/AdministratorAccess"
                    scan = self.scan(arn, form)
                    self.assertEqual([h["rule"] for h in scan.hits], ["AWS-IAM-001"])


class AdministratorPolicyReferenceTest(unittest.TestCase):
    def hits(self, text):
        with tempfile.TemporaryDirectory(prefix="iac-admin-ref-") as tmp:
            (Path(tmp) / "main.tf").write_text(text, encoding="utf-8")
            return sorted(r for h in iac_scan.run(tmp).hits if h["rule"] == "AWS-IAM-001" for r in [h["address"]])

    def test_managed_policy_arns_follow_an_admin_data_source(self):
        self.assertEqual(self.hits(
            'data "aws_iam_policy" "admin" {\n  name = "AdministratorAccess"\n}\n'
            'resource "aws_iam_role" "r" {\n  assume_role_policy = "{}"\n'
            '  managed_policy_arns = [data.aws_iam_policy.admin.arn]\n}\n'), ["aws_iam_role.r"])

    def test_map_for_each_feeds_each_value(self):
        self.assertEqual(self.hits(
            'resource "aws_iam_role_policy_attachment" "a" {\n'
            '  for_each   = { admin = "arn:aws:iam::aws:policy/AdministratorAccess" }\n'
            '  role       = "app"\n  policy_arn = each.value\n}\n'
            'resource "aws_iam_role_policy_attachment" "keys" {\n'
            '  for_each   = { admin = "arn:aws:iam::aws:policy/AdministratorAccess" }\n'
            '  role       = "app"\n  policy_arn = each.key\n}\n'), ["aws_iam_role_policy_attachment.a"])


if __name__ == "__main__":
    unittest.main()
