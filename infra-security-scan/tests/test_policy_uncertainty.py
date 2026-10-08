"""IAM document composition and unresolved object keys stay explicitly unknown."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "infra-scan" / "scripts"))
import iac_scan  # noqa: E402


class PolicyUncertaintyTest(unittest.TestCase):
    def scan(self, text):
        with tempfile.TemporaryDirectory(prefix="iac-policy-uncertainty-") as tmp:
            (Path(tmp) / "main.tf").write_text(text, encoding="utf-8")
            return iac_scan.run(tmp)

    def composed_policy(self, extra, local=True, related=""):
        statement = '''  statement {
    sid = "Access"
    effect = "Allow"
    actions = ["*"]
    resources = ["*"]
  }
''' if local else ""
        return self.scan('data "aws_iam_policy_document" "composed" {\n' + extra + "\n" +
                         statement + '}\nresource "aws_iam_policy" "app" {\n'
                         '  policy = data.aws_iam_policy_document.composed.json\n}\n' + related)

    def assert_composition_unknown(self, scan):
        self.assertEqual(scan.hits, [])
        self.assertIs(scan.policy_docs[(".", "composed")], iac_scan.UNKNOWN)
        self.assertTrue(any("composition not evaluated" in note and
                            "data.aws_iam_policy_document.composed at main.tf:1" in note
                            for note in scan.not_run), scan.not_run)

    def test_source_composition_is_not_reported_as_an_empty_policy(self):
        source = json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "*", "Resource": "*",
        }]})
        for attribute, value in (("source_policy_documents", f"[jsonencode({source})]"),
                                 ("source_json", f"jsonencode({source})")):
            with self.subTest(attribute=attribute):
                self.assert_composition_unknown(self.composed_policy(
                    f"  {attribute} = {value}", local=False))

    def test_source_document_references_also_require_review(self):
        base = '''data "aws_iam_policy_document" "base" {
  statement {
    actions = ["*"]
    resources = ["*"]
  }
}
'''
        scan = self.composed_policy(
            "  source_policy_documents = [data.aws_iam_policy_document.base.json]",
            local=False, related=base)
        self.assert_composition_unknown(scan)

    def test_override_deny_does_not_leave_a_stale_local_admin_grant(self):
        override = json.dumps({"Version": "2012-10-17", "Statement": [{
            "Sid": "Access", "Effect": "Deny", "Action": "*", "Resource": "*",
        }]})
        for attribute, value in (("override_policy_documents", f"[jsonencode({override})]"),
                                 ("override_json", f"jsonencode({override})"),
                                 ("override_policy_documents", "var.overrides")):
            with self.subTest(attribute=attribute, value=value):
                self.assert_composition_unknown(self.composed_policy(f"  {attribute} = {value}"))

    def test_explicit_empty_composition_inputs_keep_known_local_grants(self):
        for attribute, values in (("source_policy_documents", ("[]", "null")),
                                  ("override_policy_documents", ("[]", "null")),
                                  ("source_json", ('""', "null")),
                                  ("override_json", ('""', "null"))):
            for value in values:
                with self.subTest(attribute=attribute, value=value):
                    scan = self.composed_policy(f"  {attribute} = {value}")
                    self.assertEqual([h["rule"] for h in scan.hits], ["AWS-IAM-001"])
                    self.assertEqual(scan.not_run, [])

    def policy_with_condition(self, condition, bucket=False, extra_statement=""):
        type_ = "aws_s3_bucket_policy" if bucket else "aws_iam_role"
        attribute = "policy" if bucket else "assume_role_policy"
        action = "s3:GetObject" if bucket else "sts:AssumeRole"
        resources = 'Resource = "arn:aws:s3:::example/*"' if bucket else ""
        return self.scan(f'''resource "{type_}" "restricted" {{
  {attribute} = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect = "Allow"
      Action = "{action}"
      Principal = {{ AWS = "*" }}
      {resources}
      Condition = {condition}
    }}{extra_statement}]
  }})
}}
''')

    def test_unknown_condition_keys_never_become_unconditional_policies(self):
        conditions = (
            '{ StringEquals = { (var.condition_key) = "o-example" } }',
            '{ StringEquals = { "${var.condition_key}" = "o-example" } }',
            '{ (var.operator) = { "aws:PrincipalOrgID" = "o-example" } }',
        )
        for condition in conditions:
            for bucket in (False, True):
                with self.subTest(condition=condition, bucket=bucket):
                    scan = self.policy_with_condition(condition, bucket=bucket)
                    self.assertEqual(scan.hits, [])
                    self.assertEqual(len(scan.not_run), 1)
                    self.assertIn("unresolved key", scan.not_run[0])
                    self.assertIn("main.tf:2", scan.not_run[0])

    def test_unknown_key_cannot_override_a_known_object_entry_silently(self):
        value = iac_scan.literal('{ Effect = "Allow", (var.key) = "Deny" }')
        self.assertIs(value, iac_scan.UNKNOWN)

    def test_unknown_condition_does_not_hide_an_independent_unconditional_statement(self):
        statement = ', { Effect = "Allow", Action = "sts:AssumeRole", Principal = { AWS = "*" } }'
        scan = self.policy_with_condition(
            '{ StringEquals = { (var.condition_key) = "o-example" } }', extra_statement=statement)
        self.assertEqual([h["rule"] for h in scan.hits], ["AWS-IAM-003"])
        self.assertEqual(len(scan.not_run), 1)

    def test_literal_condition_remains_supported(self):
        scan = self.policy_with_condition('{ StringEquals = { "aws:PrincipalOrgID" = "o-example" } }')
        self.assertEqual(scan.hits, [])
        self.assertEqual(scan.not_run, [])


if __name__ == "__main__":
    unittest.main()
