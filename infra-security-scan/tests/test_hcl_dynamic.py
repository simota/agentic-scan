"""Unexpanded dynamic blocks preserve uncertainty without hiding static evidence."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "infra-scan" / "scripts"))
import iac_scan  # noqa: E402


class DynamicHclTest(unittest.TestCase):
    def scan(self, text):
        with tempfile.TemporaryDirectory(prefix="iac-dynamic-") as tmp:
            (Path(tmp) / "main.tf").write_text(text, encoding="utf-8")
            return iac_scan.run(tmp)

    def assert_dynamic_not_run(self, scan):
        self.assertTrue(any("dynamic block not evaluated" in note and "main.tf:" in note
                            for note in scan.not_run), scan.not_run)

    def trust(self, conditions, github=False):
        issuer = "token.actions.githubusercontent.com"
        principal = "arn:aws:iam::111122223333:oidc-provider/" + issuer if github else "*"
        kind = "Federated" if github else "AWS"
        action = "sts:AssumeRoleWithWebIdentity" if github else "sts:AssumeRole"
        return self.scan(f'''data "aws_iam_policy_document" "trust" {{
  statement {{
    actions = [{json.dumps(action)}]
    principals {{
      type = {json.dumps(kind)}
      identifiers = [{json.dumps(principal)}]
    }}
    {conditions}
  }}
}}
resource "aws_iam_role" "app" {{
  assume_role_policy = data.aws_iam_policy_document.trust.json
}}
''')

    def test_dynamic_metadata_options_are_not_missing(self):
        for expression in ("[1]", "var.options"):
            with self.subTest(for_each=expression):
                scan = self.scan('''variable "options" {
  type = list(number)
}
resource "aws_instance" "app" {
  ami = "ami-example"
  instance_type = "t3.micro"
  dynamic "metadata_options" {
    for_each = ''' + expression + '''
    content {
      http_tokens = "required"
    }
  }
}
''')
                self.assertEqual(scan.hits, [])
                self.assert_dynamic_not_run(scan)

    def test_dynamic_condition_does_not_become_unconditional_trust(self):
        scan = self.trust('''dynamic "condition" {
      for_each = [1]
      content {
        test = "StringEquals"
        variable = "aws:PrincipalOrgID"
        values = ["o-a1b2c3d4e5"]
      }
    }''')
        self.assertEqual(scan.hits, [])
        self.assert_dynamic_not_run(scan)

    def test_dynamic_subject_requires_review_instead_of_claiming_it_is_missing(self):
        scan = self.trust('''condition {
      test = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values = ["sts.amazonaws.com"]
    }
    dynamic "condition" {
      for_each = [1]
      content {
        test = "StringLike"
        variable = "token.actions.githubusercontent.com:sub"
        values = ["repo:trusted/app:*"]
      }
    }''', github=True)
        self.assertEqual(scan.hits, [])
        self.assert_dynamic_not_run(scan)
        self.assertTrue(any("AWS-IAM-004" in note and "unknown" in note
                            for note in scan.not_run))

    def test_static_subject_still_bounds_a_dynamic_condition(self):
        scan = self.trust('''dynamic "condition" {
      for_each = [1]
      content {
        test = "StringEquals"
        variable = "token.actions.githubusercontent.com:aud"
        values = ["sts.amazonaws.com"]
      }
    }
    condition {
      test = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values = ["repo:trusted/app:*"]
    }''', github=True)
        self.assertEqual(scan.hits, [])
        self.assert_dynamic_not_run(scan)
        self.assertFalse(any("AWS-IAM-004" in note for note in scan.not_run))

    def test_static_ingress_evidence_survives_a_dynamic_sibling(self):
        scan = self.scan('''resource "aws_security_group" "app" {
  dynamic "ingress" {
    for_each = [1]
    content {
      protocol = "tcp"
      from_port = 443
      to_port = 443
      cidr_blocks = ["10.0.0.0/8"]
    }
  }
  ingress {
    protocol = "tcp"
    from_port = 22
    to_port = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
''')
        self.assertEqual([(h["rule"], h["line"]) for h in scan.hits], [("AWS-NET-001", 11)])
        self.assert_dynamic_not_run(scan)

    def test_dynamic_ingress_is_visible_as_not_run_without_expanding_it(self):
        scan = self.scan('''resource "aws_security_group" "app" {
  dynamic "ingress" {
    for_each = [1]
    content {
      protocol = "tcp"
      from_port = 22
      to_port = 22
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}
''')
        self.assertEqual(scan.hits, [])
        self.assert_dynamic_not_run(scan)

    def test_dynamic_statement_does_not_invent_a_policy_grant(self):
        scan = self.scan('''data "aws_iam_policy_document" "trust" {
  dynamic "statement" {
    for_each = []
    content {
      actions = ["sts:AssumeRole"]
      principals {
        type = "AWS"
        identifiers = ["*"]
      }
    }
  }
}
resource "aws_iam_role" "app" {
  assume_role_policy = data.aws_iam_policy_document.trust.json
}
''')
        self.assertEqual(scan.hits, [])
        self.assert_dynamic_not_run(scan)

    def test_dynamic_oidc_does_not_prove_the_provider_is_oidc(self):
        scan = self.scan('''resource "google_iam_workload_identity_pool_provider" "app" {
  dynamic "oidc" {
    for_each = []
    content {
      issuer_uri = "https://issuer.example"
    }
  }
  saml {
    idp_metadata_xml = var.metadata
  }
}
''')
        self.assertEqual(scan.hits, [])
        self.assert_dynamic_not_run(scan)

    def test_dynamic_cluster_hardening_is_not_assumed_absent(self):
        scan = self.scan('''resource "google_container_cluster" "app" {
  dynamic "private_cluster_config" {
    for_each = [1]
    content {
      enable_private_endpoint = true
    }
  }
  dynamic "workload_identity_config" {
    for_each = [1]
    content {
      workload_pool = "example.svc.id.goog"
    }
  }
}
''')
        self.assertEqual(scan.hits, [])
        self.assert_dynamic_not_run(scan)
        self.assertEqual(len(scan.not_run), 2)


if __name__ == "__main__":
    unittest.main()
