"""CIDR spelling and trust-policy actions must preserve the actual grant."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "infra-scan" / "scripts"))
import iac_scan  # noqa: E402

EXPANDED_WORLD = "0:0:0:0:0:0:0:0/0"
ISSUER = "token.actions.githubusercontent.com"
PROVIDER = "arn:aws:iam::111122223333:oidc-provider/" + ISSUER


class ScanCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="iac-network-trust-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)

    def scan(self, text, name="main.tf"):
        # Several subtests use different input formats in the same directory.
        for old in self.repo.iterdir():
            old.unlink()
        (self.repo / name).write_text(text, encoding="utf-8")
        return iac_scan.run(self.repo)


class NetworkCidrTest(ScanCase):
    def ingress(self, cidr, format_):
        values = {"security_group_id": "sg-example", "cidr_ipv6": cidr,
                  "ip_protocol": "tcp", "from_port": 22, "to_port": 22}
        if format_ == "terraform":
            body = "\n".join(f"  {key} = {json.dumps(value)}" for key, value in values.items())
            return self.scan('resource "aws_vpc_security_group_ingress_rule" "ssh" {\n'
                             + body + "\n}\n")
        if format_ == "plan":
            doc = {"planned_values": {"root_module": {"resources": [{
                "address": "aws_vpc_security_group_ingress_rule.ssh", "mode": "managed",
                "type": "aws_vpc_security_group_ingress_rule", "values": values,
            }]}}}
        elif format_ == "cloudformation":
            doc = {"Resources": {"Ssh": {"Type": "AWS::EC2::SecurityGroupIngress",
                                         "Properties": {"GroupId": "sg-example",
                                                        "CidrIpv6": cidr, "IpProtocol": "tcp",
                                                        "FromPort": 22, "ToPort": 22}}}}
        else:
            doc = {"SecurityGroups": [{"GroupId": "sg-example", "IpPermissions": [{
                "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                "Ipv6Ranges": [{"CidrIpv6": cidr}],
            }]}]}
        return self.scan(json.dumps(doc), "input.json")

    def test_equivalent_ipv6_world_ranges_hit_in_every_ingress_format(self):
        for format_ in ("terraform", "plan", "cloudformation", "snapshot"):
            for cidr in ("::/0", EXPANDED_WORLD, "0000:0000:0000:0000:0000:0000:0000:0000/0"):
                with self.subTest(format=format_, cidr=cidr):
                    scan = self.ingress(cidr, format_)
                    self.assertEqual([hit["rule"] for hit in scan.hits], ["AWS-NET-001"])
                    self.assertEqual(scan.hits[0]["detail"], "ingress from ::/0 to 22/SSH")
                    self.assertEqual(scan.not_run, [])

    def test_restricted_invalid_and_unresolved_ranges_do_not_establish_world_access(self):
        for cidr in ("::/128", "2001:db8::/64", "0.0.0.0/32", "not-a-cidr", "::/129",
                     None, {"Ref": "SourceCidr"}):
            with self.subTest(cidr=cidr):
                scan = self.ingress(cidr, "cloudformation")
                self.assertEqual(scan.hits, [])

    def test_known_ipv6_range_survives_an_unknown_plan_sibling(self):
        resource = {"address": "aws_security_group.ssh", "mode": "managed",
                    "type": "aws_security_group", "values": {"ingress": [{
                        "protocol": "tcp", "from_port": 22, "to_port": 22,
                        "ipv6_cidr_blocks": [None, EXPANDED_WORLD],
                    }]}}
        doc = {"planned_values": {"root_module": {"resources": [resource]}},
               "resource_changes": [{"address": resource["address"], "change": {
                   "after_unknown": {"ingress": [{"ipv6_cidr_blocks": [True, False]}]},
               }}]}
        scan = self.scan(json.dumps(doc), "plan.json")
        self.assertEqual([hit["rule"] for hit in scan.hits], ["AWS-NET-001"])
        self.assertTrue(any("unknown" in note for note in scan.not_run))
        resource["values"]["ingress"][0]["ipv6_cidr_blocks"][1] = "2001:db8::/64"
        self.assertEqual(self.scan(json.dumps(doc), "plan.json").hits, [])

    def test_other_network_checks_use_the_same_ipv6_normalization(self):
        cases = (
            ("GCP-NET-001", '''resource "google_compute_firewall" "ssh" {
  name = "allow-ssh"
  network = "default"
  source_ranges = ["CIDR"]
  allow {
    protocol = "tcp"
    ports = ["22"]
  }
}
'''),
            ("AWS-EKS-001", '''resource "aws_eks_cluster" "app" {
  vpc_config {
    endpoint_public_access = true
    public_access_cidrs = ["CIDR"]
  }
}
'''),
            ("GCP-SQL-001", '''resource "google_sql_database_instance" "app" {
  settings {
    ip_configuration {
      ssl_mode = "ENCRYPTED_ONLY"
      authorized_networks {
        value = "CIDR"
      }
    }
  }
}
'''),
        )
        for rule, text in cases:
            for cidr in ("::/0", EXPANDED_WORLD):
                with self.subTest(rule=rule, cidr=cidr):
                    scan = self.scan(text.replace("CIDR", cidr))
                    self.assertEqual([hit["rule"] for hit in scan.hits], [rule])
                    self.assertIn("::/0", scan.hits[0]["detail"])
            for value in ('"2001:db8::/64"', "var.allowed_cidr"):
                with self.subTest(rule=rule, value=value):
                    self.assertEqual(self.scan(text.replace('"CIDR"', value)).hits, [])


class TrustActionTest(ScanCase):
    @staticmethod
    def statement(action="sts:AssumeRole", github=False, fixed_subject=False):
        st = {"Effect": "Allow", "Action": action,
              "Principal": {"Federated": PROVIDER} if github else {"AWS": "*"}}
        if github:
            st["Condition"] = {"StringLike": {
                ISSUER + ":sub": "repo:trusted/app:*" if fixed_subject else "repo:*",
            }}
        return st

    def policy(self, statements, format_="terraform", replacements=None):
        doc = {"Version": "2012-10-17", "Statement": statements}
        if format_ == "terraform":
            body = json.dumps(doc)
            for before, after in (replacements or {}).items():
                body = body.replace(json.dumps(before), after)
            return self.scan('resource "aws_iam_role" "app" {\n'
                             f'  assume_role_policy = jsonencode({body})\n' + '}\n')
        if format_ == "plan":
            data = {"planned_values": {"root_module": {"resources": [{
                "address": "aws_iam_role.app", "mode": "managed", "type": "aws_iam_role",
                "values": {"assume_role_policy": json.dumps(doc)},
            }]}}}
        else:
            data = {"Resources": {"Role": {"Type": "AWS::IAM::Role", "Properties": {
                "AssumeRolePolicyDocument": doc,
            }}}}
        return self.scan(json.dumps(data), "role.json")

    def test_separate_tag_permission_does_not_grant_role_assumption(self):
        assume = self.statement()
        assume["Principal"] = {"AWS": "arn:aws:iam::111122223333:root"}
        for format_ in ("terraform", "plan", "cloudformation"):
            with self.subTest(format=format_):
                scan = self.policy([assume, self.statement("sts:TagSession")], format_)
                self.assertEqual(scan.hits, [])
                self.assertEqual(scan.not_run, [])

    def test_assume_role_actions_keep_case_and_iam_wildcard_support(self):
        for action in ("sts:AssumeRole", "STS:ASSUMEROLE", "*", "*:*", "sts:*",
                       "sts:AssumeR?le", "sts:AssumeRole*", ["sts:TagSession", "sts:AssumeRole"]):
            with self.subTest(action=action):
                scan = self.policy([self.statement(action)])
                self.assertEqual([hit["rule"] for hit in scan.hits], ["AWS-IAM-003"])
                self.assertEqual(scan.not_run, [])

    def test_non_assumption_and_absent_actions_do_not_grant_assume_role(self):
        for action in ("sts:TagSession", "sts:SetSourceIdentity", "sts:AssumeRoleWithSAML",
                       "sts:AssumeRoleWithWebIdentity", "sts:AssumeRol[e]",
                       "sts:" + "*?" * 20 + "x", [], None):
            with self.subTest(action=action):
                self.assertEqual(self.policy([self.statement(action)]).hits, [])
        statement = self.statement()
        del statement["Action"]
        self.assertEqual(self.policy([statement]).hits, [])

    def test_unknown_actions_require_review_without_inventing_assume_role(self):
        for action in ("unknown-action", ["sts:TagSession", "unknown-action"]):
            with self.subTest(action=action):
                scan = self.policy([self.statement(action)],
                                   replacements={"unknown-action": "var.actions"})
                self.assertEqual(scan.hits, [])
                self.assertTrue(any("AWS-IAM-003" in note and "action" in note.lower()
                                    for note in scan.not_run))
        scan = self.policy([self.statement({"Ref": "TrustAction"})], "cloudformation")
        self.assertEqual(scan.hits, [])
        self.assertTrue(any("AWS-IAM-003" in note for note in scan.not_run))

    def test_unknown_action_does_not_hide_an_independent_known_permission(self):
        scan = self.policy([self.statement(["unknown-action", "sts:AssumeRole"])],
                           replacements={"unknown-action": "var.actions"})
        self.assertEqual([hit["rule"] for hit in scan.hits], ["AWS-IAM-003"])

    def test_not_action_is_left_for_review(self):
        for action in (None, "sts:AssumeRole"):
            with self.subTest(action=action):
                statement = self.statement(action)
                if action is None:
                    del statement["Action"]
                statement["NotAction"] = "sts:TagSession"
                scan = self.policy([statement])
                self.assertEqual(scan.hits, [])
                self.assertTrue(any("AWS-IAM-003" in note for note in scan.not_run))

    def test_data_policy_document_uses_the_same_action_check(self):
        for action, expected in (("sts:TagSession", []), ("sts:AssumeRole", ["AWS-IAM-003"])):
            with self.subTest(action=action):
                scan = self.scan('''data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["ACTION"]
    principals {
      type = "AWS"
      identifiers = ["*"]
    }
  }
}
resource "aws_iam_role" "app" {
  assume_role_policy = data.aws_iam_policy_document.trust.json
}
'''.replace("ACTION", action))
                self.assertEqual([hit["rule"] for hit in scan.hits], expected)

    def test_github_tag_permission_does_not_bypass_a_fixed_assumption_subject(self):
        assume = self.statement("sts:AssumeRoleWithWebIdentity", github=True, fixed_subject=True)
        tags = self.statement("sts:TagSession", github=True)
        del tags["Condition"]
        scan = self.policy([assume, tags])
        self.assertEqual(scan.hits, [])
        self.assertEqual(scan.not_run, [])

    def test_github_requires_the_web_identity_action_with_case_and_wildcards(self):
        for action in ("sts:AssumeRoleWithWebIdentity", "STS:ASSUMEROLEWITHWEBIDENTITY",
                       "*", "sts:*", "sts:AssumeRole*", "sts:AssumeRoleWithWebIdentit?"):
            with self.subTest(action=action):
                scan = self.policy([self.statement(action, github=True)])
                self.assertEqual([hit["rule"] for hit in scan.hits], ["AWS-IAM-004"])
        for action in ("sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:TagSession"):
            with self.subTest(action=action):
                self.assertEqual(self.policy([self.statement(action, github=True)]).hits, [])

    def test_github_unknown_action_or_not_action_does_not_prove_an_unbounded_grant(self):
        scan = self.policy([self.statement("unknown-action", github=True)],
                           replacements={"unknown-action": "var.actions"})
        self.assertEqual(scan.hits, [])
        self.assertTrue(any("AWS-IAM-004" in note for note in scan.not_run))
        statement = self.statement(github=True)
        del statement["Action"]
        statement["NotAction"] = "sts:TagSession"
        scan = self.policy([statement])
        self.assertEqual(scan.hits, [])
        self.assertTrue(any("AWS-IAM-004" in note for note in scan.not_run))
        scan = self.policy([self.statement("unknown-action", github=True, fixed_subject=True)],
                           replacements={"unknown-action": "var.actions"})
        self.assertEqual(scan.hits, [])
        self.assertEqual(scan.not_run, [])


if __name__ == "__main__":
    unittest.main()
