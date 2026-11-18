"""Regressions for GitHub subject bounds and unknown Terraform plan values."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "infra-security-scan" / "scripts"))
import iac_scan  # noqa: E402

ISSUER = "token.actions.githubusercontent.com"
AUD, SUB = ISSUER + ":aud", ISSUER + ":sub"
PROVIDER = "arn:aws:iam::111122223333:oidc-provider/" + ISSUER


class ScanCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="iac-plan-oidc-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)

    def write(self, name, text):
        (self.repo / name).write_text(text, encoding="utf-8")


class GitHubSubjectTest(ScanCase):
    def scan_policy(self, conditions, provider=PROVIDER, replacements=None, cfn=False):
        policy = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
            "Principal": {"Federated": provider}, "Condition": conditions,
        }]}
        if cfn:
            self.write("role.json", json.dumps({"Resources": {"CiRole": {
                "Type": "AWS::IAM::Role", "Properties": {"AssumeRolePolicyDocument": policy},
            }}}))
        else:
            literal = json.dumps(policy)
            for before, after in (replacements or {}).items():
                literal = literal.replace(json.dumps(before), after)
            self.write("main.tf", 'resource "aws_iam_role" "ci" {\n'
                       f'  assume_role_policy = jsonencode({literal})\n' + '}\n')
        return iac_scan.run(self.repo)

    def condition(self, op, values):
        conditions = {"StringEquals": {AUD: "sts.amazonaws.com"}}
        conditions.setdefault(op, {})[SUB] = values
        return conditions

    def test_globs_in_organization_or_repository_are_reported(self):
        for pattern in ("repo:trusted*/*", "repo:trusted?/app:*", "repo:trusted/app*:*",
                        "repo:trusted/*", "repo:*", "*:*", "*"):
            with self.subTest(pattern=pattern):
                scan = self.scan_policy(self.condition("StringLike", pattern))
                self.assertEqual([hit["rule"] for hit in scan.hits], ["AWS-IAM-004"])
                self.assertEqual(scan.not_run, [])

    def test_branch_and_environment_globs_keep_a_fixed_repository(self):
        for pattern in ("repo:trusted/app:ref:refs/heads/*", "repo:trusted/app:environment:*",
                        "repo:trusted/app:*"):
            with self.subTest(pattern=pattern):
                scan = self.scan_policy(self.condition("StringLike", pattern))
                self.assertEqual(scan.hits, [])
                self.assertEqual(scan.not_run, [])

    def test_string_equals_does_not_expand_wildcards(self):
        for op in ("StringEquals", "StringEqualsIgnoreCase"):
            with self.subTest(operator=op):
                scan = self.scan_policy(self.condition(op, "repo:trusted*/*"))
                self.assertEqual(scan.hits, [])
                self.assertEqual(scan.not_run, [])

    def test_or_values_include_the_broad_alternative(self):
        scan = self.scan_policy(self.condition("StringLike", [
            "repo:trusted/app:*", "repo:trusted*/*",
        ]))
        self.assertEqual([hit["rule"] for hit in scan.hits], ["AWS-IAM-004"])

    def test_fixed_subject_conjunct_bounds_a_broad_condition(self):
        conditions = self.condition("StringLike", "repo:trusted*/*")
        conditions["StringEquals"][SUB] = "repo:trusted/app:ref:refs/heads/main"
        scan = self.scan_policy(conditions)
        self.assertEqual(scan.hits, [])
        self.assertEqual(scan.not_run, [])

    def test_fixed_subject_conjunct_also_bounds_an_unknown_condition(self):
        conditions = self.condition("StringLike", "unknown-subject")
        conditions["StringEquals"][SUB] = "repo:trusted/app:ref:refs/heads/main"
        scan = self.scan_policy(conditions, replacements={"unknown-subject": "var.subject"})
        self.assertEqual(scan.hits, [])
        self.assertEqual(scan.not_run, [])

    def test_negated_or_qualified_operators_are_left_for_review(self):
        for op in ("StringNotLike", "StringNotEquals", "ForAllValues:StringLike", "Null"):
            with self.subTest(operator=op):
                scan = self.scan_policy(self.condition(op, "repo:trusted/app:*"))
                self.assertEqual(scan.hits, [])
                self.assertTrue(any("AWS-IAM-004" in note and "unsupported" in note
                                    for note in scan.not_run))

    def test_intersecting_broad_conditions_are_left_for_review(self):
        conditions = self.condition("StringLike", "repo:trusted/*")
        conditions["ForAnyValue:StringLike"] = {SUB: "repo:*/app:*"}
        scan = self.scan_policy(conditions)
        self.assertEqual(scan.hits, [])
        self.assertTrue(any("AWS-IAM-004" in note for note in scan.not_run))

    def test_unknown_subject_or_condition_is_visible_as_not_run(self):
        for conditions, replacements in (
                (self.condition("StringLike", "unknown-subject"), {"unknown-subject": "var.subject"}),
                ("unknown-condition", {"unknown-condition": "var.condition"})):
            with self.subTest(conditions=conditions):
                scan = self.scan_policy(conditions, replacements=replacements)
                self.assertEqual(scan.hits, [])
                self.assertTrue(any("AWS-IAM-004" in note and "unknown" in note
                                    for note in scan.not_run))

    def test_another_issuer_subject_cannot_be_the_fixed_github_condition(self):
        conditions = self.condition("StringLike", "repo:trusted*/*")
        conditions["StringEqualsIfExists"] = {"other.example:sub": "fixed"}
        scan = self.scan_policy(conditions)
        self.assertEqual(scan.hits, [])
        self.assertTrue(any("AWS-IAM-004" in note for note in scan.not_run))

    def test_issuer_substrings_do_not_identify_github(self):
        scan = self.scan_policy(self.condition("StringLike", "repo:*"),
                                provider=PROVIDER + ".other.example")
        self.assertEqual(scan.hits, [])
        self.assertEqual(scan.not_run, [])

    def test_cloudformation_uses_the_same_subject_bounds(self):
        scan = self.scan_policy(self.condition("StringLike", "repo:trusted*/*"), cfn=True)
        self.assertEqual([hit["rule"] for hit in scan.hits], ["AWS-IAM-004"])


class PlanUnknownTest(ScanCase):
    def resource(self, type_, name, values, address=None):
        return {"address": address or f"{type_}.{name}", "mode": "managed",
                "type": type_, "name": name, "values": values}

    def scan_plan(self, resources, masks=None, children=None, extra_changes=None):
        changes = [{"address": address, "change": {"actions": ["create"], "after_unknown": mask}}
                   for address, mask in (masks or {}).items()]
        changes.extend(extra_changes or [])
        plan = {"format_version": "1.2", "planned_values": {"root_module": {
            "resources": resources, "child_modules": children or [],
        }}, "resource_changes": changes}
        self.write("plan.json", json.dumps(plan, indent=2))
        return iac_scan.run(self.repo)

    def test_unknown_public_access_flags_are_not_disabled_flags(self):
        res = self.resource("aws_s3_bucket_public_access_block", "pending", {"bucket": "example"})
        flags = {key: True for key in ("block_public_acls", "block_public_policy",
                                       "ignore_public_acls", "restrict_public_buckets")}
        scan = self.scan_plan([res], {res["address"]: flags})
        self.assertEqual(scan.hits, [])
        self.assertTrue(any(res["address"] in note and "unknown" in note for note in scan.not_run))

    def test_explicit_false_and_missing_values_keep_existing_findings(self):
        resources = [self.resource("aws_ebs_volume", "off", {"encrypted": False}),
                     self.resource("aws_ebs_volume", "unset", {}),
                     self.resource("aws_ebs_volume", "on", {"encrypted": True})]
        scan = self.scan_plan(resources, {resources[0]["address"]: {"encrypted": False}})
        self.assertEqual({hit["address"] for hit in scan.hits},
                         {"aws_ebs_volume.off", "aws_ebs_volume.unset"})
        self.assertEqual(scan.not_run, [])

    def test_unknowns_match_full_resource_addresses_in_child_modules(self):
        root = self.resource("aws_ebs_volume", "disk", {"encrypted": False}, "aws_ebs_volume.disk[0]")
        child = self.resource("aws_ebs_volume", "disk", {}, "module.app.aws_ebs_volume.disk[1]")
        scan = self.scan_plan([root], {child["address"]: {"encrypted": True}},
                              [{"address": "module.app", "resources": [child]}])
        self.assertEqual([hit["address"] for hit in scan.hits], [root["address"]])
        self.assertEqual(len(scan.resources), 2)
        self.assertTrue(any(child["address"] in note for note in scan.not_run))

    def test_deposed_object_cannot_replace_the_current_unknown_mask(self):
        res = self.resource("aws_ebs_volume", "replaced", {})
        deposed = {"address": res["address"], "deposed": "old-object", "change": {
            "actions": ["delete"], "after": None, "after_unknown": {},
        }}
        scan = self.scan_plan([res], {res["address"]: {"encrypted": True}}, extra_changes=[deposed])
        self.assertEqual(scan.hits, [])
        self.assertTrue(any("unknown" in note for note in scan.not_run))

    def test_nested_block_attribute_unknown_does_not_become_unset(self):
        res = self.resource("aws_instance", "pending", {"metadata_options": [{"http_tokens": None}]})
        scan = self.scan_plan([res], {res["address"]: {"metadata_options": [{"http_tokens": True}]}})
        self.assertEqual(scan.hits, [])
        self.assertTrue(any("unknown" in note for note in scan.not_run))

    def test_unknown_blocks_and_list_elements_preserve_their_uncertainty(self):
        for values, mask in (({}, {"metadata_options": True}),
                             ({"metadata_options": None}, {"metadata_options": True}),
                             ({"metadata_options": [None]}, {"metadata_options": [True]})):
            with self.subTest(values=values):
                res = self.resource("aws_instance", "pending", values)
                scan = self.scan_plan([res], {res["address"]: mask})
                self.assertEqual(scan.hits, [])
                self.assertTrue(any("unknown" in note for note in scan.not_run))

    def test_nested_list_unknown_keeps_known_ingress_evidence(self):
        ingress = {"protocol": "tcp", "from_port": 22, "to_port": 22,
                   "cidr_blocks": [None, "0.0.0.0/0"]}
        res = self.resource("aws_security_group", "mixed", {"ingress": [ingress]})
        mask = {"ingress": [{"cidr_blocks": [True, False]}]}
        scan = self.scan_plan([res], {res["address"]: mask})
        self.assertEqual([hit["rule"] for hit in scan.hits], ["AWS-NET-001"])
        self.assertTrue(any("unknown" in note for note in scan.not_run))
        # The unknown list element alone is not a public CIDR.
        ingress["cidr_blocks"] = [None, "10.0.0.0/8"]
        scan = self.scan_plan([res], {res["address"]: mask})
        self.assertEqual(scan.hits, [])

    def test_entire_resource_unknown_does_not_apply_defaults(self):
        res = self.resource("aws_ebs_volume", "pending", None)
        scan = self.scan_plan([res], {res["address"]: True})
        self.assertEqual(scan.hits, [])
        self.assertEqual(len(scan.resources), 1)
        self.assertTrue(any("unknown" in note for note in scan.not_run))

    def test_partial_known_nested_options_still_allow_their_own_findings(self):
        res = self.resource("aws_eks_cluster", "pending", {"vpc_config": [{
            "endpoint_public_access": True, "public_access_cidrs": ["0.0.0.0/0"],
        }]})
        scan = self.scan_plan([res], {res["address"]: {"vpc_config": [{"subnet_ids": True}]}})
        self.assertEqual([hit["rule"] for hit in scan.hits], ["AWS-EKS-001"])
        mask = {"vpc_config": [{"public_access_cidrs": True}]}
        scan = self.scan_plan([res], {res["address"]: mask})
        self.assertEqual(scan.hits, [])

    def test_firewall_unknown_enablement_or_allow_cannot_establish_ingress(self):
        values = {"direction": "INGRESS", "source_ranges": ["0.0.0.0/0"],
                  "allow": [{"protocol": "tcp", "ports": ["22"]}]}
        res = self.resource("google_compute_firewall", "pending", values)
        for mask in ({"disabled": True}, {"allow": True}, {"allow": [True]},
                     {"allow": [{"protocol": True}]}, {"allow": [{"ports": True}]}):
            with self.subTest(mask=mask):
                scan = self.scan_plan([res], {res["address"]: mask})
                self.assertEqual(scan.hits, [])
                self.assertTrue(any("unknown" in note for note in scan.not_run))
        # Unknown unrelated attributes must not hide a definitely enabled rule.
        values["disabled"] = False
        scan = self.scan_plan([res], {res["address"]: {"name": True}})
        self.assertEqual([hit["rule"] for hit in scan.hits], ["GCP-NET-001"])

    def test_gke_unknown_private_endpoint_does_not_prove_public_access(self):
        values = {"private_cluster_config": [{}],
                  "workload_identity_config": [{"workload_pool": "example.svc.id.goog"}]}
        res = self.resource("google_container_cluster", "pending", values)
        for mask in ({"private_cluster_config": [{"enable_private_endpoint": True}]},
                     {"private_cluster_config": True}, {"private_cluster_config": [True]},
                     {"master_authorized_networks_config": True}):
            with self.subTest(mask=mask):
                scan = self.scan_plan([res], {res["address"]: mask})
                self.assertEqual(scan.hits, [])
                self.assertTrue(any("unknown" in note for note in scan.not_run))
        # A known absent private endpoint keeps the pre-existing finding.
        values["private_cluster_config"] = [{"enable_private_endpoint": False}]
        scan = self.scan_plan([res])
        self.assertEqual([hit["detail"] for hit in scan.hits],
                         ["no master authorized networks and no private endpoint"])

    def test_gke_unknown_blocks_preserve_independent_known_hardening_gaps(self):
        values = {"enable_legacy_abac": True}
        res = self.resource("google_container_cluster", "pending", values)
        mask = {"private_cluster_config": True, "master_authorized_networks_config": True,
                "workload_identity_config": True}
        scan = self.scan_plan([res], {res["address"]: mask})
        self.assertEqual([(hit["severity"], hit["detail"]) for hit in scan.hits],
                         [("High", "enable_legacy_abac = true")])
        # The identity block's known absence remains a separate Low finding.
        del mask["workload_identity_config"]
        scan = self.scan_plan([res], {res["address"]: mask})
        self.assertEqual({hit["detail"] for hit in scan.hits},
                         {"enable_legacy_abac = true", "no workload_identity_config"})

    def test_unknown_oidc_block_does_not_establish_provider_type(self):
        res = self.resource("google_iam_workload_identity_pool_provider", "pending",
                            {"attribute_condition": None})
        for mask in ({"oidc": True}, {"oidc": [True]}):
            with self.subTest(mask=mask):
                scan = self.scan_plan([res], {res["address"]: mask})
                self.assertEqual(scan.hits, [])
                self.assertTrue(any("unknown" in note for note in scan.not_run))

    def test_known_oidc_block_keeps_condition_gap_when_only_issuer_is_unknown(self):
        values = {"attribute_condition": None, "oidc": [{}]}
        res = self.resource("google_iam_workload_identity_pool_provider", "pending", values)
        scan = self.scan_plan([res], {res["address"]: {"oidc": [{"issuer_uri": True}]}})
        self.assertEqual([hit["rule"] for hit in scan.hits], ["GCP-WIF-001"])
        scan = self.scan_plan([res], {res["address"]: {"attribute_condition": True}})
        self.assertEqual(scan.hits, [])


if __name__ == "__main__":
    unittest.main()
