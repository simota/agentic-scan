"""iac_scan on inputs real repositories hold beside plain Terraform: SAM, Terragrunt,
Kustomize, Helm, Serverless, Pulumi, large plans, unknown exports and deep nesting."""
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-scan" / "scripts"))
import iac_scan  # noqa: E402

OPEN_SG = ('resource "aws_security_group_rule" "r" {\n  type = "ingress"\n  from_port = 22\n'
           '  to_port = 22\n  protocol = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}\n')


class InputKindTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
        return path

    def scan(self, *snapshots):
        return iac_scan.run(self.root, snapshots)

    def hits(self, scan):
        return sorted({(h["rule"], h["file"]) for h in scan.hits})

    def notes(self, scan, rel):
        return [n for n in scan.not_run if rel in n]

    def test_deep_hcl_is_a_note_not_a_crash(self):
        self.write("a/deep.tf", 'resource "aws_instance" "x" {\n' + "a {\n" * 3000 + "}\n" * 3001)
        self.write("b/interp.tf", 'resource "aws_instance" "y" {\n  description = "'
                   + '${"' * 3000 + '"\n}\n')
        self.write("c/literal.tf", 'resource "aws_iam_policy" "p" {\n  policy = jsonencode('
                   + '{"a":' * 600 + "1" + "}" * 600 + ")\n}\n")
        self.write("d/main.tf", OPEN_SG)
        scan = self.scan()
        self.assertTrue(self.notes(scan, "a/deep.tf"), scan.not_run)
        self.assertTrue(self.notes(scan, "b/interp.tf"), scan.not_run)
        self.assertTrue(self.notes(scan, "c/literal.tf"), scan.not_run)
        # The rest of the repository is still assessed.
        self.assertIn(("AWS-NET-001", "d/main.tf"), self.hits(scan))

    def test_large_plan_is_read_in_linear_time(self):
        resources = [{"address": f"aws_s3_bucket.b{n}", "mode": "managed", "type": "aws_s3_bucket",
                      "name": f"b{n}", "values": {"bucket": f"b{n}"}} for n in range(12000)]
        resources.append({"address": "aws_db_instance.db", "mode": "managed", "type": "aws_db_instance",
                          "name": "db", "values": {"publicly_accessible": True, "storage_encrypted": True}})
        plan = {"format_version": "1.2", "planned_values": {"root_module": {"resources": resources}},
                "resource_changes": [{"address": r["address"], "change": {"after_unknown": {}}}
                                     for r in resources]}
        text = json.dumps(plan, indent=2)
        self.assertGreater(len(text), iac_scan.MAX_BYTES)
        self.write("plan.json", text)
        start = time.monotonic()
        scan = self.scan()
        self.assertLess(time.monotonic() - start, 30)
        self.assertIn(("AWS-RDS-001", "plan.json"), self.hits(scan))

    def test_unknown_snapshot_export_is_named(self):
        snaps = Path(self.tmp.name + "-snaps")
        snaps.mkdir()
        try:
            (snaps / "aws-rds.json").write_text(json.dumps({"DBInstances": [{"PubliclyAccessible": True}]}))
            self.write("main.tf", OPEN_SG)
            scan = self.scan(str(snaps))
            self.assertTrue([n for n in scan.not_run if "aws-rds.json" in n and "review by hand" in n],
                            scan.not_run)
        finally:
            (snaps / "aws-rds.json").unlink()
            snaps.rmdir()

    def test_export_in_repository_is_named(self):
        self.write("exports/roles.json", json.dumps({"RoleDetailList": [{"RoleName": "r"}]}))
        self.assertTrue(self.notes(self.scan(), "exports/roles.json"))

    def test_sam_function_rules(self):
        template = {"Transform": "AWS::Serverless-2016-10-31", "Resources": {
            "Fn": {"Type": "AWS::Serverless::Function", "Properties": {
                "FunctionUrlConfig": {"AuthType": "NONE"},
                "Policies": ["AdministratorAccess",
                             {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}]}},
            "Scoped": {"Type": "AWS::Serverless::Function", "Properties": {
                "Role": "arn:aws:iam::111122223333:role/r", "Policies": ["AdministratorAccess"]}}}}
        self.write("sam/template.json", json.dumps(template, indent=1))
        scan = self.scan()
        hits = {(h["rule"], h["address"]) for h in scan.hits}
        self.assertIn(("AWS-LAMBDA-001", "cfn:Fn"), hits)
        self.assertIn(("AWS-IAM-001", "cfn:Fn"), hits)
        # SAM ignores Policies when Role is given.
        self.assertNotIn(("AWS-IAM-001", "cfn:Scoped"), hits)
        self.assertTrue([n for n in self.notes(scan, "sam/template.json") if "Transform" in n])

    def test_sam_yaml_template(self):
        self.write("template.yaml", "Transform: AWS::Serverless-2016-10-31\nResources:\n  Fn:\n"
                   "    Type: AWS::Serverless::Function\n    Properties:\n      FunctionUrlConfig:\n"
                   "        AuthType: NONE\n")
        self.assertIn(("AWS-LAMBDA-001", "template.yaml"), self.hits(self.scan()))

    def test_terragrunt_secrets_and_unpinned_source(self):
        password = "Zq" + "x9" * 5 + "Wp"
        self.write("live/terragrunt.hcl", 'terraform {\n  source = "git::https://example.com/m.git//vpc"\n}\n'
                   f'inputs = {{\n  db_password = "{password}"\n}}\n')
        scan = self.scan()
        self.assertIn(("PS-001", "live/terragrunt.hcl"), self.hits(scan))
        self.assertIn(("SEC-001", "live/terragrunt.hcl"), self.hits(scan))
        self.assertTrue(self.notes(scan, "live/terragrunt.hcl"))

    def test_tfvars_json_secret(self):
        self.write("prod.auto.tfvars.json", json.dumps({"db_password": "Zq" + "x9" * 5 + "Wp"}, indent=1))
        scan = self.scan()
        self.assertIn(("SEC-001", "prod.auto.tfvars.json"), self.hits(scan))
        self.assertIn({"path": "prod.auto.tfvars.json", "kind": "tfvars"}, scan.files)

    def test_cloudformation_dot_template(self):
        template = {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"Sg": {
            "Type": "AWS::EC2::SecurityGroup", "Properties": {"SecurityGroupIngress": [
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"}]}}}}
        self.write("stack.template", json.dumps(template, indent=1))
        self.assertIn(("AWS-NET-001", "stack.template"), self.hits(self.scan()))

    def test_unevaluated_kinds_are_named(self):
        for name in ("serverless.yml", "Pulumi.yaml", "Pulumi.prod.yaml", "image.pkr.hcl",
                     "mod/main_override.tf.json"):
            self.write(name, "x: 1\n" if not name.endswith(".json") else "{}")
        scan = self.scan()
        for name in ("serverless.yml", "Pulumi.yaml", "Pulumi.prod.yaml", "image.pkr.hcl"):
            self.assertTrue(self.notes(scan, name), name)
        self.assertTrue([n for n in self.notes(scan, "main_override.tf.json") if "final configuration" in n])

    def test_lock_and_test_files_are_quiet(self):
        self.write(".terraform.lock.hcl", 'provider "x" {}\n')
        self.write("tests/a.tftest.hcl", 'run "x" {}\n')
        self.assertEqual(self.scan().not_run, [])

    def test_tool_caches_are_skipped(self):
        for cache in (".terragrunt-cache/abc/def", ".aws-sam/build", ".serverless"):
            self.write(f"{cache}/main.tf", OPEN_SG)
        self.write("main.tf", OPEN_SG)
        self.assertEqual(self.hits(self.scan()), [("AWS-NET-001", "main.tf")])

    def test_kustomization_is_not_a_cluster_object(self):
        self.write("overlay/kustomization.yaml", "apiVersion: kustomize.config.k8s.io/v1beta1\n"
                   "kind: Kustomization\nresources:\n  - ../base\n")
        self.write("legacy/kustomization.yaml", "resources:\n  - ../base\n")
        scan = self.scan()
        self.assertFalse([r for r in scan.resources if "Kustomization" in r["address"]], scan.resources)
        self.assertTrue(self.notes(scan, "overlay/kustomization.yaml"))
        self.assertTrue(self.notes(scan, "legacy/kustomization.yaml"))

    def test_flux_kustomization_is_still_a_cluster_object(self):
        self.write("flux.yaml", "apiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\n"
                   "metadata:\n  name: apps\n")
        self.assertTrue([r for r in self.scan().resources if "Kustomization" in r["address"]])

    def test_helm_template_note_says_so(self):
        self.write("chart/Chart.yaml", "name: c\nversion: 1.0.0\n")
        self.write("chart/templates/rb.yaml", "apiVersion: rbac.authorization.k8s.io/v1\n"
                   "kind: ClusterRoleBinding\nmetadata:\n  name: {{ .Release.Name }}\n")
        notes = self.notes(self.scan(), "chart/templates/rb.yaml")
        self.assertTrue(notes and "helm template" in notes[0], notes)

    def test_irrelevant_binaries_are_counted_not_listed(self):
        self.write("assets/big.zip", b"PK" + b"\1" * (iac_scan.MAX_BYTES + 1))
        self.write("docs/notes.txt", "caf\xe9".encode("latin-1"))
        self.write("bad.tf", b"x = \"\xff\"\n")
        scan = self.scan()
        self.assertIn("binary or not UTF-8, skipped: bad.tf", scan.not_run)
        self.assertNotIn("file too large to scan: assets/big.zip", scan.not_run)
        self.assertNotIn("not UTF-8, skipped: docs/notes.txt", scan.not_run)
        self.assertTrue([n for n in scan.not_run if n.startswith("1 other file(s) too large")], scan.not_run)
        self.assertTrue([n for n in scan.not_run if n.startswith("1 other file(s) not UTF-8")], scan.not_run)


if __name__ == "__main__":
    unittest.main()
