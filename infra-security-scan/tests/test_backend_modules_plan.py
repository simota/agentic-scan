"""Backends, module calls, provider credentials and plan JSON shapes."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "infra-security-scan" / "scripts"))
import iac_scan  # noqa: E402


def scan(files):
    with tempfile.TemporaryDirectory(prefix="iac-backend-") as tmp:
        for name, text in files.items():
            path = Path(tmp) / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text if isinstance(text, str) else json.dumps(text, indent=2), encoding="utf-8")
        return iac_scan.run(tmp)


def hits(files):
    return sorted((h["rule"], h["file"], h["line"]) for h in scan(files).hits)


class BackendTest(unittest.TestCase):
    def test_partial_s3_backend_is_noted_not_flagged(self):
        result = scan({"envs/prod/main.tf": 'terraform {\n  backend "s3" {}\n}\n'})
        self.assertEqual(result.hits, [])
        self.assertTrue(any("-backend-config" in n for n in result.not_run))

    def test_backend_config_file_can_supply_encrypt(self):
        files = {"envs/prod/main.tf": 'terraform {\n  backend "s3" {\n    key = "k"\n  }\n}\n',
                 "envs/prod/backend.hcl": 'bucket = "b"\nencrypt = true\n'}
        self.assertEqual(hits(files), [])

    def test_encrypt_false_is_flagged_even_with_a_kms_key(self):
        text = 'terraform {\n  backend "s3" {\n    encrypt = false\n    kms_key_id = "k"\n  }\n}\n'
        self.assertEqual([h[0] for h in hits({"main.tf": text})], ["PS-002"])

    def test_module_only_prod_root_and_called_child_directories(self):
        files = {"envs/prod-eu/main.tf": 'module "app" {\n  source = "../../modules/app"\n}\n',
                 "live/production/root/main.tf": 'terraform {\n  cloud {}\n}\n'
                                                 'module "vpc" {\n  source = "../modules/vpc"\n}\n',
                 "live/production/modules/vpc/main.tf": 'resource "aws_vpc" "v" {}\n'}
        self.assertEqual(hits(files), [("PS-002", "envs/prod-eu/main.tf", 1)])


class ModuleAndProviderTest(unittest.TestCase):
    def test_refs_that_are_not_commits_or_tags(self):
        for ref, flagged in (("feature/foo", True), ("refs/heads/main", True), ("main", True),
                             ("v1.2.3", False), ("1.4.0-rc1", False), ("a" * 40, False)):
            with self.subTest(ref=ref):
                text = f'module "m" {{\n  source = "git::https://example.com/m.git?ref={ref}"\n}}\n'
                self.assertEqual(bool(hits({"main.tf": text})), flagged)

    def test_static_credentials_for_other_providers(self):
        self.assertEqual([h[0] for h in hits({"main.tf": 'provider "google" {\n'
                                                          '  credentials = file("sa-key.json")\n}\n'})], ["PS-003"])
        self.assertEqual(hits({"main.tf": 'provider "kubernetes" {\n'
                                          '  token = data.aws_eks_cluster_auth.c.token\n}\n'}), [])

    def test_indexed_policy_documents_are_resolved(self):
        text = ('data "aws_iam_policy_document" "admin" {\n  for_each = toset(["a"])\n  statement {\n'
                '    actions = ["*"]\n    resources = ["*"]\n  }\n}\n'
                'resource "aws_iam_policy" "p" {\n  policy = data.aws_iam_policy_document.admin["a"].json\n}\n')
        self.assertIn("AWS-IAM-001", [h[0] for h in hits({"main.tf": text})])

    def test_unresolved_policy_is_noted(self):
        result = scan({"main.tf": 'resource "aws_iam_policy" "p" {\n  policy = module.x.json\n}\n'})
        self.assertTrue(any("policy document not resolved" in n for n in result.not_run))

    def test_unicode_identifiers_parse_as_blocks(self):
        text = 'resource "aws_ebs_volume" "v" {\n  ñ = {\n    encrypted = true\n  }\n  encrypted = false\n}\n'
        self.assertEqual(hits({"main.tf": text}), [("AWS-EBS-001", "main.tf", 5)])


class PlanTest(unittest.TestCase):
    def plan(self, resources):
        return {"format_version": "1.2", "planned_values": {"root_module": {"resources": resources}}}

    def test_empty_strings_are_unset(self):
        r = [{"address": "aws_kms_key.k", "mode": "managed", "type": "aws_kms_key",
              "values": {"custom_key_store_id": "", "enable_key_rotation": False}},
             {"address": "aws_db_instance.d", "mode": "managed", "type": "aws_db_instance",
              "values": {"replicate_source_db": "", "storage_encrypted": False}}]
        self.assertEqual({h[0] for h in hits({"plan.json": self.plan(r)})}, {"AWS-KMS-001", "AWS-RDS-002"})

    def test_escaped_and_non_ascii_addresses_keep_their_lines(self):
        r = [{"address": 'aws_ebs_volume.v["café<1>"]', "mode": "managed", "type": "aws_ebs_volume",
              "values": {"encrypted": False}}]
        text = json.dumps(self.plan(r), indent=2, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e")
        expected = next(n for n, line in enumerate(text.split("\n"), 1) if '"address"' in line)
        self.assertEqual(hits({"plan.json": text}), [("AWS-EBS-001", "plan.json", expected)])

    def test_unexpected_shapes_do_not_crash(self):
        for doc in ({"planned_values": "x"}, self.plan([{"address": "a", "type": None, "values": {}}]),
                    self.plan([{"address": "a", "type": "aws_s3_bucket", "values": [1]}])):
            with self.subTest(doc=doc):
                result = scan({"plan.json": doc})
                self.assertEqual(result.hits, [])



class PrecisionTest(unittest.TestCase):
    def test_backend_configs_must_all_encrypt(self):
        files = {"main.tf": 'terraform {\n  backend "s3" {\n    key = "k"\n  }\n}\n',
                 "dev.tfbackend": "encrypt = true\n", "prod.tfbackend": "encrypt = false\n"}
        self.assertEqual([h[0] for h in hits(files)], ["PS-002"])

    def test_dated_branch_names_are_not_tags(self):
        text = 'module "m" {\n  source = "git::https://example.com/m.git?ref=2024-hotfix-branch"\n}\n'
        self.assertEqual([h[0] for h in hits({"main.tf": text})], ["PS-001"])

    def test_wrapped_file_credentials(self):
        for value in ('"${file("sa-key.json")}"', 'trimspace(file("secret.txt"))'):
            with self.subTest(value=value):
                text = f'provider "google" {{\n  credentials = {value}\n}}\n'
                self.assertEqual([h[0] for h in hits({"main.tf": text})], ["PS-003"])

    def test_rule_line_is_the_open_range(self):
        text = ('resource "aws_security_group_rule" "r" {\n  type = "ingress"\n  from_port = 22\n'
                '  to_port = 22\n  protocol = "tcp"\n  cidr_blocks = ["10.0.0.0/8"]\n'
                '  ipv6_cidr_blocks = ["::/0"]\n}\n')
        self.assertEqual(hits({"main.tf": text}), [("AWS-NET-001", "main.tf", 7)])


if __name__ == "__main__":
    unittest.main()
