"""Native Terraform overrides and structural CloudFormation YAML inventory."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "infra-scan" / "scripts"))
import iac_scan  # noqa: E402


class ScanFiles(unittest.TestCase):
    def scan(self, files):
        with tempfile.TemporaryDirectory(prefix="iac-override-inventory-") as tmp:
            for name, text in files.items():
                path = Path(tmp) / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            return iac_scan.run(tmp)


class TerraformOverrideTest(ScanFiles):
    SSH = '''resource "aws_security_group_rule" "ssh" {
  type = "ingress"
  security_group_id = "sg-00000000000000000"
  protocol = "tcp"
  from_port = 22
  to_port = 22
  cidr_blocks = ["10.0.0.0/8"]
}
'''

    def test_override_world_cidr_uses_inherited_ports_and_one_inventory_entry(self):
        scan = self.scan({
            "main.tf": self.SSH,
            "override.tf": '''resource "aws_security_group_rule" "ssh" {
  cidr_blocks = ["0.0.0.0/0"]
}
''',
        })
        self.assertEqual([(r["address"], r["file"], r["line"]) for r in scan.resources],
                         [("aws_security_group_rule.ssh", "override.tf", 1)])
        self.assertEqual([(h["rule"], h["file"], h["line"]) for h in scan.hits],
                         [("AWS-NET-001", "override.tf", 1)])
        self.assertEqual(scan.not_run, [])
        # Source-carrying line numbers must remain ordinary JSON numbers.
        json.dumps(iac_scan.report(scan, Path("."), "unknown", iac_scan.build_findings(scan.hits)))

    def test_secure_override_removes_the_original_encryption_hit(self):
        scan = self.scan({
            "main.tf": 'resource "aws_ebs_volume" "disk" { encrypted = false }\n',
            "override.tf": 'resource "aws_ebs_volume" "disk" { encrypted = true }\n',
        })
        self.assertEqual(len(scan.resources), 1)
        self.assertEqual(scan.hits, [])
        self.assertEqual(scan.not_run, [])

    def test_inherited_unsafe_attribute_keeps_its_original_source(self):
        scan = self.scan({
            "main.tf": '''resource "aws_ebs_volume" "disk" {
  size = 1
  encrypted = false
}
''',
            "override.tf": '''resource "aws_ebs_volume" "disk" {
  tags = { Name = "retained" }
}
''',
        })
        self.assertEqual([(h["rule"], h["file"], h["line"]) for h in scan.hits],
                         [("AWS-EBS-001", "main.tf", 3)])

    def test_overrides_follow_all_normal_files_then_lexical_override_order(self):
        scan = self.scan({
            "z-main.tf": 'resource "aws_ebs_volume" "disk" { encrypted = true }\n',
            "a_override.tf": 'resource "aws_ebs_volume" "disk" { encrypted = false }\n',
            "z_override.tf": 'resource "aws_ebs_volume" "disk" { encrypted = true }\n',
        })
        self.assertEqual(len(scan.resources), 1)
        self.assertEqual(scan.resources[0]["file"], "z_override.tf")
        self.assertEqual(scan.hits, [])

    def test_overrides_do_not_change_other_resources_or_module_directories(self):
        scan = self.scan({
            "a/main.tf": '''resource "aws_ebs_volume" "disk" { encrypted = true }
resource "aws_lambda_function_url" "public" { authorization_type = "NONE" }
''',
            "a/override.tf": 'resource "aws_ebs_volume" "disk" { encrypted = false }\n',
            "b/main.tf": 'resource "aws_ebs_volume" "disk" { encrypted = false }\n',
        })
        self.assertEqual(len(scan.resources), 3)
        self.assertEqual({(h["rule"], h["file"]) for h in scan.hits}, {
            ("AWS-EBS-001", "a/override.tf"), ("AWS-EBS-001", "b/main.tf"),
            ("AWS-LAMBDA-001", "a/main.tf"),
        })
        self.assertEqual(scan.not_run, [])

    def test_override_replaces_all_ingress_blocks(self):
        def group(cidrs):
            rules = "".join('''  ingress {
    protocol = "tcp"
    from_port = 22
    to_port = 22
    cidr_blocks = ["''' + cidr + '''"]
  }
''' for cidr in cidrs)
            return 'resource "aws_security_group" "app" {\n' + rules + '}\n'

        scan = self.scan({"main.tf": group(["0.0.0.0/0", "::/0"]),
                          "override.tf": group(["10.0.0.0/8"])})
        self.assertEqual(len(scan.resources), 1)
        self.assertEqual(scan.hits, [])
        self.assertEqual(scan.not_run, [])

    def test_nested_blocks_are_replaced_instead_of_deep_merged(self):
        scan = self.scan({
            "main.tf": '''resource "aws_instance" "app" {
  metadata_options {
    http_endpoint = "disabled"
    http_tokens = "required"
  }
}
''',
            "override.tf": '''resource "aws_instance" "app" {
  metadata_options {
    http_tokens = "optional"
  }
}
''',
        })
        self.assertEqual([(h["rule"], h["file"], h["line"]) for h in scan.hits],
                         [("AWS-EC2-001", "override.tf", 3)])

    def test_dynamic_override_replaces_known_blocks_without_becoming_absent(self):
        scan = self.scan({
            "main.tf": '''resource "aws_instance" "app" {
  metadata_options { http_tokens = "optional" }
}
''',
            "override.tf": '''resource "aws_instance" "app" {
  dynamic "metadata_options" {
    for_each = var.options
    content { http_tokens = "required" }
  }
}
''',
        })
        self.assertEqual(scan.hits, [])
        self.assertTrue(any("dynamic block not evaluated" in note and "override.tf:2" in note
                            for note in scan.not_run), scan.not_run)

    def test_static_override_replaces_dynamic_blocks_of_its_target_type(self):
        scan = self.scan({
            "main.tf": '''resource "aws_instance" "app" {
  dynamic "metadata_options" {
    for_each = var.options
    content { http_tokens = "required" }
  }
}
''',
            "override.tf": '''resource "aws_instance" "app" {
  metadata_options { http_tokens = "optional" }
}
''',
        })
        self.assertEqual([(h["rule"], h["file"], h["line"]) for h in scan.hits],
                         [("AWS-EC2-001", "override.tf", 2)])
        self.assertEqual(scan.not_run, [])

    def test_inherited_dynamic_blocks_keep_their_original_not_run_location(self):
        scan = self.scan({
            "main.tf": '''resource "aws_instance" "app" {
  dynamic "metadata_options" {
    for_each = var.options
    content { http_tokens = "required" }
  }
}
''',
            "override.tf": 'resource "aws_instance" "app" { tags = { Name = "app" } }\n',
        })
        self.assertEqual(scan.hits, [])
        self.assertTrue(any("dynamic block not evaluated" in note and "main.tf:2" in note
                            for note in scan.not_run), scan.not_run)

    def test_lifecycle_arguments_merge_and_provider_aliases_stay_separate(self):
        files = {
            "main.tf": '''resource "aws_ebs_volume" "disk" {
  encrypted = true
  lifecycle { prevent_destroy = true }
}
provider "aws" {
  alias = "east"
  region = "us-east-1"
}
provider "aws" {
  alias = "west"
  region = "us-west-1"
}
''',
            "override.tf": '''resource "aws_ebs_volume" "disk" {
  lifecycle { create_before_destroy = true }
}
provider "aws" {
  alias = "west"
  region = "us-west-2"
}
''',
        }
        scan = iac_scan.Scan(Path("."))
        parsed, uncertain = iac_scan.terraform_overrides(
            scan, [(name, iac_scan.parse_hcl(text)) for name, text in files.items()])
        views = [iac_scan.HclView(block) for _, blocks in parsed for block in blocks]
        lifecycle = next(v for v in views if v.block.type == "resource").blocks("lifecycle")[0]
        self.assertIs(lifecycle.get("prevent_destroy"), True)
        self.assertIs(lifecycle.get("create_before_destroy"), True)
        self.assertEqual(lifecycle.line("prevent_destroy").file, "main.tf")
        self.assertEqual(lifecycle.line("create_before_destroy").file, "override.tf")
        self.assertEqual({v.get("alias"): v.get("region") for v in views if v.block.type == "provider"},
                         {"east": "us-east-1", "west": "us-west-2"})
        self.assertEqual(uncertain, set())

    def test_module_version_override_preserves_its_source(self):
        scan = self.scan({
            "main.tf": 'module "network" { source = "terraform-aws-modules/vpc/aws" }\n',
            "override.tf": 'module "network" { version = "1.0.0" }\n',
        })
        self.assertEqual(len(scan.modules), 1)
        self.assertEqual(scan.modules[0]["source"], "terraform-aws-modules/vpc/aws")
        self.assertEqual(scan.modules[0]["version"], "1.0.0")
        self.assertEqual(scan.hits, [])

    def test_cloud_override_replaces_backend_from_separate_terraform_block(self):
        scan = self.scan({
            "backend.tf": '''terraform {
  backend "s3" { encrypt = false }
}
''',
            "main.tf": '''terraform { required_version = ">= 1.0" }
resource "aws_ebs_volume" "disk" { encrypted = true }
''',
            "override.tf": '''terraform {
  cloud {
    organization = "example"
    workspaces { name = "example" }
  }
}
''',
        })
        self.assertEqual(scan.backends, [])
        self.assertEqual(scan.hits, [])
        self.assertEqual(scan.not_run, [])

    def test_ambiguous_override_is_one_unknown_resource(self):
        scan = self.scan({
            "a.tf": 'resource "aws_ebs_volume" "disk" { encrypted = false }\n',
            "b.tf": 'resource "aws_ebs_volume" "disk" { encrypted = true }\n',
            "override.tf": 'resource "aws_ebs_volume" "disk" { size = 1 }\n',
        })
        self.assertEqual(len(scan.resources), 1)
        self.assertEqual(scan.hits, [])
        self.assertTrue(any("ambiguous base" in note and "aws_ebs_volume.disk" in note
                            for note in scan.not_run), scan.not_run)

    def test_missing_base_is_explicitly_not_run(self):
        scan = self.scan({"override.tf": 'resource "aws_ebs_volume" "disk" { encrypted = false }\n'})
        self.assertEqual(scan.resources, [])
        self.assertEqual(scan.hits, [])
        self.assertTrue(any("no base declaration" in note and "aws_ebs_volume.disk" in note
                            for note in scan.not_run), scan.not_run)


class CloudFormationYamlInventoryTest(ScanFiles):
    def test_parameter_types_and_nested_type_fields_are_not_resources(self):
        text = '''AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  VpcId:
    Type: AWS::EC2::VPC::Id
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Metadata:
      Example:
        Type: AWS::EC2::Instance
'''
        scan = self.scan({"stack.yaml": text})
        self.assertEqual([(r["address"], r["type"], r["line"]) for r in scan.resources],
                         [("cfn:Bucket", "AWS::S3::Bucket", 7)])
        self.assertEqual(scan.hits, [])
        self.assertEqual(scan.not_run,
                         ["cloudformation yaml: rules not applied (no YAML parser): stack.yaml"])

    def test_intrinsic_tag_fallback_skips_parameters_and_opaque_nested_templates(self):
        text = '''Parameters:
  VpcId:
    Type: AWS::EC2::VPC::Id
Metadata:
  Example: !Sub |
    Resources:
      FakeRoot:
        Type: AWS::EC2::Instance
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref BucketName
    Metadata:
      Example: |
        Type: AWS::EC2::Instance
        Resources:
          FakeNested:
            Type: AWS::EC2::Instance
  'Queue':
    'Type': 'AWS::SQS::Queue'
'''
        scan = self.scan({"stack.yaml": text})
        self.assertEqual(scan.files, [{"path": "stack.yaml", "kind": "cloudformation-yaml"}])
        self.assertEqual([(r["address"], r["type"], r["line"]) for r in scan.resources],
                         [("cfn:Bucket", "AWS::S3::Bucket", 11),
                          ("cfn:Queue", "AWS::SQS::Queue", 21)])

    def test_supported_flow_collections_are_inventoried_structurally(self):
        scan = self.scan({"stack.yaml": '''{Resources: {Bucket: {Type: 'AWS::S3::Bucket'}}, Parameters: {VpcId: {Type: 'AWS::EC2::VPC::Id'}}}
'''})
        self.assertEqual([(r["address"], r["line"]) for r in scan.resources], [("cfn:Bucket", 1)])

    def test_tagged_fallback_does_not_invent_resources_from_literal_root_text(self):
        scan = self.scan({"stack.yaml": '''AWSTemplateFormatVersion: '2010-09-09'
Description: !Sub |
  Resources:
    Fake:
      Type: AWS::EC2::Instance
Parameters:
  VpcId:
    Type: AWS::EC2::VPC::Id
Resources: {}
'''})
        self.assertEqual(scan.resources, [])
        self.assertEqual(scan.hits, [])


if __name__ == "__main__":
    unittest.main()
