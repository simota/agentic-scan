"""AWS rules on realistic shapes: CloudFormation short-form tags and CDK output,
SAM Globals, plan JSON defaults, Terragrunt trees, CLI exports and HCL idioms."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-security-scan" / "scripts"))
import iac_scan  # noqa: E402

SECRET = "Zq" + "x9" * 5 + "Wp"


def scan(files, snapshots=None):
    with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as snap:
        for name, text in files.items():
            path = Path(tmp) / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text if isinstance(text, str) else json.dumps(text, indent=1), encoding="utf-8")
        for name, doc in (snapshots or {}).items():
            (Path(snap) / name).write_text(json.dumps(doc, indent=1), encoding="utf-8")
        return iac_scan.run(tmp, [snap] if snapshots else ())


def hits(result):
    return sorted({(h["rule"], h["address"]) for h in result.hits})


class CloudFormationTest(unittest.TestCase):
    def test_short_form_tags(self):
        template = """AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      VpcId: !Ref VpcId
      GroupDescription: !Sub '${AWS::StackName} rdp'
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 3389
          ToPort: 3389
          CidrIp: 0.0.0.0/0
  Site:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
      BucketName: !Join ['-', [site, !Ref AWS::AccountId]]
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Role: !If
        - UseRole
        - !GetAtt Role.Arn
        - !Ref AWS::NoValue
"""
        result = scan({"stack.yaml": template})
        self.assertEqual(hits(result), [("AWS-NET-001", "cfn:Sg"), ("AWS-S3-001", "cfn:Site")])

    def test_cdk_join_admin_arn_and_role_policies(self):
        admin = {"Fn::Join": ["", ["arn:", {"Ref": "AWS::Partition"}, ":iam::aws:policy/AdministratorAccess"]]}
        doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        template = {"Resources": {
            "Deploy": {"Type": "AWS::IAM::Role", "Properties": {"ManagedPolicyArns": [admin]}},
            "Inline": {"Type": "AWS::IAM::RolePolicy", "Properties": {"PolicyDocument": doc}},
            "Imported": {"Type": "AWS::KMS::Key", "Properties": {"Origin": "EXTERNAL"}},
            "Plain": {"Type": "AWS::KMS::Key", "Properties": {}}}}
        self.assertEqual(hits(scan({"cdk.out/App.template.json": template})),
                         [("AWS-IAM-001", "cfn:Deploy"), ("AWS-IAM-001", "cfn:Inline"), ("AWS-KMS-001", "cfn:Plain")])

    def test_launch_templates_instances_and_literal_secrets(self):
        template = {"Resources": {
            "Lt": {"Type": "AWS::EC2::LaunchTemplate", "Properties": {"LaunchTemplateData": {
                "MetadataOptions": {"HttpTokens": "optional"},
                "BlockDeviceMappings": [{"Ebs": {"Encrypted": False}}]}}},
            "Good": {"Type": "AWS::EC2::LaunchTemplate", "Properties": {"LaunchTemplateData": {
                "MetadataOptions": {"HttpTokens": "required"}}}},
            "Vm": {"Type": "AWS::EC2::Instance", "Properties": {"LaunchTemplate": {"LaunchTemplateId": {"Ref": "Good"}}}},
            "Db": {"Type": "AWS::RDS::DBInstance", "Properties": {
                "MasterUserPassword": SECRET, "StorageEncrypted": True}},
            "Resolved": {"Type": "AWS::RDS::DBInstance", "Properties": {
                "MasterUserPassword": "{{resolve:secretsmanager:db}}", "StorageEncrypted": True}},
            "Fn": {"Type": "AWS::Lambda::Function", "Properties": {"Environment": {"Variables": {"API_TOKEN": SECRET}}}},
            "Task": {"Type": "AWS::ECS::TaskDefinition", "Properties": {"ContainerDefinitions": [
                {"Environment": [{"Name": "DB_PASSWORD", "Value": SECRET}, {"Name": "LOG", "Value": "x"}]}]}}}}
        result = scan({"t.json": template})
        self.assertEqual(hits(result), [("AWS-EBS-001", "cfn:Lt"), ("AWS-EC2-001", "cfn:Lt"), ("SEC-001", "t.json")])
        self.assertEqual(sorted(h["detail"] for h in result.hits if h["rule"] == "SEC-001"),
                         ["literal value assigned to API_TOKEN (cfn:Fn)", "literal value assigned to DB_PASSWORD (cfn:Task)",
                          "literal value assigned to MasterUserPassword (cfn:Db)"])
        # Its launch template is in this template and checked on its own.
        self.assertFalse([n for n in result.not_run if "cfn:Vm" in n])

    def test_sam_globals(self):
        template = {"Transform": "AWS::Serverless-2016-10-31",
                    "Globals": {"Function": {"FunctionUrlConfig": {"AuthType": "NONE"}}},
                    "Resources": {"Inherits": {"Type": "AWS::Serverless::Function", "Properties": {}},
                                  "Overrides": {"Type": "AWS::Serverless::Function", "Properties": {
                                      "FunctionUrlConfig": {"AuthType": "AWS_IAM"}}}}}
        self.assertEqual(hits(scan({"template.json": template})), [("AWS-LAMBDA-001", "cfn:Inherits")])


class PlanTest(unittest.TestCase):
    def plan(self, resources, configured):
        return {"planned_values": {"root_module": {"resources": [
                    {"address": a, "mode": "managed", "type": a.split(".")[0], "name": a.split(".")[1], "values": v}
                    for a, v, _ in resources]}},
                "resource_changes": [{"address": a, "change": {"after_unknown": u}} for a, _, u in resources],
                "configuration": {"root_module": {"resources": [
                    {"address": a, "expressions": e} for a, e in configured.items()]}}}

    def test_omitted_arguments_are_defaults_not_unknowns(self):
        doc = self.plan([("aws_instance.web", {"ami": "ami-1"}, {"metadata_options": True, "id": True}),
                         ("aws_ebs_volume.data", {"size": 10}, {"encrypted": True, "id": True}),
                         ("aws_ebs_volume.set", {"size": 10}, {"encrypted": True})],
                        {"aws_instance.web": {"ami": {}}, "aws_ebs_volume.data": {"size": {}},
                         "aws_ebs_volume.set": {"size": {}, "encrypted": {"references": ["var.e"]}}})
        result = scan({"plan.json": doc})
        self.assertEqual(hits(result), [("AWS-EBS-001", "aws_ebs_volume.data"), ("AWS-EC2-001", "aws_instance.web")])
        self.assertEqual(result.not_run, ["plan value unknown until apply (encrypted); affected checks not run: "
                                          "aws_ebs_volume.set at plan.json:24"])

    def test_unknowns_no_rule_reads_are_quiet(self):
        doc = self.plan([("aws_s3_bucket_public_access_block.p", {
            "block_public_acls": True, "block_public_policy": True, "ignore_public_acls": True,
            "restrict_public_buckets": True}, {"bucket": True, "id": True})], {})
        self.assertEqual(scan({"plan.json": doc}).not_run, [])


class TerraformIdiomTest(unittest.TestCase):
    def test_trust_conditions_that_do_not_narrow(self):
        policy = ('jsonencode({ Statement = [{ Effect = "Allow", Principal = { AWS = "*" }, Action = "sts:AssumeRole",'
                  ' Condition = { Bool = { "aws:SecureTransport" = "true" } } }] })')
        narrowed = ('jsonencode({ Statement = [{ Effect = "Allow", Principal = { AWS = "*" }, Action = "sts:AssumeRole",'
                    ' Condition = { StringEquals = { "aws:PrincipalOrgID" = "o-1" } } }] })')
        result = scan({"iam.tf": f'resource "aws_iam_role" "open" {{\n  assume_role_policy = {policy}\n}}\n'
                                 f'resource "aws_iam_role" "org" {{\n  assume_role_policy = {narrowed}\n}}\n'})
        self.assertEqual(hits(result), [("AWS-IAM-003", "aws_iam_role.open")])

    def test_imds_defaults_launch_templates_and_lines(self):
        result = scan({"main.tf": '''resource "aws_ec2_instance_metadata_defaults" "d" {
  http_tokens = "required"
}
resource "aws_instance" "partial" {
  metadata_options {
    http_put_response_hop_limit = 2
  }
}
resource "aws_launch_template" "app" {
  metadata_options {
    http_tokens = "required"
  }
}
resource "aws_instance" "via_lt" {
  launch_template {
    id = aws_launch_template.app.id
  }
}
resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = "sg-1"
  ip_protocol = "tcp"
  from_port = 22
  to_port = 22
  cidr_ipv4 = "0.0.0.0/0"
}
'''})
        self.assertEqual([(h["rule"], h["line"]) for h in result.hits], [("AWS-NET-001", 24)])
        self.assertEqual(result.not_run, [])

    def test_admin_through_data_source_and_for_each(self):
        result = scan({"iam.tf": '''data "aws_iam_policy" "admin" {
  name = "AdministratorAccess"
}
resource "aws_iam_role_policy_attachment" "a" {
  role = "r"
  policy_arn = data.aws_iam_policy.admin.arn
}
resource "aws_iam_role_policy_attachment" "b" {
  for_each = toset(["arn:aws:iam::aws:policy/AdministratorAccess", "arn:aws:iam::aws:policy/ReadOnlyAccess"])
  role = "r"
  policy_arn = each.value
}
'''})
        self.assertEqual(hits(result), [("AWS-IAM-001", "aws_iam_role_policy_attachment.a"),
                                        ("AWS-IAM-001", "aws_iam_role_policy_attachment.b")])

    def test_container_environment_literals(self):
        result = scan({"ecs.tf": f'''resource "aws_ecs_task_definition" "t" {{
  container_definitions = jsonencode([{{
    environment = [{{ name = "DB_PASSWORD", value = "{SECRET}" }}, {{ name = "LOG", value = "debug" }}]
  }}])
}}
resource "kubernetes_deployment" "d" {{
  env {{
    name  = "AUTH_TOKEN"
    value = "{SECRET}"
  }}
}}
'''})
        self.assertEqual(sorted((h["line"], h["detail"]) for h in result.hits),
                         [(3, "literal value for DB_PASSWORD"), (8, "literal value for AUTH_TOKEN")])


class TerragruntTest(unittest.TestCase):
    def test_live_repository(self):
        result = scan({
            "root.hcl": 'remote_state {\n  backend = "s3"\n  config = {\n    bucket = "s"\n    encrypt = false\n  }\n}\n',
            "prod/account.hcl": 'locals {\n  account_id = "111122223333"\n}\n',
            "_envcommon/vpc.hcl": 'locals {\n  base = "git::https://example.com/m.git//vpc"\n}\n'
                                  'terraform {\n  source = "${local.base}?ref=main"\n}\n',
            "prod/app/terragrunt.hcl": 'include "root" {\n  path = find_in_parent_folders("root.hcl")\n}\n',
            "prod/app/main.tf": 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n',
            "vault/policy.hcl": 'path "secret/*" {\n  capabilities = ["read"]\n}\n'})
        self.assertEqual(hits(result), [("PS-001", "terragrunt:_envcommon/vpc.hcl"),
                                        ("PS-002", "terragrunt.remote_state.s3")])
        terragrunt = [n for n in result.not_run if n.startswith("Terragrunt configuration")]
        self.assertEqual(len(terragrunt), 1)
        self.assertIn("(4 file(s))", terragrunt[0])
        self.assertTrue([n for n in result.not_run if "Vault" in n and "vault/policy.hcl" in n])


class ExportTest(unittest.TestCase):
    def test_cli_exports_get_rules(self):
        admin = "arn:aws:iam::aws:policy/AdministratorAccess"
        open_trust = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}
        result = scan({"main.tf": "\n"}, {
            "aws-iam.json": {"RoleDetailList": [{"RoleName": "open", "Arn": "arn:aws:iam::1:role/open",
                                                 "AssumeRolePolicyDocument": open_trust}],
                             "UserDetailList": [{"UserName": "u", "Arn": "arn:aws:iam::1:user/u",
                                                 "AttachedManagedPolicies": [{"PolicyArn": admin}]}],
                             "GroupDetailList": [], "Policies": []},
            "aws-rds.json": {"DBInstances": [{"DBInstanceIdentifier": "db", "PubliclyAccessible": True,
                                              "StorageEncrypted": False}]},
            "aws-instances.json": {"Reservations": [{"Instances": [{"InstanceId": "i-1", "MetadataOptions": {
                "HttpTokens": "optional", "HttpEndpoint": "enabled"}}]}]},
            "aws-lambda-urls.json": {"FunctionUrlConfigs": [{"FunctionArn": "arn:fn", "AuthType": "NONE"}]},
            "aws-cloudtrail.json": {"trailList": [{"Name": "t", "IsMultiRegionTrail": False,
                                                   "LogFileValidationEnabled": True}]},
            "aws-account-pab.json": {"PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": False,
                "RestrictPublicBuckets": True}}})
        self.assertEqual(sorted(h["rule"] for h in result.hits),
                         ["AWS-CT-001", "AWS-EC2-001", "AWS-IAM-001", "AWS-IAM-003", "AWS-LAMBDA-001",
                          "AWS-RDS-001", "AWS-RDS-002", "AWS-S3-002"])
        self.assertEqual(result.not_run, [])


if __name__ == "__main__":
    unittest.main()
