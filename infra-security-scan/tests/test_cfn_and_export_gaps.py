"""CloudFormation documents and rules written as strings, intrinsics or JSON in a
.yaml file, tags before quoted scalars, and AWS export cursors: each is read, or
named in not_run, and none aborts the scan or reads as a secret."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "infra-security-scan" / "scripts"))
import iac_scan  # noqa: E402

SSH_WORLD = '''  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: {description}
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
'''


def scan(files, snapshots=None):
    with tempfile.TemporaryDirectory(prefix="iac-cfn-gaps-") as tmp:
        for name, text in files.items():
            path = Path(tmp) / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return iac_scan.run(tmp, [str(Path(tmp) / snapshots)] if snapshots else ())


def template(resources):
    return 'AWSTemplateFormatVersion: "2010-09-09"\nResources:\n' + resources


def rules(result):
    return sorted({h["rule"] for h in result.hits})


class TemplateShapeTest(unittest.TestCase):
    def test_a_quoted_scalar_after_a_short_form_tag(self):
        for description in ('!Sub "web tier #${AWS::StackName}"', "!Sub 'echo region: ${AWS::Region}'"):
            with self.subTest(description=description):
                result = scan({"t.yaml": template(SSH_WORLD.format(description=description))})
                self.assertEqual(rules(result), ["AWS-NET-001"], result.not_run)

    def test_a_long_form_intrinsic_as_a_flow_key(self):
        text = template(SSH_WORLD.format(description="x") + "      VpcId: {Fn::ImportValue: shared-vpc}\n")
        result = scan({"t.yaml": text})
        self.assertEqual(rules(result), ["AWS-NET-001"], result.not_run)

    def test_a_json_template_saved_as_yaml(self):
        doc = {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"Sg": {
            "Type": "AWS::EC2::SecurityGroup", "Properties": {"GroupDescription": "x", "SecurityGroupIngress": [
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"}]}}}}
        result = scan({"template.yaml": json.dumps(doc, indent=2)})
        self.assertEqual(rules(result), ["AWS-NET-001"], result.not_run)

    def test_a_list_ref_to_a_launch_template_does_not_abort(self):
        text = template('''  Lt:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateData:
        MetadataOptions:
          HttpTokens: required
  Vm:
    Type: AWS::EC2::Instance
    Properties:
      LaunchTemplate:
        LaunchTemplateId: !Ref [Lt]
''')
        result = scan({"t.yaml": text})
        self.assertTrue(any("cfn:Vm" in line for line in result.not_run), result.not_run)


class PolicyDocumentTest(unittest.TestCase):
    def test_a_json_string_document_is_read(self):
        doc = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                                         "Resource": "arn:aws:s3:::b/*"}]})
        admin = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
        text = template(f'''  Bp:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: b
      PolicyDocument: '{doc}'
  Admin:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument: '{admin}'
''')
        self.assertEqual(rules(scan({"t.yaml": text})), ["AWS-IAM-001", "AWS-S3-003"])

    def test_a_statement_with_a_condition_is_a_literal(self):
        text = template('''  Deploy:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal: {Federated: "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"}
            Action: sts:AssumeRoleWithWebIdentity
            Condition:
              StringEquals:
                token.actions.githubusercontent.com:aud: sts.amazonaws.com
                token.actions.githubusercontent.com:sub: repo:org/app:ref:refs/heads/main
''')
        result = scan({"t.yaml": text})
        self.assertEqual((result.hits, result.not_run), ([], []))

    def test_intrinsic_ports_open_to_the_world_are_named(self):
        text = template('''  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: x
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: !Ref Port
          ToPort: !Ref Port
          CidrIp: 0.0.0.0/0
''')
        result = scan({"t.yaml": text})
        self.assertEqual(result.hits, [])
        self.assertTrue(any("unresolved protocol or ports" in line for line in result.not_run), result.not_run)

    def test_unread_documents_and_conditional_statements_are_named(self):
        text = template('''  Block:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument: |
        {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
  Conditional:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Statement:
          - !If [IsDev, {Effect: Allow, Action: "*", Resource: "*"}, !Ref AWS::NoValue]
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: x
      SecurityGroupIngress:
        - !If [IsDev, {IpProtocol: tcp, FromPort: 22, ToPort: 22, CidrIp: 0.0.0.0/0}, !Ref AWS::NoValue]
''')
        result = scan({"t.yaml": text})
        self.assertEqual(result.hits, [])
        for address in ("cfn:Block", "cfn:Conditional", "cfn:Sg"):
            with self.subTest(address=address):
                self.assertTrue(any(address in line and "not a literal" in line for line in result.not_run),
                                result.not_run)


class ExportCursorTest(unittest.TestCase):
    def test_idempotency_and_pagination_tokens_are_not_secrets(self):
        export = {"Reservations": [{"Instances": [{
            "InstanceId": "i-0abc", "ClientToken": "terraform-20240101000000000000000001",
            "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"}}]}],
            "NextToken": "eyJOZXh0VG9rZW4iOiBudWxsLCAiYm90b190cnVuY2F0ZV9hbW91bnQiOiAxfQ=="}
        result = scan({"repo/main.tf": "", "exports/aws-instances.json": json.dumps(export, indent=2)},
                      snapshots="exports")
        self.assertNotIn("SEC-001", rules(result))
        # A secret-named field in an export is still reported.
        export["Reservations"][0]["Instances"][0]["AuthToken"] = "plain-" + "value-1234"
        result = scan({"repo/main.tf": "", "exports/aws-instances.json": json.dumps(export, indent=2)},
                      snapshots="exports")
        self.assertIn("SEC-001", rules(result))


if __name__ == "__main__":
    unittest.main()
