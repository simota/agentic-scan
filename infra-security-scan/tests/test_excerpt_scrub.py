"""Source excerpts never carry secrets written as free text or in uncommon shapes.

Each case writes a synthetic marker where a secret would be, renders a finding
located on that line, and checks that neither HTML report contains it.
"""
import json
from pathlib import Path
import sys
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-scan" / "scripts"))
import redaction  # noqa: E402
import render  # noqa: E402

from test_output_redaction import OutputTest  # noqa: E402

M = "synthetic" + "Marker7Q"


def line_of(text, needle=M):
    return next(n for n, row in enumerate(text.split("\n"), 1) if needle in row)


CASES = {
    "last_applied.yaml": (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n  annotations:\n"
        "    kubectl.kubernetes.io/last-applied-configuration: '{\"spec\":{\"env\":[{\"name\":\"DB_PASSWORD\","
        f"\"value\":\"{M}\"}}]}}}}'\nspec:\n  replicas: 1\n"),
    "sensitive_fn.tf": f'locals {{\n  x = sensitive("{M}")\n}}\n',
    "ssm.tf": ('resource "aws_ssm_parameter" "p" {\n  name = "/app/config"\n  type = "SecureString"\n'
               f'  value = "{M}"\n}}\n'),
    "k8s_secret.tf": ('resource "kubernetes_secret" "s" {\n  metadata {\n    name = "tls"\n  }\n'
                      f'  data = {{\n    "tls.crt" = "{M}"\n  }}\n}}\n'),
    "heredoc_call.tf": ('resource "aws_db_instance" "d" {\n  engine = "postgres"\n'
                        f'  password = trimspace(<<EOF\nab)c\n{M}\nEOF\n  )\n  publicly_accessible = true\n}}\n'),
    "jdbc.tf": f'locals {{\n  url = "jdbc:sqlserver://db:1433;user=sa;password={M}"\n}}\n',
    "scp_source.tf": f'module "m" {{\n  source = "git::{M}@github.com:org/mod.git?ref=v1"\n}}\n',
    "args.yaml": ("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n  - name: c\n"
                  f"    image: x\n    args: [\"--password\", \"{M}\"]\n"),
    "db_pass.yaml": ("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n  - name: c\n"
                     f"    image: x\n    env:\n    - name: DB_PASS\n      value: {M}\n"),
    "lambda.json": json.dumps({"Environment": {"Variables": {"PGPASS": M}}}, indent=2),
    "plan.json": json.dumps({"format_version": "1.2", "variables": {"admin_pw": {"value": M}},
                             "planned_values": {"root_module": {}}}, indent=2),
    "comment.tf": f'resource "aws_s3_bucket" "b" {{\n  # old admin pw was {M}\n  bucket = "b"\n}}\n',
    "userdata.tf": f'resource "aws_instance" "i" {{\n  ami = "ami-1"\n  user_data_base64 = "{M}"\n}}\n',
    "shell.json": json.dumps({"Resources": {"I": {"Type": "AWS::EC2::Instance", "Properties": {
        "UserData": {"Fn::Join": ["", ["#!/bin/bash\n", f"mysql -uroot -p{M}\n"]]}}}}}, indent=2),
    "putty.tf": ('locals {\n  k = <<EOT\nPuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n'
                 f'Private-Lines: 1\n{M}\nPrivate-MAC: 00\nEOT\n}}\n'),
    "cfn_ref.json": json.dumps({"Parameters": {"Boot": {"Type": "String", "Default": M}},
                                "Resources": {"D": {"Type": "AWS::RDS::DBInstance", "Properties": {
                                    "MasterUserPassword": {"Ref": "Boot"}}}}}, indent=2),
}


# A short-form tag or anchor before the value does not end it on that line;
# each finding sits on the public line after it, as a neighbouring finding would.
# A lowercase word: the last-pass scrub of opaque tokens does not catch it.
W = "quiet" + "meadowlark"
TAGGED = {
    **{f"cfn_tag_{n}.yaml": ("Resources:\n  Db:\n    Type: AWS::RDS::DBInstance\n    Properties:\n"
                             f"      MasterUserPassword: {value}\n    Next: x\n")
       for n, value in enumerate((f"!Sub |\n        {W}", f"!Join\n        - ''\n        - - a\n          - {W}",
                                  f"!Join # joined\n        - ''\n        - - {W}",
                                  f"&pw !Sub >-\n        {W}", f"!!str\n        {W}"))},
    "cfn_userdata.yaml": ("Resources:\n  Web:\n    Type: AWS::EC2::Instance\n    Properties:\n"
                          "      UserData:\n        Fn::Base64: !Sub |\n          #!/bin/bash\n"
                          f"          printf '%s' '{W}' > /etc/app/db.conf\n      ImageId: ami-1\n"),
}


class ExcerptScrubTest(OutputTest):
    def test_free_text_and_uncommon_secret_shapes_stay_out_of_reports(self):
        for name, text in CASES.items():
            with self.subTest(name=name):
                self.write(name, text)
                record = self.record(f"{name}:{line_of(text)}")
                for page in self.pages(record):
                    self.assertNotIn(M, page)

    def test_tagged_yaml_values_stay_hidden_below_their_key(self):
        for name, text in TAGGED.items():
            with self.subTest(name=name):
                self.write(name, text)
                public = "ImageId" if "ImageId" in text else "Next"
                record = self.record(f"{name}:{line_of(text, public)}")
                for page in self.pages(record):
                    self.assertNotIn(W, page)

    def test_secret_names_the_public_spellings_and_lists_missed(self):
        cases = {
            "authorizer.tf": f'resource "aws_lambda_function" "auth" {{\n'
                             f'  environment {{ variables = {{ AUTHORIZER_SECRET = "{W}" }} }}\n}}\n',
            "authorizer_token.tf": f'locals {{\n  lambda_authorizer_token = "{W}"\n}}\n',
            "kms.tf": f'resource "aws_kms_ciphertext" "c" {{\n  key_id = "k"\n  plaintext = "{W}"\n}}\n',
            "vpn.tf": f'resource "aws_vpn_connection" "v" {{\n  tunnel1_preshared_key = "{W}"\n}}\n',
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                text += 'resource "aws_s3_bucket" "logs" {\n  bucket = "logs"\n}\n'
                self.write(name, text)
                record = self.record(f"{name}:{line_of(text, 'bucket = ')}")
                for page in self.pages(record):
                    self.assertNotIn(W, page)
        # The public spellings stay readable.
        for line in ('authorizer_id = "abc123"', 'authorizer_uri = "arn:aws:apigateway:x"',
                     'authorization_type = "CUSTOM"', 'type = "PLAINTEXT"'):
            with self.subTest(line=line):
                self.assertEqual(redaction.redact_lines([line]), [line])
                self.assertEqual(redaction.scrub_line(line), line)

    def test_respelled_locations_name_the_file_they_open(self):
        for name, text in ((".env", f"PGPASS={M}\n"), ("terraform.tfstate", f'{{"result": "{M}"}}\n'),
                           (".envrc", f"export TOKEN={M}\n")):
            for spelling in (f"{name}/.", f"./{name}"):
                with self.subTest(spelling=spelling):
                    self.write(name, text)
                    self.assertEqual(render.attach_sources(self.record(f"{spelling}:1"), self.repo), {})

    def test_public_lines_keep_their_values(self):
        text = ('resource "aws_lambda_function_url" "u" {\n  authorization_type = "NONE"\n}\n'
                'resource "aws_db_instance" "d" {\n  password = var.db_password\n'
                '  publicly_accessible = true\n  ami = "ami-0abcdef1234567890"\n}\n')
        self.write("main.tf", text)
        rows = self.excerpt("main.tf:2-7")
        shown = "\n".join(r[1] for r in rows)
        for kept in ('authorization_type = "NONE"', "password = var.db_password", "ami-0abcdef1234567890"):
            self.assertIn(kept, shown)

    def test_scrub_line_masks_opaque_tokens_and_userinfo(self):
        self.assertNotIn("Zx9", redaction.scrub_line('  k = "Zx9kQ2vLm8Rt4Wp7Ab"'))
        self.assertIn("[redacted]@db", redaction.scrub_line('  u = "app:secretvalue@db.example.com:5432/app"'))
        self.assertIn("://[redacted]@", redaction.scrub_line('  u = "postgres://app:a b@db/app"'))



class ScrubPrecisionTest(OutputTest):
    """The scrub keeps the evidence a finding needs and runs in linear time."""

    def test_long_lines_are_fast(self):
        import time
        for line in ("x://" + 'a"' * 50000, "password" + " " * 100000 + "x", '{"a": "s3://b", ' * 20000):
            start = time.monotonic()
            redaction.scrub_lines([line], "json")
            self.assertLess(time.monotonic() - start, 2.0)

    def test_json_heredoc_policy_stays_readable(self):
        text = ('resource "aws_iam_policy" "p" {\n  policy = <<EOF\n{\n  "Statement": [{\n'
                '    "Effect": "Allow", "Action": "*", "Resource": "*"\n  }]\n}\nEOF\n}\n')
        self.write("main.tf", text)
        shown = "\n".join(r[1] for r in self.excerpt("main.tf:1-9"))
        self.assertIn('"Action": "*"', shown)

    def test_ordinary_names_do_not_hide_whole_files(self):
        cases = {
            "plan.json": json.dumps({"format_version": "1.2", "planned_values": {"root_module": {}},
                                     "configuration": {"root_module": {"resources": [{"expressions": {
                                         "metadata_options": [{"http_tokens": {"constant_value": "optional"}}],
                                         "authorization_type": {"constant_value": "NONE"}}}]}}}, indent=2),
            "deploy.yaml": ("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n  - name: c\n"
                            "    image: x\n    args: [\"-port=8080\", \"/bin/auth-server\"]\n"),
            "svc.tf": ('resource "aws_ecs_service" "s" {\n  name = "auth-service"\n}\n'
                       'output "o" {\n  value = aws_ecs_service.s.id\n}\n'),
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                self.write(name, text)
                self.assertIn("F-001", render.attach_sources(self.record(f"{name}:2"), self.repo))

    def test_openers_in_comments_open_nothing(self):
        text = '# usage: cat <<EOF\nresource "aws_s3_bucket" "b" {\n  bucket = "visible-bucket"\n}\n'
        self.write("main.tf", text)
        self.assertIn("visible-bucket", "\n".join(r[1] for r in self.excerpt("main.tf:3")))

    def test_identifiers_and_refs_stay_readable(self):
        for line, kept in (('  role = "arn:aws:iam::111122223333:role/my-role-2024"', "my-role-2024"),
                           ('  source = "git::https://e.com/m.git?ref=' + "a1b2" * 10 + '"', "ref=a1b2"),
                           ('  bucket = "my-bucket-2024-prod"', "my-bucket-2024-prod"),
                           ('  member = "user:alice@example.com"', "user:alice@example.com"),
                           ('  args = ["-port=8080"]', "-port=8080")):
            with self.subTest(line=line):
                self.assertIn(kept, redaction.scrub_line(line))
        self.assertNotIn("Zx", redaction.scrub_line('  cmd = "mysql -uroot -pZx9secret"'))


if __name__ == "__main__":
    unittest.main()
