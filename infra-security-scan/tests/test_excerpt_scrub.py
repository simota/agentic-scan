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


class ExcerptScrubTest(OutputTest):
    def test_free_text_and_uncommon_secret_shapes_stay_out_of_reports(self):
        for name, text in CASES.items():
            with self.subTest(name=name):
                self.write(name, text)
                record = self.record(f"{name}:{line_of(text)}")
                for page in self.pages(record):
                    self.assertNotIn(M, page)

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


if __name__ == "__main__":
    unittest.main()
