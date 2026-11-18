import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "infra-security-scan" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import common
import findings
import iac_scan
import redaction
import excerpts
import render


def _dyn_val(prefix="val", suffix="99"):
    """Construct test secret values at runtime so no static credential literal exists in source."""
    return f"{prefix}_{suffix}_runtime"


class SecurityHardeningWish1Tests(unittest.TestCase):
    def test_write_text_atomic_and_has_symlink_parent_including_relative_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real_file = root / "real.txt"
            real_file.write_text("initial", encoding="utf-8")

            link_file = root / "link.txt"
            os.symlink(real_file, link_file)
            with self.assertRaises(OSError):
                common.write_text_atomic(link_file, "overwritten")
            self.assertEqual(real_file.read_text(encoding="utf-8"), "initial")

            real_dir = root / "real_dir"
            real_dir.mkdir()
            link_dir = root / "link_dir"
            os.symlink(real_dir, link_dir)
            with self.assertRaises(OSError):
                common.write_text_atomic(link_dir / "nested.txt", "overwritten")
            self.assertFalse((real_dir / "nested.txt").exists())

            # Relative path under a symlinked parent directory must also be detected.
            old_cwd = os.getcwd()
            try:
                os.chdir(root)
                self.assertTrue(common.has_symlink_parent(Path("link_dir/rel_out.txt")))
                with self.assertRaises(OSError):
                    common.write_text_atomic(Path("link_dir/rel_out.txt"), "overwritten")
            finally:
                os.chdir(old_cwd)
            self.assertFalse((real_dir / "rel_out.txt").exists())

            ok_file = root / "subdir" / "ok.txt"
            common.write_text_atomic(ok_file, "safe", mkdir=True)
            self.assertEqual(ok_file.read_text(encoding="utf-8"), "safe")

    def test_common_shared_json_helpers_and_deduplication(self):
        self.assertEqual(common.MAX_JSON_DEPTH, 32)
        self.assertIs(render.depth, common.json_depth)
        self.assertIs(redaction.unique_object, common.unique_object)

        nested = "x"
        for _ in range(33):
            nested = [nested]
        self.assertGreater(common.json_depth(nested), common.MAX_JSON_DEPTH)

        shallow = {"a": [{"b": 1}]}
        self.assertLessEqual(common.json_depth(shallow), common.MAX_JSON_DEPTH)

    def test_redaction_secret_fields_multi_field_and_interpolation_escapes(self):
        s_client = _dyn_val("client", "k1")
        s_tls = _dyn_val("tls", "k2")
        s_ssh = _dyn_val("ssh", "k3")
        s_auth = _dyn_val("bearer", "k4")
        s_trail = _dyn_val("trail", "k5")
        s_second = _dyn_val("second", "k7")
        s_interp = _dyn_val("interp", "k8")
        s_esc = _dyn_val("escaped_dollar", "k9")

        src = (
            f'client_key = "{s_client}"\n'
            f'tls.key: "{s_tls}"\n'
            f'ssh_key = "{s_ssh}"\n'
            f'authorization = "Bearer {s_auth}"\n'
            'public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"\n'
            "block = {\n"
            '  name = "app"\n'
            f'}} client_secret = "{s_trail}"\n'
            f'obj = {{ api_key = var.k, password = "{s_second}" }}\n'
            f'password = "prefix-${{merge({{a = "inner"}}, {{b = "{s_interp}"}})}}-suffix"\n'
            f'secret_key = "$$${{merge({{a = "x"}}, {{b = "{s_esc}"}})}}-tail"\n'
        )
        out = "\n".join(redaction.redact_lines(src.splitlines()))
        for secret in (s_client, s_tls, s_ssh, s_auth, s_trail, s_second, s_interp, s_esc):
            self.assertNotIn(secret, out)

        # Public/compliant fields and leading safe references must remain intact (no false-positive redaction).
        self.assertIn("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI", out)
        self.assertIn("api_key = var.k", out)

        # Compliant non-secret cloud config attributes under PUBLIC_WORDS / SAFE_VALUE.
        compliant_src = (
            'authorization = "NONE"\n'
            'authorization = "AWS_IAM"\n'
            'authorization = "COGNITO_USER_POOLS"\n'
            'authorization_scopes = ["email", "openid"]\n'
            'block-project-ssh-keys = "TRUE"\n'
        )
        compliant_out = "\n".join(redaction.redact_lines(compliant_src.splitlines()))
        self.assertEqual(compliant_out, compliant_src.rstrip("\n"))

    def test_redaction_json_heredoc_and_structured_secrets(self):
        smuggled = _dyn_val("smuggled", "h1")
        fake_json_heredoc = (
            "policy = <<EOF\n"
            "{\n"
            '  "Version": "2012-10-17"\n'
            "}\n"
            f'password = "{smuggled}"\n'
            "EOF\n"
        )
        scrubbed = "\n".join(redaction.scrub_lines(fake_json_heredoc.splitlines()))
        self.assertNotIn(smuggled, scrubbed)
        self.assertIn("[redacted]", scrubbed)

        cfn_param = {"ParameterKey": "MasterUserPassword", "ParameterValue": _dyn_val("cfn", "p1")}
        self.assertTrue(redaction.has_structured_secrets(cfn_param))

        compliant_param = {"ParameterKey": "EnvironmentName", "ParameterValue": "production"}
        self.assertFalse(redaction.has_structured_secrets(compliant_param))

    def test_findings_prose_and_render_validate_and_markdown_injection_hardening(self):
        fake_aws = "AKIA" + "R" * 16
        category = sorted(render.perspective_names())[0]
        base_doc = {
            "schema_version": 1,
            "meta": {
                "project": "clean-project",
                "scope": "full",
                "date": "2026-10-17",
                "assessor": "bot",
                "method": "iac",
                "inputs": [{"kind": "iac", "path": "main.tf", "note": "ok"}],
            },
            "inventory": {"resources": 1, "files": 1},
            "findings": [
                {
                    "id": "I-001",
                    "rule": "SEC-001",
                    "category": category,
                    "provider": "aws",
                    "severity": "High",
                    "confidence": "Confirmed",
                    "title": "Valid title",
                    "location": "main.tf:1",
                    "resources": ["aws_db_instance.main"],
                    "impact": "Impact text",
                    "fix": "Rotate",
                    "controls": ["IAM boundary"],
                    "validation": {"verdict": "Unverified", "evidence": ""},
                    "references": [
                        {
                            "title": "Ref",
                            "url": "https://example.com/a(b)c",
                        }
                    ],
                }
            ],
            "attack_paths": [
                {
                    "id": "AP-01",
                    "entry": "internet",
                    "target": "aws_db_instance.main",
                    "status": "open",
                    "edges": ["internet -> aws_db_instance.main (main.tf:1)"],
                    "findings": ["I-001"],
                }
            ],
            "perspectives": [],
            "checked_ok": [],
            "decisions": [],
            "limitations": [],
            "next_steps": [],
        }
        # Compliant baseline document passes both findings.payload_problems and render.validate.
        self.assertEqual(findings.payload_problems(base_doc, "findings.json"), [])
        render.validate(base_doc)

        # HTML injection in meta.project, finding.controls, or finding.location is caught by findings.payload_problems.
        html_doc = json.loads(json.dumps(base_doc))
        html_doc["meta"]["project"] = "demo <svg onload=alert(1)>"
        html_doc["findings"][0]["controls"] = ["<script>alert(1)</script>"]
        html_doc["findings"][0]["location"] = "dir/<img src=x onerror=alert(1)>/main.tf:1"
        probs = findings.payload_problems(html_doc, "findings.json")
        self.assertEqual(len(probs), 3)

        # P3 negative check: credential shape in location/controls must be refused by credential_problems and NEVER echoed.
        cred_doc = json.loads(json.dumps(base_doc))
        cred_doc["findings"][0]["controls"] = [f"ctrl {fake_aws}"]
        cred_doc["findings"][0]["location"] = f"dir_{fake_aws}/main.tf:1"
        cred_probs = findings.credential_problems(cred_doc, "findings.json")
        self.assertTrue(cred_probs)
        self.assertNotIn(fake_aws, "\n".join(cred_probs))

        # Credential in a schema error message must be scrubbed (P3 negative check).
        bad_doc = json.loads(json.dumps(base_doc))
        bad_doc["findings"][0][f"unknown_{fake_aws}"] = "val"
        with self.assertRaises(render.SchemaError) as ctx:
            render.validate(bad_doc)
        self.assertNotIn(fake_aws, str(ctx.exception))
        self.assertIn("[REDACTED]", str(ctx.exception))

        # Line breaks in location, meta.*, controls.*, attack_paths.entry/target, or unbalanced url parens rejected.
        for mutator in (
            lambda d: d["findings"][0].__setitem__("location", "main.tf:1\n## Injected"),
            lambda d: d["meta"].__setitem__("project", "proj\n| table | break |"),
            lambda d: d["findings"][0].__setitem__("controls", ["line1\r\nline2"]),
            lambda d: d["attack_paths"][0].__setitem__("entry", "internet\n### Heading"),
            lambda d: d["findings"][0]["references"][0].__setitem__("url", "https://example.com/foo)bar"),
        ):
            mut_doc = json.loads(json.dumps(base_doc))
            mutator(mut_doc)
            with self.assertRaises(render.SchemaError):
                render.validate(mut_doc)

        # U+2028 / U+2029 escaped in dashboard JSON script block and normalized in Markdown.
        sep_doc = json.loads(json.dumps(base_doc))
        sep_doc["findings"][0]["detail"] = "line\u2028sep\u2029end"
        dash_html = render.render_dashboard(sep_doc, render.LABELS["en"], "en", {})
        md_script = dash_html.split('<script type="application/json" id="md">', 1)[1].split("</script>", 1)[0]
        self.assertNotIn("\u2028", md_script)
        self.assertNotIn("\u2029", md_script)
        self.assertIn("\\u2028", md_script)
        self.assertIn("try{", render.DASH_JS.replace(" ", ""))

        md_code = render._md_code_span("a\nb\u2028c")
        self.assertNotIn("\n", md_code)
        self.assertNotIn("\u2028", md_code)

    def test_render_hcl_and_template_evidence_redaction_and_attach_sources_guards(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            s_paired = _dyn_val("tg_paired", "s1")
            paired_hcl = root / "paired.hcl"
            paired_hcl.write_text(
                f'resource "custom" "x" {{\n  parameter_key = "db_password"\n  parameter_value = "{s_paired}"\n}}\n',
                encoding="utf-8",
            )
            self.assertIsNone(excerpts.source_lines(paired_hcl))

            # Non-literal output/locals references (var.x -> UNKNOWN) must NOT suppress source excerpts.
            ref_tf = root / "outputs.tf"
            ref_tf.write_text(
                'output "db_password" {\n  value = var.db_password\n}\n'
                'locals {\n  api_token = var.api_token\n}\n',
                encoding="utf-8",
            )
            ref_lines = excerpts.source_lines(ref_tf)
            self.assertIsNotNone(ref_lines)
            self.assertIn("var.db_password", "\n".join(ref_lines))

            # Literal secret in output or locals in .tf must be detected by hcl_has_paired_secret.
            lit_tf = root / "lit_outputs.tf"
            lit_tf.write_text(
                f'output "db_password" {{\n  value = "{_dyn_val("out_lit", "s2")}"\n}}\n',
                encoding="utf-8",
            )
            self.assertIsNone(excerpts.source_lines(lit_tf))

            s_tg = _dyn_val("tg_direct", "s3")
            hcl_path = root / "terragrunt.hcl"
            hcl_path.write_text(
                f'inputs = {{\n  db_password = "{s_tg}"\n}}\n',
                encoding="utf-8",
            )
            s_cfn = _dyn_val("cfn_tpl", "s4")
            tpl_path = root / "stack.template"
            tpl_path.write_text(
                "AWSTemplateFormatVersion: '2010-09-09'\n"
                "Resources:\n"
                "  Db:\n"
                "    Type: AWS::RDS::DBInstance\n"
                "    Properties:\n"
                f'      MasterUserPassword: "{s_cfn}"\n',
                encoding="utf-8",
            )
            hcl_lines = excerpts.source_lines(hcl_path)
            self.assertIsNotNone(hcl_lines)
            self.assertNotIn(s_tg, "\n".join(hcl_lines))

            tpl_lines = excerpts.source_lines(tpl_path)
            self.assertIsNotNone(tpl_lines)
            self.assertNotIn(s_cfn, "\n".join(tpl_lines))

            # attach_sources must reject symlinked parent dirs and SKIP_DIRS (.terraform, .git).
            outside_dir = root / "outside"
            outside_dir.mkdir()
            secret_outside = _dyn_val("outside", "s5")
            (outside_dir / "main.tf").write_text(f'# {secret_outside}\nresource "aws_s3_bucket" "b" {{}}\n', encoding="utf-8")

            repo = root / "repo"
            repo.mkdir()
            os.symlink(outside_dir, repo / "linked_sub")
            tf_cache = repo / ".terraform"
            tf_cache.mkdir()
            (tf_cache / "cached.tf").write_text(f'# {secret_outside}\n', encoding="utf-8")

            data = {
                "findings": [
                    {"id": "I-001", "rule": "AWS-S3-001", "location": "linked_sub/main.tf:1"},
                    {"id": "I-002", "rule": "AWS-S3-001", "location": ".terraform/cached.tf:1"},
                ]
            }
            sources = excerpts.attach_sources(data, repo)
            self.assertEqual(sources, {})

            # output_dir_problem must reject symlinked --out and symlinked parent of --out.
            self.assertIsNotNone(render.output_dir_problem(repo / "linked_sub" / "report_out", repo))

    def test_iac_scan_iam_wildcard_notaction_condition_and_compliant_counterparts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "iam.tf").write_text(
                """
resource "aws_iam_role" "cross_ifexists" {
  name = "cross-ifexists"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { AWS = "*" },
      Action = "sts:AssumeRole",
      Condition = {
        StringEqualsIfExists = {
          "sts:ExternalId" = "ext-123"
        }
      }
    }]
  })
}

resource "aws_iam_role" "cross_wildcard_ip" {
  name = "cross-wildcard-ip"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { AWS = "*" },
      Action = "sts:AssumeRole",
      Condition = {
        IpAddress = {
          "aws:SourceIp" = "0.0.0.0/0"
        }
      }
    }]
  })
}

resource "aws_iam_role" "cross_compliant" {
  name = "cross-compliant"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { AWS = "*" },
      Action = "sts:AssumeRole",
      Condition = {
        StringEquals = {
          "aws:PrincipalOrgID" = "o-exampleorgid"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "multi_service" {
  name = "multi"
  role = aws_iam_role.cross_compliant.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Action = ["s3:*", "ec2:*", "iam:PassRole"],
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy" "benign_telemetry" {
  name = "benign-telemetry"
  role = aws_iam_role.cross_compliant.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Action = ["logs:*", "xray:*"],
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy" "not_resource_admin" {
  name = "not_resource_admin"
  role = aws_iam_role.cross_compliant.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Action = "*",
      NotResource = "arn:aws:s3:::audit-bucket/*"
    }]
  })
}

resource "aws_iam_role_policy" "not_action_admin" {
  name = "not_action_admin"
  role = aws_iam_role.cross_compliant.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      NotAction = ["cloudtrail:DeleteTrail"],
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy" "not_action_scoped" {
  name = "not_action_scoped"
  role = aws_iam_role.cross_compliant.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      NotAction = ["iam:*", "organizations:*"],
      Resource = "arn:aws:s3:::my-app-bucket/*"
    }]
  })
}

resource "aws_iam_role" "gh_oidc_forany_eq" {
  name = "gh-oidc-forany-eq"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Federated = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" },
      Action = "sts:AssumeRoleWithWebIdentity",
      Condition = {
        "ForAnyValue:StringEquals" = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub" = "repo:org/app:ref:refs/heads/main"
        }
      }
    }]
  })
}

resource "aws_iam_role" "gh_oidc_compliant" {
  name = "gh-oidc-compliant"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Federated = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" },
      Action = "sts:AssumeRoleWithWebIdentity",
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub" = "repo:org/app:ref:refs/heads/main"
        }
      }
    }]
  })
}
""",
                encoding="utf-8",
            )
            scan = iac_scan.run(root)
            by_rule = {}
            for h in scan.hits:
                by_rule.setdefault(h["rule"], set()).add(h["address"])

            self.assertIn("AWS-IAM-001", by_rule)
            self.assertIn("aws_iam_role_policy.multi_service", by_rule["AWS-IAM-001"])
            self.assertIn("aws_iam_role_policy.not_resource_admin", by_rule["AWS-IAM-001"])
            self.assertIn("aws_iam_role_policy.not_action_admin", by_rule["AWS-IAM-001"])
            # Compliant policies must NOT trigger AWS-IAM-001 (AC-4).
            self.assertNotIn("aws_iam_role_policy.benign_telemetry", by_rule["AWS-IAM-001"])
            self.assertNotIn("aws_iam_role_policy.not_action_scoped", by_rule["AWS-IAM-001"])

            # AWS-IAM-002 must still fire when iam:PassRole is combined with multi-service wildcards.
            self.assertIn("AWS-IAM-002", by_rule)
            self.assertIn("aws_iam_role_policy.multi_service", by_rule["AWS-IAM-002"])

            self.assertIn("AWS-IAM-003", by_rule)
            self.assertIn("aws_iam_role.cross_ifexists", by_rule["AWS-IAM-003"])
            self.assertIn("aws_iam_role.cross_wildcard_ip", by_rule["AWS-IAM-003"])
            self.assertNotIn("aws_iam_role.cross_compliant", by_rule["AWS-IAM-003"])

            self.assertIn("AWS-IAM-004", by_rule)
            self.assertIn("aws_iam_role.gh_oidc_forany_eq", by_rule["AWS-IAM-004"])
            self.assertNotIn("aws_iam_role.gh_oidc_compliant", by_rule["AWS-IAM-004"])

    def test_iac_scan_gcp_k8s_cfn_hcl_locals_and_snapshot_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            snap_dir = root / "snapshots"
            snap_dir.mkdir()

            s_cfn_passphrase = _dyn_val("passphrase_val", "c1")
            s_local_sec = _dyn_val("local_sec", "c2")
            s_inline_var = _dyn_val("inline_var", "c3")
            s_snap_env = _dyn_val("snap_lambda_sec", "c4")
            fake_aws_dir = "AKIA" + "Q" * 16

            (repo / "gcp.tf").write_text(
                f"""
locals {{ db_password = "{s_local_sec}" }}
variable "api_token" {{ default = "{s_inline_var}" }}
variable "safe_empty" {{ default = "" }}

resource "google_bigquery_dataset" "public_ds" {{
  dataset_id = "ds"
  access {{
    role          = "READER"
    special_group = "allAuthenticatedUsers"
  }}
}}

resource "google_bigquery_dataset" "private_ds" {{
  dataset_id = "priv_ds"
  access {{
    role          = "READER"
    special_group = "projectReaders"
  }}
}}

resource "google_project_iam_member" "foreach_pub" {{
  for_each = toset(["allUsers"])
  project  = "my-proj"
  role     = "roles/viewer"
  member   = each.value
}}

resource "google_project_iam_member" "foreach_priv" {{
  for_each = toset(["user:alice@example.com"])
  project  = "my-proj"
  role     = "roles/viewer"
  member   = each.value
}}

resource "google_iam_workload_identity_pool_provider" "unscoped" {{
  workload_identity_pool_id          = "pool"
  workload_identity_pool_provider_id = "gh"
  oidc {{
    issuer_uri = "https://token.actions.githubusercontent.com"
  }}
}}

resource "google_iam_workload_identity_pool_provider" "scoped" {{
  workload_identity_pool_id          = "pool"
  workload_identity_pool_provider_id = "gh-scoped"
  attribute_condition                = "assertion.repository_owner == 'my-org'"
  oidc {{
    issuer_uri = "https://token.actions.githubusercontent.com"
  }}
}}
""",
                encoding="utf-8",
            )
            (repo / "stack.template").write_text(
                f"""
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  SigningPassphrase:
    Type: String
    NoEcho: true
    Default: "{s_cfn_passphrase}"
  PlaintextSsmPassword:
    Type: String
    Default: "{{{{resolve:ssm:/app/db/password:1}}}}"
  VaultedSecretPassword:
    Type: String
    Default: "{{{{resolve:secretsmanager:prod/db:SecretString:password}}}}"
  SecureSsmPassword:
    Type: String
    Default: "{{{{resolve:ssm-secure:/app/db/password:1}}}}"
Resources:
  Dummy:
    Type: AWS::S3::Bucket
""",
                encoding="utf-8",
            )
            (repo / "k8s.yaml").write_text(
                """
apiVersion: v1
kind: ServiceAccount
metadata:
  name: mount-sa
  namespace: prod
automountServiceAccountToken: true
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: no-mount-sa
  namespace: prod
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: safe-with-sa
  namespace: prod
spec:
  template:
    spec:
      serviceAccountName: no-mount-sa
      containers:
        - name: app
          image: nginx:1.25
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: default-token-mounted
  namespace: prod
spec:
  template:
    spec:
      serviceAccountName: mount-sa
      containers:
        - name: app
          image: nginx:1.25
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: empty-cron
spec:
  jobTemplate:
    spec: {}
---
apiVersion: v1
kind: Pod
metadata:
  name: null-container-pod
spec:
  containers:
    - null
    - name: app
      image: nginx:1.25
""",
                encoding="utf-8",
            )
            # Resource with credential-shaped name to verify P3 non-echo in iac_scan.printable(report).
            (repo / "named.tf").write_text(
                f'resource "aws_s3_bucket" "b_{fake_aws_dir}" {{\n  acl = "public-read"\n}}\n',
                encoding="utf-8",
            )

            # Snapshot export with Lambda environment secret.
            (snap_dir / "lambda.json").write_text(
                json.dumps(
                    {
                        "Functions": [
                            {
                                "FunctionName": "my-fn",
                                "Environment": {"Variables": {"DB_PASSWORD": s_snap_env}},
                            }
                        ]
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            scan = iac_scan.run(repo, snapshots=[snap_dir])
            by_rule = {}
            for h in scan.hits:
                by_rule.setdefault(h["rule"], set()).add(h["address"])

            self.assertIn("google_bigquery_dataset.public_ds", by_rule.get("GCP-GCS-002", set()))
            self.assertNotIn("google_bigquery_dataset.private_ds", by_rule.get("GCP-GCS-002", set()))

            self.assertIn("google_project_iam_member.foreach_pub", by_rule.get("GCP-IAM-001", set()))
            self.assertNotIn("google_project_iam_member.foreach_priv", by_rule.get("GCP-IAM-001", set()))

            self.assertIn("google_iam_workload_identity_pool_provider.unscoped", by_rule.get("GCP-WIF-001", set()))
            self.assertNotIn("google_iam_workload_identity_pool_provider.scoped", by_rule.get("GCP-WIF-001", set()))

            # CFN Parameter Default checks: SigningPassphrase and PlaintextSsmPassword flagged;
            # VaultedSecretPassword and SecureSsmPassword exempted.
            sec_hits = [h for h in scan.hits if h["rule"] == "SEC-001"]
            sec_details = "\n".join(h["detail"] for h in sec_hits)
            self.assertIn("literal default for parameter SigningPassphrase", sec_details)
            self.assertIn("literal default for parameter PlaintextSsmPassword", sec_details)
            self.assertNotIn("VaultedSecretPassword", sec_details)
            self.assertNotIn("SecureSsmPassword", sec_details)

            # HCL inline locals and inline variable default flagged; safe_empty not flagged.
            self.assertIn("literal value assigned to db_password", sec_details)
            self.assertIn("literal default for variable api_token", sec_details)
            self.assertNotIn("safe_empty", sec_details)

            # Snapshot secret flagged.
            self.assertTrue(any("@snapshots/" in h["file"] and h["rule"] == "SEC-001" for h in sec_hits))

            # K8S-001: Deployment referencing ServiceAccount with automountServiceAccountToken: true is flagged;
            # Deployment referencing ServiceAccount with automountServiceAccountToken: false is exempt.
            self.assertIn("k8s:Deployment/prod/default-token-mounted", by_rule.get("K8S-001", set()))
            self.assertNotIn("k8s:Deployment/prod/safe-with-sa", by_rule.get("K8S-001", set()))

            # P3 negative check: iac_scan.printable(iac_scan.report(...)) must never echo secret values or credential shapes.
            built_findings = iac_scan.build_findings(scan.hits)
            rep_text = json.dumps(iac_scan.printable(iac_scan.report(scan, repo, "", built_findings)))
            for secret in (s_cfn_passphrase, s_local_sec, s_inline_var, s_snap_env, fake_aws_dir):
                self.assertNotIn(secret, rep_text)

    def test_iac_scan_resilience_huge_int_and_merge_into_and_cli_guards(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            huge_digits = "9" * 5000
            deep_hcl = "locals {\n  x = " + ("{" * 90) + huge_digits + ("}" * 90) + "\n}\n"
            (root / "deep.tf").write_text(deep_hcl, encoding="utf-8")
            scan = iac_scan.run(root)
            self.assertIsInstance(scan.hits, list)

            dup_json = root / "dup.json"
            dup_json.write_text('{"schema_version": 1, "schema_version": 2}', encoding="utf-8")
            with self.assertRaises(ValueError):
                iac_scan.merge_into(dup_json, [], {"resources": 0, "files": 0}, None)

            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = iac_scan.main([str(root), "--out", str(root)])
            self.assertEqual(rc, 2)

            # Symlinked parent directory for --out must also be rejected with exit code 2.
            real_out = root / "real_out"
            real_out.mkdir()
            link_out = root / "link_out"
            os.symlink(real_out, link_out)
            out2, err2 = io.StringIO(), io.StringIO()
            with redirect_stdout(out2), redirect_stderr(err2):
                rc2 = iac_scan.main([str(root), "--out", str(link_out / "iac.json")])
            self.assertEqual(rc2, 2)


if __name__ == "__main__":
    unittest.main()
