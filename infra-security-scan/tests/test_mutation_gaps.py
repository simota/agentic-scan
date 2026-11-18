"""Behaviour that mutation testing showed no test pinned: excerpt redaction of
multi-line and less common forms, rule recall per alternative, and record gates.
Each case names what a regression would leak or miss."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-security-scan" / "scripts"))
import contract_check  # noqa: E402
import findings  # noqa: E402
import iac_scan  # noqa: E402
import redaction  # noqa: E402
import excerpts  # noqa: E402
import render  # noqa: E402

MARK = "Zq" + "x9" * 3 + "Wp"  # low entropy: only the structural rules can hide it

LEAKS = {
    # Short secret spellings (DB_PASS, admin_pw) across lines.
    "list.tf": f'locals {{\n  DB_PASS = [\n    "{MARK}",\n  ]\n}}\n',
    "jsonencode.tf": f'locals {{\n  admin_pw = jsonencode({{\n    a = "{MARK}"\n  }})\n}}\n',
    "heredoc.tf": f'locals {{\n  admin_pw = <<EOF\n{{"a": "{MARK}"}}\nEOF\n}}\n',
    "indented_heredoc.tf": f'locals {{\n  DB_PASS = <<-EOF\n    {MARK}\n    EOF\n}}\n',
    "token_list.tf": f'locals {{\n  token = [\n    "{MARK}",\n  ]\n}}\n',
    "nested.json": f'{{\n  "DB_PASS": {{\n    "a": "{MARK}"\n  }}\n}}\n',
    "split.json": f'{{\n  "DB_PASS":\n    "{MARK}"\n}}\n',
    "split_key.json": f'{{\n  "password"\n  :\n  "{MARK}"\n}}\n',
    "seq.yaml": f"DB_PASS:\n  - {MARK}\n",
    "block.yaml": f"a:\n  DB_PASS: |\n    {MARK}\n",
    # Container commands.
    "redis.tf": f'locals {{\n  cmd = "redis-cli -a {MARK}"\n}}\n',
    "redis.yaml": f'command: ["redis-cli", "-h", "cache", "-a", "{MARK}", "ping"]\n',
    "flags.yaml": f"command:\n- --password\n- {MARK}\n",
    "ecs.json": json.dumps({"Command": ["--db-password", MARK]}, indent=1),
    "psql.json": json.dumps({"command": ["sh", "-c", "psql", "-p" + MARK]}, indent=1),
    # Name/value pairs and parameters.
    "env.yaml": f"env:\n- name: DB_PASS\n  value: {MARK}\n",
    "ecs_env.json": json.dumps({"Environment": [{"Name": "DB_PASS", "Value": MARK}]}, indent=1),
    "tags.json": json.dumps({"Tags": [{"Key": "db_password", "Value": MARK}]}, indent=1),
    "plan.json": json.dumps({"variables": {"admin_pw": {"value": MARK}}}, indent=1),
    "noecho.yaml": f"Parameters:\n  Seed:\n    Type: String\n    NoEcho: true\n    Default: {MARK}\n",
    "noecho.json": json.dumps({"Parameters": {"Seed": {"Type": "String", "NoEcho": "true", "Default": MARK}}},
                              indent=1),
    "sub.json": json.dumps({"Parameters": {"Seed": {"Type": "String", "Default": MARK}}, "Resources": {"Db": {
        "Type": "AWS::RDS::DBInstance", "Properties": {"MasterUserPassword": {"Fn::Sub": "${Seed}"}}}}},
        indent=1),
    # Terraform declarations that mark a value secret.
    "ssm.tf": f'resource "aws_ssm_parameter" "p" {{\n  type  = "SecureString"\n  value = "{MARK}"\n}}\n',
    "k8s_secret.tf": f'resource "kubernetes_secret" "s" {{\n  data = {{\n    a = "{MARK}"\n  }}\n}}\n',
    "ephemeral.tf": f'variable "db" {{\n  ephemeral = true\n  default   = "{MARK}"\n}}\n',
    "sensitive_fn.tf": f'locals {{\n  a = sensitive("{MARK}")\n}}\n',
    # Single-line forms the scrub layer owns.
    "userinfo.tf": f'locals {{\n  url = "postgres://app:{MARK}@db.internal/app"\n}}\n',
    "scp.tf": f'locals {{\n  src = "{MARK}@github.com:org/repo.git"\n}}\n',
    "discord.tf": f'locals {{\n  hook = "https://discord.com/api/webhooks/1/{MARK}"\n}}\n',
    "startup.tf": f'locals {{\n  startup_script = "echo {MARK}"\n}}\n',
    "comment.tf": f'# token {MARK}\nlocals {{}}\n',
    "shell.tf": f'locals {{\n  run = "app --password {MARK}"\n}}\n',
}
SENSITIVE_FILES = {".pgpass": f"db:5432:app:app:{MARK}\n", "secrets/prod.yaml": f"a: 1\nadmin: {MARK}\n",
                   "certs/tls.pem": f"x\n{MARK}\n", "deploy/.npmrc": f"x={MARK}\n", ".netrc": f"x {MARK}\n",
                   ".docker/config.json": json.dumps({"a": MARK})}


class ExcerptLeakTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_secret_forms_never_reach_an_excerpt(self):
        for name, text in LEAKS.items():
            with self.subTest(name=name):
                lines = excerpts.source_lines(self.write(name, text))
                shown = "\n".join(line for line in lines or [] if isinstance(line, str))
                self.assertNotIn(MARK, shown)

    def test_sensitive_files_are_never_excerpted(self):
        for name, text in SENSITIVE_FILES.items():
            with self.subTest(name=name):
                self.write(name, text)
                record = render.empty_record()
                record["findings"] = [{"id": "F-001", "location": f"{name}:1", "resources": ["x"]}]
                rows = excerpts.attach_sources(record, self.repo).get("F-001") or []
                self.assertNotIn(MARK, "\n".join(str(r) for r in rows))

    def test_ordinary_lines_stay_visible(self):
        for line in ('bypass_mode = "strict"', 'compass = "north"', 'cmd = "redis-cli -h cache ping"',
                     'source = "git::https://example.com/m.git?ref=v1.2.0"'):
            self.assertEqual(redaction.scrub_line(line), line)


def scan_hits(files):
    with tempfile.TemporaryDirectory() as tmp:
        for name, text in files.items():
            path = Path(tmp) / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return {(h["rule"], h["file"]) for h in iac_scan.run(tmp).hits}


def sg(protocol, port):
    return (f'resource "aws_security_group" "s" {{\n  ingress {{\n    protocol = "{protocol}"\n'
            f'    from_port = {port}\n    to_port = {port}\n    cidr_blocks = ["0.0.0.0/0"]\n  }}\n}}\n')


ADMIN_DOC = 'jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })'


class RuleRecallTest(unittest.TestCase):
    """One case per alternative a rule table lists."""

    def expect(self, rule, name, text, hit=True):
        with self.subTest(rule=rule, name=name, text=text[:60]):
            self.assertEqual((rule, name) in scan_hits({name: text}), hit)

    def test_secret_key_spellings(self):
        value = "Zq" + "x9" * 4 + "Wp"
        for key in ("password", "passwd", "secret_key", "auth_token", "api_key", "access_key", "private_key",
                    "db_pass", "admin_pw", "credentials"):
            self.expect("SEC-001", "main.tf", f'locals {{\n  {key} = "{value}"\n}}\n')
        self.expect("SEC-001", "terraform.tfvars", f'db_password = "{value}"\n')
        self.expect("SEC-001", "main.tf", f'locals {{\n  connection_string = "Server=a;Password={value}"\n}}\n')
        self.expect("SEC-001", "main.tf", f'locals {{\n  connection_string = "postgres://admin:{value}@db/prod"\n}}\n')
        for key, text in (("bypass", value), ("credentials", "keys/account.json"),
                          ("connection_string", "Server=a;Database=b")):
            self.expect("SEC-001", "main.tf", f'locals {{\n  {key} = "{text}"\n}}\n', hit=False)
        self.expect("SEC-001", "main.tf", 'resource "x" "y" {\n  password = "plain-word"\n'
                    '  secret_key_ref {\n    name = "s"\n  }\n}\n')

    def test_sensitive_protocols(self):
        self.expect("AWS-NET-001", "main.tf", sg("-1", 0))
        self.expect("AWS-NET-001", "main.tf", sg("6", 22))
        self.expect("AWS-NET-001", "main.tf", sg("all", 0))

    def test_s3_acls_and_blocks(self):
        for acl in ("public-read-write", "authenticated-read"):
            self.expect("AWS-S3-001", "main.tf", f'resource "aws_s3_bucket_acl" "b" {{\n  acl = "{acl}"\n}}\n')
        self.expect("AWS-S3-001", "main.tf", 'resource "aws_s3_bucket_acl" "b" {\n  access_control_policy {\n'
                    '    grant {\n      permission = "READ"\n      grantee {\n        type = "Group"\n'
                    '        uri = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"\n      }\n'
                    '    }\n  }\n}\n')
        self.expect("AWS-S3-002", "main.tf", 'resource "aws_s3_bucket_public_access_block" "b" {\n'
                    '  block_public_acls = true\n  block_public_policy = true\n  ignore_public_acls = true\n'
                    '  restrict_public_buckets = false\n}\n')

    def test_identity_policies(self):
        for type_ in ("aws_iam_user_policy", "aws_iam_group_policy"):
            self.expect("AWS-IAM-001", "main.tf", f'resource "{type_}" "p" {{\n  policy = {ADMIN_DOC}\n}}\n')
        self.expect("AWS-IAM-001", "main.tf", 'resource "aws_iam_user_policy_attachment" "a" {\n'
                    '  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"\n}\n')
        self.expect("AWS-IAM-001", "main.tf", 'resource "aws_iam_role_policy_attachment" "a" {\n'
                    '  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess-Amplify"\n}\n', hit=False)

    def test_open_condition_keys_do_not_narrow(self):
        self.expect("AWS-S3-003", "main.tf", 'resource "aws_s3_bucket_policy" "p" {\n  policy = jsonencode({\n'
                    '    Statement = [{ Effect = "Allow", Principal = "*", Action = "s3:GetObject",\n'
                    '      Resource = "*", Condition = { StringLike = { "aws:UserAgent" = "*" } } }]\n  })\n}\n')

    def test_gcs_public_acls(self):
        self.expect("GCP-GCS-002", "main.tf", 'resource "google_storage_bucket_acl" "a" {\n'
                    '  role_entity = ["READER:allUsers"]\n}\n')
        self.expect("GCP-GCS-002", "main.tf", 'resource "google_storage_object_acl" "a" {\n'
                    '  predefined_acl = "publicRead"\n}\n')
        self.expect("GCP-GCS-002", "main.tf", 'resource "google_bigquery_dataset_access" "a" {\n'
                    '  special_group = "allUsers"\n}\n')
        self.expect("GCP-GCS-002", "main.tf", 'resource "google_bigquery_dataset" "d" {\n  access {\n'
                    '    special_group = "allUsers"\n    role = "READER"\n  }\n}\n')

    def test_other_rules(self):
        self.expect("AWS-CT-001", "main.tf", 'resource "aws_cloudtrail" "t" {\n  is_multi_region_trail = true\n'
                    '  enable_log_file_validation = false\n}\n')
        self.expect("AWS-RDS-001", "main.tf", 'resource "aws_rds_cluster_instance" "i" {\n'
                    '  publicly_accessible = true\n}\n')


def call(main, *argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = main([str(a) for a in argv])
    return code, out.getvalue()


def review(fid="F-001", **extra):
    f = {"id": fid, "title": "t", "severity": "Medium", "confidence": "Suspected",
         "category": "Network exposure", "provider": "aws", "resources": ["aws_s3_bucket.b"],
         "location": "main.tf:1", "actor": "a", "path": "1. edge (main.tf:1)", "contrast": "none",
         "impact": "i", "fix": "f", "regression": "r", "validation": {"verdict": "Likely"}}
    f.update(extra)
    return f


class RecordGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.record = self.root / "findings.json"

    def tearDown(self):
        self.tmp.cleanup()

    def merge(self, fragment):
        path = self.root / "frag.json"
        path.write_text(json.dumps(fragment), encoding="utf-8")
        return call(findings.main, "merge", self.record, path)

    def test_attack_prose_is_refused_in_every_field(self):
        metadata = "169.254." + "169.254"
        for fragment in ({"findings": [review(title=f"SSRF to {metadata}")]},
                         {"findings": [review(impact="read 169.254.170.2/v2/credentials")]},
                         {"findings": [review(fix="javascript:alert(1)")]},
                         {"findings": [review(impact="' union select password from users")]},
                         {"attack_paths": [{"id": "AP-01", "entry": "Internet", "target": metadata,
                                            "status": "open", "edges": ["a (main.tf:1)"]}]},
                         {"attack_paths": [{"id": "AP-01", "entry": "Internet", "target": "t", "status": "open",
                                            "edges": [f"curl http://{metadata}/latest (main.tf:1)"]}]}):
            with self.subTest(fragment=str(fragment)[:70]):
                self.assertEqual(self.merge(fragment)[0], 1)
                self.assertFalse(self.record.exists())

    def test_validate_rejects(self):
        base = render.empty_record()
        base["meta"] = {"project": "p", "scope": "s", "date": "2026-10-09", "assessor": "a"}
        cases = [
            {"findings": [review(validation={"verdict": "Valid"})]},
            {"schema_version": 2},
            {"findings": [review("F-001x")]},
            {"findings": [review("I-001x", rule="AWS-S3-001")]},
            {"findings": [review(references=[{"title": "t", "url": "https:///x"}])]},
        ]
        for change in cases:
            with self.subTest(change=str(change)[:70]):
                with self.assertRaises(render.SchemaError):
                    render.validate({**base, **change})
        for key in ("scope", "date", "assessor"):
            with self.subTest(missing=key):
                meta = {k: v for k, v in base["meta"].items() if k != key}
                with self.assertRaises(render.SchemaError):
                    render.validate({**base, "meta": meta})

    def test_remove_an_attack_path_and_its_links(self):
        self.record.write_text(json.dumps({**render.empty_record(), "findings": [review(attack_paths=["AP-01"])],
                                           "attack_paths": [{"id": "AP-01", "entry": "Internet", "target": "t",
                                                             "status": "open", "edges": ["e (main.tf:1)"],
                                                             "findings": ["F-001"]}]}), encoding="utf-8")
        self.assertEqual(call(findings.main, "remove", self.record, "AP-01")[0], 0)
        data = json.loads(self.record.read_text(encoding="utf-8"))
        self.assertEqual((data["attack_paths"], data["findings"][0]["attack_paths"]), ([], []))

    def test_contract_output_files(self):
        out = self.root / "out"
        out.mkdir()
        (out / "real.html").write_text("<!doctype html><p>x", encoding="utf-8")
        (out / "dashboard.html").symlink_to(out / "real.html")
        self.assertEqual(contract_check.output_problem(out / "dashboard.html"), "is not a regular file")
        (out / "assessment.pdf").write_bytes(b"%PDF-1.4\n%x\n")
        self.assertIsNone(contract_check.output_problem(out / "assessment.pdf"))
        (out / "iac.json").write_text("[]", encoding="utf-8")
        self.assertEqual(contract_check.output_problem(out / "iac.json"), "was not written by iac_scan.py --out")


if __name__ == "__main__":
    unittest.main()
