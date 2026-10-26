"""Credential shapes the excerpt and module-source redaction used to miss,
and public evidence it used to hide."""
import base64
from pathlib import Path
import random
import string
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-scan" / "scripts"))
import redaction  # noqa: E402
import render  # noqa: E402

# Below every entropy threshold, so only the shape rules can hide it.
SECRET = "zq" + "vk" + "17" + "mw"


class ExcerptShapeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def excerpt(self, name, text, line):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        record = {"findings": [{"id": "F-001", "location": f"{name}:{line}"}]}
        rows = render.attach_sources(record, self.repo).get("F-001")
        return None if rows is None else "\n".join(text for _, text, _ in rows)

    def assertHidden(self, name, text, line):
        shown = self.excerpt(name, text, line)
        self.assertNotIn(SECRET, shown or "")
        return shown

    def test_go_dsn_password_is_hidden(self):
        shown = self.assertHidden("main.tf", 'locals {\n  MYSQL_DSN = "app:%s@tcp(db:3306)/x"\n  x = 1\n}\n'
                                  % SECRET, 3)
        self.assertIn('"app:[redacted]@tcp(db:3306)/x"', shown)
        self.assertHidden("k8s/d.yaml", 'env:\n  - name: DB_DSN\n    value: "api:%s@tcp(mysql:3306)/api"\n'
                          'securityContext:\n  privileged: true\n' % SECRET, 5)

    def test_oracle_user_slash_password_is_hidden(self):
        shown = self.assertHidden("c.tf", 'locals {\n  url = "jdbc:oracle:thin:scott/%s@db.example.com:1521/ORCL"\n'
                                  '  y = 1\n}\n' % SECRET, 3)
        self.assertIn("scott/[redacted]@db.example.com:1521/ORCL", shown)

    def test_url_password_with_delimiters_is_hidden(self):
        for value in (SECRET + "#2024", SECRET + "?x", SECRET + "/x"):
            with self.subTest(value=value):
                shown = self.assertHidden("a.tf", 'locals {\n  dsn = "postgres://app:%s@db.internal:5432/app"\n'
                                          '  y = 1\n}\n' % value, 3)
                self.assertIn("postgres://[redacted]@db.internal:5432/app", shown)

    def test_signing_key_names_hide_their_values(self):
        for name in ("JWT_SIGNING_KEY", "HMAC_KEY", "SESSION_KEY", "APP_KEY"):
            with self.subTest(name=name):
                self.assertTrue(redaction.is_secret_name(name))
                self.assertHidden("k8s/s.yaml", 'env:\n  - name: %s\n    value: "%s"\n'
                                  'securityContext:\n  privileged: true\n' % (name, SECRET), 5)
                self.assertHidden("main.tf", 'locals {\n  %s = "%s"\n  x = 1\n}\n' % (name.lower(), SECRET), 3)

    def test_public_evidence_stays_readable(self):
        cases = (
            ("cfn/lt.yaml", "MetadataOptions:\n  HttpTokens: optional\n", 2, "HttpTokens: optional"),
            ("cfn/lt.json", '{"MetadataOptions": {\n  "HttpTokens": "optional"\n}}\n', 2, '"HttpTokens": "optional"'),
            ("p.tf", 'resource "aws_iam_account_password_policy" "p" {\n  minimum_password_length = 8\n}\n', 2,
             "minimum_password_length = 8"),
            ("cfn/pool.yaml", "Client:\n  RefreshTokenValidity: 30\n", 2, "RefreshTokenValidity: 30"),
            ("s.tf", 'data "aws_iam_policy_document" "p" {\n  statement {\n    resources = '
             '["arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf"]\n  }\n}\n', 3,
             "secret:prod/db-AbCdEf"),
            ("k8s/i.yaml", "containers:\n  - image: nginx@sha256:%s\n    securityContext:\n"
             "      privileged: true\n" % ("ab" * 32), 4, "image: nginx@sha256:"),
        )
        for name, text, line, kept in cases:
            with self.subTest(name=name):
                self.assertIn(kept, self.excerpt(name, text, line))

    def test_only_the_secrets_manager_prefix_of_an_arn_is_public(self):
        for line in ("DB: arn:aws:rds:us-east-1:111122223333:db:prod;password=%s",
                     'x = "arn:aws:secretsmanager:us-east-1:1:secret:db?token=%s"',
                     '"arn:aws:s3:::b/password=%s"', "arn:aws:s3:::bkt/token:%s"):
            with self.subTest(line=line):
                shown = redaction.scrub_line(redaction.redact(line % SECRET, syntax="yaml"), "yaml")
                self.assertNotIn(SECRET, shown)

    def test_a_literal_read_by_a_secret_attribute_is_hidden(self):
        db = ('resource "aws_db_instance" "d" {\n  publicly_accessible = true\n  password = %s\n}\n')
        same_file = 'variable "db_admin" {\n  default = "%s"\n}\n' % SECRET + db % "var.db_admin"
        self.assertIsNone(self.excerpt("one/main.tf", same_file, 5))
        (self.repo / "two").mkdir()
        (self.repo / "two" / "variables.tf").write_text('variable "db_admin" {\n  default = "%s"\n}\n' % SECRET,
                                                      encoding="utf-8")
        self.assertIsNone(self.excerpt("two/main.tf", db % '"${var.db_admin}"', 2))
        self.assertIsNone(self.excerpt("three/main.tf", 'locals {\n  admin = "%s"\n}\n' % SECRET
                                       + db % "local.admin", 5))
        # Nothing to leak: no default, or the variable feeds a public setting.
        self.assertIn("password = var.db_admin", self.excerpt("four/main.tf", 'variable "db_admin" {}\n'
                                                              + db % "var.db_admin", 3))
        shown = self.excerpt("five/main.tf", 'variable "engine" {\n  default = "postgres"\n}\n'
                             + db.replace("password = %s", "engine = %s") % "var.engine", 5)
        self.assertIn('default = "postgres"', shown)
        # Numbers and collections hold a secret too.
        number = "4193" + "9071"
        for n, (declared, read) in enumerate((
                ('variable "db_admin" {\n  default = %s\n}\n' % number, "var.db_admin"),
                ('locals {\n  pin = %s\n}\n' % number, "local.pin"),
                ('locals {\n  creds = { admin = "%s" }\n}\n' % SECRET, "local.creds.admin"),
                ('variable "cfg" {\n  default = { admin = "%s" }\n}\n' % SECRET, "var.cfg.admin"),
                ('locals {\n  pws = ["%s"]\n}\n' % SECRET, "local.pws[0]"))):
            with self.subTest(read=read):
                self.assertIsNone(self.excerpt(f"six{n}/main.tf", declared + db % read, 5))

    def test_a_path_or_secret_name_read_by_reference_keeps_the_module_readable(self):
        rule = ('resource "aws_security_group_rule" "ssh" {\n  type = "ingress"\n  from_port = 22\n'
                '  to_port = 22\n  cidr_blocks = ["0.0.0.0/0"]\n}\n')
        for n, other in enumerate((
                'variable "credentials_file" {\n  default = "account.json"\n}\n'
                'provider "google" {\n  credentials = file(var.credentials_file)\n}\n',
                'variable "db_secret_name" {\n  default = "prod/db"\n}\n'
                'data "aws_secretsmanager_secret_version" "d" {\n  secret_id = var.db_secret_name\n}\n',
                'variable "pub" {\n  default = "id.pub"\n}\nresource "x" "y" {\n  ssh_key = file(var.pub)\n}\n',
                'variable "n" {\n  default = 16\n}\nresource "random_password" "p" {\n'
                '  password_length = var.n\n}\n')):
            with self.subTest(other=other[:30]):
                (self.repo / f"seven{n}").mkdir()
                (self.repo / f"seven{n}" / "other.tf").write_text(other, encoding="utf-8")
                self.assertIn("0.0.0.0/0", self.excerpt(f"seven{n}/sg.tf", rule, 5) or "")

    def test_a_number_under_a_plain_secret_key_stays_hidden(self):
        self.assertNotIn("1234", redaction.redact("  password = 1234"))
        self.assertNotIn("8", redaction.redact("  password_length = 8 # note"))

    def test_a_number_is_public_only_under_a_setting_name(self):
        number = "4193" + "9071"
        for line in ("ENV MYSQL_ROOT_PASSWORD %s", "MYSQL_ROOT_PASSWORD=%s", "  db_pass: %s"):
            with self.subTest(line=line):
                self.assertNotIn(number, redaction.scrub_line(line % number, "yaml"))
        shown = self.excerpt("Dockerfile", "FROM mysql:8\nENV MYSQL_ROOT_PASSWORD %s\n" % number, 2)
        self.assertNotIn(number, shown or "")
        for kept in ("minimum_password_length = 14", "RefreshTokenValidity: 30", '"MaxPasswordAge": 90,',
                     "password_reuse_prevention = 24"):
            with self.subTest(kept=kept):
                self.assertEqual(redaction.scrub_line(kept, "yaml"), kept)

    def test_a_mixed_case_token_with_underscores_is_judged_by_entropy(self):
        rng = random.Random(7)
        token = "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(24))
        for prefix in ("sk_" + "live_", "npm_", "hf_", ""):
            with self.subTest(prefix=prefix):
                value = prefix + token[:12] + "_" + token[12:]
                self.assertNotIn(token[:12], redaction.scrub_line("# billing key: " + value, "hcl"))
        for kept in ("name = my_bucket_name_for_logs_2024", "env: AWS_DEFAULT_REGION_FOR_STAGING_2",
                     "role = aws_iam_role.Lambda_Exec_Role2.arn", 'name = "EC2_Instance_Profile_v2"',
                     'function_name = "Process_Orders_V2_Handler"'):
            with self.subTest(kept=kept):
                self.assertEqual(redaction.scrub_line(kept, "yaml"), kept)

    def test_a_base64_key_after_an_equals_sign_is_one_token(self):
        # NAME=<key> is judged as one token, exactly as NAME <key> is; before,
        # about a quarter of keys kept runs of eight or more characters.
        rng = random.Random(11)
        for _ in range(200):
            key = base64.b64encode(bytes(rng.randrange(256) for _ in range(32))).decode()
            spaced = redaction.scrub_line("# rotate: ENCRYPTION_KEY " + key, "hcl")
            joined = redaction.scrub_line("# rotate: ENCRYPTION_KEY=" + key, "hcl")
            self.assertEqual(joined, spaced.replace("KEY ", "KEY=", 1), key)


class ModuleSourceTest(unittest.TestCase):
    def test_password_with_url_delimiters_never_reaches_the_record(self):
        for value in (SECRET + "#x", SECRET + "?x", SECRET + "/x", "1234/x", "1234#x"):
            with self.subTest(value=value):
                safe = redaction.module_source("git::https://deploy:%s@gitlab.example.com/g/m.git?ref=v1" % value)
                self.assertEqual(safe, "git::https://[redacted]@gitlab.example.com/g/m.git?ref=v1")

    def test_userinfo_boundaries(self):
        # A port cannot be told from a numeric password: the host is hidden too.
        self.assertEqual(redaction.module_source("https://h.example:443/a@b"), "https://[redacted]@b")
        self.assertEqual(redaction.module_source("https://h.example:443/a"), "https://h.example:443/a")
        self.assertEqual(redaction.module_source("http://[::1]:8080/a@b"), "http://[::1]:8080/a@b")
        self.assertEqual(redaction.module_source("https://u:1234@h/x"), "https://[redacted]@h/x")


if __name__ == "__main__":
    unittest.main()
