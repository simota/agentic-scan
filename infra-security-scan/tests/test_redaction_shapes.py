"""Credential shapes the excerpt and module-source redaction used to miss,
and public evidence it used to hide."""
from pathlib import Path
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

    def test_a_number_under_a_plain_secret_key_stays_hidden(self):
        self.assertNotIn("1234", redaction.redact("  password = 1234"))
        self.assertNotIn("8", redaction.redact("  password_length = 8 # note"))


class ModuleSourceTest(unittest.TestCase):
    def test_password_with_url_delimiters_never_reaches_the_record(self):
        for value in (SECRET + "#x", SECRET + "?x", SECRET + "/x"):
            with self.subTest(value=value):
                safe = redaction.module_source("git::https://deploy:%s@gitlab.example.com/g/m.git?ref=v1" % value)
                self.assertEqual(safe, "git::https://[redacted]@gitlab.example.com/g/m.git?ref=v1")

    def test_host_port_and_path_at_sign_are_not_userinfo(self):
        self.assertEqual(redaction.module_source("https://h.example:443/a@b"), "https://h.example:443/a@b")
        self.assertEqual(redaction.module_source("https://u:1234@h/x"), "https://[redacted]@h/x")


if __name__ == "__main__":
    unittest.main()
