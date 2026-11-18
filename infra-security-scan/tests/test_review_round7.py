"""Regressions for the seventh review: report safety, schema and contract."""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-security-scan" / "scripts"))
import findings  # noqa: E402
import iac_scan  # noqa: E402
import redaction  # noqa: E402
import excerpts  # noqa: E402
import render  # noqa: E402

from test_output_redaction import OutputTest, finding  # noqa: E402

SAMPLE = REPO / "examples" / "findings.sample.json"


def quiet(fn, *args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = fn(*args)
    return code, out.getvalue(), err.getvalue()


class ExcerptLeakTest(OutputTest):
    def assert_hidden(self, name, text, line, value):
        self.write(name, text)
        record = self.record(f"{name}:{line}")
        self.assertEqual(excerpts.attach_sources(record, self.repo), {})
        for page in self.pages(record):
            self.assertNotIn(value, page)

    def test_hcl_name_value_pairs_hide_the_file(self):
        value = "synthetic-" + "env-value"
        self.assert_hidden("env.tf", (
            'resource "aws_ecs_task_definition" "t" {\n'
            '  container_definitions = jsonencode([{\n'
            '    environment = [\n'
            '      {\n        name  = "DB_PASSWORD"\n'
            f'        value = "{value}"\n      }}\n'
            '    ]\n  }])\n}\n'), 1, value)

    def test_kubernetes_provider_env_block_hides_the_file(self):
        value = "synthetic-" + "block-value"
        self.assert_hidden("k8s.tf", (
            'resource "kubernetes_deployment" "d" {\n'
            '  env {\n    name  = "STRIPE_SECRET"\n'
            f'    value = "{value}"\n  }}\n}}\n'), 1, value)

    def test_secret_named_variable_default_hides_the_file(self):
        value = "synthetic-" + "default-value"
        self.assert_hidden("vars.tf", (
            'variable "db_password" {\n'
            f'  default = "{value}"\n}}\n'
            'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'), 4, value)

    def test_numeric_secret_named_variable_keeps_the_excerpt(self):
        self.write("kms.tf", 'variable "secret_recovery_window_in_days" {\n  default = 7\n}\n'
                             'resource "x" "y" {\n  a = 1\n}\n')
        self.assertIn("F-001", excerpts.attach_sources(self.record("kms.tf:4"), self.repo))

    def test_public_name_value_pairs_keep_the_excerpt(self):
        self.write("tags.tf", 'resource "x" "y" {\n  env {\n    name  = "REGION"\n'
                              '    value = "eu-west-1"\n  }\n}\n')
        self.assertIn("F-001", excerpts.attach_sources(self.record("tags.tf:1"), self.repo))

    def test_cloudformation_capitalized_name_value_hides_the_file(self):
        value = "synthetic-" + "cfn-value"
        doc = {"Resources": {"Task": {"Type": "AWS::ECS::TaskDefinition", "Properties": {
            "ContainerDefinitions": [{"Environment": [{"Name": "DB_PASSWORD", "Value": value}]}]}}}}
        self.assert_hidden("task.json", json.dumps(doc, indent=2), 1, value)

    def test_ssh2_private_key_body_is_redacted(self):
        body = "AAAA" + "synthetic" * 6
        lines = ["deploy_key = <<EOT", "---- BEGIN SSH2 ENCRYPTED " + "PRIVATE KEY ----", body,
                 "---- END SSH2 ENCRYPTED " + "PRIVATE KEY ----", "EOT"]
        out = redaction.redact_lines(lines)
        self.assertNotIn(body, "\n".join(out))

    def test_state_backups_dotenv_and_ssh_keys_are_never_read(self):
        value = "synthetic-" + "file-value"
        for name in ("terraform.tfstate.1700000000.backup", ".env.production",
                     ".ssh/id_ed25519", "config/kubeconfig"):
            with self.subTest(name=name):
                self.write(name, f"result = \"{value}\"\nother = 1\n")
                self.assertEqual(excerpts.attach_sources(self.record(f"{name}:1"), self.repo), {})


class OutputPathTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        (self.repo / "infra").mkdir(parents=True)
        (self.repo / "infra" / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n', encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_render_refuses_output_inside_the_repository(self):
        code, _, err = quiet(render.main, [str(SAMPLE), "--out", str(self.repo / "report"),
                                           "--repo", str(self.repo), "--no-pdf"])
        self.assertEqual(code, 2)
        self.assertIn("inside the assessed repository", err)
        self.assertFalse((self.repo / "report").exists())

    def test_render_refuses_to_write_through_a_symlink(self):
        out, outside = self.root / "out", self.root / "outside.html"
        out.mkdir()
        outside.write_text("keep", encoding="utf-8")
        (out / "dashboard.html").symlink_to(outside)
        code, _, err = quiet(render.main, [str(SAMPLE), "--out", str(out), "--no-pdf"])
        self.assertEqual(code, 2)
        self.assertEqual(outside.read_text(encoding="utf-8"), "keep")

    def test_scan_refuses_output_inside_the_repository(self):
        for option in ("--out", "--into"):
            with self.subTest(option=option):
                target = self.repo / "infra" / "iac.json"
                code, _, err = quiet(iac_scan.main, [str(self.repo), option, str(target)])
                self.assertEqual(code, 2)
                self.assertIn("inside the scanned repository", err)
                self.assertFalse(target.exists())

    def test_scan_refuses_output_inside_a_snapshots_directory(self):
        exports = self.root / "exports"
        exports.mkdir()
        for option in ("--out", "--into"):
            with self.subTest(option=option):
                target = exports / "run" / "iac.json"
                code, _, err = quiet(iac_scan.main, [str(self.repo), "--snapshots", str(exports), option, str(target)])
                self.assertEqual(code, 2)
                self.assertIn("inside a --snapshots directory", err)
                self.assertFalse(target.exists())

    def test_merge_keeps_the_record_mode(self):
        record = self.root / "findings.json"
        record.write_text(json.dumps(render.empty_record()), encoding="utf-8")
        os.chmod(record, 0o644)
        fragment = self.root / "f.json"
        fragment.write_text(json.dumps({"limitations": ["static"]}), encoding="utf-8")
        code, _, err = quiet(findings.main, ["merge", str(record), str(fragment)])
        self.assertEqual(code, 0, err)
        self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o644)

    def test_merge_into_a_missing_directory_is_exit_2(self):
        fragment = self.root / "f.json"
        fragment.write_text(json.dumps({"limitations": ["static"]}), encoding="utf-8")
        code, _, err = quiet(findings.main, ["merge", str(self.root / "missing" / "findings.json"),
                                             str(fragment)])
        self.assertEqual(code, 2)
        self.assertNotIn("Traceback", err)


class ContrastProseTest(unittest.TestCase):
    def test_contrast_is_checked_for_payloads(self):
        f = finding("main.tf:1")
        f["contrast"] = "metadata at 169.254.169.254"
        problems = findings.fragment_problems({"findings": [f]}, "fragment", render.empty_record())
        self.assertTrue(any("F-001.contrast" in p for p in problems), problems)


class SchemaHardeningTest(unittest.TestCase):
    def sample(self):
        return json.loads(SAMPLE.read_text(encoding="utf-8"))

    def problems(self, data):
        try:
            render.validate(data)
        except render.SchemaError as e:
            return e.problems
        return []

    def test_sample_is_valid(self):
        self.assertEqual(self.problems(self.sample()), [])

    def test_unhashable_values_are_problems_not_crashes(self):
        cases = [
            lambda d: d["findings"][0].__setitem__("id", ["F-001"]),
            lambda d: d["findings"][0].__setitem__("attack_paths", [["AP-01"]]),
            lambda d: d["attack_paths"][0]["findings"].append({"id": "F-001"}),
            lambda d: d["perspectives"].append({"name": ["Kubernetes"], "status": "Applied"}),
        ]
        for n, change in enumerate(cases):
            with self.subTest(case=n):
                data = self.sample()
                change(data)
                self.assertTrue(self.problems(data))

    def test_strict_scalars(self):
        cases = [
            lambda d: d.__setitem__("schema_version", True),
            lambda d: d.__setitem__("schema_version", 1.0),
            lambda d: d["meta"].__setitem__("date", "2026-13-45"),
            lambda d: d["meta"].__setitem__("date", "2026-10-09\n"),
            lambda d: d["findings"][0].__setitem__("location", "a.tf:10-5"),
            lambda d: d["findings"][0].__setitem__("location", "a.tf:0"),
            lambda d: d["findings"][0].__setitem__("title", "two\nlines"),
            lambda d: d["findings"][0].__setitem__("cwe", "see notes"),
            lambda d: d["findings"][0].__setitem__("references", [{"url": "https://example.com/"}]),
            lambda d: d["findings"][5].__setitem__("id", "F-0001"),
            lambda d: d["findings"][0].pop("contrast"),
            lambda d: d["findings"][0].__setitem__("contrats", "typo"),
            lambda d: d["meta"].__setitem__("owner", "x"),
            lambda d: d["attack_paths"][0].__setitem__("severity", "High"),
            lambda d: d["perspectives"][0].__setitem__("steps", "NE1"),
        ]
        for n, change in enumerate(cases):
            with self.subTest(case=n):
                data = self.sample()
                change(data)
                self.assertTrue(self.problems(data))

    def test_contract_check_survives_a_string_validation(self):
        import contract_check
        data = self.sample()
        data["findings"][7]["validation"] = "Valid"
        with tempfile.TemporaryDirectory() as tmp:
            problems = contract_check.check(data, tmp, pdf=False)
        self.assertTrue(problems)


if __name__ == "__main__":
    unittest.main()
