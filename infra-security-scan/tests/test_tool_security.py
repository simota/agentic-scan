"""The tools themselves under a hostile repository: names shaped like keys,
command-line passwords, hand-made outputs, slow inputs and planted git layouts."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-scan" / "scripts"))
import contract_check  # noqa: E402
import findings  # noqa: E402
import iac_scan  # noqa: E402
import redaction  # noqa: E402
import excerpts  # noqa: E402
import render  # noqa: E402

KEY = "AKIA" + "Q" * 16
PASSWORD = "correct" + "horsebattery"


def call(main, *argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = main([str(a) for a in argv])
    return code, out.getvalue()


class ToolSecurityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.out = self.root / "out"

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_key_shaped_names_are_redacted_and_merges_still_work(self):
        self.write("main.tf", f'resource "aws_security_group" "{KEY}" {{\n  ingress {{\n    from_port = 22\n'
                              '    to_port = 22\n    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')
        self.write(f"ghp_{'Q' * 36}/big.tf", "x" * (iac_scan.MAX_BYTES + 1))
        code, out = call(iac_scan.main, self.repo, "--out", self.out / "iac.json", "--into", self.out / "findings.json")
        self.assertEqual(code, 0, out)
        for name in ("iac.json", "findings.json"):
            text = (self.out / name).read_text(encoding="utf-8")
            self.assertNotIn(KEY, text)
            self.assertNotIn("ghp_" + "Q" * 36, text)
        fragment = self.root / "frag.json"
        fragment.write_text(json.dumps({"limitations": ["No live calls"]}), encoding="utf-8")
        self.assertEqual(call(findings.main, "merge", self.out / "findings.json", fragment)[0], 0)

    def test_command_line_passwords(self):
        for line in (f"curl -u admin:{PASSWORD} https://internal/api", f"curl --user u:{PASSWORD} https://x",
                     f"docker login -u ci -p {PASSWORD} registry", f'command = "docker login reg -p {PASSWORD}"',
                     f"sshpass -p {PASSWORD} ssh host", f"az login -u a -p {PASSWORD}",
                     f"openssl enc -k {PASSWORD} -in f", f"ldapsearch -w {PASSWORD} -D cn=admin"):
            self.assertNotIn(PASSWORD, redaction.scrub_line(line, "yaml"), line)
        for line in ("docker run -p 8080:80 nginx", "curl -u $USER https://x"):
            self.assertEqual(redaction.scrub_line(line, "yaml"), line)

    def test_backslash_continuation_after_a_secret(self):
        lines = redaction.scrub_lines(["export DB_PASSWORD=\\", f"  {PASSWORD}", "echo done"], "text")
        self.assertNotIn(PASSWORD, "\n".join(lines))
        self.assertEqual(lines[2], "echo done")

    def test_contract_rejects_fabricated_baseline_and_credentials(self):
        sample = json.loads((REPO / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
        self.out.mkdir()
        (self.out / "findings.json").write_text(json.dumps(sample), encoding="utf-8")
        self.assertEqual(call(render.main, self.out / "findings.json", "--out", self.out, "--no-pdf")[0], 0)
        (self.out / "iac.json").write_text(json.dumps({"tool": "iac_scan", "findings": []}), encoding="utf-8")
        problems = contract_check.check(sample, self.out, pdf=False)
        self.assertTrue([p for p in problems if p.startswith("I-*: differ from iac.json")], problems)
        sample["checked_ok"].append(f"token {KEY}")
        problems = contract_check.check(sample, self.out, pdf=False)
        self.assertTrue([p for p in problems if "credential-shaped" in p], problems)
        self.assertFalse([p for p in problems if KEY in p])
        (self.out / "iac.json").write_text('{"tool": "iac_scan"}', encoding="utf-8")
        self.assertEqual(contract_check.output_problem(self.out / "iac.json"), "was not written by iac_scan.py --out")

    def test_slow_inputs_stay_bounded(self):
        inner = ",".join(f'"k{i}":{i}' for i in range(100000))
        start = time.monotonic()
        iac_scan.json_key_lines('{"a":' * 900 + "{" + inner + "}" + "}" * 900)
        self.assertLess(time.monotonic() - start, 5)
        self.write("deep.tf", "a {\n" * 300 + "x = 1\n" * 5000 + "}\n" * 300)
        start = time.monotonic()
        self.assertIn("HCL nested too deeply, skipped: deep.tf", iac_scan.run(self.repo).not_run)
        self.assertLess(time.monotonic() - start, 5)

    def test_render_skips_files_the_scanner_skipped(self):
        big = self.write("big.yaml", "a: 1\n" * (iac_scan.MAX_BYTES // 4))
        self.assertIsNone(excerpts.source_lines(big))
        self.write("mod/main.tf", 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n')
        self.write("mod/zz.tf", "# " + "x" * iac_scan.MAX_BYTES)
        self.assertTrue(excerpts.hcl_module_sensitive(self.repo / "mod"))

    def test_planted_bare_repository_is_not_read(self):
        bare = self.repo / "infra"
        (bare / "refs" / "heads").mkdir(parents=True)
        (bare / "objects").mkdir()
        (bare / "HEAD").write_text("ref: refs/heads/main\n")
        (bare / "config").write_text("[core]\n\tbare = true\n")
        (bare / "refs" / "heads" / "main").write_text("deadbeef" * 5 + "\n")
        try:
            subprocess.run(["git", "--version"], capture_output=True, check=True)
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("git not installed")
        self.assertNotEqual(iac_scan.git_commit(bare), "deadbeef" * 5)


if __name__ == "__main__":
    unittest.main()
