"""Findings from a Go service run (with GUARD) and a fresh whole-repo review."""
import io
import json
import re
from pathlib import Path
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_architecture_scan import REPO, SKILL, complete_doc, finding, findings, make_env, render


class RuleStatusTests(unittest.TestCase):
    def test_a_valid_finding_needs_a_violated_rule(self):
        self.assertEqual(findings.ALLOWED_RULE_STATUS["Valid"], ("violated",))
        self.assertIn("partly read", findings.ALLOWED_RULE_STATUS["Likely"])


class FixedCountTests(unittest.TestCase):
    def test_fixed_and_accepted_are_counted_beside_the_assessed_totals(self):
        doc = complete_doc()
        doc["findings"][0]["status"] = "Fixed"
        doc["findings"][1]["status"] = "Accepted"
        counts = findings.template_counts(doc)
        self.assertEqual((counts["n_high"], counts["n_fixed"], counts["n_accepted"]), (1, 1, 1))


class RenumberPathTests(unittest.TestCase):
    def test_a_mistyped_record_path_creates_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "nope" / "a" / "findings.json"
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(findings.main(["renumber", str(target)]), 1)
            self.assertFalse((Path(d) / "nope").exists())


class ArrowTests(unittest.TestCase):
    def test_an_arrow_stays_readable_but_cannot_quote_a_list_item(self):
        self.assertEqual(render.markdown_inline("calls a -> b"), "calls a -> b")
        self.assertEqual(render.markdown_code("a->b"), "<code>a->b</code>")
        self.assertTrue(render.block_safe(render.markdown_inline("> quoted")).startswith("&#62;"))
        self.assertIn("&#92;&#62;", render.markdown_inline("\\>"))
        self.assertIn("&lt;b", render.markdown_inline("<b>x</b>"))


class MakefileDefaultTests(unittest.TestCase):
    def make(self, *args, env=None):
        return subprocess.run(["make", "--no-print-directory", "-f", str(REPO / "Makefile"), *args],
                              env=env or make_env(), capture_output=True, text=True, timeout=60)

    def test_an_empty_host_override_falls_back_to_the_default(self):
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / ".codex").mkdir()
            env = {**make_env(), "HOME": home, "CODEX_HOME": ""}
            result = self.make("status", "AGENT=codex", "SKILLS_DIR=", "PROJECT=", env=env)
        self.assertIn(f"{home}/.codex/skills/architecture-scan", result.stdout)

    def test_an_empty_host_override_on_the_command_line_falls_back_too(self):
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / ".codex").mkdir()
            env = {**make_env(), "HOME": home}
            result = self.make("status", "AGENT=codex", "CODEX_HOME=", "SKILLS_DIR=", "PROJECT=",
                               env=env)
        self.assertIn(f"{home}/.codex/skills/architecture-scan", result.stdout)

    def test_demo_writes_to_a_new_private_directory_by_default(self):
        result = self.make("demo", "DEMO_OUT=")
        self.assertEqual(result.returncode, 0, result.stderr)
        written = Path(result.stdout.split("wrote ", 1)[1].split(" and ", 1)[0]).parent
        try:
            self.assertTrue(written.name.startswith("architecture-scan-demo."))
            self.assertEqual(written.stat().st_mode & 0o077, 0)
        finally:
            for child in written.iterdir():
                child.unlink()
            written.rmdir()


class GuardRecordTests(unittest.TestCase):
    def test_both_documented_guard_fragments_merge_and_pass_check(self):
        text = (SKILL / "reference" / "validation.md").read_text(encoding="utf-8")
        fragments = re.findall(r"`(\{\"findings\": \[\{\"id\": \"A-001\".*?\}\]\})`", text)
        self.assertEqual(len(fragments), 2)
        sample = (REPO / "examples" / "findings.sample.json").read_text(encoding="utf-8")
        for fragment in fragments:
            with self.subTest(fragment=fragment[:40]), tempfile.TemporaryDirectory() as d:
                out = Path(d)
                (out / "findings.json").write_text(sample, encoding="utf-8")
                (out.parent / f"{out.name}.frag.json").write_text(fragment, encoding="utf-8")
                frag = out.parent / f"{out.name}.frag.json"
                try:
                    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        self.assertEqual(findings.main(["merge", str(out / "findings.json"),
                                                        str(frag)]), 0)
                        render.main([str(out / "findings.json"), "--out", str(out)])
                    self.assertEqual(findings.contract_problems(out), [])
                finally:
                    frag.unlink()


class PartialCollisionHintTests(unittest.TestCase):
    def test_the_refusal_says_to_split_the_correction(self):
        doc = {"findings": [finding()]}
        with self.assertRaisesRegex(findings.SchemaError, "separate fragments"):
            findings.merge(doc, {"findings": [{"id": "A-001", "title": "x",
                                               "location": "y.py:1"}]}, "f")


if __name__ == "__main__":
    unittest.main()
