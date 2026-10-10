"""Tests for mutations that previously survived the suite (escaping, guards, contract)."""
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_install import REPO, clean_environment
from test_privacy_scan import complete_doc, finding, findings, render

MARKUP = "<zz>&x"


def every_public_string(doc):
    """Put markup into every free-text field the dashboard shows."""
    doc["meta"].update(project=MARKUP, scope=MARKUP, assessor=MARKUP, method=MARKUP, commit=MARKUP)
    f = doc["findings"][0]
    for key in ("title", "data", "subjects", "flow", "impact", "fix", "guard", "contrast",
                "conditions", "commitment"):
        f[key] = MARKUP
    f["location"] = ["src/<zz>&x.py:1"]
    f["validation"]["evidence"] = MARKUP
    f["validation"]["method"] = "analysed"
    f["analysis"] = {"tool": MARKUP, "command": MARKUP, "result": MARKUP}
    f["references"] = [{"title": MARKUP, "url": "https://example.com/<zz>"}]
    doc["commitments"][0].update(statement=MARKUP, source=MARKUP, family=MARKUP,
                                 status="not checked", reason=MARKUP)
    doc["perspectives"][0]["note"] = MARKUP
    for key in ("checked_ok", "limitations", "decisions", "next_steps"):
        doc[key] = [MARKUP]
    return doc


class HtmlEscapingTests(unittest.TestCase):
    def test_no_field_can_add_markup_to_the_dashboard(self):
        doc = every_public_string(complete_doc())
        findings.validate(doc, complete=True)
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                html = render.render_html(doc, lang)
                self.assertNotIn("<zz>", html)
                self.assertNotIn("&x", html.replace("&amp;x", ""))
                self.assertIn("&lt;zz&gt;&amp;x", html)
                self.assertIn("<title>", html)
                self.assertEqual(html.count("<title>"), 1)


class GuardCoverageTests(unittest.TestCase):
    def test_step_and_conditions_are_checked_for_personal_values(self):
        for key in ("step", "conditions"):
            for value in ("alice@corp.co.jp", "4111 1111 1111 1111"):
                with self.subTest(key=key, value=value), self.assertRaises(findings.SchemaError) as raised:
                    findings.validate({"findings": [finding(**{key: value})]})
                self.assertIn(key, str(raised.exception))

    def test_commit_hashes_are_bounded(self):
        doc = complete_doc()
        doc["meta"]["commit"] = "1" * 64
        findings.validate(doc)
        doc["meta"]["commit"] = "1" * 65
        with self.assertRaises(findings.SchemaError):
            findings.validate(doc)

    def test_three_decoding_rounds_are_applied(self):
        with self.assertRaises(findings.SchemaError):
            findings._no_personal_values("user%252540corp.io", "field")


class ContractCoverageTests(unittest.TestCase):
    def problems(self, doc):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            (out / "findings.json").write_text(json.dumps(doc), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                render.main([str(out / "findings.json"), "--out", str(out)])
            return findings.contract_problems(out)

    def test_empty_limitations_and_checked_ok_fail_the_contract(self):
        for key, message in (("limitations", "limitations:"), ("checked_ok", "checked_ok:")):
            with self.subTest(key=key):
                doc = complete_doc()
                doc[key] = []
                self.assertTrue(any(p.startswith(message) for p in self.problems(doc)))


class MarkdownCoverageTests(unittest.TestCase):
    def test_strikethrough_markers_stay_literal(self):
        self.assertEqual(render.markdown_text("~~x~~"), "\\~\\~x\\~\\~")

    def test_unrecorded_perspectives_still_get_a_row(self):
        doc = complete_doc()
        doc["perspectives"] = doc["perspectives"][:1]
        table = render.render_markdown(doc, "en").split("## Perspective coverage", 1)[1]
        rows = [line for line in table.split("\n## ", 1)[0].splitlines()
                if line.startswith("| ") and not line.startswith("| Perspective")]
        self.assertEqual(len(rows), len(findings.PERSPECTIVES))
        self.assertEqual(sum(" | — | " in row for row in rows), len(findings.PERSPECTIVES) - 1)


@unittest.skipUnless(hasattr(os, "mkfifo"), "needs FIFOs")
class SpecialFileTests(unittest.TestCase):
    def test_render_refuses_to_replace_a_linked_special_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fifo = root / "pipe"
            os.mkfifo(fifo)
            out = root / "out"
            out.mkdir()
            (out / "findings.json").write_text(json.dumps(complete_doc()), encoding="utf-8")
            (out / "report.md").symlink_to(fifo)
            with redirect_stderr(io.StringIO()):
                self.assertEqual(render.main([str(out / "findings.json"), "--out", str(out)]), 1)
            self.assertTrue(fifo.is_fifo())
            self.assertFalse((out / "dashboard.html").exists())


def make(cwd, *args, env=None):
    return subprocess.run(["make", "--no-print-directory", *args], cwd=cwd,
                          env=clean_environment(env), capture_output=True, text=True, timeout=120)


class MakefileCoverageTests(unittest.TestCase):
    def test_missing_hosts_are_skipped_and_nothing_linked_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            status = make(REPO, "status", "AGENT=agy", f"AGY_HOME={missing}", "SKILLS_DIR=", "PROJECT=")
            self.assertEqual(status.returncode, 0, status.stderr)
            self.assertIn("skip", status.stdout)
            linked = make(REPO, "link", "AGENT=agy", f"AGY_HOME={missing}", "SKILLS_DIR=", "PROJECT=")
            self.assertNotEqual(linked.returncode, 0)
            self.assertIn("nothing linked", linked.stderr)
            self.assertFalse(missing.exists())

    def copy(self, root):
        checkout = root / "checkout"
        shutil.copytree(REPO, checkout, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        return checkout

    def test_make_check_passes_on_a_clean_copy_and_catches_broken_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = self.copy(Path(directory))
            env = {**os.environ, "TMPDIR": directory, "PYTHONDONTWRITEBYTECODE": "1"}
            # `-o test` keeps check from running this suite again.
            clean = make(checkout, "-o", "test", "check", env=env)
            self.assertEqual(clean.returncode, 0, clean.stderr)

            sample = checkout / "examples" / "findings.sample.json"
            doc = json.loads(sample.read_text(encoding="utf-8"))
            doc["limitations"] = []
            sample.write_text(json.dumps(doc), encoding="utf-8")
            broken = make(checkout, "-o", "test", "check", env=env)
            self.assertNotEqual(broken.returncode, 0)
            self.assertIn("does not pass the run contract", broken.stderr)

            shutil.copyfile(REPO / "examples" / "findings.sample.json", sample)
            skill = checkout / "skills" / "privacy-scan" / "SKILL.md"
            text = skill.read_text(encoding="utf-8")
            start = text.index("description: ")
            end = text.index("\n", start)
            skill.write_text(text[:start] + "description: " + "x" * 500 + text[end:], encoding="utf-8")
            long = make(checkout, "-o", "test", "check", env=env)
            self.assertNotEqual(long.returncode, 0)
            self.assertIn("description is", long.stderr)


if __name__ == "__main__":
    unittest.main()
