"""Bypasses of the inline-text, link, heading and contract hardening."""
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_architecture_scan import REPO, SKILL, complete_doc, finding, findings, render


class InlineTextTests(unittest.TestCase):
    def test_links_and_images_in_text_fields_stay_literal(self):
        for value in ("[click](javascript:alert(1))", "![x](https://evil.example/t.png)",
                      "[a][ref]", "see [docs](docs/a.md)"):
            with self.subTest(value=value):
                rendered = render.markdown_inline(value)
                self.assertNotRegex(rendered, r"[\[\]]")

    def test_backslashes_stay_literal_and_disarm_the_next_character(self):
        rendered = render.markdown_inline(r"api/\*/models.py and web/\*/models.py")
        self.assertNotRegex(rendered, r"(?<!&#)\*")
        self.assertEqual(rendered.count("&#92;&#42;"), 2)
        self.assertEqual(render.markdown_inline(r"C:\repo & <x>"), "C:&#92;repo &amp; &lt;x>")

    def test_emphasis_and_code_spans_are_kept(self):
        self.assertEqual(render.markdown_inline("keep *this* and `x | y`"),
                         "keep *this* and " + render.markdown_code("x | y"))

    def test_stray_backticks_cannot_join_two_fields(self):
        doc = complete_doc()
        doc["meta"].update(date="2026`", assessor="`x")
        row = [line for line in render.render_markdown(doc, "en").splitlines()
               if line.startswith("| Date")][0]
        self.assertNotIn("`", row)
        self.assertNotIn("<code>", row)

    def test_heading_keeps_a_hash_followed_by_blanks(self):
        for title in ("x #  ", "x ##\t", "acme #"):
            with self.subTest(title=title):
                self.assertTrue(render.heading_text(title).endswith("&#35;"))

    def test_control_characters_never_hide_a_scheme(self):
        for url in ("java\nscript:alert(1)", "\x01javascript:alert(1)", "java\tscript:x",
                    " javascript:x", "JavaScript:x", "data:text/html,x", "docs/a\x7f.md"):
            with self.subTest(url=url):
                self.assertFalse(render.is_safe_link(url))
                self.assertNotIn("](<", render.markdown_reference({"url": url, "title": "t"}))
        for url in ("docs/adr/1.md", "../x.md", "https://example.com/a", "#anchor"):
            with self.subTest(url=url):
                self.assertTrue(render.is_safe_link(url))

    def test_dashboard_title_is_one_line_of_text(self):
        doc = complete_doc()
        doc["meta"]["project"] = "Shop\n<Core>"
        title = re.search(r"<title>(.*?)</title>", render.render_html(doc, "en"))[1]
        self.assertEqual(title, "Architecture assessment: Shop &lt;Core&gt;")


class OutputPairTests(unittest.TestCase):
    def test_failed_render_replaces_neither_output(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            target = out / "findings.json"
            target.write_text(json.dumps(complete_doc()), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(render.main([str(target), "--out", str(out)]), 0)
            report = (out / "report.md").read_bytes()
            (out / "dashboard.html").unlink()
            (out / "dashboard.html").mkdir()
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(render.main([str(target), "--out", str(out), "--lang", "ja"]), 1)
            self.assertEqual((out / "report.md").read_bytes(), report)
            self.assertEqual(sorted(p.name for p in out.iterdir()),
                             ["dashboard.html", "findings.json", "report.md"])


class SchemaEdgeTests(unittest.TestCase):
    def test_step_numbers_exist_in_the_perspectives_reference(self):
        text = (SKILL / "reference" / "perspectives.md").read_text(encoding="utf-8")
        hunt = text.split("## Hunt steps per perspective", 1)[1].split("## Sound constructs", 1)[0]
        highest = {}
        for prefix, number in re.findall(r"^\| ([A-Z]{2})([0-9]+) \|", hunt, re.MULTILINE):
            highest[prefix] = max(highest.get(prefix, 0), int(number))
        self.assertEqual(highest, dict(zip(findings.STEP_PREFIXES, findings.STEP_COUNTS)))
        with self.assertRaisesRegex(findings.SchemaError, r"DM1-DM5"):
            findings.validate({"findings": [finding(step="DM9")]})

    def test_byte_order_mark_is_not_content(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "fragment.json"
            path.write_bytes(b"\xef\xbb\xbf" + json.dumps({"limitations": ["x"]}).encode())
            self.assertEqual(findings.read_json(path), {"limitations": ["x"]})


class ContractEdgeTests(unittest.TestCase):
    def setUp(self):
        self.out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.out)

    def problems(self, doc):
        target = self.out / "findings.json"
        target.write_text(json.dumps(doc), encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            render.main([str(target), "--out", str(self.out)])
        return findings.contract_problems(self.out)

    def test_evidence_must_name_a_path_and_a_line_from_one(self):
        for evidence, ok in (("discussed at 10:30", False), ("job.py:0", False),
                             ("Makefile:12", True), (r"C:\repo\job.py:3", True),
                             ("see worker/job.py:58-60", True)):
            with self.subTest(evidence=evidence):
                doc = complete_doc()
                doc["findings"][0]["validation"]["evidence"] = evidence
                bad = [p for p in self.problems(doc) if "path:line" in p]
                self.assertEqual(not bad, ok, bad)

    def test_confirmed_finding_contradicting_its_rule_status_fails(self):
        for status, verdict, ok in (("holds", "Valid", False), ("not checked", "Likely", False),
                                    ("partly read", "Valid", False), ("partly read", "Likely", True),
                                    ("holds", "Unverified", True),
                                    ("holds", "FalsePositive", True)):
            with self.subTest(status=status, verdict=verdict):
                doc = complete_doc()
                doc["rules"][0].update(status=status, reason="scope")
                doc["findings"][0].update(rule="R-01")
                doc["findings"][0]["validation"].update(verdict=verdict, evidence="job.py:58")
                bad = [p for p in self.problems(doc) if "R-01" in p]
                self.assertEqual(not bad, ok, bad)


class MakefileMessageTests(unittest.TestCase):
    def test_failed_link_names_the_requested_destination(self):
        with tempfile.TemporaryDirectory() as d:
            missing = str(Path(d) / "no such dir")
            result = subprocess.run(["make", "--no-print-directory", "-C", str(REPO), "link",
                                     f"SKILLS_DIR={missing}"],
                                    capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"SKILLS_DIR={missing}", result.stderr)
        self.assertNotIn("codex", result.stderr)


if __name__ == "__main__":
    unittest.main()
