"""Behaviour the documentation promises, found false or undocumented by an audit."""
import io
import json
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_architecture_scan import SKILL, complete_doc, finding, findings, render


class MergeOrderTests(unittest.TestCase):
    def test_remove_runs_first_so_a_rule_can_be_replaced(self):
        doc = complete_doc()
        replacement = {"id": "R-01", "statement": "billing is the only writer",
                       "source": "docs/adr/1.md:3", "status": "violated"}
        findings.merge(doc, {"remove": {"rules": ["R-01"]}, "rules": [replacement]}, "f")
        self.assertEqual(doc["rules"], [replacement])

    def test_a_perspective_cannot_be_removed_and_the_message_says_so(self):
        with self.assertRaisesRegex(findings.SchemaError, "perspective is replaced"):
            findings.merge(complete_doc(), {"remove": {"perspectives": ["Coupling"]}}, "f")


class UnknownKeyTests(unittest.TestCase):
    def test_typos_in_rendered_records_are_refused(self):
        cases = [
            ("findings[0]", lambda d: d["findings"][0].update(contrats="x")),
            ("findings[0].validation", lambda d: d["findings"][0]["validation"].update(evidnce="x")),
            ("findings[0].references[0]", lambda d: d["findings"][0].update(
                references=[{"url": "https://e.example", "titel": "x"}])),
            ("rules[0]", lambda d: d["rules"][0].update(reson="x")),
            ("perspectives[0]", lambda d: d["perspectives"][0].update(notes="x")),
        ]
        for where, change in cases:
            with self.subTest(where=where):
                doc = complete_doc()
                change(doc)
                with self.assertRaisesRegex(findings.SchemaError, re.escape(f"{where}: unknown keys")):
                    findings.validate(doc, complete=True)

    def test_meta_keeps_extra_run_context(self):
        doc = complete_doc()
        doc["meta"]["history_window"] = "12 months"
        findings.validate(doc, complete=True)


class RefusedMergeTests(unittest.TestCase):
    def test_a_refused_first_merge_leaves_no_output_directory(self):
        with tempfile.TemporaryDirectory() as d:
            fragment = Path(d) / "f.json"
            fragment.write_text(json.dumps({"findings": [{"id": "A-001"}]}), encoding="utf-8")
            target = Path(d) / "new" / "findings.json"
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(findings.main(["merge", str(target), str(fragment)]), 1)
            self.assertFalse(target.parent.exists())

    def test_the_lock_never_removes_the_directory_it_locked(self):
        # Another merge may hold the directory open while waiting for the lock.
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "new" / "findings.json"
            with self.assertRaises(RuntimeError):
                with findings._exclusive(target):
                    raise RuntimeError("refused while holding the lock")
            self.assertTrue(target.parent.is_dir())


class RenderClaimTests(unittest.TestCase):
    def test_emphasis_at_the_start_of_a_list_item_is_kept(self):
        for item, kept in (("*em* first", "*em* first"), ("**bold** first", "**bold** first"),
                           ("~~old~~ plan", "~~old~~ plan"), ("_em_ first", "_em_ first")):
            with self.subTest(item=item):
                self.assertEqual(render.block_safe(render.markdown_inline(item)), kept)
        for item, encoded in (("* bullet", "&#42; bullet"), ("- bullet", "&#45; bullet"),
                              ("* * *", "&#42; * *"), ("___", "&#95;__"), ("```", "&#96;``")):
            with self.subTest(item=item):
                self.assertTrue(render.block_safe(render.markdown_inline(item)).startswith(
                    encoded[:5]))

    def test_blank_rule_reason_gets_no_row(self):
        doc = complete_doc()
        doc["rules"][0].update(status="not checked", reason="  ")
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                reason = render.LABELS[lang]["reason"]
                self.assertNotIn(f"{reason}:", render.render_markdown(doc, lang))
                self.assertNotIn(f"{reason}:", render.render_html(doc, lang))

    def test_scripts_import_without_warnings(self):
        for script in ("findings.py", "render.py"):
            with self.subTest(script=script):
                result = subprocess.run([sys.executable, "-W", "error", "-c",
                                         "import ast,sys; ast.parse(open(sys.argv[1], "
                                         "encoding='utf-8').read())", str(SKILL / "scripts" / script)],
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
