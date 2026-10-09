"""`findings.py renumber`: severity-then-path order without hand-editing the record."""
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_architecture_scan import SKILL, complete_doc, finding, findings, render


class RenumberTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.target = self.tmp / "findings.json"

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = findings.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def write(self, doc):
        self.target.write_text(json.dumps(doc), encoding="utf-8")

    def test_orders_by_severity_then_path_and_line(self):
        doc = complete_doc()
        doc["findings"] = [
            finding("A-001", "Low", location="b.py:1"),
            finding("A-002", "High", location=["z.py:9", "a.py:1"]),
            finding("A-003", "Low", location="a.py:20"),
            finding("A-004", "Low", location="a.py:3"),
            finding("A-005", "Medium", location="m.py:1"),
        ]
        self.write(doc)
        code, out, _ = self.run_cli("renumber", str(self.target))
        self.assertEqual(code, 0)
        result = findings.read_json(self.target)["findings"]
        self.assertEqual([f["id"] for f in result], ["A-001", "A-002", "A-003", "A-004", "A-005"])
        self.assertEqual([f["location"] for f in result],
                         [["z.py:9", "a.py:1"], "m.py:1", "a.py:3", "a.py:20", "b.py:1"])
        self.assertIn("A-002 -> A-001", out)

    def test_changed_ids_warn_that_older_fragments_name_old_ids(self):
        doc = complete_doc()
        doc["findings"] = [finding("A-001", "Low"), finding("A-002", "High")]
        self.write(doc)
        code, _, err = self.run_cli("renumber", str(self.target))
        self.assertEqual(code, 0)
        self.assertIn("new IDs", err)
        self.write(complete_doc())
        self.assertEqual(self.run_cli("renumber", str(self.target))[2], "")

    def test_mentions_are_rewritten_in_one_pass(self):
        doc = complete_doc()
        doc["findings"] = [finding("A-001", "Low"), finding("A-002", "High")]
        doc["findings"][1]["trace"] = "Same writer as A-001; see A-002 and A-999"
        doc["next_steps"] = ["Fix A-002 before A-001", "Ticket JIRA-A-001 and A-0012 stay"]
        self.write(doc)
        self.assertEqual(self.run_cli("renumber", str(self.target))[0], 0)
        result = findings.read_json(self.target)
        self.assertEqual(result["findings"][0]["trace"], "Same writer as A-002; see A-001 and A-999")
        self.assertEqual(result["next_steps"],
                         ["Fix A-001 before A-002", "Ticket JIRA-A-001 and A-0012 stay"])

    def test_ordered_record_is_left_untouched(self):
        self.write(complete_doc())
        before = self.target.read_bytes()
        code, out, _ = self.run_cli("renumber", str(self.target))
        self.assertEqual(code, 0)
        self.assertIn("already in order", out)
        self.assertEqual(self.target.read_bytes(), before)

    def test_fixes_an_out_of_order_run_so_check_passes(self):
        doc = complete_doc()
        doc["findings"] = [finding("A-001", "Low"), finding("A-002", "High")]
        doc["next_steps"] = ["Fix A-002"]
        self.write(doc)
        with redirect_stdout(io.StringIO()):
            render.main([str(self.target), "--out", str(self.tmp)])
        self.assertTrue(any("severity order" in p for p in findings.contract_problems(self.tmp)))
        self.assertEqual(self.run_cli("renumber", str(self.target))[0], 0)
        with redirect_stdout(io.StringIO()):
            render.main([str(self.target), "--out", str(self.tmp)])
        self.assertEqual(findings.contract_problems(self.tmp), [])
        self.assertEqual(findings.read_json(self.target)["next_steps"], ["Fix A-001"])

    def test_invalid_or_missing_record_is_refused(self):
        code, _, err = self.run_cli("renumber", str(self.tmp / "absent.json"))
        self.assertEqual(code, 1)
        self.assertIn("refused", err)
        self.target.write_text('{"findings": [{"id": "A-001"}]}', encoding="utf-8")
        before = self.target.read_bytes()
        self.assertEqual(self.run_cli("renumber", str(self.target))[0], 1)
        self.assertEqual(self.target.read_bytes(), before)

    def test_scripts_leave_no_bytecode_beside_the_skill(self):
        self.write(complete_doc())
        scripts = SKILL / "scripts"
        shutil.rmtree(scripts / "__pycache__", ignore_errors=True)
        for args in (["render.py", str(self.target), "--out", str(self.tmp)],
                     ["findings.py", "check", str(self.tmp)]):
            subprocess.run([sys.executable, str(scripts / args[0]), *args[1:]],
                           capture_output=True, check=True, timeout=30)
        self.assertFalse((scripts / "__pycache__").exists())


if __name__ == "__main__":
    unittest.main()
