"""Every CLI option says what it takes; findings.py answers -h like the argparse scripts."""

import ast
import contextlib
import io
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import findings  # noqa: E402


class CliHelpTests(unittest.TestCase):
    def test_every_argparse_option_has_help(self):
        for name in ("inventory.py", "render.py", "contract_check.py", "compare.py"):
            tree = ast.parse((SCRIPTS / name).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "add_argument":
                    option = node.args[0].value
                    with self.subTest(script=name, option=option):
                        self.assertTrue(any(k.arg == "help" for k in node.keywords))

    def test_findings_help_prints_usage_and_succeeds(self):
        for flag in ("-h", "--help"):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(findings.main([flag]), 0)
            self.assertIn("findings.py renumber", out.getvalue())
            self.assertIn("Exit status", out.getvalue())

    def test_findings_usage_errors_still_exit_2(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(findings.main([]), 2)
            self.assertEqual(findings.main(["-h", "extra"]), 2)
        self.assertIn("usage:", err.getvalue())


if __name__ == "__main__":
    unittest.main()
