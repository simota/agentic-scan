"""The run contract must reject unusable required output files."""
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

from support import complete_doc, findings, render, run_cli, run_main


OUTPUTS = ("dashboard.html", "findings.json", "report.md")


class OutputContractTests(unittest.TestCase):
    def prepare(self, root):
        out = root / "out"
        out.mkdir()
        source = out / "findings.json"
        source.write_text(json.dumps(complete_doc()), encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(render.main([str(source), "--out", str(out)]), 0)
        return out

    def check(self, out, *args):
        return run_main(findings.main, "check", out, *args)

    def assert_rejected(self, result, name, reason):
        code, output, errors = result
        self.assertEqual(code, 1)
        self.assertNotIn("contract ok", output)
        self.assertIn(name, errors)
        self.assertIn(reason, errors)
        self.assertNotIn("Traceback", errors)

    def test_complete_generated_outputs_pass(self):
        with tempfile.TemporaryDirectory() as d:
            out = self.prepare(Path(d))
            result, output, errors = self.check(out)
            self.assertEqual(result, 0)
            self.assertIn("contract ok", output)
            self.assertEqual(errors, "")

    def test_required_output_directories_are_rejected(self):
        for name in OUTPUTS:
            with self.subTest(output=name), tempfile.TemporaryDirectory() as d:
                out = self.prepare(Path(d))
                target = out / name
                target.unlink()
                target.mkdir()
                self.assert_rejected(self.check(out), name, "regular file")

    def test_required_empty_outputs_are_rejected(self):
        for name in OUTPUTS:
            with self.subTest(output=name), tempfile.TemporaryDirectory() as d:
                out = self.prepare(Path(d))
                (out / name).write_bytes(b"")
                self.assert_rejected(self.check(out), name, "empty output")

    def test_required_broken_symlinks_are_rejected(self):
        for name in OUTPUTS:
            with self.subTest(output=name), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                out = self.prepare(root)
                target = out / name
                target.unlink()
                try:
                    target.symlink_to(root / "missing-output")
                except (OSError, NotImplementedError):
                    self.skipTest("symbolic links are unavailable")
                self.assert_rejected(self.check(out), name, "unreadable output")

    def test_valid_symlink_outputs_still_pass(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            out = self.prepare(root)
            for name in OUTPUTS:
                target = out / name
                target.rename(root / name)
                try:
                    target.symlink_to(Path("..") / name)
                except (OSError, NotImplementedError):
                    self.skipTest("symbolic links are unavailable")
            result, output, errors = self.check(out)
            self.assertEqual(result, 0)
            self.assertIn("contract ok", output)
            self.assertEqual(errors, "")

    def test_required_output_open_and_read_errors_are_controlled(self):
        for name in OUTPUTS:
            for operation in ("open", "read"):
                with self.subTest(output=name, operation=operation), \
                        tempfile.TemporaryDirectory() as d:
                    out = self.prepare(Path(d))
                    target = out / name
                    original_open = Path.open

                    def fail_read(path, *args, **kwargs):
                        if path == target:
                            if operation == "open":
                                raise PermissionError("output read denied")
                            source = MagicMock()
                            source.__enter__.return_value.read.side_effect = OSError(
                                "output read denied")
                            return source
                        return original_open(path, *args, **kwargs)

                    with patch.object(Path, "open", fail_read):
                        result = self.check(out)
                    self.assert_rejected(result, name, "output read denied")

    def test_required_output_stat_errors_are_controlled(self):
        with tempfile.TemporaryDirectory() as d:
            out = self.prepare(Path(d))
            target = out / "report.md"
            original_stat = Path.stat

            def fail_stat(path, *args, **kwargs):
                if path == target:
                    raise PermissionError("output metadata denied")
                return original_stat(path, *args, **kwargs)

            with patch.object(Path, "stat", fail_stat):
                result = self.check(out)
            self.assert_rejected(result, target.name, "output metadata denied")

    def test_output_directory_listing_errors_are_controlled(self):
        with tempfile.TemporaryDirectory() as d:
            out = self.prepare(Path(d))
            with patch.object(Path, "iterdir", side_effect=PermissionError("listing denied")):
                result = self.check(out)
            self.assert_rejected(result, str(out), "listing denied")

    def test_invalid_utf8_findings_are_rejected_without_a_traceback(self):
        with tempfile.TemporaryDirectory() as d:
            out = self.prepare(Path(d))
            (out / "findings.json").write_bytes(b"\xff")
            self.assert_rejected(self.check(out), "findings.json", "utf-8")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires FIFO support")
    def test_required_fifos_are_rejected_without_blocking(self):
        for name in OUTPUTS:
            with self.subTest(output=name), tempfile.TemporaryDirectory() as d:
                out = self.prepare(Path(d))
                target = out / name
                target.unlink()
                os.mkfifo(target)
                result = run_cli("findings.py", "check", out, timeout=5)
                self.assert_rejected(
                    (result.returncode, result.stdout, result.stderr), name, "regular file")

    def test_allow_only_exempts_additional_output_names(self):
        with tempfile.TemporaryDirectory() as d:
            out = self.prepare(Path(d))
            (out / "screenshots").mkdir()
            (out / "diagnostics.log").touch()
            allowed = ("--allow", "screenshots", "--allow", "diagnostics.log")
            self.assert_rejected(self.check(out), "screenshots", "unexpected output")
            self.assertEqual(self.check(out, *allowed)[0], 0)
            (out / "report.md").write_bytes(b"")
            self.assert_rejected(
                self.check(out, *allowed, "--allow", "report.md"), "report.md", "empty output")


    def test_an_entry_name_with_a_line_break_stays_on_one_problem_line(self):
        with tempfile.TemporaryDirectory() as d:
            out = self.prepare(Path(d))
            (out / "notes\nfindings.json: ok").touch()
            code, _, errors = self.check(out)
            self.assertEqual(code, 1)
            self.assertEqual(errors.splitlines(),
                             ["unexpected output: 'notes\\nfindings.json: ok' "
                              "(pass --allow 'notes\\nfindings.json: ok' if requested)"])


if __name__ == "__main__":
    unittest.main()
