"""JSON inputs must be regular files, including through symbolic links."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

from test_performance_scan import SKILL, complete_doc


class JsonInputFileTests(unittest.TestCase):
    def run_cli(self, script, *args, env_updates=None):
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env.update(env_updates or {})
        return subprocess.run(
            [sys.executable, str(SKILL / "scripts" / script), *(str(arg) for arg in args)],
            capture_output=True, text=True, check=False, timeout=2, env=env)

    def snapshot(self, root):
        entries = {}
        for path in root.rglob("*"):
            mode = path.lstat().st_mode
            record = (stat.S_IFMT(mode), stat.S_IMODE(mode))
            if stat.S_ISLNK(mode):
                record += (path.readlink(),)
            elif stat.S_ISREG(mode):
                record += (path.read_bytes(),)
            entries[str(path.relative_to(root))] = record
        return entries

    def prepare(self, root):
        out = root / "out"
        out.mkdir()
        target = out / "findings.json"
        target.write_text(json.dumps(complete_doc()), encoding="utf-8")
        (out / "report.md").write_bytes(b"Previous report\n")
        (out / "dashboard.html").write_bytes(b"Previous dashboard\n")
        fragment = root / "fragment.json"
        fragment.write_text(json.dumps({"meta": {"project": "Updated project"}}),
                            encoding="utf-8")
        return out, target, fragment

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires FIFO support")
    def test_commands_reject_fifo_inputs_without_blocking_or_changing_files(self):
        for origin in ("existing findings", "fragment", "render input"):
            for symlink in (False, True):
                with self.subTest(origin=origin, symlink=symlink), \
                        tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    out, target, fragment = self.prepare(root)
                    input_path = fragment if origin == "fragment" else target
                    input_path.unlink()
                    fifo = root / "input.fifo" if symlink else input_path
                    os.mkfifo(fifo)
                    if symlink:
                        try:
                            input_path.symlink_to(fifo)
                        except (OSError, NotImplementedError):
                            self.skipTest("symbolic links are unavailable")
                    original = self.snapshot(root)

                    if origin == "render input":
                        result = self.run_cli("render.py", target, "--out", out)
                        code, prefix = 2, "schema:"
                    else:
                        result = self.run_cli("findings.py", "merge", target, fragment)
                        code, prefix = 1, "refused:"

                    self.assertEqual(result.returncode, code, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertIn(prefix, result.stderr)
                    self.assertIn("regular file", result.stderr)
                    diagnostic_path = fifo if origin == "existing findings" else input_path
                    self.assertIn(str(diagnostic_path), result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertEqual(self.snapshot(root), original)

    def test_commands_report_json_decoder_limits_without_changing_files(self):
        cases = [("nesting", "[" * 200000 + "0" + "]" * 200000, {})]
        if hasattr(sys, "get_int_max_str_digits"):
            cases.append(("integer", "1" * 4301, {"PYTHONINTMAXSTRDIGITS": "4300"}))
        for kind, content, env_updates in cases:
            for origin in ("existing findings", "fragment", "render input"):
                with self.subTest(kind=kind, origin=origin), \
                        tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    out, target, fragment = self.prepare(root)
                    input_path = fragment if origin == "fragment" else target
                    input_path.write_text(content, encoding="utf-8")
                    original = self.snapshot(root)

                    if origin == "render input":
                        result = self.run_cli("render.py", target, "--out", out,
                                              env_updates=env_updates)
                        code, prefix = 2, "schema:"
                    else:
                        result = self.run_cli("findings.py", "merge", target, fragment,
                                              env_updates=env_updates)
                        code, prefix = 1, "refused:"

                    self.assertEqual(result.returncode, code, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertIn(prefix, result.stderr)
                    self.assertIn(str(input_path), result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertEqual(self.snapshot(root), original)

    def test_regular_file_symlinks_work_as_merge_and_render_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out, target, fragment = self.prepare(root)
            record = root / "record.json"
            update = root / "update.json"
            target.rename(record)
            fragment.rename(update)
            try:
                target.symlink_to(Path("..") / record.name)
                fragment.symlink_to(update.name)
            except (OSError, NotImplementedError):
                self.skipTest("symbolic links are unavailable")

            result = self.run_cli("findings.py", "merge", target, fragment)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(target.is_symlink())
            self.assertTrue(fragment.is_symlink())
            self.assertEqual(json.loads(record.read_text(encoding="utf-8"))["meta"]["project"],
                             "Updated project")
            self.assertEqual(target.read_bytes(), record.read_bytes())

            result = self.run_cli("render.py", target, "--out", out)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(target.is_symlink())
            for name in ("report.md", "dashboard.html"):
                self.assertIn("Updated project", (out / name).read_text(encoding="utf-8"))
            result = self.run_cli("findings.py", "check", out)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
