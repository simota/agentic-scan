"""Cyclic paths must produce controlled errors without changing nearby files."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_performance_scan import SKILL, complete_doc, render


class PathResolutionTests(unittest.TestCase):
    def make_loop(self, target, mutual=False):
        peer = target.with_name(target.name + ".peer") if mutual else target
        try:
            target.symlink_to(peer.name)
            if mutual:
                peer.symlink_to(target.name)
        except (OSError, NotImplementedError):
            self.skipTest("symbolic links are unavailable")

    def snapshot(self, root):
        entries = {}
        for path in root.rglob("*"):
            name = str(path.relative_to(root))
            if path.is_symlink():
                entries[name] = ("symlink", path.readlink())
            elif path.is_dir():
                entries[name] = ("directory",)
            else:
                entries[name] = ("file", path.read_bytes())
        return entries

    def run_cli(self, script, *args):
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            [sys.executable, str(SKILL / "scripts" / script), *(str(arg) for arg in args)],
            capture_output=True, text=True, check=False, timeout=10, env=env)

    def assert_controlled_error(self, result, code, prefix):
        self.assertEqual(result.returncode, code, result.stderr)
        self.assertIn(prefix, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_merge_rejects_cyclic_destinations_without_changing_files(self):
        for mutual in (False, True):
            with self.subTest(mutual=mutual), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                fragment = root / "fragment.json"
                fragment.write_text(json.dumps(complete_doc()), encoding="utf-8")
                (root / "report.md").write_bytes(b"Existing report\n")
                target = root / "findings.json"
                self.make_loop(target, mutual)
                original = self.snapshot(root)

                result = self.run_cli("findings.py", "merge", target, fragment)

                self.assertEqual(self.snapshot(root), original)
                self.assert_controlled_error(result, 1, "refused:")

    def test_render_rejects_cyclic_outputs_without_changing_files(self):
        for mutual in (False, True):
            with self.subTest(mutual=mutual), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "findings.json"
                source.write_text(json.dumps(complete_doc()), encoding="utf-8")
                out = root / "out"
                out.mkdir()
                (out / "report.md").write_bytes(b"Existing report\n")
                self.make_loop(out / "dashboard.html", mutual)
                original = self.snapshot(root)

                result = self.run_cli("render.py", source, "--out", out)

                self.assertEqual(self.snapshot(root), original)
                self.assert_controlled_error(result, 1, "render:")

    def test_write_outputs_rejects_a_cyclic_path_as_an_oserror(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.md"
            dashboard = root / "dashboard.html"
            report.write_bytes(b"Existing report\n")
            self.make_loop(dashboard)
            original = self.snapshot(root)

            with self.assertRaises(OSError):
                render.write_outputs([(report, b"New report\n"),
                                      (dashboard, b"New dashboard\n")])

            self.assertEqual(self.snapshot(root), original)

    def test_render_cyclic_input_keeps_the_schema_error_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "findings.json"
            self.make_loop(source)
            out = root / "out"
            out.mkdir()
            (out / "report.md").write_bytes(b"Existing report\n")
            (out / "dashboard.html").write_bytes(b"Existing dashboard\n")
            original = self.snapshot(root)

            result = self.run_cli("render.py", source, "--out", out)

            self.assertEqual(self.snapshot(root), original)
            self.assert_controlled_error(result, 2, "schema:")


if __name__ == "__main__":
    unittest.main()
