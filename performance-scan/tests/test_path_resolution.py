"""Cyclic paths must produce controlled errors without changing nearby files."""
import json
from pathlib import Path
import tempfile
import unittest

from support import complete_doc, render, run_cli, snapshot


class PathResolutionTests(unittest.TestCase):
    def make_loop(self, target, mutual=False):
        peer = target.with_name(target.name + ".peer") if mutual else target
        try:
            target.symlink_to(peer.name)
            if mutual:
                peer.symlink_to(target.name)
        except (OSError, NotImplementedError):
            self.skipTest("symbolic links are unavailable")

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
                original = snapshot(root)

                result = run_cli("findings.py", "merge", target, fragment)

                self.assertEqual(snapshot(root), original)
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
                original = snapshot(root)

                result = run_cli("render.py", source, "--out", out)

                self.assertEqual(snapshot(root), original)
                self.assert_controlled_error(result, 1, "render:")

    def test_write_outputs_rejects_a_cyclic_path_as_an_oserror(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.md"
            dashboard = root / "dashboard.html"
            report.write_bytes(b"Existing report\n")
            self.make_loop(dashboard)
            original = snapshot(root)

            with self.assertRaises(OSError):
                render.write_outputs([(report, b"New report\n"),
                                      (dashboard, b"New dashboard\n")])

            self.assertEqual(snapshot(root), original)

    def test_render_cyclic_input_keeps_the_schema_error_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "findings.json"
            self.make_loop(source)
            out = root / "out"
            out.mkdir()
            (out / "report.md").write_bytes(b"Existing report\n")
            (out / "dashboard.html").write_bytes(b"Existing dashboard\n")
            original = snapshot(root)

            result = run_cli("render.py", source, "--out", out)

            self.assertEqual(snapshot(root), original)
            self.assert_controlled_error(result, 2, "schema:")


if __name__ == "__main__":
    unittest.main()
