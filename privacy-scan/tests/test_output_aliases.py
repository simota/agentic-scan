"""Reject aliased report destinations without changing the recorded findings."""
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from test_privacy_scan import SKILL, complete_doc, render

with patch.object(sys, "path", [str(SKILL / "scripts")] + sys.path):
    import output_io


class OutputAliasTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def make_output(self, name):
        out = self.root / name
        out.mkdir()
        (out / "findings.json").write_text(json.dumps(complete_doc()), encoding="utf-8")
        (out / "report.md").write_text("# Previous report\n", encoding="utf-8")
        (out / "dashboard.html").write_text("<html>Previous report</html>\n", encoding="utf-8")
        return out

    def snapshot(self):
        """Include link spelling, file bytes and modes, and any staging leftovers."""
        result = {}
        for path in self.root.rglob("*"):
            name = str(path.relative_to(self.root))
            if path.is_symlink():
                result[name] = ("link", str(path.readlink()))
            elif path.is_dir():
                result[name] = ("directory",)
            else:
                result[name] = ("file", path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
        return result

    def assert_render_refused(self, out, source=None):
        previous = self.snapshot()
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = render.main([str(source or out / "findings.json"), "--out", str(out)])
        self.assertEqual(result, 1)
        self.assertIn("write failed", stderr.getvalue())
        self.assertNotIn("wrote ", stdout.getvalue())
        self.assertEqual(self.snapshot(), previous)

    def test_render_rejects_outputs_pointing_to_each_other(self):
        for link_name, target_name in (("report.md", "dashboard.html"),
                                       ("dashboard.html", "report.md")):
            for target_exists in (True, False):
                with self.subTest(link=link_name, target_exists=target_exists):
                    out = self.make_output(f"{link_name}-{target_exists}")
                    (out / link_name).unlink()
                    if not target_exists:
                        (out / target_name).unlink()
                    (out / link_name).symlink_to(target_name)
                    self.assert_render_refused(out)

    def test_render_rejects_output_link_to_findings(self):
        for name in ("report.md", "dashboard.html"):
            with self.subTest(output=name):
                out = self.make_output(name)
                (out / name).unlink()
                (out / name).symlink_to("findings.json")
                self.assert_render_refused(out)

    def test_render_rejects_input_link_to_an_output(self):
        for name in ("report.md", "dashboard.html"):
            with self.subTest(output=name):
                out = self.make_output(name)
                source = out / "findings.json"
                (out / name).write_bytes(source.read_bytes())
                source.unlink()
                source.symlink_to(name)
                self.assert_render_refused(out)

    def test_render_rejects_input_named_as_an_output(self):
        for name in ("report.md", "dashboard.html"):
            with self.subTest(output=name):
                out = self.make_output(name)
                source = out / name
                source.write_bytes((out / "findings.json").read_bytes())
                self.assert_render_refused(out, source)

    def test_render_rejects_shared_target_through_directory_symlink(self):
        out = self.make_output("output")
        stored = self.root / "stored"
        stored.mkdir()
        (stored / "shared").write_text("Previous target\n", encoding="utf-8")
        (self.root / "alias").symlink_to("stored", target_is_directory=True)
        for name, directory in (("report.md", "stored"), ("dashboard.html", "alias")):
            (out / name).unlink()
            (out / name).symlink_to(Path("..") / directory / "shared")
        self.assert_render_refused(out)

    def test_writer_rejects_resolved_output_aliases(self):
        target = self.root / "target"
        target.write_text("Previous target\n", encoding="utf-8")
        alias = self.root / "alias"
        alias.symlink_to(target.name)
        previous = self.snapshot()
        with self.assertRaises(OSError):
            output_io.write_utf8_files({target: "First output", alias: "Second output"})
        self.assertEqual(self.snapshot(), previous)

    def test_render_preserves_distinct_symlinks_and_their_target_modes(self):
        out = self.make_output("output")
        stored = self.root / "stored"
        stored.mkdir()
        names = ("findings.json", "report.md", "dashboard.html")
        source_bytes = (out / "findings.json").read_bytes()
        for name in names:
            (out / name).replace(stored / name)
            (stored / name).chmod(0o640)
            (out / name).symlink_to(Path("..") / "stored" / name)
        with redirect_stdout(io.StringIO()):
            result = render.main([str(out / "findings.json"), "--out", str(out)])
        self.assertEqual(result, 0)
        self.assertEqual((stored / "findings.json").read_bytes(), source_bytes)
        self.assertTrue((stored / "report.md").read_text(encoding="utf-8").startswith("# Privacy assessment"))
        self.assertTrue((stored / "dashboard.html").read_text(encoding="utf-8").startswith("<!doctype html>"))
        for name in names:
            self.assertTrue((out / name).is_symlink())
            self.assertEqual((out / name).readlink(), Path("..") / "stored" / name)
            self.assertEqual(stat.S_IMODE((stored / name).stat().st_mode), 0o640)
        for directory in (out, stored):
            self.assertEqual({path.name for path in directory.iterdir()}, set(names))


if __name__ == "__main__":
    unittest.main()
