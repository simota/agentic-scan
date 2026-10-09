"""A failed merge must never destroy the existing findings record."""
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

try:
    import resource
except ImportError:
    resource = None

from test_performance_scan import SKILL, complete_doc, findings


class AtomicMergeTests(unittest.TestCase):
    def prepare(self, root, existing=True, project="Updated project"):
        target = root / "findings.json"
        if existing:
            target.write_text(json.dumps(complete_doc(), indent=2) + "\n", encoding="utf-8")
        fragment = root / "fragment.json"
        fragment.write_text(json.dumps({"meta": {"project": project}}), encoding="utf-8")
        return target, fragment

    def test_unencodable_text_preserves_existing_or_absent_target(self):
        for existing in (True, False):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                target, fragment = self.prepare(root, existing, project="\ud800")
                original = target.read_bytes() if existing else None
                names = {path.name for path in root.iterdir()}
                result = subprocess.run(
                    [sys.executable, str(SKILL / "scripts/findings.py"),
                     "merge", str(target), str(fragment)],
                    capture_output=True, text=True, check=False)
                self.assertEqual(target.read_bytes() if target.exists() else None, original)
                self.assertEqual(result.returncode, 1)
                self.assertIn("refused:", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual({path.name for path in root.iterdir()}, names)

    def test_encoder_recursion_failure_preserves_existing_or_absent_target(self):
        for existing in (True, False):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                target, fragment = self.prepare(root, existing)
                original = target.read_bytes() if existing else None
                names = {path.name for path in root.iterdir()}
                output, errors = io.StringIO(), io.StringIO()
                # Decoder and encoder recursion limits differ across Python versions.
                with patch.object(findings.json, "dumps", side_effect=RecursionError(
                        "JSON encoding nesting limit")), \
                        redirect_stdout(output), redirect_stderr(errors):
                    result = findings.main(["merge", str(target), str(fragment)])
                self.assertEqual(target.read_bytes() if target.exists() else None, original)
                self.assertEqual(result, 1)
                self.assertEqual(output.getvalue(), "")
                self.assertIn("refused:", errors.getvalue())
                self.assertIn("JSON encoding nesting limit", errors.getvalue())
                self.assertNotIn("Traceback", errors.getvalue())
                self.assertEqual({path.name for path in root.iterdir()}, names)

    @unittest.skipUnless(resource is not None and hasattr(resource, "RLIMIT_FSIZE"),
                         "requires a per-process file size limit")
    def test_partial_write_failure_preserves_record_and_removes_temporary_file(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            target, fragment = self.prepare(root)
            original = target.read_bytes()
            self.assertGreater(len(original), 1024)
            names = {path.name for path in root.iterdir()}
            child = (
                "import resource, signal, sys\n"
                "sys.path.insert(0, sys.argv[1])\n"
                "import findings\n"
                "_, hard = resource.getrlimit(resource.RLIMIT_FSIZE)\n"
                "resource.setrlimit(resource.RLIMIT_FSIZE, (1024, hard))\n"
                "signal.signal(signal.SIGXFSZ, signal.SIG_IGN)\n"
                "sys.exit(findings.main(['merge', sys.argv[2], sys.argv[3]]))\n"
            )
            result = subprocess.run(
                [sys.executable, "-c", child, str(SKILL / "scripts"), str(target), str(fragment)],
                capture_output=True, text=True, check=False)
            self.assertEqual(target.read_bytes(), original)
            self.assertEqual(result.returncode, 1)
            self.assertIn("refused:", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertEqual({path.name for path in root.iterdir()}, names)

    def test_replace_failure_preserves_existing_or_absent_target(self):
        for existing in (True, False):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                target, fragment = self.prepare(root, existing)
                original = target.read_bytes() if existing else None
                names = {path.name for path in root.iterdir()}
                errors = io.StringIO()
                with patch("os.replace", side_effect=OSError("replace refused")), \
                        redirect_stdout(io.StringIO()), redirect_stderr(errors):
                    result = findings.main(["merge", str(target), str(fragment)])
                self.assertEqual(target.read_bytes() if target.exists() else None, original)
                self.assertEqual(result, 1)
                self.assertIn("refused:", errors.getvalue())
                self.assertIn("replace refused", errors.getvalue())
                self.assertEqual({path.name for path in root.iterdir()}, names)

    @unittest.skipUnless(os.name == "posix", "requires POSIX permission bits")
    def test_success_preserves_existing_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            target, fragment = self.prepare(root)
            target.chmod(0o640)
            names = {path.name for path in root.iterdir()}
            with redirect_stdout(io.StringIO()):
                result = findings.main(["merge", str(target), str(fragment)])
            self.assertEqual(result, 0)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
            self.assertEqual(json.loads(target.read_text())["meta"]["project"], "Updated project")
            self.assertEqual({path.name for path in root.iterdir()}, names)

    def test_success_updates_symlink_destination_without_replacing_link(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            records = root / "records"
            records.mkdir()
            target, fragment = self.prepare(records)
            link = root / "findings.json"
            try:
                link.symlink_to(Path("records") / target.name)
            except (OSError, NotImplementedError):
                self.skipTest("symbolic links are unavailable")
            names = {path.name for path in records.iterdir()}
            with redirect_stdout(io.StringIO()):
                result = findings.main(["merge", str(link), str(fragment)])
            self.assertEqual(result, 0)
            self.assertTrue(link.is_symlink())
            self.assertEqual(json.loads(target.read_text())["meta"]["project"], "Updated project")
            self.assertEqual(link.read_bytes(), target.read_bytes())
            self.assertEqual({path.name for path in records.iterdir()}, names)


if __name__ == "__main__":
    unittest.main()
