"""Regression coverage for metadata validation and failure-safe record writes."""
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

from test_architecture_scan import SKILL, complete_doc, findings


class FindingsPersistenceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.out = self.tmp / "out"
        self.out.mkdir()
        self.target = self.out / "findings.json"

    def write_json(self, path, value):
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def run_merge(self, *fragments):
        paths = [self.write_json(self.tmp / f"fragment-{i}.json", value)
                 for i, value in enumerate(fragments)]
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = findings.main(["merge", str(self.target), *map(str, paths)])
        return result, stdout.getvalue(), stderr.getvalue()

    def test_present_required_metadata_is_validated_before_merge_writes(self):
        for field in ("project", "scope", "date", "assessor"):
            for value in (None, 0, False, [], {}, "", " \n\t "):
                for existing in (False, True):
                    with self.subTest(field=field, value=value, existing=existing):
                        self.target.unlink(missing_ok=True)
                        if existing:
                            self.write_json(self.target, complete_doc())
                        before = self.target.read_bytes() if existing else None
                        result, stdout, stderr = self.run_merge({"meta": {field: value}})
                        self.assertEqual(result, 1)
                        self.assertIn(f"meta.{field}", stderr)
                        self.assertEqual(stdout, "")
                        if existing:
                            self.assertEqual(self.target.read_bytes(), before)
                        else:
                            self.assertFalse(self.target.exists())

    def test_later_metadata_correction_does_not_hide_an_invalid_fragment(self):
        self.write_json(self.target, complete_doc())
        before = self.target.read_bytes()
        result, stdout, stderr = self.run_merge(
            {"meta": {"project": None}},
            {"meta": {"project": "corrected"}},
        )
        self.assertEqual(result, 1)
        self.assertIn("meta.project", stderr)
        self.assertEqual(stdout, "")
        self.assertEqual(self.target.read_bytes(), before)

    def test_invalid_existing_metadata_is_rejected_before_a_repair_fragment(self):
        doc = complete_doc()
        doc["meta"]["scope"] = []
        self.write_json(self.target, doc)
        before = self.target.read_bytes()
        result, stdout, stderr = self.run_merge({"meta": {"scope": "corrected"}})
        self.assertEqual(result, 1)
        self.assertIn("meta.scope", stderr)
        self.assertEqual(stdout, "")
        self.assertEqual(self.target.read_bytes(), before)

    def test_omitted_metadata_can_still_be_added_incrementally(self):
        fragments = [{}] + [{"meta": {key: value}}
                            for key, value in complete_doc()["meta"].items()]
        result, stdout, stderr = self.run_merge(*fragments)
        self.assertEqual(result, 0, stderr)
        self.assertIn("merged", stdout)
        self.assertEqual(findings.read_json(self.target)["meta"], complete_doc()["meta"])
        findings.validate({})
        findings.validate({"meta": {}})

    @unittest.skipUnless(os.name == "posix", "requires POSIX file size limits")
    def test_partial_write_failure_preserves_record_and_cleans_staging_file(self):
        # A real OS write limit also covers buffered errors raised during close.
        program = (
            "import importlib.util, resource, signal, sys\n"
            "spec = importlib.util.spec_from_file_location('findings_under_test', sys.argv[1])\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(module)\n"
            "signal.signal(signal.SIGXFSZ, signal.SIG_IGN)\n"
            "resource.setrlimit(resource.RLIMIT_FSIZE, (128, 128))\n"
            "sys.exit(module.main(sys.argv[2:]))\n"
        )
        for existing in (False, True):
            with self.subTest(existing=existing):
                self.target.unlink(missing_ok=True)
                if existing:
                    self.write_json(self.target, complete_doc())
                before = self.target.read_bytes() if existing else None
                fragment = self.write_json(self.tmp / "fragment.json", complete_doc())
                result = subprocess.run(
                    [sys.executable, "-c", program, str(SKILL / "scripts" / "findings.py"),
                     "merge", str(self.target), str(fragment)],
                    capture_output=True, text=True, check=False, timeout=10,
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn("refused:", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual(result.stdout, "")
                if existing:
                    self.assertEqual(self.target.read_bytes(), before)
                else:
                    self.assertFalse(self.target.exists())
                self.assertEqual({p.name for p in self.out.iterdir()},
                                 {"findings.json"} if existing else set())

    def test_replace_failure_preserves_record_and_cleans_staging_file(self):
        for existing in (False, True):
            with self.subTest(existing=existing):
                self.target.unlink(missing_ok=True)
                if existing:
                    self.write_json(self.target, complete_doc())
                before = self.target.read_bytes() if existing else None
                with patch("os.replace", side_effect=OSError("replacement failed")):
                    result, stdout, stderr = self.run_merge(complete_doc())
                self.assertEqual(result, 1)
                self.assertIn("replacement failed", stderr)
                self.assertEqual(stdout, "")
                if existing:
                    self.assertEqual(self.target.read_bytes(), before)
                else:
                    self.assertFalse(self.target.exists())
                self.assertEqual({p.name for p in self.out.iterdir()},
                                 {"findings.json"} if existing else set())

    @unittest.skipUnless(os.name == "posix", "requires POSIX permission modes")
    def test_replacement_preserves_existing_permission_mode(self):
        self.write_json(self.target, complete_doc())
        self.target.chmod(0o640)
        result, stdout, stderr = self.run_merge({"meta": {"project": "updated"}})
        self.assertEqual(result, 0, stderr)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o640)
        self.assertEqual(findings.read_json(self.target)["meta"]["project"], "updated")
        self.assertEqual({p.name for p in self.out.iterdir()}, {"findings.json"})

    @unittest.skipUnless(os.name == "posix", "requires POSIX permission modes")
    def test_new_record_uses_normal_creation_permissions(self):
        reference = self.tmp / "mode-reference"
        reference.write_bytes(b"reference")
        result, stdout, stderr = self.run_merge(complete_doc())
        self.assertEqual(result, 0, stderr)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode),
                         stat.S_IMODE(reference.stat().st_mode))

    @unittest.skipUnless(os.name == "posix", "requires symbolic links")
    def test_merge_preserves_symlink_and_updates_its_target(self):
        records = self.tmp / "records"
        records.mkdir()
        actual = records / "record.json"
        for existing in (False, True):
            with self.subTest(existing=existing):
                self.target.unlink(missing_ok=True)
                actual.unlink(missing_ok=True)
                if existing:
                    self.write_json(actual, complete_doc())
                self.target.symlink_to(Path("..") / "records" / actual.name)
                result, stdout, stderr = self.run_merge({"meta": {"project": "updated"}})
                self.assertEqual(result, 0, stderr)
                self.assertTrue(self.target.is_symlink())
                self.assertEqual(findings.read_json(actual)["meta"]["project"], "updated")
                if existing:
                    self.assertEqual(findings.read_json(actual)["findings"],
                                     complete_doc()["findings"])
                self.assertEqual({p.name for p in records.iterdir()}, {"record.json"})
                self.assertEqual({p.name for p in self.out.iterdir()}, {"findings.json"})


if __name__ == "__main__":
    unittest.main()
