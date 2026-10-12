"""Independent regressions for the units source used by inventory output checks."""

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import inventory  # noqa: E402


@unittest.skipUnless(inventory.SAFE_OUTPUT, "requires descriptor-relative output support")
class UnitsSourceSelectionTests(unittest.TestCase):
    def test_input_alias_retargeted_after_read_cannot_hide_source_collision(self):
        contents = (ROOT / "examples" / "units.sample.json").read_bytes()
        for alias_kind in ("file", "parent"):
            with self.subTest(alias=alias_kind), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                repo = base / "repo"
                repo.mkdir()
                original, replacement = base / "original", base / "replacement"
                original.mkdir()
                replacement.mkdir()
                source, other_source = original / "units.json", replacement / "units.json"
                source.write_bytes(contents)
                other_source.write_bytes(contents)
                alias = base / "selected"
                try:
                    alias.symlink_to(original if alias_kind == "parent" else source,
                                     target_is_directory=alias_kind == "parent")
                except (OSError, NotImplementedError):
                    self.skipTest("symlinks are not supported")
                selected = alias / "units.json" if alias_kind == "parent" else alias
                validate = inventory.check_units
                retargeted = False

                def retarget_after_read(data):
                    nonlocal retargeted
                    result = validate(data)
                    self.assertFalse(retargeted)
                    alias.unlink()
                    alias.symlink_to(replacement if alias_kind == "parent" else other_source,
                                     target_is_directory=alias_kind == "parent")
                    retargeted = True
                    return result

                errors = io.StringIO()
                with mock.patch.object(inventory, "check_units", side_effect=retarget_after_read), \
                        contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors):
                    status = inventory.main([str(repo), "--units", str(selected), "--out", str(source)])
                self.assertTrue(retargeted)
                self.assertEqual(source.read_bytes(), contents, "the originally read units source was overwritten")
                self.assertEqual(other_source.read_bytes(), contents)
                self.assertEqual(status, 2, errors.getvalue())
                self.assertIn("overwrite", errors.getvalue())
                self.assertNotIn("Traceback", errors.getvalue())

    def test_an_existing_hardlink_to_the_units_source_is_rejected(self):
        contents = (ROOT / "examples" / "units.sample.json").read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repo = base / "repo"
            repo.mkdir()
            source, output = base / "units.json", base / "inventory.json"
            source.write_bytes(contents)
            try:
                output.hardlink_to(source)
            except (OSError, NotImplementedError):
                self.skipTest("hardlinks are not supported")
            errors = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors):
                status = inventory.main([str(repo), "--units", str(source), "--out", str(output)])
            self.assertEqual(status, 2, errors.getvalue())
            self.assertIn("overwrite", errors.getvalue())
            self.assertEqual(source.read_bytes(), contents)
            self.assertEqual(output.read_bytes(), contents)
            self.assertTrue(output.samefile(source))

    def test_a_case_alias_of_the_units_source_is_rejected(self):
        contents = (ROOT / "examples" / "units.sample.json").read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repo = base / "repo"
            repo.mkdir()
            source, output = base / "Units.json", base / "units.json"
            source.write_bytes(contents)
            if not output.exists() or not output.samefile(source):
                self.skipTest("requires a case-insensitive filesystem")
            errors = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors):
                status = inventory.main([str(repo), "--units", str(source), "--out", str(output)])
            self.assertEqual(status, 2, errors.getvalue())
            self.assertIn("overwrite", errors.getvalue())
            self.assertEqual(source.read_bytes(), contents)
            self.assertEqual(output.read_bytes(), contents)


if __name__ == "__main__":
    unittest.main()
