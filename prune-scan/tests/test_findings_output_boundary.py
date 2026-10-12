"""Record updates must stay in the directory selected before reading inputs."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from test_findings_regressions import findings, record, units_record


@unittest.skipUnless(hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd,
                     "requires descriptor-relative output operations")
class RecordOutputBoundaryTests(unittest.TestCase):
    def exercise_swap(self, command, replacement, ancestor, timing):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            workspace, out = base / "workspace", base / "workspace" / "out"
            out.mkdir(parents=True)
            outside, saved = base / "outside", base / "selected"
            outside_out = outside / "out" if ancestor else outside
            outside_out.mkdir(parents=True)
            name = "units.json" if command == "units" else "findings.json"
            initial = units_record() if command == "units" else record()
            if command == "renumber":
                initial["findings"][0]["id"] = "P-009"
            target = out / name
            target.write_text(json.dumps(initial), encoding="utf-8")
            unrelated = units_record() if command == "units" else record()
            if command == "units":
                unrelated["app"] = "Unrelated application"
            else:
                unrelated["meta"]["project"] = "Unrelated repository"
            outside_bytes = json.dumps(unrelated).encode("utf-8")
            (outside_out / name).write_bytes(outside_bytes)
            fragment = base / "fragment.json"
            fragment.write_text(json.dumps({"app": "Updated application"} if command == "units"
                                           else {"summary": "Reviewed update"}), encoding="utf-8")
            selected_node = workspace if ancestor else out
            swapped = False

            def swap():
                nonlocal swapped
                if swapped:
                    return
                selected_node.rename(saved)
                if replacement == "symlink":
                    selected_node.symlink_to(outside, target_is_directory=True)
                else:
                    outside.rename(selected_node)
                swapped = True

            real_dump, real_load = findings.dump, findings.load_json

            def dump_and_swap(data):
                text = real_dump(data)
                swap()
                return text

            def load_after_swap(path, *args, **kwargs):
                if Path(path) == target:
                    swap()
                return real_load(path, *args, **kwargs)

            operation = "dump" if timing == "write" else "load_json"
            callback = dump_and_swap if timing == "write" else load_after_swap
            argv = [command, str(target)] + ([] if command == "renumber" else [str(fragment)])
            errors = io.StringIO()
            with mock.patch.object(findings, operation, side_effect=callback), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors):
                status = findings.main(argv)
            self.assertTrue(swapped)
            self.assertEqual(status, 0, errors.getvalue())
            self.assertEqual(target.read_bytes(), outside_bytes)
            selected = saved / "out" / name if ancestor else saved / name
            result = json.loads(selected.read_text(encoding="utf-8"))
            if command == "units":
                self.assertEqual(result["app"], "Updated application")
            else:
                self.assertEqual(result["meta"]["project"], "Example")
                if command == "renumber":
                    self.assertEqual(result["findings"][0]["id"], "P-001")
                else:
                    self.assertEqual(result["summary"], "Reviewed update")

    def test_updates_do_not_follow_output_parent_replacements(self):
        for command in ("merge", "units", "renumber"):
            for replacement in ("symlink", "directory"):
                for ancestor in (False, True):
                    with self.subTest(command=command, replacement=replacement, ancestor=ancestor):
                        self.exercise_swap(command, replacement, ancestor, "write")

    def test_updates_read_the_base_from_the_selected_directory(self):
        for command in ("merge", "units", "renumber"):
            with self.subTest(command=command):
                self.exercise_swap(command, "directory", True, "read")

    def test_directory_replacement_during_resolution_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            out, outside, saved = base / "out", base / "outside", base / "selected"
            out.mkdir()
            outside.mkdir()
            original = json.dumps(record()).encode("utf-8")
            target = out / "findings.json"
            target.write_bytes(original)
            replacement = b'{"unrelated":true}'
            (outside / target.name).write_bytes(replacement)
            fragment = base / "fragment.json"
            fragment.write_text('{"summary":"Reviewed update"}', encoding="utf-8")
            resolve = Path.resolve
            swapped = False

            def resolve_and_swap(path, *args, **kwargs):
                nonlocal swapped
                result = resolve(path, *args, **kwargs)
                if path == out and not swapped:
                    out.rename(saved)
                    outside.rename(out)
                    swapped = True
                return result

            errors = io.StringIO()
            with mock.patch.object(Path, "resolve", resolve_and_swap), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors):
                status = findings.main(["merge", str(target), str(fragment)])
            self.assertTrue(swapped)
            self.assertEqual(status, 2, errors.getvalue())
            self.assertIn("directory changed", errors.getvalue())
            self.assertEqual((saved / target.name).read_bytes(), original)
            self.assertEqual(target.read_bytes(), replacement)

    def test_updating_a_record_symlink_preserves_its_original_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            out = base / "out"
            out.mkdir()
            source, target = base / "original.json", out / "findings.json"
            original = json.dumps(record()).encode("utf-8")
            source.write_bytes(original)
            target.symlink_to(source)
            fragment = base / "fragment.json"
            fragment.write_text('{"summary":"Reviewed update"}', encoding="utf-8")
            errors = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors):
                status = findings.main(["merge", str(target), str(fragment)])
            self.assertEqual(status, 0, errors.getvalue())
            self.assertFalse(target.is_symlink())
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(json.loads(target.read_text(encoding="utf-8"))["summary"], "Reviewed update")

    def test_regular_updates_keep_working_without_descriptor_support(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            target, fragment = base / "findings.json", base / "fragment.json"
            target.write_text(json.dumps(record()), encoding="utf-8")
            fragment.write_text('{"summary":"Reviewed update"}', encoding="utf-8")
            with mock.patch.object(findings, "SAFE_OUTPUT", False), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                status = findings.main(["merge", str(target), str(fragment)])
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(target.read_text(encoding="utf-8"))["summary"], "Reviewed update")


if __name__ == "__main__":
    unittest.main()
