"""Repository-boundary and false-positive regressions found in the full review."""
import contextlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import inventory  # noqa: E402


class TraversalBoundaryTests(unittest.TestCase):
    def test_known_dependency_lockfiles_do_not_count_as_source_references(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("bun.lock", "npm-shrinkwrap.json", "Pipfile.lock"):
                (root / name).write_text('{"unused_function": "1"}\n', encoding="utf-8")
            (root / "unused.py").write_text("def unused_function():\n    pass\n", encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual(result["files_scanned"], 1)
            self.assertEqual([row["name"] for row in result["unreferenced_symbols"]], ["unused_function"])

    def test_binary_nul_after_the_first_eight_kilobytes_is_not_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "data.bin").write_bytes(b" " * 8192 + b"\0\n# deprecated binary-content\n")
            result = inventory.inventory(root)
            self.assertEqual(result["files_scanned"], 0)
            self.assertEqual(result["markers"], [])

    def test_extensionless_secret_files_are_not_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            names = ("secrets", "secret", ".secrets", ".secret", "app.secrets")
            for name in names:
                (root / name).write_text("deprecated private-secret-value\n", encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual(result["files_scanned"], 0)
            self.assertEqual(result["files_skipped"], len(names))
            self.assertNotIn("private-secret-value", json.dumps(result))

    def test_symlink_replacing_a_discovered_file_is_not_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = parent / "repo"
            root.mkdir()
            source = root / "ordinary.py"
            source.write_text("pass\n", encoding="utf-8")
            outside = parent / "private.py"
            outside.write_text("# deprecated outside-secret-value\n", encoding="utf-8")
            original = inventory.iter_files

            def swap_after_discovery(repo, **kwargs):
                for path in original(repo, **kwargs):
                    path.unlink()
                    try:
                        path.symlink_to(outside)
                    except (OSError, NotImplementedError):
                        self.skipTest("File symlinks are not supported")
                    yield path

            with mock.patch.object(inventory, "iter_files", side_effect=swap_after_discovery):
                result = inventory.inventory(root)
            self.assertEqual(result["files_scanned"], 0)
            self.assertNotIn("outside-secret-value", json.dumps(result))

    def test_symlink_replacing_a_discovered_parent_is_not_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root, outside = parent / "repo", parent / "private"
            (root / "src").mkdir(parents=True)
            outside.mkdir()
            (root / "src" / "ordinary.py").write_text("pass\n", encoding="utf-8")
            (outside / "ordinary.py").write_text("# deprecated outside-secret-value\n", encoding="utf-8")
            original = inventory.iter_files

            def swap_after_discovery(repo, **kwargs):
                for path in original(repo, **kwargs):
                    (root / "src").rename(root / "saved")
                    try:
                        (root / "src").symlink_to(outside, target_is_directory=True)
                    except (OSError, NotImplementedError):
                        self.skipTest("Directory symlinks are not supported")
                    yield path

            with mock.patch.object(inventory, "iter_files", side_effect=swap_after_discovery):
                result = inventory.inventory(root)
            self.assertEqual(result["files_scanned"], 0)
            self.assertNotIn("outside-secret-value", json.dumps(result))

    @unittest.skipUnless(inventory.SAFE_DIR_OPEN and hasattr(os, "fwalk"), "requires descriptor-relative walking")
    def test_directory_replacement_before_or_after_discovery_keeps_the_selected_repository(self):
        for replaced in ("root", "ancestor"):
            for timing in ("before", "after"):
                with self.subTest(replaced=replaced, timing=timing), tempfile.TemporaryDirectory() as tmp:
                    parent = Path(tmp)
                    workspace = parent / "workspace"
                    root = workspace / "repo"
                    root.mkdir(parents=True)
                    (root / "ordinary.py").write_text("def selected_function():\n    pass\n", encoding="utf-8")
                    original = inventory.iter_files

                    def replace_directory():
                        (root if replaced == "root" else workspace).rename(parent / "saved")
                        root.mkdir(parents=True)
                        (root / "ordinary.py").write_text("# deprecated outside-content\n", encoding="utf-8")
                        (root / "outside-name.py").write_text("# deprecated outside-content\n", encoding="utf-8")

                    def swap_at_discovery(repo, **kwargs):
                        if timing == "before":
                            replace_directory()
                        for path in original(repo, **kwargs):
                            if timing == "after":
                                replace_directory()
                            yield path

                    with mock.patch.object(inventory, "iter_files", side_effect=swap_at_discovery):
                        result = inventory.inventory(root)
                    self.assertNotIn("outside-content", json.dumps(result))
                    self.assertNotIn("outside-name", json.dumps(result))
                    self.assertEqual(result["files_scanned"], 1)
                    self.assertEqual(result["files_skipped"], 0)
                    self.assertEqual([row["name"] for row in result["unreferenced_symbols"]], ["selected_function"])

    def test_repository_replaced_during_resolution_is_an_argument_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = parent / "repo"
            root.mkdir()
            (root / "ordinary.py").write_text("pass\n", encoding="utf-8")
            output = parent / "inventory.json"
            original = Path.resolve
            replaced = False

            def swap_after_resolution(path, *args, **kwargs):
                nonlocal replaced
                resolved = original(path, *args, **kwargs)
                if path == root and not replaced:
                    replaced = True
                    root.rename(parent / "saved")
                    root.mkdir()
                    (root / "ordinary.py").write_text("# deprecated outside-content\n", encoding="utf-8")
                return resolved

            errors = io.StringIO()
            with mock.patch.object(Path, "resolve", swap_after_resolution), \
                    contextlib.redirect_stderr(errors), contextlib.redirect_stdout(io.StringIO()):
                status = inventory.main([str(root), "--out", str(output)])
            self.assertTrue(replaced)
            self.assertEqual(status, 2)
            self.assertNotIn("Traceback", errors.getvalue())
            self.assertFalse(output.exists())

    @unittest.skipUnless(inventory.SAFE_DIR_OPEN and hasattr(os, "fwalk"), "requires descriptor-relative walking")
    def test_source_stays_pinned_if_repository_changes_just_before_file_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = parent / "repo"
            root.mkdir()
            selected = "def selected_function():\n    pass\n"
            (root / "ordinary.py").write_text(selected, encoding="utf-8")
            original = inventory.read_file
            read_texts = []

            def swap_before_read(path, repo, **kwargs):
                root.rename(parent / "saved")
                root.mkdir()
                (root / "ordinary.py").write_text("# deprecated outside-content\n", encoding="utf-8")
                result = original(path, repo, **kwargs)
                read_texts.append(result[0])
                return result

            with mock.patch.object(inventory, "read_file", side_effect=swap_before_read):
                result = inventory.inventory(root)
            self.assertEqual(read_texts, [selected])
            self.assertNotIn("outside-content", json.dumps(result))
            self.assertEqual(result["files_scanned"], 1)

    def test_directory_replacement_is_rejected_without_descriptor_relative_walking(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = parent / "repo"
            root.mkdir()
            (root / "ordinary.py").write_text("pass\n", encoding="utf-8")
            original = inventory.iter_files

            def swap_after_discovery(repo, **kwargs):
                for path in original(repo, **kwargs):
                    root.rename(parent / "saved")
                    root.mkdir()
                    (root / "ordinary.py").write_text("# deprecated outside-content\n", encoding="utf-8")
                    yield path

            with mock.patch.object(inventory, "SAFE_DIR_OPEN", False), \
                    mock.patch.object(inventory, "iter_files", side_effect=swap_after_discovery):
                with self.assertRaises(OSError):
                    inventory.inventory(root)

    @unittest.skipUnless(inventory.SAFE_DIR_OPEN, "requires descriptor-relative directory opens")
    def test_symlink_replacing_a_repository_root_ancestor_is_not_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            workspace, outside = parent / "workspace", parent / "private"
            root = workspace / "repo"
            root.mkdir(parents=True)
            (outside / "repo").mkdir(parents=True)
            (root / "ordinary.py").write_text("pass\n", encoding="utf-8")
            (outside / "repo" / "ordinary.py").write_text(
                "# deprecated outside-secret-value\n", encoding="utf-8")
            original = inventory.iter_files

            def swap_after_discovery(repo, **kwargs):
                for path in original(repo, **kwargs):
                    workspace.rename(parent / "saved")
                    try:
                        workspace.symlink_to(outside, target_is_directory=True)
                    except (OSError, NotImplementedError):
                        self.skipTest("Directory symlinks are not supported")
                    yield path

            with mock.patch.object(inventory, "iter_files", side_effect=swap_after_discovery):
                result = inventory.inventory(root)
            self.assertNotIn("outside-secret-value", json.dumps(result))
            self.assertEqual(result["files_scanned"], 1)
            self.assertEqual(result["files_skipped"], 0)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes require POSIX")
    def test_fifo_replacing_a_discovered_file_does_not_wait_for_a_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            program = '''import json, os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import inventory
root = Path(sys.argv[2])
source = root / "ordinary.py"
source.write_text("pass\\n", encoding="utf-8")
original = inventory.iter_files
def swapped(repo, **kwargs):
    for path in original(repo, **kwargs):
        path.unlink()
        os.mkfifo(path)
        yield path
inventory.iter_files = swapped
print(json.dumps(inventory.inventory(root)))
'''
            result = subprocess.run([sys.executable, "-c", program, str(SCRIPTS), tmp],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)["files_scanned"], 0)

    def test_file_growth_after_the_size_check_still_obeys_the_byte_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "ordinary.py"
            source.write_text("# deprecated marker\n", encoding="utf-8")
            original_stat, original_fstat = Path.stat, os.fstat
            grown = False

            def grow_after_check(info):
                nonlocal grown
                if stat.S_ISREG(info.st_mode) and not grown:
                    grown = True
                    with source.open("ab") as handle:
                        handle.write(b"x" * 128)
                return info

            def path_stat(path, *args, **kwargs):
                return grow_after_check(original_stat(path, *args, **kwargs))

            def file_stat(fd):
                return grow_after_check(original_fstat(fd))

            with mock.patch.object(inventory, "MAX_BYTES", 64), \
                    mock.patch.object(inventory, "iter_files", return_value=iter([source])), \
                    mock.patch.object(Path, "stat", path_stat), \
                    mock.patch.object(inventory.os, "fstat", side_effect=file_stat):
                result = inventory.inventory(root)
            self.assertTrue(grown)
            self.assertEqual(result["files_scanned"], 0)
            self.assertEqual(result["markers"], [])


class StructuredInputTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "surrogateescape filenames require POSIX")
    def test_non_utf8_filenames_are_skipped_without_aborting_the_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = parent / "repo"
            root.mkdir()
            (root / "ordinary.py").write_text("def uncalled():\n    pass\n", encoding="utf-8")
            with open(os.fsencode(root) + b"/helper-\xff.py", "wb") as handle:
                handle.write(b"# deprecated unreadable-name\n")
            output = parent / "inventory.json"
            with contextlib.redirect_stdout(io.StringIO()):
                status = inventory.main([str(root), "--out", str(output)])
            self.assertEqual(status, 0)
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["files_scanned"], 1)
            self.assertEqual(result["files_skipped"], 1)
            self.assertEqual([row["name"] for row in result["unreferenced_symbols"]], ["uncalled"])

    @unittest.skipUnless(os.name == "posix", "surrogateescape filenames require POSIX")
    def test_non_utf8_repository_name_is_escaped_in_its_display_label(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = Path(os.fsdecode(os.fsencode(parent) + b"/repo-\xff"))
            root.mkdir()
            (root / "ordinary.py").write_text("def uncalled():\n    pass\n", encoding="utf-8")
            output = parent / "inventory.json"
            with contextlib.redirect_stdout(io.StringIO()):
                status = inventory.main([str(root), "--out", str(output)])
            self.assertEqual(status, 0)
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["repository"], "repo-\\udcff")
            self.assertEqual(result["files_scanned"], 1)

    def test_output_parent_symlink_loop_is_an_argument_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = parent / "repo"
            root.mkdir()
            units = parent / "units.json"
            contents = (ROOT / "examples" / "units.sample.json").read_bytes()
            units.write_bytes(contents)
            loop = parent / "loop"
            try:
                loop.symlink_to(loop.name, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("Directory symlinks are not supported")
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors), contextlib.redirect_stdout(io.StringIO()):
                status = inventory.main([str(root), "--out", str(loop / "inventory.json"), "--units", str(units)])
            self.assertEqual(status, 2)
            self.assertIn("--out", errors.getvalue())
            self.assertNotIn("Traceback", errors.getvalue())
            self.assertEqual(units.read_bytes(), contents)

    def test_output_cannot_replace_the_units_input_through_path_aliases(self):
        for alias in ("same", "input-symlink", "parent-symlink"):
            with self.subTest(alias=alias), tempfile.TemporaryDirectory() as tmp:
                parent = Path(tmp)
                root = parent / "repo"
                root.mkdir()
                source = parent / "units.json"
                contents = (ROOT / "examples" / "units.sample.json").read_bytes()
                source.write_bytes(contents)
                units, output = source, source
                try:
                    if alias == "input-symlink":
                        units = parent / "input.json"
                        units.symlink_to(source)
                    elif alias == "parent-symlink":
                        linked = parent / "linked"
                        linked.symlink_to(parent, target_is_directory=True)
                        output = linked / "units.json"
                except (OSError, NotImplementedError):
                    self.skipTest("Symlinks are not supported")
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors), contextlib.redirect_stdout(io.StringIO()):
                    status = inventory.main([str(root), "--out", str(output), "--units", str(units)])
                self.assertEqual(status, 2)
                self.assertIn("overwrite", errors.getvalue())
                self.assertEqual(source.read_bytes(), contents)

    def test_replacing_an_output_symlink_preserves_its_units_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = parent / "repo"
            root.mkdir()
            source, output = parent / "units.json", parent / "inventory.json"
            contents = (ROOT / "examples" / "units.sample.json").read_bytes()
            source.write_bytes(contents)
            try:
                output.symlink_to(source)
            except (OSError, NotImplementedError):
                self.skipTest("File symlinks are not supported")
            with contextlib.redirect_stdout(io.StringIO()):
                status = inventory.main([str(root), "--out", str(output), "--units", str(source)])
            self.assertEqual(status, 0)
            self.assertFalse(output.is_symlink())
            self.assertEqual(source.read_bytes(), contents)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["tool"], "inventory.py")

    def test_invalid_json_data_cannot_break_utf8_inventory_output(self):
        fixtures = (
            ("package.json", '{"dependencies":{"\\ud800":"1"}}'),
            ("package.json", '{"dependencies":{"unused":"1"},"dependencies":{}}'),
            ("locales/en.json", '{"\\ud800":"translation"}'),
            ("locales/en.json", '{"key":"first","key":"second"}'),
        )
        for filename, content in fixtures:
            with self.subTest(filename=filename, content=content), tempfile.TemporaryDirectory() as tmp:
                parent = Path(tmp)
                root = parent / "repo"
                target = root / filename
                target.parent.mkdir(parents=True)
                target.write_text(content, encoding="utf-8")
                (root / "unused.py").write_text("def uncalled():\n    pass\n", encoding="utf-8")
                output = parent / "inventory.json"
                with contextlib.redirect_stdout(io.StringIO()):
                    status = inventory.main([str(root), "--out", str(output)])
                self.assertEqual(status, 0)
                result = json.loads(output.read_text(encoding="utf-8"))
                self.assertEqual([row["name"] for row in result["unreferenced_symbols"]], ["uncalled"])
                self.assertEqual(result["i18n_unreferenced"], [])
                self.assertEqual(result["unimported_dependencies"], [])

    def test_nonstring_package_entries_do_not_become_removal_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(json.dumps({
                "scripts": {"valid": "echo task", "invalid": None},
                "dependencies": {"real-package": "1", "invalid-package": {"version": "1"}},
            }), encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual([row["name"] for row in result["scripts"]], ["valid"])
            self.assertEqual([row["name"] for row in result["unimported_dependencies"]], ["real-package"])


class OutputBoundaryTests(unittest.TestCase):
    @unittest.skipUnless(inventory.SAFE_OUTPUT, "Descriptor-relative output is not supported")
    def test_output_parent_replacement_during_scan_cannot_redirect_the_write(self):
        for level in ("parent", "ancestor"):
            for replacement in ("symlink", "directory"):
                with self.subTest(level=level, replacement=replacement), tempfile.TemporaryDirectory() as tmp:
                    base = Path(tmp)
                    root = base / "repo"
                    root.mkdir()
                    units_parent = base / "source-tree" / "reports"
                    output_parent = base / "output-tree" / "reports"
                    units_parent.mkdir(parents=True)
                    output_parent.mkdir(parents=True)
                    source = units_parent / "units.json"
                    contents = (ROOT / "examples" / "units.sample.json").read_bytes()
                    source.write_bytes(contents)
                    output = output_parent / source.name
                    output.write_text("previous inventory", encoding="utf-8")
                    selected = output_parent if level == "parent" else output_parent.parent
                    moved = selected.with_name(selected.name + "-original")
                    actual_output = moved / (output.name if level == "parent" else "reports/" + output.name)
                    scan = inventory.inventory

                    def swap_during_scan(*args, **kwargs):
                        result = scan(*args, **kwargs)
                        selected.rename(moved)
                        if replacement == "symlink":
                            target = units_parent if level == "parent" else units_parent.parent
                            try:
                                selected.symlink_to(target, target_is_directory=True)
                            except (OSError, NotImplementedError):
                                self.skipTest("Directory symlinks are not supported")
                        else:
                            output_parent.mkdir(parents=True)
                            output.write_text("replacement inventory", encoding="utf-8")
                        return result

                    with mock.patch.object(inventory, "inventory", side_effect=swap_during_scan), \
                            contextlib.redirect_stdout(io.StringIO()):
                        status = inventory.main([str(root), "--out", str(output), "--units", str(source)])
                    self.assertEqual(status, 0)
                    self.assertEqual(source.read_bytes(), contents)
                    if replacement == "directory":
                        self.assertEqual(output.read_text(encoding="utf-8"), "replacement inventory")
                    self.assertEqual(json.loads(actual_output.read_text(encoding="utf-8"))["tool"], "inventory.py")

    @unittest.skipUnless(inventory.SAFE_OUTPUT, "Descriptor-relative output is not supported")
    def test_output_parent_replaced_during_resolution_is_rejected(self):
        for level in ("parent", "ancestor"):
            for replacement in ("symlink", "directory"):
                with self.subTest(level=level, replacement=replacement), tempfile.TemporaryDirectory() as tmp:
                    base = Path(tmp)
                    root = base / "repo"
                    root.mkdir()
                    output_parent = base / "output-tree" / "reports"
                    output_parent.mkdir(parents=True)
                    output = output_parent / "inventory.json"
                    source = base / "units.json"
                    contents = (ROOT / "examples" / "units.sample.json").read_bytes()
                    source.write_bytes(contents)
                    selected = output_parent if level == "parent" else output_parent.parent
                    moved = selected.with_name(selected.name + "-original")
                    resolve = Path.resolve
                    swapped = False

                    def swap_during_resolution(path, *args, **kwargs):
                        nonlocal swapped
                        result = resolve(path, *args, **kwargs)
                        if path == output_parent and not swapped:
                            swapped = True
                            selected.rename(moved)
                            if replacement == "symlink":
                                try:
                                    selected.symlink_to(moved, target_is_directory=True)
                                except (OSError, NotImplementedError):
                                    self.skipTest("Directory symlinks are not supported")
                            else:
                                output_parent.mkdir(parents=True)
                        return result

                    errors = io.StringIO()
                    with mock.patch.object(Path, "resolve", swap_during_resolution), \
                            contextlib.redirect_stderr(errors), contextlib.redirect_stdout(io.StringIO()):
                        status = inventory.main([str(root), "--out", str(output), "--units", str(source)])
                    self.assertEqual(status, 2)
                    self.assertIn("--out", errors.getvalue())
                    self.assertNotIn("Traceback", errors.getvalue())
                    self.assertEqual(source.read_bytes(), contents)
                    self.assertFalse(output.exists())

    @unittest.skipUnless(inventory.SAFE_OUTPUT, "Descriptor-relative output is not supported")
    def test_an_existing_output_parent_alias_can_change_without_redirecting_the_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root, selected, outside = base / "repo", base / "selected", base / "outside"
            root.mkdir()
            selected.mkdir()
            outside.mkdir()
            alias = base / "alias"
            try:
                alias.symlink_to(selected, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("Directory symlinks are not supported")
            source = outside / "units.json"
            contents = (ROOT / "examples" / "units.sample.json").read_bytes()
            source.write_bytes(contents)
            scan = inventory.inventory

            def change_alias(*args, **kwargs):
                result = scan(*args, **kwargs)
                alias.unlink()
                alias.symlink_to(outside, target_is_directory=True)
                return result

            with mock.patch.object(inventory, "inventory", side_effect=change_alias), \
                    contextlib.redirect_stdout(io.StringIO()):
                status = inventory.main([str(root), "--out", str(alias / source.name), "--units", str(source)])
            self.assertEqual(status, 0)
            self.assertEqual(source.read_bytes(), contents)
            self.assertEqual(json.loads((selected / source.name).read_text(encoding="utf-8"))["tool"], "inventory.py")

    @unittest.skipUnless(inventory.SAFE_OUTPUT, "Descriptor-relative output is not supported")
    def test_output_commit_and_failure_cleanup_keep_the_pinned_parent(self):
        for fail in (False, True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                root = base / "repo"
                root.mkdir()
                source_parent, output_parent = base / "sources", base / "output"
                source_parent.mkdir()
                output_parent.mkdir()
                source = source_parent / "units.json"
                contents = (ROOT / "examples" / "units.sample.json").read_bytes()
                source.write_bytes(contents)
                output = output_parent / source.name
                output.write_text("previous inventory", encoding="utf-8")
                moved = base / "original-output"
                replace, open_file = os.replace, os.open
                descriptors = []

                def record_open(*args, **kwargs):
                    descriptor = open_file(*args, **kwargs)
                    descriptors.append(descriptor)
                    return descriptor

                def swap_before_replace(*args, **kwargs):
                    output_parent.rename(moved)
                    try:
                        output_parent.symlink_to(source_parent, target_is_directory=True)
                    except (OSError, NotImplementedError):
                        self.skipTest("Directory symlinks are not supported")
                    if fail:
                        raise OSError("injected commit failure")
                    return replace(*args, **kwargs)

                with mock.patch.object(os, "open", side_effect=record_open), \
                        mock.patch.object(os, "replace", side_effect=swap_before_replace), \
                        contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    status = inventory.main([str(root), "--out", str(output), "--units", str(source)])
                self.assertEqual(status, 1 if fail else 0)
                self.assertEqual(source.read_bytes(), contents)
                self.assertEqual(sorted(path.name for path in moved.iterdir()), [output.name])
                self.assertEqual(sorted(path.name for path in source_parent.iterdir()), [source.name])
                if fail:
                    self.assertEqual((moved / output.name).read_text(encoding="utf-8"), "previous inventory")
                else:
                    self.assertEqual(json.loads((moved / output.name).read_text(encoding="utf-8"))["tool"],
                                     "inventory.py")
                for descriptor in set(descriptors):
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)

    @unittest.skipUnless(inventory.SAFE_OUTPUT, "Descriptor-relative output is not supported")
    def test_output_permissions_are_private_for_new_files_and_preserved_for_existing_files(self):
        for mode in (None, 0o640):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                root = base / "repo"
                root.mkdir()
                output = base / "inventory.json"
                if mode is not None:
                    output.write_text("previous inventory", encoding="utf-8")
                    output.chmod(mode)
                with contextlib.redirect_stdout(io.StringIO()):
                    status = inventory.main([str(root), "--out", str(output)])
                self.assertEqual(status, 0)
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600 if mode is None else mode)

    def test_unsupported_output_runtime_keeps_untagged_scans_and_refuses_units(self):
        for tagged in (False, True):
            with self.subTest(tagged=tagged), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                root = base / "repo"
                root.mkdir()
                source, output = base / "units.json", base / "inventory.json"
                contents = (ROOT / "examples" / "units.sample.json").read_bytes()
                source.write_bytes(contents)
                argv = [str(root), "--out", str(output)]
                if tagged:
                    argv += ["--units", str(source)]
                errors = io.StringIO()
                with mock.patch.object(inventory, "SAFE_OUTPUT", False), \
                        mock.patch.object(inventory, "write_output", wraps=inventory.write_output) as fallback, \
                        contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors):
                    status = inventory.main(argv)
                self.assertEqual(status, 2 if tagged else 0)
                self.assertEqual(source.read_bytes(), contents)
                if tagged:
                    self.assertIn("--units requires descriptor-relative output support", errors.getvalue())
                    self.assertFalse(output.exists())
                    fallback.assert_not_called()
                else:
                    fallback.assert_called_once()
                    self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["tool"], "inventory.py")

    @unittest.skipUnless(inventory.SAFE_OUTPUT, "Descriptor-relative output is not supported")
    def test_invalid_units_close_both_selected_descriptors(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "repo"
            root.mkdir()
            source, output = base / "units.json", base / "inventory.json"
            source.write_text('{"units": [], "units": []}', encoding="utf-8")
            open_file, descriptors = os.open, []

            def record_open(*args, **kwargs):
                descriptor = open_file(*args, **kwargs)
                descriptors.append(descriptor)
                return descriptor

            errors = io.StringIO()
            with mock.patch.object(os, "open", side_effect=record_open), \
                    contextlib.redirect_stderr(errors), contextlib.redirect_stdout(io.StringIO()):
                status = inventory.main([str(root), "--out", str(output), "--units", str(source)])
            self.assertEqual(status, 2)
            self.assertIn("duplicate JSON key", errors.getvalue())
            self.assertFalse(output.exists())
            for descriptor in set(descriptors):
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    @unittest.skipUnless(inventory.SAFE_OUTPUT and hasattr(os, "mkfifo"), "POSIX FIFO checks are not supported")
    def test_units_fifo_is_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "repo"
            root.mkdir()
            source, output = base / "units.json", base / "inventory.json"
            os.mkfifo(source)
            result = subprocess.run([sys.executable, str(SCRIPTS / "inventory.py"), str(root),
                                     "--out", str(output), "--units", str(source)],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertIn("expected a regular JSON file", result.stderr)
            self.assertFalse(output.exists())


class ConservativeCandidateTests(unittest.TestCase):
    def test_go_import_comments_do_not_hide_registration_dependencies(self):
        imports = ('import _ "github.com/lib/pq" // Register the database driver.\n',
                   'import (\n    _ "github.com/lib/pq" // Register the database driver.\n)\n',
                   'import _ "github.com/lib/pq"\r\n')
        for source in imports:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "go.mod").write_text(
                    "module example.com/app\nrequire github.com/lib/pq v1.10.9\n", encoding="utf-8")
                (root / "main.go").write_text("package main\n" + source, encoding="utf-8")
                result = inventory.inventory(root)
                self.assertEqual(result["unimported_dependencies"], [])

    def test_comments_inside_parenthesized_python_imports_do_not_hide_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pkg").mkdir()
            (root / "pkg" / "main.py").write_text(
                "from . import (\n    helper_one, # first helper\n    # a comment with ) punctuation\n"
                "    helper_two,\n)\n", encoding="utf-8")
            for name in ("helper_one", "helper_two"):
                (root / "pkg" / f"{name}.py").write_text("pass\n", encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual(result["orphan_files"], [])

    def test_python_distribution_names_and_import_alias_whitespace_count_as_uses(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("attrs\nrequests\n", encoding="utf-8")
            (root / "main.py").write_text("import attrs\nimport requests\tas\tclient\n", encoding="utf-8")
            (root / "pkg").mkdir()
            (root / "pkg" / "main.py").write_text("from . import helper\tas\tlocal\n", encoding="utf-8")
            (root / "pkg" / "helper.py").write_text("pass\n", encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual(result["unimported_dependencies"], [])
            self.assertEqual(result["orphan_files"], [])

    def test_dependency_replacements_and_purposes_stay_in_their_ecosystem(self):
        manifests = (
            ("Cargo.toml", '[dependencies]\nuuid = "1"\nnanoid = "1"\n'),
            ("package.json", json.dumps({"dependencies": {"six": "1", "mock": "1", "pytest": "1", "nose": "1"}})),
            ("requirements.txt", "uuid\nnanoid\nnode-fetch\n"),
        )
        for filename, contents in manifests:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / filename).write_text(contents, encoding="utf-8")
                result = inventory.inventory(root)
                self.assertEqual(result["platform_replaceable"], [])
                self.assertEqual(result["duplicate_purpose"], [])

    def test_npm_start_hooks_account_for_the_implicit_server_entrypoint(self):
        for server in ("server.js", "server.ts"):
            with self.subTest(server=server), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                package = root / "packages" / "server"
                package.mkdir(parents=True)
                (package / "package.json").write_text(json.dumps({
                    "scripts": {"prestart": "echo before", "poststart": "echo after"},
                }), encoding="utf-8")
                (package / server).write_text('console.log("ready");\n', encoding="utf-8")
                result = inventory.inventory(root)
                expected = [] if server == "server.js" else ["prestart", "poststart"]
                self.assertEqual([row["name"] for row in result["uninvoked_scripts"]], expected)

    def test_absolute_imports_can_resolve_from_a_python_script_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "server").mkdir()
            (root / "server" / "main.py").write_text("import helpers\n", encoding="utf-8")
            (root / "server" / "helpers.py").write_text("pass\n", encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual(result["orphan_files"], [])

    def test_go_dot_and_blank_imports_keep_their_declared_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "go.mod").write_text(
                "module example.com/app\nrequire (\nexample.com/dot v1.0.0\nexample.com/blank v1.0.0\n)\n",
                encoding="utf-8")
            (root / "main.go").write_text(
                'package main\nimport (\n. "example.com/dot"\n_ "example.com/blank"\n)\n', encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual(result["unimported_dependencies"], [])

    def test_go_block_comments_around_import_specs_keep_used_dependencies(self):
        declarations = (
            'import _ "example.com/plugin" /* registers plugin */\n',
            'import _ `example.com/plugin` /* registers plugin */\n',
            'import ( /* registration */ _ `example.com/plugin` /* plugin */ )\n',
            '/* registration */ import /* optional name */ _ /* plugin */ "example.com/plugin"\n',
            'import (\n/* registration */ _ /* plugin */ "example.com/plugin" /* registers plugin */\n)\n',
            'import /* documentation\ncontinued */ _ "example.com/plugin" /* registration\ncontinued */\n',
        )
        for declaration in declarations:
            with self.subTest(declaration=declaration), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "go.mod").write_text(
                    "module example.com/app\nrequire example.com/plugin v1.0.0\n", encoding="utf-8")
                (root / "main.go").write_text("package main\n" + declaration, encoding="utf-8")
                self.assertEqual(inventory.inventory(root)["unimported_dependencies"], [])

    def test_commented_go_imports_do_not_count_as_dependency_uses(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "go.mod").write_text(
                "module example.com/app\nrequire example.com/unused v1.0.0\n", encoding="utf-8")
            (root / "main.go").write_text(
                'package main\n/*\nimport _ "example.com/unused"\n*/\n', encoding="utf-8")
            rows = inventory.inventory(root)["unimported_dependencies"]
            self.assertEqual([row["name"] for row in rows], ["example.com/unused"])

    def test_go_literal_contents_do_not_count_as_import_declarations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "go.mod").write_text(
                "module example.com/app\nrequire example.com/unused v1.0.0\n", encoding="utf-8")
            (root / "main.go").write_text(
                'package main\nconst example = `\nimport _ "example.com/unused"\n`\n', encoding="utf-8")
            rows = inventory.inventory(root)["unimported_dependencies"]
            self.assertEqual([row["name"] for row in rows], ["example.com/unused"])

    def test_go_import_paths_decode_raw_and_interpreted_string_literals(self):
        literals = ('`example.com/plu\rgin`', r'"example.com\x2fplugin"',
                    r'"example.com\057plugin"', r'"example.com/\u0070lugin"')
        for literal in literals:
            with self.subTest(literal=literal), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "go.mod").write_text(
                    "module example.com/app\nrequire example.com/plugin v1.0.0\n", encoding="utf-8")
                (root / "main.go").write_text("package main\nimport\n_ " + literal + "\n", encoding="utf-8")
                self.assertEqual(inventory.inventory(root)["unimported_dependencies"], [])

    def test_go_import_paths_accept_plus_and_tilde(self):
        for package in ("a+b", "a~b"):
            with self.subTest(package=package), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "go.mod").write_text(
                    "module example.com/app\nrequire example.com/plugin v1.0.0\n", encoding="utf-8")
                (root / "main.go").write_text(
                    f'package main\nimport _ "example.com/plugin/{package}"\n', encoding="utf-8")
                self.assertEqual(inventory.inventory(root)["unimported_dependencies"], [])

    def test_invalid_go_unicode_escapes_do_not_stop_the_scan(self):
        literals = (r'"example.com/plugin/\UFFFFFFFF"', r'"example.com/plugin/\U80000000"',
                    r'"example.com/plugin/\U00110000"', r'"example.com/plugin/\uD800"')
        for literal in literals:
            with self.subTest(literal=literal), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "go.mod").write_text(
                    "module example.com/app\nrequire example.com/plugin v1.0.0\n", encoding="utf-8")
                (root / "main.go").write_text("package main\nimport _ " + literal + "\n", encoding="utf-8")
                rows = inventory.inventory(root)["unimported_dependencies"]
                self.assertEqual([row["name"] for row in rows], ["example.com/plugin"])

    def test_unterminated_go_literals_and_comments_have_bounded_scan_time(self):
        program = r'''import sys
sys.path.insert(0, sys.argv[1])
import inventory
for opening in ('"', "'"):
    source = opening + ('\\' + opening) * 65536
    assert list(inventory.go_import_paths(source)) == []
source = "/* \n" * 65536
assert list(inventory.go_import_paths(source)) == []
'''
        result = subprocess.run([sys.executable, "-c", program, str(SCRIPTS)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_test_importer_locations_obey_the_per_row_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "candidate.ts").write_text("export default 1;\n", encoding="utf-8")
            for index in range(inventory.MAX_LOCATIONS + 3):
                (root / f"test_{index}.ts").write_text('import "./candidate";\n', encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual(result["orphan_files"], [{
                "path": "candidate.ts",
                "test_importers": [f"test_{index}.ts" for index in range(inventory.MAX_LOCATIONS)],
            }])

    def test_large_source_keeps_locations_and_full_counts_before_truncation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            total = 1500
            (root / "bulk.py").write_text(
                "".join(f"def unused_{index}():\n    pass\n\n" for index in range(total)), encoding="utf-8")
            result = inventory.inventory(root)
            rows = result["unreferenced_symbols"]
            self.assertEqual(len(rows), inventory.MAX_ROWS)
            self.assertEqual([row["location"] for row in rows],
                             [f"bulk.py:{index * 3 + 1}" for index in range(inventory.MAX_ROWS)])
            self.assertEqual(result["truncated"]["unreferenced_symbols"], total - inventory.MAX_ROWS)

    def test_multiline_python_decorators_are_registration_uses(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "handlers.py").write_text(
                '@router.get(\n    "/example",\n)\ndef registered():\n    pass\n\n'
                '@register(\n    name="listener",\n)\nclass Listener:\n    pass\n\n'
                'def uncalled():\n    pass\n', encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual([row["name"] for row in result["unreferenced_symbols"]], ["uncalled"])
            self.assertEqual(result["decorated_symbols_skipped"], 2)

    def test_python_docstring_examples_are_not_real_definitions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "helpers.py").write_text(
                '\"\"\"Example:\ndef documented_example():\n    pass\n\"\"\"\n\n'
                'def uncalled():\n    pass\n', encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual([row["name"] for row in result["unreferenced_symbols"]], ["uncalled"])

    def test_typescript_imports_resolve_emitted_javascript_extensions(self):
        for imported, source in (("feature.js", "feature.ts"), ("view.jsx", "view.tsx"),
                                 ("esm.mjs", "esm.mts"), ("common.cjs", "common.cts")):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "main.ts").write_text(f'import "./{imported}";\n', encoding="utf-8")
                (root / source).write_text("export default 1;\n", encoding="utf-8")
                result = inventory.inventory(root)
                self.assertEqual(result["orphan_files"], [])

    def test_mts_and_cts_sources_are_scanned_and_declarations_are_not_orphans(self):
        for extension in ("mts", "cts"):
            with self.subTest(extension=extension), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / f"unused.{extension}").write_text("export function uncalled() {}\n", encoding="utf-8")
                (root / f"types.d.{extension}").write_text("export type Data = string;\n", encoding="utf-8")
                result = inventory.inventory(root)
                self.assertIn("uncalled", [row["name"] for row in result["unreferenced_symbols"]])
                self.assertEqual([row["path"] for row in result["orphan_files"]], [f"unused.{extension}"])

    def test_sass_and_less_css_modules_are_not_static_css_candidates(self):
        for extension in ("css", "scss", "sass", "less", "styl", "pcss"):
            with self.subTest(extension=extension), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / f"component.module.{extension}").write_text(".module-class { color: red; }\n", encoding="utf-8")
                (root / "styles.css").write_text(".unused-class { color: red; }\n", encoding="utf-8")
                result = inventory.inventory(root)
                self.assertEqual([row["class"] for row in result["css_unreferenced"]], ["unused-class"])

    def test_install_pack_and_publish_lifecycle_hooks_need_no_explicit_invocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hooks = ("preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare",
                     "postprepare", "prepublishOnly", "prepack", "postpack", "publish", "postpublish",
                     "dependencies", "preversion", "version", "postversion")
            (root / "package.json").write_text(json.dumps({
                "scripts": {name: "echo task" for name in (*hooks, "uninvoked-task")},
            }), encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual([row["name"] for row in result["uninvoked_scripts"]], ["uninvoked-task"])

    def test_relative_unit_prefixes_are_normalized_before_matching(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src" / "nested").mkdir(parents=True)
            (root / "src" / "nested" / "unused.py").write_text("def uncalled():\n    pass\n", encoding="utf-8")
            units = {"units": [
                {"id": "UN-01", "paths": ["."]},
                {"id": "UN-02", "paths": ["./src//nested/./"]},
            ]}
            result = inventory.inventory(root, units=units)
            self.assertEqual(result["unreferenced_symbols"][0]["unit"], "UN-02")
            self.assertEqual(result["orphan_files"][0]["unit"], "UN-02")


if __name__ == "__main__":
    unittest.main()
