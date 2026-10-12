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

            def swap_after_discovery(repo):
                for path in original(repo):
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

            def swap_after_discovery(repo):
                for path in original(repo):
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

            def swap_after_discovery(repo):
                for path in original(repo):
                    workspace.rename(parent / "saved")
                    try:
                        workspace.symlink_to(outside, target_is_directory=True)
                    except (OSError, NotImplementedError):
                        self.skipTest("Directory symlinks are not supported")
                    yield path

            with mock.patch.object(inventory, "iter_files", side_effect=swap_after_discovery):
                result = inventory.inventory(root)
            self.assertNotIn("outside-secret-value", json.dumps(result))
            self.assertEqual(result["files_scanned"], 0)
            self.assertEqual(result["files_skipped"], 1)

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
def swapped(repo):
    for path in original(repo):
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
