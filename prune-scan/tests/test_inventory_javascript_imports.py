"""JavaScript import scans must remain conservative and bounded on large source files."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import inventory  # noqa: E402


class JavaScriptImportTests(unittest.TestCase):
    def assert_referenced_helper_is_kept(self, source, extension=".ts"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            if extension in (".vue", ".svelte", ".html"):
                source = f'<script type="module">\n{source}\n</script>\n'
            (root / f"main{extension}").write_text(source, encoding="utf-8")
            (root / "helper.ts").write_text("export const value = 1;\n", encoding="utf-8")
            (root / "unused.ts").write_text("export default 1;\n", encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual(result["orphan_files"], [{"path": "unused.ts", "test_importers": []}])

    def test_import_and_reexport_forms_keep_referenced_modules_in_scripts(self):
        statements = (
            'import value from "./helper";',
            '\ufeffimport value from "./helper";',
            'import\ufeffvalue\ufefffrom\ufeff"./helper";',
            'import { value as selected } from "./helper";',
            'import * as values from "./helper";',
            'import type { Value } from "./helper";',
            'import type Value from "./helper";',
            'import type from "./helper";',
            'import from from "./helper";',
            'import \u03c0 from "./helper";',
            r'import \u0068 from "./helper";',
            r'import \u{68} from "./helper";',
            'import { type Value, type as alias } from "./helper";',
            'export { value } from "./helper";',
            'export * from "./helper";',
            'export * as helpers from "./helper";',
            'export type { Value } from "./helper";',
            'import "./helper";',
            'const value = require("./helper");',
            'const value = import("./helper");',
        )
        for extension in (".ts", ".vue", ".svelte", ".html"):
            for statement in statements:
                with self.subTest(extension=extension, statement=statement):
                    self.assert_referenced_helper_is_kept(statement, extension)

    def test_comments_between_import_tokens_do_not_hide_references(self):
        statements = (
            '''import/* "quoted" 'words' */"./helper";''',
            '''import /* "quoted" */ { value } /* 'words' */ from /* "more" */ "./helper";''',
            '''export /* "quoted" */ { value } /* 'words' */ from /* "more" */ "./helper";''',
            '''import { value } from // "quoted" 'words'\n"./helper";''',
            '''const value = require /* "quoted" */ ( /* 'words' */ "./helper" /* "more" */ );''',
            '''const value = import /* "quoted" */ ( /* 'words' */ "./helper" /* "more" */ );''',
        )
        for statement in statements:
            with self.subTest(statement=statement):
                self.assert_referenced_helper_is_kept(statement)

    def test_export_expressions_and_templates_do_not_hide_later_imports(self):
        statements = (
            'export const value = import("./helper");',
            'export const value = require("./helper");',
            'const value = `${await import("./helper")}`;',
            'export const pattern = /"/; import value from "./helper";',
            '''export const value = "other";\nimport { value as helper } from "./helper";''',
        )
        for statement in statements:
            with self.subTest(statement=statement):
                self.assert_referenced_helper_is_kept(statement)

    def test_import_words_in_literal_text_and_comments_cannot_hide_later_imports(self):
        prefixes = (
            'const note = "import /*";\n',
            'const note = `import /*`;\n',
            '// import /*\n',
        )
        statements = (
            'import value from "./helper";',
            '''import /* "quoted" */ { value } from /* 'words' */ "./helper";''',
            '''const value = import /* "quoted" */ ("./helper", {});''',
        )
        for prefix in prefixes:
            for statement in statements:
                with self.subTest(prefix=prefix, statement=statement):
                    self.assert_referenced_helper_is_kept(prefix + statement)

    def test_string_named_imports_and_exports_keep_local_sources_and_packages(self):
        statements = (
            'export { "x" as "y" } from "{module}";',
            'export { "from" as "public-name" } from "{module}";',
            'import { "x" as x } from "{module}";',
            r'import { "a\"b" as local } from "{module}";',
            'import value, { "x" as x } from "{module}";',
            'export * as "named exports" from "{module}";',
        )
        for statement in statements:
            for extension in (".mts", ".cts"):
                with self.subTest(statement=statement, extension=extension), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / "main.ts").write_text(statement.replace("{module}", "./helper"), encoding="utf-8")
                    for name in ("helper", "unused"):
                        (root / f"{name}{extension}").write_text("export default 1;\n", encoding="utf-8")
                    result = inventory.inventory(root)
                    self.assertEqual(result["orphan_files"],
                                     [{"path": f"unused{extension}", "test_importers": []}])
            with self.subTest(statement=statement, package=True), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "main.ts").write_text(statement.replace("{module}", "used-package"), encoding="utf-8")
                (root / "package.json").write_text(json.dumps({
                    "dependencies": {"used-package": "1", "unused-package": "1"},
                }), encoding="utf-8")
                result = inventory.inventory(root)
                self.assertEqual([row["name"] for row in result["unimported_dependencies"]], ["unused-package"])

    def test_shared_quoted_module_is_reported_once_without_hiding_real_imports(self):
        module = "x" * 50000
        source = '/*\n' + 'import /*\n' * 300 + '*/ "' + module + '";\nimport "./helper";\n'
        specs = list(inventory.js_import_specs(source))
        self.assertEqual(len(specs), 2)
        self.assertEqual(specs, [module, "./helper"])

    def test_dynamic_import_options_keep_referenced_sources(self):
        statements = (
            'const value = import("./helper", {});',
            'const value = import("./helper", getOptions({ text: ")", nested: [","] }));',
            'const value = import("./helper",);',
            '''const value = import /* comment */ ( "./helper" /* before comma */ ,\n'''
            '''    // options may contain arbitrary expressions\n    getOptions(),\n);''',
        )
        for statement in statements:
            with self.subTest(statement=statement):
                self.assert_referenced_helper_is_kept(statement)

    def test_dynamic_import_attributes_record_json_specifiers(self):
        source = '''const data = import("./data.json", { with: { type: "json" } });'''
        # JSON files are not orphan candidates; inspect the import signal itself.
        self.assertEqual(list(inventory.js_import_specs(source)), ["./data.json"])

    def test_dynamic_import_attributes_keep_declared_dependencies(self):
        statements = (
            'const data = import("json-data", { with: { type: "json" } });',
            '''const data = import("json-data" /* , ) */ , {\n'''
            '''    with: { type: "json" },\n    note: "unused-package",\n});''',
            'const data = import("json-data", options);',
        )
        for statement in statements:
            with self.subTest(statement=statement), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "main.ts").write_text(statement, encoding="utf-8")
                (root / "package.json").write_text(json.dumps({
                    "dependencies": {"json-data": "1", "unused-package": "1"},
                }), encoding="utf-8")
                result = inventory.inventory(root)
                self.assertEqual([row["name"] for row in result["unimported_dependencies"]],
                                 ["unused-package"])

    def test_dynamic_import_options_do_not_turn_computed_specifier_prefixes_into_dependencies(self):
        statements = (
            'const value = import("unused-package" + suffix, {});',
            'const value = import("unused-package".concat("-suffix"), {});',
            'const value = import("unused-package" /* , ) */ + suffix, options);',
            'const value = import(specifier, { note: "unused-package" });',
        )
        for statement in statements:
            with self.subTest(statement=statement), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "main.ts").write_text(statement, encoding="utf-8")
                (root / "package.json").write_text(json.dumps({
                    "dependencies": {"unused-package": "1"},
                }), encoding="utf-8")
                result = inventory.inventory(root)
                self.assertEqual([row["name"] for row in result["unimported_dependencies"]],
                                 ["unused-package"])

    def test_repeated_import_words_and_large_multiline_import_finish_within_timeout(self):
        preludes = {
            "comment": "/* " + "import export " * 50000 + " */\n;\n",
            "template": 'const examples = `' + "import value from /* boundary */ " * 30000 + '`;\n',
        }
        for kind, prelude in preludes.items():
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                parent = Path(tmp)
                root = parent / "repo"
                root.mkdir()
                source = (prelude + "import {\n"
                          + "".join(f"  value as local{index},\n" for index in range(30000))
                          + '} from "./helper";\n')
                self.assertLess(len(source.encode("utf-8")), inventory.MAX_BYTES)
                (root / "main.ts").write_text(source, encoding="utf-8")
                (root / "helper.ts").write_text("export const value = 1;\n", encoding="utf-8")
                (root / "unused.ts").write_text("export default 1;\n", encoding="utf-8")
                output = parent / "inventory.json"
                result = subprocess.run(
                    [sys.executable, str(SCRIPTS / "inventory.py"), str(root), "--out", str(output)],
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["orphan_files"],
                                 [{"path": "unused.ts", "test_importers": []}])

    def test_malformed_and_overlapping_candidates_finish_within_timeout(self):
        payloads = {
            "unterminated_comment": "import /* " * 30000,
            "unterminated_string": '"' + '\\"import ' * 30000,
            "unterminated_named_clause": "import { " * 30000,
            "shared_named_clause": ("import /* " * 15000 + "*/ {\n"
                                    + "value,\n" * 30000 + '} from "./helper";\n'),
            "overlapping_named_tails": ("import { a, /* " * 15000 + "*/\n"
                                        + "value,\n" * 30000 + '} from "./helper";\n'),
            "operator_suffixes": ('const note = "' + "import-" * 30000
                                  + '";\nimport value from "./helper";\n'),
            "identifier_suffixes": ('const note = "' + "$import\u200d\\u{24}" * 30000
                                    + '";\nimport value from "./helper";\n'),
        }
        script = (
            f"import sys; sys.path.insert(0, {str(SCRIPTS)!r}); import inventory; "
            "source = sys.stdin.read(); specs = list(inventory.js_import_specs(source)); "
            "assert all(spec == './helper' for spec in specs)"
        )
        for kind, source in payloads.items():
            with self.subTest(kind=kind):
                self.assertLess(len(source.encode("utf-8")), inventory.MAX_BYTES)
                result = subprocess.run([sys.executable, "-c", script], input=source,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_large_quoted_bindings_and_incomplete_clauses_finish_within_timeout(self):
        quoted_name = json.dumps('from "unused-pkg"')
        bindings = "".join(f"  {quoted_name} as local{index},\n" for index in range(30000))
        sources = {
            "quoted_import": 'import {\n' + bindings + '} from "./helper";\n',
            "unclosed_brace": "import { " + "import export " * 50000,
            "nested_braces": "import { " * 60000,
            "unclosed_quote": 'import { "' + "import { export " * 50000,
        }
        for kind, source in sources.items():
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                parent = Path(tmp)
                root = parent / "repo"
                root.mkdir()
                self.assertLess(len(source.encode("utf-8")), inventory.MAX_BYTES)
                (root / "main.ts").write_text(source, encoding="utf-8")
                (root / "helper.ts").write_text(
                    f"const value = 1; export {{ value as {quoted_name} }};\n", encoding="utf-8")
                (root / "unused.ts").write_text("export default 1;\n", encoding="utf-8")
                (root / "package.json").write_text(json.dumps({
                    "dependencies": {"unused-pkg": "1"},
                }), encoding="utf-8")
                output = parent / "inventory.json"
                result = subprocess.run(
                    [sys.executable, str(SCRIPTS / "inventory.py"), str(root), "--out", str(output)],
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                document = json.loads(output.read_text(encoding="utf-8"))
                expected = ["unused.ts"] if kind == "quoted_import" else ["helper.ts", "unused.ts"]
                self.assertEqual([row["path"] for row in document["orphan_files"]], expected)
                self.assertEqual([row["name"] for row in document["unimported_dependencies"]],
                                 ["unused-pkg"])


if __name__ == "__main__":
    unittest.main()
