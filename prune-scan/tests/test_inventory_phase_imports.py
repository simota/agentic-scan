"""Phase imports retain references without confusing ordinary binding names.

Primary syntax references:
https://nodejs.org/download/release/v24.15.0/docs/api/esm.html#wasm-source-phase-imports
https://tc39.es/proposal-source-phase-imports/
https://tc39.es/proposal-defer-import-eval/#sec-left-hand-side-expressions
https://www.typescriptlang.org/docs/handbook/release-notes/typescript-5-9.html
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import inventory  # noqa: E402


class PhaseImportTests(unittest.TestCase):
    def assert_dependency_is_kept(self, source, dependency="used-wasm"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.mjs").write_text(source, encoding="utf-8")
            (root / "package.json").write_text(json.dumps({
                "dependencies": {dependency: "1", "unused-package": "1"},
            }), encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual([row["name"] for row in result["unimported_dependencies"]],
                             ["unused-package"])

    def test_static_source_phase_bindings_keep_dependencies(self):
        statements = (
            'import source module from "used-wasm";',
            'import source source from "used-wasm";',
            'import source from from "used-wasm";',
            'import source type from "used-wasm";',
            '''import /* phase */ source /* binding */ \u03c0
               from /* module */ "used-wasm/sub.wasm";''',
        )
        for statement in statements:
            with self.subTest(statement=statement):
                self.assert_dependency_is_kept(statement)

    def test_dynamic_source_phase_keeps_dependencies(self):
        statements = (
            'const module = await import.source("used-wasm");',
            '''const module = import /* phase */ . /* name */ source
               /* arguments */ ( /* module */ "used-wasm" /* end */ );''',
            'const result = `${await import.source("used-wasm")}`;',
            'export const module = import.source("used-wasm");',
        )
        for statement in statements:
            with self.subTest(statement=statement):
                self.assert_dependency_is_kept(statement)

    def test_dynamic_defer_draft_syntax_keeps_dependencies(self):
        # The TC39 draft permits options/trailing commas; this is not a Node runtime test.
        statements = (
            'const namespace = import.defer("used-lazy");',
            'const namespace = import.defer("used-lazy", options);',
            'const namespace = import.defer("used-lazy",);',
            '''const namespace = import /* phase */ . defer /* args */ (
               "used-lazy" /* module */ , { note: "unused-package" });''',
        )
        for statement in statements:
            with self.subTest(statement=statement):
                self.assert_dependency_is_kept(statement, "used-lazy")

    def test_phase_words_remain_ordinary_default_bindings(self):
        for binding in ("source", "defer"):
            for clause in (binding, binding + ", { value }", binding + ", * as values"):
                statement = f'import {clause} from "used-package";'
                with self.subTest(statement=statement):
                    self.assert_dependency_is_kept(statement, "used-package")
        for statement in ('import type from "used-package";', 'import from from "used-package";'):
            with self.subTest(statement=statement):
                self.assert_dependency_is_kept(statement, "used-package")

    def test_deferred_namespace_import_keeps_local_sources_and_packages(self):
        self.assert_dependency_is_kept('import defer * as feature from "used-lazy";', "used-lazy")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.ts").write_text('import defer * as feature from "./helper.js";', encoding="utf-8")
            (root / "helper.ts").write_text("export const value = 1;\n", encoding="utf-8")
            (root / "unused.ts").write_text("export const other = 2;\n", encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual(result["orphan_files"], [{"path": "unused.ts", "test_importers": []}])

    def test_local_wasm_source_specifiers_are_recorded(self):
        # Wasm files are not orphan candidates; inspect the import signal itself.
        for statement in ('import source module from "./helper.wasm";',
                          'const module = import.source("./helper.wasm");'):
            with self.subTest(statement=statement):
                self.assertEqual(list(inventory.js_import_specs(statement)), ["./helper.wasm"])

    def test_computed_phase_specifiers_and_other_properties_do_not_create_references(self):
        statements = [
            f'const value = import.{phase}({expression});'
            for phase in ("source", "defer")
            for expression in ('"unused-package" + suffix', '"unused-package".concat("-suffix")', 'specifier')
        ]
        statements += ['const value = require.source("unused-package");',
                       'const value = require.defer("unused-package");',
                       'const value = import.meta.resolve("unused-package");']
        for statement in statements:
            with self.subTest(statement=statement):
                self.assertEqual(list(inventory.js_import_specs(statement)), [])


if __name__ == "__main__":
    unittest.main()
