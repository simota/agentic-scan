"""Quoted module binding names must not hide imports or become module specifiers."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "prune-scan" / "scripts"))

import inventory  # noqa: E402


class QuotedBindingTests(unittest.TestCase):
    # ModuleExportName permits StringLiteral in the ECMAScript import/export
    # grammar, including namespace re-exports. The import's local binding is
    # still an identifier, and a local export's source binding is an identifier.
    # https://tc39.es/ecma262/multipage/ecmascript-language-scripts-and-modules.html#sec-imports
    # https://tc39.es/ecma262/multipage/ecmascript-language-scripts-and-modules.html#sec-exports
    IMPORTS = (
        'import { "x" as selected } from "__SOURCE__";',
        "import { 'x' as selected } from '__SOURCE__';",
        'import { "" as empty } from "__SOURCE__";',
        'import initial, { "x" as selected, "" as empty } from "__SOURCE__";',
        'import $initial, { "x" as selected } from "__SOURCE__";',
        'import 初期値, { "x" as selected } from "__SOURCE__";',
        'import initial, { type Value, "x" as selected } from "__SOURCE__";',
        'import type { "x" as Selected } from "__SOURCE__";',
        'import { value, "x" as selected, default as initial, } from "__SOURCE__";',
        'import { "x" as from } from "__SOURCE__";',
    )
    EXPORTS = (
        'export { "x" as "y" } from "__SOURCE__";',
        'export { "x" } from "__SOURCE__";',
        'export { x as "y" } from "__SOURCE__";',
        "export { 'x' as selected } from '__SOURCE__';",
        'export { "" as "empty" } from "__SOURCE__";',
        'export { "default" as "initial", value as default, "x" as selected, } from "__SOURCE__";',
    )
    ESCAPED = (
        r'import { "quo\"te" as selected } from "__SOURCE__";',
        r"import { 'quo\'te' as selected } from '__SOURCE__';",
        r'import { "\u0078" as selected } from "__SOURCE__";',
        r'import { "slash\\name" as selected } from "__SOURCE__";',
        'import { "🍌" as selected } from "__SOURCE__";',
        r'export { "quo\"te" as "alias\"name" } from "__SOURCE__";',
        r"export { 'quo\'te' as 'alias\'name' } from '__SOURCE__';",
        r'export { "\u0078" as "" } from "__SOURCE__";',
        r'export { "slash\\name" as selected } from "__SOURCE__";',
        'export { "🍌" as selected } from "__SOURCE__";',
    )
    COMMENTED = (
        'import /* quote " */ initial, { "x" /* from "unused-pkg" } */ as selected,\n'
        ' "" as empty, } from // from "unused-pkg"\n "__SOURCE__";',
        'export { "x" as /* from "unused-pkg" } */ "y",\n'
        ' "" as empty, } /* quote " */ from "__SOURCE__";',
        'import { "x\\\n" as selected } from "__SOURCE__";',
        'export { "x\\\n" as "y" } from "__SOURCE__";',
    )
    NAMESPACES = (
        'export * as "namespace-name" from "__SOURCE__";',
        'export * as "" from "__SOURCE__";',
        r'export * as "quote\"name" from "__SOURCE__";',
    )
    FALSE_FROM_NAMES = (
        "from 'unused-pkg'",
        "from './unused'",
        '} from "unused-pkg"; {',
        '} from "./unused"; {',
    )

    def scan(self, source):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.ts").write_text(source, encoding="utf-8")
            names = ("x", "", 'quo"te', "quo'te", "slash\\name", "🍌", *self.FALSE_FROM_NAMES)
            aliases = ", ".join("value as " + json.dumps(name, ensure_ascii=False) for name in names)
            helper = ("const value = 1;\nexport type Value = number;\nexport { value };\n"
                      f"export default value;\nexport {{ {aliases} }};\n")
            # Extensionless imports must retain both plausible module sources;
            # neither file's full name appears in the import's source string.
            for extension in (".mts", ".cts"):
                (root / ("helper" + extension)).write_text(helper, encoding="utf-8")
                (root / ("unused" + extension)).write_text("export const spare = 0;\n", encoding="utf-8")
            (root / "package.json").write_text(json.dumps({
                "dependencies": {"pkg": "1", "unused-pkg": "1"},
            }), encoding="utf-8")
            return inventory.inventory(root)

    def assert_references_are_kept(self, statements):
        for statement in statements:
            for specifier in ("./helper", "pkg"):
                with self.subTest(statement=statement, specifier=specifier):
                    result = self.scan(statement.replace("__SOURCE__", specifier))
                    expected_files = ["unused.cts", "unused.mts"]
                    expected_packages = ["unused-pkg"]
                    if specifier == "pkg":
                        expected_files = ["helper.cts", "helper.mts", *expected_files]
                    else:
                        expected_packages = ["pkg", *expected_packages]
                    self.assertEqual([row["path"] for row in result["orphan_files"]], expected_files)
                    self.assertEqual([row["name"] for row in result["unimported_dependencies"]], expected_packages)

    def test_quoted_named_imports_keep_local_modules_and_packages(self):
        self.assert_references_are_kept(self.IMPORTS)

    def test_quoted_named_reexports_keep_local_modules_and_packages(self):
        self.assert_references_are_kept(self.EXPORTS)

    def test_escaped_and_unicode_binding_names_keep_references(self):
        self.assert_references_are_kept(self.ESCAPED)

    def test_comments_and_multiline_quoted_bindings_keep_references(self):
        self.assert_references_are_kept(self.COMMENTED)

    def test_quoted_namespace_exports_keep_local_modules_and_packages(self):
        self.assert_references_are_kept(self.NAMESPACES)

    def test_exported_regex_object_does_not_hide_later_quoted_import(self):
        self.assert_references_are_kept((
            'export const patterns = { pattern: /"/ };\n'
            'import { "x" as selected } from "__SOURCE__";',
        ))

    def test_from_text_inside_binding_names_does_not_create_extra_references(self):
        statements = []
        for name in self.FALSE_FROM_NAMES:
            quoted = json.dumps(name)
            statements.extend((f'import {{ {quoted} as selected }} from "__SOURCE__";',
                               f'export {{ {quoted} as selected }} from "__SOURCE__";'))
        self.assert_references_are_kept(statements)

    def test_local_export_aliases_and_exported_strings_do_not_create_imports(self):
        statements = [f'const value = 1; export {{ value as {json.dumps(name)} }};'
                      for name in self.FALSE_FROM_NAMES]
        statements.extend(('export const example = "from \'unused-pkg\'";',
                           'export const example = "from \'./unused\'";'))
        for source in statements:
            with self.subTest(source=source):
                result = self.scan(source)
                self.assertEqual([row["path"] for row in result["orphan_files"]],
                                 ["helper.cts", "helper.mts", "unused.cts", "unused.mts"])
                self.assertEqual([row["name"] for row in result["unimported_dependencies"]],
                                 ["pkg", "unused-pkg"])


if __name__ == "__main__":
    unittest.main()
