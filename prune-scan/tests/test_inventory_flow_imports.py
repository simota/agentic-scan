"""Flow type-only references must keep their modules and dependencies in use.

Primary syntax references (these fixtures do not execute Flow in Node):
https://flow.org/en/docs/types/modules/
https://flow.org/en/docs/types/utilities/#toc-exports
https://github.com/facebook/flow/blob/b96b5e3529f55b4a5837f3ff90801e22b108c083/tests/import_typeof/import_typeof.js
https://github.com/facebook/flow/blob/b96b5e3529f55b4a5837f3ff90801e22b108c083/src/parser/test/flow/types/import_type_shorthand/migrated_0006.js
https://github.com/facebook/flow/blob/b96b5e3529f55b4a5837f3ff90801e22b108c083/src/parser/test/flow/types/import_type_shorthand/migrated_0005.js
https://github.com/facebook/flow/blob/b96b5e3529f55b4a5837f3ff90801e22b108c083/src/parser/test/flow/types/import_type_shorthand/type_as_as.js
https://github.com/facebook/flow/blob/b96b5e3529f55b4a5837f3ff90801e22b108c083/rust_port/crates/flow_parser/src/statement_parser.rs
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "prune-scan" / "scripts"))

import inventory  # noqa: E402


class FlowImportTests(unittest.TestCase):
    def scan(self, source):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.js").write_text(source, encoding="utf-8")
            (root / "helper.js").write_text(
                "export default class Widget {}\n"
                "export { Widget };\n"
                "export const value = 1;\n"
                "export type Shape = { value: number };\n"
                'export { value as typeof, value as type, value as "x", Widget as as };\n',
                encoding="utf-8",
            )
            (root / "unused.js").write_text("export const spare = 0;\n", encoding="utf-8")
            (root / "package.json").write_text(json.dumps({
                "dependencies": {"used-pkg": "1", "unused-pkg": "1"},
            }), encoding="utf-8")
            return inventory.inventory(root)

    def assert_references_are_kept(self, statements):
        for statement in statements:
            for specifier in ("./helper", "used-pkg"):
                with self.subTest(statement=statement, specifier=specifier):
                    result = self.scan(statement.replace("__SOURCE__", specifier))
                    expected_files = {"unused.js"}
                    expected_packages = {"unused-pkg"}
                    if specifier == "used-pkg":
                        expected_files.add("helper.js")
                    else:
                        expected_packages.add("used-pkg")
                    # Use an extensionless source so the filename fallback
                    # cannot accidentally retain helper.js after a missed import.
                    self.assertEqual({row["path"] for row in result["orphan_files"]}, expected_files)
                    self.assertEqual({row["name"] for row in result["unimported_dependencies"]},
                                     expected_packages)

    def test_typeof_default_named_and_namespace_imports_keep_references(self):
        self.assert_references_are_kept((
            '// @flow\nimport typeof Widget from "__SOURCE__";',
            '// @flow\nimport typeof { Widget } from "__SOURCE__";',
            '// @flow\nimport typeof { Widget as WidgetType, value as ValueType } from "__SOURCE__";',
            '// @flow\nimport typeof * as Widgets from "__SOURCE__";',
        ))

    def test_inline_typeof_and_aliased_mixed_imports_keep_references(self):
        statements = [
            '// @flow\nimport { typeof Widget } from "__SOURCE__";',
            '// @flow\nimport { typeof Widget as WidgetType } from "__SOURCE__";',
            '// @flow\nimport { typeof Widget, Widget as WidgetImplementation } from "__SOURCE__";',
            '// @flow\nimport { typeof Widget as WidgetType, value, } from "__SOURCE__";',
        ]
        # The official Flow parser accepts `as` as the imported name, with
        # either type or typeof and an optional explicit alias.
        for prefix in ("type", "typeof"):
            for clause in (prefix + " as", prefix + " as as AsAlias"):
                statements.append(f'// @flow\nimport {{ {clause} }} from "__SOURCE__";')
        self.assert_references_are_kept(statements)

    def test_typeof_comments_and_from_binding_keep_references(self):
        self.assert_references_are_kept((
            '// @flow\nimport typeof from from "__SOURCE__";',
            '// @flow\nimport /* kind */ typeof /* binding */ Widget\n'
            '  from /* source */ "__SOURCE__";',
            '// @flow\nimport typeof // binding follows\n'
            '  Widget from // source follows\n"__SOURCE__";',
            '// @flow\nimport { /* kind */ typeof /* value */ Widget\n'
            '  as /* alias */ WidgetType, value, } from "__SOURCE__";',
        ))

    def test_type_imports_and_contextual_default_bindings_keep_references(self):
        statements = [
            '// @flow\nimport type Widget from "__SOURCE__";',
            '// @flow\nimport type { Shape as SelectedShape } from "__SOURCE__";',
            '// @flow\nimport { type Shape as SelectedShape, value } from "__SOURCE__";',
        ]
        for binding in ("type", "source", "defer", "from"):
            for clause in (binding, binding + ", { value }", binding + ", * as values"):
                statements.append(f'import {clause} from "__SOURCE__";')
        self.assert_references_are_kept(statements)

    def test_reserved_export_names_and_quoted_bindings_keep_references(self):
        # These are ordinary JavaScript export names and explicit aliases.
        # The local binding can itself be `as`; these are not Flow modifiers.
        self.assert_references_are_kept((
            'import { typeof as TypeofValue } from "__SOURCE__";',
            'import { typeof as as } from "__SOURCE__";',
            'import { type as as } from "__SOURCE__";',
            'export { typeof as TypeofValue } from "__SOURCE__";',
            'import { "typeof" as TypeofValue, "type" as TypeValue } from "__SOURCE__";',
            'export { "typeof" as "value" } from "__SOURCE__";',
            'import initial, { "x" as selected } from "__SOURCE__";',
        ))

    def test_typeof_expressions_do_not_create_module_references(self):
        for source in (
            'const kinds = [typeof "used-pkg", typeof "./helper"];',
            'const value = 1; const kind = typeof value;',
        ):
            with self.subTest(source=source):
                result = self.scan(source)
                self.assertEqual({row["path"] for row in result["orphan_files"]},
                                 {"helper.js", "unused.js"})
                self.assertEqual({row["name"] for row in result["unimported_dependencies"]},
                                 {"used-pkg", "unused-pkg"})


if __name__ == "__main__":
    unittest.main()
