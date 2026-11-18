"""Escaped module names must retain the files and dependencies a runtime loads."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import inventory  # noqa: E402

NODE = shutil.which("node")


class EscapedSpecifierTests(unittest.TestCase):
    # ECMAScript StringLiteral evaluates escapes once and represents strings as UTF-16.
    # https://tc39.es/ecma262/multipage/ecmascript-language-lexical-grammar.html#sec-literals-string-literals
    FORMS = (
        "import __SOURCE__;",
        "import __BINDING__ from __SOURCE__;",
        'import { "value" as __BINDING__ } from __SOURCE__;',
        "import * as __BINDING__ from __SOURCE__;",
        "export { value as __BINDING__ } from __SOURCE__;",
        "export * as __BINDING__ from __SOURCE__;",
        "const __BINDING__ = import(__SOURCE__);",
        'const __BINDING__ = import(__SOURCE__, { with: { type: "json" } });',
        "const __BINDING__ = require(__SOURCE__);",
        "import source __BINDING__ from __SOURCE__;",
        "import defer * as __BINDING__ from __SOURCE__;",
        "const __BINDING__ = import.source(__SOURCE__);",
        "const __BINDING__ = import.defer(__SOURCE__);",
        "import typeof __BINDING__ from __SOURCE__;",
    )

    def scan(self, source, *, helper="helper"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.ts").write_text(source, encoding="utf-8")
            (root / f"{helper}.ts").write_text("export const value = 1;\n", encoding="utf-8")
            (root / "unused.ts").write_text("export default 0;\n", encoding="utf-8")
            (root / "package.json").write_text(json.dumps({
                "dependencies": {"react": "1", "unused-package": "1"},
            }), encoding="utf-8")
            return inventory.inventory(root)

    def assert_only_controls(self, result):
        self.assertEqual([row["path"] for row in result["orphan_files"]], ["unused.ts"])
        self.assertEqual([row["name"] for row in result["unimported_dependencies"]], ["unused-package"])

    def test_import_export_flow_and_phase_forms_decode_only_the_module_specifier(self):
        for form in self.FORMS:
            with self.subTest(form=form):
                local = form.replace("__BINDING__", "local").replace("__SOURCE__", r'"./hel\u0070er"')
                package = form.replace("__BINDING__", "dependency").replace("__SOURCE__", r'"re\x61ct"')
                self.assert_only_controls(self.scan(local + "\n" + package + "\n"))

    def test_unicode_hex_and_identity_escapes_keep_local_sources_and_dependencies(self):
        literals = (
            (r'"./hel\u0070er"', r'"re\u0061ct"'),
            (r'"./hel\x70er"', r'"re\x61ct"'),
            (r'"./hel\u{70}er"', r'"re\u{61}ct"'),
            (r'"./hel\u{0000000000000070}er"', r'"re\u{0000000000000061}ct"'),
        )
        for local, package in literals:
            with self.subTest(local=local, package=package):
                self.assert_only_controls(self.scan(f"import {local};\nconst dependency = require({package});\n"))
        # Identity escapes retain ordinary non-escape characters, including punctuation.
        self.assert_only_controls(self.scan(r'import "\.\/he\lper"; import "rea\ct";'))

    def test_escaped_quotes_retain_the_actual_source_file_name(self):
        examples = ((r'"./he\"lper"', 'he"lper'), (r"'./he\'lper'", "he'lper"))
        for literal, helper in examples:
            with self.subTest(literal=literal):
                self.assert_only_controls(self.scan(f'import {literal};\nimport "react";\n', helper=helper))

    def test_line_continuations_keep_references_without_inserting_line_separators(self):
        for newline in ("\n", "\r", "\r\n", "\u2028", "\u2029"):
            with self.subTest(newline=repr(newline)):
                local = '"./hel' + "\\" + newline + 'per"'
                package = '"re' + "\\" + newline + 'act"'
                self.assert_only_controls(self.scan(f"import {local};\nconst dependency = import({package});\n"))

    def test_surrogate_pairs_and_code_points_match_unicode_filenames(self):
        examples = (
            (r'"./\uD83C\uDF4C"', "🍌"),
            (r'"./\u{1F34C}"', "🍌"),
            ('"./🍌"', "🍌"),
            (r'"./\u65E5\u672C\u8A9E"', "日本語"),
            ('"./日本語"', "日本語"),
        )
        for literal, helper in examples:
            with self.subTest(literal=literal):
                self.assert_only_controls(self.scan(f'import {literal};\nimport "react";\n', helper=helper))

    def test_produced_backslashes_are_not_decoded_again(self):
        source = r'import "./hel\\u0070er"; import "./hel\u005cu0070er"; require("re\\x61ct");'
        self.assertEqual(list(inventory.js_import_specs(source)),
                         [r"./hel\u0070er", r"./hel\u0070er", r"re\x61ct"])
        result = self.scan(source)
        self.assertEqual([row["path"] for row in result["orphan_files"]], ["helper.ts", "unused.ts"])
        self.assertEqual([row["name"] for row in result["unimported_dependencies"]], ["react", "unused-package"])

    def test_legacy_commonjs_octal_and_decimal_escapes_keep_their_string_values(self):
        self.assert_only_controls(self.scan(r'const local = require("./hel\160er"); require("\162eact");'))
        self.assertEqual(list(inventory.js_import_specs(r'require("./\8\9"); require("./\400");')),
                         ["./89", "./ 0"])

    def test_invalid_escapes_and_lone_surrogates_do_not_hide_later_imports(self):
        literals = (
            r'"re\xG1ct"', r'"re\x1"', r'"re\u12"', r'"re\uZZZZct"',
            r'"re\u{}ct"', r'"re\u{12z}ct"', r'"re\u{110000}ct"', r'"re\u{FFFFFFFFFFFFFFFF}ct"',
            r'"re\u{61ct"', r'"re\uD800ct"', r'"re\uDC00ct"', r'"re\uDC00\uD800ct"',
            r'"re\uD800\u0061ct"', r'"re\0act"',
        )
        for literal in literals:
            with self.subTest(literal=literal):
                source = f"import {literal};\n" + r'import "./hel\x70er";'
                self.assertEqual(list(inventory.js_import_specs(source)), ["./helper"])
                result = self.scan(source)
                self.assertEqual([row["path"] for row in result["orphan_files"]], ["unused.ts"])
                self.assertEqual([row["name"] for row in result["unimported_dependencies"]],
                                 ["react", "unused-package"])
                json.dumps(result, ensure_ascii=False).encode("utf-8")

    def test_computed_specifier_prefixes_do_not_become_decoded_imports(self):
        source = (r'import("./hel\u0070er" + suffix); require("re\x61ct".toLowerCase());'
                  r'import.source("re\x61ct" + suffix);')
        self.assertEqual(list(inventory.js_import_specs(source)), [])
        result = self.scan(source)
        self.assertEqual([row["path"] for row in result["orphan_files"]], ["helper.ts", "unused.ts"])
        self.assertEqual([row["name"] for row in result["unimported_dependencies"]], ["react", "unused-package"])

    @unittest.skipUnless(NODE, "Node is only needed for the independent runtime comparison")
    def test_node_loads_the_same_static_dynamic_and_commonjs_references(self):
        forms = (
            ("main.mjs", r'import local from "./hel\u0070er.js"; import dependency from "re\x61ct";'
             "console.log(local + dependency);"),
            ("main.mjs", r'const local = (await import("./hel\u0070er.js")).default;'
             r'const dependency = (await import("re\x61ct")).default; console.log(local + dependency);'),
            ("main.cjs", r'const local = require("./hel\u0070er.js"); const dependency = require("re\x61ct");'
             "console.log(local + dependency);"),
        )
        for entry, source in forms:
            with self.subTest(entry=entry, source=source), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "node_modules" / "react").mkdir(parents=True)
                (root / "node_modules" / "react" / "index.js").write_text("module.exports = 2;\n", encoding="utf-8")
                (root / "helper.js").write_text("module.exports = 40;\n", encoding="utf-8")
                (root / "unused.js").write_text("module.exports = 0;\n", encoding="utf-8")
                (root / "package.json").write_text(json.dumps({
                    "type": "commonjs", "dependencies": {"react": "1", "unused-package": "1"},
                }), encoding="utf-8")
                (root / entry).write_text(source, encoding="utf-8")
                result = subprocess.run([NODE, str(root / entry)], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "42")
                data = inventory.inventory(root)
                self.assertEqual([row["path"] for row in data["orphan_files"]], ["unused.js"])
                self.assertEqual([row["name"] for row in data["unimported_dependencies"]], ["unused-package"])

    def test_overlapping_candidates_decode_large_literals_once_and_finish_promptly(self):
        program = r'''import sys
sys.path.insert(0, sys.argv[1])
import inventory
source = sys.stdin.read()
specifiers = list(inventory.js_import_specs(source))
expected = ["a" * 50000, "react"] if sys.argv[2] == "valid" else ["react"]
assert specifiers == expected
'''
        for kind, literal in (("valid", r"\u0061" * 50000), ("invalid", r"\u{" * 50000)):
            with self.subTest(kind=kind):
                source = "import /* " * 15000 + '*/ "' + literal + '";\n' + r'import "re\x61ct";'
                self.assertLess(len(source.encode("utf-8")), inventory.MAX_BYTES)
                result = subprocess.run([sys.executable, "-c", program, str(SCRIPTS), kind], input=source,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
