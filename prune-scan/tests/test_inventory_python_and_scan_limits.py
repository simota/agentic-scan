"""Real import references and bounded scans for long, ordinary repository inputs."""
import json
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


class PythonImportStatementTests(unittest.TestCase):
    def test_inline_suites_semicolons_and_continuations_keep_dependencies(self):
        sources = (
            "import os; import httpx\n",
            "if True: import httpx\n",
            "def load(): import httpx\n",
            "import os, \\\n    httpx as client\n",
            "import \\\n    httpx\n",
            "if True: from httpx import Client\n",
            "from \\\n    httpx import Client\n",
        )
        for source in sources:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "main.py").write_text(source, encoding="utf-8")
                (root / "requirements.txt").write_text("httpx\nunused-package\n", encoding="utf-8")
                rows = inventory.inventory(root)["unimported_dependencies"]
                self.assertEqual([row["name"] for row in rows], ["unused-package"])

    def test_inline_and_continued_imports_keep_local_sources(self):
        sources = (
            "import os; import helper\n",
            "if True: import helper\n",
            "import os, \\\n    helper as local\n",
            "import os; from . import helper\n",
            "if True: from . import helper\n",
            "from . \\\n    import helper as local\n",
        )
        for source in sources:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "pkg").mkdir()
                for name in ("__init__", "helper", "unused"):
                    (root / "pkg" / f"{name}.py").write_text("value = 1\n", encoding="utf-8")
                (root / "pkg" / "main.py").write_text(source, encoding="utf-8")
                self.assertEqual(inventory.inventory(root)["orphan_files"],
                                 [{"path": "pkg/unused.py", "test_importers": []}])

    def test_relative_imports_do_not_count_as_external_packages(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pkg").mkdir()
            (root / "pkg" / "__init__.py").write_text("", encoding="utf-8")
            (root / "pkg" / "main.py").write_text("if True: from . import httpx\n", encoding="utf-8")
            (root / "pkg" / "httpx.py").write_text("value = 1\n", encoding="utf-8")
            (root / "requirements.txt").write_text("httpx\n", encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual(result["orphan_files"], [])
            self.assertEqual([row["name"] for row in result["unimported_dependencies"]], ["httpx"])

    def test_inline_test_imports_keep_their_importer_without_hiding_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tests").mkdir()
            (root / "tests" / "test_registration.py").write_text(
                "def test_load(): import helper; import httpx\n", encoding="utf-8")
            (root / "helper.py").write_text("value = 1\n", encoding="utf-8")
            (root / "requirements.txt").write_text("httpx\n", encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual(result["unimported_dependencies"], [])
            self.assertEqual(result["orphan_files"], [{
                "path": "helper.py", "test_importers": ["tests/test_registration.py"],
            }])

    def test_comment_and_string_examples_do_not_invent_imports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.py").write_text(
                '\"\"\"Documentation:\nimport httpx\nfrom . import helper\n\"\"\"\n'
                '# import httpx\n# from . import helper\n'
                'example = "import httpx; from . import helper"\n', encoding="utf-8")
            (root / "helper.py").write_text("value = 1\n", encoding="utf-8")
            (root / "requirements.txt").write_text("httpx\n", encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual([row["name"] for row in result["unimported_dependencies"]], ["httpx"])
            self.assertEqual(result["orphan_files"], [{"path": "helper.py", "test_importers": []}])

    def test_unsupported_python_syntax_keeps_best_effort_imports(self):
        for failure in (SyntaxError, ValueError, RecursionError, MemoryError):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "main.py").write_text(
                    "import httpx\nfrom . import (\n    helper, # retained local module\n)\n", encoding="utf-8")
                (root / "helper.py").write_text("value = 1\n", encoding="utf-8")
                (root / "requirements.txt").write_text("httpx\n", encoding="utf-8")
                with mock.patch.object(inventory.ast, "parse", side_effect=failure):
                    result = inventory.inventory(root)
                self.assertEqual(result["unimported_dependencies"], [])
                self.assertEqual(result["orphan_files"], [])

    def test_parser_stack_limit_in_test_source_keeps_the_scan_and_imports(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = parent / "repo"
            (root / "tests").mkdir(parents=True)
            (root / "tests" / "test_numeric.py").write_text(
                "import httpx\ndef test_numeric():\n    assert " + "+" * 8000 + "1\n", encoding="utf-8")
            (root / "requirements.txt").write_text("httpx\n", encoding="utf-8")
            output = parent / "inventory.json"
            result = subprocess.run([sys.executable, str(SCRIPTS / "inventory.py"), str(root), "--out", str(output)],
                                    capture_output=True, text=True, timeout=8)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["unimported_dependencies"], [])


class ScannerBoundaryTests(unittest.TestCase):
    def test_each_dynamic_class_in_a_template_keeps_its_possible_selectors(self):
        sources = (
            "node.className = `button-${kind} icon-${name} tone-${color}`;\n",
            "node.className = `button-${nested ? `icon-${name}` : ''} tone-${color}`;\n",
        )
        for source in sources:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "main.ts").write_text(source, encoding="utf-8")
                (root / "styles.css").write_text(
                    ".button-primary {}\n.icon-star {}\n.tone-blue {}\n.unused {}\n", encoding="utf-8")
                result = inventory.inventory(root)
                self.assertEqual(result["css_dynamic_prefixes"], ["button-", "icon-", "tone-"])
                self.assertEqual(result["css_unreferenced"], [{"class": "unused", "location": "styles.css:4"}])

    def test_ordinary_strings_do_not_create_template_class_prefixes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.ts").write_text('node.className = "icon-${name}";\n', encoding="utf-8")
            (root / "styles.css").write_text(".icon-star {}\n", encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual(result["css_dynamic_prefixes"], [])
            self.assertEqual(result["css_unreferenced"], [{"class": "icon-star", "location": "styles.css:1"}])

    def test_css_delimiter_boundaries_retain_nested_and_adjacent_selectors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "styles.css").write_text(
                ".first { color: red; .nested { color: blue; } }"
                "@media (width > 20em) { .inside { color: green; } }"
                ".last { color: black; }", encoding="utf-8")
            rows = inventory.inventory(root)["css_unreferenced"]
            self.assertEqual([row["class"] for row in rows], ["first", "nested", "inside", "last"])

    def test_css_comments_preserve_locations_and_unclosed_comments_hide_their_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "styles.css").write_text(
                ".before { } /* .hidden { }\n.hidden_more { } */\n"
                ".after { }\n/* .unfinished { }\n.still_hidden { }\n", encoding="utf-8")
            self.assertEqual(inventory.inventory(root)["css_unreferenced"], [
                {"class": "before", "location": "styles.css:1"},
                {"class": "after", "location": "styles.css:3"},
            ])

    def test_table_scan_preserves_multiple_tables_columns_and_locations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "schema.sql").write_text(
                '-- inventory fixture\nCREATE TABLE "unused_table" (\n'
                '  id INT,\n  private_name TEXT\n);\n\n'
                'CREATE TABLE IF NOT EXISTS `active_table` (\n'
                '  id INT,\n  unused_column TEXT,\n  PRIMARY KEY (id)\n);\n'
                'CREATE TABLE incomplete (\n', encoding="utf-8")
            (root / "main.py").write_text('active_table = "id"\n', encoding="utf-8")
            result = inventory.inventory(root)
            self.assertEqual(result["sql_tables_unreferenced"], [
                {"table": "unused_table", "location": "schema.sql:2"},
            ])
            self.assertEqual(result["sql_columns_unreferenced"], [
                {"table": "active_table", "column": "unused_column", "location": "schema.sql:9"},
            ])

    def test_long_tokens_brace_free_css_and_blank_python_lines_finish_promptly(self):
        program = r'''import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import inventory
root = Path(sys.argv[2])
(root / "data.txt").write_text("x" * 262144, encoding="utf-8")
(root / "styles.css").write_text(".unfinished " * 16384, encoding="utf-8")
# Unsupported syntax deliberately exercises the best-effort regex fallback.
(root / "future.py").write_text("\n" * 65536 + "def unsupported[(:\n", encoding="utf-8")
(root / ".env.example").write_text("\n" * 65536 + "UNUSED_SETTING=ignored\n", encoding="utf-8")
(root / "flags.ts").write_text("\n" * 65536 + "keep: true\n", encoding="utf-8")
(root / "classes.ts").write_text("`" + "a-" * 65536 + "`;\n`button-${variant}`;\n'icon-' + name;\n",
                                 encoding="utf-8")
(root / "main.py").write_text("import helper\n", encoding="utf-8")
(root / "helper.py").write_text("value = 1\n", encoding="utf-8")
print(json.dumps(inventory.inventory(root)))
'''
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run([sys.executable, "-c", program, str(SCRIPTS), tmp],
                                    capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["files_scanned"], 8)
        self.assertNotIn("helper.py", [row["path"] for row in data["orphan_files"]])
        self.assertEqual(data["css_unreferenced"], [])
        self.assertEqual(data["css_dynamic_prefixes"], ["button-", "icon-"])
        self.assertEqual(data["env_declared_not_read"], [{
            "name": "UNUSED_SETTING", "location": ".env.example:65537",
        }])
        self.assertEqual([(row["name"], row["value"], row["definitions"]) for row in data["feature_flags"]],
                         [("keep", True, ["flags.ts:65537"])])

    def test_repeated_unclosed_css_comments_and_sql_tables_finish_promptly(self):
        program = r'''import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import inventory
root = Path(sys.argv[2])
(root / "styles.css").write_text("/* .hidden { }\n" * 32768, encoding="utf-8")
(root / "schema.sql").write_text("CREATE TABLE t (\n" * 32768, encoding="utf-8")
print(json.dumps(inventory.inventory(root)))
'''
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run([sys.executable, "-c", program, str(SCRIPTS), tmp],
                                    capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["files_scanned"], 2)
        self.assertEqual(data["css_unreferenced"], [])
        self.assertEqual(data["sql_tables_unreferenced"], [])


if __name__ == "__main__":
    unittest.main()
