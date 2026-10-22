"""Regression coverage for the fourth review round: SQL dump formats, manifest
line numbers, per-unit candidate counts, comment syntax per language,
destructured env reads and source directories named like virtualenvs."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from test_deep_review_fixes import scan  # noqa: E402


class SqlDumpTests(unittest.TestCase):
    def test_mysql_table_options_end_the_table(self):
        result = scan({
            "db/my.sql": ("CREATE TABLE `orders` (\n  `id` int NOT NULL,\n  `total` int,\n"
                          "  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n\n"
                          "CREATE TABLE `old_audit` (\n  `id` int,\n  `payload` text\n) ENGINE=InnoDB;\n"),
            "app/q.py": 'SQL = "select id, total from orders"\n',
        })
        self.assertEqual(result["sql_tables_unreferenced"], [{"table": "old_audit", "location": "db/my.sql:7"}])
        self.assertEqual(result["sql_columns_unreferenced"], [])

    def test_parentheses_inside_a_body_do_not_end_it(self):
        result = scan({
            "db/schema.sql": ("CREATE TABLE items (\n  id integer,\n  price numeric(10, 2) CHECK (price > 0),\n"
                              "  note text DEFAULT ');',\n  legacy_code text\n);\nCREATE TABLE old_log (\n  id integer\n);\n"),
            "app/q.py": 'SQL = "select id, price, note from items"\n',
        })
        self.assertEqual(result["sql_tables_unreferenced"], [{"table": "old_log", "location": "db/schema.sql:7"}])
        self.assertEqual(result["sql_columns_unreferenced"],
                         [{"table": "items", "column": "legacy_code", "location": "db/schema.sql:5"}])

    def test_schema_qualified_and_differently_cased_names(self):
        result = scan({
            "db/pg.sql": ("CREATE TABLE public.users (\n    id integer,\n    email text,\n    fax_number text\n);\n"
                          "CREATE TABLE CUSTOMERS (\n    ID integer\n);\n"),
            "app/q.py": 'SQL = "select id, email from users join customers using (id)"\n',
        })
        self.assertEqual(result["sql_tables_unreferenced"], [])
        self.assertEqual(result["sql_columns_unreferenced"],
                         [{"table": "users", "column": "fax_number", "location": "db/pg.sql:4"}])


class ManifestLineTests(unittest.TestCase):
    def test_dependency_and_script_rows_point_into_their_own_section(self):
        result = scan({
            "package.json": ('{\n  "name": "web",\n  "scripts": {\n    "storybook": "storybook dev",\n'
                             '    "jest": "jest"\n  },\n  "jest": {\n    "testEnvironment": "node"\n  },\n'
                             '  "dependencies": {\n    "left-pad": "1"\n  },\n'
                             '  "devDependencies": {\n    "storybook": "8",\n    "left-pad": "1"\n  }\n}\n'),
        })
        locations = {(row["name"], row["section"]): row["location"] for row in result["unimported_dependencies"]}
        self.assertEqual(locations[("left-pad", "dependencies")], "package.json:11")
        self.assertEqual(locations[("left-pad", "devDependencies")], "package.json:15")
        scripts = {row["name"]: row["location"] for row in result["scripts"]}
        self.assertEqual(scripts, {"storybook": "package.json:4", "jest": "package.json:5"})


class UnitCountTests(unittest.TestCase):
    def test_by_unit_counts_candidates_not_full_inventories(self):
        units = {"units": [{"id": "UN-01", "paths": ["server/"]}, {"id": "UN-02", "paths": ["package.json"]}]}
        result = scan({
            "server/app.js": ('const express = require("express");\nconst app = express();\n'
                              'app.get("/used", h);\napp.get("/unused", h);\nconst port = process.env.PORT;\n'),
            "server/client.js": 'fetch("/used");\n',
            "package.json": '{"scripts": {"start": "node server/app.js", "lint": "x"}, "dependencies": {"express": "4"}}',
        }, units=units)
        # UN-01: the unreferenced symbol, the orphan file and the unreferenced route;
        # UN-02: the two uninvoked scripts. routes, scripts, env_read and
        # dependencies_declared list everything, so they are not counted again.
        self.assertEqual(result["by_unit"], {"UN-01": 3, "UN-02": 2})
        self.assertEqual(result["routes"][0]["unit"], "UN-01")  # Full inventories are still tagged.


class CommentSyntaxTests(unittest.TestCase):
    def test_hash_lines_that_are_code_in_their_language_are_not_comments(self):
        result = scan({
            "src/model.rs": ("use serde::Serialize;\n\n#[derive(Debug, Clone)]\n#[serde(rename_all = \"camelCase\")]\n"
                             "#[cfg_attr(test, derive(PartialEq))]\n#[allow(dead_code)]\npub struct Model { id: u32 }\n"),
            "src/counter.js": "class Counter {\n  #count = 0;\n  #step = 1;\n  #max = (10);\n  #min = (0);\n}\n",
            "src/app.css": "#a { color: red; }\n#b { color: red; }\n#c { color: red; }\n#d { color: red; }\n",
        })
        self.assertEqual(result["commented_code"], [])

    def test_commented_code_is_still_found_in_each_comment_syntax(self):
        result = scan({
            "a.py": "x = 1\n# y = f(x)\n# if y:\n#     return (y)\n# z = [y]\n",
            "b.js": "let x;\n// x = f();\n// if (x) {\n//   g(x);\n// }\n",
            "c.sql": "-- SELECT a FROM t;\n-- SELECT b FROM t;\n-- UPDATE t SET a = (1);\n-- INSERT INTO t (a);\n",
            "d.rs": "fn main() {}\n// let a = f();\n// let b = g(a);\n// if a { h(); }\n// return (b);\n",
        })
        self.assertEqual([row["location"] for row in result["commented_code"]],
                         ["a.py:2-5", "b.js:2-5", "c.sql:1-4", "d.rs:2-5"])


class EnvReadTests(unittest.TestCase):
    def test_destructured_process_env_reads_count(self):
        result = scan({
            ".env.example": "PORT=3000\nDATABASE_URL=\nFEATURE_BETA=false\n",
            "server/config.js": ("const {\n  PORT = 3000,\n  DATABASE_URL: dbUrl,\n  FEATURE_BETA,\n"
                                 "} = process.env;\nmodule.exports = { PORT, dbUrl, FEATURE_BETA };\n"),
        })
        self.assertEqual(sorted(row["name"] for row in result["env_read"]), ["DATABASE_URL", "FEATURE_BETA", "PORT"])
        self.assertEqual({row["name"]: row["locations"] for row in result["env_read"]}["DATABASE_URL"],
                         ["server/config.js:3"])
        self.assertEqual(result["env_declared_not_read"], [])
        self.assertIn("FEATURE_BETA", [row["name"] for row in result["feature_flags"]])


class SkipDirectoryTests(unittest.TestCase):
    def test_source_directory_named_env_is_read_unless_it_is_a_virtualenv(self):
        result = scan({
            "src/env/schema.mjs": 'import { isUrl } from "../lib/validators.mjs";\nexport const url = isUrl(process.env.DATABASE_URL);\n',
            "src/lib/validators.mjs": "export function isUrl(value) { return value; }\n",
            "src/index.mjs": 'import { url } from "./env/schema.mjs";\nconsole.log(url);\n',
            "env/pyvenv.cfg": "home = /usr/bin\n",
            "env/lib/site.py": "def unused_in_venv(): pass\n",
        })
        self.assertEqual(result["orphan_files"], [])
        self.assertEqual([row["name"] for row in result["env_read"]], ["DATABASE_URL"])
        self.assertNotIn("unused_in_venv", [row["name"] for row in result["unreferenced_symbols"]])


if __name__ == "__main__":
    unittest.main()
