"""Regression coverage for the fifth review round: route templates and trailing
slashes, Python import-name case, Make and npm command options, multi-target
Make rules, SQL string literals, Cargo dependency tables, secret-named excerpt
sources, N/A reasons, Unlikely findings' next action and second-language pages."""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import contract_check  # noqa: E402
import render  # noqa: E402
from test_deep_review_fixes import scan, write_tree  # noqa: E402
import test_records_fourth_review  # noqa: E402


def mentions(result):
    return {row["route"]: row["mentions"] for row in result["routes"]}


class RouteMatchingTests(unittest.TestCase):
    def test_template_parameters_with_spaces_or_quotes_still_name_the_route(self):
        result = scan({
            "server/api.js": 'router.get("/users/:id/posts", h);\nrouter.get("/orders/:id/items", h);\n',
            "web/client.js": 'fetch(`/users/${ user.id }/posts`);\nfetch(`/orders/${order["id"]}/items`);\n',
        })
        self.assertEqual(mentions(result), {"/users/:id/posts": 1, "/orders/:id/items": 1})
        self.assertEqual(result["unreferenced_routes"], [])

    def test_a_trailing_slash_on_either_side_names_the_same_route(self):
        result = scan({
            "server/urls.py": ('urlpatterns = [re_path(r"^api/items/$", v), path("api/orders/", v),\n'
                               '               path("api/tags/", v), path("api/users/", v)]\n'),
            "web/client.js": 'fetch("/api/items/");\nfetch("/api/orders");\nfetch(`/api/users/${id}`);\n'
                             'fetch("/api/users/42");\nfetch("/api/tags/?page=2");\n',
        })
        # /api/users/${id} and /api/users/42 are another route, not /api/users/.
        self.assertEqual(mentions(result), {"^api/items/$": 1, "api/orders/": 1, "api/tags/": 1,
                                            "api/users/": 0})


class DependencyTests(unittest.TestCase):
    def test_import_names_with_capitals_are_imports(self):
        result = scan({
            "requirements.txt": "PyQt5==5.15.9\nPySide6==6.6\nPillow\nmysqlclient\nunused-lib\n",
            "main.py": "from PyQt5.QtWidgets import QApplication\nimport PySide6\nfrom PIL import Image\n"
                       "import MySQLdb\n",
        })
        self.assertEqual([row["name"] for row in result["unimported_dependencies"]], ["unused-lib"])

    def test_cargo_dependency_tables_declare_one_dependency_each(self):
        result = scan({
            "Cargo.toml": ('[package]\nname = "x"\n[dependencies]\nanyhow = "1"\n[dependencies.serde]\n'
                           'version = "1"\nfeatures = ["derive"]\n[dev-dependencies.unusedcrate]\nversion = "1"\n'),
            "src/main.rs": "use anyhow::Result;\nuse serde::Serialize;\n",
        })
        self.assertEqual(result["dependencies_declared"], [{"manifest": "Cargo.toml", "count": 3}])
        self.assertEqual([(row["name"], row["location"]) for row in result["unimported_dependencies"]],
                         [("unusedcrate", "Cargo.toml:8")])


class CommandTests(unittest.TestCase):
    def scripts(self, files):
        return {row["name"]: (row["invocations"], row["default"], row["location"]) for row in scan(files)["scripts"]}

    def test_make_options_with_separate_values_do_not_end_the_command(self):
        rows = self.scripts({
            "Makefile": "all:\n\techo\ntest:\n\techo\nbuild:\n\techo\nrelease:\n\techo\nlint:\n\techo\n",
            ".github/workflows/ci.yml": ("steps:\n  - run: make -j 4 test\n  - run: make -j $(nproc) build\n"
                                         "  - run: make --directory . release\n  - run: make -j lint\n"),
        })
        self.assertEqual({name: row[0] for name, row in rows.items()},
                         {"all": 0, "test": 1, "build": 1, "release": 1, "lint": 1})

    def test_every_target_of_a_multi_target_rule_is_listed(self):
        rows = self.scripts({
            "Makefile": "all install: build\n\techo\nbuild:\n\techo\nclean distclean:\n\trm -rf out\n",
            "docs/dev.md": "Run `make distclean` to start over.\n",
        })
        self.assertEqual(rows, {"all": (0, True, "Makefile:1"), "install": (0, False, "Makefile:1"),
                                "build": (1, False, "Makefile:3"), "clean": (0, False, "Makefile:5"),
                                "distclean": (1, False, "Makefile:5")})

    def test_options_with_values_after_run_are_not_the_script(self):
        rows = self.scripts({
            "package.json": '{"private": true}',
            "web/package.json": '{"name": "web", "scripts": {"compile": "tsc", "lint": "eslint ."}}',
            ".github/workflows/ci.yml": ("steps:\n  - run: npm run --workspace web compile\n"
                                         "  - run: npm run --prefix web lint\n"),
        })
        self.assertEqual({name: row[0] for name, row in rows.items()}, {"compile": 1, "lint": 1})


class SqlStringTests(unittest.TestCase):
    def test_commas_inside_string_literals_do_not_start_columns(self):
        result = scan({
            "db/schema.sql": ("CREATE TABLE customers (\n  id INTEGER PRIMARY KEY,\n"
                              "  status VARCHAR(20) DEFAULT 'new, awaiting review',\n"
                              "  note TEXT COMMENT 'it''s, ok -- really',\n  legacy TEXT\n);\n"),
            "app.py": 'q = "select id, status, note from customers"\n',
        })
        self.assertEqual(result["sql_columns_unreferenced"],
                         [{"table": "customers", "column": "legacy", "location": "db/schema.sql:5"}])


class SecretExcerptTests(unittest.TestCase):
    def test_secret_named_files_and_secret_bearing_sources_are_not_excerpted(self):
        files = {
            "deploy/old.ppk": "PuTTY-User-Key-File-2: ssh-rsa\nPrivate-Lines: 14\nAAAAB3\n",
            "deploy/passwords.txt": "hunter2\n",
            ".vault-token": "hvs.CAESabc\n",
            "auth.json": '{"github-oauth": {"github.com": "ghp_ABC"}}\n',
            "deploy/htpasswd": "admin:$apr1$x\n",
            "server/db_pass.py": 'import os\nDB_PASS = "hunter2-prod"\n',
            "server/keys.py": 'import os\nSIGNING_KEY = "c2ln"\n',
            "server/url.py": 'import os\nDATABASE_URL = "postgres://larder:S3cretPw@db/x"\n',
            "server/plain.py": 'def f():\n    pass\nkey = d["key"]\nitems.sort(key=len)\nURL = "https://a.b/c:d@e"\n',
        }
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(Path(tmp), files)
            shown = {path for path in files if render.snippet(tmp, f"{path}:2")}
        self.assertEqual(shown, {"server/plain.py"})


class NotApplicableReasonTests(unittest.TestCase):
    run_contract = test_records_fourth_review.ContractRuleTests.run_contract

    def test_punctuation_alone_is_not_a_reason(self):
        for result in ("N/A：", "N/A。", "N/A…", "N/A ->"):
            with self.subTest(result=result):
                def bare(data):
                    data["perspectives"][5] = {"name": data["perspectives"][5]["name"], "result": result}
                problems = self.run_contract(bare)
                self.assertEqual(len(problems), 1, problems)
                self.assertIn("N/A without a reason", problems[0])

    def test_a_japanese_reason_is_a_reason(self):
        def explained(data):
            data["perspectives"][5] = {"name": data["perspectives"][5]["name"], "result": "N/A：データベースなし"}
        self.assertEqual(self.run_contract(explained), [])


class RenderedPageTests(unittest.TestCase):
    def render_out(self, tmp, change=lambda data: None):
        out = Path(tmp) / "out"
        out.mkdir()
        data = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
        data["limitations"] = ["report.pdf not produced: this test checks HTML"]
        change(data)
        (out / "findings.json").write_text(json.dumps(data), encoding="utf-8")
        (out / "units.json").write_bytes((ROOT / "examples" / "units.sample.json").read_bytes())
        (out / "inventory.json").write_text('{"tool": "inventory.py"}\n', encoding="utf-8")
        return out

    def test_an_unlikely_finding_has_no_next_action(self):
        def unlikely(data):
            data["findings"][2]["validation"]["verdict"] = "Unlikely"
        with tempfile.TemporaryDirectory() as tmp:
            out = self.render_out(tmp, unlikely)
            data = json.loads((out / "findings.json").read_text(encoding="utf-8"))
            units = json.loads((out / "units.json").read_text(encoding="utf-8"))
            items = {item["id"]: item for item in render.to_common(data, "en", units)["findings"]}
        self.assertNotIn("action", items["P-003"])
        self.assertIn("action", items["P-004"])

    def test_a_second_language_directory_needs_both_pages(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = self.render_out(tmp)
            with contextlib.redirect_stdout(io.StringIO()):
                for target, lang in ((out, "en"), (out / "ja", "ja")):
                    self.assertEqual(render.main([str(out / "findings.json"), "--out", str(target),
                                                  "--lang", lang, "--no-pdf"]), 0)
            self.assertEqual(list(contract_check.problems(out, no_pdf=True, allow=("ja",))), [])
            (out / "ja" / "report.html").unlink()
            problems = list(contract_check.problems(out, no_pdf=True, allow=("ja",)))
        self.assertEqual(len(problems), 1, problems)
        self.assertTrue(problems[0].startswith("ja/report.html: missing"), problems)


if __name__ == "__main__":
    unittest.main()
