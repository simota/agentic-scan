"""Regression coverage for the ninth review round: Go methods, Python modules
loaded by dotted name, bare getenv/environ reads, byte order marks, exported
flag constants, route mention prefiltering and punctuation-only reasons."""

import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from test_deep_review_fixes import scan  # noqa: E402
import test_records_fourth_review  # noqa: E402


def symbols(result):
    return {row["name"] for row in result["unreferenced_symbols"]}


def orphans(result):
    return {row["path"] for row in result["orphan_files"]}


class GoMethodTests(unittest.TestCase):
    def test_methods_are_not_unreferenced_symbols_but_functions_still_are(self):
        result = scan({"main.go": ("package main\n\ntype handler struct{}\n\n"
                                   "func (h *handler) ServeHTTP(w int, r int) {}\n"
                                   "func (h handler) String() string { return \"\" }\n"
                                   "func unusedHelper() {}\n\nfunc main() { _ = handler{} }\n")})
        self.assertNotIn("ServeHTTP", symbols(result))
        self.assertNotIn("String", symbols(result))
        self.assertIn("unusedHelper", symbols(result))


class DottedModuleTests(unittest.TestCase):
    def test_modules_named_in_django_settings_and_server_commands_are_not_orphans(self):
        result = scan({
            "manage.py": 'import os\nos.environ.setdefault("DJANGO_SETTINGS_MODULE", "mysite.settings")\n',
            "mysite/__init__.py": "",
            "mysite/settings.py": ('ROOT_URLCONF = "mysite.urls"\nINSTALLED_APPS = ["polls.apps.PollsConfig"]\n'
                                   'MIDDLEWARE = ["polls.middleware.TimingMiddleware"]\n'),
            "mysite/urls.py": "urlpatterns = []\n",
            "mysite/asgi.py": "application = None\n",
            "polls/__init__.py": "",
            "polls/apps.py": "class PollsConfig:\n    name = 'polls'\n",
            "polls/middleware.py": "class TimingMiddleware:\n    pass\n",
            "Procfile": "web: uvicorn mysite.asgi:application\n",
            "polls/unused.py": "def nothing():\n    pass\n",
            "tests/test_unused.py": 'def test_it(monkeypatch):\n    monkeypatch.setattr("polls.unused.nothing", None)\n',
        })
        found = orphans(result)
        for path in ("mysite/settings.py", "mysite/urls.py", "mysite/asgi.py", "polls/apps.py",
                     "polls/middleware.py"):
            self.assertNotIn(path, found)
        self.assertIn("polls/unused.py", found)

    def test_file_names_and_plain_pairs_do_not_hide_orphans(self):
        result = scan({
            "main.py": ('open("config.json")\nopen("settings.yaml")\nX = {"a": 1}\nY = "image:latest"\n'
                        'HOST = "api.example.com"\n'),
            "api.py": "D = 1\n",
            "config.py": "A = 1\n",
            "settings.py": "B = 1\n",
            "image.py": "C = 1\n",
        })
        self.assertTrue({"config.py", "settings.py", "image.py", "api.py"} <= orphans(result), orphans(result))


class EnvironmentReadTests(unittest.TestCase):
    def test_imported_getenv_and_environ_are_reads(self):
        result = scan({
            ".env.example": "DATABASE_URL=\nPAGE_SIZE=\n",
            "config.py": ('from os import getenv, environ\nURL = getenv("DATABASE_URL")\n'
                          'SIZE = environ.get("PAGE_SIZE")\n'),
        })
        self.assertEqual({row["name"] for row in result["env_read"]}, {"DATABASE_URL", "PAGE_SIZE"})
        self.assertEqual(result["env_declared_not_read"], [])

    def test_a_method_named_getenv_is_not_an_environment_read(self):
        result = scan({"config.py": 'URL = settings.getenv("DATABASE_URL")\nX = self.environ["PAGE"]\n'})
        self.assertEqual(result["env_read"], [])


class ByteOrderMarkTests(unittest.TestCase):
    def test_a_bom_does_not_hide_the_first_key_of_json_and_env_files(self):
        result = scan({
            "package.json": '﻿{"dependencies": {"left-pad": "1"}, "scripts": {"lint": "eslint ."}}',
            ".env.example": "﻿PORT=\n",
            "server.js": 'console.log(process.env.PORT);\n',
        })
        self.assertEqual(result["dependencies_declared"], [{"manifest": "package.json", "count": 1}])
        self.assertIn("lint", {row["name"] for row in result["scripts"]})
        self.assertEqual(result["env_read_not_declared"], [])


class FlagDefinitionTests(unittest.TestCase):
    def test_exported_constants_in_a_flag_file_are_definitions(self):
        result = scan({"web/src/flags.ts": ("export const NEW_CHECKOUT = true;\nconst DARK_MODE: boolean = false;\n"
                                            "export const flags = {\n  betaSearch: true,\n};\n")})
        values = {row["name"]: row["value"] for row in result["feature_flags"]}
        self.assertEqual(values, {"NEW_CHECKOUT": True, "DARK_MODE": False, "betaSearch": True})


class RouteMentionTests(unittest.TestCase):
    def test_many_routes_over_large_unrelated_files_stay_fast(self):
        files = {"server/app.py": "".join(f'@app.get("/r{n}/items")\ndef r{n}():\n    pass\n' for n in range(100))}
        files.update({f"docs/page{n}.md": "lorem ipsum dolor sit amet\n" * 4000 for n in range(40)})
        files["web/client.ts"] = 'fetch("/r7/items");\n'
        start = time.monotonic()
        result = scan(files)
        self.assertLess(time.monotonic() - start, 6)
        mentions = {row["route"]: row["mentions"] for row in result["routes"]}
        self.assertEqual(mentions["/r7/items"], 1)
        self.assertEqual(mentions["/r8/items"], 0)


class ReasonTests(unittest.TestCase):
    run_contract = test_records_fourth_review.ContractRuleTests.run_contract

    def test_a_punctuation_only_note_is_not_a_reason(self):
        for note in ("-", "…", "。", " ->"):
            with self.subTest(note=note):
                def bare(data):
                    data["perspectives"][5] = {"name": data["perspectives"][5]["name"], "result": "N/A", "note": note}
                problems = self.run_contract(bare)
                self.assertEqual(len(problems), 1, problems)
                self.assertIn("N/A without a reason", problems[0])

    def test_a_note_with_words_is_a_reason(self):
        def explained(data):
            data["perspectives"][5] = {"name": data["perspectives"][5]["name"], "result": "N/A",
                                       "note": "データベースなし"}
        self.assertEqual(self.run_contract(explained), [])

    def test_the_no_pdf_limitation_needs_a_worded_reason(self):
        for reason in ("-", " …", ""):
            with self.subTest(reason=reason):
                def punctuation(data):
                    data["limitations"] = [line for line in data["limitations"]
                                           if not line.startswith("report.pdf not produced")]
                    data["limitations"].append("report.pdf not produced:" + reason)
                problems = self.run_contract(punctuation)
                self.assertTrue(any("--no-pdf needs the line" in p for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
