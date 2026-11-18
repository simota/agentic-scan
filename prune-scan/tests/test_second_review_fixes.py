"""Regression coverage for the second review round: bounded invocation and route
matching, secret-named sources, credential paths and prose annotations."""

import contextlib
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import contract_check  # noqa: E402
import findings  # noqa: E402
import inventory  # noqa: E402
import render  # noqa: E402
from test_deep_review_fixes import scan  # noqa: E402


class BoundedMatchingTests(unittest.TestCase):
    def assert_fast(self, files, limit=10):
        started = time.monotonic()
        result = scan(files)
        self.assertLess(time.monotonic() - started, limit)
        return result

    def test_overlapping_make_tokens_cannot_backtrack_exponentially(self):
        self.assert_fast({
            "Makefile": "build:\n\techo\nclean:\n\techo\na:\n\techo\n",
            "README.md": ("Run: make" + " -j=4" * 40 + " q\n" + "make" + " -C a" * 40 + " q\n"),
        })

    def test_route_mentions_start_once_per_path(self):
        self.assert_fast({"app.js": 'app.get("/items", h);\n', "data.txt": '"' + "/$" * 40000 + '"\n'})

    def test_jsonc_trailing_comma_lookahead_stays_linear(self):
        body = "".join(f'"k{n}": 1, /* c */\n' for n in range(6000))
        self.assert_fast({"tsconfig.json": "{" + body + '"last": 1}\n', "x.ts": "export const a = 1;\n"})

    def test_make_rules_and_npm_lines_stay_linear(self):
        self.assert_fast({
            "Makefile": "a" + " " * 80000 + "\nbuild:\n\techo\n",
            "package.json": '{"scripts": {"build": "x"}}',
            "notes.txt": "npm -a " * 20000 + "\n",
        })


class SecretSourceTests(unittest.TestCase):
    def test_secret_named_sources_export_no_literals(self):
        result = scan({
            "src/credentials.ts": ('const key = `AKIAIOSFODNN7EXAMPLE.${region}`;\n'
                                   'const cls = "sk_live_51HxQ2abcdEFGH-" + suffix;\n'
                                   'isEnabled("ghp_16C7e42F292c6912E7710c838347Ae178B4a");\n'
                                   'app.get("/sk_live_route", h);\n'),
            "src/index.ts": 'import "./credentials";\n',
        })
        serialized = json.dumps(result)
        for literal in ("AKIAIOSFODNN7EXAMPLE", "sk_live_", "ghp_16C7"):
            self.assertNotIn(literal, serialized)

    def test_ordinary_files_beside_credentials_are_read(self):
        result = scan({
            "package.json": '{"dependencies": {"js-yaml": "4"}, "scripts": {"build:prod": "x"}}',
            "src/kubeconfig.ts": 'import yaml from "js-yaml";\nimport { p } from "./paths";\nyaml.load(p);\n',
            "src/paths.ts": "export const p = 1;\n",
            "src/index.ts": 'import "./kubeconfig";\n',
            ".docker/Dockerfile": "RUN npm run build:prod\n",
            ".docker/config.json": '{"auths": {"r": {"auth": "c2VjcmV0"}}}\n',
            ".kube/config": "token: secret\n",
        })
        self.assertEqual(result["unimported_dependencies"], [])
        self.assertEqual(result["orphan_files"], [])
        self.assertEqual(result["uninvoked_scripts"], [])
        self.assertNotIn("c2VjcmV0", json.dumps(result))


class ThirdReviewTests(unittest.TestCase):
    def test_secret_named_sources_still_suppress_candidates(self):
        result = scan({
            "src/flags.ts": "export const FLAGS = {\n  newLogin: true,\n};\n",
            "src/useCredentials.ts": ('isEnabled("newLogin");\nt(`login.errors.${kind}`);\n'
                                      "const cls = `cred-${kind}`;\n"),
            "src/index.ts": 'import "./useCredentials";\nimport "./flags";\n',
            "src/locales/en.json": '{"login": {"errors": {"expired": "x", "invalid": "y"}}}',
            "src/app.css": ".cred-expired { color: red; }\n.cred-invalid { color: blue; }\n",
        })
        self.assertEqual([(row["name"], row["checks"]) for row in result["feature_flags"]], [("newLogin", 1)])
        self.assertEqual(result["i18n_unreferenced"], [])
        self.assertEqual(result["css_unreferenced"], [])
        self.assertEqual(result["i18n_dynamic_prefixes"], [])
        self.assertEqual(result["css_dynamic_prefixes"], [])

    def test_env_flags_read_only_in_secret_sources_are_not_rows(self):
        result = scan({
            "src/credentials.ts": "const a = process.env.ENABLE_PRIVATE_CUSTOMER;\nconst b = process.env.ENABLE_SHARED;\n",
            "src/app.ts": "const b = process.env.ENABLE_SHARED;\n",
        })
        self.assertEqual([(row["name"], row["checks"]) for row in result["feature_flags"]], [("ENABLE_SHARED", 2)])

    def test_kube_files_of_any_name_are_never_read(self):
        result = scan({".kube/prod.yaml": "# deprecated 2024-01-01 token SEKRITVALUE2\n"})
        self.assertEqual(result["files_scanned"], 0)
        self.assertNotIn("SEKRITVALUE2", json.dumps(result))

    def test_make_directory_option_selects_one_project(self):
        result = scan({
            "a/Makefile": "first:\n\techo\nsecond:\n\techo\n",
            "b/Makefile": "zero:\n\techo\nfirst:\n\techo\nsecond:\n\techo\n",
            "README.md": "Run `make -C a first second`.\n",
        })
        invoked = {(row["source"], row["name"]): row["invocations"] for row in result["scripts"]}
        self.assertEqual(invoked[("a/Makefile", "second")], 1)
        self.assertEqual((invoked[("b/Makefile", "first")], invoked[("b/Makefile", "second")]), (0, 0))

    def test_package_manager_counts_only_the_script_it_runs(self):
        result = scan({
            "package.json": json.dumps({"scripts": {"run": "x", "web": "x", "build": "x", "test": "x",
                                                    "lint": "x", "dev": "x"}}),
            "README.md": ("npm --prefix web run build\nnpm test\nyarn workspace web lint\n"
                          "pnpm --filter web dev -- --port 1\n"),
        })
        invoked = {row["name"]: row["invocations"] for row in result["scripts"]}
        self.assertEqual(invoked, {"run": 0, "web": 0, "build": 1, "test": 1, "lint": 1, "dev": 1})

    def test_kube_directory_is_never_read(self):
        result = scan({".kube/config.prod": "server: https://k8s.example  # TODO 2024-01-01 SEKRITVALUE1\n"})
        self.assertEqual(result["files_scanned"], 0)
        self.assertNotIn("SEKRITVALUE1", json.dumps(result))

    def test_extends_diamonds_and_long_chains_are_walked_once(self):
        files = {"tsconfig.c0.json": '{"compilerOptions": {"paths": {"@x/*": ["./x/*"]}}}',
                 "tsconfig.c1.json": '{"extends": "./tsconfig.c0.json"}'}
        for i in range(2, 40):
            files[f"tsconfig.c{i}.json"] = json.dumps({"extends": [f"./tsconfig.c{i - 2}.json",
                                                                 f"./tsconfig.c{i - 1}.json"]})
        files["tsconfig.json"] = '{"extends": "./tsconfig.c39.json"}'
        files["main.ts"] = 'import { a } from "@x/a";\na();\n'
        files["x/a.ts"] = "export function a() {}\n"
        started = time.monotonic()
        result = scan(files)
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(result["orphan_files"], [])

    def test_many_targets_and_module_runs_stay_fast(self):
        files = {f"mk/part{i}.mk": "".join(f"t{i}_{j}:\n\techo\n" for j in range(30)) for i in range(40)}
        files["Makefile"] = "".join(f"include mk/part{i}.mk\n" for i in range(40))
        files["notes.txt"] = "".join(f"make t{i}_0 t{i}_1\n" for i in range(40)) + "make" + " -make" * 8000 + "\n"
        files["README.md"] = "".join(f"python -m pkg.job{i}\n" for i in range(3000))
        files.update({f"pkg/mod{i}.py": "def f():\n    pass\n" for i in range(1500)})
        started = time.monotonic()
        result = scan(files)
        self.assertLess(time.monotonic() - started, 30)
        invoked = {row["name"]: row["invocations"] for row in result["scripts"]}
        self.assertEqual((invoked["t1_0"], invoked["t1_1"], invoked["t1_2"]), (1, 1, 0))

    def test_long_tokens_and_many_command_starts_stay_linear(self):
        files = {"package.json": '{"scripts": {"build": "x", "a/a": "x"}}', "Makefile": "build:\n\techo\n",
                 "a.txt": "npm run " + "a/" * 100000 + "\n", "b.txt": "make " + "a/" * 100000 + "\n",
                 "c.txt": "make " * 200000 + "\n", "d.txt": "npm " * 200000 + "\n"}
        started = time.monotonic()
        result = scan(files)
        self.assertLess(time.monotonic() - started, 15)
        invoked = {row["name"]: row["invocations"] for row in result["scripts"]}
        self.assertEqual(invoked["a/a"], 1)

    def test_python_module_run_before_a_period(self):
        result = scan({"README.md": "Run the job with python -m app.nightly.\n",
                       "app/nightly.py": "def run():\n    pass\n"})
        self.assertEqual(result["orphan_files"], [])


class MatchingRegressionTests(unittest.TestCase):
    def test_import_specifiers_are_not_route_mentions(self):
        result = scan({
            "server/app.py": '@app.get("/users")\ndef users():\n    pass\n',
            "web/src/main.js": 'import UsersPage from "@/pages/users";\nimport x from "~/a/users";\n',
        })
        self.assertEqual([row["mentions"] for row in result["routes"]], [0])

    def test_shell_variable_mounts_still_mention_a_route(self):
        result = scan({
            "server/routes.js": 'router.get("/users", h);\n',
            "scripts/smoke.sh": "curl https://example.com/api/$VERSION/users\n",
        })
        self.assertEqual([row["mentions"] for row in result["routes"]], [1])

    def test_a_nested_config_without_aliases_blocks_the_root_paths(self):
        result = scan({
            "tsconfig.json": '{"compilerOptions": {"paths": {"@/*": ["./src/*"]}}}',
            "src/foo.ts": "export function foo() {}\n",
            "src/main.ts": 'import { foo } from "./foo";\nfoo();\n',
            "packages/app/tsconfig.json": '{"compilerOptions": {"strict": true}}',
            "packages/app/main.ts": 'import { bar } from "@/bar";\nbar();\n',
            "src/bar.ts": "export function bar() {}\n",
        })
        self.assertEqual([row["path"] for row in result["orphan_files"]], ["src/bar.ts"])

    def test_python_module_runs_resolve_dotted_paths(self):
        result = scan({
            "README.md": "Run `python -m json.tool data.json` or `python -m http.server`.\n",
            "scripts/tool.py": "def main():\n    pass\n",
            "web/server.py": "def main():\n    pass\n",
            "Makefile": "run:\n\tpython -m app.cli\n",
            "app/cli/__main__.py": "print()\n",
        })
        self.assertEqual([row["path"] for row in result["orphan_files"]], ["scripts/tool.py"])

    def test_opentelemetry_sdk_needs_its_own_import(self):
        result = scan({
            "requirements.txt": "opentelemetry-api\nopentelemetry-sdk\n",
            "app/run.py": "from opentelemetry import trace\n",
        })
        self.assertEqual([row["name"] for row in result["unimported_dependencies"]], ["opentelemetry-sdk"])

    def test_targets_of_included_makefiles_share_a_command_line(self):
        result = scan({
            "Makefile": "include common.mk\nbuild:\n\techo\n",
            "common.mk": "deps:\n\techo\n",
            ".github/workflows/ci.yml": "steps:\n  - run: make deps build\n",
        })
        invocations = {row["name"]: row["invocations"] for row in result["scripts"]}
        self.assertEqual(invocations, {"build": 1, "deps": 1})

    def test_unrelated_makefiles_do_not_share_command_lines(self):
        result = scan({
            "a/Makefile": "first:\n\techo\n",
            "b/Makefile": "zero:\n\techo\nsecond:\n\techo\n",
            "README.md": "Run `make -C a first second`.\n",
            "c/Makefile": "include rules.mk\nall: deps\n",
            "c/rules.mk": "lint:\n\techo\ndeps:\n\techo\n",
        })
        uninvoked = sorted(f"{row['source']}:{row['name']}" for row in result["uninvoked_scripts"])
        self.assertEqual(uninvoked, ["b/Makefile:second"])

    def test_secret_route_definitions_are_not_mentions(self):
        result = scan({
            "server/app.js": 'app.get("/users", h);\n',
            "src/credentials.ts": 'app.get("/users", h);\n',
        })
        self.assertEqual([(row["location"], row["mentions"]) for row in result["routes"]], [("server/app.js:1", 0)])

    def test_tsconfig_extends_carries_paths(self):
        result = scan({
            "tsconfig.base.json": '{"compilerOptions": {"paths": {"@shared/*": ["packages/shared/src/*"]}}}',
            "packages/app/tsconfig.json": '{"extends": "../../tsconfig.base", "compilerOptions": {"strict": true}}',
            "packages/app/src/main.ts": 'import { fmt } from "@shared/fmt";\nfmt();\n',
            "packages/shared/src/fmt.ts": "export function fmt() {}\n",
            "packages/shared/src/orphan.ts": "export function o() {}\n",
        })
        self.assertEqual([row["path"] for row in result["orphan_files"]], ["packages/shared/src/orphan.ts"])


class ProseAndContractTests(unittest.TestCase):
    def test_notes_before_a_sentence_period_are_annotations(self):
        mapping = {"P-001": "P-901", "P-002": "P-902"}
        index = findings.SourceLiteralIndex([])
        for text, expected in {"Remove /debug/dump(P-002).": "Remove /debug/dump(P-902).",
                               "Remove server/app.py(P-002).": "Remove server/app.py(P-902).",
                               "src/report(P-002).md": "src/report(P-002).md"}.items():
            with self.subTest(text=text):
                self.assertEqual(findings.rewrite_prose(text, mapping, index), expected)

    @unittest.skipUnless(hasattr(os, "symlink"), "needs symbolic links")
    def test_symlinked_allowed_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            out, elsewhere = Path(tmp) / "out", Path(tmp) / "ja"
            out.mkdir()
            data = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
            data["limitations"] = ["report.pdf not produced: this test checks HTML"]
            (out / "findings.json").write_text(json.dumps(data), encoding="utf-8")
            (out / "units.json").write_bytes((ROOT / "examples" / "units.sample.json").read_bytes())
            (out / "inventory.json").write_text('{"tool": "inventory.py"}\n', encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                for target, lang in ((out, "en"), (elsewhere, "ja")):
                    self.assertEqual(render.main([str(out / "findings.json"), "--out", str(target),
                                                  "--lang", lang, "--no-pdf"]), 0)
            (out / "ja").symlink_to(elsewhere, target_is_directory=True)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
                status = contract_check.main([str(out), "--no-pdf", "--allow", "ja"])
            self.assertEqual(status, 1)
            self.assertIn("ja: a symbolic link to a directory", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
