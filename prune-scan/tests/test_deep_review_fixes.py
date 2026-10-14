"""Regression coverage for the October 2026 deep review: inventory matching,
excerpt line numbers, credential files, second-language pages and prose IDs."""

import contextlib
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import contract_check  # noqa: E402
import findings  # noqa: E402
import inventory  # noqa: E402
import render  # noqa: E402
from test_findings_regressions import record, run_cli, units_record  # noqa: E402


def write_tree(root, files):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            path.write_bytes(text)
        else:
            path.write_text(text, encoding="utf-8")


def scan(files, **kwargs):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_tree(root, files)
        return inventory.inventory(root, today="2026-10-14", **kwargs)


class InventoryMatchingTests(unittest.TestCase):
    def test_secret_named_source_is_read_for_imports_but_never_excerpted(self):
        result = scan({
            "package.json": '{"dependencies": {"axios": "1"}}',
            "web/src/index.ts": 'import { useCredentials } from "./auth/useCredentials";\nuseCredentials();\n',
            "web/src/auth/useCredentials.ts": ('import axios from "axios";\nimport { fmt } from "../lib/fmt2";\n'
                                               "// deprecated 2020-01-01 plain marker\n"
                                               "export const useCredentials = () => fmt(axios);\n"),
            "web/src/lib/fmt2.ts": "export function fmt(x) { return x; }\n",
            "config/credentials.json": '{"deprecated": "2020-01-01 secret-value"}\n',
        })
        self.assertEqual(result["orphan_files"], [])
        self.assertEqual(result["unimported_dependencies"], [])
        self.assertNotIn("fmt", [row["name"] for row in result["unreferenced_symbols"]])
        self.assertEqual(result["files_skipped"], 1)  # credentials.json, a data file
        self.assertEqual([row["text"] for row in result["markers"]], ["[omitted: source may contain secrets]"])
        self.assertNotIn("secret-value", json.dumps(result))

    def test_credential_files_and_directories_are_never_read(self):
        names = (".htpasswd", ".pgpass", ".dockercfg", ".docker/config.json", ".kube/config", "ops/kubeconfig",
                 "infra/terraform.tfstate", "infra/terraform.tfstate.backup", "vault.kdbx")
        result = scan({name: "deprecated 2020-01-01 secret-value\n" for name in names})
        self.assertEqual(result["files_scanned"], 0)
        self.assertNotIn("secret-value", json.dumps(result))

    def test_python_packages_below_the_root_resolve(self):
        result = scan({
            "backend/app/main.py": "from app.models import User\nUser()\n",
            "backend/app/models.py": "class User:\n    pass\n",
        })
        self.assertEqual(result["orphan_files"], [])

    def test_tsconfig_paths_base_url_and_conventional_aliases_resolve(self):
        result = scan({
            "web/tsconfig.json": ('{\n  // comments and trailing commas are allowed\n'
                                  '  "compilerOptions": {"baseUrl": ".", "paths": {"#lib/*": ["./src/lib/*",],},},\n}\n'),
            "web/src/main.ts": ('import { a } from "#lib/alpha";\nimport { b } from "@/lib/beta";\n'
                                'import { c } from "src/lib/gamma";\na(); b(); c();\n'),
            "web/src/lib/alpha.ts": "export function a() {}\n",
            "web/src/lib/beta.ts": "export function b() {}\n",
            "web/src/lib/gamma.ts": "export function c() {}\n",
            "web/src/lib/orphan.ts": "export function d() {}\n",
        })
        self.assertEqual([row["path"] for row in result["orphan_files"]], ["web/src/lib/orphan.ts"])

    def test_namespace_python_distributions_and_go_indirect_requirements(self):
        result = scan({
            "requirements.txt": "azure-storage-blob\ngoogle-auth\nopentelemetry-api\nruamel.yaml\nunused-pkg\n",
            "app/run.py": ("from azure.storage.blob import BlobClient\nimport google.auth\n"
                           "from opentelemetry import trace\nfrom ruamel.yaml import YAML\n"),
            "go.mod": ("module example.com/m\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/sys v0.20.0 // indirect\n"
                       "\tgithub.com/pkg/errors v0.9.1\n)\n"),
            "main.go": 'package main\n\nimport "fmt"\n\nfunc main() { fmt.Println() }\n',
        })
        self.assertEqual(sorted(row["name"] for row in result["unimported_dependencies"]),
                         ["github.com/pkg/errors", "unused-pkg"])

    def test_css_imports_count_as_package_imports(self):
        result = scan({
            "package.json": '{"dependencies": {"normalize.css": "8", "bootstrap": "5", "unused": "1"}}',
            "web/main.scss": '@import "normalize.css";\n@use "~bootstrap/scss/grid";\n@use "sass:math";\n',
        })
        self.assertEqual([row["name"] for row in result["unimported_dependencies"]], ["unused"])

    def test_env_and_flag_rows_are_tagged_with_their_unit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_tree(root, {
                "server/config.py": 'import os\nTOKEN_URL = os.getenv("PAGE_SIZE")\n',
                "server/flags.py": 'FLAGS = {\n    "beta": True,\n}\n',
                ".env.example": "UNUSED_SETTING=\n",
            })
            units = {"units": [{"id": "UN-01", "kind": "area", "name": "Server", "paths": ["server/"]},
                               {"id": "UN-02", "kind": "shared", "name": "Config", "paths": [".env.example"]}]}
            result = inventory.inventory(root, today="2026-10-14", units=units)
        self.assertEqual(result["env_read"][0]["unit"], "UN-01")
        self.assertEqual(result["env_read_not_declared"][0]["unit"], "UN-01")
        self.assertEqual(result["feature_flags"][0]["unit"], "UN-01")
        self.assertEqual(result["env_declared_not_read"][0]["unit"], "UN-02")

    def test_mounted_server_routes_and_absolute_urls_are_mentions(self):
        result = scan({
            "server/routes.js": 'router.get("/items", list);\nrouter.get("/orphan", h);\napp.use("/api", router);\n',
            "server/app.py": '@app.get("/api/things")\ndef things():\n    pass\n',
            "web/src/client.js": ('fetch("/api/items");\nfetch("https://api.example.com/api/things");\n'
                                  'const path = "src/orphan.py";\n'),
            "web/src/App.tsx": '<Route path="/items/:id" element={<Item />} />\n',
        })
        mentions = {row["route"]: row["mentions"] for row in result["routes"]}
        self.assertEqual(mentions, {"/items": 1, "/orphan": 0, "/api/things": 1, "/items/:id": 0})

    def test_http_client_calls_are_not_server_routes(self):
        result = scan({
            "web/src/api.ts": ('import axios from "axios";\nconst api = axios.create({});\n'
                               'export const me = () => api.get("/users/me");\n'),
            "server/routes.js": 'const api = express.Router();\napi.get("/health", h);\n',
        })
        self.assertEqual([row["route"] for row in result["routes"]], ["/health"])

    def test_make_prerequisites_count_and_prose_does_not(self):
        result = scan({
            "Makefile": ("all: build\nbuild:\n\techo build\nrelease: build | lint\nlint:\n\techo\n"
                         ".PHONY: stale\nstale:\n\techo\ndeploy:\n\techo\nship:\n\techo\n"),
            "README.md": ("We make every effort so that people can release safely and deploy often.\n"
                          "Run `make -C . -s VERBOSE=1 lint ship`.\n"),
            "package.json": '{"scripts": {"build": "vite build", "watch": "vite"}}',
            ".github/workflows/ci.yml": "steps:\n  - run: npm --prefix web run build\n",
        })
        invocations = {(row["source"], row["name"]): row["invocations"] for row in result["scripts"]}
        self.assertEqual(invocations[("Makefile", "build")], 2)
        self.assertEqual(invocations[("Makefile", "lint")], 2)
        self.assertEqual(invocations[("Makefile", "ship")], 1)
        self.assertEqual(invocations[("package.json", "build")], 1)
        self.assertEqual(sorted(row["name"] for row in result["uninvoked_scripts"]),
                         ["deploy", "release", "stale", "watch"])

    def test_option_runs_cannot_make_invocation_matching_slow(self):
        line = ("make " + "-a " * 20000 + "\n" + "npm " + "--x y " * 5000 + "\n" + "npm " + "--x=1 --y " * 5000
                + "\nmake " + "-C d " * 5000 + "zzz\n")
        started = time.monotonic()
        scan({"Makefile": "".join(f"t{i}:\n\techo\n" for i in range(20)),
              "package.json": json.dumps({"scripts": {f"s{i}": "x" for i in range(20)}}),
              "notes.txt": line})
        self.assertLess(time.monotonic() - started, 10)

    def test_python_module_runs_name_their_file(self):
        result = scan({
            "Makefile": "nightly:\n\tpython3 -u -m server.jobs.nightly\n",
            "server/jobs/nightly.py": "def run():\n    pass\n\nrun()\n",
            "server/jobs/weekly.py": "def run():\n    pass\n\nrun()\n",
        })
        self.assertEqual([row["path"] for row in result["orphan_files"]], ["server/jobs/weekly.py"])

    def test_locale_keys_assets_and_css_selectors(self):
        result = scan({
            "web/src/locales/en.json": '{"save": "Save", "Delete item": "Delete", "nav": {"home": "Home"}, "gone": "x"}',
            "web/src/locales/ja.json": '{"save": "保存", "Delete item": "削除", "nav": {"home": "ホーム"}, "gone": "x"}',
            "web/src/main.ts": 't("common:save");\nt("Delete item");\nt("common:nav.home");\n',
            "web/index.html": '<img src="/img/logo@2x.png">\n<div class="used"></div>\n',
            "web/public/img/logo@2x.png": b"\x89PNG\r\n",
            "web/public/img/unused@3x.png": b"\x89PNG\r\n",
            "web/src/main.css": 'a[href$=".pdf"] { color: red; }\n.used, [data-x="y.z"] .missing { color: blue; }\n',
        })
        self.assertEqual([row["key"] for row in result["i18n_unreferenced"]], ["gone"])
        self.assertEqual([row["path"] for row in result["assets_unreferenced"]], ["web/public/img/unused@3x.png"])
        self.assertEqual([(row["class"], row["location"]) for row in result["css_unreferenced"]],
                         [("missing", "web/src/main.css:2")])

    def test_sql_comments_do_not_create_columns(self):
        result = scan({
            "db/schema.sql": ("CREATE TABLE items (\n  id INTEGER PRIMARY KEY, -- stable id, never reused\n"
                              "  name TEXT /* shown, sorted */,\n  extra TEXT\n);\n"),
            "app.py": "QUERY = 'SELECT id, name FROM items'\n",
        })
        self.assertEqual([(row["column"], row["location"]) for row in result["sql_columns_unreferenced"]],
                         [("extra", "db/schema.sql:4")])

    def test_line_numbers_count_newlines_only(self):
        result = scan({"server/app.py": "x = 1\f\n# legacy note\n# TODO 2020-01-01 drop this\n"})
        self.assertEqual([row["location"] for row in result["markers"]], ["server/app.py:3"])


class RenderAndContractTests(unittest.TestCase):
    def test_excerpts_keep_path_line_numbering_with_other_separators(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_tree(root, {"server/app.py": ("one = 1\n"
                                                "page = 2\f# form feed\n"
                                                "s = 'a b\x85c'\n"
                                                "crlf = 4\r\n"
                                                "def target():\n"
                                                "    pass\n")})
            excerpt = render.snippet(str(root), "server/app.py:5")
        self.assertEqual(excerpt["hit"], [5, 5])
        self.assertEqual(excerpt["lines"][excerpt["hit"][0] - excerpt["start"]], "def target():")
        self.assertEqual(len(excerpt["lines"]), 5)
        self.assertFalse(any(render.LINE_BREAKS.search(line) for line in excerpt["lines"]))
        self.assertEqual(excerpt["lines"][2], "crlf = 4")

    def test_credential_files_are_never_excerpted(self):
        files = {".htpasswd": "admin:$apr1$hash\n", "deploy/.pgpass": "db:5432:app:app:pw\n",
                 "deploy/.docker/config.json": '{"auths": {"r": {"auth": "YWRtaW4="}}}\n',
                 "ops/kubeconfig": "users:\n- user:\n    client-key-data: LS0t\n", "kube/.kube/config": "x\n",
                 "infra/terraform.tfstate": "{}\n", "vault.kdbx": "x\n", "app.py": "client_key = load()\n"}
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(Path(tmp), files)
            for name in files:
                with self.subTest(name=name):
                    self.assertIsNone(render.snippet(tmp, f"{name}:1"))

    def test_invalid_pdf_timeout_is_refused_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "findings.json").write_text(json.dumps(record()), encoding="utf-8")
            for value in ("300s", "5m", "abc", "0", "-1", "inf", "nan"):
                with self.subTest(value=value), mock.patch.dict(os.environ, {"PRUNE_SCAN_PDF_TIMEOUT": value}):
                    stderr = io.StringIO()
                    with contextlib.redirect_stderr(stderr):
                        status = render.main([str(out / "findings.json"), "--out", str(out)])
                    self.assertEqual(status, 2)
                    self.assertIn("PRUNE_SCAN_PDF_TIMEOUT", stderr.getvalue())
                    self.assertFalse((out / "report.html").exists())
            with mock.patch.dict(os.environ, {"PRUNE_SCAN_PDF_TIMEOUT": "300s"}), \
                    contextlib.redirect_stdout(io.StringIO()):
                # No PDF is attempted, so the variable does not matter.
                self.assertEqual(render.main([str(out / "findings.json"), "--out", str(out), "--no-pdf"]), 0)

    def write_run(self, out):
        data = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
        data["limitations"] = ["report.pdf not produced: this test checks HTML"]
        (out / "findings.json").write_text(json.dumps(data), encoding="utf-8")
        (out / "units.json").write_bytes((ROOT / "examples" / "units.sample.json").read_bytes())
        (out / "inventory.json").write_text('{"tool": "inventory.py"}\n', encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(render.main([str(out / "findings.json"), "--out", str(out), "--lang", "ja",
                                          "--no-pdf"]), 0)
            self.assertEqual(render.main([str(out / "findings.json"), "--out", str(out / "en"), "--lang", "en",
                                          "--no-pdf"]), 0)

    def check(self, out, *allow):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
            status = contract_check.main([str(out), "--no-pdf", *(f"--allow={name}" for name in allow)])
        return status, stderr.getvalue()

    def test_allowed_second_language_must_show_the_current_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            self.write_run(out)
            self.assertEqual(self.check(out, "en"), (0, ""))
            self.assertEqual(self.check(out, "en/")[0], 0)  # Tab completion adds the slash.
            data = json.loads((out / "findings.json").read_text(encoding="utf-8"))
            data["summary"] = "Changed after the English pages were rendered."
            (out / "findings.json").write_text(json.dumps(data), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                render.main([str(out / "findings.json"), "--out", str(out), "--lang", "ja", "--no-pdf"])
            status, stderr = self.check(out, "en")
            self.assertEqual(status, 1)
            self.assertIn("en/dashboard.html: stale", stderr)
            self.assertIn("en/report.html: stale", stderr)
            self.assertIn("--lang en", stderr)

    def test_allow_rejects_names_outside_the_output_directory(self):
        for value in ("a/b", "..", ".", "/"):
            with self.subTest(value=value), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    contract_check.main([".", f"--allow={value}"])
                self.assertEqual(raised.exception.code, 2)


class FindingsRecordTests(unittest.TestCase):
    MAPPING = {"P-001": "P-007", "P-002": "P-009", "P-003": "P-010"}

    def rewrite(self, text):
        return findings.rewrite_prose(text, self.MAPPING, findings.SourceLiteralIndex([]))

    def test_references_after_paths_in_japanese_prose_are_renumbered(self):
        cases = {
            "server/app.pyを削除してP-001を直す。": "server/app.pyを削除してP-007を直す。",
            "web/src/Leaderboard.tsxはP-002で扱う": "web/src/Leaderboard.tsxはP-009で扱う",
            "web/src/flags.ts(P-002)": "web/src/flags.ts(P-009)",
            "/debug/dumpとP-002": "/debug/dumpとP-009",
            "/debug/dump(P-002)からも漏れる。": "/debug/dump(P-009)からも漏れる。",
            "/api/leaderboard(P-002、P-003)": "/api/leaderboard(P-009、P-010)",
            "server/(P-002)": "server/(P-009)",
            "P-003/app.pyを削除してP-001": "P-003/app.pyを削除してP-007",
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(self.rewrite(text), expected)

    def test_source_names_after_paths_stay_literal(self):
        for text in ("src/[[...P-002]].tsx", "./report.資料P-002", "src/資料(P-002).md", "src/report(P-002).md",
                     "src/資料(P-002)はじめに.md", "docs/資料P-002", "P-002/P-001.資料", "./P-002/P-001資料"):
            with self.subTest(text=text):
                self.assertEqual(self.rewrite(text), text)

    def test_japanese_sample_reference_follows_a_renumber(self):
        data = json.loads((ROOT / "examples" / "findings.sample.ja.json").read_text(encoding="utf-8"))
        impact = next(f for f in data["findings"] if f["id"] == "P-004")["impact"]
        self.assertIn("/debug/dump(P-002)", impact)
        mapping = {f["id"]: f["id"] for f in data["findings"]}
        mapping["P-002"] = "P-036"
        self.assertIn("/debug/dump(P-036)", findings.rewrite_prose(impact, mapping, findings.SourceLiteralIndex([])))

    def test_an_entry_point_can_be_detached(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "units.json").write_text(json.dumps(units_record()), encoding="utf-8")
            base = record()
            base["findings"][0]["entry_ref"] = "EP-01"
            (out / "findings.json").write_text(json.dumps(base), encoding="utf-8")
            (out / "fragment.json").write_text(json.dumps({"findings": [{"id": "P-001", "entry_ref": ""}]}),
                                               encoding="utf-8")
            result = run_cli("merge", out / "findings.json", out / "fragment.json")
            self.assertEqual(result.returncode, 0, result.stderr)
            merged = json.loads((out / "findings.json").read_text(encoding="utf-8"))
            self.assertEqual(merged["findings"][0]["entry_ref"], "")

    def test_directory_targets_exit_2_without_a_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            fragment = Path(tmp) / "fragment.json"
            fragment.write_text("{}", encoding="utf-8")
            for args in (("merge", tmp, fragment), ("units", ".", fragment), ("check", "..")):
                with self.subTest(args=args):
                    result = subprocess.run([sys.executable, str(SCRIPTS / "findings.py"), *map(str, args)],
                                            capture_output=True, text=True, cwd=tmp)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertNotIn("Traceback", result.stderr)


class SampleConsistencyTests(unittest.TestCase):
    def test_perspective_results_count_their_findings(self):
        for name in ("findings.sample.json", "findings.sample.ja.json"):
            data = json.loads((ROOT / "examples" / name).read_text(encoding="utf-8"))
            for perspective in data["perspectives"]:
                family = perspective["name"][:2]
                members = [f for f in data["findings"] if f["perspective"].startswith(family)]
                excluded = sum(1 for f in members if f["validation"]["verdict"] in findings.EXCLUDED)
                numbers = [int(n) for n in re.findall(r"[0-9]+", perspective["result"])]
                with self.subTest(sample=name, family=family):
                    self.assertEqual(numbers, [len(members) - excluded] + ([excluded] if excluded else []))

    def test_occurrences_stay_inside_the_fixture(self):
        data = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
        for finding in data["findings"]:
            for location in [finding["location"], *finding.get("occurrences", [])]:
                path, _, line = location.rpartition(":")
                lines = (ROOT / "examples" / "larder" / path).read_bytes().split(b"\n")
                with self.subTest(finding=finding["id"], location=location):
                    self.assertLessEqual(int(line.split("-")[0]), len(lines))


if __name__ == "__main__":
    unittest.main()
