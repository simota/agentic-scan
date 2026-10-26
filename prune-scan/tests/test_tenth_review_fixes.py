"""Regression coverage for the tenth review round: Django re_path regex routes, dependency scans,
nested feature flag definitions and sources in legacy encodings."""

import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "prune-scan" / "scripts"))

from test_deep_review_fixes import scan  # noqa: E402


def mentions(result):
    return {row["route"]: row["mentions"] for row in result["routes"]}


class RegexRouteTests(unittest.TestCase):
    def test_regex_syntax_matches_the_urls_that_name_the_route(self):
        result = scan({
            "server/urls.py": ('urlpatterns = [re_path(r"^feed\\.xml$", v), re_path(r"^orders/(\\d+)/$", v),\n'
                               '               re_path(r"^reports/?$", v), re_path(r"^tags/[a-z-]+/$", v),\n'
                               '               re_path(r"^users/(?P<pk>[0-9]+)/edit/$", v)]\n'),
            "web/base.html": '<link href="/feed.xml">\n',
            "web/client.js": 'fetch(`/orders/${id}/`);\nfetch("/reports");\nfetch("/tags/" + t);\n'
                             'fetch(`/tags/${t}/`);\nfetch(`/users/${pk}/edit/`);\n',
        })
        self.assertEqual(mentions(result), {"^feed\\.xml$": 1, "^orders/(\\d+)/$": 1, "^reports/?$": 1,
                                            "^tags/[a-z-]+/$": 1, "^users/(?P<pk>[0-9]+)/edit/$": 1})
        self.assertEqual(result["unreferenced_routes"], [])

    def test_regex_routes_nothing_names_are_still_listed(self):
        result = scan({
            "server/urls.py": 'urlpatterns = [re_path(r"^legacy/(\\d+)\\.json$", v)]\n',
            "web/client.js": 'fetch("/legacy.json");\nfetch("/legacy/7/json");\n',
        })
        self.assertEqual([row["route"] for row in result["unreferenced_routes"]], ["^legacy/(\\d+)\\.json$"])


class DependencyScanTests(unittest.TestCase):
    def test_tool_file_size_is_scanned_once_per_manifest_not_per_dependency(self):
        def elapsed(n):
            deps = ", ".join(f'"pkg-{i}": "1.0.0"' for i in range(n))
            start = time.perf_counter()
            result = scan({
                "package.json": '{"scripts": {"lint": "eslint ."}, "devDependencies": {"eslint": "9", %s}}' % deps,
                "deploy/values.yaml": "  - name: container-image-value-that-is-long\n    value: x\n" * 30000,
                ".github/workflows/ci.yml": "run: pkg-7 --check\n",
            })
            seconds = time.perf_counter() - start
            status = {row["name"]: row["status"] for row in result["unimported_dependencies"]}
            self.assertEqual((status["eslint"], status["pkg-7"], status["pkg-8"]),
                             ("script_only", "script_only", "unreferenced"))
            return seconds
        small, large = elapsed(20), elapsed(800)
        self.assertLess(large, max(small, 0.05) * 3)


class NestedFlagTests(unittest.TestCase):
    def flags(self, files):
        return {row["name"]: (row["value"], row["definitions"], row["checks"])
                for row in scan(files)["feature_flags"]}

    def test_an_enabled_field_names_the_key_that_encloses_it(self):
        self.assertEqual(self.flags({
            "config/flags.yaml": "new_checkout:\n  enabled: true\n  owner: payments\n"
                                 "legacy_search:  # retired\n  enabled: false\n",
            "web/features.json": '{\n  "dark_mode": {\n    "default": true\n  },\n  "beta_nav": false\n}\n',
            "server/toggles.toml": "[flags.bulk_import]\nenabled = false\n\n[flags.export_csv]\nenabled = true\n",
            "src/app.js": 'if (isEnabled("new_checkout")) { run(); }\n',
        }), {
            "new_checkout": (True, ["config/flags.yaml:2"], 1),
            "legacy_search": (False, ["config/flags.yaml:5"], 0),
            "dark_mode": (True, ["web/features.json:3"], 0),
            "beta_nav": (False, ["web/features.json:5"], 0),
            "bulk_import": (False, ["server/toggles.toml:2"], 0),
            "export_csv": (True, ["server/toggles.toml:5"], 0),
        })

    def test_an_unnested_field_name_is_still_its_own_flag(self):
        self.assertEqual(self.flags({"flags.py": "enabled = True\nFLAGS = {\n    'search_v2': True,\n}\n"}),
                         {"enabled": (True, ["flags.py:1"], 0), "search_v2": (True, ["flags.py:3"], 0)})



class LegacyEncodingTests(unittest.TestCase):
    def test_sources_in_legacy_encodings_still_count_their_imports_and_names(self):
        result = scan({
            "requirements.txt": "requests\n",
            "main.py": "# -*- coding: latin-1 -*-\n# caf\u00e9\nimport requests\nfrom helpers import slug\n"
                       .encode("latin-1"),
            "helpers.py": "def slug(text):\n    return text\n",
            "web/index.ts": '// \u8aac\u660e\nimport { fmt } from "./fmt";\nfmt();\n'.encode("shift_jis"),
            "web/fmt.ts": "export function fmt() {}\n",
        })
        self.assertEqual(result["files_skipped"], 0)
        self.assertEqual((result["unimported_dependencies"], result["orphan_files"], result["unreferenced_symbols"]),
                         ([], [], []))


if __name__ == "__main__":
    unittest.main()
