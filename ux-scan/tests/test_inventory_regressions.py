"""Regression coverage for repository inventory parsing and file boundaries."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "ux-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import inventory  # noqa: E402


class InventoryRegressionTests(unittest.TestCase):
    def scan(self, files):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, contents in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents, encoding="utf-8")
            return inventory.inventory(root)

    def run_cli(self, repo, out, *args, timeout=5):
        return subprocess.run(
            [sys.executable, str(SCRIPTS / "inventory.py"), str(repo), "--out", str(out), *map(str, args)],
            capture_output=True, text=True, timeout=timeout,
        )

    def test_css_comment_without_braces_completes(self):
        # A valid large comment used to trigger quadratic retries in BLOCK.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "banner.css").write_text("/*" + "x" * 1_000_000 + "*/\n", encoding="utf-8")
            out = root / "inventory.json"
            result = self.run_cli(repo, out)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["files_scanned"], 1)

    def test_css_rule_boundaries_keep_adjacent_and_nested_rules(self):
        data = self.scan({"a.css":
            ".btn { width: 20px; }.icon { height: 30px; }\n"
            "@media (max-width: 600px) {\n"
            "  .close { min-width: 21px; }\n"
            "  .link:focus { outline: none; }\n"
            "}\n"
            ".toggle { height: 22px; }\n"})
        self.assertEqual([(r["selector"], r["location"]) for r in data["tap_targets"]], [
            (".btn", "a.css:1"), (".icon", "a.css:1"),
            (".close", "a.css:3"), (".toggle", "a.css:6"),
        ])
        self.assertEqual(data["focus_outline"][0]["location"], "a.css:4")

    def test_css_comments_do_not_create_candidates_and_preserve_lines(self):
        data = self.scan({"a.css":
            "/*\n"
            ".btn { width: 20px; outline: none; padding: 13px; z-index: 999; transition: all 1s; }\n"
            "*/\n"
            '.btn::before { content: "/* visible text */"; height: 30px; padding: 8px; }\n'})
        self.assertEqual(data["spacing"], [{"value": "8px", "count": 1, "locations": ["a.css:4"]}])
        self.assertEqual(data["z_index"], [])
        self.assertEqual(data["focus_outline"], [])
        self.assertEqual(data["motion"]["declarations"], 0)
        self.assertEqual([(row["selector"], row["location"]) for row in data["tap_targets"]],
                         [(".btn::before", "a.css:4")])

    def test_embedded_styles_keep_css_locations_without_counting_script_styles_twice(self):
        data = self.scan({"a.vue":
            '<template><button style="padding: 8px">Save</button></template>\n'
            '<script>const style = {padding: "16px"};</script>\n'
            '<style>\n'
            '/* .btn { width: 12px; padding: 99px; outline: none; } */\n'
            '.btn { width: 30px; padding: 24px; }\n'
            '</style>\n'})
        self.assertEqual(data["spacing"], [
            {"value": "16px", "count": 1, "locations": ["a.vue:2"]},
            {"value": "24px", "count": 1, "locations": ["a.vue:5"]},
            {"value": "8px", "count": 1, "locations": ["a.vue:1"]},
        ])
        self.assertEqual([(row["selector"], row["location"]) for row in data["tap_targets"]],
                         [(".btn", "a.vue:5")])
        self.assertEqual(data["focus_outline"], [])

    def test_html_script_style_objects_are_scanned_once(self):
        data = self.scan({"index.html":
            '<div style="padding: 8px">Save</div>\n'
            '<script>Object.assign(document.body.style, {padding: "16px"});</script>\n'})
        self.assertEqual(data["spacing"], [
            {"value": "16px", "count": 1, "locations": ["index.html:2"]},
            {"value": "8px", "count": 1, "locations": ["index.html:1"]},
        ])

    def test_html_comment_markers_in_strings_do_not_hide_real_styles(self):
        data = self.scan({"a.vue":
            '<!-- <img src="commented.png"> -->\n'
            '<style>.before::before {content: "<!--";}\n'
            '.btn {padding: 13px;}\n'
            '.after::after {content: "-->";}</style>\n'
            '<script>const opening = "<!--"; const style = {padding: 16}; const closing = "-->";</script>\n'
            '<button title="<!--"><svg /></button><div title="-->"></div>\n'})
        self.assertEqual(data["spacing"], [
            {"value": "13px", "count": 1, "locations": ["a.vue:3"]},
            {"value": "16px", "count": 1, "locations": ["a.vue:5"]},
        ])
        self.assertEqual(data["images"], [])

    def test_js_strings_with_comment_markers_do_not_hide_later_candidates(self):
        for extension in ("js", "jsx", "tsx", "mjs"):
            with self.subTest(extension=extension):
                name = f"a.{extension}"
                data = self.scan({name:
                    'const stripComment = (s) => s.replaceAll("<!--", "");\n'
                    'const jsxStart = "{/*";\n'
                    'const style = { padding: 16 };\n'
                    'const jsxEnd = "*/}"; const htmlEnd = "-->";\n'
                    'const view = <img src="photo.png" />;\n'
                    '{/* <img src="commented.png" /> padding: 99 */}\n'})
                self.assertEqual(data["spacing"], [{"value": "16px", "count": 1, "locations": [f"{name}:3"]}])
                self.assertEqual([row["location"] for row in data["images"]], [f"{name}:5"])

    def test_unclosed_comment_marker_does_not_erase_remaining_source(self):
        data = self.scan({"a.html": '<!-- unclosed\n<img src="photo.png">\n'})
        self.assertEqual([row["location"] for row in data["images"]], ["a.html:2"])

    def test_dense_css_keeps_counts_and_precise_first_locations(self):
        count = 20_000
        data = self.scan({"a.css": ".btn { padding: 8px; }\n" * count + ".end { padding: 13px; }\n"})
        self.assertEqual(data["spacing"], [
            {"value": "8px", "count": count, "locations": [f"a.css:{i}" for i in range(1, 6)]},
            {"value": "13px", "count": 1, "locations": [f"a.css:{count + 1}"]},
        ])

    def test_source_lines_handle_unicode_and_newline_boundaries(self):
        text = "日本語\n\nlast\r\n"
        source_lines = inventory.SourceLines(text)
        expected = [1, 1, 1, 1, 2, 3, 3, 3, 3, 3, 3, 4]
        self.assertEqual([source_lines(i) for i in range(len(text) + 1)], expected)

    def test_long_unitless_css_number_does_not_hide_following_lengths(self):
        # This input formerly caused quadratic backtracking in the length regex.
        data = self.scan({"a.css": ".x { padding: " + "9" * 50_000 + "; margin: -.5rem .25em; }\n"})
        self.assertEqual({row["value"] for row in data["spacing"]}, {"-8px", "4px"})

    def test_extreme_numeric_literals_are_warned_and_other_candidates_survive(self):
        giant = "9" * 4_400
        overflow = "9" * 400
        data = self.scan({
            "a.css": f".x {{ z-index: {giant}; padding: 8px; }}\n"
                     f".x {{ font-size: {overflow}px; width: {overflow}px; }}\n",
            "b.jsx": f"const style = {{ zIndex: {giant}, padding: 16 }};\n<img src=\"x\" />\n",
        })
        self.assertEqual(data["files_scanned"], 2)
        self.assertEqual(data["z_index"], [])
        self.assertEqual(data["font_sizes"], [])
        self.assertEqual(data["fixed_widths"], [])
        self.assertEqual({row["value"] for row in data["spacing"]}, {"8px", "16px"})
        self.assertEqual(data["images"][0]["location"], "b.jsx:2")
        self.assertEqual([row["location"] for row in data["parse_warnings"]],
                         ["a.css:2", "a.css:1", "a.css:2", "b.jsx:1"])

    def test_parse_warnings_are_capped_and_the_omitted_count_is_reported(self):
        giant = "9" * (inventory.MAX_INTEGER_DIGITS + 1)
        data = self.scan({"a.css": f".x {{ z-index: {giant}; }}\n" * (inventory.MAX_ROWS + 3)})
        self.assertEqual(len(data["parse_warnings"]), inventory.MAX_ROWS)
        self.assertEqual(data["truncated"], {"parse_warnings": 3})

    def test_bad_locale_json_is_skipped_without_aborting_other_files(self):
        cases = {
            "deep": '{"x":' * 10_000 + '"text"' + '}' * 10_000,
            "duplicate": '{"text":"first","text":"last"}',
            "nonfinite": '{"value":Infinity}',
            "surrogate": '{"text":"\\ud800"}',
        }
        for name, source in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                repo = root / "repo"
                (repo / "locales").mkdir(parents=True)
                (repo / "locales" / "en.json").write_text(source, encoding="utf-8")
                (repo / "a.html").write_text('<img src="photo.png">', encoding="utf-8")
                out = root / "inventory.json"
                result = self.run_cli(repo, out)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                data = json.loads(out.read_text(encoding="utf-8"))
                self.assertEqual((data["files_scanned"], data["files_skipped"]), (1, 1))
                self.assertEqual(data["images"][0]["location"], "a.html:1")
                self.assertEqual(data["parse_warnings"][0]["location"], "locales/en.json:1")
                self.assertIn("file skipped", data["parse_warnings"][0]["reason"])

    def test_nested_valid_locale_objects_are_flattened_without_python_recursion(self):
        depth = 1_100
        value = "Save"
        for _ in range(depth):
            value = {"x": value}
        self.assertEqual(list(inventory.flatten(value)), [(".".join(["x"] * depth), "Save")])

    def test_html_tag_names_and_character_references_are_handled(self):
        data = self.scan({"index.html":
            '<IMG SRC="photo.png">\n'
            '<META NAME="viewport" CONTENT="user-scalable=no">\n'
            '<LABEL FOR="search">Search</LABEL><INPUT ID="search">\n'
            '<INPUT ARIA-LABEL="&#x20;&Tab;">\n'
            '<BUTTON><SVG></SVG></BUTTON>\n'})
        self.assertEqual(data["images"][0]["location"], "index.html:1")
        self.assertTrue(data["viewport_meta"][0]["blocks_zoom"])
        self.assertEqual([row["location"] for row in data["inputs"]], ["index.html:4"])
        self.assertEqual(data["icon_buttons"], [{"element": "button", "location": "index.html:5"}])

    def test_vue_bindings_and_event_modifiers_preserve_unknown_attributes(self):
        data = self.scan({"a.vue":
            '<input :aria-label="label" />\n'
            '<button v-bind:aria-label="label"><X /></button>\n'
            '<input v-bind="field" />\n'
            '<input v-bind.prop="field" />\n'
            '<input :[attributeName]="value" />\n'
            '<input v-bind:[attributeName]="value" />\n'
            '<input :aria-label="\' \'" />\n'
            '<button :aria-label="\'\'"><X /></button>\n'
            '<input :aria-label />\n'
            '<div @click.stop="go" @keydown.enter="go" role="button" :tabindex="0">Go</div>\n'
            '<span @click.prevent="go">Go</span>\n'
            '<input name="email" :type="type" :autocomplete="auto" :aria-label="label" />\n'
            '<Input /><IconButton :label="label" />\n'})
        self.assertEqual([row["location"] for row in data["inputs"]], ["a.vue:7"])
        self.assertEqual(data["icon_buttons"], [{"element": "button", "location": "a.vue:8"}])
        self.assertEqual(data["click_handlers"], [{"element": "span", "location": "a.vue:11",
                                                   "missing": ["role", "tabindex", "key handler"]}])

    def test_malformed_viewport_number_does_not_abort_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "index.html").write_text(
                '<meta name="viewport" content="maximum-scale=1.0.0">\n'
                '<meta name="viewport" content="maximum-scale=.">\n'
                '<img src="photo.png">\n', encoding="utf-8")
            out = root / "inventory.json"
            result = self.run_cli(repo, out)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(len(data["viewport_meta"]), 2)
            self.assertEqual(data["images"][0]["location"], "index.html:3")

    def test_viewport_numeric_prefixes_and_case(self):
        cases = {
            "maximum-scale=1.0.0": True,
            "maximum-scale=1e1": False,
            "maximum-scale=2e-1": True,
            "maximum-scale=.5": True,
            "maximum-scale=-1": False,
            "maximum-scale=.": False,
            "MAXIMUM-SCALE=1.5": True,
            "USER-SCALABLE=NO": True,
            "user-scalable=yes, maximum-scale=2": False,
        }
        for content, expected in cases.items():
            with self.subTest(content=content):
                data = self.scan({"index.html": f'<meta name="viewport" content="{content}">'})
                self.assertEqual(len(data["viewport_meta"]), 1)
                self.assertEqual(data["viewport_meta"][0]["blocks_zoom"], expected)

    def test_viewport_name_is_case_insensitive(self):
        data = self.scan({"index.html": '<meta name="VIEWPORT" content="user-scalable=no">'})
        self.assertEqual(len(data["viewport_meta"]), 1)
        self.assertTrue(data["viewport_meta"][0]["blocks_zoom"])

    def test_mdx_pages_are_routes_and_markup_candidates(self):
        data = self.scan({"app/(public)/help/page.mdx": '# Help\n\n<img src="guide.png" />\n'})
        self.assertEqual(data["files_scanned"], 1)
        self.assertEqual(data["routes"], [{"route": "/help", "location": "app/(public)/help/page.mdx:1"}])
        self.assertEqual(data["images"][0]["location"], "app/(public)/help/page.mdx:3")

    def test_next_routes_exclude_slots_private_folders_and_unsupported_interception(self):
        files = {
            "app/@analytics/views/page.tsx": "/views",
            "app/(marketing)/about/page.tsx": "/about",
            "app/_private/secret/page.tsx": None,
            "app/news/_components/page.tsx": None,
            "app/@modal/(.)photo/page.tsx": None,
            "app/(..)(..)feed/page.tsx": None,
            "routes/@slot/+page.svelte": "/@slot",
            "routes/_private/+page.svelte": "/_private",
            "routes/(group)/public/+page.svelte": "/public",
        }
        data = self.scan({name: "<main />" for name in files})
        self.assertEqual({row["location"]: row["route"] for row in data["routes"]},
                         {f"{name}:1": route for name, route in files.items() if route is not None})
        self.assertEqual({row["location"] for row in data["parse_warnings"]},
                         {"app/@modal/(.)photo/page.tsx:1", "app/(..)(..)feed/page.tsx:1"})
        self.assertTrue(all("interception" in row["reason"] for row in data["parse_warnings"]))

    def test_json_token_sources_are_not_discarded(self):
        data = self.scan({
            "styles/tokens.json": '{"spacing":{"small":8}}',
            "styles/theme.json": '{"fontSize":{"body":16}}',
            "package.json": '{"name":"example"}',
            "locales/en.json": '{"save":"Save"}',
        })
        self.assertEqual(data["token_sources"], [
            {"path": "styles/theme.json", "custom_properties": 0},
            {"path": "styles/tokens.json", "custom_properties": 0},
        ])

    def test_empty_name_attributes_do_not_hide_unlabelled_inputs(self):
        data = self.scan({"a.jsx":
            '<input aria-label="" placeholder="Search" />\n'
            '<input aria-labelledby="  " />\n'
            '<textarea title={" "} />\n'
            '<input aria-label />\n'
            '<input aria-label={label} />\n'
            '<input aria-label="" title="Search" />\n'
            '<label htmlFor="search">Search</label><input id="search" aria-label="" />\n'
            '<label>Search <input aria-label="" /></label>\n'
            '<input {...field} aria-label="" />\n'})
        self.assertEqual([r["location"] for r in data["inputs"]], ["a.jsx:1", "a.jsx:2", "a.jsx:3", "a.jsx:4"])
        self.assertTrue(data["inputs"][0]["placeholder_only"])

    def test_icon_buttons_with_empty_names_and_plain_component_name(self):
        data = self.scan({"a.jsx":
            '<button aria-label=""><X /></button>\n'
            '<button title={" "}><X /></button>\n'
            '<IconButton />\n'
            '<CloseIconButton label=" " />\n'
            '<IconButton label={label} />\n'
            '<IconButton label="Close" />\n'
            '<button aria-label={label}><X /></button>\n'
            '<button aria-label="">Close</button>\n'
            '<IconButton {...props} />\n'})
        self.assertEqual([(r["element"], r["location"]) for r in data["icon_buttons"]], [
            ("button", "a.jsx:1"), ("button", "a.jsx:2"),
            ("IconButton", "a.jsx:3"), ("CloseIconButton", "a.jsx:4"),
        ])

    def test_inventory_skips_oversize_binary_invalid_utf8_and_symlinked_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "large.css").write_bytes(b"x" * (inventory.MAX_BYTES + 1))
            (root / "binary.css").write_bytes(b"\0.btn{width:20px}")
            (root / "invalid.css").write_bytes(b"\xff.btn{width:20px}")
            outside = Path(tmp) / "outside"
            outside.mkdir()
            (outside / "a.css").write_text(".btn{width:20px}", encoding="utf-8")
            (root / "linked").symlink_to(outside, target_is_directory=True)
            data = inventory.inventory(root)
            self.assertEqual(data["files_scanned"], 0)
            self.assertEqual(data["files_skipped"], 3)
            self.assertEqual(data["tap_targets"], [])

    def test_cli_output_failures_are_clean_and_do_not_leave_temporary_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            for out in (root / "missing" / "inventory.json", root / "directory"):
                with self.subTest(out=out):
                    if out.name == "directory":
                        out.mkdir()
                    result = self.run_cli(repo, out)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn("cannot write", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertFalse(list(root.glob(".*.tmp")))

    def test_cli_replaces_output_symlink_without_overwriting_referent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            target = root / "keep.txt"
            target.write_text("keep", encoding="utf-8")
            out = root / "inventory.json"
            out.symlink_to(target)
            result = self.run_cli(repo, out)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(target.read_text(encoding="utf-8"), "keep")
            self.assertFalse(out.is_symlink())
            self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["files_scanned"], 0)

    def test_cli_rejects_invalid_utf8_flows_without_replacing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            bad = root / "flows.json"
            bad.write_bytes(b"\xff")
            out = root / "inventory.json"
            out.write_text("keep", encoding="utf-8")
            result = self.run_cli(repo, out, "--flows", bad)
            self.assertEqual(result.returncode, 2)
            self.assertIn("flows", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertEqual(out.read_text(encoding="utf-8"), "keep")

    def test_flows_digest_tracks_semantics_and_distinguishes_recon(self):
        flows = json.loads((ROOT / "examples" / "flows.sample.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            before = inventory.inventory(root, flows)
            self.assertRegex(before["flows_sha256"], r"^sha256:[a-f0-9]{64}$")
            reordered = dict(reversed(list(flows.items())))
            reordered["tokens"] = dict(reversed(list(flows["tokens"].items())))
            self.assertEqual(inventory.inventory(root, reordered)["flows_sha256"], before["flows_sha256"])
            changed = {**flows, "viewports": ["320x640"]}
            after = inventory.inventory(root, changed)
            self.assertNotEqual(after["flows_sha256"], before["flows_sha256"])
            self.assertEqual(after["smallest_viewport"], 320)
            self.assertIsNone(inventory.inventory(root)["flows_sha256"])

    def test_cli_rejects_duplicate_flows_keys_without_replacing_output(self):
        flows = json.loads((ROOT / "examples" / "flows.sample.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            bad = root / "flows.json"
            bad.write_text('{"app":"ignored",' + json.dumps(flows)[1:], encoding="utf-8")
            out = root / "inventory.json"
            out.write_text("keep", encoding="utf-8")
            result = self.run_cli(repo, out, "--flows", bad)
            self.assertEqual(result.returncode, 2)
            self.assertIn("flows", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertEqual(out.read_text(encoding="utf-8"), "keep")

    def test_cli_refuses_output_inside_repository_including_symlink_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            source = repo / "app.jsx"
            source.write_text("export default () => <main />;\n", encoding="utf-8")
            alias = root / "alias"
            alias.symlink_to(repo, target_is_directory=True)
            keep = root / "keep.json"
            keep.write_text("keep", encoding="utf-8")
            link = repo / "link.json"
            link.symlink_to(keep)
            for out in (repo / "inventory.json", source, alias / "inventory.json", link):
                with self.subTest(out=out):
                    result = self.run_cli(repo, out)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn("outside the reviewed repository", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
            self.assertEqual(source.read_text(encoding="utf-8"), "export default () => <main />;\n")
            self.assertEqual(keep.read_text(encoding="utf-8"), "keep")
            self.assertTrue(link.is_symlink())
            self.assertFalse((repo / "inventory.json").exists())


if __name__ == "__main__":
    unittest.main()
