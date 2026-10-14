"""Regression coverage for repository inventory parsing and file boundaries."""

import errno
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "ux-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import inventory  # noqa: E402
from file_io import SUPPORTS_ROOT_READS  # noqa: E402


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
        # A valid large comment used to trigger quadratic rule-scanning retries.
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

    def test_nested_css_keeps_only_each_rules_direct_declarations(self):
        data = self.scan({"a.scss":
            '.btn {\n'
            '  width: 20px; outline: none;\n'
            '  .child { height: 10px; border: 1px solid red; }\n'
            '  min-height: 30px;\n'
            '}\n'})
        self.assertEqual(data["tap_targets"], [{
            "selector": ".btn", "sizes": {"width": "20px", "min-height": "30px"},
            "below_24": True, "location": "a.scss:1",
        }])
        self.assertEqual(data["focus_outline"], [{
            "selector": ".btn", "location": "a.scss:1", "replacement_in_rule": False,
            "focus_visible_rule_in_file": False,
        }])

    def test_nested_css_preserves_explicit_selectors_through_media_wrappers(self):
        data = self.scan({"a.css":
            '@media (max-width: 600px) {\n'
            '  .icon {\n'
            '    width: 22px;\n'
            '    @supports (height: 10px) { .nested-btn { height: 18px; } }\n'
            '    height: 32px;\n'
            '  }\n'
            '}\n'})
        self.assertEqual(data["tap_targets"], [
            {"selector": ".icon", "sizes": {"width": "22px", "height": "32px"},
             "below_24": True, "location": "a.css:2"},
            {"selector": ".nested-btn", "sizes": {"height": "18px"},
             "below_24": True, "location": "a.css:4"},
        ])

    def test_css_rule_delimiters_ignore_strings_escapes_and_function_values(self):
        data = self.scan({"a.css":
            '.btn[data-note="};{"] {\n'
            '  content: "};{";\n'
            '  background: url(data:image/svg+xml;<svg>{}</svg>);\n'
            '  width: 20px;\n'
            '  .child { content: ";{}"; height: 10px; }\n'
            '  height: 30px;\n'
            '}\n'
            '.btn\\{compact { width: 21px; }\n'})
        self.assertEqual([(r["selector"], r["sizes"], r["location"]) for r in data["tap_targets"]], [
            ('.btn[data-note="};{"]', {"width": "20px", "height": "30px"}, "a.css:1"),
            ('.btn\\{compact', {"width": "21px"}, "a.css:8"),
        ])

    def test_nested_css_with_a_large_declaration_completes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "a.css").write_text('.btn { --content: ' + 'x' * 1_000_000
                                        + '; width: 20px; .child {height: 10px} height: 30px; }\n',
                                        encoding="utf-8")
            out = root / "inventory.json"
            result = self.run_cli(repo, out)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["tap_targets"][0]["sizes"],
                             {"width": "20px", "height": "30px"})

    def test_css_conditions_are_not_element_fixed_widths(self):
        data = self.scan({"a.css":
            "@media (min-width: 640px) {\n"
            "  .card { width: 480px; min-width: 320px!important; }\n"
            "}\n"
            "@media (\n"
            "  min-width: 960px\n"
            ") { .wide { width: 1024px; } }\n"
            "@supports (width: 720px) { .tile { min-width: 40rem; } }\n"
            "@supports (width: 730px !important) {}\n"
            "@supports (width: 740px\n"
            "  !IMPORTANT\n"
            ") {}\n"})
        self.assertEqual(data["fixed_widths"], [
            {"value": "1024px", "count": 1, "locations": ["a.css:6"]},
            {"value": "320px", "count": 1, "locations": ["a.css:2"]},
            {"value": "480px", "count": 1, "locations": ["a.css:2"]},
            {"value": "640px", "count": 1, "locations": ["a.css:7"]},
        ])
        self.assertEqual(data["breakpoints"], [
            {"value": "640px", "count": 1, "locations": ["a.css:1"]},
            {"value": "960px", "count": 1, "locations": ["a.css:4"]},
        ])

    def test_fixed_width_declarations_keep_inline_and_indented_styles(self):
        data = self.scan({
            "a.html": '<div style="width: 600px; min-width: 400px !important">Card</div>\n',
            "b.sass": ".card\n  width: 480px\n  min-width: 20rem\n"
                      "@media (min-width: 40rem)\n  .wide\n    width: 800px\n",
        })
        self.assertEqual(data["fixed_widths"], [
            {"value": "320px", "count": 1, "locations": ["b.sass:3"]},
            {"value": "400px", "count": 1, "locations": ["a.html:1"]},
            {"value": "480px", "count": 1, "locations": ["b.sass:2"]},
            {"value": "600px", "count": 1, "locations": ["a.html:1"]},
            {"value": "800px", "count": 1, "locations": ["b.sass:6"]},
        ])
        self.assertEqual(data["breakpoints"], [{"value": "640px", "count": 1, "locations": ["b.sass:4"]}])

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

    def test_quoted_template_attributes_are_not_nested_elements(self):
        for extension in ("html", "vue", "svelte", "astro"):
            with self.subTest(extension=extension):
                name = f"a.{extension}"
                data = self.scan({name:
                    '<div data-example="<input><img><button><svg></svg></button>">Example</div>\n'
                    '<img src="real.png">\n'})
                self.assertEqual(data["inputs"], [])
                self.assertEqual(data["icon_buttons"], [])
                self.assertEqual(data["images"], [{"location": f"{name}:2", "missing": ["alt", "dimensions"]}])

    def test_raw_text_elements_do_not_create_markup_candidates(self):
        for extension in ("html", "vue", "svelte", "astro"):
            with self.subTest(extension=extension):
                name = f"a.{extension}"
                data = self.scan({name:
                    '<script>const example = "<input><img>";</script>\n'
                    '<style>.example::after { content: "<input><img>"; }</style>\n'
                    '<textarea aria-label="Example"><input><img></textarea>\n'
                    '<title><input><img></title>\n'
                    '<img src="real.png">\n'})
                self.assertEqual(data["inputs"], [])
                self.assertEqual([row["location"] for row in data["images"]], [f"{name}:5"])

    def test_raw_text_comments_do_not_hide_following_elements(self):
        data = self.scan({"a.html":
            '<TEXTAREA aria-label="Example"><!--</TEXTAREA>\n'
            '<IMG src="real.png">\n'
            '<div data-example="-->">Text</div>\n'})
        self.assertEqual([row["location"] for row in data["images"]], ["a.html:2"])
        self.assertEqual(data["inputs"], [])

    def test_embedded_languages_ignore_fake_blocks_and_attributes(self):
        for extension in ("html", "vue", "svelte", "astro"):
            with self.subTest(extension=extension):
                name = f"a.{extension}"
                data = self.scan({name:
                    '<div title="<style>.btn {padding: 37px; height: 9px}</style>">Example</div>\n'
                    '<div title="<script>const style = {padding: 47}</script>">Example</div>\n'
                    '<script>const example = `style="padding: 57px"`;</script>\n'
                    '<textarea aria-label="Example"><style>.btn {padding: 67px}</style></textarea>\n'
                    '<style data-example="a > b">.btn {padding: 8px; height: 40px}</style>\n'
                    '<script data-example="a > b">const style = {padding: 16};</script>\n'})
                self.assertEqual(data["spacing"], [
                    {"value": "16px", "count": 1, "locations": [f"{name}:6"]},
                    {"value": "8px", "count": 1, "locations": [f"{name}:5"]},
                ])
                self.assertEqual([(row["selector"], row["location"]) for row in data["tap_targets"]],
                                 [(".btn", f"{name}:5")])

    def test_embedded_javascript_keeps_style_expressions_and_astro_frontmatter(self):
        data = self.scan({
            "a.vue": '<div :style="{padding: 8}">Vue</div>\n'
                     '<script setup>const style = {padding: 16};</script>\n',
            "b.svelte": '<div style={{padding: 24}}>Svelte</div>\n'
                        '<script>const style = {padding: 32};</script>\n',
            "c.astro": '---\nconst style = {padding: 40};\n---\n'
                       '<div style={{padding: 48}}>Astro</div>\n',
        })
        self.assertEqual({row["value"]: row["locations"] for row in data["spacing"]}, {
            "8px": ["a.vue:1"], "16px": ["a.vue:2"], "24px": ["b.svelte:1"],
            "32px": ["b.svelte:2"], "40px": ["c.astro:2"], "48px": ["c.astro:4"],
        })

    def test_wrapping_labels_use_actual_tag_boundaries(self):
        data = self.scan({"a.html":
            '<div data-example="<label>"><input /></div><span data-example="</label>" />\n'
            '<label>Search<span data-example="</label>"><input /></span></label>\n'
            '<label>Outer<label>Inner<input /></label><input /></label>\n'
            '<input />\n'})
        self.assertEqual([row["location"] for row in data["inputs"]], ["a.html:1", "a.html:4"])

    def test_jsx_regex_and_markup_strings_do_not_hide_later_elements(self):
        data = self.scan({"a.jsx":
            '<input aria-label="URL" value={url.replace(/\\//g, "-")} />\n'
            '<input aria-label="Pattern" value={/a\\/*b/.test(value)} />\n'
            "const example = '<input title=\"';\n"
            '<img src="real.png" />\n'})
        self.assertEqual([row["location"] for row in data["images"]], ["a.jsx:4"])

    def test_jsx_inside_fallback_and_render_props_remains_a_candidate(self):
        for extension in ("jsx", "tsx", "astro", "svelte"):
            with self.subTest(extension=extension):
                name = f"a.{extension}"
                data = self.scan({name:
                    '<Suspense fallback={<img src="loading.png" />}><Content /></Suspense>\n'
                    '<Field render={() => <input type="email" />} />\n'})
                self.assertEqual([row["location"] for row in data["images"]], [f"{name}:1"])
                self.assertEqual([(row["location"], row["missing"]) for row in data["inputs"]],
                                 [(f"{name}:2", ["label", "autocomplete"])])

    def test_dense_malformed_tags_and_long_attributes_complete(self):
        cases = {
            "labels": "<label>text\n" * 30_000,
            "attribute": '<div title="' + '<input title=' * 50_000 + '">\n',
            "prefixes": "<div " * 30_000 + "\n",
        }
        for name, prefix in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                repo = root / "repo"
                repo.mkdir()
                (repo / "a.html").write_text(prefix + '<img src="real.png">\n', encoding="utf-8")
                out = root / "inventory.json"
                result = self.run_cli(repo, out)
                self.assertEqual(result.returncode, 0, result.stderr)
                data = json.loads(out.read_text(encoding="utf-8"))
                self.assertEqual(data["inputs"], [])
                self.assertEqual([row["location"] for row in data["images"]],
                                 [f"a.html:{prefix.count(chr(10)) + 1}"])

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
                if name == "deep":
                    self.assertIn("256 nested object/array containers", data["parse_warnings"][0]["reason"])

    def test_locale_depth_boundary_covers_objects_arrays_and_mixed_containers(self):
        for kind in ("objects", "arrays", "mixed"):
            for depth in (255, 256, 257):
                with self.subTest(kind=kind, depth=depth):
                    openings, closings = [], []
                    for index in range(depth):
                        is_object = kind == "objects" or (kind == "mixed" and index % 2 == 0)
                        openings.append('{"x":' if is_object else '[')
                        closings.append('}' if is_object else ']')
                    source = "".join(openings) + '"Save"' + "".join(reversed(closings))
                    data = self.scan({"locales/en.json": source, "a.html": '<img src="photo.png">'})
                    self.assertEqual(data["limits"]["locale_container_depth"], 256)
                    self.assertEqual(data["images"][0]["location"], "a.html:1")
                    if depth <= 256:
                        self.assertEqual((data["files_scanned"], data["files_skipped"]), (2, 0))
                        self.assertEqual(data["parse_warnings"], [])
                    else:
                        self.assertEqual((data["files_scanned"], data["files_skipped"]), (1, 1))
                        self.assertEqual(data["parse_warnings"][0]["location"], "locales/en.json:1")
                        self.assertIn("256 nested object/array containers", data["parse_warnings"][0]["reason"])

    def test_locale_depth_includes_branches_that_expansion_does_not_read(self):
        # The outer object is depth 1, so these 256 nested arrays reach depth 257.
        for key in ("ignored_array", "@metadata"):
            with self.subTest(key=key):
                source = '{"save":"Save",' + json.dumps(key) + ':' + '[' * 256 + '0' + ']' * 256 + '}'
                data = self.scan({"locales/en.json": source})
                self.assertEqual((data["files_scanned"], data["files_skipped"]), (0, 1))
                self.assertIn("256 nested object/array containers", data["parse_warnings"][0]["reason"])

    def test_locale_depth_ignores_container_characters_and_escapes_inside_strings(self):
        text = '"\\' + '{[' * 300 + '}]' * 300 + '\\"'
        data = self.scan({"locales/en.json": json.dumps({text: text})})
        self.assertEqual((data["files_scanned"], data["files_skipped"]), (1, 0))
        self.assertEqual(data["parse_warnings"], [])

    def test_flatten_helper_does_not_recurse_on_nested_objects(self):
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

    def test_positive_tabindex_uses_html_integer_parsing(self):
        values = ["01", "+2", " \t003tail", "4.5", "0", "-1", "", "\u0661", "{5}", "\u00a06"]
        data = self.scan({"index.html": "\n".join(f'<div tabindex="{value}"></div>' for value in values)})
        self.assertEqual([(r["value"], r["location"]) for r in data["positive_tabindex"]],
                         [(1, "index.html:1"), (2, "index.html:2"),
                          (3, "index.html:3"), (4, "index.html:4")])

    def test_positive_tabindex_keeps_static_and_unknown_template_expressions_separate(self):
        data = self.scan({"a.jsx":
            '<div tabIndex={+2} />\n'
            '<div tabIndex={"03"} />\n'
            '<div tabIndex={4 - 5} />\n'
            '<div tabIndex={`5${index}`} />\n'
            '<div tabIndex={index} />\n'
            '<div tabIndex="{6}" />\n',
            "b.vue": '<div :tabindex="+7" /><div :tabindex="8 - 9" />\n'})
        self.assertEqual([(r["value"], r["location"]) for r in data["positive_tabindex"]],
                         [(2, "a.jsx:1"), (3, "a.jsx:2"), (7, "b.vue:1")])

    def test_destructive_calls_in_nested_handlers_and_modified_events(self):
        data = self.scan({
            "a.jsx": '<button onClick={() => {\n  api.deleteItem(id);\n}}>Delete</button>\n'
                     '<Button onPress={async () => { await removeItem(id); }} />\n'
                     '<Button onTap={() => discardDraft()} />\n'
                     '<button {...props} onClick={() => deleteItem(id)}>Delete</button>\n',
            "b.vue": '<button @click.stop="deleteItem(id)">Delete</button>\n'
                     "<button v-on:click.prevent='removeItem(id)'>Remove</button>\n",
            "c.svelte": '<button on:click={() => { destroyItem(id); }}>Destroy</button>\n',
            "d.html": '<button onclick="deleteItem(id)">Delete</button>\n',
        })
        self.assertEqual([(r["call"], r["location"]) for r in data["destructive_actions"]], [
            ("api.deleteItem", "a.jsx:2"), ("removeItem", "a.jsx:4"), ("discardDraft", "a.jsx:5"),
            ("deleteItem", "a.jsx:6"),
            ("deleteItem", "b.vue:1"), ("removeItem", "b.vue:2"),
            ("destroyItem", "c.svelte:1"), ("deleteItem", "d.html:1"),
        ])

    def test_destructive_calls_stay_inside_actual_handlers(self):
        data = self.scan({
            "a.html": '<div title="onClick={deleteExample()}">Example</div>\n'
                      '<script>const example = "onClick={removeExample()}";</script>\n'
                      '<button data-onclick="destroyExample()">Example</button>\n'
                      '<button onclick="save()" title="discardExample()">Save</button>\n',
            "b.jsx": '<button onClick={() => { if (confirm("Delete?")) deleteItem(id); }}>Delete</button>\n',
        })
        self.assertEqual(data["destructive_actions"], [])

    def test_nested_handler_attributes_do_not_duplicate_the_same_destructive_call(self):
        data = self.scan({"a.jsx":
            '<Button onClick={() => setContent(<button onClick={() => removeItem(id)}>Remove</button>)} />\n'
            '<button onClick={() => { removeItem(first); removeItem(second); }}>Remove both</button>\n'})
        self.assertEqual(data["destructive_actions"], [
            {"call": "removeItem", "location": "a.jsx:1"},
            {"call": "removeItem", "location": "a.jsx:2"},
            {"call": "removeItem", "location": "a.jsx:2"},
        ])

    def test_mdx_pages_are_routes_and_markup_candidates(self):
        data = self.scan({"app/(public)/help/page.mdx": '# Help\n\n<img src="guide.png" />\n'})
        self.assertEqual(data["files_scanned"], 1)
        self.assertEqual(data["routes"], [{"route": "/help", "location": "app/(public)/help/page.mdx:1"}])
        self.assertEqual(data["images"][0]["location"], "app/(public)/help/page.mdx:3")

    def test_next_typescript_pages_are_routes(self):
        data = self.scan({
            "src/app/(public)/help/page.ts": 'export default function Page() { return "Help"; }\n',
            "src/app/_private/page.ts": 'export default function Page() { return null; }\n',
        })
        self.assertEqual(data["routes"], [{"route": "/help", "location": "src/app/(public)/help/page.ts:1"}])

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
            (root / "late-binary.css").write_bytes(b" " * 9000 + b"\0.btn{width:20px}")
            (root / "invalid.css").write_bytes(b"\xff.btn{width:20px}")
            outside = Path(tmp) / "outside"
            outside.mkdir()
            (outside / "a.css").write_text(".btn{width:20px}", encoding="utf-8")
            (root / "linked").symlink_to(outside, target_is_directory=True)
            data = inventory.inventory(root)
            self.assertEqual(data["files_scanned"], 0)
            self.assertEqual(data["files_skipped"], 4)
            self.assertEqual(data["tap_targets"], [])

    def test_directory_scan_failures_are_visible_and_other_files_still_scan(self):
        for blocked_name in (".", "private"):
            with self.subTest(blocked=blocked_name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "private").mkdir()
                (root / "private" / "hidden.html").write_text('<img src="hidden.png">', encoding="utf-8")
                (root / "visible.html").write_text('<img src="visible.png">', encoding="utf-8")
                blocked = root / blocked_name
                scandir = inventory.os.scandir

                def refuse_directory(path):
                    if Path(path) == blocked:
                        raise PermissionError(errno.EACCES, "Permission denied", str(path))
                    return scandir(path)

                with patch.object(inventory.os, "scandir", side_effect=refuse_directory):
                    data = inventory.inventory(root)
                expected_scanned = 0 if blocked_name == "." else 1
                self.assertEqual((data["files_scanned"], data["files_skipped"]), (expected_scanned, 0))
                self.assertEqual([row["location"] for row in data["images"]],
                                 [] if blocked_name == "." else ["visible.html:1"])
                self.assertEqual(data["parse_warnings"], [{
                    "location": f"{blocked_name}:1",
                    "reason": "directory could not be scanned; contents skipped: Permission denied",
                }])

    @unittest.skipUnless(SUPPORTS_ROOT_READS, "requires descriptor-relative repository reads")
    def test_inventory_rejects_an_ancestor_replaced_by_a_symlink_during_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "repo"
            styles = root / "styles"
            styles.mkdir(parents=True)
            (styles / "a.css").write_text(".btn{padding:8px}", encoding="utf-8")
            (root / "a.html").write_text('<img src="real.png">', encoding="utf-8")
            outside = base / "outside"
            outside.mkdir()
            (outside / "a.css").write_text(".btn{padding:99px}", encoding="utf-8")
            read_regular = inventory.read_regular

            def replace_then_read(path, **kwargs):
                if path.name == "a.css":
                    styles.rename(base / "original")
                    styles.symlink_to(outside, target_is_directory=True)
                return read_regular(path, **kwargs)

            with patch.object(inventory, "read_regular", side_effect=replace_then_read):
                data = inventory.inventory(root)
            self.assertEqual((data["files_scanned"], data["files_skipped"]), (1, 1))
            self.assertEqual(data["spacing"], [])
            self.assertEqual([row["location"] for row in data["images"]], ["a.html:1"])
            self.assertEqual(data["parse_warnings"][0]["location"], "styles/a.css:1")
            self.assertIn("file skipped", data["parse_warnings"][0]["reason"])

    @unittest.skipIf(os.name == "nt", "requires a filesystem with arbitrary byte filenames")
    def test_invalid_unicode_filename_does_not_abort_cli_or_hide_other_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            bad = os.fsencode(repo) + b"/invalid-\xff.css"
            try:
                with open(bad, "wb") as handle:
                    handle.write(b".btn{padding:13px}")
            except OSError as e:
                if e.errno != errno.EILSEQ:
                    raise
                self.skipTest("this filesystem (e.g. APFS) refuses filenames that are not valid UTF-8")
            (repo / "a.html").write_text('<img src="real.png">', encoding="utf-8")
            out = root / "inventory.json"
            result = self.run_cli(repo, out)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual((data["files_scanned"], data["files_skipped"]), (1, 1))
            self.assertEqual(data["spacing"], [])
            self.assertEqual([row["location"] for row in data["images"]], ["a.html:1"])
            self.assertIn("filename is not valid Unicode", data["parse_warnings"][0]["reason"])

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

    def test_preprocessor_line_comments_do_not_hide_or_invent_candidates(self):
        data = self.scan({
            "a.scss": "// Don't change these without design review\n"
                      ".icon-btn { width: 20px; height: 20px; }\n"
                      ".close:focus { outline: none; }\n"
                      "// Won't fix (later\n"
                      ".tab { height: 30px; // padding: 13px; z-index: 9999\n"
                      "  background: url(//cdn.example/x.png); }\n",
            "b.vue": '<template><p>x</p></template>\n<style lang="scss">\n'
                     "// Isn't used\n.chip { height: 18px; }\n</style>\n",
            "c.scss": ".hero { background: url( //cdn.example.com/hero.png) no-repeat; }\n"
                      ".bg { background: url(#{$cdn}//img/x.png); }\n"
                      ".link:focus { outline: none; }\n",
        })
        self.assertEqual([(r["selector"], r["location"]) for r in data["tap_targets"]], [
            (".icon-btn", "a.scss:2"), (".tab", "a.scss:5"), (".chip", "b.vue:4")])
        self.assertEqual([(r["selector"], r["location"]) for r in data["focus_outline"]],
                         [(".close:focus", "a.scss:3"), (".link:focus", "c.scss:3")])
        self.assertEqual(data["spacing"], [])
        self.assertEqual(data["z_index"], [])

    def test_plain_css_strings_end_at_a_newline(self):
        data = self.scan({"a.css": ".x::after { content: 'it\n}\n.btn { width: 20px; }\n"})
        self.assertEqual([r["selector"] for r in data["tap_targets"]], [".btn"])

    def test_focus_replacement_requires_a_visible_focus_style(self):
        data = self.scan({"a.css":
            ".btn:focus { outline: 0; box-shadow: none; }\n"
            ".link { outline: none; border-radius: 4px; border: 1px solid; }\n"
            ".tab:focus { outline: 0px; box-shadow: 0 0 0 3px blue; }\n"
            ".chip:focus { outline: none; --border-color: red; background: transparent !important; }\n"})
        self.assertEqual([(r["selector"], r["replacement_in_rule"]) for r in data["focus_outline"]], [
            (".btn:focus", False), (".link", False), (".tab:focus", True), (".chip:focus", False)])

    def test_style_object_outline_zero_is_a_candidate(self):
        data = self.scan({"a.jsx": "export const s = { outline: 0, color: 'red' };\n"
                                   "export const t = { outline: '0px' };\n"})
        self.assertEqual([r["location"] for r in data["focus_outline"]], ["a.jsx:1", "a.jsx:2"])

    def test_locale_namespaces_and_region_tags(self):
        data = self.scan({
            "locales/en/app.json": json.dumps({"save": "Save changes"}),
            "locales/de/app.json": json.dumps({"save": "Änderungen speichern"}),
            "i18n/en-US.json": json.dumps({"save": "Save changes"}),
            "i18n/de-DE.json": json.dumps({"save": "Änderungen speichern"}),
        })
        self.assertEqual([(e["bundle"], e["base"], e["lang"]) for e in data["locale_expansion"]], [
            ("i18n/{lang}.json", "en-US", "de-DE"), ("locales/{lang}/app.json", "en", "de")])

    def test_camel_case_destructive_handlers(self):
        data = self.scan({"D.tsx":
            "export const D = (props) => <>\n"
            "<button onClick={() => handleDelete(1)}>x</button>\n"
            "<button onClick={() => onDelete(2)}>x</button>\n"
            "<button onClick={() => props.onRemove(3)}>x</button>\n"
            "<button onClick={() => toggleDropdown()}>x</button>\n"
            "<button onClick={() => dropdown()}>x</button>\n"
            "<button onClick={() => onDrop(file)}>x</button>\n"
            "<button onClick={() => setOpen(isDeleted(x))}>x</button>\n"
            "<button onClick={() => wasDestroyed()}>x</button>\n"
            "</>;\n"})
        self.assertEqual([r["call"] for r in data["destructive_actions"]],
                         ["handleDelete", "onDelete", "props.onRemove"])

    def test_dynamic_label_targets_match_identical_ids(self):
        data = self.scan({"F.jsx":
            "export const F = ({ id, other }) => <>\n"
            "<label htmlFor={id}>Email</label><input id={ id } type=\"email\" autoComplete=\"email\" />\n"
            "<input id={other} type=\"text\" />\n"
            "</>;\n"})
        self.assertEqual([r["location"] for r in data["inputs"]], ["F.jsx:3"])
        data = self.scan({"G.jsx":
            "export function Billing({ id }) {\n"
            "  return <><label htmlFor={id}>Card</label><input id={id} /></>;\n"
            "}\n"
            "export function Search({ id }) {\n"
            "  return <input id={id} />;\n"
            "}\n"})
        self.assertEqual([r["location"] for r in data["inputs"]], ["G.jsx:2", "G.jsx:5"])
        data = self.scan({"H.tsx":
            "export const Billing: React.FC<Props> = ({ id }) => (\n"
            "  <><label htmlFor={id}>Card</label><input id={id} /></>\n"
            ");\n"
            "export default ({ id }) => <input id={id} />;\n"})
        self.assertEqual([r["location"] for r in data["inputs"]], ["H.tsx:2", "H.tsx:4"])

    def test_relative_child_routes_are_not_orphans(self):
        data = self.scan({"routes.jsx":
            '<Route path="/account"><Route path="settings" /></Route>\n'
            '<Link to="/account">Account</Link>\n'})
        self.assertEqual([r["route"] for r in data["routes"]], ["/account", "settings"])
        self.assertEqual(data["orphan_routes"], [])

    def test_framework_key_handler_aliases(self):
        data = self.scan({
            "a.svelte": '<div on:click={go} on:keyup={key} role="button" tabindex="0">x</div>\n',
            "b.vue": '<template><div @click="go" v-on:keyup.enter="go" role="button" tabindex="0">x</div>'
                     '<span (click)="go()" (keypress)="go()" role="button" tabindex="0">y</span></template>\n',
            "c.html": '<div (click)="go()" (keyup.enter)="go()" role="button" tabindex="0">x</div>\n',
            "d.svelte": '<div on:click|preventDefault={go} on:keydown|self={key} role="button" tabindex="0">x</div>\n'
                        '<span on:click|once={go}>y</span>\n',
        })
        self.assertEqual([(r["location"], r["missing"]) for r in data["click_handlers"]],
                         [("d.svelte:2", ["role", "tabindex", "key handler"])])
        data = self.scan({"e.html": '<div (click)="go()" (keyup.enter)="go()" role="button" tabindex="0">x</div>\n'})
        self.assertEqual(data["click_handlers"], [])

    def test_range_media_queries_and_em_widths(self):
        data = self.scan({"a.css":
            "@media (768px <= width) { .a { width: 30em; } }\n"
            "@media (400px <= width <= 700px) { .b { color: red; } }\n"
            "@media (width >= 1024px) { .c { color: red; } }\n"
            ".icon { width: 1.25em; height: 1.25em; }\n"})
        self.assertEqual(sorted(r["value"] for r in data["breakpoints"]), ["1024px", "400px", "700px", "768px"])
        self.assertEqual([r["value"] for r in data["fixed_widths"]], ["480px"])
        self.assertEqual(data["tap_targets"][0]["sizes"], {"width": "20px", "height": "20px"})

    def test_icon_buttons_named_by_a_child(self):
        data = self.scan({"B.jsx":
            '<button onClick={go}><img src="/x.svg" alt="Close" width="16" height="16"/></button>\n'
            '<button onClick={go}><svg aria-label="Menu"><path d="M0"/></svg></button>\n'
            '<button onClick={go}><img src="/x.svg" alt="" width="16" height="16"/></button>\n'
            '<button onClick={go}><img src="/x.svg" alt={""} width="16" height="16"/></button>\n'
            '<button onClick={go}><svg aria-label={""}/></button>\n'
            '<button onClick={go}><svg aria-labelledby={ \'\' }/></button>\n'
            '<button onClick={go}><svg aria-label={label}/></button>\n'})
        self.assertEqual([r["location"] for r in data["icon_buttons"]], ["B.jsx:3", "B.jsx:4", "B.jsx:5", "B.jsx:6"])

    def test_sveltekit_layout_reset_pages_are_routes(self):
        data = self.scan({"src/routes/about/+page@.svelte": "<h1>About</h1>\n",
                          "src/routes/team/+page@(app).svelte": "<h1>Team</h1>\n"})
        self.assertEqual(sorted(r["route"] for r in data["routes"]), ["/about", "/team"])

    def test_destructive_handlers_passed_by_reference(self):
        data = self.scan({
            "D.jsx": "<button onClick={handleDelete}>x</button>\n<button onClick={ props.onRemove }>x</button>\n"
                     "<button onClick={openMenu}>x</button>\n",
            "E.vue": '<template><button @click="deleteTask">x</button></template>\n',
        })
        self.assertEqual([(r["call"], r["location"]) for r in data["destructive_actions"]],
                         [("handleDelete", "D.jsx:1"), ("props.onRemove", "D.jsx:2"), ("deleteTask", "E.vue:1")])

    def test_pathological_inputs_stay_linear(self):
        import time
        cases = {
            "a.html": '<div onclick="' + "a." * 20000 + 'x">y</div>\n',
            "b.html": '<div onclick="' + "aDelete" * 10000 + '">y</div>\n',
            "c.jsx": "<Route " * 20000,
            "d.scss": ".a { b: " + "url(" * 20000 + " }\n",
            "e.jsx": "<a {" * 20000,
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                started = time.monotonic()
                self.scan({name: text})
                self.assertLess(time.monotonic() - started, 3)

    def test_javascript_comments_in_braces_do_not_hide_later_markup(self):
        data = self.scan({"P.svelte": "<button on:click={() => { // don't\n go() }}>ok</button>\n"
                                      '<img src="a.png">\n<div on:click={x}>y</div>\n'})
        self.assertEqual([r["location"] for r in data["images"]], ["P.svelte:3"])
        self.assertEqual([r["location"] for r in data["click_handlers"]], ["P.svelte:4"])

    def test_icon_button_with_long_svg_path(self):
        data = self.scan({"I.jsx": '<button onClick={go}>\n<svg viewBox="0 0 24 24"><path d="M' + "1 2 " * 600
                                   + '"/></svg>\n</button>\n'})
        self.assertEqual([r["location"] for r in data["icon_buttons"]], ["I.jsx:1"])

    def test_choice_inputs_and_separate_name_and_id(self):
        data = self.scan({"f.html":
            '<label><input type="checkbox" name="email_notifications"> Email me</label>\n'
            '<label><input type="radio" name="phone_verified"> Verified</label>\n'
            '<label for="n2">Name</label><input name="name" id="n2">\n'})
        self.assertEqual([(r["location"], r["missing"]) for r in data["inputs"]], [("f.html:3", ["autocomplete"])])

    def test_round_two_scans_stay_linear(self):
        import time
        cases = {"a.css": "(min-width:1px)" * 60000,
                 "b.html": '<div onclick="' + "aDelete" * 8000 + '-">x</div>\n',
                 "c.css": ".a:focus{outline:none;border:0." + "0" * 20000 + "x}\n"}
        for name, text in cases.items():
            with self.subTest(name=name):
                started = time.monotonic()
                self.scan({name: text})
                self.assertLess(time.monotonic() - started, 3)

    def test_destructive_calls_after_calls_indexes_and_optional_chains(self):
        data = self.scan({"D.jsx": "<button onClick={() => useStore.getState().removeTask(id)}>x</button>\n"
                                   "<button onClick={() => api?.deleteTask(id)}>x</button>\n"
                                   "<button onClick={() => list[0].remove()}>x</button>\n"})
        self.assertEqual([r["call"] for r in data["destructive_actions"]], ["removeTask", "deleteTask", "remove"])

    def test_jsx_text_with_slashes_and_regex_braces_does_not_hide_later_tags(self):
        for opener in ("<List renderEmpty={() => <p>Type // to search</p>} />",
                       "<Tip content={<span>Docs at example.com //v2</span>} />",
                       "<input aria-label=\"q\" onChange={e => /[{]/.test(v)} />"):
            with self.subTest(opener=opener):
                data = self.scan({"a.jsx": opener + '\n<img src="a.png">\n<div onClick={x}>y</div>\n'
                                           "<button onClick={() => deleteTask(id)}>z</button>\n"})
                self.assertEqual([r["location"] for r in data["images"]], ["a.jsx:2"])
                self.assertEqual([r["location"] for r in data["click_handlers"]], ["a.jsx:3"])
                self.assertEqual([r["location"] for r in data["destructive_actions"]], ["a.jsx:4"])

    def test_preprocessor_interpolation_stays_in_the_selector(self):
        data = self.scan({"a.scss": ".btn-#{$s} { height: 20px; }\n.icon-#{$s}:focus { outline: none; }\n"
                                    ".chip-@{x} { width: 18px; }\n"})
        self.assertEqual([r["selector"] for r in data["tap_targets"]], [".btn-#{$s}", ".chip-@{x}"])
        self.assertEqual([r["selector"] for r in data["focus_outline"]], [".icon-#{$s}:focus"])

    def test_angular_bindings_and_router_links(self):
        data = self.scan({"c.component.html":
            '<button [attr.aria-label]="label" (click)="close()"><mat-icon svgIcon="x"></mat-icon></button>\n'
            '<input [attr.aria-label]="label" name="q">\n'
            '<a routerLink="/account" (click)="track()">Account</a>\n'
            '<a [routerLink]="\'/billing\'">Billing</a><a [routerLink]="[\'/team\', id]">Team</a>\n',
            "routes.ts": "export const routes = [{ path: '/account' }, { path: '/billing' }, { path: '/team' }];\n"})
        self.assertEqual(data["icon_buttons"], [])
        self.assertEqual(data["inputs"], [])
        self.assertEqual(data["click_handlers"], [])
        self.assertEqual(data["orphan_routes"], [])

    def test_container_queries_are_not_breakpoints(self):
        data = self.scan({"a.css": "@container card (min-width: 400px) { .a { color: red; } }\n"
                                   "@media (min-width: 640px) { .b { color: red; } }\n"})
        self.assertEqual([r["value"] for r in data["breakpoints"]], ["640px"])

    def test_invisible_focus_values_are_not_replacements(self):
        data = self.scan({"a.css": ".a:focus { outline: none; border: 0 none; }\n"
                                   ".b:focus { outline: none; background: inherit; }\n"
                                   ".c:focus { outline: none; border: 2px solid; }\n"})
        self.assertEqual([r["replacement_in_rule"] for r in data["focus_outline"]], [False, False, True])

    def test_vue_string_literal_links_reach_routes(self):
        data = self.scan({"Nav.vue": "<template><router-link :to=\"'/about'\">About</router-link></template>\n",
                          "router.js": "export default [{ path: '/about' }];\n"})
        self.assertEqual(data["orphan_routes"], [])

    def test_server_template_styles_are_measured(self):
        data = self.scan({"page.php": "<style>\n.btn { width: 20px; outline: none; padding: 13px; }\n</style>\n"
                                      '<div style="width: 400px">x</div>\n'})
        self.assertEqual([r["location"] for r in data["tap_targets"]], ["page.php:2"])
        self.assertEqual([r["location"] for r in data["focus_outline"]], ["page.php:2"])
        self.assertEqual([r["value"] for r in data["fixed_widths"]], ["400px"])
        self.assertEqual([r["value"] for r in data["spacing"]], ["13px"])

    def test_server_template_tags_and_attribute_groups_are_spreads(self):
        data = self.scan({
            "a.erb": '<input type="text" name="q" <%= "required" if strict %>>\n<img src="a" <%= attrs %>>\n',
            "b.php": '<input type="checkbox" <?php checked($a, 1); ?>>\n',
            "c.html": '<input type="{{ widget.type }}" name="{{ widget.name }}"{% include "attrs.html" %}>\n'
                      '<img src="{{ src }}" {{ img_attrs }}>\n',
        })
        self.assertEqual(data["inputs"], [])
        self.assertEqual(data["images"], [])

    def test_svelte_shorthand_attributes(self):
        data = self.scan({"P.svelte": '<a {href} on:click={track}>x</a>\n<img {src} {alt} width="1" height="1">\n'
                                      '<label for={id}>Email</label><input {id} type="email" autocomplete="email">\n'})
        self.assertEqual(data["click_handlers"], [])
        self.assertEqual(data["images"], [])
        self.assertEqual(data["inputs"], [])

    def test_more_destructive_call_shapes_and_housekeeping(self):
        data = self.scan({"D.jsx":
            "<button onClick={() => onDelete?.(task.id)}>x</button>\n"
            "<button onClick={() => props.onRemove?.()}>x</button>\n"
            "<button onClick={() => deleteMutation.mutate(id)}>x</button>\n"
            "<button onClick={deleteMutation.mutate}>x</button>\n"
            "<button onClick={() => document.body.classList.remove('open')}>x</button>\n"
            "<button onClick={() => params.delete('q')}>x</button>\n"})
        self.assertEqual([r["location"] for r in data["destructive_actions"]], ["D.jsx:1", "D.jsx:2", "D.jsx:3", "D.jsx:4"])

    def test_nav_arrays_reach_routes(self):
        data = self.scan({"app/settings/page.tsx": "export default () => null;\n",
                          "Nav.tsx": 'const navigation = [{ name: "Settings", href: "/settings" }];\n'})
        self.assertEqual(data["orphan_routes"], [])

    def test_commented_out_markup_is_not_scanned(self):
        data = self.scan({
            "a.tsx": '// <img src="old.png" />\n/* <input name="email" /> */\nexport const A = () => <p>Type // to search</p>;\n',
            "b.html": '{# <img src="x"> #}\n{% comment %}<input name="email">{% endcomment %}\n'
                      '{{!-- <img src="y"> --}}\n{{! <img src="z"> }}\n',
            "c.erb": '<%# <img src="w"> %>\n<img src="real.png">\n',
        })
        self.assertEqual([r["location"] for r in data["images"]], ["c.erb:2"])
        self.assertEqual(data["inputs"], [])

    def test_icon_font_ligatures_and_empty_buttons(self):
        data = self.scan({"a.html": '<button mat-icon-button (click)="remove(t)"><mat-icon>delete</mat-icon></button>\n'
                                    '<button class="btn-close"></button>\n<button>Save</button>\n'
                                    '<button v-text="label"></button>\n'})
        self.assertEqual([r["location"] for r in data["icon_buttons"]], ["a.html:1", "a.html:2"])

    def test_truncate_in_class_helpers_inline_outline_next_viewport(self):
        data = self.scan({"a.tsx": 'export const A = () => <p className={cn("truncate text-sm", c)}>x</p>;\n'
                                   "export const viewport = { width: 'device-width', maximumScale: 1, userScalable: false };\n",
                          "b.html": '<a href="/x" style="outline: none">x</a>\n'})
        self.assertEqual([r["pattern"] for r in data["truncation"]], ['className={cn("truncate'])
        self.assertEqual([(r["location"], r["blocks_zoom"]) for r in data["viewport_meta"]], [("a.tsx:2", True)])
        self.assertEqual([(r["selector"], r["location"]) for r in data["focus_outline"]], [("(inline style)", "b.html:1")])

    def test_alpine_jinja2_and_whole_word_personal_fields(self):
        data = self.scan({"a.jinja2": '<div x-on:click="go" x-on:keydown.enter="go" role="button" tabindex="0">x</div>\n'
                                      '<label>Capacity <input name="capacity"></label>\n'
                                      '<label>Pattern <input name="wildcard"></label>\n'
                                      '<label>Mic <input name="microphone"></label>\n'
                                      '<label>Mail <input name="user_email"></label>\n'})
        self.assertEqual(data["files_scanned"], 1)
        self.assertEqual(data["click_handlers"], [])
        self.assertEqual([(r["name"], r["missing"]) for r in data["inputs"]], [("user_email", ["autocomplete", "type=email"])])

    def test_numeric_regions_three_letter_languages_and_label_components(self):
        data = self.scan({
            "locales/en.json": json.dumps({"save": "Save"}), "locales/es-419.json": json.dumps({"save": "Guardar cambios"}),
            "i18n/en/app.json": json.dumps({"save": "Save"}), "i18n/fil/app.json": json.dumps({"save": "I-save ang mga pagbabago"}),
            "F.tsx": '<Label htmlFor="phone">Phone</Label><input id="phone" type="tel" autoComplete="tel" />\n',
        })
        self.assertEqual(sorted((e["bundle"], e["lang"]) for e in data["locale_expansion"]),
                         [("i18n/{lang}/app.json", "fil"), ("locales/{lang}.json", "es-419")])
        self.assertEqual(data["inputs"], [])

    def test_round_three_slow_paths(self):
        import time
        cases = {"a.svelte": "<div on:click={() => { // it's }\n" * 20000,
                 "b.tsx": "<a b={ ' <c d={ \n" * 20000,
                 "c.html": "<button><span>x</span>\n" * 20000}
        for name, text in cases.items():
            with self.subTest(name=name):
                started = time.monotonic()
                self.scan({name: text})
                self.assertLess(time.monotonic() - started, 4)

    def test_round_three_self_review_regressions(self):
        data = self.scan({
            "list.hbs": '{{#each items}}<li>{{this}}</li>{{/each}}\n<!-- <img src="old-banner.png"> -->\n'
                        '<!-- <input name="legacy"> -->\n',
            "D.jsx": "<button onClick={deleteModal.onOpen}>Delete</button>\n"
                     "<button onClick={() => removeDrawer.open()}>x</button>\n"
                     "<button onClick={() => deleteTask(id).then(done)}>x</button>\n",
            "f.html": "".join(f'<label>{n} <input name="{n}" type="text"></label>\n' for n in (
                "telephone", "phonenumber", "cellphone", "emailaddress", "useremail", "newpassword", "postcode",
                "billingaddress", "microphone", "capacity")),
        })
        self.assertEqual(data["images"], [])
        self.assertEqual([r["call"] for r in data["destructive_actions"]], ["deleteTask"])
        self.assertEqual([r["name"] for r in data["inputs"]], [
            "telephone", "phonenumber", "cellphone", "emailaddress", "useremail", "newpassword", "postcode",
            "billingaddress"])
        self.assertIn("type=tel", data["inputs"][0]["missing"])
        self.assertIn("type=email", data["inputs"][3]["missing"])

    def test_line_leading_slashes_in_jsx_text_are_text(self):
        import time
        data = self.scan({"a.jsx": 'export const A = () => (\n<div>\n// visible text <img src="x" />\n</div>\n);\n'
                                   'const f = () =>\n// <img src="commented" />\nnull;\n'})
        self.assertEqual([r["location"] for r in data["images"]], ["a.jsx:3"])
        started = time.monotonic()
        self.scan({"b.jsx": "<div>\n" + "// note\n" * 50000})
        self.assertLess(time.monotonic() - started, 3)
        data = self.scan({"c.jsx": 'export const C = () => (\n<div>\n{x}\n// after an expression <img src="x" />\n'
                                   '{a.map((v) => {\n  return v;\n})}\n// after a callback <img src="y" />\n</div>\n);\n'
                                   'function f() {\n  return 1;\n}\n// <img src="commented" />\n'})
        self.assertEqual([r["location"] for r in data["images"]], ["c.jsx:4", "c.jsx:8"])
        for text in ("{}\n" + "// note\n" * 50000, "}\n// note\n" * 30000, "}" * 100000 + "\n// note\n" * 1000):
            started = time.monotonic()
            self.scan({"d.jsx": text})
            self.assertLess(time.monotonic() - started, 3)


if __name__ == "__main__":
    unittest.main()
