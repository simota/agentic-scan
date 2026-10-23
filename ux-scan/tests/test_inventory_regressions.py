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
        self.assertEqual([row["location"] for row in data["inputs"]], ["a.html:1", "a.html:3", "a.html:4"])

    def test_explicit_label_targets_do_not_label_unrelated_wrapped_controls(self):
        for extension, target_attr in (("html", "for"), ("jsx", "htmlFor"), ("vue", "for")):
            with self.subTest(extension=extension):
                name = f"a.{extension}"
                data = self.scan({name:
                    f'<label {target_attr}="search">Search<input /></label>\n'
                    '<input id="search" />\n'
                    f'<label {target_attr}="">Missing target<textarea></textarea></label>\n'
                    f'<label {target_attr}="nested">Nested<input id="nested" /></label>\n'})
                self.assertEqual([(row["element"], row["location"], row["missing"]) for row in data["inputs"]],
                                 [("input", f"{name}:1", ["label"]), ("textarea", f"{name}:3", ["label"])])

    def test_implicit_label_only_names_its_first_labelable_descendant(self):
        data = self.scan({"a.html":
            '<label>Search<input type="hidden"><input id="first"><input id="second"></label>\n'
            '<label>Action<button>Run</button><input id="after-button"></label>\n'
            '<label>Choice<select></select><textarea></textarea></label>\n'
            '<label>Progress<progress value="1" max="2"></progress><input id="after-progress"></label>\n'
            '<label>Search<span><input id="deep"></span></label>\n'})
        self.assertEqual([(row["name"], row["location"]) for row in data["inputs"]], [
            ("second", "a.html:1"), ("after-button", "a.html:2"),
            ("", "a.html:3"), ("after-progress", "a.html:4"),
        ])

    def test_wrapping_labels_keep_dynamic_targets_and_types_unknown(self):
        data = self.scan({
            "a.jsx": '<label htmlFor={fieldId}>Search<input id={fieldId} /></label>\n'
                     '<label htmlFor={fieldId}>Search<input /><input id={fieldId} /></label>\n'
                     '<label>Search<input type={kind} /><input /></label>\n'
                     '<label>Search<input type={kind} /><input /><input /></label>\n'
                     '<label {...props}>Search<input /><input /></label>\n'
                     '<label>Search<input {...props} /><input /></label>\n',
            "b.vue": '<label :for="fieldId">Search<input :id="fieldId" /></label>\n'
                     '<label>Search<input :type="kind" /><input /></label>\n'
                     '<label v-bind="props">Search<input /><input /></label>\n',
        })
        self.assertEqual([(row["type"], row["location"], row["missing"]) for row in data["inputs"]],
                         [("text", "a.jsx:4", ["label"])])

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

    def test_svelte_event_modifiers_keep_click_keyboard_and_destructive_handlers(self):
        data = self.scan({"a.svelte":
            '<button on:click|preventDefault={() => deleteItem(id)}>Delete</button>\n'
            '<span on:click|stopPropagation={go}>Go</span>\n'
            '<div on:click|once|capture={go} on:keydown|preventDefault={go} '
            'role="button" tabindex="0">Go</div>\n'
            '<button on:click|once={() => removeItem(first)} '
            'on:click|capture={() => discardItem(second)}>Remove both</button>\n'
            '<button onclick={() => destroyItem(id)}>Destroy</button>\n'
            '<button title="on:click|once={eraseExample()}">Example</button>\n'})
        self.assertEqual(data["click_handlers"], [{
            "element": "span", "missing": ["role", "tabindex", "key handler"], "location": "a.svelte:2",
        }])
        self.assertEqual([(row["call"], row["location"]) for row in data["destructive_actions"]], [
            ("deleteItem", "a.svelte:1"), ("removeItem", "a.svelte:4"),
            ("discardItem", "a.svelte:4"), ("destroyItem", "a.svelte:5"),
        ])

    def test_keyboard_handler_aliases_do_not_create_missing_handler_candidates(self):
        data = self.scan({
            "a.svelte": '<span on:click|stopPropagation={go} on:keyup|preventDefault={go} '
                        'role="button" tabindex="0">Go</span>\n'
                        '<span on:click={go} on:keypress={go} role="button" tabindex="0">Go</span>\n',
            "b.vue": '<div @click="go" v-on:keyup.enter="go" role="button" tabindex="0">Go</div>\n'
                     '<span @click="go" @keypress.enter="go" role="button" tabindex="0">Go</span>\n',
            "c.html": '<div (click)="go()" (keyup)="go()" role="button" tabindex="0">Go</div>\n',
        })
        self.assertEqual(data["click_handlers"], [])

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
                # inventory() scans the resolved root, so the refused path must be resolved
                # too: macOS keeps temporary directories behind the /var -> /private/var link.
                root = Path(tmp).resolve()
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

    def test_cli_refuses_output_that_aliases_flows_before_scanning(self):
        for alias_kind in ("same", "parent-symlink", "symlink", "hardlink"):
            with self.subTest(alias=alias_kind), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                repo = root / "repo"
                repo.mkdir()
                records = root / "records"
                records.mkdir()
                flows = records / "flows.json"
                original = (ROOT / "examples" / "flows.sample.json").read_bytes()
                flows.write_bytes(original)
                out = flows
                if alias_kind == "parent-symlink":
                    parent = root / "alias"
                    parent.symlink_to(records, target_is_directory=True)
                    out = parent / "flows.json"
                elif alias_kind in ("symlink", "hardlink"):
                    out = records / "inventory.json"
                    if alias_kind == "symlink":
                        out.symlink_to(flows)
                    else:
                        os.link(flows, out)
                # Reject argument collisions before traversing the reviewed app.
                with patch.object(inventory, "inventory", side_effect=AssertionError("must not scan")):
                    with patch("sys.stderr"):
                        self.assertEqual(inventory.main([str(repo), "--out", str(out), "--flows", str(flows)]), 2)
                result = self.run_cli(repo, out, "--flows", flows)
                self.assertEqual(result.returncode, 2)
                self.assertIn("--flows input must be different from --out", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual(flows.read_bytes(), original)
                self.assertEqual(out.read_bytes(), original)
                self.assertEqual(out.is_symlink(), alias_kind == "symlink")

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

    def test_an_unclosed_brace_in_markup_does_not_hide_the_rest_of_the_file(self):
        import time
        data = self.scan({"index.html": '<p>a <b {x</p>\n<img src="a.png">\n<input name="email">\n',
                          "a.vue": '<template>\n<b {x>\n<img src="b.png">\n</template>\n'})
        self.assertEqual([r["location"] for r in data["images"]], ["a.vue:3", "index.html:2"])
        self.assertEqual([r["location"] for r in data["inputs"]], ["index.html:3"])
        # A quoted attribute value of the malformed tag is not markup either.
        data = self.scan({"q.html": "<div data={x title=\"<img src='fake.png'>\">\n<img src=\"real.png\">\n"})
        self.assertEqual([r["location"] for r in data["images"]], ["q.html:2"])
        # A raw-text element opened by a malformed tag still hides the markup-like text inside it.
        data = self.scan({"s.html": "<script {x>\nconst demo = '<img src=\"fake.png\">';\n</script>\n<img src=\"real.png\">\n"})
        self.assertEqual([r["location"] for r in data["images"]], ["s.html:4"])
        started = time.monotonic()
        self.scan({"many.html": "<b {x>\n" * 100000})
        self.assertLess(time.monotonic() - started, 4)

    def test_sources_that_are_not_utf8_are_skipped_with_a_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.css").write_bytes(b"/* caf\xe9 */\n.btn{width:20px;height:20px}\n")
            (root / "b.js").write_bytes(b"\0\0")  # A binary is skipped silently.
            data = inventory.inventory(root)
        self.assertEqual(data["files_skipped"], 2)
        self.assertEqual([w["location"] for w in data["parse_warnings"]], ["a.css:1"])
        self.assertIn("not valid UTF-8", data["parse_warnings"][0]["reason"])

    def test_locale_json_with_a_byte_order_mark_is_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "locales").mkdir()
            (root / "locales" / "en.json").write_bytes(b'\xef\xbb\xbf{"hi": "Hello"}')
            (root / "locales" / "de.json").write_bytes(b'\xef\xbb\xbf{"hi": "Hallo Hallo Hallo"}')
            data = inventory.inventory(root)
        self.assertEqual(data["parse_warnings"], [])
        self.assertEqual([(r["base"], r["lang"]) for r in data["locale_expansion"]], [("en", "de")])

    def test_out_in_a_differently_cased_spelling_of_the_repository_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp).resolve() / "repo"
            repo.mkdir()
            (repo / "app.css").write_text(".a{margin:8px}\n", encoding="utf-8")
            alias = repo.with_name("REPO")
            if not alias.exists():
                self.skipTest("case-sensitive filesystem: a differently cased name is another directory")
            result = self.run_cli(repo, alias / "inventory.json")
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("outside the reviewed repository", result.stderr)
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
        data = self.scan({"b.vue": '<template>\n<button v-text=""></button>\n<button v-text="label"></button>\n</template>\n',
                          "c.jsx": 'export const C = () => <div><button children="" /><button children={label}></button>\n'
                                   '<button children=""></button></div>;\n'})
        # A self-closing button has no content: <button children="" /> is as empty as <button children=""></button>.
        self.assertEqual([r["location"] for r in data["icon_buttons"]], ["b.vue:2", "c.jsx:1", "c.jsx:2"])
        data = self.scan({"e.jsx": 'export const E = () => (<div>\n<button className="close" onClick={close} />\n'
                                   '<button aria-label="Close" />\n<button children="Close" />\n</div>);\n',
                          "f.vue": '<template>\n<button class="close" @click="close" />\n</template>\n',
                          # In HTML a slash does not close a button: its content follows.
                          "g.html": '<button class="close"/>Close</button>\n'})
        self.assertEqual([r["location"] for r in data["icon_buttons"]], ["e.jsx:2", "f.vue:2"])
        data = self.scan({"d.jsx": 'const x=/* <img src="a" /> */1;\nconst r = /a/*2;\nconst y = a /* <img src="b" /> */ + 1;\n'})
        self.assertEqual(data["images"], [])

    def test_truncate_in_class_helpers_inline_outline_next_viewport(self):
        data = self.scan({"a.tsx": 'export const A = () => <p className={cn("truncate text-sm", c)}>x</p>;\n'
                                   "export const viewport = { width: 'device-width', maximumScale: 1, userScalable: false };\n",
                          "b.html": '<a href="/x" style="outline: none">x</a>\n'})
        self.assertEqual([r["pattern"] for r in data["truncation"]], ['className={cn("truncate'])
        self.assertEqual([(r["location"], r["blocks_zoom"]) for r in data["viewport_meta"]], [("a.tsx:2", True)])
        self.assertEqual([(r["selector"], r["location"]) for r in data["focus_outline"]], [("(inline style)", "b.html:1")])
        files = {f"s{n}.tsx": f"export const viewport = {{ maximumScale: {value} }};\n"
                 for n, value in enumerate((".5", "1e5", "1_000", "0x10", "1 / 2", "1.5 // tight"))}
        data = self.scan(files)
        self.assertEqual([(r["location"], r["blocks_zoom"]) for r in data["viewport_meta"]],
                         [("s0.tsx:1", True), ("s1.tsx:1", False), ("s2.tsx:1", False), ("s3.tsx:1", False),
                          ("s4.tsx:1", False), ("s5.tsx:1", True)])
        # themeColor holds objects, as in the Next.js documentation.
        data = self.scan({"app/layout.tsx": "export const viewport = {\n"
                                            "  themeColor: [{ media: '(prefers-color-scheme: dark)', color: 'black' },\n"
                                            "               { media: '(prefers-color-scheme: light)', color: 'white' }],\n"
                                            "  maximumScale: 1,\n  userScalable: false,\n}\n"})
        self.assertEqual([(r["location"], r["blocks_zoom"]) for r in data["viewport_meta"]], [("app/layout.tsx:1", True)])

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
        data = self.scan({"e.jsx": 'export const E = () => (\n<div>\n{foo("}")}\n// a string <img src="a" />\n'
                                   '{x.replace(/}/g, "")}\n// a regex <img src="b" />\n{`}${y}`}\n// a template <img src="c" />\n'
                                   '</div>\n);\nfunction f() {\n  return "}";\n}\n// <img src="commented" />\n'})
        self.assertEqual([r["location"] for r in data["images"]], ["e.jsx:4", "e.jsx:6", "e.jsx:8"])
        data = self.scan({"g.jsx": 'export const G = () => (\n<div>\nhello\n// after text <img src="a" />\n'
                                   'Hello {name}, welcome\n// after mixed text <img src="b" />\n</div>\n);\n'
                                   'const a = b\n// <img src="commented" />\nconst o = {\n  label: "x"\n}\n// <img src="c2" />\n'})
        self.assertEqual([r["location"] for r in data["images"]], ["g.jsx:4", "g.jsx:6"])
        data = self.scan({"h.jsx": 'const compared = foo >\n  bar\n// <img src="commented" />\n'
                                   'export const H = () => (\n<div className="a"\n  onClick={() => go()}>\n'
                                   '// visible <img src="a" />\n</div>\n);\n'})
        self.assertEqual([r["location"] for r in data["images"]], ["h.jsx:7"])
        for text in ("<div>\n" + "text\n// note\n" * 30000, "{}\n" + "// note\n" * 50000, '}"\n// note\n' * 30000, "}/ /\n// note\n" * 30000, "}\n// note\n" * 30000, "}" * 100000 + "\n// note\n" * 1000):
            started = time.monotonic()
            self.scan({"d.jsx": text})
            self.assertLess(time.monotonic() - started, 3)


    def test_regex_classes_and_camel_case_exceptions(self):
        import time
        # "/*" inside a regex character class starts no block comment, so later comments are still masked.
        data = self.scan({"a.jsx": 'const r = /[/*]/;\n// <img src="old" />\nconst x=/* <img src="c" /> */1;\n'
                                   'if (ready) /[/*]/.test(value);\n// <img src="old2" />\n'
                                   'const q = i++ / /* <img src="old3" /> */ divisor;\n'
                                   'export const A = () => <img src="a.png" />;\n'
                                   'export const B = () => <p><b>x</b>/* <img src="d" /> */</p>;\n'})
        self.assertEqual([r["location"] for r in data["images"]], ["a.jsx:7"])
        started = time.monotonic()
        self.scan({"b.jsx": "/*" * 300000})
        self.assertLess(time.monotonic() - started, 5)
        # microPhone and autoMobile split into micro_phone and auto_mobile; neither is personal.
        data = self.scan({"c.html": '<label>Mic <input name="microPhone"></label>\n'
                                    '<label>Car <input name="autoMobile"></label>\n'
                                    '<label>Tel <input name="mobilePhone"></label>\n'})
        self.assertEqual([(r["name"], r["missing"]) for r in data["inputs"]],
                         [("mobilePhone", ["autocomplete", "type=tel"])])

    def test_aria_hidden_glyph_buttons_and_cr_line_ends(self):
        data = self.scan({"a.html": '<button onclick="closeIt()"><span aria-hidden="true">&times;</span></button>\n'
                                    '<button><span aria-hidden="true">×</span> Close</button>\n'
                                    '<button><span aria-hidden="true"><span>×</span>close</span></button>\n'
                                    '<button><img src="x.svg" aria-hidden="true">Close</button>\n'
                                    '<button><span title="1 > 0" aria-hidden="true">×</span></button>\n'
                                    '<button><span title="x aria-hidden=\'true\'">Close</span></button>\n'
                                    '<button><span aria-hidden="true"><b title="<span>">x</b></span>Close</button>\n',
                          "b.tsx": 'export const B = () => <button onClick={close}><span aria-hidden="true">×</span>'
                                   '</button>;\n'
                                   '<button onClick={close}><span aria-hidden="true" style={{ fontSize: 20 }}>×</span>'
                                   '</button>;\n'})
        self.assertEqual([r["location"] for r in data["icon_buttons"]],
                         ["a.html:1", "a.html:3", "a.html:5", "b.tsx:1", "b.tsx:2"])
        # A lone CR ends a line, as in the report excerpts.
        data = self.scan({"c.html": '<!doctype html>\r<p>one</p>\r<img src="x.png">\r',
                          "d.jsx": 'const a = 1;\r// <img src="c" />\rexport const D = () => <img src="d" />;\r'})
        self.assertEqual([r["location"] for r in data["images"]], ["c.html:3", "d.jsx:3"])

    def test_round_seven_documented_candidates(self):
        # Quoted rem and em widths in style objects count at 16px, like spacing.
        data = self.scan({"a.tsx": 'export const A = () => <div style={{ width: "30rem", minWidth: "25em" }} />;\n'})
        self.assertEqual(sorted(r["value"] for r in data["fixed_widths"]), ["400px", "480px"])
        # Comment lines in plain script and <script> blocks are masked, as in .js files.
        comments = '// zIndex: 9999\n/* margin: "13px" */\nconst s = { zIndex: 7 };\n'
        data = self.scan({"theme.ts": comments, "theme.cjs": comments,
                          "A.vue": "<template><p>x</p></template>\n<script>\n" + comments + "</script>\n"})
        self.assertEqual([(r["value"], sorted(r["locations"])) for r in data["z_index"]],
                         [(7, ["A.vue:5", "theme.cjs:3", "theme.ts:3"])])
        self.assertEqual(data["spacing"], [])
        # "{/*" in plain script opens an ordinary comment, not a JSX one ending at "*/}".
        data = self.scan({"t.ts": "const a = {/* note */ zIndex: 5 };\nconst b = { zIndex: 6 };\n"})
        self.assertEqual([r["value"] for r in data["z_index"]], [5, 6])
        # An element or arrow function before path does not hide a route.
        data = self.scan({"App.tsx": '<Route element={<Settings />} path="/settings" />\n'
                                     '<Route loader={() => load()} path="/admin" />\n<Route index element={<Home />} />\n'})
        self.assertEqual([r["route"] for r in data["routes"]], ["/settings", "/admin"])
        # Every reduced-motion query is listed, as documented.
        data = self.scan({"m.css": "".join("@media (prefers-reduced-motion: reduce) { .a%d { transition: none; } }\n" % i
                                          for i in range(7))})
        self.assertEqual(len(data["motion"]["reduced_motion"]), 7)
        # Vue class bindings and Svelte class directives that truncate.
        data = self.scan({"T.vue": "<template><div :class=\"['truncate', size]\">a</div></template>\n",
                          "S.svelte": "<p class:truncate={long}>x</p>\n<p :class=\"{ 'line-clamp-2': c }\">y</p>\n"})
        self.assertEqual(sorted(loc for r in data["truncation"] for loc in r["locations"]),
                         ["S.svelte:1", "S.svelte:2", "T.vue:1"])
        # zip is a short stem: whole words and zipcode only.
        data = self.scan({"F.tsx": 'export const F = () => <form><input aria-label="Level" name="gzipLevel" />'
                                   '<input aria-label="ZIP" name="billingZip" /><input aria-label="ZIP" name="zipcode" /></form>;\n'})
        self.assertEqual([r["name"] for r in data["inputs"] if "autocomplete" in r["missing"]], ["billingZip", "zipcode"])
        # An arrow function in a child's prop is not button text.
        data = self.scan({"B.tsx": "export const B = () => <button onClick={go}>"
                                   "<TrashIcon onMouseEnter={() => setHover(true)} /></button>;\n"
                                   "export const C = () => <button onClick={go}><Icon a={() => 1} />Delete</button>;\n"})
        self.assertEqual([r["location"] for r in data["icon_buttons"]], ["B.tsx:1"])

    def scan_with_flows(self, files, tokens=None):
        flows = {"viewports": ["360x640", "1280x800"],
                 "tokens": tokens or {"spacing": [4, 8, 12, 16, 24], "font_sizes": [12, 14, 16, 20, 24, 32],
                                      "breakpoints": [768, 1024]}}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, contents in files.items():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_text(contents, encoding="utf-8")
            return inventory.inventory(root, flows)

    def test_widths_that_cannot_apply_at_the_smallest_viewport(self):
        data = self.scan_with_flows({"a.css":
            ".modal { width: 600px; max-width: 100%; }\n"
            "@media (min-width: 1024px) {\n  .sidebar { width: 400px; }\n}\n"
            "@media screen and (width >= 48em), print { .wide { width: 700px; } }\n"
            ".grid { min-width: 500px; max-width: 100%; }\n"
            "@media (max-width: 1023px) { .rail { width: 380px; } }\n"
            "@media (min-width: 320px) { .card { width: 360.5px; } }\n"
            ".p { width: 610px; max-width: calc(100% - 2rem); }\n"
            ".q { width: 620px; max-width: calc(100% + 20px); }\n"
            ".r { width: 630px; max-width: 100% !important; }\n"
            ".s { width: 640px; max-width: 100%, 1px; }\n",
            "b.scss": ".panel {\n  @media (min-width: 900px) { width: 720px; }\n}\n"})
        wide = {r["value"]: r["wider_than_smallest_viewport"] for r in data["fixed_widths"]}
        # Capped by max-width, or only inside a min-width media query above 360px: cannot overflow there.
        self.assertFalse(wide["600px"])
        self.assertFalse(wide["400px"])
        self.assertFalse(wide["720px"])
        # A query list applies when any of its queries does; min-width beats max-width; max-width queries apply.
        self.assertTrue(wide["700px"])
        self.assertTrue(wide["500px"])
        self.assertTrue(wide["380px"])
        self.assertTrue(wide["360.5px"])
        # Only a cap that cannot exceed its container counts: 100% less a length, not 100% plus one.
        self.assertFalse(wide["610px"])
        self.assertTrue(wide["620px"])
        self.assertFalse(wide["630px"])
        self.assertTrue(wide["640px"])
        # The same value is wider when any one of its declarations applies at the smallest viewport.
        data = self.scan_with_flows({"a.css": "@media (min-width: 1024px) { .a { width: 400px; } }\n.b { width: 400px; }\n"})
        self.assertTrue(data["fixed_widths"][0]["wider_than_smallest_viewport"])

    def test_breakpoint_upper_bounds_and_fluid_sizes_are_on_scale(self):
        data = self.scan_with_flows({"a.css":
            "@media (max-width: 767.98px) { .a { color: red; } }\n"
            "@media (max-width: 1023px) { .b { color: red; } }\n"
            "@media (min-width: 700px) { .c { color: red; } }\n"
            "@media (min-width: 1023px) { .d { color: red; } }\n"
            "@media (width < 767.5px), (1023.9px >= width) { .e { color: red; } }\n"
            "@media (766.5px < width) { .f { color: red; } }\n"
            "h1 { font-size: clamp(1.5rem, 1.2rem + 1.5vw, 2rem); }\n"
            ".stack { padding-bottom: calc(1rem + 3px); margin: max(13px, 1rem) 0; }\n"
            ".g { grid-gap: 14px; grid-row-gap: 8px; }\n"
            ".w { margin:\n  16px\n  20px; }\n"})
        # The tolerance is for upper bounds; a min-width 1 px below a breakpoint is off the scale.
        self.assertEqual(sorted(r["value"] for r in data["off_scale"]["breakpoints"]), ["1023px", "700px", "766.5px"])
        self.assertEqual(sorted(r["value"] for r in data["font_sizes"]), ["24px", "32px"])
        self.assertEqual(sorted(r["value"] for r in data["off_scale"]["spacing"]), ["13px", "14px", "20px"])
        self.assertIn({"value": "20px", "count": 1, "locations": ["a.css:10"]}, data["spacing"])

    def test_style_object_keys_theme_units_theme_folders_and_selectors(self):
        data = self.scan({
            "A.vue": "<template><div :style=\"{ 'margin-top': '13px', 'font-size': '15px' }\">a</div></template>\n",
            "B.tsx": "export const B = () => <><Box sx={{ padding: 3, marginTop: '13px' }} />"
                     "<div style={{ padding: 5 }} /></>;\n",
            "C.ts": 'export const c = { "padding": 18, "zIndex": 40 };\n',
            "src/theme/index.ts": "export const theme = createTheme({});\n",
            "d.css": ".left:hover { color: red; }\n.x { left: 0; }\n",
        })
        # Bare numbers in MUI sx are theme spacing units, not px; quoted lengths there are px.
        self.assertEqual(sorted((r["value"], loc) for r in data["spacing"] for loc in r["locations"]),
                         [("13px", "A.vue:1"), ("13px", "B.tsx:1"), ("18px", "C.ts:1"), ("5px", "B.tsx:1")])
        self.assertEqual([r["value"] for r in data["font_sizes"]], ["15px"])
        self.assertEqual([r["value"] for r in data["z_index"]], [40])
        self.assertIn("src/theme/index.ts", [t["path"] for t in data["token_sources"]])
        # A class or id named left or right is a selector, not a physical property.
        flows_rtl = {"locales": ["ar"]}
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "d.css").write_text(".left:hover { color: red; }\n#right:focus { x: 1 }\n.x { left: 0; }\n",
                                              encoding="utf-8")
            data = inventory.inventory(Path(tmp), flows_rtl)
        self.assertEqual(data["physical_properties"], [{"property": "left", "count": 1, "locations": ["d.css:3"]}])


if __name__ == "__main__":
    unittest.main()
