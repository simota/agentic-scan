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
