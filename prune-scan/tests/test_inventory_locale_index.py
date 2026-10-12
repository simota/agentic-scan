"""Locale inventories retain key locations without rescanning every JSON suffix."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import inventory  # noqa: E402


class LocaleIndexTests(unittest.TestCase):
    def test_escaped_keys_have_their_actual_source_lines(self):
        source = '{\n  "caf\\u00e9": "Coffee",\n  "say\\\"hi": "Hello",\n  "back\\\\slash": "Back"\n}\n'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "locales").mkdir()
            (root / "locales" / "en.json").write_text(source, encoding="utf-8")
            rows = {row["key"]: row for row in inventory.inventory(root)["i18n_unreferenced"]}
        self.assertEqual(rows['café']["location"], "locales/en.json:2")
        self.assertEqual(rows['say"hi']["location"], "locales/en.json:3")
        self.assertEqual(rows['back\\slash']["location"], "locales/en.json:4")

    def test_key_shaped_text_in_values_is_not_indexed_as_a_key(self):
        source = json.dumps({"example": 'an escaped "target": is only prose', "target": "Real key"}, indent=2)
        lines = inventory.json_key_lines(source)
        self.assertEqual(lines["target"], 3)
        self.assertEqual(set(lines), {"example", "target"})

    def test_reference_counts_languages_and_caps_survive_a_large_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "repo"
            (root / "locales").mkdir(parents=True)
            entries = {f"key_{i:05}": "Label" for i in range(30000)}
            entries["used_key"] = "Keep this label"
            source = json.dumps(entries, indent=2)
            self.assertLess(len(source.encode("utf-8")), inventory.MAX_BYTES)
            (root / "locales" / "en.json").write_text(source, encoding="utf-8")
            (root / "locales" / "ja.json").write_text(source, encoding="utf-8")
            (root / "main.js").write_text('t("used_key");\n', encoding="utf-8")
            output = base / "inventory.json"
            result = subprocess.run(
                [sys.executable, str(SCRIPTS / "inventory.py"), str(root), "--out", str(output)],
                capture_output=True, text=True, timeout=10,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            data = json.loads(output.read_text(encoding="utf-8"))
        rows = data["i18n_unreferenced"]
        self.assertEqual(len(rows), inventory.MAX_ROWS)
        self.assertEqual(data["truncated"]["i18n_unreferenced"], 30000 - inventory.MAX_ROWS)
        self.assertEqual(rows[0]["key"], "key_00000")
        self.assertEqual(rows[0]["location"], "locales/en.json:2")
        self.assertEqual(rows[0]["langs"], ["en", "ja"])
        self.assertEqual(rows[-1]["location"], f"locales/en.json:{inventory.MAX_ROWS + 1}")
        self.assertNotIn("used_key", {row["key"] for row in rows})


if __name__ == "__main__":
    unittest.main()
