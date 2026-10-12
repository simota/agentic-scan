"""Exercise the documented demo command, including its HTML-only output contract."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("make"), "make is required for the demo command")
class DemoTests(unittest.TestCase):
    def test_demo_refuses_output_symlinks_without_touching_their_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            out.mkdir()
            outside = Path(tmp) / "outside.json"
            outside.write_text("keep this content", encoding="utf-8")
            (out / "flows.json").symlink_to(outside)
            result = subprocess.run(
                ["make", "--no-print-directory", "demo", "NO_PDF=1",
                 f"DEMO_OUT={out}", f"PYTHON={sys.executable}"],
                cwd=ROOT, text=True, capture_output=True, timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("symlink", result.stderr)
            self.assertEqual(outside.read_text(encoding="utf-8"), "keep this content")
            self.assertEqual({p.name for p in out.iterdir()}, {"flows.json"})

    def test_html_only_demo_satisfies_contract_in_both_languages(self):
        for lang, sample in (("en", "findings.sample.json"), ("ja", "findings.sample.ja.json")):
            with self.subTest(lang=lang), tempfile.TemporaryDirectory() as tmp:
                source = ROOT / "examples" / sample
                before = source.read_bytes()
                out = Path(tmp) / "demo with spaces"
                result = subprocess.run(
                    ["make", "--no-print-directory", "demo", "NO_PDF=1",
                     f"LANG_OUT={lang}", f"DEMO_OUT={out}", f"PYTHON={sys.executable}"],
                    cwd=ROOT, text=True, capture_output=True, timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("contract ok:", result.stdout)
                self.assertEqual({p.name for p in out.iterdir()},
                                 {"findings.json", "flows.json", "inventory.json",
                                  "dashboard.html", "report.html"})
                data = json.loads((out / "findings.json").read_text(encoding="utf-8"))
                self.assertTrue(any(line.startswith("report.pdf not produced:")
                                    for line in data["limitations"]))
                self.assertIn(f'<html lang="{lang}"',
                              (out / "report.html").read_text(encoding="utf-8"))
                self.assertEqual(source.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
