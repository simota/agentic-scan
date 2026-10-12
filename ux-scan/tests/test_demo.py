"""Exercise the documented demo command, including its HTML-only output contract."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))

import prepare_sample  # noqa: E402
from scan_report_kit import output  # noqa: E402


class SamplePreparationTests(unittest.TestCase):
    def test_sample_input_is_preserved_when_it_aliases_any_demo_output(self):
        record = (ROOT / "examples" / "findings.sample.json").read_bytes()
        for name in prepare_sample.OUTPUTS:
            for alias_at in (None, "input", "output", "hardlink"):
                with self.subTest(name=name, alias_at=alias_at), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    out = root / "out"
                    out.mkdir()
                    for output_name in prepare_sample.OUTPUTS:
                        (out / output_name).write_bytes(record if output_name == name else b"previous output")
                    before = {p.name: p.read_bytes() for p in out.iterdir()}
                    source = out / name
                    if alias_at == "hardlink":
                        source = root / "sample.json"
                        os.link(out / name, source)
                    elif alias_at is not None:
                        alias = root / "alias"
                        alias.symlink_to(out, target_is_directory=True)
                        if alias_at == "input":
                            source = alias / name
                        else:
                            out = alias
                    with mock.patch("sys.stderr") as stderr:
                        result = prepare_sample.main([str(source), "--out", str(out), "--no-pdf"])
                    self.assertEqual(result, 2)
                    self.assertIn("sample input", "".join(str(call) for call in stderr.write.call_args_list))
                    self.assertEqual({p.name: p.read_bytes() for p in out.iterdir()}, before)
                    self.assertEqual(source.read_bytes(), record)

    def test_failed_publication_preserves_both_existing_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            before = {"flows.json": b"previous flows", "findings.json": b"previous findings"}
            for name, content in before.items():
                (out / name).write_bytes(content)
            replace = output.os.replace
            failed = False

            def fail_second_record(source, destination):
                nonlocal failed
                if Path(destination) == out / "findings.json" and not failed:
                    failed = True
                    raise OSError("simulated findings publication failure")
                return replace(source, destination)

            with mock.patch.object(output.os, "replace", side_effect=fail_second_record), \
                    mock.patch("sys.stderr"):
                result = prepare_sample.main([
                    str(ROOT / "examples" / "findings.sample.json"), "--out", str(out), "--no-pdf",
                ])
            self.assertEqual(result, 2)
            self.assertTrue(failed)
            self.assertEqual({p.name: p.read_bytes() for p in out.iterdir()}, before)


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
