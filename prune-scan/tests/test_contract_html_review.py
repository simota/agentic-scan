"""Regression tests for browser-incompatible self-closing contract HTML."""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "prune-scan" / "scripts"))

import contract_check  # noqa: E402


class ContractHtmlReviewTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out = Path(tmp.name)
        data = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
        data["limitations"].append("report.pdf not produced: this test checks HTML")
        sources = {
            "findings.json": json.dumps(data).encode("utf-8"),
            "units.json": (ROOT / "examples" / "units.sample.json").read_bytes(),
            "inventory.json": b'{"tool": "inventory.py"}\n',
        }
        for name, source in sources.items():
            (self.out / name).write_bytes(source)
        self.stamps = "".join(
            f'<meta name="{stamp}" content="sha256:{hashlib.sha256(sources[name]).hexdigest()}">'
            for stamp, name in ((contract_check.STAMP, "findings.json"),
                                (contract_check.UNITS_STAMP, "units.json"))
        )
        self.page = f'<html lang="en"><head>{self.stamps}</head><body>Report</body></html>'
        for name in ("dashboard.html", "report.html"):
            (self.out / name).write_text(self.page, encoding="utf-8")
        self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])

    def assert_rejected(self, page):
        for name in ("dashboard.html", "report.html"):
            with self.subTest(page=name):
                path = self.out / name
                path.write_text(page, encoding="utf-8")
                try:
                    errors = list(contract_check.problems(self.out, no_pdf=True))
                    self.assertTrue(any(error.startswith(f"{name}: invalid or incomplete HTML")
                                        for error in errors), errors)
                finally:
                    path.write_text(self.page, encoding="utf-8")

    def test_self_closing_non_void_head_elements_cannot_validate_inert_stamps(self):
        for tag in ("style", "script", "title", "template", "textarea", "iframe", "div"):
            for opening in (f"<{tag}/>", f"<{tag.upper()} />"):
                with self.subTest(opening=opening):
                    self.assert_rejected(self.page.replace("<head>", "<head>" + opening, 1))

    def test_self_closing_body_cannot_supply_a_missing_end_tag(self):
        self.assert_rejected(self.page.replace("<body>Report</body>", "<body/>"))

    def test_self_closing_envelope_elements_are_invalid(self):
        for page in ('<html lang="en"/>',
                     '<html lang="en"><head/><body></body></html>',
                     '<html lang="en"><head></head><body/></html>'):
            with self.subTest(page=page):
                metadata = contract_check.PageMetadata(page)
                self.assertTrue(metadata.invalid)
                self.assertFalse(metadata.complete)

    def test_void_self_closing_elements_preserve_valid_stamps(self):
        for ending in ("/>", " />"):
            with self.subTest(ending=ending):
                head = '<link rel="stylesheet" href="report.css"' + ending
                head += self.stamps.replace(">", ending)
                page = f'<html lang="en"><head>{head}</head><body><br/><img src="icon.png" /></body></html>'
                for name in ("dashboard.html", "report.html"):
                    (self.out / name).write_text(page, encoding="utf-8")
                self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])

    def test_self_closing_text_in_comments_and_scripts_is_not_markup(self):
        content = '<!-- <head/> --><script>const example = "<style/>";</script>'
        page = self.page.replace("<head>", "<head>" + content, 1)
        for name in ("dashboard.html", "report.html"):
            (self.out / name).write_text(page, encoding="utf-8")
        self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])


if __name__ == "__main__":
    unittest.main()
