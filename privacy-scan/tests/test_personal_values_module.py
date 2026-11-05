"""The personal-value guard as its own module: a pure reason-or-None interface."""
import ast
import unittest

from test_privacy_scan import SKILL, finding, findings, personal_values

SYNTHETIC_EMAIL = "synthetic@privacy-scan.localhost"
LONG_DIGITS = "0000 0000 0000"


class GuardInterfaceTests(unittest.TestCase):
    def test_find_returns_the_reason_or_none_without_changing_input(self):
        cases = {
            f"sent to {SYNTHETIC_EMAIL}": personal_values.EMAIL,
            f"account {LONG_DIGITS}": personal_values.LONG_NUMBER_VALUE,
            "synthetic%40privacy-scan.localhost": personal_values.EMAIL,  # decoded copies too
            "user@example.com and 2026-10-09..2026-10-10": None,
            "": None,
            None: None,
        }
        for value, reason in cases.items():
            with self.subTest(value=value):
                self.assertEqual(personal_values.find(value), reason)

    def test_find_in_url_inspects_decoded_components(self):
        self.assertEqual(personal_values.find_in_url(
            "https://example.invalid/?email=synthetic%40privacy-scan.localhost"), personal_values.EMAIL)
        self.assertEqual(personal_values.find_in_url(
            "https://example.invalid/?account=0000+0000+0000"), personal_values.LONG_NUMBER_VALUE)
        self.assertEqual(personal_values.find_in_url("https://[broken/" + "%30" * 12),
                         personal_values.LONG_NUMBER_VALUE)
        self.assertIsNone(personal_values.find_in_url("https://example.invalid/docs?page=2"))

    def test_findings_names_the_field_and_keeps_the_reason(self):
        doc = {"findings": [finding(title=f"forwards {SYNTHETIC_EMAIL}")]}
        with self.assertRaises(findings.SchemaError) as caught:
            findings.validate(doc)
        self.assertEqual(str(caught.exception), f"findings[0].title: {personal_values.EMAIL}")
        self.assertNotIn(SYNTHETIC_EMAIL, str(caught.exception))

    def test_guard_depends_on_the_standard_library_only(self):
        tree = ast.parse((SKILL / "scripts" / "personal_values.py").read_text(encoding="utf-8"))
        imported = {alias.name.split(".")[0] for node in ast.walk(tree)
                    if isinstance(node, ast.Import) for alias in node.names}
        imported |= {node.module.split(".")[0] for node in ast.walk(tree)
                     if isinstance(node, ast.ImportFrom)}
        # Python 3.9 (CI) has no sys.stdlib_module_names, so the list is explicit.
        self.assertEqual(imported, {"bisect", "html", "re", "unicodedata", "urllib"})


if __name__ == "__main__":
    unittest.main()
