"""Regression checks for personal-value variants and readable, nonempty outputs."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from test_privacy_scan import complete_doc, finding, findings, render


# Synthetic, non-deliverable addresses outside the reserved example domains.
PRIVATE_VARIANTS = (
    '"synthetic user"@privacy-scan.localhost',
    '"synthetic \\"user\\""@privacy-scan.localhost',
    '"synthetic@user"@privacy-scan.localhost',
    "架空利用者@privacy-scan.localhost",
    "synthetic-user@例示.localhost",
    "synthetic-user＠privacy-scan.localhost",
    *(f"synthetic@privacy-scan{dot}localhost" for dot in ("\u3002", "\uff0e", "\uff61")),
    *(f"synthetic@example.com{dot}privacy-scan.localhost"
      for dot in ("\u3002", "\uff0e", "\uff61")),
    *(f"synthetic@example.com{mark}.privacy-scan.localhost" for mark in ("\u030b", "\u0338")),
    "synthetic@privacy-scan\u030b.localhost",
    "synthetic@l\u00b7l.localhost",
    "synthetic@\u0375α.localhost",
    "synthetic@אב\u05f3.localhost",
    "synthetic@אב\u05f4גד.localhost",
    "synthetic@テスト\u30fb例.localhost",
    "synthetic@سنڌي\u06fd.localhost",
    "synthetic@سنڌي\u06fe.localhost",
    "synthetic@བོད\u0f0b.localhost",
    "synthetic@क्\u200cष.localhost",
    "synthetic@क्\u200dष.localhost",
    "synthetic@example.com\u30fbprivacy-scan.localhost",
    "Contact synthetic@privacy-scan.localhost..trailing",
    "0000  0000  0000",
    "0000\u00a00000\u00a00000",
    "0000\u202f0000\u202f00000",
    "0000\t0000\t0000",
    "0000\u16800000\u16800000",
)


class PersonalValueVariantSafetyTests(unittest.TestCase):
    def test_variants_are_refused_by_merge_render_and_check(self):
        for value in (*PRIVATE_VARIANTS, "synthetic-secret\ud800tail", "synthetic-secret\udffftail"):
            with self.subTest(value=ascii(value)), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                out = root / "output"
                out.mkdir()
                target, fragment = out / "findings.json", root / "fragment.json"
                original = (json.dumps(complete_doc(), indent=2) + "\n").encode("utf-8")
                target.write_bytes(original)
                fragment.write_text(json.dumps({"findings": [
                    {"id": "PV-001", "title": value}]}), encoding="utf-8")
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    self.assertEqual(findings.main(["merge", str(target), str(fragment)]), 1)
                self.assertEqual(target.read_bytes(), original)

                # Direct records must fail before replacing prior reports too.
                doc = complete_doc()
                doc["findings"][0]["title"] = value
                target.write_text(json.dumps(doc), encoding="utf-8")
                reports = {"report.md": b"previous report", "dashboard.html": b"previous dashboard"}
                for name, content in reports.items():
                    (out / name).write_bytes(content)
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    self.assertEqual(render.main([str(target), "--out", str(out)]), 2)
                    self.assertEqual(findings.main(["check", str(out)]), 1)
                for name, content in reports.items():
                    self.assertEqual((out / name).read_bytes(), content)
                messages = stdout.getvalue() + stderr.getvalue()
                self.assertIn("findings[0].title", messages)
                self.assertNotIn(value, messages)
                self.assertNotIn("synthetic-secret", messages)
                self.assertNotIn("Traceback", messages)

    def test_quoted_and_unicode_reserved_examples_remain_allowed(self):
        for local in ('"synthetic user"', "架空利用者"):
            for domain in ("example.com", "sub.example.org", "EXAMPLE.NET", "host.example",
                           "host.test", "host.invalid"):
                with self.subTest(local=local, domain=domain):
                    findings.validate({"findings": [finding(title=f"{local}@{domain}")]})
        for address in ('"synthetic user"@example.com.localhost',
                        "架空利用者@notexample.com", "架空利用者@example.net.localhost"):
            with self.subTest(address=address), self.assertRaises(findings.SchemaError):
                findings.validate({"findings": [finding(title=address)]})

    def test_reserved_examples_keep_japanese_punctuation_boundaries(self):
        addresses = (
            "user@example.com", '"synthetic user"@example.com', "架空利用者@example.com",
            "synthetic@sub\u030b.example.com", "user@example\u3002com",
            "user@example\uff0ecom", "user@example\uff61com",
        )
        contexts = ("「{}」を使う", "『{}』を使う", "（{}）を使う", "{}、例を使う", "例：{}。")
        for address in addresses:
            for context in contexts:
                with self.subTest(address=address, context=context):
                    findings.validate({"findings": [finding(title=context.format(address))]})

    def test_repeated_and_nonbreaking_spaces_keep_the_twelve_digit_threshold(self):
        for separator in ("  ", "\u00a0", "\u202f", "\t", "\u1680"):
            for suffix in ("000", "0000"):
                value = separator.join(("0000", "0000", suffix))
                with self.subTest(separator=repr(separator), digit_count=8 + len(suffix)):
                    doc = {"findings": [finding(title=value)]}
                    if len(suffix) == 3:
                        findings.validate(doc)
                    else:
                        with self.assertRaises(findings.SchemaError):
                            findings.validate(doc)

    def test_line_breaks_still_separate_unrelated_numbers(self):
        for separator in ("\n", "\r\n", "\u2028", "\u2029"):
            with self.subTest(separator=repr(separator)):
                findings.validate({"findings": [finding(title=separator.join(("0000",) * 3))]})


class OutputFileSafetyTests(unittest.TestCase):
    def write_outputs(self, out):
        (out / "findings.json").write_text(json.dumps(complete_doc()), encoding="utf-8")
        for name in ("report.md", "dashboard.html"):
            (out / name).write_text("rendered output", encoding="utf-8")

    def test_required_outputs_cannot_be_empty(self):
        for name in sorted(findings.OUTPUTS):
            with self.subTest(output=name), tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                self.write_outputs(out)
                (out / name).write_bytes(b"")
                self.assertIn(f"empty output: {name}", findings.contract_problems(out))

    def test_unreadable_outputs_fail_without_disclosing_os_errors(self):
        original_open = Path.open
        for name in sorted(findings.OUTPUTS):
            with self.subTest(output=name), tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                self.write_outputs(out)

                def open_except_output(path, *args, **kwargs):
                    if path == out / name:
                        raise PermissionError("synthetic-secret")
                    return original_open(path, *args, **kwargs)

                stderr = io.StringIO()
                with patch.object(Path, "open", open_except_output), \
                        redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                    self.assertEqual(findings.main(["check", str(out)]), 1)
                self.assertIn(f"unreadable output: {name}", stderr.getvalue())
                self.assertNotIn("synthetic-secret", stderr.getvalue())
                self.assertNotIn("Traceback", stderr.getvalue())

    def test_invalid_utf8_findings_fail_with_a_safe_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            self.write_outputs(out)
            (out / "findings.json").write_bytes(b'{"meta":{"project":"synthetic-secret\xff"}}')
            stderr = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                self.assertEqual(findings.main(["check", str(out)]), 1)
            self.assertIn("UTF-8 JSON", stderr.getvalue())
            self.assertNotIn("synthetic-secret", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
