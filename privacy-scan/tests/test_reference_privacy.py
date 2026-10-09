"""Regression checks for personal values encoded in reference URLs."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_privacy_scan import complete_doc, findings, render


SYNTHETIC_EMAIL = "synthetic@privacy-scan.localhost"
ENCODED_EMAIL = "synthetic%40privacy-scan.localhost"


def reference_doc(url):
    doc = complete_doc()
    doc["findings"][0]["references"] = [{"title": "Source reference", "url": url}]
    return doc


class ReferencePrivacyTests(unittest.TestCase):
    def test_encoded_personal_values_are_refused_in_url_components(self):
        urls = (
            f"https://example.invalid/?email={ENCODED_EMAIL}",
            f"https://example.invalid/?{ENCODED_EMAIL}=field",
            f"https://example.invalid/people/{ENCODED_EMAIL}",
            f"https://{ENCODED_EMAIL}@docs.example.com/",
            f"../people/{ENCODED_EMAIL}",
            f"#email={ENCODED_EMAIL}",
            f"mailto:{ENCODED_EMAIL}",
            "https://example.invalid/?email=synthetic%40privacy-scan%2Elocalhost",
            "https://example.invalid/?email=synthetic%EF%BC%A0privacy-scan.localhost",
            "https://example.invalid/?email=synthetic%40%5B192.0.2.1%5D",
            "https://example.invalid/?account=" + "%30" * 12,
            "https://example.invalid/?account=0000%200000%200000",
            "https://example.invalid/?account=0000%090000%090000",
            "https://example.invalid/?account=0000%C2%A00000%C2%A00000",
            "https://example.invalid/accounts/0000%2D0000%2D0000",
            "https://example.invalid/?account=0000+0000+0000",
        )
        for url in urls:
            with self.subTest(url=url):
                with self.assertRaises(findings.SchemaError) as raised:
                    findings.validate(reference_doc(url), complete=True)
                self.assertIn("references[0].url", str(raised.exception))
                self.assertNotIn(url, str(raised.exception))
                self.assertNotIn("privacy-scan.localhost", str(raised.exception))

    def test_raw_and_parsed_forms_are_both_checked(self):
        urls = (
            # The raw non-example address must not be hidden by decoding a suffix.
            "https://example.invalid/?email=synthetic@privacy-scan.localhost%2Eexample.com",
            # URL parsing removes literal tabs/newlines before a link is followed.
            "https://example.invalid/?email=synthetic@\nprivacy-scan.localhost",
            "https://example.invalid/?email=synthetic@privacy-scan.\tlocalhost",
            # Malformed URLs remain visible as text, so inspect their decoded values too.
            f"https://[broken/?email={ENCODED_EMAIL}",
        )
        for url in urls:
            with self.subTest(url=url), self.assertRaises(findings.SchemaError):
                findings.validate(reference_doc(url), complete=True)

    def test_reserved_examples_and_safe_url_values_remain_allowed(self):
        urls = (
            *(f"https://example.invalid/?email=synthetic%40{domain}"
              for domain in ("example.com", "sub.example.org", "EXAMPLE.NET",
                             "host.example", "host.test", "host.invalid")),
            "https://example.invalid/?email=%22synthetic%20user%22%40example.com",
            "../people/synthetic%40example.com",
            "#email=synthetic%40host.test",
            "https://example.invalid/?account=0000%200000%20000",
            "https://example.invalid/?account=0000+0000+000",
            "https://example.invalid/?first=000000&second=000000",
            "https://example.invalid/?000000=000000",
            # Encoded plus signs are literal plus signs, not form separators.
            "https://example.invalid/?token=0000%2B0000%2B0000",
            # Repeated decoding still exempts reserved example domains.
            "https://example.invalid/?literal=synthetic%2540example.com",
            "https://[broken/%20source",
        )
        for url in urls:
            with self.subTest(url=url):
                doc = reference_doc(url)
                findings.validate(doc, complete=True)
                self.assertEqual(doc, reference_doc(url))

    def test_commands_refuse_values_without_replacing_outputs_or_echoing_them(self):
        cases = (
            (f"https://example.invalid/?email={ENCODED_EMAIL}", SYNTHETIC_EMAIL),
            ("https://example.invalid/?account=0000+0000+0000", "0000 0000 0000"),
            (f"https://[broken/?email={ENCODED_EMAIL}", SYNTHETIC_EMAIL),
        )
        for url, decoded_value in cases:
            with self.subTest(url=url), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                out = root / "output"
                out.mkdir()
                target, fragment = out / "findings.json", root / "fragment.json"
                originals = {
                    "findings.json": json.dumps(complete_doc()).encode("utf-8"),
                    "dashboard.html": b"previous dashboard",
                    "report.md": b"previous report",
                }
                for name, content in originals.items():
                    (out / name).write_bytes(content)
                fragment.write_text(json.dumps({"findings": [{
                    "id": "PV-001", "references": [{"url": url}],
                }]}), encoding="utf-8")
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    self.assertEqual(findings.main(["merge", str(target), str(fragment)]), 1)
                self.assertEqual({name: (out / name).read_bytes() for name in originals}, originals)

                # Direct input must fail before either existing report is replaced.
                invalid_record = json.dumps(reference_doc(url)).encode("utf-8")
                target.write_bytes(invalid_record)
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    self.assertEqual(render.main([str(target), "--out", str(out)]), 2)
                    self.assertEqual(findings.main(["check", str(out)]), 1)
                for name in ("dashboard.html", "report.md"):
                    self.assertEqual((out / name).read_bytes(), originals[name])
                self.assertEqual(target.read_bytes(), invalid_record)
                messages = stdout.getvalue() + stderr.getvalue()
                self.assertIn("findings[0].references[0].url", messages)
                for value in (url, decoded_value, "privacy-scan.localhost", "Traceback"):
                    self.assertNotIn(value, messages)

    def test_accepted_urls_keep_their_original_spelling_in_every_output(self):
        url = "https://EXAMPLE.invalid/docs%2fprivacy?email=synthetic%40example.com#scope%2fdetail"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / "output"
            out.mkdir()
            target, fragment = out / "findings.json", root / "fragment.json"
            fragment.write_text(json.dumps(reference_doc(url)), encoding="utf-8")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(findings.main(["merge", str(target), str(fragment)]), 0)
                self.assertEqual(render.main([str(target), "--out", str(out)]), 0)
                self.assertEqual(findings.main(["check", str(out)]), 0)
            self.assertEqual(json.loads(target.read_text(encoding="utf-8")), reference_doc(url))
            for name in ("dashboard.html", "report.md"):
                self.assertIn(url, (out / name).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
