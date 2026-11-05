"""Reject personal mailboxes with email-header comments and folding whitespace."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

from test_privacy_scan import complete_doc, finding, findings, personal_values, render


# Synthetic mailboxes only, outside the reserved example domains.
PRIVATE_ADDRESSES = (
    "synthetic-user @ privacy-scan.localhost",
    "synthetic-user (fixture) @ privacy-scan.localhost",
    "synthetic-user@(fixture)privacy-scan.localhost",
    "synthetic-user(left(nested)tail)@(right(nested)tail)privacy-scan.localhost",
    "synthetic-user (x@y) @ privacy-scan.localhost",
    "synthetic-user (x@example.com) @ privacy-scan.localhost",
    "synthetic-user (x@(nested)example.com) @ privacy-scan.localhost",
    r"synthetic-user (escaped \) and \( and \\) @ privacy-scan.localhost",
    "synthetic-user\r\n \t@\r\n \tprivacy-scan.localhost",
    "synthetic-user@\n privacy-scan.localhost",
    '"synthetic user" @privacy-scan.localhost',
    '"synthetic user" (fixture) @ (fixture) privacy-scan.localhost',
    r'"synthetic \"user\"" (fixture) @ privacy-scan.localhost',
    '"synthetic\r\n user" (fixture) @ privacy-scan.localhost',
    "synthetic-user (fixture) @ (fixture) [192.0.2.1]",
    '"synthetic user" (fixture) @ [IPv6:2001:db8::1]',
    "synthetic-user @ [\r\n 192.0.2.1\r\n ]",
)


class EmailCfwsTests(unittest.TestCase):
    def test_cfws_mailboxes_are_refused_without_replacing_or_disclosing_outputs(self):
        for address in PRIVATE_ADDRESSES:
            with self.subTest(address=ascii(address)), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                out = root / "output"
                out.mkdir()
                target, fragment = out / "findings.json", root / "fragment.json"
                doc = complete_doc()
                target.write_text(json.dumps(doc), encoding="utf-8")
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(render.main([str(target), "--out", str(out)]), 0)
                self.assertEqual(findings.contract_problems(out), [])
                originals = {name: (out / name).read_bytes() for name in findings.OUTPUTS}
                doc["findings"][0]["validation"]["evidence"] = address
                fragment.write_text(json.dumps({"findings": [{
                    "id": "PV-001", "validation": doc["findings"][0]["validation"],
                }]}), encoding="utf-8")
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    self.assertEqual(findings.main(["merge", str(target), str(fragment)]), 1)
                self.assertEqual({name: (out / name).read_bytes() for name in originals}, originals)

                target.write_text(json.dumps(doc), encoding="utf-8")
                submitted = target.read_bytes()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    self.assertEqual(render.main([str(target), "--out", str(out)]), 2)
                    self.assertEqual(findings.main(["check", str(out)]), 1)
                self.assertEqual(target.read_bytes(), submitted)
                for name in ("report.md", "dashboard.html"):
                    self.assertEqual((out / name).read_bytes(), originals[name])
                messages = stdout.getvalue() + stderr.getvalue()
                self.assertIn("findings[0].validation.evidence", messages)
                self.assertIn("contains an e-mail address", messages)
                for private_value in (address, "synthetic", "privacy-scan.localhost", "Traceback"):
                    self.assertNotIn(private_value, messages)

    def test_reserved_mailboxes_keep_original_spelling_and_quoted_internal_at_signs(self):
        locals_and_cfws = (
            "synthetic-user (left(nested)) @ (right) ",
            r'"synthetic \"user\"" (escaped \)) @ ',
            '"synthetic@privacy-scan.localhost" (fixture) @ ',
            '"synthetic@[192.0.2.1]"\r\n \t@\r\n ',
            '"synthetic@privacy-scan.localhost\r\n extra" (fixture) @ ',
        )
        for prefix in locals_and_cfws:
            for domain in ("example.com", "sub.example.org", "EXAMPLE.NET", "host.example",
                           "host.test", "host.invalid"):
                with self.subTest(prefix=ascii(prefix), domain=domain):
                    value = prefix + domain
                    doc = {"findings": [finding(title=value)]}
                    findings.validate(doc)
                    self.assertEqual(doc["findings"][0]["title"], value)
                    self.assertEqual(list(personal_values._email_domains(value)), [domain])

    def test_reserved_cfws_spelling_survives_merge_and_render(self):
        value = "synthetic-user (fixture (nested)) \t@ (domain) EXAMPLE.COM"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / "output"
            out.mkdir()
            fragment, target = root / "fragment.json", out / "findings.json"
            doc = complete_doc()
            doc["findings"][0]["validation"]["evidence"] = value
            fragment.write_text(json.dumps(doc), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(findings.main(["merge", str(target), str(fragment)]), 0)
                self.assertEqual(render.main([str(target), "--out", str(out)]), 0)
                self.assertEqual(findings.main(["check", str(out)]), 0)
            self.assertEqual(json.loads(target.read_text(encoding="utf-8")), doc)
            for name in ("report.md", "dashboard.html"):
                self.assertIn(value, (out / name).read_text(encoding="utf-8"))

    def test_comments_and_malformed_quotes_do_not_hide_other_personal_values(self):
        values = (
            '"safe" (synthetic@privacy-scan.localhost) @ example.com',
            '"safe" (outer (synthetic @ privacy-scan.localhost)) @ example.com',
            '"safe" ("synthetic@privacy-scan.localhost") @ example.com',
            "safe @ (synthetic@privacy-scan.localhost) example.com",
            '"synthetic@privacy-scan.localhost\nbroken" (fixture) @ example.com',
            '"synthetic@privacy-scan.localhost" (unclosed @ example.com',
        )
        for value in values:
            with self.subTest(value=ascii(value)), self.assertRaisesRegex(
                    findings.SchemaError, "contains an e-mail address"):
                findings.validate({"limitations": [value]})

    def test_cfws_handling_does_not_join_unrelated_prose_or_numbers(self):
        values = (
            "synthetic-user\n@privacy-scan.localhost",
            "synthetic-user (fixture)\n@privacy-scan.localhost",
            "synthetic-user@\nprivacy-scan.localhost",
            "synthetic-user@ (unclosed)\nprivacy-scan.localhost",
            "0000 (fixture) 0000 (fixture) 0000 user@example.com",
            "0000\n 0000\n 0000 user@example.com",
            "user@example.com. A new sentence",
        )
        for value in values:
            with self.subTest(value=ascii(value)):
                doc = {"limitations": [value]}
                findings.validate(doc)
                self.assertEqual(doc["limitations"], [value])

    def test_large_comments_and_folded_quoted_candidates_finish_within_deadline(self):
        script = textwrap.dedent(r'''
            import sys
            sys.path.insert(0, sys.argv[1])
            from test_privacy_scan import findings

            values = (
                "synthetic" + "(x)" * 32768 + " @ example.com",
                "synthetic" + "(" * 32768 + "x" + ")" * 32768 + " @ example.com",
                "(" * 100000 + " synthetic @ example.com",
                ")" * 100000 + " synthetic @ example.com",
                "(a@b)" * 32768 + " synthetic @ example.com",
                '"' + "synthetic@privacy-scan.localhost," * 4096
                    + '"' + "(x)" * 32768 + " @ example.com",
                '"a\\\"' * 32768 + " synthetic @ example.com",
            )
            for value in values:
                findings.validate({"limitations": [value]})
            try:
                findings.validate({"limitations": [
                    "(x)" * 32768 + " synthetic (fixture) @ privacy-scan.localhost",
                ]})
            except findings.SchemaError:
                pass
            else:
                raise AssertionError("a mailbox after a long comment sequence was missed")
        ''')
        try:
            result = subprocess.run(
                [sys.executable, "-B", "-c", script, str(Path(__file__).resolve().parent)],
                capture_output=True, text=True, timeout=10,
            )
        except subprocess.TimeoutExpired:
            raise self.failureException("CFWS scanning exceeded the 10-second deadline") from None
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
