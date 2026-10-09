"""Regression checks for email address literals and non-email IP references."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_privacy_scan import complete_doc, finding, findings, render


# Documentation addresses only; no real mailbox or personal data is used.
LOCAL_PARTS = ("synthetic-user", '"synthetic user"', "架空利用者")
PRIVATE_ADDRESSES = tuple(
    f"{local}@{domain}"
    for local in LOCAL_PARTS
    for domain in ("[192.0.2.1]", "[IPv6:2001:db8::1]")
)


class EmailAddressLiteralTests(unittest.TestCase):
    def make_run(self, root):
        out = root / "output"
        out.mkdir()
        target = out / "findings.json"
        target.write_text(json.dumps(complete_doc(), indent=2) + "\n", encoding="utf-8")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(render.main([str(target), "--out", str(out)]), 0)
        # Establish that later check failures are caused by the submitted value.
        self.assertEqual(findings.contract_problems(out), [])
        return out, target

    def record_with_address(self, address):
        doc = complete_doc()
        doc["findings"][0]["validation"]["evidence"] = address
        return doc

    def assert_safe_diagnostic(self, address, stdout, stderr):
        self.assertIn("findings[0].validation.evidence", stderr.getvalue())
        self.assertIn("contains an e-mail address", stderr.getvalue())
        messages = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn(address, messages)
        self.assertNotIn("Traceback", messages)

    def test_merge_refuses_literals_and_preserves_existing_outputs(self):
        for address in PRIVATE_ADDRESSES:
            with self.subTest(address=address), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                out, target = self.make_run(root)
                originals = {name: (out / name).read_bytes() for name in findings.OUTPUTS}
                validation = self.record_with_address(address)["findings"][0]["validation"]
                fragment = root / "fragment.json"
                fragment.write_text(json.dumps({"findings": [
                    {"id": "PV-001", "validation": validation}]}), encoding="utf-8")
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    code = findings.main(["merge", str(target), str(fragment)])
                self.assertEqual(code, 1)
                self.assertEqual({name: (out / name).read_bytes() for name in originals}, originals)
                self.assert_safe_diagnostic(address, stdout, stderr)

    def test_direct_render_refuses_literals_and_preserves_existing_outputs(self):
        for address in PRIVATE_ADDRESSES:
            with self.subTest(address=address), tempfile.TemporaryDirectory() as directory:
                out, target = self.make_run(Path(directory))
                target.write_text(json.dumps(self.record_with_address(address)), encoding="utf-8")
                originals = {name: (out / name).read_bytes() for name in findings.OUTPUTS}
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    code = render.main([str(target), "--out", str(out)])
                self.assertEqual(code, 2)
                self.assertEqual({name: (out / name).read_bytes() for name in originals}, originals)
                self.assert_safe_diagnostic(address, stdout, stderr)

    def test_check_refuses_literals_with_no_other_contract_violations(self):
        for address in PRIVATE_ADDRESSES:
            with self.subTest(address=address), tempfile.TemporaryDirectory() as directory:
                out, target = self.make_run(Path(directory))
                target.write_text(json.dumps(self.record_with_address(address)), encoding="utf-8")
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    code = findings.main(["check", str(out)])
                self.assertEqual(code, 1)
                problems = findings.contract_problems(out)
                self.assertEqual(len(problems), 1, problems)
                self.assertIn("findings[0].validation.evidence", problems[0])
                self.assertIn("contains an e-mail address", problems[0])
                self.assert_safe_diagnostic(address, stdout, stderr)

    def test_bracketed_domains_do_not_inherit_example_exemptions(self):
        for domain in ("example.com", "host.invalid"):
            with self.subTest(domain=domain), self.assertRaisesRegex(
                    findings.SchemaError, "contains an e-mail address"):
                findings.validate({"findings": [finding(title=f"synthetic@[{domain}]")]})

    def test_reserved_examples_and_non_email_ip_references_remain_allowed(self):
        allowed = (
            *(f"{local}@{domain}" for local in LOCAL_PARTS
              for domain in ("example.com", "host.invalid")),
            "192.0.2.1", "[192.0.2.1]", "2001:db8::1", "[IPv6:2001:db8::1]",
            "https://[2001:db8::1]/health",
        )
        for value in allowed:
            with self.subTest(value=value):
                findings.validate({"findings": [finding(title=value)]})


if __name__ == "__main__":
    unittest.main()
