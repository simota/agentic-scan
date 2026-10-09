"""Keep email candidate scanning bounded without changing quoted-address rules."""
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest

from test_privacy_scan import findings


class EmailCandidateScanningTests(unittest.TestCase):
    def test_quoted_candidates_keep_internal_at_signs_out_of_domain_scanning(self):
        cases = (
            ('"synthetic@privacy-scan.localhost"@example.com', ["example.com"]),
            ('email="synthetic user"@privacy-scan.localhost', ["privacy-scan.localhost"]),
            ('"synthetic@privacy-scan.localhost"suffix@example.com',
             ["privacy-scan.localhost", "example.com"]),
            ('"synthetic@privacy-scan.localhost\nbroken"@example.com',
             ["privacy-scan.localhost"]),
            ('"synthetic\\\"@privacy-scan.localhost"@example.com', ["example.com"]),
            ('"synthetic@[192.0.2.1]"@example.com', ["example.com"]),
            ('synthetic@example.com@privacy-scan.localhost',
             ["example.com", "privacy-scan.localhost"]),
            ("@privacy-scan.localhost", []),
        )
        for value, domains in cases:
            with self.subTest(value=value):
                self.assertEqual(list(findings._email_domains(value)), domains)

    def test_large_public_fields_finish_with_mixed_candidate_shapes(self):
        # A generous process deadline catches repeated suffix rescans while
        # leaving ample headroom for slower CI machines. Each field is valid
        # report prose, and an example address defeats an '@' absence shortcut.
        script = textwrap.dedent(r'''
            import sys
            sys.path.insert(0, sys.argv[1])
            from test_privacy_scan import finding, findings

            sentence = "解析した経路では送信先までの各処理を確認し、制御の適用条件と静的解析の限界を記録した。"
            values = (
                sentence * 4096,
                sentence * 4096 + " user@example.com",
                "a" * 200000 + " user@example.com",
                'a\\"' * 65536 + " user@example.com",
                '"a@b"' * 32768 + " user@example.com",
                "a@" * 65536 + "example.com",
                '"' + "synthetic@privacy-scan.localhost," * 4096 + '"@example.com',
            )
            for value in values:
                findings.validate({"limitations": [value]})
                findings.validate({"findings": [finding(analysis={
                    "tool": "source-scan", "command": "source-scan api/app.py", "result": value,
                })]})
            try:
                findings.validate({"limitations": [
                    sentence * 4096 + " synthetic@privacy-scan.localhost",
                ]})
            except findings.SchemaError:
                pass
            else:
                raise AssertionError("a private-domain address after long prose was missed")
        ''')
        try:
            result = subprocess.run(
                [sys.executable, "-B", "-c", script, str(Path(__file__).resolve().parent)],
                capture_output=True, text=True, timeout=10,
            )
        except subprocess.TimeoutExpired:
            raise self.failureException(
                "email candidate scanning did not finish within the 10-second deadline"
            ) from None
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
