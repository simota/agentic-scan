"""IMDSv1 hypotheses require an endpoint that is not disabled or unknown."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "infra-scan" / "scripts"))
import iac_scan  # noqa: E402


class ImdsEndpointTest(unittest.TestCase):
    def scan(self, text, suffix="tf"):
        with tempfile.TemporaryDirectory(prefix="iac-imds-") as tmp:
            (Path(tmp) / f"main.{suffix}").write_text(text, encoding="utf-8")
            return iac_scan.run(tmp)

    def hcl(self, type_, endpoint, tokens='"optional"'):
        return self.scan(f'''resource "{type_}" "app" {{
  metadata_options {{
    http_endpoint = {endpoint}
    http_tokens = {tokens}
  }}
}}
''')

    def test_disabled_endpoint_never_reports_imdsv1(self):
        for type_ in ("aws_instance", "aws_launch_template"):
            for tokens in ('"optional"', "null", "var.tokens"):
                with self.subTest(type_=type_, tokens=tokens):
                    scan = self.hcl(type_, '"disabled"', tokens)
                    self.assertEqual(scan.hits, [])
                    self.assertEqual(scan.not_run, [])

    def test_unknown_endpoint_does_not_establish_imdsv1(self):
        for type_ in ("aws_instance", "aws_launch_template"):
            with self.subTest(type_=type_):
                scan = self.hcl(type_, "var.endpoint")
                self.assertEqual(scan.hits, [])
                self.assertTrue(any("AWS-EC2-001" in note and "unknown metadata endpoint" in note
                                    and "main.tf:3" in note for note in scan.not_run))

    def test_required_tokens_bound_an_unknown_endpoint(self):
        scan = self.hcl("aws_instance", "var.endpoint", '"required"')
        self.assertEqual(scan.hits, [])
        self.assertEqual(scan.not_run, [])

    def test_enabled_optional_tokens_keep_the_finding(self):
        for type_ in ("aws_instance", "aws_launch_template"):
            with self.subTest(type_=type_):
                scan = self.hcl(type_, '"enabled"')
                self.assertEqual([h["rule"] for h in scan.hits], ["AWS-EC2-001"])
                self.assertEqual(scan.not_run, [])

    def test_plan_endpoint_enablement_is_checked_after_restoring_unknowns(self):
        for type_ in ("aws_instance", "aws_launch_template"):
            for endpoint, unknown in (("disabled", False), (None, True)):
                with self.subTest(type_=type_, endpoint=endpoint, unknown=unknown):
                    address = f"{type_}.app"
                    plan = {"planned_values": {"root_module": {"resources": [{
                        "address": address, "mode": "managed", "type": type_,
                        "values": {"metadata_options": [{"http_endpoint": endpoint,
                                                          "http_tokens": "optional"}]},
                    }]}}, "resource_changes": [{"address": address, "change": {
                        "after_unknown": {"metadata_options": [{"http_endpoint": unknown}]},
                    }}]}
                    scan = self.scan(json.dumps(plan), "json")
                    self.assertEqual(scan.hits, [])
                    if unknown:
                        self.assertTrue(any("unknown metadata endpoint" in note for note in scan.not_run))
                    else:
                        self.assertEqual(scan.not_run, [])


if __name__ == "__main__":
    unittest.main()
