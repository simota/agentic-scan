import base64
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from urllib.parse import quote

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-scan" / "scripts"))
import iac_scan  # noqa: E402
import redaction  # noqa: E402
import render  # noqa: E402


def finding(location):
    return {
        "id": "F-001", "title": "Public configuration needs review", "severity": "Medium",
        "confidence": "Suspected", "category": "Network exposure", "provider": "multi",
        "resources": ["example.main"], "location": location, "actor": "External actor",
        "path": f"1. Public configuration ({location})", "impact": "A private boundary is expected",
        "fix": "Restrict the public boundary", "regression": "Assert private access",
        "validation": {"verdict": "Likely"},
    }


class OutputTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def record(self, location):
        record = render.empty_record()
        record["meta"] = {"project": "test", "scope": "local fixtures", "date": "2026-10-08",
                          "assessor": "unit test"}
        record["findings"] = [finding(location)]
        return record

    def pages(self, record):
        source = self.root / "findings.json"
        source.write_text(json.dumps(record), encoding="utf-8")
        out = self.root / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            code = render.main([str(source), "--out", str(out), "--repo", str(self.repo), "--no-pdf"])
        self.assertEqual(code, 0)
        return [(out / name).read_text(encoding="utf-8") for name in ("dashboard.html", "assessment.html")]

    def excerpt(self, location):
        return render.attach_sources(self.record(location), self.repo)["F-001"]


class SourceRedactionTest(OutputTest):
    def test_kubernetes_secret_values_are_not_exposed_by_neighboring_findings(self):
        plaintext = "synthetic-" + "configuration-value"
        for field, value in (("data", base64.b64encode(plaintext.encode()).decode()),
                             ("stringData", plaintext)):
            with self.subTest(field=field):
                self.write("resources.yaml", "apiVersion: v1\nkind: Secret\nmetadata:\n"
                           "  name: application\n" + field + ":\n  config: " + value + "\n")
                baseline = iac_scan.build_findings(iac_scan.run(self.repo).hits)
                self.assertTrue(any(f["rule"] == "K8S-003" for f in baseline))
                record = self.record("resources.yaml:6")
                record["findings"] += baseline
                self.assertEqual(render.attach_sources(record, self.repo), {})
                for page in self.pages(record):
                    self.assertNotIn(value, page)
                    self.assertNotIn(plaintext, page)

    def test_service_account_key_stays_out_of_scan_and_other_finding_excerpts(self):
        body = "synthetic-" + "private-material-for-test"
        key = "-----BEGIN " + "PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n"
        self.write("project-12345.json", json.dumps({
            "type": "service_account", "project_id": "demo", "private_key": key,
            "publicly_accessible": True,
        }, indent=2))
        scan = iac_scan.run(self.repo)
        baseline = iac_scan.build_findings(scan.hits)
        self.assertTrue(any(f["rule"] == "SEC-001" for f in baseline))
        record = self.record("project-12345.json:5")
        record["findings"] += baseline
        sources = render.attach_sources(record, self.repo)
        self.assertIn("F-001", sources)
        self.assertTrue(all(f["id"] not in sources for f in baseline if f["rule"] == "SEC-001"))
        outputs = self.pages(record) + [json.dumps(iac_scan.report(scan, self.repo, "", baseline)),
                                       json.dumps(record)]
        for output in outputs:
            self.assertNotIn(body, output)
        for page in outputs[:2]:
            self.assertIn("publicly_accessible", page)

    def test_quoted_json_keys_are_redacted_in_context(self):
        values = ["synthetic-" + name for name in ("db-password", "api-value", "connection-value")]
        self.write("plan.json", json.dumps({
            "password": values[0], "apiKey": values[1], "connection_string": values[2],
            "publicly_accessible": True,
        }, indent=2))
        for page in self.pages(self.record("plan.json:5")):
            for value in values:
                self.assertNotIn(value, page)
            self.assertIn("publicly_accessible", page)

    def test_qualified_secret_keys_are_redacted_in_context(self):
        value = "synthetic-" + "annotation-value"
        for key, scalar in (("example.com/password", value),
                            ('"example.com/token"', value),
                            ("example.com/password", "|-\n      " + value)):
            with self.subTest(key=key, scalar=scalar):
                self.write("manifest.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n"
                           "  name: example\n  annotations:\n    " + key + ": " + scalar +
                           '\ndata:\n  publicly_accessible: "true"\n')
                for page in self.pages(self.record("manifest.yaml:7")):
                    self.assertNotIn(value, page)
                    self.assertIn("publicly_accessible", page)

    def test_pem_start_before_excerpt_still_hides_every_body_line(self):
        body = ["synthetic-pem-" + str(n) for n in range(12)]
        self.write("main.tf", "\n".join([
            "config = <<EOT", "-----BEGIN " + "RSA PRIVATE KEY-----", *body,
            "-----END RSA PRIVATE KEY-----", "EOT", "publicly_accessible = true",
        ]))
        rows = self.excerpt("main.tf:10")
        self.assertEqual([n for n, _, hit in rows if hit], [10])
        text = "\n".join(t for _, t, _ in rows)
        for value in body:
            self.assertNotIn(value, text)
        self.assertIn("publicly_accessible = true", "\n".join(t for _, t, _ in self.excerpt("main.tf:17")))

    def test_secret_heredoc_start_before_excerpt_hides_values_until_terminator(self):
        body = ["synthetic-heredoc-" + str(n) for n in range(12)]
        self.write("main.tf", "\n".join([
            'resource "aws_db_instance" "main" {', "  password = <<-VALUE", *body,
            "  VALUE", "  publicly_accessible = true", "}",
        ]))
        for location in ("main.tf:10", "main.tf:16"):
            text = "\n".join(t for _, t, _ in self.excerpt(location))
            for value in body:
                self.assertNotIn(value, text)
        self.assertIn("publicly_accessible = true", text)

    def test_yaml_secret_block_keeps_subsequent_configuration(self):
        body = ["  synthetic-yaml-" + str(n) for n in range(12)]
        self.write("manifest.yaml", "\n".join(["password: |-", *body, "publicly_accessible: true"]))
        for location in ("manifest.yaml:9", "manifest.yaml:14"):
            text = "\n".join(t for _, t, _ in self.excerpt(location))
            self.assertNotIn("synthetic-yaml-", text)
        self.assertIn("publicly_accessible: true", text)

    def test_multiline_json_values_and_sensitive_objects_are_hidden(self):
        first, second = "synthetic-" + "scalar-value", "synthetic-" + "nested-value"
        self.write("plan.json", '{\n"password":\n"' + first + '",\n"credentials": {\n'
                   '"arbitrary": "' + second + '"\n},\n"publicly_accessible": true\n}\n')
        for page in self.pages(self.record("plan.json:4")):
            self.assertNotIn(first, page)
            self.assertNotIn(second, page)

    def test_blank_lines_before_json_secret_value_keep_redaction_pending(self):
        value = "synthetic-" + "delayed-value"
        for whitespace in ("\n", "  \n\t\n"):
            with self.subTest(whitespace=whitespace):
                self.write("plan.json", '{\n  "password":\n' + whitespace +
                           '  "' + value + '",\n  "publicly_accessible": true\n}\n')
                for page in self.pages(self.record("plan.json:5")):
                    self.assertNotIn(value, page)
                    self.assertIn("publicly_accessible", page)

    def test_reference_prefix_does_not_exempt_an_entire_expression(self):
        value = "synthetic-" + "literal-value"
        self.assertEqual(redaction.redact("password = var.db_password"), "password = var.db_password")
        self.assertNotIn(value, redaction.redact('password = var.db_password + "' + value + '"'))


class ModuleRedactionTest(OutputTest):
    def test_credentials_stay_out_of_all_module_outputs_and_excerpts(self):
        username = "synthetic-" + "username"
        password = "synthetic-" + "password"
        token = "ghp_" + "a" * 36
        signature = "synthetic-" + "signed-query"
        sources = [
            f"git::https://{username}:{password}@git.example.invalid/config.git?ref=main&access_token={token}",
            f"git::https://{token}@git.example.invalid/config.git?ref=v1.2.3",
            f"https://example.invalid/config.zip?X-Amz-Signature={signature}&X-Amz-Security-Token={token}",
        ]
        for n, source in enumerate(sources):
            self.write(f"module{n}.tf", f'module "m{n}" {{\n  source = "{source}"\n}}\n')
        scan = iac_scan.run(self.repo)
        baseline = iac_scan.build_findings(scan.hits)
        self.assertTrue(any(h["rule"] == "PS-001" and h["file"] == "module0.tf" for h in scan.hits))
        self.assertFalse(any(h["rule"] == "PS-001" and h["file"] == "module1.tf" for h in scan.hits))
        record_path = self.root / "merged.json"
        iac_scan.merge_into(record_path, baseline, iac_scan.inventory_of(scan), "")
        outputs = []
        for n in range(len(sources)):
            record = self.record(f"module{n}.tf:2")
            record["findings"] += baseline
            outputs += self.pages(record)
        outputs += [json.dumps(iac_scan.report(scan, self.repo, "", baseline)),
                    record_path.read_text(encoding="utf-8")]
        for output in outputs:
            for value in (username, password, token, signature):
                self.assertNotIn(value, output)
            self.assertIn("git.example.invalid/config.git?ref=main", output)
        safe = scan.modules[0]["source"]
        self.assertTrue(safe.startswith("git::https://[redacted]@"))
        self.assertIn("access_token=[redacted]", safe)

    def test_encoded_credentials_and_unknown_query_values_are_redacted(self):
        value = "synthetic-" + "value with spaces"
        encoded = quote(value)
        source = f"git::https://user:{encoded}@git.example.invalid/r.git?access%5Ftoken={encoded}&ref=v1&depth=1"
        safe = redaction.module_source(source)
        self.assertNotIn(encoded, safe)
        self.assertNotIn(value, safe)
        self.assertIn("access%5Ftoken=[redacted]&ref=v1&depth=1", safe)
        self.assertNotIn(encoded, redaction.module_source(f"https://example.invalid/r?custom_auth={encoded}"))
        token = "ghp_" + "b" * 36
        encoded_token = "".join(f"%{ord(c):02x}" for c in token)
        self.assertNotIn(encoded_token, redaction.module_source(f"https://example.invalid/r.git?ref={encoded_token}"))

    def test_nonsecret_addresses_and_revision_options_are_preserved(self):
        for source in ("./module", "../module", "hashicorp/vpc/aws",
                       "git::https://git.example.invalid/config.git//module?ref=v1.2.3&depth=1",
                       "git::https://git.example.invalid/config.git//token=value?ref=v1&depth=1"):
            with self.subTest(source=source):
                self.assertEqual(redaction.module_source(source), source)
                self.assertEqual(redaction.redact('source = "' + source + '"'),
                                 'source = "' + source + '"')

    def test_malformed_authority_never_falls_back_to_raw_credentials(self):
        value = "synthetic-" + "password"
        for source in (f"git::https://user:{value}@[invalid/repo.git", f"https:user:{value}@host/repo"):
            self.assertNotIn(value, redaction.module_source(source))

    def test_scp_username_and_url_fragment_are_redacted(self):
        value = "synthetic-" + "credential"
        self.assertEqual(redaction.module_source(f"git::{value}@git.example.invalid:team/repo.git?ref=v1"),
                         "git::[redacted]@git.example.invalid:team/repo.git?ref=v1")
        self.assertNotIn(value, redaction.module_source(f"https://example.invalid/repo.git#{value}"))


if __name__ == "__main__":
    unittest.main()
