import base64
import contextlib
import html
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
        "fix": "Restrict the public boundary", "regression": "Assert private access", "contrast": "none",
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
    def test_escaped_secret_keys_omit_json_and_yaml_excerpts(self):
        value = "synthetic-" + "escaped-field-value"
        for key, encoded in (("password", "pass\\u0077ord"),
                             ("api_key", "api\\u005fkey"),
                             ("credentials", "credential\\u0073")):
            for suffix in ("json", "yaml"):
                with self.subTest(key=key, suffix=suffix):
                    text = json.dumps({"settings": {key: value}, "publicly_accessible": True})
                    self.write("resource." + suffix, text.replace(key, encoded))
                    record = self.record("resource." + suffix + ":1")
                    self.assertEqual(render.attach_sources(record, self.repo), {})
                    for page in self.pages(record):
                        self.assertNotIn(value, page)

    def test_public_escapes_and_keylike_values_keep_original_source(self):
        value = "visible-configuration"
        variants = [
            json.dumps({"public_name": value}).replace("public_name", "public\\u005fname"),
            json.dumps({"pass\\u0077ord": value}),  # Decoding once leaves a literal backslash.
            json.dumps({"note": '"pass\\u0077ord": "' + value + '"'}),
        ]
        for suffix in ("json", "yaml"):
            for n, text in enumerate(variants):
                with self.subTest(suffix=suffix, text=text):
                    self.write("resource." + suffix, text)
                    rows = self.excerpt("resource." + suffix + ":1")
                    if n == 0:
                        self.assertEqual(rows, [(1, text, True)])
                    else:
                        # A key or prose spelling "pass…" is treated as a secret
                        # word by the final scrub; the line stays, its value goes.
                        self.assertEqual([(r[0], r[2]) for r in rows], [(1, True)])
                        self.assertNotIn(value, rows[0][1])

    def test_yaml_apostrophes_do_not_hide_escaped_secret_keys(self):
        value = "synthetic-" + "yaml-escaped-field"
        for before, after in (("# don't", "# don't"),
                              ("description: don't", "note: don't")):
            with self.subTest(before=before):
                self.write("resource.yaml", before + '\n"pass\\u0077ord": "' + value + '"\n' +
                           after + "\npublicly_accessible: true\n")
                record = self.record("resource.yaml:4")
                self.assertEqual(render.attach_sources(record, self.repo), {})
                for page in self.pages(record):
                    self.assertNotIn(value, page)

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


class StructuredSourceRedactionTest(OutputTest):
    POD = ("apiVersion: v1\nkind: Pod\nmetadata:\n  name: app\nspec:\n"
           "  containers:\n    - name: app\n      image: example/app:v1\n"
           "      securityContext:\n        privileged: true\n")

    def assert_source_omitted(self, record, value):
        self.assertEqual(render.attach_sources(record, self.repo), {})
        for page in self.pages(record):
            self.assertNotIn(value, page)
            self.assertNotIn('class="snippet"', page)

    def test_secret_env_stays_out_of_baseline_reports(self):
        value = "synthetic-" + "environment-value"
        self.write("pod.yaml", self.POD + "      env:\n        - name: DB_PASSWORD\n"
                   "          value: " + value + "\n")
        scan = iac_scan.run(self.repo)
        record = self.record("pod.yaml:10")
        record["findings"] = iac_scan.build_findings(scan.hits)
        self.assertEqual([(f["rule"], f["location"]) for f in record["findings"]],
                         [("K8S-001", "pod.yaml:10")])
        self.assertEqual(scan.not_run, [])
        self.assert_source_omitted(record, value)

    def test_yaml_env_order_flow_quotes_and_block_values(self):
        value = "synthetic-" + "environment-variants"
        variants = [
            "      env:\n        - value: " + value + "\n          name: DB_PASSWORD\n",
            '      "env": [{"value": "' + value + '", "name": "API_TOKEN"}]\n',
            '      "e\\u006ev":\n        - "n\\u0061me": DB_PASSWORD\n'
            '          "value": "' + value + '"\n',
            "      env:\n        - name: DB_PASSWORD\n          value: |-\n            " + value + "\n",
        ]
        for env in variants:
            with self.subTest(env=env):
                self.write("pod.yml", self.POD + env)
                self.assert_source_omitted(self.record("pod.yml:10"), value)

    def test_json_pod_lists_and_other_container_kinds_hide_secret_env(self):
        value = "synthetic-" + "json-environment"
        for container_key in ("containers", "initContainers", "ephemeralContainers"):
            for indent in (None, 2):
                with self.subTest(container_key=container_key, indent=indent):
                    pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "app"},
                           "spec": {container_key: [{"name": "app", "securityContext": {"privileged": True},
                                                     "env": [{"value": value, "name": "CLIENT_SECRET"}]}]}}
                    doc = {"apiVersion": "v1", "kind": "List", "items": [pod]}
                    self.write("pods.json", json.dumps(doc, indent=indent))
                    self.assert_source_omitted(self.record("pods.json:1"), value)

    def test_secret_in_later_yaml_document_prevents_neighboring_excerpts(self):
        value = "synthetic-" + "second-document"
        self.write("pods.yaml", self.POD + "--- # another workload\n" + self.POD +
                   "      env: [{name: DB_PASSWORD, value: " + value + "}]\n...\n")
        self.assert_source_omitted(self.record("pods.yaml:10"), value)

    def test_secret_manifest_is_omitted_without_a_baseline_secret_finding(self):
        value = "synthetic-" + "secret-object"
        for suffix, text in (
            ("yaml", "apiVersion: v1\nkind: Secret\nmetadata: {name: app}\nstringData:\n  config: " + value),
            ("json", json.dumps({"kind": "Secret", "data": {"config": value}})),
        ):
            with self.subTest(suffix=suffix):
                self.write("resource." + suffix, text)
                self.assert_source_omitted(self.record("resource." + suffix + ":1"), value)

    def test_typed_secret_list_with_kindless_items_has_no_excerpt(self):
        value = "synthetic-" + "typed-secret-list"
        doc = {"apiVersion": "v1", "kind": "SecretList", "items": [
            {"metadata": {"name": "app"}, "stringData": {"config": value}}]}
        texts = [("json", json.dumps(doc, indent=indent)) for indent in (None, 2)]
        texts.append(("yaml", "apiVersion: v1\nkind: SecretList\nitems:\n"
                      "  - metadata: {name: app}\n    data: {config: " + value + "}\n"))
        for suffix, text in texts:
            with self.subTest(suffix=suffix, text=text):
                self.write("resource." + suffix, text)
                self.assert_source_omitted(self.record("resource." + suffix + ":1"), value)

    def test_env_dictionary_checks_decoded_secret_names(self):
        for value in ("synthetic-" + "escaped-env", "var.bootstrap_value"):
            for suffix in ("json", "yaml"):
                with self.subTest(value=value, suffix=suffix):
                    text = json.dumps({"env": {"DB_PASSWORD": value}, "privileged": True})
                    text = text.replace("DB_PASSWORD", "DB_PASS\\u0057ORD")
                    self.write("resource." + suffix, text)
                    self.assert_source_omitted(self.record("resource." + suffix + ":1"), value)

    def test_public_env_dictionary_keeps_its_excerpt(self):
        for suffix in ("json", "yaml"):
            with self.subTest(suffix=suffix):
                text = json.dumps({"env": {"LOG_LEVEL": "visible-configuration"}, "privileged": True})
                self.write("resource." + suffix, text.replace("LOG_LEVEL", "LOG\\u005fLEVEL"))
                record = self.record("resource." + suffix + ":1")
                self.assertIn("F-001", render.attach_sources(record, self.repo))
                for page in self.pages(record):
                    self.assertIn("visible-configuration", page)
                    self.assertIn('class="snippet"', page)

    def test_sensitive_plan_output_stays_out_of_baseline_reports(self):
        value = "synthetic-" + "sensitive-output"
        plan = {"format_version": "1.2", "terraform_version": "1.9.0", "planned_values": {
            "outputs": {"bootstrap": {"sensitive": True, "type": "string", "value": value}},
            "root_module": {"resources": [{"address": "aws_ebs_volume.data", "mode": "managed",
                                           "type": "aws_ebs_volume", "name": "data",
                                           "values": {"availability_zone": "us-east-1a", "encrypted": False}}]},
        }}
        for indent in (None, 2):
            with self.subTest(indent=indent):
                self.write("plan.json", json.dumps(plan, indent=indent))
                scan = iac_scan.run(self.repo)
                record = self.record("plan.json:1")
                record["findings"] = iac_scan.build_findings(scan.hits)
                self.assertEqual([f["rule"] for f in record["findings"]], ["AWS-EBS-001"])
                self.assertEqual(scan.not_run, [])
                self.assert_source_omitted(record, value)

    def test_nested_plan_sensitivity_masks_hide_original_source(self):
        value = "synthetic-" + "masked-property"
        for mask_name in ("sensitive_values", "before_sensitive", "after_sensitive"):
            with self.subTest(mask_name=mask_name):
                self.write("plan.json", json.dumps({
                    "values": {"settings": [{"public": "visible"}, {"bootstrap": value}]},
                    mask_name: {"settings": [{"public": False}, {"bootstrap": True}]},
                }, indent=2))
                self.assert_source_omitted(self.record("plan.json:4"), value)

    def test_unsupported_yaml_and_invalid_json_never_use_raw_source(self):
        value = "synthetic-" + "ambiguous-structure"
        cases = [
            ("yaml", self.POD + "      env: !Custom " + value),
            ("yml", "defaults: &shared [{name: DB_PASSWORD, value: " + value + "}]\n" +
             self.POD + "      env: *shared\n"),
            ("yaml", self.POD + "      env:\n        - name: DB_PASSWORD\n          name: LOG_LEVEL\n"
             "          value: " + value),
            ("json", '{"env": [{"name": "DB_PASSWORD", "value": "' + value + '"}],'),
            ("json", '{"sensitive": true, "sensitive": false, "value": "' + value + '"}'),
        ]
        for suffix, text in cases:
            with self.subTest(suffix=suffix, text=text):
                self.write("resource." + suffix, text)
                self.assert_source_omitted(self.record("resource." + suffix + ":1"), value)

    def test_opaque_env_names_and_malformed_sensitive_masks_are_omitted(self):
        value = "synthetic-" + "opaque-structure"
        documents = [
            {"env": [{"value": value}]},
            {"env": [{"name": None, "value": value}]},
            {"env": value},
            {"sensitive": None, "value": value},
            {"sensitive_values": {"bootstrap": "unknown"}, "values": {"bootstrap": value}},
        ]
        for doc in documents:
            with self.subTest(doc=doc):
                self.write("resource.json", json.dumps(doc))
                self.assert_source_omitted(self.record("resource.json:1"), value)

    def test_public_env_and_secret_references_keep_original_source_lines(self):
        variants = [
            "      env:\n        - name: LOG_LEVEL\n          value: info\n",
            "      env:\n        - name: DB_PASSWORD\n          valueFrom:\n"
            "            secretKeyRef: {name: database, key: password}\n",
        ]
        for env in variants:
            with self.subTest(env=env):
                self.write("pod.yaml", self.POD + env)
                rows = self.excerpt("pod.yaml:10")
                self.assertEqual([(n, text) for n, text, hit in rows if hit],
                                 [(10, "        privileged: true")])
                self.assertIn("      env:", [text for _, text, _ in rows])

    def test_false_and_empty_sensitivity_masks_keep_public_json_excerpts(self):
        doc = {"sensitive": False, "value": "visible-configuration",
               "environment": "production",
               "sensitive_values": {"settings": [False, {}, []],
                                    "env": [{"name": False, "value": False}]},
               "before_sensitive": {}, "after_sensitive": []}
        self.write("plan.json", json.dumps(doc, indent=2))
        rows = self.excerpt("plan.json:3")
        self.assertEqual([n for n, _, hit in rows if hit], [3])
        self.assertIn("visible-configuration", "\n".join(text for _, text, _ in rows))


class CloudFormationSourceRedactionTest(OutputTest):
    @staticmethod
    def template(no_echo, value, default_first):
        fields = [("NoEcho", no_echo), ("Default", value)]
        if default_first:
            fields.reverse()
        return {"AWSTemplateFormatVersion": "2010-09-09",
                "Parameters": {"Bootstrap": {"Type": "String", **dict(fields)}},
                "Resources": {"Database": {"Type": "AWS::RDS::DBInstance", "Properties": {
                    "DBInstanceClass": "db.t3.micro", "Engine": "postgres", "AllocatedStorage": "20",
                    "PubliclyAccessible": True, "StorageEncrypted": True, "MasterUsername": "dbadmin",
                    "MasterUserPassword": {"Ref": "Bootstrap"},
                }}}}

    @staticmethod
    def yaml_text(template, flow):
        if flow:
            return json.dumps(template)  # JSON flow syntax is also valid YAML.
        return ('AWSTemplateFormatVersion: "2010-09-09"\nParameters:\n  Bootstrap:\n' +
                "".join(f"    {key}: {json.dumps(value)}\n"
                        for key, value in template["Parameters"]["Bootstrap"].items()) +
                "Resources: " + json.dumps(template["Resources"]) + "\n")

    def assert_source_omitted(self, record, value):
        self.assertEqual(render.attach_sources(record, self.repo), {})
        for page in self.pages(record):
            self.assertNotIn(value, page)
            self.assertNotIn('class="snippet"', page)

    def test_escaped_password_property_stays_out_of_baseline_reports(self):
        value = "synthetic-" + "escaped-database-password"
        template = self.template(False, "public-configuration", default_first=False)
        template["Resources"]["Database"]["Properties"]["MasterUserPassword"] = value
        for indent in (None, 2):
            with self.subTest(indent=indent):
                text = json.dumps(template, indent=indent).replace("MasterUserPassword", "MasterUserPass\\u0077ord")
                self.write("template.json", text)
                scan = iac_scan.run(self.repo)
                record = self.record("template.json:1")
                record["findings"] = iac_scan.build_findings(scan.hits)
                self.assertEqual([f["rule"] for f in record["findings"]], ["AWS-RDS-001"])
                self.assertEqual(scan.not_run, [])
                self.assertNotIn(value, json.dumps(iac_scan.report(scan, self.repo, "", record["findings"])))
                self.assert_source_omitted(record, value)

    def test_noecho_defaults_stay_out_of_baseline_reports(self):
        value = "synthetic-" + "noecho-default"
        for no_echo in (True, "true", "TRUE"):
            for default_first in (False, True):
                for indent in (None, 2):
                    with self.subTest(no_echo=no_echo, default_first=default_first, indent=indent):
                        template = self.template(no_echo, value, default_first)
                        self.write("template.json", json.dumps(template, indent=indent))
                        scan = iac_scan.run(self.repo)
                        record = self.record("template.json:1")
                        record["findings"] = iac_scan.build_findings(scan.hits)
                        self.assertEqual([f["rule"] for f in record["findings"]], ["AWS-RDS-001"])
                        self.assertEqual(scan.not_run, [])
                        self.assert_source_omitted(record, value)

    def test_noecho_defaults_stay_out_of_yaml_excerpts(self):
        value = "synthetic-" + "noecho-yaml-default"
        for no_echo in (True, "true", "TRUE"):
            for default_first in (False, True):
                for flow in (False, True):
                    with self.subTest(no_echo=no_echo, default_first=default_first, flow=flow):
                        text = self.yaml_text(self.template(no_echo, value, default_first), flow)
                        self.write("template.yaml", text)
                        # CloudFormation YAML baseline rules are not supported;
                        # a reviewed finding points at the neighboring resource.
                        line = next(n for n, row in enumerate(text.splitlines(), 1) if "Resources" in row)
                        self.assert_source_omitted(self.record(f"template.yaml:{line}"), value)

    def test_noecho_block_strings_omit_source_lines_and_html(self):
        value = "synthetic-" + "noecho-block-default"
        for style in ("|-", ">-"):
            for default_first in (False, True):
                with self.subTest(style=style, default_first=default_first):
                    text = self.yaml_text(self.template(True, value, default_first), flow=False)
                    text = text.replace("    NoEcho: true\n", f"    NoEcho: {style}\n      true\n")
                    self.write("template.yaml", text)
                    self.assertIsNone(render.source_lines(self.repo / "template.yaml"))
                    line = next(n for n, row in enumerate(text.splitlines(), 1) if "Resources" in row)
                    self.assert_source_omitted(self.record(f"template.yaml:{line}"), value)

    def test_ambiguous_noecho_values_omit_source_lines_and_html(self):
        value = "synthetic-" + "noecho-ambiguous-default"
        for no_echo in (None, 0, "", {"Ref": "DisplayMode"}):
            with self.subTest(no_echo=no_echo):
                self.write("template.json", json.dumps(self.template(no_echo, value, default_first=True)))
                self.assertIsNone(render.source_lines(self.repo / "template.json"))
                self.assert_source_omitted(self.record("template.json:1"), value)

    def test_default_referenced_by_a_secret_property_is_omitted(self):
        value = "synthetic-" + "referenced-default"
        for no_echo in (False, "false"):
            template = self.template(no_echo, value, False)
            self.write("template.json", json.dumps(template, indent=2))
            line = next(n for n, row in enumerate(json.dumps(template, indent=2).splitlines(), 1) if value in row)
            self.assert_source_omitted(self.record(f"template.json:{line}"), value)

    def test_false_noecho_keeps_public_json_and_yaml_excerpts(self):
        value = "visible-configuration"
        for no_echo in (False, "false", "FALSE"):
            for default_first in (False, True):
                template = self.template(no_echo, value, default_first)
                # A default feeding MasterUserPassword is a password whatever NoEcho
                # says (test_default_referenced_by_a_secret_property_is_omitted).
                props = template["Resources"]["Database"]["Properties"]
                props["DBName"] = props.pop("MasterUserPassword")
                variants = [("json", json.dumps(template, indent=indent)) for indent in (None, 2)]
                variants += [("yaml", self.yaml_text(template, flow)) for flow in (False, True)]
                for suffix, text in variants:
                    with self.subTest(no_echo=no_echo, default_first=default_first, suffix=suffix, text=text):
                        filename = "template." + suffix
                        self.write(filename, text)
                        line = next(n for n, row in enumerate(text.splitlines(), 1) if value in row)
                        record = self.record(f"{filename}:{line}")
                        self.assertIn("F-001", render.attach_sources(record, self.repo))
                        for page in self.pages(record):
                            self.assertIn(value, page)
                            self.assertIn('class="snippet"', page)


class ModuleRedactionTest(OutputTest):
    def test_apostrophe_userinfo_stays_out_of_all_module_outputs_and_excerpts(self):
        credentials = [("synthetic'" + "username", "synthetic-" + "password"),
                       ("synthetic-" + "username", "synthetic'" + "password")]
        for username, password in credentials:
            with self.subTest(username=username, password=password):
                source = f"git::https://{username}:{password}@git.example.invalid/config.git?ref=main"
                self.write("main.tf", f'module "example" {{\n  source = "{source}"\n}}\n')
                scan = iac_scan.run(self.repo)
                record = self.record("main.tf:2")
                record["findings"] = iac_scan.build_findings(scan.hits)
                self.assertEqual([f["rule"] for f in record["findings"]], ["PS-001"])
                outputs = [json.dumps(iac_scan.report(scan, self.repo, "", record["findings"]))]
                outputs += [html.unescape(page) for page in self.pages(record)]
                for output in outputs:
                    self.assertNotIn(username, output)
                    self.assertNotIn(password, output)
                    self.assertIn("git.example.invalid/config.git?ref=main", output)

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
