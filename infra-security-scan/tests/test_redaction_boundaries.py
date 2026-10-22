import contextlib
import html
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-scan" / "scripts"))
import iac_scan  # noqa: E402
import render  # noqa: E402


class RedactionBoundaryTest(unittest.TestCase):
    EBS = ('resource "aws_ebs_volume" "main" {\n'
           '  availability_zone = "us-east-1a"\n  encrypted = false\n}\n')
    POD = ('{apiVersion: v1, kind: Pod, metadata: {name: app}, '
           'spec: {containers: [{name: app, image: example/app:v1, '
           'securityContext: {privileged: true}}]}}')

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
        path.write_bytes(text.encode("utf-8"))
        return path

    def record(self, location=None):
        record = render.empty_record()
        record["meta"] = {"project": "test", "scope": "local fixtures", "date": "2026-10-08",
                          "assessor": "unit test"}
        if location:
            record["findings"] = [{
                "id": "F-001", "title": "Configuration boundary needs review", "severity": "Medium",
                "confidence": "Suspected", "category": "Network exposure", "provider": "multi",
                "resources": ["example.main"], "location": location, "actor": "External actor",
                "path": "1. Review the configuration boundary", "impact": "A private boundary is expected",
                "fix": "Restrict the boundary", "regression": "Assert private access", "contrast": "none",
                "validation": {"verdict": "Likely"},
            }]
        else:
            record["findings"] = iac_scan.build_findings(iac_scan.run(self.repo).hits)
            self.assertTrue(record["findings"])
        return record

    def pages(self, record):
        path = self.root / "findings.json"
        path.write_text(json.dumps(record), encoding="utf-8")
        out = self.root / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            code = render.main([str(path), "--out", str(out), "--repo", str(self.repo), "--no-pdf"])
        self.assertEqual(code, 0)
        return [html.unescape((out / name).read_text(encoding="utf-8"))
                for name in ("dashboard.html", "assessment.html")]

    def assert_hidden(self, record, *values, omitted=False):
        if omitted:
            self.assertEqual(render.attach_sources(record, self.repo), {})
        pages = self.pages(record)
        for page in pages:
            for value in values:
                self.assertNotIn(value, page)
            if omitted:
                self.assertNotIn('class="snippet"', page)
        return pages

    def test_sensitive_hcl_variable_and_output_omit_neighboring_baseline_excerpts(self):
        value = "synthetic-" + "sensitive-hcl-value"
        for kind, field in (("variable", "default"), ("output", "value")):
            for first in (True, False):
                with self.subTest(kind=kind, value_first=first):
                    attrs = [f'  {field} = "{value}"', '  sensitive = true']
                    if not first:
                        attrs.reverse()
                    path = self.write("main.tf", f'{kind} "bootstrap" {{\n' + "\n".join(attrs) + "\n}\n" + self.EBS)
                    record = self.record()
                    self.assertEqual([f["rule"] for f in record["findings"]], ["AWS-EBS-001"])
                    self.assertIsNone(render.source_lines(path))
                    # Keep the value in range even if a baseline's property
                    # location moves farther from the neighboring declaration.
                    record["findings"] += self.record("main.tf:2-3")["findings"]
                    self.assert_hidden(record, value, omitted=True)

    def test_bom_sensitive_hcl_omits_neighboring_baseline_excerpts(self):
        value = "synthetic-" + "bom-sensitive-value"
        for kind, field in (("variable", "default"), ("output", "value")):
            with self.subTest(kind=kind):
                text = (f'{kind} "bootstrap" {{\n  sensitive = true\n  {field} = "{value}"\n}}\n'
                        'resource "aws_ebs_volume" "main" {\n  encrypted = false\n'
                        '  availability_zone = "us-east-1a"\n}\n')
                path = self.write("main.tf", "\ufeff" + text)
                record = self.record()
                self.assertEqual([f["rule"] for f in record["findings"]], ["AWS-EBS-001"])
                self.assert_hidden(record, value, omitted=True)
                self.assertIsNone(render.source_lines(path))

    def test_bom_sibling_and_override_sensitivity_omit_public_file_excerpts(self):
        value = "synthetic-" + "bom-module-value"
        self.write("main.tf", f'variable "bootstrap" {{\n  default = "{value}"\n}}\n' + self.EBS)
        declarations = {
            "outputs.tf": 'output "private_export" {\n  sensitive = true\n  value = var.bootstrap\n}\n',
            "override.tf": 'variable "bootstrap" {\n  sensitive = true\n}\n',
        }
        for name, declaration in declarations.items():
            with self.subTest(sibling=name):
                sibling = self.write(name, "\ufeff" + declaration)
                try:
                    record = self.record("main.tf:2")
                    record["findings"] += self.record()["findings"]
                    self.assert_hidden(record, value, omitted=True)
                finally:
                    sibling.unlink()

    def test_unknown_hcl_sensitivity_is_conservative(self):
        value = "synthetic-" + "unknown-sensitivity-value"
        for flag in ('var.visibility', 'null', '"false"', '(false)'):
            with self.subTest(flag=flag):
                self.write("main.tf", 'output "bootstrap" {\n  value = "' + value +
                           '"\n  sensitive = ' + flag + '\n}\n' + self.EBS)
                self.assert_hidden(self.record(), value, omitted=True)

    def test_override_sensitivity_covers_values_in_either_source_file(self):
        value = "synthetic-" + "override-sensitive-value"
        for kind, field in (("variable", "default"), ("output", "value")):
            for sensitive_in_override in (True, False):
                with self.subTest(kind=kind, sensitive_in_override=sensitive_in_override):
                    declarations = [f'{kind} "bootstrap" {{\n  {field} = "{value}"\n}}\n',
                                    f'{kind} "bootstrap" {{\n  sensitive = true\n}}\n']
                    if not sensitive_in_override:
                        declarations.reverse()
                    self.write("main.tf", declarations[0])
                    self.write("override.tf", declarations[1])
                    self.write("resources.tf", self.EBS)
                    source = "main.tf" if sensitive_in_override else "override.tf"
                    record = self.record(source + ":2")
                    record["findings"] += self.record()["findings"]
                    self.assert_hidden(record, value, omitted=True)

    def test_unknown_hcl_sibling_context_omits_excerpts(self):
        value = "synthetic-" + "unknown-module-value"
        self.write("main.tf", 'variable "bootstrap" {\n  default = "' + value + '"\n}\n')
        sibling = self.repo / "override.tf"
        sibling.write_bytes(bytes([255]))
        self.assert_hidden(self.record("main.tf:2"), value, omitted=True)
        sibling.unlink()
        outside = self.root / "outside.tf"
        outside.write_text('output "public" { value = true }', encoding="utf-8")
        sibling.symlink_to(outside)
        self.assert_hidden(self.record("main.tf:2"), value, omitted=True)

    def test_terraform_json_override_context_omits_both_source_formats(self):
        value = "synthetic-" + "json-override-sensitive-value"
        for sensitive_in_json in (True, False):
            with self.subTest(sensitive_in_json=sensitive_in_json):
                hcl_attr = f'default = "{value}"' if sensitive_in_json else 'sensitive = true'
                json_attr = {"sensitive": True} if sensitive_in_json else {"default": value}
                self.write("main.tf", 'variable "bootstrap" {\n  ' + hcl_attr + '\n}\n')
                self.write("override.tf.json", json.dumps({"variable": {"bootstrap": json_attr}}))
                source = "main.tf:2" if sensitive_in_json else "override.tf.json:1"
                self.assert_hidden(self.record(source), value, omitted=True)

    def test_sensitive_hcl_module_does_not_hide_a_public_child_module(self):
        value = "visible-configuration"
        self.write("variables.tf", 'variable "bootstrap" { sensitive = true }\n')
        self.write("child/main.tf", 'output "status" { value = "' + value + '" }\n' + self.EBS)
        record = self.record("child/main.tf:1")
        self.assertIn("F-001", render.attach_sources(record, self.repo))
        for page in self.pages(record):
            self.assertIn(value, page)

    def test_public_hcl_blocks_keep_values_and_original_line_numbers(self):
        value = "visible-configuration"
        for kind, field in (("variable", "default"), ("output", "value")):
            for flag in ('  sensitive = false # public\n', ''):
                for prefix in ("", "\ufeff"):
                    with self.subTest(kind=kind, flag=flag, bom=bool(prefix)):
                        text = (f'{kind} "public_label" {{\n  {field} = "{value}"\n' + flag + '}\n' + self.EBS)
                        path = self.write("main.tf", prefix + text)
                        self.assertEqual(render.source_lines(path), text.splitlines())
                        for page in self.pages(self.record("main.tf:1-10")):
                            self.assertIn(value, page)
                            self.assertIn('class="snippet"', page)

    def test_sensitive_looking_hcl_comments_and_strings_do_not_omit_public_excerpts(self):
        text = ('# variable "hidden" { sensitive = true }\n'
                'locals { note = "sensitive = true" }\n'
                'output "status" {\n  value = "visible-configuration"\n  sensitive = false\n}\n' + self.EBS)
        path = self.write("main.tf", text)
        self.assertEqual(render.source_lines(path), text.splitlines())
        for page in self.pages(self.record("main.tf:1-10")):
            self.assertIn("visible-configuration", page)

    def test_yaml_passwords_cannot_use_the_hcl_reference_exception(self):
        for prefix in ('var.', 'local.', 'data.', 'module.', 'aws_', 'google_'):
            with self.subTest(prefix=prefix):
                value = prefix + "synthetic_private_value"
                self.write("pods.yaml", 'apiVersion: v1\nkind: List\nitems:\n  - apiVersion: v1\n'
                           '    kind: ConfigMap\n    metadata: {name: app}\n    data:\n'
                           '      password: ' + value + '\n  - ' + self.POD + '\n')
                record = self.record()
                self.assertEqual([f["rule"] for f in record["findings"]], ["K8S-001"])
                for page in self.assert_hidden(record, value):
                    self.assertIn("privileged: true", page)

    def test_real_hcl_references_and_public_yaml_scalars_stay_visible(self):
        self.write("main.tf", 'resource "aws_db_instance" "main" {\n  publicly_accessible = true\n'
                   '  password = var.db_password\n  storage_encrypted = true\n}\n')
        for page in self.pages(self.record()):
            self.assertIn("password = var.db_password", page)
        text = 'log_level: var.visible_configuration\npublicly_accessible: true\n'
        path = self.write("settings.yaml", text)
        self.assertEqual(render.source_lines(path), text.splitlines())
        for page in self.pages(self.record("settings.yaml:2")):
            self.assertIn("var.visible_configuration", page)

    def test_adjacent_json_secret_values_are_hidden_across_layouts(self):
        first, second = "synthetic-" + "first-secret", "synthetic-" + "second-secret"
        resource = {"address": "aws_ebs_volume.main", "mode": "managed", "type": "aws_ebs_volume",
                    "name": "main", "values": {"availability_zone": "us-east-1a", "encrypted": False}}
        planned = json.dumps({"root_module": {"resources": [resource]}})
        variants = [
            (first, second, '\n', 'visible-configuration'),
            ({"payload": first}, {"payload": second}, '\n', 'visible-configuration'),
            ([first], second, '\n', 'visible-configuration'),
            ({"payload": first}, second, '\r\n', 'visible-configuration'),
            (first, {"payload": second}, '\r', 'visible-configuration'),
            (first, second, '\n', 'visible' + chr(0x2028) + 'configuration'),
            ({"payload": first}, second, '\n', 'visible' + chr(0x85) + 'configuration'),
        ]
        for a, b, newline, note in variants:
            with self.subTest(first_type=type(a).__name__, second_type=type(b).__name__,
                              newline=repr(newline), note=repr(note)):
                text = ('{\n "note": ' + json.dumps(note, ensure_ascii=False) + ',\n "variables": {\n'
                        ' "first_password":\n' + json.dumps(a, indent=2) + ', "second_password":\n' +
                        json.dumps(b, indent=2) + '\n },\n "planned_values": ' + planned + '\n}\n')
                self.write("plan.json", text.replace('\n', newline))
                self.assertEqual([f["rule"] for f in self.record()["findings"]], ["AWS-EBS-001"])
                # Include both values even when the baseline location is farther away.
                for page in self.assert_hidden(self.record("plan.json:1-40"), first, second):
                    self.assertIn("availability_zone", page)

    def test_json_public_keylike_strings_and_boolean_values_keep_source(self):
        # Prose spelling "password": "x" inside a string is scrubbed by the final
        # pass (redaction.scrub_lines); booleans and null stay visible.
        prose = json.dumps({"note": '"password": "synthetic-prose-value"'}, indent=2)
        path = self.write("resource.json", prose)
        lines = render.source_lines(path)
        self.assertEqual(len(lines), len(prose.splitlines()))
        self.assertNotIn("synthetic-prose-value", "\n".join(lines))
        texts = [json.dumps({"password": False, "token": None, "public": "visible-configuration"}, indent=2)]
        for text in texts:
            with self.subTest(text=text):
                path = self.write("resource.json", text)
                self.assertEqual(render.source_lines(path), text.splitlines())
                for page in self.pages(self.record("resource.json:1-10")):
                    self.assertIn("visible-configuration", page)

    def test_compact_json_keeps_public_fields_before_secret_values(self):
        value = "synthetic-" + "compact-json-secret"
        self.write("resource.json", json.dumps({"public": "visible-configuration", "password": value}))
        for page in self.assert_hidden(self.record("resource.json:1"), value):
            self.assertIn("visible-configuration", page)

    def test_adjacent_hcl_secret_heredocs_keep_their_entire_bodies_hidden(self):
        first, second = "synthetic-" + "first-hcl-secret", "synthetic-" + "second-heredoc-secret"
        prefixes = ['    credentials = {\n      username = "' + first + '"\n    },',
                    '    credentials = {username = "' + first + '"},']
        for prefix in prefixes:
            with self.subTest(multiline='\n' in prefix):
                text = ('resource "aws_instance" "app" {\n  user_data = jsonencode({\n' + prefix +
                        ' password = <<VALUE\n' + second + '\n' + second + '\nVALUE\n  })\n'
                        '  metadata_options { http_tokens = "optional" }\n'
                        '  ami = "ami-example"\n  instance_type = "t3.micro"\n}\n')
                path = self.write("main.tf", text)
                lines = render.source_lines(path)
                self.assertEqual(len(lines), len(text.splitlines()))
                record = self.record()
                self.assertEqual([f["rule"] for f in record["findings"]], ["AWS-EC2-001"])
                record["findings"] += self.record("main.tf:1-40")["findings"]
                for page in self.assert_hidden(record, first, second):
                    self.assertIn("ami-example", page)

    def test_yaml_secret_sequences_include_same_indent_items_and_comments(self):
        value = "synthetic-" + "yaml-list-value"
        for comment in ('', '# another item\n'):
            for indent in ('', '  '):
                with self.subTest(comment=bool(comment), indent=len(indent)):
                    text = ('credentials:\n' + indent + '- user: public\n' + comment + indent +
                            '- value: ' + value + '\npublicly_accessible: true\n')
                    path = self.write("settings.yaml", text)
                    lines = render.source_lines(path)
                    self.assertEqual(len(lines), len(text.splitlines()))
                    self.assertEqual(lines[-1], 'publicly_accessible: true')
                    for page in self.assert_hidden(self.record("settings.yaml:1-10"), value):
                        self.assertIn("publicly_accessible: true", page)

    def test_actions_image_tags_and_arns_are_not_secret_keys(self):
        # "secretsmanager:" inside a value read as a key hid the rest of the
        # line, and its unclosed quote hid every line after it.
        cases = {
            "iam.tf": ('data "aws_iam_policy_document" "task" {\n  statement {\n'
                       '    actions   = ["secretsmanager:GetSecretValue"]\n'
                       '    resources = ["arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db"]\n'
                       '  }\n}\n'),
            "policy.json": ('{\n  "Statement": [{\n    "Effect": "Allow",\n'
                            '    "Action": "secretsmanager:GetSecretValue",\n    "Resource": "*"\n  }]\n}\n'),
            "pod.tf": ('resource "kubernetes_pod" "eso" {\n  spec {\n    container {\n'
                       '      image = "external-secrets/external-secrets:v0.9.0"\n'
                       '      security_context {\n        privileged = true\n      }\n    }\n  }\n}\n'),
            "pod.yaml": ('apiVersion: v1\nkind: Pod\nmetadata:\n  name: app\nspec:\n  containers:\n'
                         '    - name: app\n      image: ghcr.io/acme/token-service:1.4.2\n'
                         '      securityContext:\n        privileged: true\n'),
        }
        # scrub_line may still trim a value naming a secret word on its own
        # line (token-service:1.4.2); every other line must survive intact.
        visible = {
            "iam.tf": ('    actions   = ["secretsmanager:GetSecretValue"]', '  }'),
            "policy.json": ('    "Action": "secretsmanager:GetSecretValue",', '    "Resource": "*"'),
            "pod.tf": ('        privileged = true', '      security_context {'),
            "pod.yaml": ('      securityContext:', '        privileged: true'),
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                lines = render.source_lines(self.write(name, text))
                self.assertEqual(len(lines), len(text.splitlines()))
                self.assertNotIn("[redacted]", lines)
                for line in visible[name]:
                    self.assertIn(line, lines)

    def test_secret_keys_beside_a_colon_stay_hidden(self):
        value = "synthetic-" + "colon-value"
        for name, text in {
            "a.json": '{\n  "db_password":"' + value + '",\n  "x": 1\n}\n',
            "b.yaml": 'db_password: ' + value + '\nx: 1\n',
            "c.tf": 'locals {\n  cfg = { db_password: "' + value + '" }\n}\n',
            "d.tf": 'locals {\n  run = "app DB_PASSWORD:' + value + '"\n}\n',
        }.items():
            with self.subTest(name=name):
                lines = render.source_lines(self.write(name, text))
                self.assertNotIn(value, "\n".join(lines or []))


if __name__ == "__main__":
    unittest.main()
