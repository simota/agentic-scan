"""Secret key values inherit their meaning from a containing block/object.

Exercise the source-excerpt boundary and both generated HTML reports, including
plain values that credential-shape heuristics cannot recognize.
"""
import base64
import html
import json
from pathlib import Path
import subprocess
import sys
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-scan" / "scripts"))
import iac_scan  # noqa: E402
import excerpts  # noqa: E402
import render  # noqa: E402

from test_output_redaction import OutputTest  # noqa: E402


MD5_VALUE = "quiet" + "meadowlark"
# A valid 256-bit, RFC 4648 base64 value; its low entropy defeats shape guessing.
RAW_KEY = base64.b64encode(bytes([1]) * 32).decode("ascii")
MD5_PARENTS = ("md5_authentication_key", "md5_authentication_keys")
CSEK_PARENTS = tuple(prefix + "_encryption_key" for prefix in (
    "disk", "source_disk", "image", "source_image", "snapshot", "source_snapshot"))


def camel(name):
    first, *rest = name.split("_")
    return first + "".join(word.title() for word in rest)


class ContextualKeyRedactionTest(OutputTest):
    def case(self, name, text, companions=None):
        """Keep each module separate so one secret cannot hide another case."""
        number = getattr(self, "case_number", 0) + 1
        self.case_number = number
        prefix = f"case-{number}"
        self.write(f"{prefix}/{name}", text)
        for other, content in (companions or {}).items():
            self.write(f"{prefix}/{other}", content)
        return f"{prefix}/{name}"

    def outputs(self, rel, text, needle):
        line = next(n for n, row in enumerate(text.split("\n"), 1) if needle in row)
        record = self.record(f"{rel}:{line}")
        return {"excerpts": json.dumps(excerpts.attach_sources(record, self.repo)),
                **dict(zip(("dashboard.html", "assessment.html"), self.pages(record)))}

    def assert_hidden(self, name, text, value, companions=None):
        rel = self.case(name, text, companions)
        outputs = self.outputs(rel, text, value)
        self.assertEqual([sink for sink, output in outputs.items() if value in output], [],
                         f"{name} exposes a contextual key")

    def assert_visible(self, name, text, values, companions=None):
        rel = self.case(name, text, companions)
        outputs = self.outputs(rel, text, values[0])
        self.assertEqual([(sink, value) for sink, output in outputs.items()
                          for value in values if value not in output], [],
                         f"{name} loses public evidence")

    def test_md5_hcl_blocks_and_dynamic_content(self):
        for parent in MD5_PARENTS:
            for dynamic in (False, True):
                for suffix in ("tf", "tofu", "hcl"):
                    with self.subTest(parent=parent, dynamic=dynamic, suffix=suffix):
                        body = f'    name = "public-peer-key"\n    key = "{MD5_VALUE}"\n'
                        block = (f'  dynamic "{parent}" {{\n    for_each = [1]\n'
                                 f'    content {{\n{body}    }}\n  }}\n' if dynamic else
                                 f'  {parent} {{\n{body}  }}\n')
                        text = 'resource "google_compute_router_peer" "peer" {\n' + block + '}\n'
                        self.assert_hidden("main." + suffix, text, MD5_VALUE)

    def test_csek_hcl_blocks_and_dynamic_content(self):
        self.assertEqual(len(base64.b64decode(RAW_KEY, validate=True)), 32)
        for parent in CSEK_PARENTS:
            for dynamic in (False, True):
                with self.subTest(parent=parent, dynamic=dynamic):
                    body = f'    raw_key = "{RAW_KEY}"\n'
                    block = (f'  dynamic "{parent}" {{\n    for_each = [1]\n'
                             f'    content {{\n{body}    }}\n  }}\n' if dynamic else
                             f'  {parent} {{\n{body}  }}\n')
                    text = 'resource "google_compute_disk" "disk" {\n' + block + '}\n'
                    self.assert_hidden("main.tf", text, RAW_KEY)

    def test_json_and_yaml_objects_and_lists(self):
        for parent, field, value in ([(p, "key", MD5_VALUE) for p in MD5_PARENTS] +
                                      [(p, "raw_key", RAW_KEY) for p in CSEK_PARENTS]):
            for api_names in (False, True):
                p, f = (camel(parent), camel(field)) if api_names else (parent, field)
                for as_list in (False, True):
                    entry = {"name": "public-key-name", f: value}
                    doc = {"configuration": {p: [entry] if as_list else entry}}
                    for suffix in ("json", "yaml"):
                        with self.subTest(parent=p, field=f, as_list=as_list, suffix=suffix):
                            if suffix == "json":
                                text = json.dumps(doc, indent=2)
                            else:
                                prefix = "    - " if as_list else "    "
                                indent = "      " if as_list else "    "
                                text = (f"configuration:\n  {p}:\n{prefix}name: public-key-name\n"
                                        f'{indent}{f}: "{value}"\n')
                            self.assert_hidden("config." + suffix, text, value)

    def test_plan_values_and_embedded_json(self):
        for parent, field, value in ((MD5_PARENTS[0], "key", MD5_VALUE),
                                     (CSEK_PARENTS[0], "raw_key", RAW_KEY)):
            entry = {parent: [{field: value}]}
            plan = {"format_version": "1.2", "planned_values": {"root_module": {"resources": [
                {"address": "google_compute_router_peer.peer", "type": "google_compute_router_peer",
                 "values": entry}]}}}
            for doc in (plan, {"configuration": json.dumps(entry)}):
                with self.subTest(parent=parent, embedded="configuration" in doc):
                    self.assert_hidden("plan.json", json.dumps(doc, indent=2), value)

    def test_escaped_json_parent_and_child_keys(self):
        doc = {"md5AuthenticationKeys": [{"name": "public-key-name", "key": MD5_VALUE}]}
        text = json.dumps(doc, indent=2)
        for encoded in (text.replace("md5AuthenticationKeys", "md5\\u0041uthenticationKeys"),
                        text.replace('"key"', '"k\\u0065y"')):
            with self.subTest(text=encoded):
                self.assert_hidden("config.json", encoded, MD5_VALUE)

    def test_hcl_objects_lists_and_jsonencode(self):
        for parent, field, value in ((MD5_PARENTS[0], "key", MD5_VALUE),
                                     (CSEK_PARENTS[0], "raw_key", RAW_KEY)):
            entry = '{ ' + field + ' = "' + value + '" }'
            for payload in (entry, '[' + entry + ']'):
                for wrap in (False, True):
                    with self.subTest(parent=parent, payload=payload, jsonencode=wrap):
                        obj = '{\n    ' + parent + ' = ' + payload + '\n  }'
                        expression = 'jsonencode(' + obj + ')' if wrap else obj
                        self.assert_hidden("main.tf", 'locals {\n  config = ' + expression + '\n}\n', value)

    def test_hcl_unknown_expressions_still_hide_embedded_literals(self):
        for expression in (f'format("%s", "{MD5_VALUE}")',
                           f'var.enabled ? "{MD5_VALUE}" : var.external'):
            for block in (True, False):
                with self.subTest(expression=expression, block=block):
                    body = 'md5_authentication_key ' + ('{\n' if block else '= {\n')
                    text = ('resource "google_compute_router_peer" "peer" {\n  ' + body +
                            '    key = ' + expression + '\n  }\n}\n')
                    self.assert_hidden("main.tf", text, MD5_VALUE)

    def test_contextual_references_hide_module_local_defaults(self):
        for parent, field, value in ((MD5_PARENTS[0], "key", MD5_VALUE),
                                     (CSEK_PARENTS[0], "raw_key", RAW_KEY)):
            for reference, declaration in (
                    ("var.bootstrap", 'variable "bootstrap" { default = "' + value + '" }\n'),
                    ("local.config.key", 'locals { config = { key = "' + value + '" } }\n')):
                for dynamic in (False, True):
                    with self.subTest(parent=parent, reference=reference, dynamic=dynamic):
                        body = f'    {field} = {reference}\n'
                        block = (f'  dynamic "{parent}" {{\n    for_each = [1]\n'
                                 f'    content {{\n{body}    }}\n  }}\n' if dynamic else
                                 f'  {parent} {{\n{body}  }}\n')
                        use = 'resource "google_compute_router_peer" "peer" {\n' + block + '}\n'
                        self.assert_hidden("values.tf", declaration, value, {"main.tf": use})

    def test_contextual_object_references_hide_module_local_values(self):
        for parent, field, value in ((MD5_PARENTS[0], "key", MD5_VALUE),
                                     (CSEK_PARENTS[0], "raw_key", RAW_KEY)):
            for wrapped in (False, True):
                with self.subTest(parent=parent, wrapped=wrapped):
                    source = f'locals {{ config = {{ {field} = "{value}" }} }}\n'
                    attr = f'  {parent} = local.config\n'
                    use = ('locals {\n  wrapper = {\n' + attr + '  }\n}\n' if wrapped else
                           'resource "google_compute_router_peer" "peer" {\n' + attr + '}\n')
                    self.assert_hidden("values.tf", source, value, {"main.tf": use})

    def test_dynamic_inputs_hide_module_local_values(self):
        for parent, field, value in ((MD5_PARENTS[1], "key", MD5_VALUE),
                                     (CSEK_PARENTS[0], "raw_key", RAW_KEY)):
            with self.subTest(parent=parent):
                source = f'locals {{ items = [{{ {field} = "{value}" }}] }}\n'
                use = ('resource "google_compute_router_peer" "peer" {\n'
                       f'  dynamic "{parent}" {{\n    for_each = local.items\n    content {{\n'
                       f'      {field} = {parent}.value.{field}\n    }}\n  }}\n}}\n')
                self.assert_hidden("values.tf", source, value, {"main.tf": use})

    def test_quoted_references_are_literals_in_every_format(self):
        value = "var.bootstrap"
        for suffix, text in (
                ("tf", 'resource "google_compute_router_peer" "peer" {\n'
                       '  md5_authentication_key {\n    key = "' + value + '"\n  }\n}\n'),
                ("json", json.dumps({"md5AuthenticationKeys": [{"key": value}]}, indent=2)),
                ("yaml", 'md5AuthenticationKeys:\n  - key: "' + value + '"\n')):
            with self.subTest(suffix=suffix):
                self.assert_hidden("main." + suffix, text, value)

    def test_public_hcl_references_and_fields_stay_readable(self):
        for parent, field in ((MD5_PARENTS[0], "key"), (CSEK_PARENTS[0], "raw_key")):
            for dynamic in (False, True):
                with self.subTest(parent=parent, dynamic=dynamic):
                    evidence = f'{field} = var.external'
                    body = f'    {evidence}\n'
                    block = (f'  dynamic "{parent}" {{\n    for_each = var.items\n'
                             f'    content {{\n{body}    }}\n  }}\n' if dynamic else
                             f'  {parent} {{\n{body}  }}\n')
                    text = 'resource "google_compute_router_peer" "peer" {\n' + block + '}\n'
                    self.assert_visible("main.tf", text, [evidence])
        text = ('resource "google_compute_disk" "disk" {\n  disk_encryption_key {\n'
                '    kms_key_self_link = "projects/demo/locations/global/keyRings/ring/cryptoKeys/public"\n'
                '    raw_key = null\n    sha256 = "' + RAW_KEY + '"\n  }\n}\n')
        self.assert_visible("main.tf", text, [RAW_KEY, "cryptoKeys/public"])
        self.assert_visible("main.tf", 'locals {\n  key = "' + MD5_VALUE + '"\n}\n', [MD5_VALUE])

    def test_public_json_names_hashes_and_ordinary_keys_stay_readable(self):
        for parent in ("md5AuthenticationKeys", "md5_authentication_keys"):
            with self.subTest(parent=parent):
                doc = {parent: [{"name": "public-key-name", "key": None}],
                       "md5AuthenticationKeyName": "public-key-name", "key": MD5_VALUE}
                self.assert_visible("config.json", json.dumps(doc, indent=2), [MD5_VALUE, "public-key-name"])
        for parent in CSEK_PARENTS:
            for api_names in (False, True):
                p = camel(parent) if api_names else parent
                with self.subTest(parent=p):
                    key_name = "kmsKeyName" if api_names else "kms_key_self_link"
                    doc = {p: {key_name: "public-kms-name", "sha256": RAW_KEY}}
                    self.assert_visible("config.json", json.dumps(doc, indent=2), [RAW_KEY, "public-kms-name"])

    def test_public_name_reference_does_not_make_its_default_secret(self):
        value = "visible-configuration"
        source = 'variable "display" { default = "' + value + '" }\n'
        for block in ('md5_authentication_key { name = var.display }',
                      'disk_encryption_key { kms_key_self_link = var.display }'):
            with self.subTest(block=block):
                use = 'resource "google_compute_router_peer" "peer" {\n  ' + block + '\n}\n'
                self.assert_visible("values.tf", source, [value], {"main.tf": use})

    def test_a_real_neighboring_finding_cannot_publish_the_key(self):
        text = ('resource "google_compute_router_peer" "peer" {\n  md5_authentication_key {\n'
                '    name = "public-peer-key"\n    key = "' + MD5_VALUE + '"\n  }\n}\n'
                'resource "aws_ebs_volume" "data" { encrypted = false }\n')
        rel = self.case("main.tf", text)
        record = self.record(f"{rel}:7")
        record["findings"] = iac_scan.build_findings(iac_scan.run(self.repo).hits)
        self.assertTrue(any(f["rule"] == "AWS-EBS-001" for f in record["findings"]))
        outputs = {"excerpts": json.dumps(excerpts.attach_sources(record, self.repo)),
                   **dict(zip(("dashboard.html", "assessment.html"), self.pages(record)))}
        self.assertEqual([sink for sink, output in outputs.items() if MD5_VALUE in output], [])

    def test_aliases_reach_module_local_literals(self):
        source = f'variable "bootstrap" {{ default = "{MD5_VALUE}" }}\n'
        use = ('locals { alias = var.bootstrap }\n'
               'resource "google_compute_router_peer" "peer" {\n'
               '  md5_authentication_key { key = local.alias }\n}\n')
        self.assert_hidden("values.tf", source, MD5_VALUE, {"main.tf": use})

    def test_unknown_wrappers_do_not_hide_literal_objects_from_the_check(self):
        obj = '{md5_authentication_key = {key = "' + MD5_VALUE + '"}}'
        for expression in (f'merge({{}}, {obj})', f'var.enabled ? {obj} : {{}}'):
            with self.subTest(expression=expression):
                self.assert_hidden("main.tf", 'locals { config = ' + expression + ' }\n', MD5_VALUE)

    def test_resource_iterator_reaches_module_local_literals(self):
        source = 'locals { peers = { a = { key = "' + MD5_VALUE + '" } } }\n'
        use = ('resource "google_compute_router_peer" "peer" {\n  for_each = local.peers\n'
               '  md5_authentication_key { key = each.value.key }\n}\n')
        self.assert_hidden("values.tf", source, MD5_VALUE, {"main.tf": use})

    def test_escaped_dynamic_and_variable_labels_are_decoded(self):
        for label in ('md5\\u005fauthentication_key', 'md5_authentication_\\u006beys'):
            with self.subTest(label=label):
                text = ('resource "google_compute_router_peer" "peer" {\n'
                        f'  dynamic "{label}" {{\n    for_each = [1]\n'
                        f'    content {{ key = "{MD5_VALUE}" }}\n  }}\n}}\n')
                self.assert_hidden("main.tf", text, MD5_VALUE)
        source = 'variable "boot\\u0073trap" { default = "' + MD5_VALUE + '" }\n'
        use = ('resource "google_compute_router_peer" "peer" {\n'
               '  md5_authentication_key { key = var.bootstrap }\n}\n')
        self.assert_hidden("values.tf", source, MD5_VALUE, {"main.tf": use})

    def test_contextual_keys_do_not_use_public_enum_or_bool_exceptions(self):
        for raw, needle in (('"JWT"', "JWT"), ('"IAM"', "IAM"), ("true", "default = true")):
            with self.subTest(raw=raw):
                source = f'variable "bootstrap" {{ default = {raw} }}\n'
                use = ('resource "google_compute_router_peer" "peer" {\n'
                       '  md5_authentication_key { key = var.bootstrap }\n}\n')
                self.assert_hidden("values.tf", source, needle, {"main.tf": use})
        source = 'locals { bootstrap = "JWT" }\n'
        use = ('resource "google_compute_router_peer" "peer" {\n'
               '  md5_authentication_key { key = local.bootstrap }\n}\n')
        self.assert_hidden("values.tf", source, "JWT", {"main.tf": use})

    def test_hcl_traversal_spacing_comments_and_unicode(self):
        for name, reference in (("bootstrap", "var . bootstrap"),
                                ("bootstrap", "var /* ordinary spacing */ . bootstrap"),
                                ("構成", "var.構成")):
            with self.subTest(reference=reference):
                source = f'variable "{name}" {{ default = "{MD5_VALUE}" }}\n'
                use = ('resource "google_compute_router_peer" "peer" {\n'
                       f'  md5_authentication_key {{ key = {reference} }}\n}}\n')
                self.assert_hidden("values.tf", source, MD5_VALUE, {"main.tf": use})
        for reference in ("local .config.key", "local /* pick */ .config.key"):
            with self.subTest(reference=reference):
                source = 'locals { config = { key = "' + MD5_VALUE + '" } }\n'
                use = ('resource "google_compute_router_peer" "peer" {\n'
                       f'  md5_authentication_key {{ key = {reference} }}\n}}\n')
                self.assert_hidden("values.tf", source, MD5_VALUE, {"main.tf": use})

    def test_top_level_hcl_attributes_are_checked(self):
        text = ('inputs = {\n  md5_authentication_keys = [{\n'
                f'    name = "public-key-name"\n    key = "{MD5_VALUE}"\n  }}]\n}}\n')
        self.assert_hidden("terragrunt.hcl", text, MD5_VALUE)

    def test_external_dynamic_iterators_keep_public_evidence(self):
        for label, iterator, declare in (("md5_authentication_keys", "item", "    iterator = item\n"),
                                         ("md5_authentication_keys", "md5_authentication_keys", "")):
            with self.subTest(iterator=iterator):
                text = ('resource "google_compute_router_peer" "peer" {\n'
                        '  router = "public-router-evidence"\n'
                        f'  dynamic "{label}" {{\n    for_each = var.items\n{declare}'
                        f'    content {{\n      name = {iterator}.value.name\n'
                        f'      key = {iterator}.value.key\n    }}\n  }}\n}}\n')
                self.assert_visible("main.tf", text, ["public-router-evidence"])

    def test_object_metadata_does_not_taint_public_defaults(self):
        source = 'variable "display" { default = "public-key-name" }\n'
        for parent, fields in (("md5_authentication_keys", "name = var.display, key = var.external"),
                                ("disk_encryption_key", "kms_key_self_link = var.display, raw_key = var.external")):
            for jsonencode in (False, True):
                with self.subTest(parent=parent, jsonencode=jsonencode):
                    obj = '{ ' + parent + ' = [{' + fields + '}] }'
                    expression = 'jsonencode(' + obj + ')' if jsonencode else obj
                    use = 'locals { config = ' + expression + ' }\n'
                    self.assert_visible("values.tf", source, ["public-key-name"], {"main.tf": use})

    def test_literals_and_comments_do_not_create_reference_dependencies(self):
        source = 'variable "display" { default = "public-key-name" }\n'
        for expression in ('"var.display"', 'var.external /* var.display */', '"$${var.display}"'):
            with self.subTest(expression=expression):
                use = ('resource "google_compute_router_peer" "peer" {\n'
                       f'  md5_authentication_key {{ key = {expression} }}\n}}\n')
                self.assert_visible("values.tf", source, ["public-key-name"], {"main.tf": use})

    def test_reference_only_objects_and_cycles_keep_public_evidence(self):
        for expression in ('{ md5_authentication_key = { key = var.external } }',
                           'jsonencode({ md5_authentication_key = { key = var.external } })'):
            with self.subTest(expression=expression):
                text = 'locals {\n  label = "public-config-evidence"\n  config = ' + expression + '\n}\n'
                self.assert_visible("main.tf", text, ["public-config-evidence"])
        text = ('locals {\n  a = local.b\n  b = local.a\n  label = "public-config-evidence"\n}\n'
                'resource "google_compute_router_peer" "peer" {\n'
                '  md5_authentication_key { key = local.a }\n}\n')
        self.assert_visible("main.tf", text, ["public-config-evidence"])

    def test_templates_and_overrides_keep_secret_dependencies(self):
        for kind, reference, source, override in (
                ("variable", "var.bootstrap", f'variable "bootstrap" {{ default = "{MD5_VALUE}" }}\n',
                 'variable "bootstrap" { default = null }\n'),
                ("local", "local.bootstrap", f'locals {{ bootstrap = "{MD5_VALUE}" }}\n',
                 'locals { bootstrap = null }\n')):
            for expression in (reference, '"${' + reference + '}"'):
                with self.subTest(kind=kind, expression=expression):
                    use = ('resource "google_compute_router_peer" "peer" {\n'
                           f'  md5_authentication_key {{ key = {expression} }}\n}}\n')
                    self.assert_hidden("values.tf", source, MD5_VALUE,
                                       {"main.tf": use, "override.tf": override})

    def test_alias_dags_complete_and_preserve_only_safe_excerpts(self):
        # A sub-kilobyte DAG must not expand to hundreds of millions of values.
        # Run the real CLI in a bounded child so a regression cannot hang tests.
        for secret_use in (False, True):
            with self.subTest(secret_use=secret_use):
                text = 'locals {\n  n0 = var.external\n' + ''.join(
                    f'  n{i} = [local.n{i - 1}, local.n{i - 1}]\n' for i in range(1, 29))
                text += '  label = "public-dag-evidence"\n}\n'
                if secret_use:
                    text += ('resource "google_compute_router_peer" "peer" {\n'
                             '  md5_authentication_key { key = local.n28 }\n}\n')
                rel = self.case("main.tf", text)
                line = next(n for n, row in enumerate(text.splitlines(), 1) if "label =" in row)
                record = self.root / "dag-findings.json"
                record.write_text(json.dumps(self.record(f"{rel}:{line}")), encoding="utf-8")
                out = self.root / "dag-output"
                proc = subprocess.run([sys.executable, "-B", str(Path(render.__file__)), str(record),
                                       "--repo", str(self.repo), "--out", str(out), "--no-pdf"],
                                      capture_output=True, text=True, timeout=10)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                for name in ("dashboard.html", "assessment.html"):
                    page = html.unescape((out / name).read_text(encoding="utf-8"))
                    self.assertEqual("public-dag-evidence" in page, not secret_use, name)

    def test_custom_iterators_allow_comments_and_shadow_module_names(self):
        source = 'locals { items = [{ key = "' + MD5_VALUE + '" }] }\n'
        for iterator, name in (("/* select */ item", "item"), ("item /* select */", "item"),
                               ("local", "local"), ("var", "var")):
            with self.subTest(iterator=iterator):
                use = ('resource "google_compute_router_peer" "peer" {\n'
                       '  dynamic "md5_authentication_key" {\n    for_each = local.items\n'
                       f'    iterator = {iterator}\n    content {{ key = {name}.value.key }}\n  }}\n}}\n')
                self.assert_hidden("values.tf", source, MD5_VALUE, {"main.tf": use})

    def test_iterator_transformations_keep_input_dependencies(self):
        source = f'locals {{ peers = ["{MD5_VALUE}"] }}\n'
        for collection in ('{for i, p in local.peers: i => {key = p}}',
                           '[for p in local.peers: {key = p}]'):
            with self.subTest(collection=collection):
                use = ('resource "google_compute_router_peer" "peer" {\n'
                       '  dynamic "md5_authentication_key" {\n'
                       f'    for_each = {collection}\n'
                       '    content { key = md5_authentication_key.value.key }\n  }\n}\n')
                self.assert_hidden("values.tf", source, MD5_VALUE, {"main.tf": use})

    def test_heredoc_templates_reach_module_local_defaults(self):
        source = f'variable "bootstrap" {{ default = "{MD5_VALUE}" }}\n'
        for wrapped in (False, True):
            with self.subTest(wrapped=wrapped):
                expression = '<<-EOT\n${var.bootstrap}\nEOT\n'
                if wrapped:
                    expression = 'trimspace(' + expression + ')'
                use = ('resource "google_compute_router_peer" "peer" {\n'
                       '  md5_authentication_key {\n    key = ' + expression + '\n  }\n}\n')
                self.assert_hidden("values.tf", source, MD5_VALUE, {"main.tf": use})

    def test_structured_key_expressions_reach_module_local_defaults(self):
        source = f'variable "bootstrap" {{ default = "{MD5_VALUE}" }}\n'
        for expression in ('jsonencode({v = var.bootstrap})', 'jsonencode([var.bootstrap])'):
            with self.subTest(expression=expression):
                use = ('resource "google_compute_router_peer" "peer" {\n'
                       f'  md5_authentication_key {{ key = {expression} }}\n}}\n')
                self.assert_hidden("values.tf", source, MD5_VALUE, {"main.tf": use})

    def test_parenthesized_literal_keys_keep_their_schema_context(self):
        for parent, field, value in ((MD5_PARENTS[0], "key", MD5_VALUE),
                                     (CSEK_PARENTS[0], "raw_key", RAW_KEY)):
            for depth in (1, 2, 8):
                with self.subTest(parent=parent, depth=depth):
                    key = ('(/* schema */ ' * depth) + f'"{parent}"' + (')' * depth)
                    text = f'locals {{ config = {{ {key} = {{ {field} = "{value}" }} }} }}\n'
                    self.assert_hidden("main.tf", text, value)

    def test_external_set_iterator_keys_keep_public_evidence(self):
        for dynamic in (False, True):
            with self.subTest(dynamic=dynamic):
                if dynamic:
                    block = ('  dynamic "md5_authentication_key" {\n'
                             '    for_each = toset([var.external])\n    iterator = item\n'
                             '    content { key = item.key }\n  }\n')
                else:
                    block = ('  for_each = toset([var.external])\n'
                             '  md5_authentication_key { key = each.key }\n')
                text = ('resource "google_compute_router_peer" "peer" {\n'
                        '  router = "public-set-evidence"\n' + block + '}\n')
                self.assert_visible("main.tf", text, ["public-set-evidence"])


if __name__ == "__main__":
    unittest.main()
