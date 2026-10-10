"""Cases where the YAML subset and HCL literal parser disagreed with reference parsers."""
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-scan" / "scripts"))
import iac_scan  # noqa: E402
from iac_scan import UNKNOWN, _YamlSubset, literal, unquote  # noqa: E402

POD = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n  - name: c\n    image: x\n"


def yaml(text):
    return _YamlSubset(list(enumerate(text.split("\n"), 1))).parse()


class YamlSubsetTest(unittest.TestCase):
    def test_other_line_breaks_are_refused_not_swallowed_by_comments(self):
        for brk in ("\r", "\x85", "\u2028", "\u2029"):
            with self.subTest(brk=repr(brk)):
                text = POD + f"    securityContext: # hardened{brk}      privileged: true\n"
                with tempfile.TemporaryDirectory() as tmp:
                    Path(tmp, "pod.yaml").write_text(text, encoding="utf-8", newline="")
                    scan = iac_scan.run(tmp)
                self.assertEqual(scan.hits, [])
                self.assertTrue(any("unsupported line break" in n for n in scan.not_run), scan.not_run)

    def test_values_match_yaml(self):
        cases = {"a: x-'y # c": {"a": "x-'y"}, "a: nULL": {"a": "nULL"}, "a: NULL": {"a": None},
                 "a: \xa0true": {"a": "\xa0true"}, "a: 'q' # c": {"a": "q"}}
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(yaml(text), expected)

    def test_nested_sequences_on_one_line(self):
        # As PyYAML reads them; CloudFormation writes !Join lists this way.
        cases = {"a:\n- - b": {"a": [["b"]]}, "a:\n- - b: true": {"a": [[{"b": True}]]},
                 "- - a\n  - b\n- c": [["a", "b"], "c"], "- - - x\n    - z": [[["x", "z"]]],
                 "- - a: 1\n    b: 2\n  - c": [[{"a": "1", "b": "2"}, "c"]]}
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(yaml(text), expected)

    def test_unsupported_shapes_are_refused(self):
        for text in ('- - "<<": x', "a: [x: ]"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    yaml(text)


class HclLiteralTest(unittest.TestCase):
    def test_templates_after_a_literal_dollar_or_percent_are_unknown(self):
        for raw in ("100%${var.x}", "0.0.0.0/0%${var.x}$$", "a$${b}${c}"):
            with self.subTest(raw=raw):
                self.assertIs(unquote(raw), UNKNOWN)
        self.assertEqual(unquote("$${x}"), "${x}")
        self.assertEqual(unquote("$$${x}"), "$${x}")
        self.assertEqual(unquote("%%{x}"), "%{x}")

    def test_escapes_decode_even_beside_tabs_and_long_unicode(self):
        self.assertEqual(unquote("tab\there\\n"), "tab\there\n")
        self.assertEqual(unquote("\\U0001F600"), "\U0001F600")

    def test_for_expressions_after_any_whitespace(self):
        for raw in ("[for\tx in var.l: x]", "[for\n  x in var.l: x]", "{for\tk, v in m : k => v}"):
            with self.subTest(raw=raw):
                self.assertIs(literal(raw), UNKNOWN)


if __name__ == "__main__":
    unittest.main()
