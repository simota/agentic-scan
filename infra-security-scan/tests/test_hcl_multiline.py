"""Multiline HCL expressions must not turn inactive branches into literal items."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "infra-scan" / "scripts"))
import iac_scan  # noqa: E402


class MultilineHclTest(unittest.TestCase):
    def scan(self, text):
        with tempfile.TemporaryDirectory(prefix="iac-multiline-") as tmp:
            (Path(tmp) / "main.tf").write_text(text, encoding="utf-8")
            return iac_scan.run(tmp)

    def ingress(self, expression):
        return self.scan('''resource "aws_security_group_rule" "ssh" {
  type = "ingress"
  security_group_id = "sg-00000000000000000"
  protocol = "tcp"
  from_port = 22
  to_port = 22
  cidr_blocks = ''' + expression + "\n}\n")

    def test_multiline_conditional_stays_one_unknown_item(self):
        expressions = [
            'true ? "10.0.0.0/8" :\n    "0.0.0.0/0"',
            'var.private_only ? "10.0.0.0/8" :\n    "0.0.0.0/0"',
            'true\n    ? "10.0.0.0/8"\n    : "0.0.0.0/0"',
            '"0.0.0.0/0"\n    == "never" ? "10.0.0.0/8" : "10.0.0.0/8"',
        ]
        for expression in expressions:
            with self.subTest(expression=expression):
                value = "[\n    " + expression + "\n  ]"
                self.assertEqual(iac_scan.literal(value), [iac_scan.UNKNOWN])
                self.assertEqual(self.ingress(value).hits, [])

    def test_comments_do_not_end_an_unknown_tuple_item(self):
        expressions = [
            'var.private_only ? "10.0.0.0/8" : # comma, bracket ]\n    "0.0.0.0/0"',
            'var.private_only ? "10.0.0.0/8" : // comma, bracket ]\n    "0.0.0.0/0"',
            'var.private_only /* comma, bracket ], parenthesis ) */\n'
            '    ? "10.0.0.0/8" :\n    "0.0.0.0/0"',
            'true /* comma, bracket ] */\n'
            '    ? "10.0.0.0/8" :\n    "0.0.0.0/0"',
        ]
        for expression in expressions:
            with self.subTest(expression=expression):
                value = "[\n    " + expression + "\n  ]"
                self.assertEqual(iac_scan.literal(value), [iac_scan.UNKNOWN])
                self.assertEqual(self.ingress(value).hits, [])

    def test_known_items_survive_beside_an_unknown_expression(self):
        value = '''[
    "10.0.0.0/8",
    var.private_only ? "10.0.0.0/8" :
      "0.0.0.0/0", # this comma ends the entire conditional
    "::/0",
  ]'''
        for wrapper in ("{}", "tolist({})", "toset({})"):
            with self.subTest(wrapper=wrapper):
                expression = wrapper.format(value)
                self.assertEqual(iac_scan.literal(expression),
                                 ["10.0.0.0/8", iac_scan.UNKNOWN, "::/0"])
                hits = self.ingress(expression).hits
                self.assertEqual([(h["rule"], h["detail"]) for h in hits],
                                 [("AWS-NET-001", "ingress from ::/0 to 22/SSH")])

    def test_nested_collections_and_calls_keep_outer_element_boundaries(self):
        value = '''[
  var.private_only ? concat(["10.0.0.0/8"], ["192.168.0.0/16"]) :
    ["0.0.0.0/0", "::/0"],
  {
    protocol = "tcp"
    from_port = 22
    to_port = 22
    cidr_blocks = [
      "10.0.0.0/8",
      "::/0",
    ]
  },
]'''
        self.assertEqual(iac_scan.literal(value), [iac_scan.UNKNOWN, {
            "protocol": "tcp", "from_port": 22, "to_port": 22,
            "cidr_blocks": ["10.0.0.0/8", "::/0"],
        }])

    def test_newline_separated_object_attributes_remain_independent(self):
        scan = self.scan('''resource "aws_security_group" "app" {
  ingress = [
    var.private_only ? {
      protocol = "tcp"
      from_port = 22
      to_port = 22
      cidr_blocks = ["10.0.0.0/8"]
    } :
    {
      protocol = "tcp"
      from_port = 22
      to_port = 22
      cidr_blocks = ["0.0.0.0/0"]
    },
    {
      description = var.description
      protocol = "tcp"
      from_port = 22
      to_port = 22
      cidr_blocks = ["::/0"]
    },
  ]
}
''')
        self.assertEqual([(h["rule"], h["detail"]) for h in scan.hits],
                         [("AWS-NET-001", "ingress from ::/0 to 22/SSH")])


if __name__ == "__main__":
    unittest.main()
