"""The HCL scanners jump between the characters they act on instead of reading
every character; these cases pin the edges of each jump (escapes, templates,
comments, heredocs, unterminated input). Expected values were recorded from the
character-by-character implementation they replaced."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "infra-scan" / "scripts"))
import iac_scan  # noqa: E402

U = iac_scan.UNKNOWN


class ScannerFastPathTest(unittest.TestCase):
    def test_skip_string(self):
        cases = {'"abc"x': 5, '"a\\"b"x': 6, '"a${ "}" }b"x': 12, '"$${x}"y': 7, '"%%{x}"y': 7,
                 '"100%"x': 6, '"$x"y': 4, '"abc': 4, '"ab\\': 4}
        for text, end in cases.items():
            self.assertEqual(iac_scan.skip_string(text, 0), end, text)

    def test_skip_balanced(self):
        cases = {'{a}x': 3, '{"}"}x': 5, '{# }\n}x': 6, '{// }\n}x': 7, '{/* } */}x': 9,
                 '{<<EOT\n}\nEOT\n}x': 14, '{<x}x': 4, '{a/b}x': 5, '([{]})x': 6, '{': 1, '{/* }': 5}
        for text, end in cases.items():
            self.assertEqual(iac_scan.skip_balanced(text, 0), end, text)

    def test_scan_expr(self):
        cases = {'"a" # c': 4, 'x // c': 2, 'f(1,\n2)\nz': 7, '[1,\n2] }': 7, '<<EOT\nq}\nEOT\nnext': 12,
                 'a < b\nc': 5, 'x /* } */ y\n': 11, 'abc': 3}
        for text, end in cases.items():
            self.assertEqual(iac_scan.scan_expr(text, 0, len(text)), end, text)
        # The end bound holds even when the stop character lies beyond it.
        self.assertEqual(iac_scan.scan_expr("abc\n", 0, 2), 2)

    def test_unquote(self):
        cases = {'plain': 'plain', 'café': 'café', 'a\\nb': 'a\nb', '\\U0001F600': '\U0001F600',
                 '\\U00110000': U, '$${x}': '${x}', '%%{y}': '%{y}', '${x}': U, '100%': '100%',
                 'a\\': 'a\\', '$': '$', 'x\\"y': 'x"y'}
        for raw, value in cases.items():
            got = iac_scan.unquote(raw)
            if value is U:
                self.assertIs(got, U, raw)
            else:
                self.assertEqual(got, value, raw)

    def test_literal_skips_unknown_terms_whole(self):
        self.assertEqual(iac_scan.literal('["a", f(x, "]"), <<EOT\nb\nEOT\n]'), ["a", U, "b\n"])
        self.assertEqual(iac_scan.literal('{k = "v" # c\n n = 12}'), {"k": "v", "n": 12})

    def test_hcl_code(self):
        # [(heredocs, strings)] in the order (F, T), (F, F), (T, T), (T, F)
        cases = {
            'a = "x#y" # c': ['a = "x#y" ', 'a = "" ', 'a = "x#y" ', 'a = "" '],
            'b = "q\\"#" // c': ['b = "q\\"#" ', 'b = "" ', 'b = "q\\"#" ', 'b = "" '],
            'c /* x */ = 1': ['c  = 1'] * 4,
            '/* open\nstill */ d = 2': ['\n d = 2'] * 4,
            'e = "unterminated #': ['e = "unterminated #', 'e = ""', 'e = "unterminated #', 'e = ""'],
            'f = "x\\': ['f = "x\\', 'f = ""', 'f = "x\\', 'f = ""'],
            'p = <<EOT\nbody # not a comment\nEOT\nq = 1': ['p = ""\n\n\nq = 1'] * 2
            + ['p = <<EOT\nbody # not a comment\nEOT\nq = 1'] * 2,
            'g = a/b': ['g = a/b'] * 4,
        }
        for text, expected in cases.items():
            got = [iac_scan.hcl_code(text, h, s) for h in (False, True) for s in (True, False)]
            self.assertEqual(got, expected, text)

    def test_innermost_objects(self):
        cases = {'{a = 1}': ['{a = 1}'], '{ {a = "}"} }': ['{a = "}"}'], '"{x}" {b = 2}': ['{b = 2}'],
                 '{c = "\\"}"}': ['{c = "\\"}"}'], '{d = "x\\': [], '}{e}{': ['{e}']}
        for line, objects in cases.items():
            self.assertEqual(iac_scan.innermost_objects(line), objects, line)

    def test_quote_end(self):
        cases = [('', 0, 0), ('"', 0, 0), ('ab"', 0, 2), ('a\\"b"', 0, 4), ('a\\', 0, 2), ('\\\\"', 0, 2)]
        for line, start, end in cases:
            self.assertEqual(iac_scan.quote_end(line, start), end, line)

    def test_line_index(self):
        cases = {'': [0], 'a': [0], 'a\nb': [0, 2], '\n\n': [0, 1, 2], 'a\r\nb\n': [0, 3, 5]}
        for text, starts in cases.items():
            self.assertEqual(iac_scan.LineIndex(text).starts, starts, text)

    def test_printable_converts_each_occurrence(self):
        key = "AK" + "IA" + "Q" * 16  # credential-shaped, built at runtime
        lone = "x\ud800y"
        value = {key: [key, lone, 1, None, True, {"n": key}], lone: lone, "plain": "café"}
        out = iac_scan.printable(value)
        self.assertEqual(out, {"[redacted]": ["[redacted]", "x\\ud800y", 1, None, True, {"n": "[redacted]"}],
                               "x\\ud800y": "x\\ud800y", "plain": "café"})
        self.assertEqual(iac_scan.printable("[redacted]"), "[redacted]")

    def test_secret_shape_prefilter_matches_every_label(self):
        lines = ["k = \"" + "AK" + "IA" + "Q" * 16 + "\"", "t = \"gh" + "p_" + "a" * 36 + "\"",
                 "-" * 5 + "BEGIN RSA PRIVATE KEY" + "-" * 5, "nothing here"]
        for line in lines:
            per_label = any(p.search(line) for _, p in iac_scan.SECRET_PATTERNS)
            self.assertEqual(bool(iac_scan.ANY_SECRET_PATTERN.search(line)), per_label, line)


if __name__ == "__main__":
    unittest.main()
