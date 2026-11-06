"""Shortcuts that skip work which cannot change the result: each test pins the
edge the shortcut relies on. Expected values were recorded from the
implementation before the shortcuts."""
import copy
import json
from pathlib import Path
import random
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "infra-scan" / "scripts"))
import compare  # noqa: E402
import iac_scan  # noqa: E402
import render  # noqa: E402

SAMPLE = ROOT / "examples" / "findings.sample.json"


def secret_hits(rel, kind, text):
    scan = iac_scan.Scan(Path("."))
    iac_scan.scan_secrets(scan, rel, text, kind)
    return sorted((h["line"], h["detail"], h["strong"]) for h in scan.hits)


class SecretScanShortcutTest(unittest.TestCase):
    """The key-name patterns run only on lines holding = " (or : " in JSON), env
    entries only on lines naming "name", and the shape patterns only in a file
    with a shape somewhere."""

    def test_assignment_spacing_and_inline_objects(self):
        text = ('resource "a" "b" {\n  password\t=\t"s3cretvalue"\n  api_key="k9"\n  token = <<EOT\nzzz\nEOT\n'
                '  x = { secret = "v1" }\n}\n')
        self.assertEqual(secret_hits("main.tf", "terraform", text), [
            (2, "literal value assigned to password", False), (3, "literal value assigned to api_key", False),
            (4, "literal value assigned to token", False), (7, "literal value assigned to secret", False)])

    def test_locals_variable_and_output_literals(self):
        text = ('locals {\n  db_password = "inlocals"\n  other = "x"\n}\nvariable "db_password" {\n'
                '  default = <<EOT\nhd\nEOT\n}\noutput "token" {\n  value = "outv"\n}\n')
        self.assertEqual(secret_hits("main.tf", "terraform", text), [
            (2, "literal value assigned to db_password", False),
            (6, "literal default for variable db_password", False), (11, "literal value for output token", False)])

    def test_env_entry_name_in_any_case(self):
        text = 'env = [{ NAME = "API_TOKEN", value = "abc" }]\nenvironment {\n  Name = "DB_PASSWORD"\n  value = "pw1"\n}\n'
        self.assertEqual(secret_hits("main.tf", "terraform", text), [
            (1, "literal value for API_TOKEN", False), (3, "literal value for DB_PASSWORD", False)])
        snapshot = '{"Environment": [{"Name": "API_TOKEN", "Value": "snap"}], "NextToken": "c"}\n'
        self.assertEqual(secret_hits("s.json", "snapshot", snapshot), [(1, "literal value for API_TOKEN", False)])

    def test_only_ascii_letters_fold_to_name(self):
        # The env_pairs shortcut tests "name" in line.lower(); IGNORECASE folds no other character to these.
        import re
        chars = [chr(c) for c in range(sys.maxunicode + 1)]
        for ch in "name":
            folds = re.compile(ch, re.IGNORECASE).fullmatch
            others = [c for c in chars if c not in (ch, ch.upper()) and (ch in c.lower() or folds(c))]
            self.assertEqual(others, [], ch)

    def test_json_mapping_and_mock_outputs(self):
        self.assertEqual(secret_hits("x.tfvars.json", "tfvars", '{"db_password": "j1", "token":"j2", "ok": 1}\n'),
                         [(1, "literal value assigned to db_password", False),
                          (1, "literal value assigned to token", False)])
        text = 'mock_outputs = {\n  password = "mock"\n}\ninputs = {\n  password = "real1"\n}\n'
        self.assertEqual(secret_hits("t/terragrunt.hcl", "terragrunt", text),
                         [(5, "literal value assigned to password", False)])

    def test_shape_on_one_crlf_line(self):
        key = "AK" + "IA" + "Q" * 16  # credential-shaped, built at runtime
        self.assertEqual(secret_hits("k.yaml", "kubernetes", "a: 1\r\nkey: " + key + "\r\nb: 2\r\n"),
                         [(2, "AWS access key ID", True)])
        self.assertEqual(secret_hits("k.yaml", "kubernetes", "no shapes here\npassword: plain\n"), [])

    def test_no_shape_pattern_spans_a_newline(self):
        # The whole-file test stands for every line only because no shape crosses a line.
        for pattern in iac_scan.ANY_SECRET_PATTERN.pattern.split("|"):
            self.assertNotIn("\\s", pattern)
            self.assertNotIn(".", pattern.replace("\\.", ""))
            self.assertNotIn("[^", pattern)


class YamlShortcutTest(unittest.TestCase):
    def test_comment_and_pair(self):
        comments = {"a: 1": "a: 1", "a: 1  \t": "a: 1", "a: 1 # c": "a: 1", "a: '#x' # c": "a: '#x'",
                    "a#b": "a#b", "# only": "", "": ""}
        for text, out in comments.items():
            self.assertEqual(iac_scan._yaml_comment(text), out, text)
        pairs = {"a: 1": ("a", "1"), "a:": ("a", ""), "a:b": None, "no colon": None, "{a: 1}": None,
                 "'k:x': v": ("'k:x'", "v"), "": None}
        for text, out in pairs.items():
            self.assertEqual(iac_scan._yaml_pair(text), out, text)


class WorldCidrsTest(unittest.TestCase):
    def test_cases(self):
        cases = [
            (["0.0.0.0/0"], ["0.0.0.0/0"]), ([], []), (["10.0.0.0/8"], []), (["0.0.0.0/0", None], ["0.0.0.0/0"]),
            (["0.0.0.0/1", "128.0.0.0/1"], ["0.0.0.0/1 + 128.0.0.0/1"]), (["::/1", "8000::/1"], ["::/1 + 8000::/1"]),
            (["::/0", "bad"], ["::/0"]), (["1.2.3.4/0"], ["0.0.0.0/0"]), ("0.0.0.0/0", ["0.0.0.0/0"]),
            (["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"], ["0.0.0.0/0 split over 4 ranges"]),
            (["fe80::1%" + "x" * 80 + "/0"], ["::/0"]),  # longer than the parse cache admits
        ]
        for _ in range(2):  # the second round reads the cache
            for values, out in cases:
                self.assertEqual(iac_scan.world_cidrs(values), out, values)


def all_pairs_match(old, new):
    """compare.match as it was: score every pair."""
    pairs = []
    for o in old:
        for n in new:
            s = compare.score(o, n)
            if s is not None:
                pairs.append((-s, render.id_key(o["id"]), render.id_key(n["id"]), o, n))
    pairs.sort(key=lambda p: p[:3])
    taken_o, taken_n, out = set(), set(), []
    for _, _, _, o, n in pairs:
        if o["id"] not in taken_o and n["id"] not in taken_n:
            taken_o.add(o["id"])
            taken_n.add(n["id"])
            out.append((o, n))
    return out


class CompareCandidatesTest(unittest.TestCase):
    """match() scores only the pairs score() could accept; the pairing is unchanged."""

    def setUp(self):
        self.base = json.loads(SAMPLE.read_text(encoding="utf-8"))["findings"]

    def ids(self, pairs):
        return [(o["id"], n["id"]) for o, n in pairs]

    def test_same_pairs_as_scoring_every_pair(self):
        rnd = random.Random(7)
        for _ in range(60):
            old, new = copy.deepcopy(self.base), copy.deepcopy(self.base)
            for side in (old, new):
                rnd.shuffle(side)
                for f in side:
                    roll = rnd.random()
                    if roll < 0.15:
                        f["resources"] = [rnd.choice(["x.a", "x.b"])]
                    elif roll < 0.3:
                        f["title"] = f["title"].upper() + " ."
                    elif roll < 0.4:
                        f["location"] = "other.tf:1"
                    elif roll < 0.5 and "rule" in f:
                        f["rule"] = "SEC-001"
            # Copies under new IDs tie on score with their originals.
            new += [dict(f, id=f"F-{900 + k}") for k, f in enumerate(new[:3]) if f["id"].startswith("F-")]
            self.assertEqual(self.ids(compare.match(old, new)), self.ids(all_pairs_match(old, new)))

    def test_unhashable_values_fall_back_to_every_pair(self):
        bad = copy.deepcopy(self.base)
        bad[0]["rule"] = ["unhashable"]
        bad[1]["resources"] = [["unhashable"]]
        for old, new in ((bad, self.base), (self.base, bad), (bad, bad)):
            outcomes = []
            for fn in (compare.match, all_pairs_match):
                try:
                    outcomes.append(self.ids(fn(old, new)))
                except TypeError as e:
                    outcomes.append(repr(e))
            self.assertEqual(outcomes[0], outcomes[1])


if __name__ == "__main__":
    unittest.main()
