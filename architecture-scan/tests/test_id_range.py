"""A record holds at most 999 findings, and every cause of reordering needs a renumber."""
import io
import json
import re
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_architecture_scan import SKILL, complete_doc, finding, findings


class FindingLimitTests(unittest.TestCase):
    def thousand(self):
        # Unique three-digit IDs allow a thousandth finding only as A-000.
        return [finding(f"A-{n:03d}", location=[f"a{n}.py:1"]) for n in range(1000)]

    def test_merge_never_writes_a_record_renumber_cannot_number(self):
        with tempfile.TemporaryDirectory() as d:
            target, fragment = Path(d) / "findings.json", Path(d) / "frag.json"
            fragment.write_text(json.dumps({"findings": self.thousand()}), encoding="utf-8")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err:
                code = findings.main(["merge", str(target), str(fragment)])
            self.assertEqual(code, 1)
            self.assertIn("more than 999", err.getvalue())
            self.assertFalse(target.exists())

    def test_999_findings_including_a_000_still_renumber(self):
        # A record an earlier version merged with A-000 can still be put right.
        doc = {"findings": self.thousand()[:999]}
        findings.validate(doc)
        renamed, _ = findings.renumber(doc)
        self.assertEqual(renamed["findings"][0]["id"], "A-001")
        self.assertEqual(renamed["findings"][-1]["id"], "A-999")


class RenumberInstructionTests(unittest.TestCase):
    def test_moving_a_finding_needs_a_renumber_and_the_docs_say_so(self):
        doc = complete_doc()
        doc["findings"].append(finding("A-003", "Low", location=["zzz/last.py:1"]))
        findings.merge(doc, {"findings": [{"id": "A-003", "location": ["aaa/first.py:1"]}]}, "f")
        renamed, _ = findings.renumber(doc)
        self.assertNotEqual([f["location"] for f in renamed["findings"]],
                            [f["location"] for f in doc["findings"]])
        # Every instruction to renumber names relocation beside the other causes.
        for name in ("SKILL.md", "reference/findings-schema.md"):
            text = " ".join((SKILL / name).read_text(encoding="utf-8").split())
            for match in re.finditer(r"(?:added|adds), (regrad\w+)(,? \w+)? or exclud", text):
                with self.subTest(file=name, text=match[0]):
                    self.assertRegex(match[0], "relocat")


if __name__ == "__main__":
    unittest.main()
