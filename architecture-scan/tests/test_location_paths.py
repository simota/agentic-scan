"""A finding's location names a file, so a path that shows nothing fails check.

The schema still accepts such a record: merge validates the existing record
before it applies a fragment, so refusing it there would leave no correction
but a hand edit. `check` names it, and a fragment that sends the location
again corrects it.
"""
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_architecture_scan import complete_doc, findings, render


class BlankPathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.target = self.tmp / "findings.json"

    def problems(self, doc):
        self.target.write_text(json.dumps(doc), encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(render.main([str(self.target), "--out", str(self.tmp)]), 0)
        return findings.contract_problems(self.tmp)

    def test_a_location_whose_path_shows_nothing_fails_check(self):
        for path in (" ", "　", "​", " \t"):
            with self.subTest(path=path):
                doc = complete_doc()
                doc["findings"][1]["location"] = ["worker/job.py:4", f"{path}:3"]
                problems = self.problems(doc)
                self.assertIn(f"A-002: location {path + ':3'!r} names no file; give its "
                              "path from the repository root", problems)

    def test_a_named_path_passes_and_a_fragment_corrects_a_blank_one(self):
        doc = complete_doc()
        self.assertFalse([p for p in self.problems(doc) if "names no file" in p])
        doc["findings"][1]["location"] = " :3"
        self.target.write_text(json.dumps(doc), encoding="utf-8")
        fragment = self.tmp / "fix.json"
        fragment.write_text(json.dumps({"findings": [
            {"id": "A-002", "location": "worker/job.py:3"}]}), encoding="utf-8")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(findings.main(["merge", str(self.target), str(fragment)]), 0)
        fragment.unlink()
        corrected = json.loads(self.target.read_text(encoding="utf-8"))
        self.assertFalse([p for p in self.problems(corrected) if "names no file" in p])


if __name__ == "__main__":
    unittest.main()
