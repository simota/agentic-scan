import json
from pathlib import Path
import tempfile
import unittest

from helpers import SAMPLE_APP, contract_check, inventory, render, run, sample, write_json


class ContractTest(unittest.TestCase):
    def build(self, mutate=None, lang="en"):
        """A complete --no-pdf output directory from the sample, optionally changed before rendering."""
        out = Path(tempfile.mkdtemp())
        data = sample(lang)
        data["limitations"].append(contract_check.NO_PDF)
        if mutate:
            mutate(data)
        write_json(out / "findings.json", data)
        write_json(out / "inventory.json", inventory.scan(SAMPLE_APP))
        code, _, err = run(render.main, out / "findings.json", "--out", out, "--no-pdf", "--lang", lang)
        self.assertEqual(code, 0, err)
        return out

    def problems(self, out, *args):
        code, _, err = run(contract_check.main, out, "--no-pdf", *args)
        return code, err

    def test_samples_pass(self):
        for lang in ("en", "ja"):
            code, err = self.problems(self.build(lang=lang))
            self.assertEqual(code, 0, err)

    def test_perspective_names_come_from_the_reference(self):
        names = contract_check.perspective_names()
        self.assertEqual(len(names), 14)
        self.assertEqual(names[0], "Task and intent")
        self.assertEqual(names[-1], "Maintainability")

    def test_stale_render_is_reported(self):
        out = self.build()
        data = json.loads((out / "findings.json").read_text(encoding="utf-8"))
        data["checked_ok"].append("one more")
        write_json(out / "findings.json", data)
        code, err = self.problems(out)
        self.assertEqual(code, 1)
        self.assertIn("older findings.json", err)

    def test_violations(self):
        cases = [
            (lambda d: d["perspectives"].pop(), "'Maintainability' must be recorded"),
            (lambda d: d["findings"][7].update(id="F-010"), "without gaps"),
            (lambda d: d["findings"][0].update(severity="Low"), "severity order"),
            (lambda d: d["findings"][0].update(location="z.py:1"), "then path and line"),
            (lambda d: d["findings"][9].update(severity="High", validation={
                "verdict": "Unverified", "evidence": "", "method": "inventory.py lint"}), "L-002: a High finding needs a verdict"),
            (lambda d: d["findings"][2]["validation"].update(verdict="Unverified"), "other than Unverified"),
            (lambda d: d["findings"][5].pop("proposal"), "needs proposal.after"),
            (lambda d: d["findings"][0].pop("test"), "test (an eval"),
            (lambda d: d["findings"][0].update(category="Bugs"), "not a perspective name"),
            (lambda d: d["findings"][8].pop("source"), "come only from inventory.py"),
            (lambda d: d["findings"][2]["validation"].update(evidence="", verdict="Likely"), "needs validation.evidence"),
            (lambda d: d["limitations"].remove(contract_check.NO_EVAL), "no eval_runs"),
            (lambda d: d["meta"].pop("commit"), "meta.commit is missing"),
            (lambda d: d["perspectives"][5].update(note=""), "without a reason"),
        ]
        for mutate, message in cases:
            code, err = self.problems(self.build(mutate))
            self.assertEqual(code, 1, message)
            self.assertIn(message, err)

    def test_output_set(self):
        out = self.build()
        (out / "notes.md").write_text("x", encoding="utf-8")
        code, err = self.problems(out)
        self.assertIn("unexpected file notes.md", err)
        self.assertEqual(self.problems(out, "--allow", "notes.md")[0], 0)
        (out / "inventory.json").unlink()
        self.assertIn("missing output inventory.json", self.problems(out, "--allow", "notes.md")[1])

    def test_inventory_must_be_the_scanner_object(self):
        out = self.build()
        write_json(out / "inventory.json", [])
        code, err = self.problems(out)
        self.assertEqual(code, 1)
        self.assertIn("inventory.json was not written by inventory.py", err)

    def test_pdf_limitation_rules(self):
        out = self.build()
        code, _, err = run(contract_check.main, out)
        self.assertEqual(code, 1)
        self.assertIn("missing output report.pdf", err)
        self.assertIn("drop the limitation", err)

    def test_second_language_copy_is_checked(self):
        out = self.build()
        code, _, err = run(render.main, out / "findings.json", "--out", out / "ja", "--no-pdf", "--lang", "ja")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.problems(out, "--allow", "ja")[0], 0)
        (out / "ja" / "report.html").write_text("<html><head></head></html>", encoding="utf-8")
        self.assertIn("ja/report.html has no prompt-scan source stamp", self.problems(out, "--allow", "ja")[1])


if __name__ == "__main__":
    unittest.main()
