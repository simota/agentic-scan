"""inventory.py as a CI lint: --fail-on, --sarif and --baseline, with no review run."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from helpers import SAMPLE_APP, inventory, run, sample, write_json


class LintCiTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.repo = self.dir / "repo"
        shutil.copytree(SAMPLE_APP, self.repo)

    def test_fail_on_prints_hits_and_writes_nothing_to_stdout(self):
        code, out, err = run(inventory.main, self.repo, "--fail-on", "High")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("app/llm/prompts/answer.prompt:4: High unfilled-variable: 1 variable(s) not filled where "
                      "app/llm/answer.py:14 renders it: context", err)
        self.assertIn("app/llm/answer.py:23: High unrequested-output-key: ", err)
        self.assertNotIn("unclosed-tag", err)
        self.assertIn("2 lint hit(s) at High or above", err)

    def test_clean_repository_passes(self):
        clean = self.dir / "clean"
        (clean / "prompts").mkdir(parents=True)
        (clean / "prompts" / "a.md").write_text("Hi {name}\n", encoding="utf-8")
        (clean / "app.py").write_text('x = open("prompts/a.md").read().format(name=1)\n', encoding="utf-8")
        self.assertEqual(run(inventory.main, clean, "--fail-on", "Info")[0], 0)

    def test_sarif(self):
        path = self.dir / "lint.sarif"
        code, out, err = run(inventory.main, self.repo, "--sarif", path)
        self.assertEqual((code, out), (0, ""), err)
        doc = json.loads(path.read_text(encoding="utf-8"))
        results = doc["runs"][0]["results"]
        self.assertEqual([r["ruleId"] for r in results][:2],
                         ["prompt-scan/lint/unrequested-output-key", "prompt-scan/lint/unfilled-variable"])
        self.assertEqual(results[1]["locations"][0]["physicalLocation"]["region"], {"startLine": 4})
        self.assertEqual(doc["runs"][0]["properties"]["target"], "repo")
        # --sarif must not overwrite another input or output.
        self.assertEqual(run(inventory.main, self.repo, "--out", path, "--sarif", path)[0], 2)

    def test_baseline_suppresses_reviewed_false_positives_after_lines_move(self):
        review = sample()
        for f in review["findings"]:
            if f.get("rule") == "unclosed-tag":
                f["validation"] = {"verdict": "FalsePositive", "evidence": "closed later", "method": "read"}
        baseline = self.dir / "findings.json"
        write_json(baseline, review)
        prompt = self.repo / "app" / "llm" / "prompts" / "support_system.md"
        prompt.write_text("\n\n" + prompt.read_text(encoding="utf-8"), encoding="utf-8")
        code, _, err = run(inventory.main, self.repo, "--fail-on", "Low", "--baseline", baseline)
        self.assertEqual(code, 1)
        self.assertNotIn("unclosed-tag", err)
        self.assertIn("support_system.md:9: Low placeholder", err)
        self.assertIn("1 hit(s) suppressed by reviewed verdicts", err)
        # A verdict kept from an earlier review across a rescan still counts.
        for f in review["findings"]:
            if f.get("rule") == "unclosed-tag":
                f["previous_validation"], f["validation"] = f["validation"], {
                    "verdict": "Unverified", "evidence": "", "method": "inventory.py lint"}
        write_json(baseline, review)
        self.assertNotIn("unclosed-tag", run(inventory.main, self.repo, "--fail-on", "Low", "--baseline", baseline)[2])
        # A different tag in the same file is a different hit.
        prompt.write_text(prompt.read_text(encoding="utf-8") + "<rules>\n", encoding="utf-8")
        self.assertIn("<rules> opened", run(inventory.main, self.repo, "--fail-on", "Low", "--baseline", baseline)[2])

    def test_unreadable_baseline(self):
        bad = self.dir / "bad.json"
        bad.write_text("{", encoding="utf-8")
        code, _, err = run(inventory.main, self.repo, "--fail-on", "High", "--baseline", bad)
        self.assertEqual(code, 2, err)


if __name__ == "__main__":
    unittest.main()
