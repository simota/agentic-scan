"""export.py: SARIF, Markdown issue drafts and CSV from a checked findings.json."""

import contextlib
import copy
import csv
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "ux-scan" / "scripts"))

import export  # noqa: E402

SAMPLE = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
FLOWS = (ROOT / "examples" / "flows.sample.json").read_text(encoding="utf-8")


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.dir))
        self.review = self.dir / "review"
        self.review.mkdir()
        (self.review / "flows.json").write_text(FLOWS, encoding="utf-8")
        self.record = self.write(SAMPLE)

    def write(self, data):
        path = self.review / "findings.json"
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return path

    def run_export(self, *args, out=None):
        out = str(out or self.dir / "out")
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = export.main([args[0], str(self.record), "--out", out, *args[1:]])
        return code, stdout.getvalue(), stderr.getvalue()

    def output(self):
        return (self.dir / "out").read_text(encoding="utf-8")

    def test_sarif_has_one_result_per_open_or_accepted_counted_finding(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"][1]["status"] = "Accepted"
        data["findings"][2]["status"] = "Fixed"
        self.write(data)
        code, out, err = self.run_export("sarif", "--prefix", "examples/tasklane")
        self.assertEqual(code, 0, err)
        sarif = json.loads(self.output())
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        expected = [f["id"] for f in data["findings"]
                    if f["validation"]["verdict"] not in ("FalsePositive", "NotApplicable")
                    and f["status"] in ("Open", "Accepted")]
        self.assertEqual([r["properties"]["id"] for r in run["results"]], expected)
        rules = run["tool"]["driver"]["rules"]
        for result in run["results"]:
            self.assertEqual(rules[result["ruleIndex"]]["id"], result["ruleId"])
        first = run["results"][0]
        self.assertEqual(first["level"], "error")
        location = first["locations"][0]["physicalLocation"]
        self.assertEqual(location["artifactLocation"]["uri"], "examples/tasklane/src/components/AddTaskModal.tsx")
        self.assertEqual(location["region"], {"startLine": 11, "endLine": 11})
        accepted = next(r for r in run["results"] if r["properties"]["id"] == data["findings"][1]["id"])
        self.assertEqual(accepted["suppressions"][0]["status"], "accepted")
        signup = accepted["relatedLocations"][0]["physicalLocation"]["region"]
        self.assertEqual(signup["startLine"], 19)

    def test_sarif_fingerprints_survive_renumbering_and_line_moves(self):
        self.run_export("sarif")
        before = {r["properties"]["id"]: r["partialFingerprints"] for r in json.loads(self.output())["runs"][0]["results"]}
        data = copy.deepcopy(SAMPLE)
        data["findings"][0]["location"] = "src/components/AddTaskModal.tsx:40"
        self.write(data)
        self.run_export("sarif")
        after = {r["properties"]["id"]: r["partialFingerprints"] for r in json.loads(self.output())["runs"][0]["results"]}
        self.assertEqual(before, after)
        self.assertEqual(len({fp["uxScanFinding/v1"] for fp in after.values()}), len(after))

    def test_sarif_tells_findings_with_one_title_and_file_apart(self):
        data = copy.deepcopy(SAMPLE)
        twin = data["findings"][2]
        data["findings"][3].update(perspective=twin["perspective"], title=twin["title"])
        self.write(data)
        self.run_export("sarif")
        prints = [r["partialFingerprints"]["uxScanFinding/v1"] for r in json.loads(self.output())["runs"][0]["results"]]
        self.assertEqual(len(set(prints)), len(prints))

    def test_markdown_drafts_one_issue_per_open_finding_with_tags_escaped(self):
        code, out, err = self.run_export("markdown", "--min-severity", "High")
        self.assertEqual(code, 0, err)
        text = self.output()
        high = [f for f in SAMPLE["findings"] if f["severity"] == "High"]
        self.assertEqual(text.count("\n## ["), len(high))
        self.assertIn("## [U-001] Saving a new task discards the typed title", text)
        self.assertIn("- [ ] **U-006** High:", text)
        # Quoted JSX in observed stays visible instead of being parsed as HTML.
        self.assertIn("&lt;button onClick={onClose}>Save&lt;/button>", text)
        self.assertNotIn("<button", text)
        self.assertIn("`U-001-source.log` (before)", text)

    def test_markdown_in_japanese_and_with_selected_ids(self):
        code, _, err = self.run_export("markdown", "--lang", "ja", "--ids", "U-003, U-010")
        self.assertEqual(code, 0, err)
        text = self.output()
        self.assertIn("UX診断 課題一覧", text)
        self.assertEqual(text.count("\n## ["), 2)
        self.assertIn("### 完了条件", text)

    def test_markdown_keeps_code_spans_literal(self):
        self.assertEqual(export.prose("Use `<label>` & not <span>"), "Use `<label>` &amp; not &lt;span>")
        self.assertEqual(export.prose("```html\n<div>\n```\n<p>"), "```html\n<div>\n```\n&lt;p>")

    def test_csv_lists_every_finding_and_quotes_formula_cells(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"][0]["title"] = "=HYPERLINK(\"http://x\")"
        data["findings"][1]["fix"] = "+1 then @SUM"
        self.write(data)
        code, _, err = self.run_export("csv")
        self.assertEqual(code, 0, err)
        text = self.output()
        self.assertTrue(text.startswith("﻿id,title,severity"))
        rows = list(csv.DictReader(io.StringIO(text.lstrip("﻿"))))
        self.assertEqual([r["id"] for r in rows], [f["id"] for f in data["findings"]])
        self.assertEqual(rows[0]["title"], "'=HYPERLINK(\"http://x\")")
        self.assertEqual(rows[1]["fix"], "'+1 then @SUM")
        self.assertEqual(rows[-1]["verdict"], "FalsePositive")
        self.assertEqual(rows[1]["occurrences"], "src/components/SignupForm.tsx:18\nsrc/components/SignupForm.tsx:19")

    def test_stdout_output(self):
        code, out, _ = self.run_export("csv", out="-")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("﻿id,"))

    def test_refuses_to_replace_review_outputs_and_inputs(self):
        for name in ("findings.json", "flows.json", "report.html", "inventory.json"):
            code, _, err = self.run_export("csv", out=self.review / name)
            self.assertEqual(code, 2, name)
            self.assertIn("export.py:", err)
        (self.review / "evidence").mkdir()
        code, _, err = self.run_export("csv", out=self.review / "evidence" / "x.csv")
        self.assertEqual(code, 2)
        self.assertIn("evidence/", err)
        link = self.dir / "link.csv"
        link.symlink_to(self.dir / "elsewhere.csv")
        code, _, err = self.run_export("csv", out=link)
        self.assertEqual(code, 2)
        self.assertFalse((self.dir / "elsewhere.csv").exists())

    def test_a_file_inside_the_review_directory_names_the_allow_flag(self):
        code, out, _ = self.run_export("sarif", out=self.review / "ux.sarif")
        self.assertEqual(code, 0)
        self.assertIn("--allow ux.sarif", out)

    def test_refuses_an_invalid_record_unknown_ids_and_bad_prefixes(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"][0]["severity"] = "Critical"
        self.write(data)
        self.assertEqual(self.run_export("csv")[0], 2)
        self.write(SAMPLE)
        code, _, err = self.run_export("markdown", "--ids", "U-999")
        self.assertEqual(code, 2)
        self.assertIn("U-999", err)
        for prefix in ("/abs", "../up", "a\\b"):
            self.assertEqual(self.run_export("sarif", "--prefix", prefix)[0], 2, prefix)
        self.assertEqual(self.run_export("csv", "--prefix", "x")[0], 2)
        self.assertFalse((self.dir / "out").exists())


if __name__ == "__main__":
    unittest.main()
