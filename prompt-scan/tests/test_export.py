import json
from pathlib import Path
import tempfile
import unittest

from helpers import clone, export, run, sample, write_json


class ExportTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.path = self.dir / "findings.json"
        self.data = sample()
        write_json(self.path, self.data)

    def export(self, *args, data=None):
        if data is not None:
            write_json(self.path, data)
        return run(export.main, args[0], self.path, *args[1:])

    def test_exported_leaves_out_excluded_and_fixed_findings(self):
        data = clone(self.data)
        data["findings"][0]["status"] = "Fixed"
        data["findings"][1]["validation"] = {"verdict": "FalsePositive", "evidence": "x", "method": "static"}
        ids = [f["id"] for f in export.exported(data, "Info")]
        self.assertEqual(len(ids), 9)
        self.assertNotIn(data["findings"][0]["id"], ids)
        self.assertEqual([f["severity"] for f in export.exported(data, "Medium")], ["Medium"] * 4)

    def test_summary_follows_the_chat_format(self):
        code, out, err = self.export("summary")
        self.assertEqual(code, 0, err)
        first = out.splitlines()[0]
        self.assertTrue(first.startswith("11 findings (8 defects, 3 improvements): High 2, Medium 4, Low 5, Info 0."))
        self.assertIn("Static review only.", first)
        self.assertIn("[High][defect][Confirmed] Template variable context is never filled", out)
        self.assertIn("  verdict: Valid — ", out)
        for heading in ("## Checked and sound", "## Decisions for a human", "## Next steps", "## Limitations"):
            self.assertIn(heading, out)
        code, out, _ = self.export("summary", "--lang", "ja")
        self.assertIn("## 確認して問題がなかった項目", out)

    def test_summary_names_high_findings_not_yet_valid(self):
        data = clone(self.data)
        data["findings"][0]["validation"]["verdict"] = "Likely"
        _, out, _ = self.export("summary", data=data)
        self.assertIn(f"High findings not yet Valid: {data['findings'][0]['id']}", out.splitlines()[0])

    def test_sarif_shape(self):
        out = self.dir / "out" / "x.sarif"
        out.parent.mkdir()
        code, _, err = self.export("sarif", "--out", out)
        self.assertEqual(code, 0, err)
        doc = json.loads(out.read_text())
        self.assertEqual(doc["version"], "2.1.0")
        run_ = doc["runs"][0]
        results = run_["results"]
        self.assertEqual(len(results), 11)
        rules = run_["tool"]["driver"]["rules"]
        self.assertEqual(len({r["id"] for r in rules}), len(rules))
        for r in results:
            self.assertEqual(rules[r["ruleIndex"]]["id"], r["ruleId"])
            region = r["locations"][0]["physicalLocation"]["region"]
            self.assertGreaterEqual(region["startLine"], 1)
        first = results[0]
        self.assertEqual((first["level"], first["properties"]["id"]), ("error", "F-001"))
        ranged = next(r for r in results if r["properties"]["id"] == "F-004")
        self.assertEqual(ranged["locations"][0]["physicalLocation"]["region"], {"startLine": 5, "endLine": 6})
        lint = next(r for r in results if r["properties"]["id"].startswith("L-"))
        self.assertTrue(lint["ruleId"].startswith("prompt-scan/lint/"))

    def test_sarif_fingerprint_survives_renumbering_and_line_moves(self):
        a = export.exported(self.data, "Info")[0]
        b = dict(a, id="F-042", location="app/llm/answer.py:40")
        self.assertEqual(export.fingerprint(a), export.fingerprint(b))
        self.assertNotEqual(export.fingerprint(a), export.fingerprint(dict(a, title="other")))

    def test_sarif_accepted_finding_is_suppressed(self):
        data = clone(self.data)
        data["findings"][0]["status"] = "Accepted"
        _, out, _ = self.export("sarif", data=data)
        result = json.loads(out)["runs"][0]["results"][0]
        self.assertEqual(result["suppressions"][0]["status"], "accepted")

    def test_issues_fill_the_template(self):
        out = self.dir / "issues"
        code, _, err = self.export("issues", "--out", out)
        self.assertEqual(code, 0, err)
        names = sorted(p.name for p in out.iterdir())
        self.assertEqual(len(names), 12)
        self.assertIn("index.md", names)
        body = (out / "F-001.md").read_text()
        self.assertNotIn("{{", body.replace("{{ context }}", ""))
        self.assertNotIn("<!--", body)
        self.assertIn("| Severity | High |", body)
        self.assertNotIn("| Revision |", body, "a row with only empty fields is dropped")
        self.assertNotIn("## Proposal", body, "a defect without a proposal has no proposal section")
        self.assertIn("{{ context }}", body, "field values are not treated as template fields")
        improvement = (out / "F-006.md").read_text()
        self.assertIn("## Proposal", improvement)
        self.assertIn("(F-001.md)", (out / "index.md").read_text())

    def test_issues_in_japanese(self):
        out = self.dir / "issues"
        code, _, _ = self.export("issues", "--out", out, "--lang", "ja", data=sample("ja"))
        self.assertEqual(code, 0)
        self.assertIn("## 症状", (out / "F-001.md").read_text())

    def test_issues_need_an_output_directory(self):
        with self.assertRaises(SystemExit):
            run(export.main, "issues", self.path)

    def test_fail_on_gates_open_findings_only(self):
        self.assertEqual(self.export("sarif", "--fail-on", "High")[0], 1)
        data = clone(self.data)
        for f in data["findings"]:
            if f["severity"] == "High":
                f["status"] = "Accepted"
        code, _, _ = self.export("sarif", "--fail-on", "High", data=data)
        self.assertEqual(code, 0)
        self.assertEqual(self.export("summary", "--fail-on", "Medium", data=data)[0], 1)
        self.assertEqual(self.export("summary", "--fail-on", "Medium", "--min-severity", "High", data=data)[0], 0)

    def test_refuses_to_overwrite_the_record(self):
        code, _, err = self.export("summary", "--out", self.path)
        self.assertEqual(code, 2)
        self.assertIn("findings file itself", err)
        self.assertEqual(json.loads(self.path.read_text()), self.data)

    def test_refuses_a_symlinked_target(self):
        target = self.dir / "elsewhere.txt"
        target.write_text("keep")
        (self.dir / "link.sarif").symlink_to(target)
        code, _, _ = self.export("sarif", "--out", self.dir / "link.sarif")
        self.assertEqual(code, 2)
        self.assertEqual(target.read_text(), "keep")

    def test_masks_credential_shaped_text(self):
        data = clone(self.data)
        data["findings"][0]["symptom"] = "uses ghp_" + "b" * 40
        for fmt in ("summary", "sarif"):
            _, out, _ = self.export(fmt, data=data)
            self.assertNotIn("b" * 40, out)


if __name__ == "__main__":
    unittest.main()
