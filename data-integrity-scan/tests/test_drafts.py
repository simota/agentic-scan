"""Offline tests for scripts/drafts.py: issue and plan drafts filled from the record."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parent.parent
SCRIPTS = REPO / "skills" / "data-scan" / "scripts"
SAMPLE = REPO / "examples" / "findings.sample.json"
sys.path.insert(0, str(SCRIPTS))
sys.dont_write_bytecode = True

import drafts  # noqa: E402


def sample():
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


class Drafts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_drafts(self, doc, *args, out=None):
        record = self.root / "run" / "findings.json"
        record.parent.mkdir(exist_ok=True)
        record.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
        out = out or self.root / "drafts"
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = drafts.main([str(record), "--out", str(out), *args])
        return code, out, err.getvalue()

    def test_every_template_placeholder_is_known(self):
        for lang in ("en", "ja"):
            self.assertEqual(drafts.unknown_placeholders(lang), [], lang)

    def test_sample_drafts_fill_every_placeholder(self):
        for lang in ("en", "ja"):
            with self.subTest(lang):
                code, out, err = self.run_drafts(sample(), "--lang", lang, out=self.root / lang)
                self.assertEqual(code, 0, err)
                names = sorted(p.name for p in out.iterdir())
                self.assertEqual(names, [f"issue-F-00{i}.md" for i in range(1, 5)] + ["plan.md"])
                for path in out.iterdir():
                    text = path.read_text(encoding="utf-8")
                    self.assertNotIn("{{", text, path.name)
                    self.assertNotIn("<!--", text, path.name)

    def test_plan_keeps_batch_order_and_defers_unplanned_low_findings(self):
        code, out, _ = self.run_drafts(sample(), "--lang", "en")
        self.assertEqual(code, 0)
        plan = (out / "plan.md").read_text(encoding="utf-8")
        order = [plan.index(f"### {fid}:") for fid in ("F-002", "F-001", "F-003")]
        self.assertEqual(order, sorted(order))
        deferred = plan.split("## Deferred", 1)[1]
        self.assertIn("F-004: ", deferred)
        self.assertNotIn("F-005", plan)
        self.assertIn("- <to fill in>", plan.split("## Batch", 1)[0])

    def test_a_section_left_empty_drops_its_done_when_item(self):
        code, out, _ = self.run_drafts(sample(), "--lang", "en")
        self.assertEqual(code, 0)
        with_invariants = (out / "issue-F-001.md").read_text(encoding="utf-8")
        without = (out / "issue-F-004.md").read_text(encoding="utf-8")
        self.assertIn("## Invariants", with_invariants)
        self.assertIn("Every invariant above", with_invariants)
        self.assertNotIn("## Invariants", without)
        self.assertNotIn("Every invariant above", without)
        self.assertIn("## Done when", without)

    def test_japanese_lists_code_spans_with_the_ideographic_comma(self):
        code, out, _ = self.run_drafts(sample(), "--lang", "ja")
        self.assertEqual(code, 0)
        issue = (out / "issue-F-001.md").read_text(encoding="utf-8")
        self.assertIn("<code>app/admin/customers&#95;controller.rb:42</code>、<code>db/schema.rb:88</code>", issue)

    def test_missing_optional_fields_read_none(self):
        code, out, _ = self.run_drafts(sample(), "--lang", "en")
        self.assertEqual(code, 0)
        plan = (out / "plan.md").read_text(encoding="utf-8")
        f003 = plan.split("### F-003:", 1)[1].split("##", 1)[0]
        self.assertIn("- **Depends on:** none", f003)
        self.assertIn("- **Convention:** none", f003)

    def test_an_empty_site_list_reads_a_dash_and_keeps_the_line(self):
        doc = sample()
        doc["findings"][0]["enforcement"]["sites"] = []
        code, out, err = self.run_drafts(doc, "--lang", "en", "--id", "F-001")
        self.assertEqual(code, 0, err)
        plan = (out / "plan.md").read_text(encoding="utf-8")
        f001 = plan.split("### F-001:", 1)[1].split("###", 1)[0]
        self.assertIn("; sites —; gaps ", f001)

    def test_recorded_text_cannot_open_a_link_or_break_a_table(self):
        doc = sample()
        doc["findings"][0]["hazard"] = "[x](javascript:alert(1)) | cell"
        code, out, err = self.run_drafts(doc, "--lang", "en", "--id", "F-001")
        self.assertEqual(code, 0, err)
        issue = (out / "issue-F-001.md").read_text(encoding="utf-8")
        row = next(line for line in issue.splitlines() if line.startswith("| Hazard"))
        self.assertNotIn("](", row)
        self.assertEqual(row.count("|"), 3)

    def test_fixed_and_accepted_findings_are_not_drafted_by_default(self):
        doc = sample()
        doc["findings"][2]["status"] = "Fixed"
        doc["findings"][3]["status"] = "Accepted"
        code, out, _ = self.run_drafts(doc)
        self.assertEqual(code, 0)
        self.assertEqual(sorted(p.name for p in out.glob("issue-*")),
                         ["issue-F-001.md", "issue-F-002.md"])

    def test_refusals(self):
        cases = {
            "excluded": (sample(), ["--id", "F-005"], None, "never filed"),
            "unknown id": (sample(), ["--id", "F-099"], None, "not in the record"),
            "run directory": (sample(), [], self.root / "run", "output directory"),
        }
        for name, (doc, args, out, message) in cases.items():
            with self.subTest(name):
                code, _, err = self.run_drafts(doc, *args, out=out)
                self.assertEqual(code, 2)
                self.assertIn(message, err)

    def test_ids_must_be_final(self):
        doc = sample()
        first, second = doc["findings"][0], doc["findings"][1]
        first["id"], second["id"] = "F-002", "F-001"
        for batch in doc["plan"]:
            batch["findings"] = [{"F-001": "F-002", "F-002": "F-001"}.get(i, i) for i in batch["findings"]]
        for f in doc["findings"]:
            f["depends_on"] = [{"F-001": "F-002", "F-002": "F-001"}.get(i, i) for i in f.get("depends_on", [])]
        code, _, err = self.run_drafts(doc)
        self.assertEqual(code, 2)
        self.assertIn("renumber", err)

    def test_drafts_load_without_scan_report_kit(self):
        probe = ("import builtins, sys\n"
                 "real = builtins.__import__\n"
                 "def guard(name, *a, **k):\n"
                 "    if name.startswith('scan_report_kit'):\n"
                 "        raise ImportError('scan_report_kit is not allowed here')\n"
                 "    return real(name, *a, **k)\n"
                 "builtins.__import__ = guard\n"
                 f"sys.path.insert(0, {str(SCRIPTS)!r})\n"
                 "import drafts\n")
        result = subprocess.run([sys.executable, "-I", "-B", "-c", probe], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
