"""compare.py: pairing across runs, carried triage and the regression gate."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "logic-scan" / "scripts"))
import compare  # noqa: E402
import findings  # noqa: E402
import render  # noqa: E402

SAMPLE = json.loads((REPO / "examples" / "findings.sample.json").read_text(encoding="utf-8"))


def sample():
    return copy.deepcopy(SAMPLE)


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = compare.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CompareTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.dir.name)

    def tearDown(self):
        self.dir.cleanup()

    def write(self, name, doc):
        path = self.tmp / name
        path.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
        return path

    def compared(self, old, new, *extra):
        return run(str(self.write("old.json", old)), str(self.write("new.json", new)), *extra)

    def test_the_same_record_persists_unchanged(self):
        code, out, _ = self.compared(sample(), sample(), "--format", "json")
        self.assertEqual(code, 0)
        result = json.loads(out)
        self.assertEqual(result["summary"]["new"], 0)
        self.assertEqual(result["summary"]["resolved"], 0)
        self.assertEqual(result["summary"]["changed"], 0)
        self.assertGreater(result["summary"]["persisting"], 0)

    def test_pairs_by_content_when_ids_are_renumbered(self):
        old = sample()
        dropped = copy.deepcopy(old)
        dropped["findings"] = dropped["findings"][1:]
        new, mapping = findings.renumber(dropped)
        self.assertTrue(mapping)  # every later ID moved down by one
        result = json.loads(self.compared(old, new, "--format", "json")[1])
        self.assertEqual(result["summary"]["new"], 0)
        pairs = {p["earlier"]["id"]: p["later"]["id"] for p in result["persisting"]}
        for earlier, later in mapping.items():
            if earlier in pairs:
                self.assertEqual(pairs[earlier], later)

    def test_a_dropped_finding_is_resolved_and_an_added_one_new(self):
        old, new = sample(), sample()
        resolved = old["findings"][0]["title"]
        new["findings"] = new["findings"][1:]
        result = json.loads(self.compared(old, new, "--format", "json")[1])
        self.assertEqual([r["title"] for r in result["resolved"]], [resolved])
        result = json.loads(self.compared(new, old, "--format", "json")[1])
        self.assertEqual([n["title"] for n in result["new"]], [resolved])

    def test_ledger_status_changes_are_listed_by_idiom(self):
        old, new = sample(), sample()
        new["conventions"][0]["status"] = "drifted"
        result = json.loads(self.compared(old, new, "--format", "json")[1])
        self.assertEqual([(c["earlier"]["status"], c["later"]["status"]) for c in result["conventions"]],
                         [("holds", "drifted")])

    def test_accepted_is_carried_unless_the_severity_rose(self):
        old, new = sample(), sample()
        old["findings"][1]["status"] = "Accepted"
        old["findings"][2]["status"] = "Accepted"
        old["findings"][2]["severity"] = "Low"
        carry = self.tmp / "carry.json"
        code, _, err = self.compared(old, new, "--carry", str(carry), "--out", str(self.tmp / "cmp.md"))
        self.assertEqual(code, 0, err)
        fragment = json.loads(carry.read_text(encoding="utf-8"))
        self.assertEqual(fragment, {"findings": [{"id": new["findings"][1]["id"], "status": "Accepted"}]})

    def test_carried_triage_survives_merge_render_and_check(self):
        old = sample()
        old["findings"][1]["status"] = "Accepted"
        accepted = old["findings"][1]["id"]
        old["decisions"] = old.get("decisions", []) + [
            f"{accepted}は QA lead が受け入れた: the rounding stays until the Q3 migration",
            f"{accepted} and F-999 share a cause"]
        dropped = copy.deepcopy(old)
        dropped["findings"] = [f for f in dropped["findings"] if f["id"] != old["findings"][0]["id"]]
        dropped["findings"][0]["status"] = "Open"
        dropped["decisions"] = [item for item in dropped["decisions"] if accepted not in item]
        gone = old["findings"][0]["id"]
        for batch in dropped.get("plan", []):
            batch["findings"] = [fid for fid in batch["findings"] if fid != gone]
        dropped["plan"] = [batch for batch in dropped.get("plan", []) if batch["findings"]]
        for number, batch in enumerate(dropped["plan"], 1):
            batch["batch"] = number
        new, mapping = findings.renumber(dropped)
        later = mapping.get(accepted, accepted)
        out = self.tmp / "out"
        out.mkdir()
        record = out / "findings.json"
        record.write_text(json.dumps(new, ensure_ascii=False), encoding="utf-8")
        carry = self.tmp / "carry.json"
        code, _, err = run(str(self.write("old.json", old)), str(record), "--carry", str(carry),
                           "--out", str(self.tmp / "cmp.md"))
        self.assertEqual(code, 0, err)
        fragment = json.loads(carry.read_text(encoding="utf-8"))
        self.assertEqual(fragment["findings"], [{"id": later, "status": "Accepted"}])
        # The item naming F-999, which has no counterpart, is not carried with a stale ID.
        self.assertEqual(fragment["decisions"],
                         [f"{later}は QA lead が受け入れた: the rounding stays until the Q3 migration"])
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(findings.main(["merge", str(record), str(carry)]), 0)
            self.assertEqual(render.main([str(record), "--out", str(out)]), 0)
        self.assertEqual(findings.contract_problems(out), [])

    def test_the_gate_fails_on_a_new_or_reappeared_finding(self):
        old, new = sample(), sample()
        old["findings"] = old["findings"][1:]
        old["findings"][0]["status"] = "Fixed"
        code, _, err = self.compared(old, new, "--fail-on", "Medium")
        self.assertEqual(code, 3)
        self.assertIn(f"regression: new {new['findings'][0]['id']} [High]", err)
        self.assertIn(f"regression: reappeared {new['findings'][1]['id']}", err)
        self.assertEqual(self.compared(sample(), sample(), "--fail-on", "Info")[0], 0)

    def test_japanese_markdown(self):
        code, out, _ = self.compared(sample(), sample(), "--lang", "ja")
        self.assertEqual(code, 0)
        self.assertIn("# 診断の比較", out)
        self.assertIn("## ロジックルール台帳", out)


if __name__ == "__main__":
    unittest.main()
