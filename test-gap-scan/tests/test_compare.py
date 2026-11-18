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
sys.path.insert(0, str(REPO / "skills" / "test-gap-scan" / "scripts"))
import compare  # noqa: E402
import findings  # noqa: E402

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

    def test_the_decision_naming_an_accepted_finding_is_carried_under_the_later_id(self):
        old = sample()
        old["findings"][1]["status"] = "Accepted"
        accepted = old["findings"][1]["id"]
        old["decisions"] += [f"{accepted}は QA lead が受け入れた: the gateway mock stays until Q3",
                             f"{accepted} and F-999 share a cause"]
        dropped = copy.deepcopy(old)
        dropped["findings"] = [f for f in dropped["findings"] if f["id"] != old["findings"][0]["id"]]
        dropped["findings"][0]["status"] = "Open"
        dropped["decisions"] = []
        new, mapping = findings.renumber(dropped)
        later = mapping[accepted]
        carry = self.tmp / "carry.json"
        code, _, err = self.compared(old, new, "--carry", str(carry), "--out", str(self.tmp / "cmp.md"))
        self.assertEqual(code, 0, err)
        fragment = json.loads(carry.read_text(encoding="utf-8"))
        self.assertEqual(fragment["findings"], [{"id": later, "status": "Accepted"}])
        # The item naming F-999, which has no counterpart, is not carried with a stale ID.
        self.assertEqual(fragment["decisions"],
                         [f"{later}は QA lead が受け入れた: the gateway mock stays until Q3"])
        merged = findings.merge(new, fragment, "carry")
        self.assertEqual(next(f for f in merged["findings"] if f["id"] == later)["status"], "Accepted")

    def test_a_testability_change_is_listed(self):
        old, new = sample(), sample()
        new["findings"][1]["testability"] = "Seam"
        result = json.loads(self.compared(old, new, "--format", "json")[1])
        changed = [c for p in result["persisting"] for c in p["changes"]]
        self.assertEqual(changed, [{"field": "testability", "earlier": old["findings"][1]["testability"],
                                    "later": "Seam"}])

    def test_the_gate_fails_on_a_new_or_reappeared_finding(self):
        old, new = sample(), sample()
        old["findings"] = old["findings"][1:]
        old["findings"][0]["status"] = "Fixed"
        code, _, err = self.compared(old, new, "--fail-on", "Medium")
        self.assertEqual(code, 3)
        self.assertIn(f"regression: new {new['findings'][0]['id']} [High]", err)
        self.assertIn(f"regression: reappeared {new['findings'][1]['id']}", err)
        self.assertEqual(self.compared(sample(), sample(), "--fail-on", "Info")[0], 0)

    def test_unreadable_or_mistyped_records_exit_1_with_a_schema_reason(self):
        good = self.write("good.json", sample())
        cases = {
            "empty file": b"",
            "not JSON": b"{findings: [",
            "duplicate key": b'{"meta": {}, "meta": {}}',
            "a list, not a record": b"[]",
            "findings is not a list": json.dumps(dict(sample(), findings="F-001")).encode(),
            "a finding is not an object": json.dumps(dict(sample(), findings=["F-001"])).encode(),
            "an unknown severity": json.dumps(dict(sample(), findings=[
                dict(sample()["findings"][0], severity="Critical")])).encode(),
        }
        for label, data in cases.items():
            for side in ("old", "new"):
                with self.subTest(label, side=side):
                    bad = self.tmp / "bad.json"
                    bad.write_bytes(data)
                    argv = (str(bad), str(good)) if side == "old" else (str(good), str(bad))
                    code, out, err = run(*argv)
                    self.assertEqual(code, 1, err)
                    self.assertTrue(err.startswith("schema: "), err)
                    self.assertEqual(out, "")

    def test_a_missing_record_exits_1(self):
        code, _, err = run(str(self.tmp / "absent.json"), str(self.write("good.json", sample())))
        self.assertEqual(code, 1)
        self.assertIn("schema: ", err)

    def test_zero_findings_on_either_side(self):
        empty = sample()
        empty["findings"], empty["plan"] = [], []
        empty["decisions"] = [d for d in empty.get("decisions", []) if "F-" not in d]
        result = json.loads(self.compared(empty, empty, "--format", "json")[1])
        self.assertEqual(result["summary"], {"new": 0, "resolved": 0, "persisting": 0, "changed": 0,
                                             "reappeared": 0, "now_excluded": 0, "now_reported": 0})
        result = json.loads(self.compared(empty, sample(), "--format", "json")[1])
        self.assertEqual(result["summary"]["new"],
                         sum(f["validation"]["verdict"] not in compare.EXCLUDED for f in sample()["findings"]))
        self.assertEqual(self.compared(empty, sample(), "--fail-on", "Info")[0], 3)

    def test_japanese_markdown(self):
        code, out, _ = self.compared(sample(), sample(), "--lang", "ja")
        self.assertEqual(code, 0)
        self.assertIn("# 診断の比較", out)
        self.assertIn("## イディオム台帳", out)


if __name__ == "__main__":
    unittest.main()
