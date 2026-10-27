"""A finding ID in the record's prose names a recorded finding.

renumber reads every whole-word `A-NNN` in prose as a mention of a finding, so
one that no finding holds is a stale or mistyped reference: `check` names it,
and renumber refuses to give that ID to another finding, which would silently
make the mention point at it.
"""
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_architecture_scan import architecture, complete_doc, finding, findings, render


class MentionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.target = self.tmp / "findings.json"

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = findings.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def problems(self, doc):
        self.target.write_text(json.dumps(doc), encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            render.main([str(self.target), "--out", str(self.tmp)])
        return findings.contract_problems(self.tmp)

    def test_a_mention_of_no_recorded_finding_fails_check(self):
        doc = complete_doc()
        doc["next_steps"] = ["Fix A-001 first, then A-101"]
        doc["decisions"] = ["Confirm A-042 with the billing owner"]
        doc["findings"][1]["trace"] = "1. Same writer as A-001 and A-007"
        doc["rules"][0]["statement"] = "One writer (see A-003)"
        problems = self.problems(doc)
        self.assertIn("next_steps[0]: mentions A-101, which no finding holds; name a "
                      "recorded finding (after renumber, only the new IDs)", problems)
        for where, fid in (("decisions[0]", "A-042"), ("A-002.trace", "A-007"),
                           ("R-01.statement", "A-003")):
            self.assertTrue(any(p.startswith(f"{where}: mentions {fid},") for p in problems),
                            (where, problems))
        self.assertFalse(any("A-001, which" in p for p in problems), problems)

    def test_literals_and_other_tokens_are_not_mentions(self):
        doc = complete_doc()
        doc["meta"]["scope"] = "Follow-up to the run that reported A-104"
        doc["checked_ok"] = ["JIRA-A-101 and docs/A-101.md hold; see "
                             "https://tracker.example/browse?key=A-101 and A-0012"]
        doc["rules"][0]["source"] = "docs/adr/A-101.md:3"
        doc["findings"][1]["references"] = [{"url": "https://x.example/A-101", "title": "Ticket"}]
        doc["findings"][1]["validation"] = {"verdict": "Likely", "method": "analysed",
                                            "evidence": "job.py:58"}
        doc["findings"][1]["analysis"] = {"tool": "grep", "command": "grep -rn A-101 .",
                                          "result": "2 writers"}
        self.assertEqual(self.problems(doc), [])

    def test_a_merge_after_renumber_that_names_an_old_block_id_fails_check(self):
        doc = complete_doc()
        doc["findings"] = [finding("A-101", rule="R-01"), finding("A-201", "Low")]
        doc["architecture"] = architecture("A-101")
        self.target.write_text(json.dumps(doc), encoding="utf-8")
        self.assertEqual(self.run_cli("renumber", str(self.target))[0], 0)
        # Fragments live in scratch, never in the output directory.
        scratch = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, scratch)
        late = scratch / "late.json"
        late.write_text(json.dumps({"next_steps": ["Fix A-101 before the release"]}),
                        encoding="utf-8")
        self.assertEqual(self.run_cli("merge", str(self.target), str(late))[0], 0)
        with redirect_stdout(io.StringIO()):
            render.main([str(self.target), "--out", str(self.tmp)])
        code, _, err = self.run_cli("check", str(self.tmp))
        self.assertEqual(code, 1)
        self.assertIn("next_steps[0]: mentions A-101, which no finding holds", err)

    def test_renumber_refuses_to_give_a_stale_mention_a_finding(self):
        doc = complete_doc()
        doc["findings"] = [finding("A-101", rule="R-01"), finding("A-201", "Low")]
        # A-001 is held by no finding now, but would name A-101 after renumber.
        doc["next_steps"] = ["Fix A-001 first"]
        self.target.write_text(json.dumps(doc), encoding="utf-8")
        before = self.target.read_bytes()
        code, out, err = self.run_cli("renumber", str(self.target))
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("next_steps[0] mentions A-001, which no finding holds", err)
        self.assertEqual(self.target.read_bytes(), before)

    def test_renumber_keeps_a_stale_mention_no_new_id_takes(self):
        doc = complete_doc()
        doc["findings"] = [finding("A-101", rule="R-01"), finding("A-201", "Low")]
        doc["next_steps"] = ["Fix A-101, then A-150"]
        doc["architecture"] = architecture("A-101")
        self.target.write_text(json.dumps(doc), encoding="utf-8")
        self.assertEqual(self.run_cli("renumber", str(self.target))[0], 0)
        self.assertEqual(findings.read_json(self.target)["next_steps"], ["Fix A-001, then A-150"])
        problems = self.problems(findings.read_json(self.target))
        self.assertTrue(any(p.startswith("next_steps[0]: mentions A-150,") for p in problems),
                        problems)

    def test_duplicate_evidence_names_its_finding_as_a_mention(self):
        # renumber rewrites only a whole-word ID, so evidence joining the ID to
        # its label (`ofA-001`) would keep the old ID after a renumber.
        for evidence, accepted in (("Duplicate of A-001", True), ("Duplicates A-001.", True),
                                   ("重複:A-001", True), ("重複: A-001。", True),
                                   ("Duplicate ofA-001", False), ("DuplicatesA-001", False)):
            match = findings.DUPLICATE_OF.fullmatch(evidence)
            self.assertEqual(bool(match), accepted, evidence)
            if match:
                self.assertEqual(findings._rewrite_ids(evidence, {"A-001": "A-002"}),
                                 evidence.replace("A-001", "A-002"))


if __name__ == "__main__":
    unittest.main()
