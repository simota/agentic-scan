"""After the review: recording triage, carrying it into a re-run, and gating regressions."""
import copy
import json
from pathlib import Path

from test_architecture_scan import SKILL, findings, import_module, render
from test_handoff_tools import TempDir, run, sample

compare = import_module(SKILL / "scripts" / "compare.py", "arch_compare")
drafts = import_module(SKILL / "scripts" / "drafts.py", "arch_drafts")
sarif = import_module(SKILL / "scripts" / "sarif.py", "arch_sarif")

ISSUE = "https://github.com/acme/shop/issues/12"


class OutDir(TempDir):
    def rendered(self, doc=None, name="out"):
        """A rendered output directory that passes the run contract."""
        out = self.tmp / name
        out.mkdir()
        (out / "findings.json").write_text(json.dumps(doc or sample(), ensure_ascii=False),
                                           encoding="utf-8")
        self.assertEqual(run(render.main, str(out / "findings.json"), "--out", str(out))[0], 0)
        return out

    def record(self, out):
        return json.loads((out / "findings.json").read_text(encoding="utf-8"))


class SchemaTests(TempDir):
    def test_status_note_and_issue_are_checked(self):
        for key, value, message in (("status_note", " ", "status_note: must be a nonblank"),
                                    ("issue", 12, "issue: must be a nonblank"),
                                    ("issue", "https://x/1 https://x/2", "one URL")):
            with self.subTest(key=key, value=value):
                doc = sample()
                doc["findings"][0][key] = value
                with self.assertRaisesRegex(findings.SchemaError, message):
                    findings.validate(doc, complete=True)

    def test_renumber_rewrites_a_note_but_never_the_issue_url(self):
        doc = sample()
        doc["findings"][0]["severity"] = "Low"  # A-001 moves behind A-002 and A-003
        doc["findings"][0]["status_note"] = "Waits for A-002"
        doc["findings"][0]["issue"] = "https://tracker.example/browse/A-002"
        renamed, mapping = findings.renumber(doc)
        moved = next(f for f in renamed["findings"] if f["title"] == doc["findings"][0]["title"])
        self.assertEqual(moved["status_note"], f"Waits for {mapping['A-002']}")
        self.assertEqual(moved["issue"], "https://tracker.example/browse/A-002")


class RenderTests(TempDir):
    def test_both_outputs_show_the_reason_and_link_the_issue(self):
        doc = sample()
        doc["findings"][1].update(status="Accepted", status_note="Replays are rare; Q1 rewrite",
                                  issue=ISSUE)
        outputs = render.rendered_outputs(doc, "en")
        md, html = outputs["report.md"].decode(), outputs["dashboard.html"].decode()
        self.assertIn("- **status:** Accepted\n- **status reason:** Replays are rare; Q1 rewrite\n"
                      f"- **tracked in:** [https&#58;//github.com/acme/shop/issues/12](<{ISSUE}>)",
                      md)
        self.assertIn("<dt>status reason</dt><dd>Replays are rare; Q1 rewrite</dd>", html)
        self.assertIn(f"<dt>tracked in</dt><dd><a href='{ISSUE}' rel='noopener noreferrer'>", html)
        ja = render.rendered_outputs(doc, "ja")["report.md"].decode()
        self.assertIn("- **ステータスの理由:** Replays are rare", ja)
        self.assertIn("- **管理先:** [", ja)

    def test_an_issue_that_is_not_a_web_url_is_never_a_link(self):
        doc = sample()
        doc["findings"][0]["issue"] = "javascript:alert(1)"
        outputs = render.rendered_outputs(doc, "en")
        self.assertIn("- **tracked in:** <code>javascript:alert(1)</code>",
                      outputs["report.md"].decode())
        self.assertNotIn("href='javascript:", outputs["dashboard.html"].decode())

    def test_a_record_without_the_new_fields_renders_as_before(self):
        # Only a finding that records them gets the rows.
        md = render.rendered_outputs(sample(), "en")["report.md"].decode()
        self.assertNotIn("status reason", md)
        self.assertNotIn("tracked in", md)


class TriageTests(OutDir):
    def test_accept_with_reason_and_issue_rerenders_and_keeps_the_contract(self):
        out = self.rendered()
        code, stdout, err = run(findings.main, "triage", str(out / "findings.json"), "A-002,A-003",
                                "--status", "Accepted", "--note", "Q1 rewrite; see A-001",
                                "--issue", f" {ISSUE} ")
        self.assertEqual(code, 0, err)
        self.assertIn(f"A-002: Accepted · reason: Q1 rewrite; see A-001 · tracked in {ISSUE}", stdout)
        self.assertIn("re-rendered", stdout)
        doc = self.record(out)
        for f in doc["findings"][1:]:
            self.assertEqual((f["status"], f["status_note"], f["issue"]),
                             ("Accepted", "Q1 rewrite; see A-001", ISSUE))
        self.assertEqual(doc["findings"][0].get("status"), "Open")
        self.assertEqual(run(findings.main, "check", str(out))[0], 0)

    def test_accepted_needs_a_reason(self):
        out = self.rendered()
        before = (out / "findings.json").read_bytes()
        code, _, err = run(findings.main, "triage", str(out / "findings.json"), "A-001",
                           "--status", "Accepted")
        self.assertEqual(code, 1)
        self.assertIn("Accepted needs --note", err)
        self.assertEqual((out / "findings.json").read_bytes(), before)

    def test_an_older_accepted_finding_without_a_reason_can_still_get_its_issue(self):
        doc = sample()
        doc["findings"][0]["status"] = "Accepted"
        out = self.rendered(doc)
        code, _, err = run(findings.main, "triage", str(out / "findings.json"), "A-001",
                           "--issue", ISSUE)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.record(out)["findings"][0]["issue"], ISSUE)

    def test_reopening_drops_the_old_reason_and_empty_values_remove(self):
        out = self.rendered()
        target = str(out / "findings.json")
        run(findings.main, "triage", target, "A-001", "--status", "Fixed", "--note", "PR 40",
            "--issue", ISSUE)
        self.assertEqual(run(findings.main, "triage", target, "A-001", "--status", "Open",
                             "--issue", "")[0], 0)
        f = self.record(out)["findings"][0]
        self.assertEqual(f["status"], "Open")
        self.assertNotIn("status_note", f)
        self.assertNotIn("issue", f)
        self.assertEqual(run(findings.main, "check", str(out))[0], 0)

    def test_refusals_write_nothing(self):
        doc = sample()
        doc["findings"][2]["validation"] = {"verdict": "NotApplicable", "method": "static",
                                            "evidence": "Duplicate of A-001"}
        out = self.rendered(doc)
        target = str(out / "findings.json")
        before = (out / "findings.json").read_bytes()
        for argv, message in (
                (("A-009", "--status", "Fixed"), "A-009 is not a recorded finding"),
                (("A-003", "--status", "Fixed"), "A-003 is excluded"),
                (("A-001",), "nothing to record"),
                (("A-001", "--note", "after A-077"), "status_note names A-077")):
            with self.subTest(argv=argv):
                code, _, err = run(findings.main, "triage", target, *argv)
                self.assertEqual(code, 1)
                self.assertIn(message, err)
                self.assertEqual((out / "findings.json").read_bytes(), before)
        code, _, err = run(findings.main, "triage", target, "B-1", "--status", "Fixed")
        self.assertEqual(code, 2)
        self.assertIn("finding IDs such as A-001", err)

    def test_no_render_or_no_outputs_leaves_rendering_to_the_caller(self):
        out = self.rendered()
        dashboard = (out / "dashboard.html").read_bytes()
        code, stdout, _ = run(findings.main, "triage", str(out / "findings.json"), "A-001",
                              "--status", "Fixed", "--no-render")
        self.assertEqual(code, 0)
        self.assertIn("render again:", stdout)
        self.assertEqual((out / "dashboard.html").read_bytes(), dashboard)
        self.assertEqual(run(findings.main, "check", str(out))[0], 1)  # stale until rendered
        alone = self.tmp / "alone"
        alone.mkdir()
        (alone / "findings.json").write_text(json.dumps(sample()), encoding="utf-8")
        self.assertEqual(run(findings.main, "triage", str(alone / "findings.json"), "A-001",
                             "--status", "Fixed")[0], 0)
        self.assertEqual(sorted(p.name for p in alone.iterdir()), ["findings.json"])

    def test_a_missing_record_is_refused_without_creating_it(self):
        code, _, err = run(findings.main, "triage", str(self.tmp / "none" / "findings.json"),
                           "A-001", "--status", "Fixed")
        self.assertEqual(code, 1)
        self.assertFalse((self.tmp / "none").exists())


class HandoffTests(TempDir):
    def triaged(self):
        doc = sample()
        doc["findings"][0]["issue"] = ISSUE
        doc["findings"][1].update(status="Accepted", status_note="Replays are rare")
        return doc

    def test_drafts_skip_a_tracked_finding_and_the_owner_report_links_it(self):
        files, skipped = drafts.drafts(self.triaged(), "en")
        self.assertEqual(set(files), {"A-003.md", "owner-report.md"})
        self.assertEqual(skipped, [("A-001", f"tracked in {ISSUE}"), ("A-002", "Accepted")])
        report = files["owner-report.md"]
        self.assertIn(f"- **Tracked in:** [https&#58;//github.com/acme/shop/issues/12](<{ISSUE}>)",
                      report)
        self.assertIn("- **Tracked in:** <issue URL>", report)  # A-002: none recorded
        ja = drafts.drafts(self.triaged(), "ja")[0]["owner-report.md"]
        self.assertIn("- **管理先:** <issue の URL>", ja)

    def test_sarif_justifies_a_suppression_with_the_recorded_reason(self):
        results = sarif.sarif(self.triaged())["runs"][0]["results"]
        accepted = next(r for r in results if r["properties"]["findingId"] == "A-002")
        self.assertEqual(accepted["suppressions"][0]["justification"], "Replays are rare")
        self.assertEqual(accepted["properties"]["statusNote"], "Replays are rare")
        tracked = next(r for r in results if r["properties"]["findingId"] == "A-001")
        self.assertEqual(tracked["properties"]["issue"], ISSUE)
        self.assertNotIn("suppressions", tracked)


class CarryTests(OutDir):
    def earlier(self):
        doc = sample()
        doc["findings"][0]["issue"] = ISSUE
        doc["findings"][1].update(status="Accepted", status_note="Replays are rare; see A-001")
        doc["findings"][2].update(status="Accepted")
        return doc

    def later(self):
        doc = sample()
        doc["meta"].update(date="2026-11-07", commit="9b1d2e0")
        return doc

    def carried(self, old, new):
        return compare.carry(compare.compare(old, new), old, new)

    def test_accepted_and_issues_are_carried_with_ids_rewritten(self):
        old, new = self.earlier(), self.later()
        # The later run numbers the same findings differently.
        new["findings"][0]["id"], new["findings"][1]["id"] = "A-002", "A-001"
        new["findings"].sort(key=lambda f: f["id"])
        fragment, lines = self.carried(old, new)
        by_id = {u["id"]: u for u in fragment["findings"]}
        self.assertEqual(by_id["A-002"], {"id": "A-002", "issue": ISSUE})
        self.assertEqual(by_id["A-001"], {"id": "A-001", "status": "Accepted",
                                          "status_note": "Replays are rare; see A-002"})
        self.assertEqual(by_id["A-003"]["status_note"],
                         "Accepted in the earlier assessment (2026-10-09, 0000000); "
                         "no reason was recorded")
        self.assertIn("carried A-002 → A-001: Accepted", lines)

    def test_an_unpaired_mention_is_named_as_earlier(self):
        old, new = self.earlier(), self.later()
        new["findings"] = new["findings"][1:]  # A-001 not found again
        fragment, _ = self.carried(old, new)
        note = next(u for u in fragment["findings"] if u["id"] == "A-002")["status_note"]
        self.assertEqual(note, "Replays are rare; see earlier-A-001")
        merged = copy.deepcopy(new)
        findings.merge(merged, fragment, "carry")
        self.assertNotIn("A-002.status_note", {where for where, _ in findings.unknown_mentions(merged)})

    def test_a_raised_severity_reopens_the_decision_and_fixed_is_never_carried(self):
        old, new = self.earlier(), self.later()
        old["findings"][0]["status"] = "Fixed"
        new["findings"][1]["severity"] = "High"
        fragment, lines = self.carried(old, new)
        self.assertEqual([u["id"] for u in fragment["findings"]], ["A-001", "A-003"])
        self.assertNotIn("status", fragment["findings"][0])  # Fixed found again stays Open
        self.assertIn("not carried A-002 → A-002: Accepted as Medium, now High; decide again", lines)

    def test_the_later_records_own_triage_wins(self):
        old, new = self.earlier(), self.later()
        new["findings"][1].update(status="Fixed", status_note="PR 41")
        new["findings"][0]["issue"] = "https://github.com/acme/shop/issues/99"
        fragment, _ = self.carried(old, new)
        self.assertEqual([u["id"] for u in fragment["findings"]], ["A-003"])

    def test_cli_writes_a_fragment_that_merges_and_passes_the_contract(self):
        old_path = self.write("old.json", self.earlier())
        out = self.rendered(self.later())
        carry = self.tmp / "carry.json"
        code, stdout, err = run(compare.main, str(old_path), str(out / "findings.json"),
                                "--carry", str(carry))
        self.assertEqual(code, 0, err)
        self.assertIn("# Assessment comparison", stdout)
        self.assertIn("3 finding(s) to update", err)  # stdout holds only the comparison
        self.assertEqual(run(findings.main, "merge", str(out / "findings.json"), str(carry))[0], 0)
        self.assertEqual(run(render.main, str(out / "findings.json"), "--out", str(out))[0], 0)
        self.assertEqual(run(findings.main, "check", str(out))[0], 0)
        self.assertEqual([f.get("status") for f in self.record(out)["findings"]],
                         ["Open", "Accepted", "Accepted"])


class GateTests(TempDir):
    def gate(self, old, new, threshold):
        return run(compare.main, str(self.write("old.json", old)), str(self.write("new.json", new)),
                   "--fail-on", threshold)

    def test_no_regression_passes(self):
        self.assertEqual(self.gate(sample(), sample(), "Info")[0], 0)

    def test_new_reappeared_reported_again_and_raised_findings_fail(self):
        old, new = sample(), sample()
        old["findings"] = old["findings"][1:]  # A-001 (High) is new
        old["findings"][0]["status"] = "Fixed"  # A-002 reappears
        old["findings"][1]["validation"] = {"verdict": "FalsePositive", "method": "static",
                                            "evidence": "a.py:3 is dead"}
        code, _, err = self.gate(old, new, "Low")
        self.assertEqual(code, 3)
        self.assertIn("regression: new A-001 [High]", err)
        self.assertIn("regression: reappeared A-002 [Medium]", err)
        self.assertIn("regression: reported again A-003 [Low]", err)
        # A threshold above them all lets the Medium and Low ones through.
        code, _, err = self.gate(old, new, "High")
        self.assertEqual(code, 3)
        self.assertNotIn("A-002", err)

    def test_severity_rising_to_the_threshold_fails(self):
        old, new = sample(), sample()
        new["findings"][1]["severity"] = "High"
        code, _, err = self.gate(old, new, "High")
        self.assertEqual(code, 3)
        self.assertIn("severity rose A-002 Medium → High", err)
        self.assertEqual(self.gate(old, new, "Medium")[0], 0)  # already at or above it

    def test_outputs_are_written_before_the_gate_fails(self):
        old, new = sample(), sample()
        old["findings"] = old["findings"][1:]
        report = self.tmp / "cmp.md"
        code, _, _ = run(compare.main, str(self.write("o.json", old)), str(self.write("n.json", new)),
                         "--fail-on", "High", "--out", str(report))
        self.assertEqual(code, 3)
        self.assertTrue(Path(report).read_text(encoding="utf-8").startswith("# Assessment comparison"))


if __name__ == "__main__":
    import unittest
    unittest.main()
