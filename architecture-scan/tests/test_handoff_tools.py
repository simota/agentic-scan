"""Issue and owner-report drafts, assessment comparison and SARIF export."""
import copy
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_architecture_scan import (REPO, SKILL, complete_doc, finding, findings, import_module,
                                    render)

drafts = import_module(SKILL / "scripts" / "drafts.py", "arch_drafts")
compare = import_module(SKILL / "scripts" / "compare.py", "arch_compare")
sarif = import_module(SKILL / "scripts" / "sarif.py", "arch_sarif")
SAMPLE = REPO / "examples" / "findings.sample.json"


def sample():
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


def run(main, *argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TempDir(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def write(self, name, doc):
        path = self.tmp / name
        path.write_text(json.dumps(doc), encoding="utf-8")
        return path


class DraftTests(TempDir):
    def test_every_placeholder_is_filled_in_both_languages(self):
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                files, skipped = drafts.drafts(sample(), lang)
                self.assertEqual(set(files), {"A-001.md", "A-002.md", "A-003.md", "owner-report.md"})
                self.assertEqual(skipped, [])
                for name, text in files.items():
                    self.assertNotRegex(text, r"\{\{[a-z_.\[\]]+\}\}", name)
                    self.assertTrue(text.endswith("\n") and not text.endswith("\n\n"), name)

    def test_shared_cache_and_parsed_template_change_no_draft(self):
        # drafts() fills each finding once for its issue and the owner report;
        # the drafts must match filling every one afresh.
        doc = sample()
        for lang in ("ja", "en"):
            with self.subTest(lang=lang):
                files, _ = drafts.drafts(doc, lang)
                issue = (drafts.TEMPLATES / f"issue.{lang}.md").read_text(encoding="utf-8")
                report = (drafts.TEMPLATES / f"report.{lang}.md").read_text(encoding="utf-8")
                for f in doc["findings"]:
                    self.assertEqual(files[f"{f['id']}.md"], drafts.issue_draft(f, doc, lang, issue))
                self.assertEqual(files["owner-report.md"], drafts.owner_report(doc, lang, report))
        self.assertEqual(sample(), doc)  # nothing in the record was changed

    def test_issue_carries_the_record_fields(self):
        doc = sample()
        text = drafts.drafts(doc, "en")[0]["A-001.md"]
        f = doc["findings"][0]
        self.assertTrue(text.startswith(f"**Title:** [High] {f['title']} (A-001)"))
        self.assertIn("| Perspective | Domain model and data ownership (DM1) |", text)
        self.assertIn("<code>worker/refunds/job.py:58</code>, <code>api/billing/service.py:120</code>", text)
        # The cited rule carries its statement and source, as the template asks.
        self.assertIn("R-01: Only the billing module writes invoices (source: docs/adr/0004-billing.md:12)", text)
        # One numbered step per line.
        self.assertRegex(text, r"\n1\. worker/refunds/job\.py:58 [^\n]*\n2\. api/billing")
        # Fill notes are gone; the open questions stay for a person.
        self.assertNotIn("Copy each", text)
        self.assertNotIn("if Environment-dependent", text)
        self.assertIn("## Open questions", text)
        self.assertIn("## Done when", text)

    def test_empty_optional_fields_drop_their_line_or_section(self):
        doc = complete_doc()
        f = doc["findings"][1]
        del f["step"]
        f["validation"] = {"verdict": "Likely", "method": "static"}
        text = drafts.drafts(doc, "en")[0]["A-002.md"]
        self.assertIn("| Perspective | Domain model and data ownership |", text)
        self.assertNotIn("ownership ()", text)
        self.assertIn("## Trace\n\njob.py:58 updates invoices\n", text)
        self.assertNotIn("Violated rule", text)
        self.assertNotIn("Contrast", text)
        self.assertNotIn("## Evidence", text)
        self.assertNotIn("## References", text)
        self.assertIn("| Assessed revision | UNKNOWN |", text)

    def test_references_and_analysis_are_listed(self):
        doc = complete_doc()
        f = doc["findings"][0]
        f["references"] = [{"url": "https://example.com/adr/4", "title": "ADR 4"},
                           {"url": "javascript:alert(1)"}]
        f["analysis"] = {"tool": "import-linter", "command": "lint-imports", "result": "1 broken"}
        text = drafts.drafts(doc, "en")[0]["A-001.md"]
        self.assertIn("- [ADR 4](<https://example.com/adr/4>)", text)
        self.assertIn("- <code>javascript:alert(1)</code>", text)
        self.assertIn("import-linter <code>lint-imports</code> → 1 broken", text)

    def test_excluded_and_closed_findings_are_never_drafted(self):
        doc = complete_doc()
        doc["findings"][0]["status"] = "Fixed"
        doc["findings"][1]["validation"] = {"verdict": "FalsePositive", "method": "static",
                                            "evidence": "job.py:58 is dead code"}
        files, skipped = drafts.drafts(doc, "en")
        self.assertEqual(set(files), {"owner-report.md"})
        self.assertEqual(skipped, [("A-001", "Fixed"), ("A-002", "FalsePositive")])
        # The owner report still counts the fixed one, as its template says.
        self.assertIn("Fixed 1", files["owner-report.md"])

    def test_owner_report_fills_counts_findings_diagrams_and_lists(self):
        text = drafts.drafts(sample(), "en")[0]["owner-report.md"]
        self.assertIn("**Subject:** [Architecture report] acme-shop (fictional) — 1 High / 1 Medium "
                      "(2026-10-09)", text)
        self.assertIn("| High | 1 | 1 |", text)
        self.assertIn("### A-001: Refund job writes", text)
        self.assertIn("### A-002: Shipment consumer", text)
        self.assertNotIn("### A-003", text)  # Low stays in the attached report.md
        self.assertEqual(text.count("```mermaid"), 2)
        self.assertIn("- Removed edge: worker/refunds → invoices (raw UPDATE · A-001)", text)
        self.assertIn("1. Fix A-001 and add the single-writer check to CI", text)
        self.assertIn("- **R-04** Public API responses", text)
        # What only a person can write stays a note for them.
        self.assertIn("<!-- Conclusion first", text)
        self.assertIn("<!-- If GUARD ran", text)
        self.assertIn("<issue URL>", text)

    def test_mermaid_matches_report_md(self):
        doc = sample()
        report = render.render_markdown(doc, "en")
        blocks = re.findall(r"```mermaid\n.*?```", report, re.DOTALL)
        owner = drafts.drafts(doc, "en")[0]["owner-report.md"]
        self.assertEqual(blocks, re.findall(r"```mermaid\n.*?```", owner, re.DOTALL))

    def test_cli_writes_drafts_and_flags_what_needs_a_person(self):
        out = self.tmp / "drafts"
        code, stdout, _ = run(drafts.main, str(SAMPLE), "--out", str(out))
        self.assertEqual(code, 0)
        self.assertEqual(sorted(p.name for p in out.iterdir()),
                         ["A-001.md", "A-002.md", "A-003.md", "owner-report.md"])
        self.assertIn("todo A-002: Likely / Environment-dependent", stdout)
        self.assertNotIn("todo A-001", stdout)

    def test_cli_only_and_its_refusals(self):
        out = self.tmp / "drafts"
        code, _, _ = run(drafts.main, str(SAMPLE), "--out", str(out), "--only", "A-003")
        self.assertEqual(code, 0)
        self.assertEqual(sorted(p.name for p in out.iterdir()), ["A-003.md", "owner-report.md"])
        code, _, err = run(drafts.main, str(SAMPLE), "--out", str(out), "--only", "A-009")
        self.assertEqual(code, 1)
        self.assertIn("A-009 is not a recorded finding", err)
        with self.assertRaises(SystemExit):
            run(drafts.main, str(SAMPLE), "--out", str(out), "--only", "R-01")

    def test_cli_names_stale_drafts(self):
        out = self.tmp / "drafts"
        out.mkdir()
        (out / "A-007.md").write_text("old", encoding="utf-8")
        code, _, err = run(drafts.main, str(SAMPLE), "--out", str(out))
        self.assertEqual(code, 0)
        self.assertIn("A-007.md is from an earlier run", err)
        self.assertTrue((out / "A-007.md").exists())  # named, never deleted

    def test_invalid_record_exits_2_and_writes_nothing(self):
        doc = complete_doc()
        doc["findings"][0]["severity"] = "Critical"
        out = self.tmp / "drafts"
        code, _, err = run(drafts.main, str(self.write("f.json", doc)), "--out", str(out))
        self.assertEqual(code, 2)
        self.assertIn("schema:", err)
        self.assertFalse(out.exists())

    @unittest.skipUnless(shutil.which("pandoc"), "pandoc is not installed")
    def test_hostile_text_stays_text(self):
        doc = complete_doc()
        f = doc["findings"][0]
        hostile = "[x](javascript:alert(1)) <script>a</script> bob@example.com | cell"
        for key in ("title", "impact", "trace", "fix", "guard", "scenario"):
            f[key] = hostile
        f["trace"] = "1. # heading\n2. - item " + hostile
        doc["next_steps"] = ["# not a heading", hostile]
        for name, text in drafts.drafts(doc, "en")[0].items():
            with self.subTest(name=name):
                html = subprocess.run(["pandoc", "-f", "gfm", "-t", "html"], input=text,
                                      capture_output=True, text=True, encoding="utf-8",
                                      check=True, timeout=60).stdout
                self.assertNotRegex(html, r"<a (?!href=\"#cb[0-9]+-[0-9]+\" aria-hidden)|<script|<h[1-6][^>]*>not")
                self.assertNotIn("<h1", html.split("Trace")[-1] if "Trace" in html else html)


class TraceStepTests(unittest.TestCase):
    def test_numbered_steps_split_on_the_sequence_only(self):
        self.assertEqual(drafts.trace_steps("1. a calls b 2. b writes v1.2 3. done"),
                         ["a calls b", "b writes v1.2", "done"])
        self.assertEqual(drafts.trace_steps("one step only"), ["one step only"])
        self.assertEqual(drafts.trace_steps("see 2. later"), ["see 2. later"])
        self.assertEqual(drafts.trace_steps("1. a\n2. b"), ["a", "b"])
        self.assertEqual(drafts.trace_steps("first line\nsecond line"), ["first line", "second line"])


def rescan():
    """The sample assessed again: A-001 fixed, A-002 regraded, one new finding."""
    old, new = sample(), sample()
    old["findings"][1]["status"] = "Fixed"
    new["meta"].update(commit="1111111", date="2026-11-05")
    del new["findings"][0]
    new["findings"][0]["severity"] = "High"
    for i, f in enumerate(new["findings"], 1):
        f["id"] = f"A-{i:03d}"  # renumbered, as renumber would
    added = finding("A-003", "Low", title="Orders module imports billing internals",
                    location=["api/orders/cancel.py:41"], category="Coupling", step="CP1")
    new["findings"].append(added)
    new["rules"][0]["status"] = "holds"
    return old, new


class CompareTests(TempDir):
    def test_pairs_by_content_not_by_id(self):
        old, new = rescan()
        result = compare.compare(old, new)
        self.assertEqual([f["id"] for f in result["new"]], ["A-003"])
        self.assertEqual([f["id"] for f in result["resolved"]], ["A-001"])
        pairs = {(o["id"], n["id"]): (diff, reappeared)
                 for o, n, diff, reappeared in result["persisting"]}
        # Renumbered: the old A-002 is the new A-001.
        self.assertEqual(set(pairs), {("A-002", "A-001"), ("A-003", "A-002")})
        diff, reappeared = pairs[("A-002", "A-001")]
        self.assertTrue(reappeared)
        self.assertIn(("severity_f", "Medium", "High"), diff)
        self.assertEqual(pairs[("A-003", "A-002")], ([], False))
        self.assertEqual([(o["status"], n["status"]) for o, n in result["rules"]],
                         [("violated", "holds")])

    def test_a_reworded_title_still_pairs_by_file_and_perspective(self):
        old, new = sample(), sample()
        new["findings"][2]["title"] = "Pricing domain reaches the ORM directly"
        new["findings"][2]["location"] = ["api/pricing/domain/discounts.py:9"]
        result = compare.compare(old, new)
        self.assertEqual(result["new"], [])
        self.assertEqual(result["resolved"], [])

    def test_unrelated_findings_in_one_file_do_not_pair(self):
        old, new = complete_doc(), complete_doc()
        new["findings"][1].update(title="Another problem", category="Testability", step="TS1")
        new["findings"][1].pop("rule", None)
        old["findings"][1].pop("rule", None)
        result = compare.compare(old, new)
        self.assertEqual([f["title"] for f in result["new"]], ["Another problem"])

    def test_exclusion_moves_are_their_own_lists(self):
        old, new = sample(), sample()
        new["findings"][2]["validation"] = {"verdict": "NotApplicable", "method": "static",
                                            "evidence": "discounts.py:3 is generated"}
        result = compare.compare(old, new)
        self.assertEqual([(o["id"], n["id"]) for o, n in result["now_excluded"]], [("A-003", "A-003")])
        self.assertEqual(result["resolved"], [])
        result = compare.compare(new, old)
        self.assertEqual([(o["id"], n["id"]) for o, n in result["now_reported"]], [("A-003", "A-003")])

    def test_markdown_and_json_outputs(self):
        old, new = rescan()
        old_path, new_path = self.write("old.json", old), self.write("new.json", new)
        code, text, _ = run(compare.main, str(old_path), str(new_path))
        self.assertEqual(code, 0)
        self.assertIn("**A-001** [High][Likely] Shipment consumer", text)
        self.assertIn("1 new, 1 resolved, 2 persisting (1 changed, 1 reappeared after Fixed)", text)
        self.assertIn("| High | 1 | 1 | +0 |", text)
        self.assertIn("| Medium | 1 | 0 | -1 |", text)
        self.assertIn("reappeared: the earlier record marks it Fixed", text)
        self.assertIn("Not finding a problem again is not proof", text)
        code, text, _ = run(compare.main, str(old_path), str(new_path), "--lang", "ja")
        self.assertIn("新規 1 件、解消 1 件", text)
        code, text, _ = run(compare.main, str(old_path), str(new_path), "--format", "json")
        data = json.loads(text)
        self.assertEqual(data["summary"]["reappeared"], 1)
        self.assertEqual(data["persisting"][0]["changes"][0]["field"], "severity")
        out = self.tmp / "cmp" / "comparison.md"
        code, _, _ = run(compare.main, str(old_path), str(new_path), "--out", str(out))
        self.assertEqual(code, 0)
        self.assertTrue(out.read_text(encoding="utf-8").startswith("# Assessment comparison"))

    def test_scope_change_is_named_beside_resolved(self):
        old, new = rescan()
        new["meta"]["scope"] = "api/ only"
        code, text, _ = run(compare.main, str(self.write("o.json", old)),
                            str(self.write("n.json", new)))
        self.assertIn("The scopes differ", text)

    def test_an_invalid_record_is_refused(self):
        doc = complete_doc()
        del doc["meta"]["lang"]
        code, _, err = run(compare.main, str(self.write("o.json", doc)), str(SAMPLE))
        self.assertEqual(code, 1)
        self.assertIn("schema:", err)

    def test_records_are_not_changed(self):
        old, new = rescan()
        paths = self.write("o.json", old), self.write("n.json", new)
        before = [p.read_bytes() for p in paths]
        run(compare.main, *map(str, paths))
        self.assertEqual(before, [p.read_bytes() for p in paths])


class SarifTests(TempDir):
    def test_results_levels_and_rules(self):
        data = sarif.sarif(sample())
        self.assertEqual(data["version"], "2.1.0")
        run_ = data["runs"][0]
        results = run_["results"]
        self.assertEqual([r["properties"]["findingId"] for r in results], ["A-001", "A-002", "A-003"])
        self.assertEqual([r["level"] for r in results], ["error", "warning", "note"])
        self.assertEqual([r["ruleId"] for r in results], ["DM1", "TX2", "BL1"])
        self.assertEqual({d["id"] for d in run_["tool"]["driver"]["rules"]}, {"DM1", "TX2", "BL1"})
        first = results[0]
        self.assertEqual(first["locations"][0]["physicalLocation"],
                         {"artifactLocation": {"uri": "worker/refunds/job.py"},
                          "region": {"startLine": 58}})
        self.assertEqual(first["relatedLocations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                         "api/billing/service.py")
        self.assertEqual(first["properties"]["designRules"][0]["id"], "R-01")
        self.assertEqual(run_["automationDetails"]["id"], "architecture-scan/")

    def test_left_out_and_suppressed(self):
        doc = sample()
        doc["findings"][0]["status"] = "Fixed"
        doc["findings"][1]["status"] = "Accepted"
        doc["findings"][2]["validation"]["verdict"] = "Unlikely"
        results = sarif.sarif(doc)["runs"][0]["results"]
        self.assertEqual([r["properties"]["findingId"] for r in results], ["A-002"])
        self.assertEqual(results[0]["suppressions"][0]["status"], "accepted")
        self.assertEqual(len(sarif.sarif(sample(), min_severity="Medium")["runs"][0]["results"]), 2)

    def test_fingerprint_is_stable_across_renumbering_and_lines(self):
        doc = sample()
        moved = copy.deepcopy(doc)
        moved["findings"][0]["id"] = "A-009"
        moved["findings"][0]["location"] = ["worker/refunds/job.py:61"]
        prints = [sarif.sarif(d)["runs"][0]["results"][0]["partialFingerprints"] for d in (doc, moved)]
        self.assertEqual(prints[0], prints[1])

    def test_uris_are_relative_and_encoded(self):
        self.assertEqual(sarif.uri("./src/my file.py", None), "src/my%20file.py")
        self.assertEqual(sarif.uri("src\\win\\a.py", None), "src/win/a.py")
        repo = self.tmp / "repo"
        (repo / "a").mkdir(parents=True)
        self.assertEqual(sarif.uri(str(repo / "a" / "b.py"), str(repo)), "a/b.py")
        self.assertTrue(sarif.uri("/elsewhere/b.py", str(repo)).startswith("file:///elsewhere/"))

    def test_range_and_step_less_findings(self):
        doc = complete_doc()
        del doc["findings"][0]["step"]
        doc["findings"][0]["location"] = "a/b.py:3-7"
        result = sarif.sarif(doc)["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "domain-model-and-data-ownership")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"],
                         {"startLine": 3, "endLine": 7})

    def test_cli(self):
        out = self.tmp / "x" / "architecture.sarif"
        code, stdout, _ = run(sarif.main, str(SAMPLE), "--out", str(out))
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(out.read_text(encoding="utf-8"))["runs"][0]["results"]), 3)
        code, stdout, _ = run(sarif.main, str(SAMPLE), "--min-severity", "High")
        self.assertEqual(len(json.loads(stdout)["runs"][0]["results"]), 1)
        bad = complete_doc()
        bad["findings"][0]["location"] = "nowhere"
        code, _, err = run(sarif.main, str(self.write("bad.json", bad)))
        self.assertEqual(code, 2)


class ContractTests(TempDir):
    def test_drafts_beside_the_outputs_pass_check_with_allow(self):
        out = self.tmp / "out"
        out.mkdir()
        shutil.copy(SAMPLE, out / "findings.json")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(render.main([str(out / "findings.json"), "--out", str(out)]), 0)
            self.assertEqual(drafts.main([str(out / "findings.json"), "--out", str(out / "drafts")]), 0)
        code, _, err = run(findings.main, "check", str(out))
        self.assertEqual(code, 1)
        self.assertIn("drafts", err)
        code, _, _ = run(findings.main, "check", str(out), "--allow", "drafts")
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
