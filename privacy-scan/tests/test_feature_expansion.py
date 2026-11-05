"""Comparing assessments, drafting issues and reports, and linking the ledger to findings."""
import copy
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_privacy_scan import REPO, SKILL, complete_doc, finding, findings, import_module, render

compare = import_module(SKILL / "scripts" / "compare.py", "priv_compare")
drafts = import_module(SKILL / "scripts" / "drafts.py", "priv_drafts")
SAMPLE = REPO / "examples" / "findings.sample.json"


def sample():
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


def run(main, args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(args)
    return code, out.getvalue(), err.getvalue()


class LedgerLinkTests(unittest.TestCase):
    def test_a_violated_commitment_needs_a_reported_finding_citing_it(self):
        doc = complete_doc()
        for f in doc["findings"]:
            f["commitment"] = ""
        problems = findings.record_problems(doc)
        self.assertTrue(any("C-01 is recorded as violated" in p for p in problems), problems)
        # An excluded finding breaks nothing, so it does not count as a citation.
        doc["findings"][0]["commitment"] = "C-01"
        doc["findings"][0]["validation"] = {"verdict": "FalsePositive", "method": "static",
                                            "evidence": "scrubber at app.py:30"}
        self.assertTrue(any("C-01 is recorded as violated" in p
                            for p in findings.record_problems(doc)))

    def test_holds_contradicts_an_open_valid_finding_but_not_a_fixed_or_unverified_one(self):
        doc = complete_doc()
        doc["commitments"][0]["status"] = "holds"
        problems = findings.record_problems(doc)
        self.assertTrue(any("C-01 is recorded as holds, but PV-001, PV-002" in p for p in problems),
                        problems)
        for f in doc["findings"]:
            f["status"] = "Fixed"
        self.assertEqual(findings.record_problems(doc), [])
        for f in doc["findings"]:
            f["status"] = "Open"
            f["validation"]["verdict"] = "Unverified"
        self.assertEqual(findings.record_problems(doc), [])

    def test_several_cited_commitments_each_count(self):
        doc = complete_doc()
        doc["commitments"].append({"id": "C-02", "statement": "s", "source": "p", "status": "violated"})
        doc["findings"][1]["commitment"] = "C-01, C-02"
        self.assertEqual(findings.record_problems(doc), [])
        self.assertEqual(findings.commitment_citations(doc),
                         {"C-01": ["PV-001", "PV-002"], "C-02": ["PV-002"]})

    def test_both_reports_list_the_citing_findings(self):
        doc = complete_doc()
        doc["commitments"].append({"id": "C-02", "statement": "s", "source": "p",
                                   "status": "not checked", "reason": "r"})
        markdown = render.render_markdown(doc, "en")
        self.assertIn("| C-01 | no PII in errors |  | policy | violated | PV-001, PV-002 |", markdown)
        self.assertIn("| C-02 | s |  | p | not checked — reason: r |  |", markdown)
        html = render.render_html(doc, "ja")
        self.assertIn("<td data-label='検出事項'>PV-001, PV-002</td>", html)

    def test_the_sample_passes_the_new_rules(self):
        self.assertEqual(findings.record_problems(sample()), [])


def later(doc):
    """The sample after a round of fixes: one fixed, one re-graded, one new."""
    new = copy.deepcopy(doc)
    new["meta"].update(commit="1111111", date="2026-11-01")
    first, second, third = new["findings"]
    first["location"] = ["api/app.py:25", "api/checkout/views.py:40"]
    first["status"] = "Accepted"
    second["status"] = "Fixed"
    third["severity"] = "High"
    new["findings"].append({**copy.deepcopy(third), "id": "PV-004", "severity": "Low",
                            "title": "Support export includes the phone field",
                            "location": "api/support/export.py:12",
                            "category": "Third-party sharing", "step": "TP1", "commitment": ""})
    new["commitments"][2]["status"] = "holds"
    return new


class CompareTests(unittest.TestCase):
    def test_classes_changes_and_counts(self):
        old = sample()
        result = compare.compare(old, later(old))
        self.assertEqual([f["id"] for f in result["new_findings"]], ["PV-004"])
        self.assertEqual([(f["id"], f["reason"]) for f in result["resolved"]], [("PV-002", "Fixed")])
        self.assertEqual(result["reopened"], [])
        persisting = {f["id"]: f for f in result["persisting"]}
        self.assertEqual(persisting["PV-001"]["changes"],
                         {"status": {"from": "Open", "to": "Accepted"}})
        self.assertEqual(persisting["PV-001"]["matched_by"], "location")
        self.assertEqual(persisting["PV-003"]["changes"], {"severity": {"from": "Medium", "to": "High"}})
        self.assertEqual(result["counts"]["old"], {"High": 2, "Medium": 1, "Low": 0, "Info": 0})
        self.assertEqual(result["counts"]["new"], {"High": 2, "Medium": 0, "Low": 1, "Info": 0})
        self.assertEqual([(c["id"], c["from"], c["to"]) for c in result["commitments"]["changed"]],
                         [("C-03", "violated", "holds")])

    def test_identical_records_only_persist(self):
        result = compare.compare(sample(), sample())
        self.assertEqual(len(result["persisting"]), 3)
        self.assertTrue(all(not f["changes"] for f in result["persisting"]))
        self.assertEqual(result["new_findings"] + result["resolved"] + result["reopened"], [])
        self.assertEqual(result["commitments"], {"changed": [], "added": [], "removed": []})

    def test_disappeared_excluded_and_reopened_findings(self):
        old = complete_doc()
        new = copy.deepcopy(old)
        new["findings"] = [new["findings"][0]]
        new["findings"][0]["validation"] = {"verdict": "NotApplicable", "method": "static",
                                            "evidence": "behind a feature flag never shipped"}
        result = compare.compare(old, new)
        self.assertEqual(sorted((f["id"], f["reason"]) for f in result["resolved"]),
                         [("PV-001", "NotApplicable"), ("PV-002", "gone")])
        # The reverse direction: an excluded finding that is reported again has reopened.
        result = compare.compare(new, old)
        self.assertEqual([(f["id"], f["old_id"]) for f in result["reopened"]], [("PV-001", "PV-001")])
        self.assertEqual([f["id"] for f in result["new_findings"]], ["PV-002"])

    def test_matching_survives_renumbering_moves_and_renames(self):
        old = complete_doc()
        new = copy.deepcopy(old)
        # Renumbered in the other order, the Low finding's file renamed, and the
        # High one moved down the same file.
        high, low = new["findings"]
        high["id"], low["id"] = "PV-002", "PV-001"
        high["location"] = ["api/app.py:80"]
        low["location"] = ["worker/main.py:15"]
        new["findings"] = [low, high]
        pairs = {(f["old_id"], f["id"], f["matched_by"]) for f in compare.compare(old, new)["persisting"]}
        self.assertEqual(pairs, {("PV-001", "PV-002", "location"), ("PV-002", "PV-001", "title")})

    def test_matching_is_one_to_one_and_prefers_the_nearest_line(self):
        old = complete_doc()
        old["findings"] = [finding(location=["api/app.py:10"]),
                           finding("PV-002", location=["api/app.py:90"])]
        new = copy.deepcopy(old)
        new["findings"] = [finding("PV-001", location=["api/app.py:88"])]
        result = compare.compare(old, new)
        self.assertEqual([(f["old_id"], f["id"]) for f in result["persisting"]], [("PV-002", "PV-001")])
        self.assertEqual([f["id"] for f in result["resolved"]], ["PV-001"])

    def test_different_perspectives_never_match(self):
        old = complete_doc()
        new = copy.deepcopy(old)
        new["findings"][1]["category"] = "Storage protection"
        new["findings"][1]["step"] = "SP1"
        result = compare.compare(old, new)
        self.assertEqual([f["id"] for f in result["new_findings"]], ["PV-002"])
        self.assertEqual([f["id"] for f in result["resolved"]], ["PV-002"])

    def test_commitments_match_by_statement_then_id(self):
        old = complete_doc()
        old["commitments"].append({"id": "C-02", "statement": "Exports read every store",
                                   "source": "policy", "status": "holds"})
        new = copy.deepcopy(old)
        new["commitments"] = [{"id": "C-01", "statement": "Exports read every store", "source": "policy",
                               "status": "violated"},
                              {"id": "C-02", "statement": "Logs  hold no addresses", "source": "policy",
                               "status": "holds"}]
        ledger = compare.compare(old, new)["commitments"]
        # Statements first: the old C-02 is the new C-01. The new C-02 states
        # something else, and its ID was already taken, so it is a new entry.
        self.assertEqual([(c["old_id"], c["id"], c["to"]) for c in ledger["changed"]],
                         [("C-02", "C-01", "violated")])
        self.assertEqual([c["id"] for c in ledger["added"]], ["C-02"])
        self.assertEqual([c["id"] for c in ledger["removed"]], ["C-01"])

    def test_cli_prints_escaped_markdown_or_json_and_refuses_bad_records(self):
        with tempfile.TemporaryDirectory() as directory:
            old, new = Path(directory) / "old.json", Path(directory) / "new.json"
            doc = later(sample())
            doc["findings"][3]["title"] = "Export *bold* | pipe"
            old.write_text(SAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
            new.write_text(json.dumps(doc), encoding="utf-8")
            code, out, _ = run(findings.main, ["diff", str(old), str(new)])
            self.assertEqual(code, 0)
            self.assertIn("1 new, 0 reopened, 1 resolved, 2 persisting", out)
            self.assertIn("PV-004 [Low] Export \\*bold\\* \\| pipe (`api/support/export.py:12`)", out)
            self.assertIn("status Open → Accepted", out)
            code, out, _ = run(findings.main, ["diff", str(old), str(new), "--lang", "ja"])
            self.assertIn("新規 1 件、再発 0 件、解消 1 件、継続 2 件", out)
            code, out, _ = run(findings.main, ["diff", str(old), str(new), "--json"])
            self.assertEqual(json.loads(out)["new"]["commit"], "1111111")
            doc["meta"].pop("assessor")
            new.write_text(json.dumps(doc), encoding="utf-8")
            code, _, err = run(findings.main, ["diff", str(old), str(new)])
            self.assertEqual(code, 1)
            self.assertIn("current record: meta.assessor", err)

    def test_diff_runs_as_an_isolated_script(self):
        result = subprocess.run(
            [sys.executable, "-I", str(SKILL / "scripts" / "findings.py"), "diff", str(SAMPLE), str(SAMPLE)],
            capture_output=True, text=True, env={"PYTHONDONTWRITEBYTECODE": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("0 new, 0 reopened, 0 resolved, 3 persisting", result.stdout)


class DraftTests(unittest.TestCase):
    def write(self, doc, *extra, out_name="drafts"):
        directory = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, directory)
        record = Path(directory) / "record" / "findings.json"
        record.parent.mkdir()
        record.write_text(json.dumps(doc), encoding="utf-8")
        out = Path(directory) / out_name
        code, stdout, stderr = run(drafts.main, [str(record), "--out", str(out), *extra])
        return code, out, stdout, stderr

    def test_every_open_finding_gets_an_issue_and_one_owner_report(self):
        doc = sample()
        doc["findings"][2]["status"] = "Fixed"
        code, out, stdout, _ = self.write(doc)
        self.assertEqual(code, 0)
        self.assertEqual(sorted(p.name for p in out.iterdir()),
                         ["issue-PV-001.md", "issue-PV-002.md", "owner-report.md"])
        self.assertIn("private tracker only (unfixed High): PV-001, PV-002", stdout)

    def test_templates_are_filled_in_both_languages(self):
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                code, out, _, _ = self.write(sample(), "--lang", lang)
                self.assertEqual(code, 0)
                for path in out.iterdir():
                    text = path.read_text(encoding="utf-8")
                    self.assertNotIn("{{", text, path.name)
                    self.assertNotIn("<!--", text, path.name)
                issue = (out / "issue-PV-001.md").read_text(encoding="utf-8")
                self.assertIn("`api/app.py:22`, `api/checkout/views.py:40`", issue)
                self.assertIn("C-01 — No personal field is sent to error tracking", issue)
                self.assertTrue(issue.startswith("> **"))
                report = (out / "owner-report.md").read_text(encoding="utf-8")
                for fid in ("PV-001", "PV-002", "PV-003"):
                    self.assertIn(f"### {fid}: ", report)
                self.assertIn("C-04: Data is stored in the EU (SHARE;", report)
                self.assertIn("cited by: PV-001" if lang == "en" else "該当: PV-001", report)

    def test_owner_report_takes_counts_from_the_record(self):
        code, out, _, _ = self.write(sample())
        report = (out / "owner-report.md").read_text(encoding="utf-8")
        self.assertIn("— 2 High / 1 Medium (2026-10-09)", report)
        self.assertIn("| High | 2 | 2 |", report)
        self.assertIn("<to fill in: the conclusion first>", report)
        self.assertIn("1. Fix PV-001 and PV-002, then add their guards", report)

    def test_blank_optional_values_drop_their_lines_and_sections(self):
        doc = complete_doc()
        doc["findings"][0].update(step="", contrast="", commitment="unwritten rule")
        doc["commitments"][0]["status"] = "partly read"
        doc["findings"][1]["validation"] = {"verdict": "Likely", "method": "static"}
        code, out, _, _ = self.write(doc, "--id", "PV-001", "--id", "PV-002")
        first = (out / "issue-PV-001.md").read_text(encoding="utf-8")
        self.assertIn("| Perspective | Logs, telemetry and errors |", first)
        self.assertNotIn("Contrast", first)
        self.assertNotIn("| Conditions |", first)
        self.assertNotIn("## References", first)
        self.assertNotIn("## Open questions", first)
        self.assertIn("- **Broken commitment:** unwritten rule\n", first)
        second = (out / "issue-PV-002.md").read_text(encoding="utf-8")
        self.assertNotIn("## Evidence", second)
        self.assertFalse(second.startswith(">"), "a Low finding needs no private-tracker line")
        self.assertIn("| Assessed revision | UNKNOWN |", second)

    def test_conditions_references_and_open_questions_are_carried(self):
        doc = complete_doc()
        doc["findings"][0].update(confidence="Environment-dependent", conditions="LOG_LEVEL=debug",
                                  references=[{"title": "SDK", "url": "https://example.com/sdk"}])
        doc["decisions"] = ["Confirm the vendor contract for PV-001", "Unrelated to PV-0012x",
                            "About PV-002 only"]
        doc["limitations"].append("Vendor settings for PV-001 were not observed")
        code, out, _, _ = self.write(doc, "--id", "PV-001")
        issue = (out / "issue-PV-001.md").read_text(encoding="utf-8")
        self.assertIn("| Conditions | LOG\\_LEVEL=debug |", issue)
        self.assertIn("- [SDK](<https://example.com/sdk>)", issue)
        questions = issue.split("## Open questions", 1)[1].split("##", 1)[0]
        self.assertEqual(re.findall(r"^- (.*)$", questions, re.M),
                         ["LOG\\_LEVEL=debug", "Confirm the vendor contract for PV-001",
                          "Vendor settings for PV-001 were not observed"])

    def test_values_are_escaped_and_never_read_as_placeholders(self):
        doc = complete_doc()
        doc["findings"][0]["flow"] = "1. {{title}} <b>x</b>"
        doc["findings"][0]["title"] = "A | B"
        code, out, _, _ = self.write(doc, "--id", "PV-001")
        issue = (out / "issue-PV-001.md").read_text(encoding="utf-8")
        self.assertIn("\n1\\. {{title}} &lt;b&gt;x&lt;/b&gt;\n", issue)
        self.assertIn("**Title:** [High] A \\| B (PV-001)", issue)

    def test_owner_report_without_high_or_medium_says_none(self):
        doc = complete_doc()
        for f in doc["findings"]:
            f["severity"] = "Low"
        doc["findings"][1]["location"] = ["worker/app.py:15"]
        code, out, _, _ = self.write(doc, "--lang", "ja")
        report = (out / "owner-report.md").read_text(encoding="utf-8")
        self.assertIn("## 3. 優先して対応すべき検出事項\n\nなし。\n", report)

    def test_refusals(self):
        code, _, _, err = self.write(complete_doc(), "--id", "PV-009")
        self.assertEqual(code, 1)
        self.assertIn("PV-009", err)
        doc = complete_doc()
        doc["findings"].reverse()
        code, _, _, err = self.write(doc)
        self.assertEqual(code, 1)
        self.assertIn("renumber", err)
        # The run's own output directory holds exactly three files.
        code, out, _, err = self.write(complete_doc(), out_name="record")
        self.assertEqual(code, 1)
        self.assertIn("run's output directory", err)
        self.assertEqual(sorted(p.name for p in out.iterdir()), ["findings.json"])
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "report.md").write_text("x", encoding="utf-8")
            code, _, err = run(drafts.main, [str(SAMPLE), "--out", directory])
            self.assertEqual(code, 1)
        with self.assertRaises(SystemExit):
            run(drafts.main, [str(SAMPLE), "--out", " "])

    def test_drafts_run_as_an_isolated_script(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, "-I", str(SKILL / "scripts" / "drafts.py"), str(SAMPLE),
                 "--out", str(Path(directory) / "d")],
                capture_output=True, text=True, env={"PYTHONDONTWRITEBYTECODE": "1"})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("private tracker only (unfixed High): PV-001, PV-002", result.stdout)

    def test_every_template_placeholder_is_known(self):
        names = set()
        for path in (SKILL / "templates").glob("*.md"):
            body = drafts.COMMENT.sub("", path.read_text(encoding="utf-8"))
            names |= set(drafts.PLACEHOLDER.findall(body))
        doc = sample()
        doc["findings"][0]["references"] = [{"title": "t", "url": "https://example.com"}]
        draft = drafts.Draft(doc, "en", doc["findings"][0])
        for name in sorted(names):
            loop = re.match(r"([a-z_]+)\[\]", name)
            with self.subTest(name=name):
                if loop:
                    draft.items(loop.group(1))
                else:
                    draft.scalar(name)


class DashboardSearchTests(unittest.TestCase):
    def test_search_box_is_labelled_and_only_shown_with_findings(self):
        html = render.render_html(complete_doc(), "ja")
        self.assertIn("<input type='search' id='finding-search' class='finding-search' "
                      "aria-label='検出事項を検索'", html)
        empty = complete_doc()
        empty["findings"] = []
        self.assertNotIn("<input type='search'", render.render_html(empty, "en"))

    def test_search_combines_with_the_severity_filter(self):
        self.assertIn("(sev!=='all'&&d.dataset.sev!==sev)||", render.JS)
        self.assertIn("!d.textContent.toLowerCase().includes(q)", render.JS)
        self.assertIn("search.addEventListener('input'", render.JS)


if __name__ == "__main__":
    unittest.main()
