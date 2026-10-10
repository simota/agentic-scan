"""Findings from a Django/Celery run, a Spring/Kafka run (ja) and a fresh script review."""
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_architecture_scan import REPO, SKILL, complete_doc, finding, findings, make_env, render


class Workspace(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.target = self.tmp / "findings.json"

    def write(self, doc):
        self.target.write_text(json.dumps(doc), encoding="utf-8")

    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = findings.main([str(a) for a in args])
        return code, out.getvalue(), err.getvalue()

    def merge(self, fragment):
        path = self.tmp / "fragment.json"
        path.write_text(json.dumps(fragment), encoding="utf-8")
        return self.cli("merge", self.target, path)

    def problems(self, doc, *allow):
        self.write(doc)
        with redirect_stdout(io.StringIO()):
            render.main([str(self.target), "--out", str(self.tmp)])
        return findings.contract_problems(self.tmp, ["fragment.json", *allow])


class BaselineRuleTests(unittest.TestCase):
    def test_a_baseline_entry_is_labelled_as_one_not_as_a_question(self):
        rule = {"id": "R-01", "statement": "No cycles", "source": "baseline; api/x.py:3",
                "inferred": True, "status": "holds"}
        self.assertEqual(render.rule_statement(rule, "en"), "No cycles (baseline)")
        self.assertEqual(render.rule_statement(rule, "ja"), "No cycles (ベースライン)")
        rule["source"] = "majority of modules"
        self.assertIn("inferred, to confirm", render.rule_statement(rule, "en"))

    def test_the_sample_puts_no_baseline_entry_in_decisions(self):
        doc = findings.read_json(REPO / "examples" / "findings.sample.json")
        baseline = {r["id"] for r in doc["rules"] if r["source"].startswith("baseline")}
        for decision in doc["decisions"]:
            self.assertFalse(any(rid in decision for rid in baseline), decision)


class ViolatedRuleTests(Workspace):
    def test_a_violated_rule_no_finding_names_fails(self):
        doc = complete_doc()
        doc["rules"].append({"id": "R-02", "statement": "s", "source": "adr", "status": "violated"})
        self.assertTrue(any(p.startswith("R-02: a violated rule") for p in self.problems(doc)))

    def test_one_root_cause_cites_every_rule_it_breaks(self):
        doc = complete_doc()
        doc["rules"].append({"id": "R-02", "statement": "s", "source": "adr", "status": "violated"})
        doc["findings"][0]["rule"] = "R-01, R-02"
        self.assertEqual(self.problems(doc), [])
        doc["findings"][0]["rule"] = "R-01、R-09"
        self.assertTrue(any("rule 'R-09' is not a rules[] id" in p for p in self.problems(doc)))

    def test_a_rule_in_a_trace_cites_nothing(self):
        doc = complete_doc()
        doc["rules"].append({"id": "R-02", "statement": "s", "source": "adr", "status": "violated"})
        for trace in ("the same edge breaks R-02", "does not violate R-02; only R-01",
                      "ルールR-02にも違反する"):
            with self.subTest(trace=trace):
                doc["findings"][0]["trace"] = trace
                self.assertTrue(any(p.startswith("R-02: a violated rule")
                                    for p in self.problems(doc)))

    def test_an_excluded_finding_does_not_explain_a_violation(self):
        doc = complete_doc()
        doc["findings"][0]["validation"].update(verdict="FalsePositive")
        self.assertTrue(any(p.startswith("R-01: a violated rule") for p in self.problems(doc)))

    def test_a_reason_left_on_a_closed_rule_fails(self):
        doc = complete_doc()
        doc["rules"][0]["reason"] = "provisional: traced by unit 2"
        problems = self.problems(doc)
        self.assertTrue(any('send "reason": null' in p for p in problems), problems)
        doc["rules"][0].update(status="partly read")
        doc["findings"][0]["validation"]["verdict"] = "Likely"
        self.assertEqual(self.problems(doc), [])


class MergeTests(Workspace):
    def setUp(self):
        super().setUp()
        self.write(complete_doc())

    def test_a_replaced_list_item_keeps_its_place(self):
        self.assertEqual(self.merge({"next_steps": ["Fix A-001 first", "Then A-002", "Guard"]})[0], 0)
        self.assertEqual(self.merge({"remove": {"next_steps": ["Then A-002"]},
                                     "next_steps": ["Then A-002 and R-01"]})[0], 0)
        self.assertEqual(findings.read_json(self.target)["next_steps"],
                         ["Fix A-001 first", "Then A-002 and R-01", "Guard"])
        self.assertEqual(self.merge({"next_steps": ["Last"]})[0], 0)
        self.assertEqual(findings.read_json(self.target)["next_steps"][-1], "Last")

    def test_a_removed_rule_sent_back_partially_is_explained(self):
        before = self.target.read_bytes()
        code, _, err = self.merge({"remove": {"rules": ["R-01"]},
                                   "rules": [{"id": "R-01", "status": "holds"}]})
        self.assertEqual(code, 1)
        self.assertIn("R-01 is removed, so the rule sent with that ID must be complete", err)
        self.assertEqual(self.target.read_bytes(), before)

    def test_errors_name_the_fragment_and_the_finding(self):
        code, _, err = self.merge({"findings": [{"id": "A-002", "analysis": None,
                                                 "validation": {"verdict": "Valid",
                                                                "method": "analysed",
                                                                "evidence": "job.py:58"}}]})
        self.assertEqual(code, 1)
        self.assertIn("fragment.json: A-002: findings[1]", err)
        code, _, err = self.merge({"findings": [finding("A-001", title="Other",
                                                        location="b.py:1")]})
        self.assertIn("fragment.json: fragment.findings: A-001 already holds", err)


class RenumberTests(Workspace):
    def test_right_names_in_the_wrong_order_are_reordered(self):
        doc = complete_doc()
        doc["findings"] = [finding("A-002", "Low"), finding("A-001", "High", rule="R-01")]
        self.write(doc)
        code, out, _ = self.cli("renumber", self.target)
        self.assertEqual(code, 0)
        self.assertIn("reordered", out)
        self.assertEqual([f["id"] for f in findings.read_json(self.target)["findings"]],
                         ["A-001", "A-002"])
        self.assertEqual(self.problems(findings.read_json(self.target)), [])

    def test_excluded_findings_are_numbered_last(self):
        doc = complete_doc()
        dup = finding("A-003", "High", location="a.py:1")
        dup["validation"] = {"verdict": "NotApplicable", "method": "static",
                             "evidence": "Duplicate of A-001"}
        doc["findings"].insert(0, dup)
        renamed, _ = findings.renumber(doc)
        self.assertEqual([f["validation"]["verdict"] for f in renamed["findings"]],
                         ["Valid", "Valid", "NotApplicable"])
        self.assertEqual(renamed["findings"][2]["validation"]["evidence"], "Duplicate of A-001")
        self.assertEqual(self.problems(renamed), [])

    def test_ids_inside_urls_in_prose_are_kept(self):
        mapping = {"A-001": "A-002", "A-002": "A-001"}
        self.assertEqual(findings._rewrite_ids(
            "A-001, see https://jira.example/browse?key=A-001 and https://x/r#A-002", mapping),
            "A-002, see https://jira.example/browse?key=A-001 and https://x/r#A-002")


class EvidenceTests(Workspace):
    def test_long_evidence_is_checked_in_linear_time(self):
        for evidence in (",".join(f"pkg.mod{i}" for i in range(5000)), "(a" * 20000,
                         "C:" * 30000, "a:" * 30000):
            start = time.monotonic()
            self.assertFalse(findings.cites_line(evidence))
            self.assertLess(time.monotonic() - start, 2)

    def test_a_path_of_any_length_is_cited(self):
        self.assertTrue(findings.cites_line("a/" * 3000 + "b.py:3"))

    def test_paths_are_found_as_the_original_regex_found_them(self):
        for text, paths in (("a:12C/x.py:1", ["a:12C/x.py"]), ("`C:.env:12", ["C:.env"]),
                            ("C:0`,;\\:12", []), ("x C://{:12", []),
                            ("a.py:3b.py:4", ["a.py"]), (r"C:\repo\job.py:3", [r"C:\repo\job.py"]),
                            ("根拠:3_add.py:12", ["3_add.py"]), ("http://x.com:80/a", [])):
            with self.subTest(text=text):
                self.assertEqual(list(findings.evidence_paths(text)), paths)

    def test_jvm_build_wrappers_are_files(self):
        self.assertTrue(findings.cites_line("gradlew:3"))
        self.assertTrue(findings.cites_line("mvnw:12"))

    def test_a_duplicate_names_the_reported_finding_it_repeats(self):
        doc = complete_doc()
        doc["findings"][1]["validation"] = {"verdict": "NotApplicable", "method": "static",
                                            "evidence": "Duplicate of A-001"}
        self.assertEqual(self.problems(doc), [])
        doc["findings"][1]["validation"]["evidence"] = "Duplicate of A-002"
        self.assertTrue(any("A-002: NotApplicable evidence" in p for p in self.problems(doc)))
        doc["findings"][1]["validation"].update(verdict="FalsePositive",
                                                evidence="Duplicate of A-001")
        self.assertTrue(any("A-002: FalsePositive evidence" in p for p in self.problems(doc)))

    def test_text_that_shows_nothing_is_blank(self):
        for value in ("\u200b", "\u2800", "\u3164 \u200d", "\u2028", "\ufe0f", "\u034f",
                      "\U000e0100 ", "\u17b4", "\u17b5\u00ad", "\U0001bca0"):
            with self.subTest(value=repr(value)):
                with self.assertRaisesRegex(findings.SchemaError, "nonblank"):
                    findings.validate({"limitations": [value]})
        findings.validate({"limitations": ["日本"]})


class RepoCheckTests(Workspace):
    def test_locations_must_exist_in_the_checkout(self):
        repo = self.tmp / "checkout"
        (repo / "worker" / "refunds").mkdir(parents=True)
        (repo / "worker" / "refunds" / "job.py").write_text("x\n" * 57, encoding="utf-8")
        self.problems(complete_doc(), "checkout")
        code, _, err = self.cli("check", self.tmp, "--allow", "fragment.json",
                                "--allow", "checkout", "--repo", repo)
        self.assertEqual(code, 1)
        self.assertIn("line 58 is past the end of worker/refunds/job.py (57 lines)", err)
        (repo / "worker" / "refunds" / "job.py").write_text("x\n" * 58, encoding="utf-8")
        self.assertEqual(self.cli("check", self.tmp, "--allow", "fragment.json",
                                  "--allow", "checkout", "--repo", repo)[0], 0)
        code, _, err = self.cli("check", self.tmp, "--allow", "fragment.json",
                                "--allow", "checkout", "--repo", self.tmp / "nowhere")
        self.assertIn("not a directory", err)

    def test_lines_end_at_lf_crlf_or_a_lone_cr(self):
        for data, lines in ((b"a\rb\rc", 3), (b"a\r\nb\r\n", 2), (b"a\nb", 2), (b"", 0),
                            (b"a\r", 1), (b"\r\n" * 3, 3)):
            with self.subTest(data=data):
                path = self.tmp / "f.py"
                path.write_bytes(data)
                self.assertEqual(findings._count_lines(path), lines)

    def test_a_crlf_split_across_chunks_is_one_line_end(self):
        path = self.tmp / "big.py"
        path.write_bytes(b"x" * ((1 << 20) - 1) + b"\r\n" + b"y\r\n")
        self.assertEqual(findings._count_lines(path), 2)

    def test_a_missing_file_is_named(self):
        doc = complete_doc()
        problems = findings.location_problems(doc, self.tmp)
        self.assertEqual(len(problems), 2)
        self.assertIn("A-001: location worker/refunds/job.py:58: no such file", problems[0])


class EmailAtTests(unittest.TestCase):
    def test_an_at_after_punctuation_or_a_blank_stays_readable(self):
        for text in ("しない。@Transactional", "（@Version）", "use @Modifying", "@scope/pkg"):
            with self.subTest(text=text):
                self.assertNotIn("&#64;", render.markdown_inline(text))

    def test_an_at_after_a_local_part_is_disarmed(self):
        for text in ("bob@example.com", "a.b+c-d_e@x.io", "メール担当@example.com", "a_@x.com"):
            with self.subTest(text=text):
                self.assertIn("&#64;<!-- -->", render.markdown_inline(text))

    @unittest.skipUnless(shutil.which("pandoc"), "pandoc is not installed")
    def test_no_e_mail_link_through_a_real_parser(self):
        text = " ".join(["（@Version", "。@Transactional", "日本@example.com", "x@y.com",
                         "a&b@c.com", "(@d.com", "a;@e.com"])
        html = subprocess.run(["pandoc", "-f", "gfm", "-t", "html"],
                              input=render.markdown_inline(text), capture_output=True,
                              text=True, encoding="utf-8", check=True, timeout=60).stdout
        self.assertNotIn("<a ", html)


class ReviewRegressionTests(Workspace):
    """Defects the review of this round's own diff found."""

    def test_only_a_valid_or_likely_finding_backs_a_violated_rule(self):
        doc = complete_doc()
        for verdict, ok in (("Unverified", False), ("Unlikely", False), ("Likely", True)):
            with self.subTest(verdict=verdict):
                doc["findings"][0]["validation"]["verdict"] = verdict
                doc["findings"][0]["severity"] = "Low"
                doc["findings"][1]["severity"] = "Low"
                problems = [p for p in self.problems(doc) if p.startswith("R-01")]
                self.assertEqual(problems == [], ok, problems)

    def test_an_excluded_finding_before_an_active_one_fails(self):
        doc = complete_doc()
        doc["findings"][0]["validation"] = {"verdict": "FalsePositive", "method": "static",
                                            "evidence": "job.py:58 delegates"}
        doc["findings"][1]["rule"] = "R-01"
        problems = self.problems(doc)
        self.assertTrue(any("numbered after the rest" in p for p in problems), problems)
        renamed, _ = findings.renumber(doc)
        self.assertEqual(self.problems(renamed), [])

    def test_a_label_before_a_path_starting_with_a_digit_still_cites_it(self):
        for evidence in ("根拠:20240101_create_orders.rb:12", "確認:1_init.sql:3",
                         "根拠:3rd_party/client.py:40"):
            with self.subTest(evidence=evidence):
                self.assertTrue(findings.cites_line(evidence))

    def test_finding_literals_stays_linear(self):
        for text in ("a" * 200000, "a" * 100000 + "@", "a!" * 50000 + "@x", "@" * 100000):
            start = time.monotonic()
            findings._rewrite_ids(text, {"A-001": "A-002"})
            self.assertLess(time.monotonic() - start, 2)

    def test_an_iri_or_urn_keeps_its_ids(self):
        mapping = {"A-001": "A-003", "A-003": "A-001"}
        for text, expected in (("https://jira.example/?project=案件&key=A-001 and A-001",
                                "https://jira.example/?project=案件&key=A-001 and A-003"),
                               ("urn:ticket:A-001 for A-001", "urn:ticket:A-001 for A-003"),
                               ("www.example.com/?key=A-001 and A-001",
                                "www.example.com/?key=A-001 and A-003"),
                               ("WWW.example.com/A-001。A-001", "WWW.example.com/A-001。A-003"),
                               ("seeWWW.example.com/?key=A-001 A-001",
                                "seeWWW.example.com/?key=A-001 A-003"),
                               ("1https://x/?key=A-001 A-001", "1https://x/?key=A-001 A-003"),
                               ("mailto:a@x.example?subject=A-001 A-001",
                                "mailto:a@x.example?subject=A-001 A-003"),
                               ("参照https://x/A-001。A-001", "参照https://x/A-001。A-003"),
                               ("Fix:A-001 first", "Fix:A-003 first"),
                               ("A-001@example.com, owner+A-001@x.example, x@A-001.example; A-001",
                                "A-001@example.com, owner+A-001@x.example, x@A-001.example; A-003"),
                               ("owner!A-001!tag@example.com, A-001%y@a.example and A-001",
                                "owner!A-001!tag@example.com, A-001%y@a.example and A-003"),
                               ("Fix A-001+ follow-up, then @A-001", "Fix A-003+ follow-up, then @A-003"),
                               ("A-001の担当はowner@example.com", "A-003の担当はowner@example.com"),
                               ("owner+A-001@mailhost and A-001", "owner+A-001@mailhost and A-003"),
                               ("owner@example.comに連絡してA-001を直す",
                                "owner@example.comに連絡してA-003を直す")):
            self.assertEqual(findings._rewrite_ids(text, mapping), expected)

    def test_a_url_ends_before_japanese_punctuation(self):
        mapping = {"A-001": "A-003", "A-003": "A-001"}
        for text, expected in (("詳細は https://example.com/x。A-001と同根",
                                "詳細は https://example.com/x。A-003と同根"),
                               ("（https://example.com/x）A-001と同根",
                                "（https://example.com/x）A-003と同根")):
            self.assertEqual(findings._rewrite_ids(text, mapping), expected)

    def test_an_empty_file_has_a_line_one_and_nothing_outside_the_checkout_counts(self):
        repo = self.tmp / "checkout"
        (repo / "pkg").mkdir(parents=True)
        (repo / "pkg" / "__init__.py").write_bytes(b"")
        (self.tmp / "outside.py").write_text("x\n" * 9, encoding="utf-8")
        (repo / "link.py").symlink_to(self.tmp / "outside.py")
        doc = complete_doc()
        doc["findings"][0]["location"] = ["pkg/__init__.py:1"]
        doc["findings"][1]["location"] = ["../outside.py:1", "link.py:1", "pkg:1"]
        problems = findings.location_problems(doc, repo)
        self.assertEqual([p.split(": ")[1] for p in problems],
                         ["location ../outside.py:1", "location link.py:1", "location pkg:1"])

    def test_a_location_holding_a_nul_is_a_problem_not_a_crash(self):
        doc = complete_doc()
        doc["findings"][0]["location"] = ["bad\x00name.py:1"]
        problems = findings.location_problems(doc, self.tmp)
        self.assertIn("A-001: location bad\x00name.py:1: no such file", problems[0])

    def test_a_symlink_loop_is_a_problem_not_a_crash(self):
        (self.tmp / "loop.py").symlink_to(self.tmp / "loop.py")
        doc = complete_doc()
        doc["findings"][0]["location"] = ["loop.py:1"]
        self.assertIn("no such file", findings.location_problems(doc, self.tmp)[0])

    def test_an_at_after_ascii_punctuation_is_disarmed(self):
        for c in "!#$%&*/=?^|~.+-_;>":
            with self.subTest(c=c):
                self.assertIn("&#64;<!-- -->", render.markdown_inline(f"a{c}@example.com"))

    def test_an_at_after_a_combining_mark_is_disarmed(self):
        for text in ("jose\u0301@example.com", "\u30ab\u3099@example.com"):
            with self.subTest(text=repr(text)):
                self.assertIn("&#64;<!-- -->", render.markdown_inline(text))

    def test_only_a_baseline_source_is_a_baseline(self):
        for source, baseline in (("baseline", True), ("Baseline; shared/db.py:12", True),
                                 ("baselines/ownership.md:4", False),
                                 ("baseline_config.yaml:12", False)):
            with self.subTest(source=source):
                rule = {"statement": "s", "source": source, "inferred": True}
                self.assertEqual(render.rule_statement(rule, "en").endswith("(baseline)"),
                                 baseline)

    def test_only_a_stated_duplicate_skips_the_line_citation(self):
        doc = complete_doc()
        for evidence, ok in (("Duplicates A-001", True), ("Duplicate of A-001.", True),
                             ("重複: A-001", True), ("重複：A-001。", True),
                             ("Duplicate of A-001. Same writer", False),
                             ("Duplicate of A-001; not actually a duplicate", False),
                             ("重複: A-001；重複ではない", False),
                             ("Not a duplicate; unlike A-001 this module is legacy", False),
                             ("This is not a duplicate of A-001", False),
                             ("Duplicate of A-001 only in part", False),
                             ("重複: A-001 ではない", False), ("A-001 の重複", False),
                             ("see docs/A-001.md", False)):
            with self.subTest(evidence=evidence):
                doc["findings"][1]["validation"] = {"verdict": "NotApplicable",
                                                    "method": "static", "evidence": evidence}
                self.assertEqual(self.problems(doc) == [], ok)


class CommandLineTests(unittest.TestCase):
    def test_help_carries_the_whole_usage(self):
        for script, needle in (("findings.py", "Exit codes"), ("render.py", "Exit codes")):
            result = subprocess.run([sys.executable, str(SKILL / "scripts" / script), "--help"],
                                    capture_output=True, text=True, timeout=30)
            self.assertIn(needle, result.stdout)

    def test_exported_install_names_do_not_redirect_the_install(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d) / "home"
            (home / ".claude").mkdir(parents=True)
            env = make_env()
            env.update(HOME=str(home), PROJECT="my-cloud-project", SKILLS_DIR=str(Path(d) / "x"),
                       AGENT="claude")
            for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "AGY_HOME"):
                env.pop(name, None)  # the default host directories are under HOME
            result = subprocess.run(["make", "--no-print-directory", "-C", str(REPO), "status"],
                                    env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(home / ".claude" / "skills"), result.stdout)
        self.assertNotIn("my-cloud-project", result.stdout + result.stderr)
        self.assertIn(".codex", result.stdout)  # AGENT from the environment is ignored too


if __name__ == "__main__":
    unittest.main()
