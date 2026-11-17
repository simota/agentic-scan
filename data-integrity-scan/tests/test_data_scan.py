"""Offline tests for data-scan's scripts and the documents they encode."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import re
import select
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
SKILL = REPO / "skills" / "data-scan"
SCRIPTS = SKILL / "scripts"
SAMPLE = REPO / "examples" / "findings.sample.json"
sys.path.insert(0, str(SCRIPTS))
sys.dont_write_bytecode = True

import findings  # noqa: E402
import render  # noqa: E402


def sample():
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


def by_id(doc, fid):
    return next(f for f in doc["findings"] if f["id"] == fid)


class Run(unittest.TestCase):
    """Render a record into a fresh output directory and check its contract."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def problems(self, doc):
        (self.out / "findings.json").write_text(json.dumps(doc, ensure_ascii=False),
                                                encoding="utf-8")
        for name, data in render.rendered_outputs(doc, doc["meta"]["lang"]).items():
            (self.out / name).write_bytes(data)
        return findings.contract_problems(self.out)

    def assertProblem(self, doc, fragment):
        problems = self.problems(doc)
        self.assertTrue(any(fragment in p for p in problems),
                        f"expected a problem containing {fragment!r}, got {problems}")


class SampleTest(Run):
    def test_an_assumed_severity_axis_sends_each_high_finding_to_decisions(self):
        doc = sample()
        high = [f["id"] for f in doc["findings"]
                if f["severity"] == "High" and f["validation"]["verdict"] not in findings.EXCLUDED]
        self.assertTrue(high)
        doc["meta"]["axis"] = "assumed"
        named = list(doc["decisions"])
        doc["decisions"] = [d for d in named
                            if not any(re.search(rf"(?<!\w){h}(?!\w)", d) for h in high)]
        self.assertProblem(doc, f"{high[0]}: its High severity rests on an assumed severity axis")
        doc["decisions"] = named + [f"Confirm the list severity is judged against: "
                                    f"{', '.join(high)} rest on it"]
        self.assertEqual(self.problems(doc), [])
        report = render.rendered_outputs(doc, "en")["report.md"].decode("utf-8")
        self.assertIn("| Severity axis | assumed; not confirmed by the requester |", report)

    def test_the_severity_axis_is_recorded_as_confirmed_or_assumed(self):
        doc = sample()
        del doc["meta"]["axis"]
        self.assertProblem(doc, "meta.axis: record whether the requester confirmed")
        doc["meta"]["axis"] = "guessed"
        with self.assertRaisesRegex(findings.SchemaError, "meta.axis"):
            findings.validate(doc, complete=True)

    def test_sample_passes_the_contract_in_both_languages(self):
        doc = sample()
        self.assertEqual(self.problems(doc), [])
        doc["meta"]["lang"] = "ja"
        self.assertEqual(self.problems(doc), [])

    def test_cli_render_and_check(self):
        target = self.out / "findings.json"
        target.write_bytes(SAMPLE.read_bytes())
        run = [sys.executable, "-B"]
        subprocess.run(run + [str(SCRIPTS / "render.py"), str(target), "--out", str(self.out)],
                       check=True, capture_output=True)
        result = subprocess.run(run + [str(SCRIPTS / "findings.py"), "check", str(self.out)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_counts_include_rollout_and_batches(self):
        counts = findings.template_counts(sample())
        self.assertEqual((counts["n_online"], counts["n_staged"], counts["n_downtime"]), (2, 1, 1))
        self.assertEqual(counts["n_batches"], 3)
        self.assertEqual(counts["n_excluded"], 1)


class ReadinessTest(Run):
    def test_medium_needs_exposure(self):
        doc = sample()
        del by_id(doc, "F-003")["exposure"]
        self.assertProblem(doc, "F-003: a Medium finding needs exposure")

    def test_medium_needs_invariants(self):
        doc = sample()
        del by_id(doc, "F-003")["invariants"]
        self.assertProblem(doc, "F-003: a Medium finding needs invariants")

    def test_medium_needs_enforcement(self):
        doc = sample()
        del by_id(doc, "F-003")["enforcement"]
        self.assertProblem(doc, "F-003: a Medium finding needs enforcement")

    def test_high_needs_steps(self):
        doc = sample()
        del by_id(doc, "F-001")["steps"]
        self.assertProblem(doc, "F-001: a High finding needs steps, each ending with "
                                "production working")

    def test_each_step_says_how_it_is_verified(self):
        doc = sample()
        by_id(doc, "F-002")["steps"][1] = "2. Make the job skip a duplicate that is already gone"
        self.assertProblem(doc, "F-002: step 2 does not say how it is checked")

    def test_every_recorded_step_says_how_it_is_verified(self):
        # reference/plan.md §4: every step, at any severity, says how it is checked.
        doc = sample()
        by_id(doc, "F-004")["steps"] = ["1. Widen the key"]
        self.assertProblem(doc, "F-004: step 1 does not say how it is checked")

    def test_low_needs_no_exposure_invariants_or_steps(self):
        doc = sample()
        f = by_id(doc, "F-004")
        del f["exposure"], f["steps"], f["enforcement"]
        self.assertEqual(self.problems(doc), [])

    def test_unverified_medium_is_refused(self):
        doc = sample()
        by_id(doc, "F-003")["validation"] = {"verdict": "Unverified", "method": "static"}
        self.assertProblem(doc, "an Unverified Medium finding was not traced")


class EnforcementTest(Run):
    def test_a_hazard_may_sit_under_enforced_invariants(self):
        # A constraint already enforces the invariant; the hazard is the lock
        # that building its index holds, not a write that breaks it.
        doc = sample()
        f = by_id(doc, "F-003")
        f.update(category="Migration locking and rewrites", step="ML2",
                 remedy="Build Index Concurrently",
                 hazard="Building the index blocks every write to wallets while it runs")
        f["enforcement"]["net"] = "enforced"
        self.assertEqual(self.problems(doc), [])

    def test_an_online_finding_may_have_no_enforcement_today(self):
        f = by_id(sample(), "F-002")
        f["enforcement"] = {"net": "none", "sites": [], "gaps": "Nothing checks the merge order"}
        self.assertEqual(findings._enforcement_problems(f), [])

    def test_a_low_finding_may_omit_enforcement(self):
        doc = sample()
        del by_id(doc, "F-004")["enforcement"]
        self.assertEqual(self.problems(doc), [])

    def test_staged_and_downtime_need_a_rollout_reason(self):
        doc = sample()
        del by_id(doc, "F-004")["rollout_reason"]
        self.assertProblem(doc, "F-004: a Downtime finding needs rollout_reason: what forces "
                                "the maintenance window")
        doc = sample()
        del by_id(doc, "F-001")["rollout_reason"]
        self.assertProblem(doc, "F-001: a Staged finding needs rollout_reason: what forces "
                                "the staging")

    def test_net_and_sites_agree(self):
        doc = sample()
        f = by_id(doc, "F-002")
        f["enforcement"]["net"] = "none"
        self.assertProblem(doc, "F-002: enforcement.net is none but enforcement.sites lists sites")
        doc = sample()
        by_id(doc, "F-001")["enforcement"]["sites"] = []
        self.assertProblem(doc, "F-001: enforcement.net is partial; name the constraints")

    def test_an_enforced_net_names_its_sites(self):
        doc = sample()
        f = by_id(doc, "F-003")
        f["enforcement"].update(net="enforced", sites=[])
        self.assertProblem(doc, "F-003: enforcement.net is enforced; name the constraints")

    def test_high_needs_invariants(self):
        doc = sample()
        by_id(doc, "F-001")["invariants"] = []
        self.assertProblem(doc, "F-001: a High finding needs invariants")

    def test_gaps_may_say_none_at_any_rollout(self):
        # gaps is the enforcement hole only; the window is rollout_reason's.
        for rollout in findings.ROLLOUTS:
            f = by_id(sample(), "F-004")
            f.update(rollout=rollout)
            f["enforcement"]["gaps"] = "none"
            self.assertEqual(findings._enforcement_problems(f), [], rollout)
            self.assertEqual(findings._rollout_problems(f), [], rollout)

    def test_online_needs_no_rollout_reason(self):
        doc = sample()
        f = by_id(doc, "F-002")
        self.assertNotIn("rollout_reason", f)
        self.assertEqual(f["rollout"], "Online")
        self.assertEqual(findings._rollout_problems(f), [])
        self.assertEqual(self.problems(doc), [])

    def test_rollout_values_are_the_three_documented(self):
        self.assertEqual(findings.ROLLOUTS, ("Online", "Staged", "Downtime"))
        self.assertEqual(findings.NETS, ("enforced", "partial", "none"))
        doc = sample()
        by_id(doc, "F-002")["rollout"] = "Instant"
        with self.assertRaisesRegex(findings.SchemaError, "rollout"):
            findings.validate(doc)

    def test_enforcement_sites_are_locations(self):
        doc = sample()
        by_id(doc, "F-001")["enforcement"]["sites"] = ["db/schema.rb"]
        with self.assertRaisesRegex(findings.SchemaError, "must be path:line"):
            findings.validate(doc)


class DependencyAndPlanTest(Run):
    def test_cycle_is_refused(self):
        doc = sample()
        by_id(doc, "F-002")["depends_on"] = ["F-001"]
        self.assertProblem(doc, "depends_on forms a cycle")

    def test_longest_chain_is_checked_without_recursion_limit(self):
        # 999 findings, the most F-NNN can number, each depending on the next.
        low = next(f for f in sample()["findings"] if f["severity"] == "Low")
        chain = []
        for n in range(1, 1000):
            f = copy.deepcopy(low)
            f["id"] = f"F-{n:03d}"
            f["depends_on"] = [f"F-{n + 1:03d}"] if n < 999 else ["F-001"]
            chain.append(f)
        self.assertEqual(findings._dependency_problems(chain),
                         ["depends_on forms a cycle: "
                          + " -> ".join(f["id"] for f in chain) + " -> F-001; findings that "
                          "depend on each other are one remedy, so merge them"])
        chain[-1]["depends_on"] = []
        self.assertEqual(findings._dependency_problems(chain), [])

    def test_unknown_dependency_is_refused(self):
        doc = sample()
        by_id(doc, "F-003")["depends_on"] = ["F-009"]
        self.assertProblem(doc, "F-003: depends_on F-009 is not a recorded finding")

    def test_dependency_on_an_excluded_finding_is_refused(self):
        doc = sample()
        by_id(doc, "F-003")["depends_on"] = ["F-005"]
        self.assertProblem(doc, "F-003: depends_on F-005, which is excluded")

    def test_self_dependency_is_a_schema_error(self):
        doc = sample()
        by_id(doc, "F-003")["depends_on"] = ["F-003"]
        with self.assertRaisesRegex(findings.SchemaError, "cannot depend on itself"):
            findings.validate(doc)

    def test_open_medium_needs_a_batch(self):
        doc = sample()
        doc["plan"] = [b for b in doc["plan"] if b["batch"] != 3]
        self.assertProblem(doc, "F-003: an open Medium finding needs a plan batch")

    def test_fixed_medium_needs_no_batch(self):
        doc = sample()
        doc["plan"] = [b for b in doc["plan"] if b["batch"] != 3]
        by_id(doc, "F-003")["status"] = "Fixed"
        self.assertEqual(self.problems(doc), [])

    def test_dependency_planned_later_is_refused(self):
        doc = sample()
        doc["plan"][0]["findings"], doc["plan"][1]["findings"] = ["F-001"], ["F-002"]
        self.assertProblem(doc, "F-001 (batch 1) depends on F-002, planned later in batch 2")

    def test_dependency_in_the_same_batch_is_allowed(self):
        doc = sample()
        doc["plan"] = [{**doc["plan"][0], "findings": ["F-002", "F-001"]},
                       {**doc["plan"][2], "batch": 2}]
        self.assertEqual(self.problems(doc), [])

    def test_batches_are_gapless(self):
        doc = sample()
        doc["plan"][2]["batch"] = 5
        self.assertProblem(doc, "plan: batches must be numbered 1")

    def test_finding_in_two_batches_is_refused(self):
        doc = sample()
        doc["plan"][2]["findings"].append("F-002")
        self.assertProblem(doc, "plan: F-002 is in batch 1 and batch 3")

    def test_excluded_finding_cannot_be_planned(self):
        doc = sample()
        doc["plan"][2]["findings"].append("F-005")
        self.assertProblem(doc, "F-005 is excluded (NotApplicable) and cannot be planned")

    def test_batch_number_must_be_an_integer(self):
        doc = sample()
        doc["plan"][0]["batch"] = True
        with self.assertRaisesRegex(findings.SchemaError, "integer from 1"):
            findings.validate(doc)


class InvisibleReasonTest(Run):
    def test_invisible_reason_on_a_closed_convention_is_blank(self):
        # render shows no reason here, so check does not ask to remove one.
        doc = sample()
        held = next(c for c in doc["conventions"] if c["status"] == "holds")
        held["reason"] = "\u200b"
        self.assertEqual(self.problems(doc), [])


class OrderTest(Run):
    def test_path_order_within_a_severity_is_checked(self):
        # Two Medium findings with gapless IDs in severity order, but not path order.
        doc = sample()
        a, b = by_id(doc, "F-002"), by_id(doc, "F-003")
        self.assertLess(findings._first_location(a), findings._first_location(b))
        for key in ("location", "title"):
            a[key], b[key] = b[key], a[key]
        self.assertProblem(doc, "numbered in renumber's order")


class SchemaExampleTest(Run):
    def test_shape_example_keeps_the_rules_it_documents(self):
        # An excerpt: only the perspectives it leaves out may be missing.
        text = (SKILL / "reference" / "findings-schema.md").read_text(encoding="utf-8")
        shape = text.split("## Shape", 1)[1]
        doc = json.loads(re.search(r"```json\n(.*?)\n```", shape, re.DOTALL)[1])
        self.assertEqual([p for p in self.problems(doc)
                          if not p.startswith("perspective not recorded")], [])


class ConventionTest(Run):
    def test_drifted_convention_needs_a_citing_finding(self):
        doc = sample()
        del by_id(doc, "F-004")["convention"]
        self.assertProblem(doc, "C-02: a drifted convention needs a Valid or Likely finding")

    def test_valid_finding_cites_only_drifted_conventions(self):
        doc = sample()
        by_id(doc, "F-004")["convention"] = "C-01, C-02"
        self.assertProblem(doc, "F-004: Valid finding cites C-01, recorded as holds")

    def test_unknown_convention_is_refused(self):
        doc = sample()
        by_id(doc, "F-004")["convention"] = "C-02, C-09"
        self.assertProblem(doc, "F-004: convention 'C-09' is not a conventions[] id")


class SchemaTest(unittest.TestCase):
    def test_remedy_must_be_a_catalog_name(self):
        doc = sample()
        doc["findings"][0]["remedy"] = "Rewrite"
        with self.assertRaisesRegex(findings.SchemaError, "remedy"):
            findings.validate(doc)

    def test_step_must_belong_to_the_perspective(self):
        doc = sample()
        doc["findings"][0]["step"] = "AI1"
        with self.assertRaisesRegex(findings.SchemaError, "not a Schema constraints step"):
            findings.validate(doc)

    def test_unknown_keys_are_refused(self):
        doc = sample()
        doc["findings"][0]["enforcement"]["hazard"] = "typo"
        with self.assertRaisesRegex(findings.SchemaError, "unknown keys"):
            findings.validate(doc)
        doc = sample()
        doc["findings"][0]["guard"] = "architecture-scan field"
        with self.assertRaisesRegex(findings.SchemaError, "unknown keys"):
            findings.validate(doc)

    def test_ids_use_the_f_prefix(self):
        doc = sample()
        doc["findings"][0]["id"] = "A-001"
        with self.assertRaisesRegex(findings.SchemaError, "must look like F-001"):
            findings.validate(doc)

    def test_huge_step_number_is_refused_not_a_crash(self):
        doc = sample()
        doc["findings"][0]["step"] = "DC" + "1" * 5000
        with self.assertRaisesRegex(findings.SchemaError, "hunt step ID"):
            findings.validate(doc)

    def test_blank_path_is_refused(self):
        for loc in (" :3", "\u200b:3", "\t:3"):
            with self.assertRaises(findings.SchemaError):
                findings._location(loc, "location")

    def test_column_after_the_line_is_refused(self):
        doc = sample()
        for loc in ("worker/sync.py:14:7", "worker/sync.py:14:7-9", "worker/sync.py:14:7-16:9"):
            doc["findings"][0]["location"] = loc
            with self.assertRaisesRegex(findings.SchemaError, "path:line", msg=loc):
                findings.validate(doc)


class MergeAndRenumberTest(unittest.TestCase):
    def test_plan_batch_is_replaced_whole_and_kept_in_order(self):
        doc = sample()
        findings.merge(doc, {"plan": [{"batch": 1, "title": "Pin", "findings": ["F-002"],
                                       "prerequisite": "none", "pr_title": "test: pin"}]}, "f")
        self.assertEqual([b["batch"] for b in doc["plan"]], [1, 2, 3])
        self.assertEqual(doc["plan"][0]["title"], "Pin")
        findings.validate(doc)

    def test_remove_plan_batch_and_convention(self):
        doc = sample()
        findings.merge(doc, {"remove": {"plan": [3], "conventions": ["C-01"]}}, "f")
        self.assertEqual([b["batch"] for b in doc["plan"]], [1, 2])
        self.assertEqual([c["id"] for c in doc["conventions"]], ["C-02"])
        with self.assertRaisesRegex(findings.SchemaError, "is not recorded"):
            findings.merge(doc, {"remove": {"plan": [7]}}, "f")
        doc = sample()
        with self.assertRaisesRegex(findings.SchemaError, "not recorded"):
            findings.merge(doc, {"remove": {"plan": [1.0]}}, "f")

    def test_resent_finding_with_reordered_locations_is_not_a_collision(self):
        doc = sample()
        resent = copy.deepcopy(by_id(doc, "F-001"))
        self.assertIsInstance(resent["location"], list)
        resent["location"] = list(reversed(resent["location"]))
        findings.merge(doc, {"findings": [resent]}, "f")
        self.assertEqual(by_id(doc, "F-001")["location"], resent["location"])

    def test_fragment_from_before_renumber_is_refused(self):
        # Re-merging a fragment still naming F-101 must not add a second copy of
        # the finding renumber called F-001.
        doc = sample()
        old = copy.deepcopy(by_id(doc, "F-001"))
        old["id"] = "F-101"
        with self.assertRaisesRegex(findings.SchemaError, "F-101 repeats F-001"):
            findings.merge(doc, {"findings": [old]}, "fragment")
        # A duplicate kept as NotApplicable shares the title and location of the
        # finding it repeats (reference/validation.md); a stale copy of it does not pass.
        dup = copy.deepcopy(old)
        dup.update(id="F-201", validation={"verdict": "NotApplicable", "method": "static",
                                           "evidence": "Duplicate of F-001"})
        findings.merge(doc, {"findings": [dup]}, "fragment")
        # A third unit's duplicate of the same finding is recorded too.
        dup["id"] = "F-301"
        findings.merge(doc, {"findings": [dup]}, "fragment")
        # A duplicate that names an ID renumber has since given away is stale.
        dup.update(id="F-202", validation={**dup["validation"], "evidence": "Duplicate of F-101"})
        with self.assertRaisesRegex(findings.SchemaError, "F-202 repeats F-001"):
            findings.merge(doc, {"findings": [dup]}, "fragment")
        # Only NotApplicable, and only evidence that is the duplicate statement alone.
        for verdict, evidence in (("FalsePositive", "Duplicate of F-001"),
                                  ("NotApplicable", "Duplicate of F-001!"),
                                  ("NotApplicable", "x Duplicate of F-001")):
            dup.update(id="F-203", validation={"verdict": verdict, "method": "static",
                                               "evidence": evidence})
            with self.assertRaisesRegex(findings.SchemaError, "F-203 repeats", msg=evidence):
                findings.merge(doc, {"findings": [dup]}, "fragment")
        # The duplicate may be recorded before the finding it names.
        doc = sample()
        kept = copy.deepcopy(by_id(doc, "F-003"))
        kept.update(id="F-902", title="Another split", location="worker/other.py:5")
        twin = copy.deepcopy(kept)
        twin.update(id="F-901", validation={"verdict": "NotApplicable", "method": "static",
                                            "evidence": "Duplicate of F-902"})
        findings.merge(doc, {"findings": [twin]}, "fragment")
        findings.merge(doc, {"findings": [kept]}, "fragment")
        # A finding excluded for another reason is no duplicate: a stale copy of
        # it under its old ID is refused (Codex review on #6).
        doc = sample()
        f = by_id(doc, "F-003")
        stale = copy.deepcopy(f)
        f["validation"] = {"verdict": "NotApplicable", "method": "static",
                           "evidence": "dead since a1b2c3d; orders/service.py:120 is unreachable"}
        stale["id"] = "F-103"
        with self.assertRaisesRegex(findings.SchemaError, "F-103 repeats F-003"):
            findings.merge(doc, {"findings": [stale]}, "fragment")
        # The same title elsewhere is another finding.
        old["location"] = "api/other.py:3"
        findings.merge(doc, {"findings": [old]}, "fragment")

    def test_renumber_rewrites_depends_on_and_plan(self):
        doc = sample()
        mapping = {"F-001": "F-101", "F-002": "F-201", "F-003": "F-202",
                   "F-004": "F-301", "F-005": "F-302"}
        shuffled = findings._rewrite_ids(copy.deepcopy(doc), mapping)
        shuffled["findings"].reverse()
        renamed, _ = findings.renumber(shuffled)
        self.assertEqual(renamed["findings"], doc["findings"])
        self.assertEqual(renamed["plan"], doc["plan"])

    def test_mention_after_a_url_in_japanese_prose_is_rewritten(self):
        # No blank separates a URL from Japanese text; an ID after its particle is prose.
        mapping = {"F-002": "F-003"}
        text = "https://github.com/acme/shop/issues/7でF-002が先と判断。F-002の後"
        self.assertEqual(findings._rewrite_ids(text, mapping),
                         "https://github.com/acme/shop/issues/7でF-003が先と判断。F-003の後")
        # An IRI keeps its IDs: after `=`, or right after kanji in its path or query.
        for iri in ("https://jira.example.com/browse?project=案件&key=F-002 を参照",
                    "https://ja.wikipedia.org/wiki/仕様F-002 を参照",
                    "https://ex.com/search?q=案件F-002&key=F-002 を参照"):
            self.assertEqual(findings._rewrite_ids(iri, mapping), iri)

    def test_enforcement_sites_keep_their_paths(self):
        # `enforcement.sites` are path:line literals like `location`.
        doc = {"enforcement": {"sites": ["F-001:3"], "gaps": "F-001 is unpinned"}}
        self.assertEqual(findings._rewrite_ids(doc, {"F-001": "F-003"}),
                         {"enforcement": {"sites": ["F-001:3"], "gaps": "F-003 is unpinned"}})


class RenderTest(unittest.TestCase):
    def test_unlikely_is_not_a_definitive_verdict(self):
        doc = sample()
        by_id(doc, "F-004")["validation"]["verdict"] = "Unlikely"
        for lang in ("en", "ja"):
            html = render.render_html(doc, lang)
            self.assertNotIn(render.DASH[lang]["none_unverified_line"], html)
            self.assertIn("Unlikely", render.plural(render.DASH[lang], "unverified_line", 1))

    def test_not_ready_card_is_not_called_needs_validation(self):
        # A Valid, Confirmed, Staged finding is staged first: validated, not yet ready to ship.
        doc = sample()
        f = by_id(doc, "F-001")
        doc["findings"], doc["plan"] = [f], [{**doc["plan"][0], "findings": [f["id"]]}]
        f.update(rollout="Staged", confidence="Confirmed", depends_on=[])
        f["validation"]["verdict"] = "Valid"
        self.assertEqual(render.action(f), "pin_first")
        for lang in ("en", "ja"):
            label = render.html_text(render.DASH[lang]["needs_validation"])
            self.assertIn(f"<span class='l'>{label}</span><div class='n'>1</div>",
                          render.render_html(doc, lang))

    def test_joined_values_render_on_separate_lines(self):
        # Emphasis must not pair a delimiter in one value with one in the next.
        doc = sample()
        doc["meta"].update(date="*2026-10-15", assessor="Claude*")
        f = by_id(doc, "F-001")
        f["validation"]["method"] = "analysed"
        f["analysis"] = {"tool": "radon*", "command": "radon cc api", "result": "*CC 41"}
        f["enforcement"].update(sites=["db/migrate/x*.rb:12", "db/b.rb:3"], gaps="only the x*")
        f["steps"] = ["rename *old - verify: specs green", "inline new* - verify: specs green"]
        for lang in ("en", "ja"):
            report = render.render_markdown(doc, lang)
            for a, b in (("2026-10-15", "Claude"), ("CC 41", "radon"), ("migrate/x", "only the x"),
                         ("rename", "inline new")):
                self.assertFalse([line for line in report.splitlines() if a in line and b in line],
                                 f"{a!r} and {b!r} share a line in {lang}")

    def test_ready_note_is_shown_on_an_online_finding(self):
        doc = sample()
        f = by_id(doc, "F-002")
        self.assertEqual(render.action(f), "fix_now")
        for lang in ("en", "ja"):
            note = render.DASH[lang]["fix_now_note"]
            self.assertIn(("traffic runs", "稼働中のまま")[lang == "ja"], note)
            shown = render.html_text(note)
            if lang == "ja":
                shown = render.mark_english(shown)
            html = render.render_html(doc, lang)
            detail = html[html.index(f"id='{render.anchor(f)}'"):]
            self.assertIn(shown, detail[:detail.index("</details>")])

    def test_invisible_text_counts_as_blank(self):
        self.assertEqual(render.revision({"commit": "\u200b"}), "UNKNOWN")
        self.assertFalse(render.filled({"evidence": "\u200b \u2060"}, "evidence"))
        self.assertTrue(render.filled({"evidence": "a.py:1"}, "evidence"))
        # An invisible method is not recorded either: the default note stands in.
        for lang in ("en", "ja"):
            self.assertEqual(render.review_method({"meta": {"method": "\u200b"}}, lang),
                             render.LABELS[lang]["static_note"])

    def test_dashboard_shows_the_history_window(self):
        doc = sample()
        for lang in ("en", "ja"):
            html = render.render_html(doc, lang)
            self.assertIn(render.html_text(doc["meta"]["window"]), html)
            self.assertIn(render.LABELS[lang]["window"], html)

    def test_empty_record_set_has_its_own_message(self):
        # Only excluded findings: the default record set is empty, and no
        # filter is set to clear, so the script needs the no-records message.
        doc = sample()
        doc["findings"] = [f for f in doc["findings"] if render.is_excluded(f)]
        doc["plan"] = []
        doc["conventions"] = [c for c in doc["conventions"] if c["status"] != "drifted"]
        for lang in ("en", "ja"):
            html = render.render_html(doc, lang)
            labels = json.loads(re.search(r"id='labels'>(.*?)</script>", html)[1])
            self.assertEqual(labels["no_records"], render.DASH[lang]["no_records"])
            self.assertIn("L.no_records", render.JS)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_dashboard_script_runs_with_no_findings(self):
        # Zero findings is a valid run; the filters are not rendered then.
        doc = sample()
        doc["findings"], doc["plan"] = [], []
        doc["conventions"] = [c for c in doc["conventions"] if c["status"] != "drifted"]
        for lang in ("en", "ja"):
            html = render.render_html(doc, lang)
            self.assertNotIn("id='f-q'", html)
            result = subprocess.run(["node", "-e", DOM_STUB], input=html, capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(result.stdout.strip(), "ok", result.stdout + result.stderr)


class LegendTest(unittest.TestCase):
    """Both outputs say what each severity and confidence level means (SKILL.md's tables)."""

    def test_every_level_has_a_legend_line_in_both_languages(self):
        for lang in ("en", "ja"):
            for level in (*findings.SEVERITIES, *findings.CONFIDENCES):
                with self.subTest(lang=lang, level=level):
                    self.assertTrue(findings.visible(render.LABELS[lang].get(f"legend_{level}", "")))

    def test_the_report_and_dashboard_show_the_legend(self):
        doc = sample()
        for lang in ("en", "ja"):
            t = render.LABELS[lang]
            report = render.render_markdown(doc, lang)
            html = render.render_html(doc, lang)
            self.assertIn(f"## {t['legend']}\n", report)
            self.assertIn(f"<h2>{render.html_text(t['legend'])}</h2>", html)
            self.assertIn("<li><a href=\"#levels\">", html)
            for level in (*findings.SEVERITIES, *findings.CONFIDENCES):
                meaning = t[f"legend_{level}"]
                self.assertIn(f"- **{level}:** {meaning}\n", report)
                shown = render.html_text(meaning)
                self.assertIn(f"<dd>{render.mark_english(shown) if lang == 'ja' else shown}</dd>", html)
            self.assertIn(t["legend_separate"], report)
            self.assertIn(render.html_text(t["legend_separate"]), html)

    def test_the_assumed_axis_line_appears_only_when_the_axis_is_assumed(self):
        doc = sample()
        for axis in ("confirmed", "assumed"):
            doc["meta"]["axis"] = axis
            for lang in ("en", "ja"):
                line = render.LABELS[lang]["legend_assumed"]
                with self.subTest(axis=axis, lang=lang):
                    self.assertEqual(line in render.render_markdown(doc, lang), axis == "assumed")
                    self.assertEqual(render.html_text(line) in render.render_html(doc, lang),
                                     axis == "assumed")
        self.assertEqual(render.LABELS["en"]["legend_assumed"],
                         "Severity rests on an assumed list; see decisions.")


def _playwright():
    """The global Node and Playwright install, if this machine has both (CI may not)."""
    node = shutil.which("node")
    if not node:
        return None
    root = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True).stdout.strip() \
        if shutil.which("npm") else ""
    env = {**os.environ, "NODE_PATH": root}
    # The package alone is not enough: its browser may never have been downloaded.
    probe = subprocess.run([node, "-e", "process.exit(require('fs').existsSync("
                            "require('playwright').chromium.executablePath()) ? 0 : 1)"],
                           env=env, capture_output=True)
    return (node, env) if probe.returncode == 0 else None


PLAYWRIGHT = _playwright()

# Drives the rendered dashboard in Chromium; prints one JSON result.
BROWSER = r"""
const { chromium } = require('playwright');
const [file, hash, sev] = process.argv.slice(1);
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.goto('file://' + file + hash, { waitUntil: 'load' });
  await page.waitForTimeout(200);
  const loaded = await page.evaluate(() => {
    const a = document.activeElement, f = a.closest('.finding');
    return { tag: a.tagName, id: f ? f.id : null,
             open: f ? f.querySelector('details').open : false };
  });
  await page.selectOption('#f-sev', sev);
  const filtered = await page.evaluate(() => ({
    shown: [...document.querySelectorAll('.finding')].filter(d => !d.hidden).map(d => d.id),
    count: document.getElementById('result-count').textContent }));
  console.log(JSON.stringify({ loaded, filtered, errors }));
  await browser.close();
})().catch(e => { console.log(JSON.stringify({ crash: String(e) })); process.exit(1); });
"""


@unittest.skipUnless(PLAYWRIGHT, "node with playwright is not installed")
class BrowserTest(unittest.TestCase):
    """The dashboard script in a real browser: a shared link and a filter."""

    def drive(self, hash_, sev, lang="en"):
        with tempfile.TemporaryDirectory() as tmp:
            page = Path(tmp) / "dashboard.html"
            page.write_text(render.render_html(sample(), lang), encoding="utf-8")
            node, env = PLAYWRIGHT
            result = subprocess.run([node, "-e", BROWSER, str(page), hash_, sev], env=env,
                                    capture_output=True, text=True, timeout=120)
        out = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertNotIn("crash", out, out.get("crash"))
        return out

    def test_a_shared_link_opens_and_focuses_the_finding(self):
        # Excluded (F-005) and upper-case links too; the browser's own jump to
        # the fragment during load must not leave focus on the body.
        for hash_ in ("#finding-f-004", "#finding-f-005", "#finding-F-003"):
            with self.subTest(hash_):
                out = self.drive(hash_, "")
                self.assertEqual(out["errors"], [])
                self.assertEqual(out["loaded"], {"tag": "SUMMARY", "open": True,
                                                 "id": hash_[1:].lower()})

    def test_the_severity_filter_shows_only_that_severity(self):
        out = self.drive("", "Medium")
        self.assertEqual(out["filtered"]["shown"], ["finding-f-002", "finding-f-003"])
        self.assertIn("2", out["filtered"]["count"])

    def test_a_reached_finding_is_not_under_the_pinned_bars(self):
        # From 1100px the app bar, the filter bar and the column heads stay
        # pinned; a finding reached by its link or by `k` shows its summary row
        # (ID, severity, verdict) below them, however tall the filters wrap.
        for lang in ("en", "ja"):
            for width in (1100, 1280, 1600):
                with self.subTest(lang=lang, width=width), \
                        tempfile.TemporaryDirectory() as tmp:
                    page = Path(tmp) / "dashboard.html"
                    page.write_text(render.render_html(sample(), lang), encoding="utf-8")
                    node, env = PLAYWRIGHT
                    result = subprocess.run([node, "-e", BROWSER_PINNED, str(page), str(width)],
                                            env=env, capture_output=True, text=True, timeout=120)
                    out = json.loads(result.stdout.strip().splitlines()[-1])
                    self.assertNotIn("crash", out, out.get("crash"))
                    self.assertEqual(out["errors"], [])
                    for how in ("link", "key"):
                        reached = out[how]
                        self.assertEqual(reached["focus"], "finding-f-003", how)
                        self.assertGreaterEqual(reached["top"], reached["pinned"], (how, reached))

    def test_without_javascript_the_column_heads_pin_under_the_app_bar(self):
        # The filter bar needs the script, so without it nothing sits between
        # the app bar and the pinned column heads for findings to show through.
        with tempfile.TemporaryDirectory() as tmp:
            page = Path(tmp) / "dashboard.html"
            page.write_text(render.render_html(sample(), "en"), encoding="utf-8")
            node, env = PLAYWRIGHT
            result = subprocess.run([node, "-e", BROWSER_NO_SCRIPT, str(page)], env=env,
                                    capture_output=True, text=True, timeout=120)
        out = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertNotIn("crash", out, out.get("crash"))
        self.assertLessEqual(abs(out["head"] - out["appbar"]), 2, out)


# A finding reached by a link, then by `k` from the one after it: where its
# summary starts, and where the pinned bars above it end.
BROWSER_PINNED = r"""
const { chromium } = require('playwright');
const [file, width] = process.argv.slice(1);
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: Number(width), height: 800 } });
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  const where = () => page.evaluate(() => {
    const bottom = s => document.querySelector(s).getBoundingClientRect().bottom;
    const a = document.activeElement, f = a.closest('.finding');
    return { focus: f ? f.id : null,
             top: Math.round(document.querySelector('#finding-f-003 summary').getBoundingClientRect().top),
             pinned: Math.round(Math.max(bottom('.appbar'), bottom('.filters-panel'), bottom('.reg-head'))) };
  });
  await page.goto('file://' + file + '#finding-f-003', { waitUntil: 'load' });
  await page.waitForTimeout(1000);  // the kit scrolls smoothly
  const link = await where();
  await page.evaluate(() => {
    const s = document.querySelector('#finding-f-004 summary');
    s.focus({ preventScroll: true });
    window.scrollTo({ top: s.closest('.finding').offsetTop + 600, behavior: 'instant' });
  });
  await page.keyboard.press('k');
  await page.waitForTimeout(1000);
  const key = await where();
  console.log(JSON.stringify({ link, key, errors }));
  await browser.close();
})().catch(e => { console.log(JSON.stringify({ crash: String(e) })); process.exit(1); });
"""

# With scripts off, scrolled into the register: where the app bar ends and the
# pinned column heads start.
BROWSER_NO_SCRIPT = r"""
const { chromium } = require('playwright');
const [file] = process.argv.slice(1);
(async () => {
  const browser = await chromium.launch();
  const context = await browser.newContext({ javaScriptEnabled: false,
                                             viewport: { width: 1280, height: 800 } });
  const page = await context.newPage();
  await page.goto('file://' + file + '#finding-f-004', { waitUntil: 'load' });
  await page.waitForTimeout(1000);
  console.log(JSON.stringify(await page.evaluate(() => ({
    appbar: Math.round(document.querySelector('.appbar').getBoundingClientRect().bottom),
    head: Math.round(document.querySelector('.reg-head').getBoundingClientRect().top) }))));
  await browser.close();
})().catch(e => { console.log(JSON.stringify({ crash: String(e) })); process.exit(1); });
"""


# Runs a dashboard's page script against a DOM holding only the page's ids.
DOM_STUB = r"""
const h = require('fs').readFileSync(0, 'utf8');
const ids = new Set([...h.matchAll(/ id='([^']+)'/g)].map(m => m[1]));
const js = h.match(/<script>([\s\S]*)<\/script>/)[1];
const text = id => (h.match(new RegExp("id='" + id + "'>([\\s\\S]*?)</script>")) || [, ''])[1];
const el = id => ({id, textContent: text(id), dataset: {}, value: '', hidden: true,
  classList: {contains: () => false}, querySelectorAll: () => [], querySelector: () => null,
  appendChild() {}});
global.document = {documentElement: {dataset: {}}, getElementById: id => ids.has(id) ? el(id) : null,
  querySelectorAll: () => [], querySelector: () => null, addEventListener() {}};
global.window = {addEventListener() {}, matchMedia: () => ({matches: false})};
global.location = {hash: ''}; global.navigator = {};
const handlers = [];
global.addEventListener = (name, fn) => handlers.push([name, fn]);
try {
  eval(js);
  for (const name of ['beforeprint', 'afterprint'])
    handlers.filter(h => h[0] === name).forEach(h => h[1]());
  console.log('ok');
} catch (e) { console.log('throws', e.message); }
"""


class DocumentsTest(unittest.TestCase):
    def read(self, name):
        return (SKILL / name).read_text(encoding="utf-8")

    def test_perspectives_and_steps_match_the_reference(self):
        text = self.read("reference/perspectives.md")
        headings = re.findall(r"^### (.+) \(([A-Z]{2})\)$", text, re.M)
        self.assertEqual([h[0] for h in headings], list(findings.PERSPECTIVES))
        self.assertEqual([h[1] for h in headings], list(findings.STEP_PREFIXES))
        table = re.findall(r"^\| (.+?) \| .+ \|$", text.split("## Hunt steps")[0], re.M)
        self.assertEqual([n for n in table if n in findings.PERSPECTIVES], list(findings.PERSPECTIVES))
        for prefix, count in zip(findings.STEP_PREFIXES, findings.STEP_COUNTS):
            steps = sorted(set(re.findall(rf"^\| ({prefix}[0-9]+) \|", text, re.M)))
            self.assertEqual(steps, [f"{prefix}{i}" for i in range(1, count + 1)], prefix)

    def test_remedies_match_the_catalog(self):
        text = self.read("reference/remedies.md").split("## Preservation pitfalls")[0]
        names = re.findall(r"^\| ([A-Z][^|]+?) \| [A-Z]{2}[0-9]", text, re.M)
        self.assertEqual(names, list(findings.REMEDIES))

    def test_catalog_cites_only_existing_steps(self):
        text = self.read("reference/remedies.md")
        steps = set(re.findall(r"\b([A-Z]{2})([0-9]+)\b", text))
        known = dict(zip(findings.STEP_PREFIXES, findings.STEP_COUNTS))
        for prefix, n in steps:
            if prefix in known:
                self.assertLessEqual(int(n), known[prefix], f"{prefix}{n}")

    def test_enums_in_skill_match_the_scripts(self):
        text = self.read("SKILL.md")
        for value in findings.ROLLOUTS + findings.SEVERITIES + findings.CONFIDENCES:
            self.assertIn(f"`{value}`" if value in findings.ROLLOUTS + findings.CONFIDENCES else value,
                          text)

    def test_concerns_match_conventions_reference(self):
        text = self.read("reference/conventions.md")
        for concern in findings.CONCERNS:
            self.assertIn(f"`{concern}`", text)

    def test_every_reference_is_named_in_skill(self):
        skill = self.read("SKILL.md")
        for ref in sorted((SKILL / "reference").glob("*.md")):
            self.assertIn(f"reference/{ref.name}", skill)




# Rule-by-rule tests: each one fails when its rule in findings.py or render.py
# is broken (a one-line mutation of the rule leaves every other test green).
def renumber_plan(doc, keep):
    doc["plan"] = [dict(b, batch=i) for i, b in enumerate(
        (b for b in doc["plan"] if b["batch"] in keep), 1)]


class ContractGapTest(Run):
    def test_missing_and_unexpected_outputs(self):
        doc = sample()
        self.problems(doc)
        (self.out / "report.md").unlink()
        (self.out / "notes.txt").write_text("x")
        problems = findings.contract_problems(self.out)
        self.assertIn("missing output: report.md", problems)
        self.assertTrue(any(p.startswith("unexpected output: notes.txt") for p in problems))

    def test_output_that_is_a_directory(self):
        self.problems(sample())
        (self.out / "dashboard.html").unlink()
        (self.out / "dashboard.html").mkdir()
        self.assertIn("output is not a file: dashboard.html", findings.contract_problems(self.out))

    def test_ids_must_be_gapless(self):
        doc = sample()
        by_id(doc, "F-005")["id"] = "F-006"
        self.assertProblem(doc, "IDs must be gapless")

    def test_severity_order(self):
        doc = sample()
        by_id(doc, "F-004")["severity"] = "High"
        self.assertProblem(doc, "numbered in severity order")

    def test_excluded_last(self):
        doc = sample()
        by_id(doc, "F-003")["validation"]["verdict"] = "FalsePositive"
        self.assertProblem(doc, "excluded findings (FalsePositive, NotApplicable) are "
                                "numbered after")

    def test_every_perspective_recorded(self):
        doc = sample()
        doc["perspectives"] = doc["perspectives"][1:]
        self.assertProblem(doc, "perspective not recorded: Schema constraints")

    def test_category_must_be_applied(self):
        doc = sample()
        p = next(p for p in doc["perspectives"] if p["name"] == "Concurrency and lost updates")
        p["status"] = "N/A"
        self.assertProblem(doc, "F-003: category Concurrency and lost updates is recorded as N/A")

    def test_stale_outputs(self):
        doc = sample()
        self.problems(doc)
        doc["findings"][0]["title"] = "Changed after render"
        (self.out / "findings.json").write_text(json.dumps(doc), encoding="utf-8")
        problems = findings.contract_problems(self.out)
        self.assertTrue(any("report.md does not match findings.json" in p for p in problems))

    def test_limitations_and_checked_ok_required(self):
        doc = sample()
        doc["limitations"], doc["checked_ok"] = [], []
        self.assertProblem(doc, "limitations: state what static reading cannot show")
        self.assertProblem(doc, "checked_ok: list what was examined")


class EvidenceTest(Run):
    def test_valid_evidence_cites_path_line(self):
        doc = sample()
        by_id(doc, "F-001")["validation"]["evidence"] = "the copies diverged"
        self.assertProblem(doc, "F-001: Valid evidence must cite path:line")

    def test_host_and_port_is_not_a_line(self):
        doc = sample()
        by_id(doc, "F-001")["validation"]["evidence"] = "db.internal:5432 times out"
        self.assertProblem(doc, "F-001: Valid evidence must cite path:line")

    def test_duplicate_must_name_a_kept_finding(self):
        doc = sample()
        by_id(doc, "F-005")["validation"]["evidence"] = "Duplicate of F-009"
        self.assertProblem(doc, "F-005: NotApplicable evidence must cite path:line")

    def test_likely_medium_needs_evidence(self):
        doc = sample()
        by_id(doc, "F-003")["validation"] = {"verdict": "Likely", "method": "static"}
        self.assertProblem(doc, "F-003: a Medium finding needs validation.evidence")

    def test_invisible_exposure_is_missing(self):
        doc = sample()
        by_id(doc, "F-003")["exposure"] = "\u200b"
        self.assertProblem(doc, "F-003: a Medium finding needs exposure")

    def test_verify_needs_its_colon(self):
        doc = sample()
        by_id(doc, "F-004")["steps"] = ["1. Inline it, verify tests green"]
        self.assertProblem(doc, "F-004: step 1 does not say how it is checked")


class EnforcementGapTest(Run):
    def test_enforcement_rules_apply_only_when_enforcement_is_recorded(self):
        # A Low Downtime finding without enforcement is complete; readiness asks
        # for enforcement only at Medium and above.
        f = copy.deepcopy(by_id(sample(), "F-004"))
        del f["enforcement"]
        self.assertEqual(findings._enforcement_problems(f), [])

    def test_an_excluded_staged_finding_needs_no_rollout_reason(self):
        doc = sample()
        f = by_id(doc, "F-005")
        f["rollout"] = "Staged"
        self.assertNotIn("rollout_reason", f)
        self.assertFalse([p for p in self.problems(doc) if "rollout_reason" in p])

class ConventionGapTest(Run):
    def test_likely_cites_drifted_or_partly_read(self):
        doc = sample()
        by_id(doc, "F-004")["validation"]["verdict"] = "Likely"
        by_id(doc, "F-004")["convention"] = "C-01, C-02"
        self.assertProblem(doc, "F-004: Likely finding cites C-01, recorded as holds")

    def test_unlikely_finding_does_not_back_drift(self):
        doc = sample()
        by_id(doc, "F-004")["validation"]["verdict"] = "Unlikely"
        self.assertProblem(doc, "C-02: a drifted convention needs a Valid or Likely finding")

    def test_closed_convention_keeps_no_reason(self):
        doc = sample()
        doc["conventions"][0]["reason"] = "provisional"
        self.assertProblem(doc, "C-01: a reason explains a not-checked")

    def test_not_checked_needs_reason(self):
        doc = sample()
        doc["conventions"][0]["status"] = "not checked"
        doc["conventions"][0].pop("reason", None)
        self.assertProblem(doc, "C-01: a not-checked convention needs a nonblank string reason")


class PlanGapTest(Run):
    def test_batches_in_order(self):
        doc = sample()
        doc["plan"][0], doc["plan"][1] = doc["plan"][1], doc["plan"][0]
        self.assertProblem(doc, "plan: batches must be numbered 1")

    def test_plan_names_recorded_findings(self):
        doc = sample()
        doc["plan"][2]["findings"].append("F-009")
        self.assertProblem(doc, "plan batch 3: F-009 is not a recorded finding")

    def test_open_dependency_must_be_planned(self):
        doc = sample()
        renumber_plan(doc, {2, 3})
        self.assertProblem(doc, "F-001 (batch 1) depends on F-002, which is in no batch")

    def test_fixed_dependency_needs_no_batch(self):
        doc = sample()
        renumber_plan(doc, {2, 3})
        by_id(doc, "F-002")["status"] = "Fixed"
        self.assertEqual(self.problems(doc), [])


class SchemaGapTest(unittest.TestCase):
    def test_location_lines(self):
        for loc in ("a.py:0", "a.py:5-3"):
            with self.assertRaises(findings.SchemaError, msg=loc):
                findings._location(loc, "location")

    def test_duplicate_dependency(self):
        doc = sample()
        by_id(doc, "F-001")["depends_on"] = ["F-002", "F-002"]
        with self.assertRaisesRegex(findings.SchemaError, "duplicate IDs"):
            findings.validate(doc)

    def test_batch_shape(self):
        doc = sample()
        doc["plan"][0]["findings"] = []
        with self.assertRaisesRegex(findings.SchemaError, "at least one finding"):
            findings.validate(doc)
        doc = sample()
        doc["plan"][1]["batch"] = 1
        with self.assertRaisesRegex(findings.SchemaError, "duplicate 1"):
            findings.validate(doc)


class LocationTest(unittest.TestCase):
    def test_repo_locations(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            (repo / "a.py").write_text("1\n2\n3\n")
            (Path(tmp) / "outside.py").write_text("1\n")
            doc = {"findings": [{"id": "F-001",
                                 "location": ["a.py:3", "a.py:9", "../outside.py:1"]}]}
            problems = findings.location_problems(doc, repo)
            self.assertEqual(len(problems), 2, problems)
            self.assertIn("line 9 is past the end of a.py (3 lines)", problems[0])
            self.assertIn("../outside.py:1: no such file", problems[1])


class EnforcementTestLocationTest(unittest.TestCase):
    def test_repo_checks_enforcement_sites_too(self):
        # The sites named under enforcement must exist at the assessed revision.
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "a.py").write_text("1\n2\n", encoding="utf-8")
            (repo / "schema.rb").write_text("1\n", encoding="utf-8")
            doc = {"findings": [{"id": "F-001", "location": "a.py:2",
                                 "enforcement": {"net": "partial", "sites": ["schema.rb:1",
                                            "schema.rb:7", "db/gone.rb:3"], "gaps": "x"}}]}
            problems = findings.location_problems(doc, repo)
            self.assertEqual(len(problems), 2, problems)
            self.assertIn("F-001: enforcement.sites schema.rb:7: line 7 is past the end", problems[0])
            self.assertIn("F-001: enforcement.sites db/gone.rb:3: no such file", problems[1])


class MergeGapTest(unittest.TestCase):
    def test_null_removes_only_optional_keys(self):
        doc = sample()
        findings.merge(doc, {"findings": [{"id": "F-004", "convention": None}]}, "f")
        self.assertNotIn("convention", by_id(doc, "F-004"))
        with self.assertRaisesRegex(findings.SchemaError, "required"):
            findings.merge(sample(), {"meta": {"project": None}}, "f")

    def test_complete_record_with_new_title_collides(self):
        doc = sample()
        other = copy.deepcopy(by_id(doc, "F-001"))
        other["title"] = "Another finding"
        with self.assertRaisesRegex(findings.SchemaError, "already holds"):
            findings.merge(doc, {"findings": [other]}, "f")

    def test_partial_record_changing_title_and_location_collides(self):
        with self.assertRaisesRegex(findings.SchemaError, "already holds"):
            findings.merge(sample(), {"findings": [{"id": "F-001", "title": "x",
                                                    "location": "x.py:1"}]}, "f")

    def test_replacement_takes_the_first_removed_slot(self):
        doc = sample()
        doc["next_steps"] = ["a", "b", "c"]
        findings.merge(doc, {"remove": {"next_steps": ["a", "c"]}, "next_steps": ["z"]}, "f")
        self.assertEqual(doc["next_steps"], ["z", "b"])
        with self.assertRaisesRegex(findings.SchemaError, "not recorded"):
            findings.merge(doc, {"remove": {"next_steps": ["nope"]}}, "f")

    def test_lists_append_without_duplicates(self):
        doc = sample()
        before = list(doc["checked_ok"])
        findings.merge(doc, {"checked_ok": [before[0]]}, "f")
        self.assertEqual(doc["checked_ok"], before)

    def test_perspective_replaced_whole(self):
        doc = sample()
        findings.merge(doc, {"perspectives": [{"name": "Backup and restore assumptions", "status": "N/A",
                                               "note": "none here"}]}, "f")
        rows = [p for p in doc["perspectives"] if p["name"] == "Backup and restore assumptions"]
        self.assertEqual([p["status"] for p in rows], ["N/A"])

    def test_removed_convention_comes_back_complete(self):
        with self.assertRaisesRegex(findings.SchemaError, "must be complete"):
            findings.merge(sample(), {"remove": {"conventions": ["C-01"]},
                                      "conventions": [{"id": "C-01", "status": "drifted"}]}, "f")


class RenumberGapTest(unittest.TestCase):
    M = {"F-001": "F-002"}

    def test_literal_keys_keep_ids(self):
        rec = {"location": "F-001.py:3", "command": "pytest -k F-001", "source": "ADR F-001",
               "url": "F-001"}
        self.assertEqual(findings._rewrite_ids(rec, self.M), rec)

    def test_email_and_nested_url_and_ticket_keep_ids(self):
        for text, want in (("mail F-001@example.com on F-001", "mail F-001@example.com on F-002"),
                           ("see https://a.example/?next=https://b.example/F-001 then F-001",
                            "see https://a.example/?next=https://b.example/F-001 then F-002"),
                           ("JIRA-F-001 and F-001", "JIRA-F-001 and F-002")):
            self.assertEqual(findings._rewrite_ids(text, self.M), want)

    def test_meta_keeps_its_ids(self):
        doc = sample()
        a, b = by_id(doc, "F-002"), by_id(doc, "F-003")
        a["id"], b["id"] = "F-003", "F-002"
        doc["meta"]["scope"] = "follows up F-002"
        renamed, mapping = findings.renumber(doc)
        self.assertTrue(mapping)
        self.assertEqual(renamed["meta"]["scope"], "follows up F-002")


class EscapingTest(unittest.TestCase):
    def test_markdown_inline(self):
        out = render.markdown_inline("[x](javascript:alert(1)) <img src=x> https://e.example "
                                     "bob@example.com a|b a\\*")
        for bad in ("[x]", "<img", "https://", "bob@example", "|", "\\*"):
            self.assertNotIn(bad, out)

    def test_backslash_keeps_the_next_delimiter_literal(self):
        self.assertEqual(render.markdown_inline("a\\*b*"), "a&#92;&#42;b*")

    def test_block_safe(self):
        self.assertTrue(render.block_safe("# h").startswith("&#35;"))
        self.assertTrue(render.block_safe("> q").startswith("&#62;"))

    def test_markdown_code(self):
        self.assertEqual(render.markdown_code("a`b<c\nd"), "<code>a&#96;b&#60;c<br>d</code>")

    def test_links(self):
        for url in ("javascript:alert(1)", "java\tscript:alert(1)", "//evil.example/x"):
            self.assertFalse(render.is_safe_link(url), url)
            self.assertNotIn("<a ", render.html_reference({"url": url}))
        self.assertFalse(render.is_web_url("https://a b"))
        self.assertTrue(render.is_safe_link("docs/adr/0007.md"))

    def test_html_and_json(self):
        self.assertEqual(render.html_text("<b>&\n"), "&lt;b&gt;&amp;<br>")
        self.assertNotIn("<", render.json_data({"t": "</script><!--"}))

    def test_bidi_and_heading(self):
        self.assertEqual(render.as_text("a\u202eb"), "a[U+202E]b")
        # Every Bidi_Control: LRM, RLM and ALM reorder the text after them too.
        for char in "\u061c\u200e\u200f\u202a\u2066\u2069":
            with self.subTest(f"U+{ord(char):04X}"):
                self.assertEqual(render.as_text(f"a{char}b"), f"a[U+{ord(char):04X}]b")
                self.assertFalse(render.is_safe_link(f"https://example.org/{char}x"))
        self.assertTrue(render.heading_text("C#").endswith("&#35;"))


class LockTest(unittest.TestCase):
    """merge, renumber, render and check share one lock on the output directory."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name)
        (self.out / "findings.json").write_text(SAMPLE.read_text(encoding="utf-8"),
                                                encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    @unittest.skipIf(findings.fcntl is None, "no fcntl: merges are not locked")
    def test_unlockable_directory_refuses_the_merge(self):
        # A directory that can be written but not read cannot be locked; parallel
        # merges there lost findings while each reported success.
        real = os.open

        def no_read(path, flags, *args):
            if os.path.isdir(path):
                raise PermissionError(13, "Permission denied", path)
            return real(path, flags, *args)

        fragment = self.out / "frag.json"
        fragment.write_text(json.dumps({"next_steps": ["x"]}), encoding="utf-8")
        err = io.StringIO()
        with mock.patch("findings.os.open", no_read), contextlib.redirect_stderr(err):
            code = findings.main(["merge", str(self.out / "findings.json"), str(fragment)])
        self.assertEqual(code, 1)
        self.assertIn("cannot lock", err.getvalue())
        self.assertNotIn("x", json.loads((self.out / "findings.json").read_text())["next_steps"])

    @unittest.skipIf(findings.fcntl is None, "no fcntl")
    def test_waiters_say_so_and_wait(self):
        with contextlib.redirect_stdout(io.StringIO()):
            render.main([str(self.out / "findings.json"), "--out", str(self.out)])
        elsewhere = tempfile.TemporaryDirectory()
        self.addCleanup(elsewhere.cleanup)
        fragment = Path(elsewhere.name) / "frag.json"  # not an output of the run
        fragment.write_text(json.dumps({"next_steps": ["waited"]}), encoding="utf-8")
        commands = {
            "merge": [sys.executable, str(SCRIPTS / "findings.py"), "merge",
                      str(self.out / "findings.json"), str(fragment)],
            "render": [sys.executable, str(SCRIPTS / "render.py"),
                       str(self.out / "findings.json"), "--out", str(self.out)],
            "check": [sys.executable, str(SCRIPTS / "findings.py"), "check", str(self.out)],
        }
        for name, command in commands.items():
            fd = os.open(self.out, os.O_RDONLY)
            try:
                findings.fcntl.flock(fd, findings.fcntl.LOCK_EX)
                proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True)
                # A waiter says so at once; without the message, give up after 30 s.
                ready, _, _ = select.select([proc.stderr], [], [], 30)
                line = proc.stderr.readline() if ready else ""
                waiting = proc.poll() is None
            finally:
                os.close(fd)
            if not ready:
                proc.kill()
            stdout, rest = proc.communicate(timeout=60)
            self.assertIn("waiting for the lock", line, name)
            self.assertTrue(waiting, f"{name} did not wait for the lock")
            # merge, then render, then check: each must finish cleanly.
            self.assertEqual(proc.returncode, 0, name + rest)
        self.assertIn("waited", json.loads((self.out / "findings.json").read_text())["next_steps"])

    @unittest.skipIf(findings.fcntl is None, "no fcntl")
    def test_render_reads_the_record_under_the_lock(self):
        # A merge that lands while render waits must be what render writes.
        record = self.out / "findings.json"
        fd = os.open(self.out, os.O_RDONLY)
        try:
            findings.fcntl.flock(fd, findings.fcntl.LOCK_EX)
            proc = subprocess.Popen([sys.executable, str(SCRIPTS / "render.py"), str(record),
                                     "--out", str(self.out)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            ready, _, _ = select.select([proc.stderr], [], [], 30)
            doc = json.loads(record.read_text(encoding="utf-8"))
            doc["findings"][0]["title"] = "Merged while render waited"
            record.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
        finally:
            os.close(fd)
        if not ready:
            proc.kill()
        _, err = proc.communicate(timeout=60)
        self.assertEqual(proc.returncode, 0, err)
        self.assertIn("Merged while render waited", (self.out / "report.md").read_text())

    @unittest.skipIf(findings.fcntl is None, "no fcntl")
    def test_record_broken_while_render_waits_is_a_schema_error(self):
        record = self.out / "findings.json"
        fd = os.open(self.out, os.O_RDONLY)
        try:
            findings.fcntl.flock(fd, findings.fcntl.LOCK_EX)
            proc = subprocess.Popen([sys.executable, str(SCRIPTS / "render.py"), str(record),
                                     "--out", str(self.out)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            ready, _, _ = select.select([proc.stderr], [], [], 30)
            record.write_text(json.dumps({"meta": {"project": "p"}}), encoding="utf-8")
        finally:
            os.close(fd)
        if not ready:
            proc.kill()
        _, err = proc.communicate(timeout=60)
        self.assertEqual(proc.returncode, 2, err)
        self.assertIn("schema:", err)
        self.assertNotIn("Traceback", err)
        self.assertFalse((self.out / "report.md").exists())

    @unittest.skipIf(findings.fcntl is None, "no fcntl")
    def test_check_reads_repo_locations_under_the_lock(self):
        with contextlib.redirect_stdout(io.StringIO()):
            render.main([str(self.out / "findings.json"), "--out", str(self.out)])
        held = []
        real = findings.location_problems

        def probe(doc, repo):
            fd = os.open(self.out, os.O_RDONLY)
            try:
                findings.fcntl.flock(fd, findings.fcntl.LOCK_EX | findings.fcntl.LOCK_NB)
                held.append(False)
            except BlockingIOError:
                held.append(True)
            finally:
                os.close(fd)
            return real(doc, repo)

        with mock.patch("findings.location_problems", probe), \
                contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            findings.main(["check", str(self.out), "--repo", str(self.out)])
        self.assertEqual(held, [True])


# The command lines, file handling and rendered content (a second mutation run).
def run_script(script, *args):
    """Run a script as the CLI does; return the CompletedProcess (text mode)."""
    return subprocess.run([sys.executable, "-B", str(SCRIPTS / script), *map(str, args)],
                          capture_output=True, text=True)


def write_json(path, doc):
    path.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
    return path


class FindingsCliTest(Run):
    """findings.py exit codes: 0 ok, 1 refused or contract failed, 2 bad command line."""

    def test_merge_exit_codes(self):
        target = self.out / "findings.json"
        good = write_json(self.out / "good.json", {"meta": {"project": "p"}})
        bad = write_json(self.out / "bad.json", {"meta": {"project": "p"}, "typo": 1})
        result = run_script("findings.py", "merge", target, good)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("merged 1 fragment(s)", result.stdout)
        result = run_script("findings.py", "merge", target, bad)
        self.assertEqual(result.returncode, 1)
        self.assertIn("refused:", result.stderr)
        self.assertEqual(run_script("findings.py", "merge", target).returncode, 2)

    def test_merge_refuses_a_blank_rollout_reason(self):
        target = write_json(self.out / "findings.json", sample())
        before = target.read_bytes()
        bad = write_json(self.out / "bad.json",
                         {"findings": [{"id": "F-004", "rollout_reason": "  "}]})
        result = run_script("findings.py", "merge", target, bad)
        self.assertEqual(result.returncode, 1)
        self.assertIn("rollout_reason: must be a nonblank string", result.stderr)
        self.assertEqual(target.read_bytes(), before)

    def test_refused_first_merge_creates_no_directory(self):
        bad = write_json(self.out / "bad.json", {"typo": 1})
        result = run_script("findings.py", "merge", self.out / "new" / "findings.json", bad)
        self.assertEqual(result.returncode, 1)
        self.assertFalse((self.out / "new").exists())

    def test_merge_refuses_a_fragment_that_breaks_the_record(self):
        target = self.out / "findings.json"
        target.write_bytes(SAMPLE.read_bytes())
        bad = write_json(self.out / "bad.json", {"meta": {"lang": "fr"}})
        result = run_script("findings.py", "merge", target, bad)
        self.assertEqual(result.returncode, 1)
        self.assertIn("meta.lang", result.stderr)
        self.assertEqual(target.read_bytes(), SAMPLE.read_bytes())

    def test_renumber_exit_codes_and_messages(self):
        missing = run_script("findings.py", "renumber", self.out / "none.json")
        self.assertEqual(missing.returncode, 1)
        doc = sample()
        by_id(doc, "F-001")["id"] = "F-009"
        target = write_json(self.out / "findings.json", doc)
        result = run_script("findings.py", "renumber", target)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("F-009 -> F-001", result.stdout)

    def test_renumber_writes_a_reorder_that_keeps_every_id(self):
        doc = sample()
        doc["findings"].reverse()
        target = write_json(self.out / "findings.json", doc)
        result = run_script("findings.py", "renumber", target)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("reordered the findings", result.stdout)
        ids = [f["id"] for f in json.loads(target.read_text(encoding="utf-8"))["findings"]]
        self.assertEqual(ids, ["F-001", "F-002", "F-003", "F-004", "F-005"])

    def test_counts_refuse_an_incomplete_record(self):
        target = write_json(self.out / "partial.json", {"findings": []})
        result = run_script("findings.py", "counts", target)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")

    def test_fixed_count_leaves_excluded_findings_out(self):
        doc = sample()
        by_id(doc, "F-005")["status"] = "Fixed"
        self.assertEqual(findings.template_counts(doc)["n_fixed"], 0)
        by_id(doc, "F-004")["status"] = "Fixed"
        self.assertEqual(findings.template_counts(doc)["n_fixed"], 1)

    def test_check_exit_codes_and_allow(self):
        self.problems(sample())
        (self.out / "notes.txt").write_text("x", encoding="utf-8")
        (self.out / "extra.txt").write_text("x", encoding="utf-8")
        result = run_script("findings.py", "check", self.out)
        self.assertEqual(result.returncode, 1)
        self.assertIn("unexpected output: notes.txt", result.stderr)
        result = run_script("findings.py", "check", self.out, "--allow", "notes.txt",
                            "--allow", "extra.txt")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("contract ok", result.stdout)
        self.assertEqual(run_script("findings.py", "check").returncode, 2)

    def test_check_with_repo_names_missing_files(self):
        self.problems(sample())
        empty = self.out / "checkout"
        empty.mkdir()
        result = run_script("findings.py", "check", self.out, "--allow", "checkout",
                            "--repo", empty)
        self.assertEqual(result.returncode, 1)
        self.assertIn("F-001: location app/admin/customers_controller.rb:42: no such file", result.stderr)


class LineCountTest(unittest.TestCase):
    def test_lone_cr_lines_and_empty_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "mac.py").write_bytes(b"a\rb\rc")
            (repo / "empty.py").write_bytes(b"")
            doc = {"findings": [{"id": "F-001", "location": ["mac.py:3", "empty.py:1"]}]}
            self.assertEqual(findings.location_problems(doc, repo), [])


class ReadJsonTest(unittest.TestCase):
    def read(self, raw):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "f.json"
            path.write_bytes(raw)
            return findings.read_json(path)

    def test_byte_order_mark_is_not_content(self):
        self.assertEqual(self.read(b"\xef\xbb\xbf{\"a\": 1}"), {"a": 1})

    def test_bad_documents_are_schema_errors(self):
        for raw in (b'{"a": 1, "a": 2}', b'{"a": NaN}', b'{"a": 1e999}', b'{"a": "\\ud800"}',
                    b"[" * 100000 + b"]" * 100000):
            with self.assertRaises(findings.SchemaError, msg=raw[:20]):
                self.read(raw)


class AtomicWriteTest(unittest.TestCase):
    def test_mode_and_symlink_are_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            real, link = Path(tmp) / "real.json", Path(tmp) / "link.json"
            real.write_bytes(b"old")
            real.chmod(0o600)
            link.symlink_to(real)
            findings._atomic_write(link, b"new")
            self.assertTrue(link.is_symlink())
            self.assertEqual(real.read_bytes(), b"new")
            self.assertEqual(real.stat().st_mode & 0o777, 0o600)


class CitesLineTest(unittest.TestCase):
    def test_files_count_and_hosts_versions_times_do_not(self):
        for text in ("Dockerfile:3", "Makefile:12", ".env.local:2", ".env.1:2", "BUILD:12",
                     "CODEOWNERS:4", "C:\\repo\\a.py:3"):
            self.assertTrue(findings.cites_line(text), text)
        for text in ("https://example.org:8080/x", "v1.2:3", "at 10:30", "ratio:3",
                     "api.example.com:443"):
            self.assertFalse(findings.cites_line(text), text)

    def test_an_opening_bracket_or_quote_is_not_part_of_the_path(self):
        for text in ("declared twice (`BUILD:12`)", "see \"gradlew:10\"", "[CODEOWNERS:4]"):
            self.assertTrue(findings.cites_line(text), text)
        self.assertTrue(findings.cites_line("same loop (server:9)", ["bin/server:9"]))
        self.assertEqual(list(findings.evidence_paths("(`BUILD:12`)")), ["BUILD"])

    def test_windows_drive_is_part_of_the_path(self):
        self.assertEqual(list(findings.evidence_paths("see C:\\repo\\a.py:3")),
                         ["C:\\repo\\a.py"])


class DashboardContentTest(unittest.TestCase):
    def html(self, doc):
        return render.render_html(doc, "en")

    def test_headline_variants(self):
        doc = sample()
        self.assertIn("<strong>3 open High / Medium findings need attention.</strong>",
                      self.html(doc))
        for fid in ("F-001", "F-002", "F-003"):
            by_id(doc, fid)["status"] = "Fixed"
        self.assertIn("<strong>1 open finding is recorded; it is not High or Medium.</strong>",
                      self.html(doc))
        by_id(doc, "F-004")["status"] = "Accepted"
        self.assertIn("<strong>No open findings are recorded.", self.html(doc))

    def test_no_included_findings_banner_shows_the_method(self):
        doc = sample()
        doc["findings"] = []
        self.assertIn("<p>Static review; git log 12 months</p></div>", self.html(doc))

    def test_contents_links_resolve_to_sections(self):
        doc = sample()
        html = self.html(doc)
        links = re.findall(r"<li><a href=\"#([a-z-]+)\">", html.split("</nav>")[0])
        self.assertEqual(links, ["overview", "priority-section", "decisions-section", "coverage",
                                 "levels", "plan", "rules", "charts", "findings", "lists"])
        for target in links:
            self.assertEqual(html.count(f"id='{target}'"), 1, target)
        doc["conventions"] = []
        self.assertNotIn("href=\"#rules\"", self.html(doc))

    def test_facets_count_included_findings_by_severity(self):
        doc = sample()
        by_sev, _ = render.counts(doc["findings"])
        html = self.html(doc)
        for s in render.SEVERITIES:
            self.assertIn(f"data-sev='{s}' aria-controls='register-list' aria-pressed='false'>"
                          f"<span class='facet-name {s}'>{s}</span>"
                          f"<span class='facet-n'>{by_sev[s]}</span></button>", html)
        doc["findings"] = []
        html = self.html(doc)
        self.assertNotIn("class='facet'", html)
        self.assertNotIn("class='keys'", html)

    def test_cards_count_not_ready_and_closed_included_only(self):
        doc = sample()
        by_id(doc, "F-005")["status"] = "Fixed"
        html = self.html(doc)
        self.assertIn("<span class='l'>Open, not ready yet</span><div class='n'>2</div>", html)
        self.assertIn("<span class='pair'>0<span class='u'>Fixed</span>", html)

    def test_priority_queue_shows_at_least_four(self):
        html = self.html(sample())
        self.assertEqual(html.count("priority-item sev-"), 4)
        self.assertNotIn("Showing 4 of 4", html)

    def test_priority_queue_stops_at_twelve_and_names_hidden_highs(self):
        doc = sample()
        base = by_id(doc, "F-001")
        doc["findings"] = [dict(copy.deepcopy(base), id=f"F-{i:03d}") for i in range(1, 14)]
        html = self.html(doc)
        self.assertEqual(html.count("priority-item sev-"), 12)
        self.assertIn("1 more open High finding is listed in the findings register.", html)
        self.assertIn("Showing 12 of 13 open findings.", html)

    def test_verify_first_note_when_a_shown_item_needs_it(self):
        doc = sample()
        by_id(doc, "F-004")["confidence"] = "Suspected"
        self.assertIn("<p class='section-note'><span class='action-label'>Verify first</span>",
                      self.html(doc))

    def test_perspective_count_counts_applied_only(self):
        doc = sample()
        doc["perspectives"][0]["status"] = "not checked"
        self.assertIn("Perspectives applied: 11 of 12", self.html(doc))

    def test_excluded_finding_has_its_own_group_and_flag(self):
        html = self.html(sample())
        row = html[html.index("<div class='finding' id='finding-f-005'"):]
        row = row[:row.index("</summary>")]
        self.assertIn("data-x='1'", row)
        self.assertIn("data-sev='excluded' class='excluded'", row)

    def test_analysis_alone_makes_the_method_analysed(self):
        doc = sample()
        del doc["meta"]["method"]
        by_id(doc, "F-001")["analysis"] = {"tool": "git", "command": "git log", "result": "12"}
        self.assertEqual(render.review_method(doc, "en"), render.LABELS["en"]["analysed_note"])

    def test_dashboard_links_only_web_urls(self):
        self.assertNotIn("<a ", render.html_reference({"url": "docs/adr/0007.md"}))


class ReportStructureTest(unittest.TestCase):
    def test_plan_conventions_and_references(self):
        doc = sample()
        by_id(doc, "F-001")["references"] = [{"url": "https://example.org/x", "title": "X"}]
        md = render.render_markdown(doc, "en")
        self.assertIn("\n## Data rule ledger\n", md)
        plan = md[md.index("\n## Plan\n"):md.index("\n## Data rule ledger")]
        self.assertIn("- F-002 ", plan)
        self.assertIn("- **references:** [X](<https://example.org/x>)", md)
        doc["plan"] = []
        self.assertIn("\n## Plan\n\nNone.\n", render.render_markdown(doc, "en"))

    def test_blank_convention_reason_is_not_rendered(self):
        doc = sample()
        doc["conventions"][0]["reason"] = "\u200b"
        self.assertNotIn("Reason:", render.render_markdown(doc, "en"))

    def test_relative_reference_is_a_markdown_link(self):
        self.assertEqual(render.markdown_reference({"url": "docs/adr/0007.md"}),
                         "[docs/adr/0007.md](<docs/adr/0007.md>)")


class RenderCliTest(Run):
    """render.py exit codes: 0 written, 1 write failed, 2 bad record or command line."""

    def test_exit_codes_and_lang_override(self):
        target = self.out / "findings.json"
        target.write_bytes(SAMPLE.read_bytes())
        result = run_script("render.py", target, "--out", self.out / "ja", "--lang", "ja")
        self.assertEqual(result.returncode, 0, result.stderr)
        html = (self.out / "ja" / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn("<html lang='ja' class='app-shell'>", html)
        bad = write_json(self.out / "bad.json", {"meta": {}})
        result = run_script("render.py", bad, "--out", self.out / "x")
        self.assertEqual(result.returncode, 2)
        self.assertIn("schema:", result.stderr)
        blocker = self.out / "file"
        blocker.write_text("x", encoding="utf-8")
        result = run_script("render.py", target, "--out", blocker)
        self.assertEqual(result.returncode, 1)
        self.assertIn("write failed", result.stderr)


class ControlCharacterTest(Run):
    """Terminal control sequences copied from an audited repo never reach a terminal raw."""

    ESC = "\x1b]8;;https://evil.example\x07link\x1b[8mhidden\x9b"

    def test_outputs_show_control_characters(self):
        doc = sample()
        by_id(doc, "F-001")["title"] = "Pricing " + self.ESC
        for lang in ("en", "ja"):
            for name, data in render.rendered_outputs(doc, lang).items():
                text = data.decode("utf-8")
                for char in "\x1b\x07\x9b":
                    self.assertNotIn(char, text, name)
                self.assertIn("U+001B", text, name)  # report.md encodes the brackets

    def test_reference_url_with_a_control_character_is_not_a_link(self):
        doc = sample()
        by_id(doc, "F-001")["references"] = [{"url": "https://a.example/\x85x\x9b", "title": "t"}]
        for lang in ("en", "ja"):
            for name, data in render.rendered_outputs(doc, lang).items():
                text = data.decode("utf-8")
                self.assertNotIn("\x85", text, name)
                self.assertNotIn("\x9b", text, name)
                self.assertNotIn("href='https://a.example", text, name)
                self.assertNotIn("(<https://a.example", text, name)

    def test_location_with_a_control_character_is_refused(self):
        with self.assertRaises(findings.SchemaError):
            findings._location("a\x1b[2Jb.py:1", "location")

    def test_check_prints_control_characters_visibly(self):
        doc = sample()
        doc["meta"]["scope"] = "api/ " + self.ESC
        self.problems(doc)
        (self.out / "findings.json").write_text("{}", encoding="utf-8")
        (self.out / "notes\x1b[2J.txt").write_text("x", encoding="utf-8")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            findings.main(["check", str(self.out)])
        self.assertNotIn("\x1b", err.getvalue())
        self.assertIn("notes[U+001B][2J.txt", err.getvalue())

    def test_render_refuses_a_symlinked_output_before_writing(self):
        # A planted link must not let render overwrite a file outside the run.
        self.problems(sample())
        victim = self.out.parent / (self.out.name + "-victim")
        victim.write_text("keep", encoding="utf-8")
        self.addCleanup(victim.unlink)
        (self.out / "report.md").unlink()
        (self.out / "report.md").symlink_to(victim)
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = render.main([str(self.out / "findings.json"), "--out", str(self.out)])
        self.assertEqual(code, 1)
        self.assertIn("symlink", err.getvalue())
        self.assertEqual(victim.read_text(encoding="utf-8"), "keep")

    def test_render_refuses_a_symlinked_output_directory(self):
        self.problems(sample())
        link = self.out.parent / (self.out.name + "-link")
        link.symlink_to(self.out)
        self.addCleanup(link.unlink)
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            code = render.main([str(self.out / "findings.json"), "--out", str(link)])
        self.assertEqual(code, 1)

    def test_check_messages_keep_one_line_per_problem(self):
        self.problems(sample())
        (self.out / "evil\rforged\nline\t.txt").write_text("x", encoding="utf-8")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            findings.main(["check", str(self.out)])
        self.assertNotIn("\r", err.getvalue())
        self.assertNotIn("\t", err.getvalue())
        self.assertIn("evil[U+000D]forged[U+000A]line[U+0009].txt", err.getvalue())

    def test_symlinked_record_is_allowed(self):
        # merge keeps a findings.json link by design; only the rendered files must be plain.
        self.problems(sample())
        elsewhere = self.out.parent / (self.out.name + "-record.json")
        elsewhere.write_bytes((self.out / "findings.json").read_bytes())
        self.addCleanup(elsewhere.unlink)
        (self.out / "findings.json").unlink()
        (self.out / "findings.json").symlink_to(elsewhere)
        self.assertEqual(findings.contract_problems(self.out), [])

    def test_symlinked_output_breaks_the_contract(self):
        self.problems(sample())
        elsewhere = self.out.parent / (self.out.name + "-victim")
        elsewhere.write_bytes((self.out / "report.md").read_bytes())
        self.addCleanup(elsewhere.unlink)
        (self.out / "report.md").unlink()
        (self.out / "report.md").symlink_to(elsewhere)
        self.assertProblem(sample(), "output is a symlink: report.md")


class AccessibilityTest(unittest.TestCase):
    """Markup a screen reader or keyboard user depends on (WCAG 2.2 AA)."""

    def test_scrolling_tables_can_be_reached_by_keyboard(self):
        html = render.render_html(sample(), "en")
        wraps = re.findall(r"<div class='tablewrap'[^>]*>", html)
        self.assertEqual(len(wraps), 2)
        for wrap in wraps:
            self.assertIn("tabindex='0'", wrap)
            self.assertIn("role='region'", wrap)
            target = re.search(r"aria-labelledby='([^']+)'", wrap)[1]
            # The heading names the table alone, without counts beside it.
            heading = re.search(rf"<(h[23]) id='{target}'>(.*?)</\1>", html)[2]
            self.assertNotIn("<span", heading)

    def test_register_cells_name_their_column(self):
        # The column header row is hidden from screen readers, so each cell says
        # which column it is, at every width.
        html = render.render_html(sample(), "en")
        row = html[html.index("<div class='finding' id='finding-f-001'"):]
        summary = row[:row.index("</summary>")]
        for label in ("Severity", "Rollout", "Status", "Verdict", "Perspective"):
            self.assertIn(f"<span class='vh'>{label} </span>", summary)
        self.assertNotIn("content:attr(data-label)", render.DASHBOARD_CSS)
        self.assertNotIn("data-label=", summary)

    def test_column_names_are_not_searched(self):
        self.assertIn(".vh", re.search(r"querySelectorAll\('([^']*)'\)\.forEach\(function\(e\)"
                                       r"\{e\.remove", render.JS)[1])

    def test_english_values_on_the_japanese_page_are_marked(self):
        html = render.render_html(sample(), "ja")
        self.assertIn("<span class='badge High' lang='en'>High</span>", html)
        self.assertIn("<span class='t' lang='en'>Staged</span>", html)  # charts
        self.assertIn("<div class='verdict' lang='en'>", html)  # priority cards
        # perspectives table, data rule ledger status, finding details
        self.assertIn("<td lang='en'>Schema constraints</td><td lang='en'>applied</td>", html)
        self.assertIn("<td><span lang='en'>drifted</span></td>", html)  # a reason may follow
        self.assertIn("<dd><span lang='en'>Valid (static)</span></dd>", html)
        self.assertIn("<dd><span lang='en'>Add Foreign Key</span></dd>", html)
        self.assertIn("<span lang='en'>Staged</span> · 規模 <span lang='en'>M</span>", html)
        self.assertEqual(render.render_html(sample(), "en").count("lang='en'"), 1)  # <html>


class EnglishVocabularySweepTest(unittest.TestCase):
    """Every fixed English value on the Japanese page sits inside lang='en'."""

    def test_no_vocabulary_outside_an_english_mark(self):
        from html.parser import HTMLParser
        words = {*findings.SEVERITIES, *findings.ROLLOUTS, *findings.CONFIDENCES,
                 *findings.VERDICTS, *findings.STATUSES, *findings.NETS, *findings.PERSPECTIVES,
                 *findings.PERSPECTIVE_STATUSES, *findings.CONVENTION_STATUSES,
                 *findings.REMEDIES, *findings.METHODS}
        vocab = re.compile("(?<![A-Za-z-])(" + "|".join(map(re.escape, words)) + ")(?![A-Za-z-])")
        doc = sample()
        # Free text is in whatever language the reviewer wrote; keep it Japanese
        # here so only the dashboard's own words are tested.
        for p in doc["perspectives"]:
            p["note"] = "確認済み"
        for b in doc["plan"]:
            b["prerequisite"] = "特になし"

        class Sweep(HTMLParser):
            def __init__(self):
                super().__init__()
                self.stack, self.skip, self.bare = [], 0, []

            def handle_starttag(self, tag, attrs):
                if tag in ("script", "style", "title"):
                    self.skip += 1
                if tag not in ("meta", "br", "input", "link"):
                    self.stack.append((tag, dict(attrs).get("lang")))

            def handle_endtag(self, tag):
                if tag in ("script", "style", "title"):
                    self.skip -= 1
                while self.stack and self.stack.pop()[0] != tag:
                    pass

            def handle_data(self, data):
                lang = next((lang for _, lang in reversed(self.stack) if lang), None)
                if not self.skip and lang != "en" and vocab.search(data):
                    self.bare.append(data.strip()[:60])

        sweep = Sweep()
        sweep.feed(render.render_html(doc, "ja"))
        self.assertEqual(sweep.bare, [])


class JapaneseWordingTest(unittest.TestCase):
    """One Japanese name per field, the same in the dashboard, report and templates."""

    def test_a_field_has_one_label(self):
        labels, dash = render.LABELS["ja"], render.DASH["ja"]
        self.assertEqual({k: (labels[k], dash[k]) for k in labels.keys() & dash.keys()
                          if labels[k] != dash[k]}, {})

    def test_severities_stay_english(self):
        self.assertIn("High", render.DASH["ja"]["open_hm"])
        self.assertIn("Medium", render.DASH["ja"]["open_hm"])
        html = render.render_html(sample(), "ja")
        self.assertIn("<span class='l'>未対応の <span lang='en'>High</span>", html)

    def test_the_brand_is_marked_english(self):
        html = render.render_html(sample(), "ja")
        self.assertIn("<span class='brand'><span lang='en'>DATA INTEGRITY REVIEW</span>", html)

    def test_latin_words_are_spaced_from_japanese(self):
        # "・" joins listed English values and is the one exception.
        touching = re.compile(r"[぀-ヺー-ヿ一-鿿][A-Za-z]"
                              r"|[A-Za-z][぀-ヺー-ヿ一-鿿]")
        bad = {k: v for table in (render.LABELS, render.DASH)
               for k, v in table["ja"].items() if isinstance(v, str) and touching.search(v)}
        self.assertEqual(bad, {})

    def test_domain_labels(self):
        labels, dash = render.LABELS, render.DASH
        self.assertEqual((labels["en"]["title"], labels["ja"]["title"]),
                         ("Data integrity assessment", "データ整合性診断"))
        self.assertEqual(dash["en"]["eyebrow"], "DATA INTEGRITY REVIEW")
        self.assertEqual({k: labels["ja"][k] for k in ("hazard", "invariants", "enforcement", "rollout")},
                         {"hazard": "危険", "invariants": "守るべき不変条件",
                          "enforcement": "現在の強制", "rollout": "適用方法"})
        self.assertEqual((dash["en"]["fix_now"], dash["en"]["pin_first"]),
                         ("Ready to ship", "Stage the rollout"))
        self.assertEqual((dash["ja"]["fix_now"], dash["ja"]["pin_first"]),
                         ("すぐ適用できる", "段階的に適用する"))

    def test_staged_and_downtime_findings_are_staged_first(self):
        doc = sample()
        self.assertEqual(render.action(by_id(doc, "F-001")), "pin_first")  # Staged
        self.assertEqual(render.action(by_id(doc, "F-004")), "pin_first")  # Downtime

    def test_templates_use_the_dashboard_labels(self):
        labels, dash = render.LABELS["ja"], render.DASH["ja"]
        issue = (SKILL / "templates" / "issue.ja.md").read_text(encoding="utf-8")
        plan = (SKILL / "templates" / "plan.ja.md").read_text(encoding="utf-8")
        self.assertIn(f"| {dash['severity']}（露出）", issue)
        for text in (issue, plan):
            self.assertIn(f"**{labels['depends_on']}:**", text)
        self.assertIn(f"## {labels['batch']} {{{{plan[].batch}}}}", plan)


class DocumentedRuleTest(Run):
    """Rules SKILL.md, plan.md and validation.md state, enforced by check."""

    def test_a_high_finding_is_confirmed(self):
        # SKILL.md: no High without history.
        for confidence in ("Suspected", "Environment-dependent"):
            doc = sample()
            by_id(doc, "F-001")["confidence"] = confidence
            self.assertProblem(doc, f"F-001: a High finding rests on a traced hazard and recorded "
                                    f"exposure, so it is Confirmed, not {confidence}")

    def test_a_confirmed_exposure_names_its_window_and_revision(self):
        for key in ("window", "commit"):
            doc = sample()
            del doc["meta"][key]
            self.assertProblem(doc, f"meta.{key}: a Confirmed exposure")
            for f in doc["findings"]:
                f["confidence"] = "Environment-dependent"
            self.assertEqual([p for p in self.problems(doc) if p.startswith("meta.")], [])

    def test_an_accepted_finding_names_the_decision(self):
        doc = sample()
        by_id(doc, "F-003")["status"] = "Accepted"
        doc["plan"] = doc["plan"][:2]
        self.assertProblem(doc, "F-003: Accepted means a person chose")
        doc["decisions"].append("F-003 kept as is: the product owner plans to retire wallets "
                                "next quarter (2026-10-15)")
        self.assertEqual(self.problems(doc), [])
        doc["meta"]["lang"] = "ja"
        doc["decisions"][-1] = "F-003は現状維持とする（来期に削除予定のため、プロダクトオーナーが判断）"
        self.assertEqual(self.problems(doc), [])
        doc["decisions"][-1] = "F-0030 ではなく XF-003 の話"
        self.assertProblem(doc, "F-003: Accepted means a person chose")

    def test_an_excluded_finding_carries_no_dependency(self):
        doc = sample()
        by_id(doc, "F-005")["depends_on"] = ["F-001"]
        self.assertProblem(doc, "F-005: an excluded finding (NotApplicable) is not planned")

    def test_a_downtime_finding_stands_alone(self):
        doc = sample()
        f = by_id(doc, "F-004")
        f["severity"] = "Medium"
        f["invariants"] = ["Every audit event gets an id the key type can hold"]
        doc["findings"].sort(key=lambda f: f["id"])
        doc["plan"][2]["findings"] = ["F-003", "F-004"]
        self.assertProblem(doc, "plan batch 3: a Downtime finding stands alone")
        doc["plan"][2]["findings"] = ["F-003"]
        doc["plan"].append({"batch": 4, "title": "Widen the audit key", "findings": ["F-004"],
                            "prerequisite": "none", "pr_title": "db: bigint key for audit_events"})
        self.assertEqual(self.problems(doc), [])

    def test_a_dependency_comes_first_within_a_batch(self):
        doc = sample()
        doc["plan"] = [{**doc["plan"][0], "findings": ["F-001", "F-002"]},
                       {**doc["plan"][2], "batch": 2}]
        self.assertProblem(doc, "F-001 depends on F-002, listed after it in batch 1")
        doc["plan"][0]["findings"] = ["F-002", "F-001"]
        self.assertEqual(self.problems(doc), [])

    def test_the_guard_record_closes_the_finding_it_proves(self):
        text = (SKILL / "reference" / "validation.md").read_text(encoding="utf-8")
        fragment = json.loads(re.search(r"^`(\{\"findings\".*\})`$", text, re.M)[1])
        target = self.out / "findings.json"
        target.write_bytes(SAMPLE.read_bytes())
        part = self.out.parent / f"{self.out.name}-guard.json"
        part.write_text(json.dumps(fragment), encoding="utf-8")
        self.addCleanup(part.unlink)
        merged = run_script("findings.py", "merge", target, part)
        self.assertEqual(merged.returncode, 0, merged.stderr)
        doc = json.loads(target.read_text(encoding="utf-8"))
        guarded = [by_id(doc, g["id"]) for g in fragment["findings"]]
        self.assertTrue(guarded)
        for f in guarded:
            self.assertEqual((f["status"], f["enforcement"]["net"]), ("Fixed", "enforced"), f["id"])
        self.assertEqual(self.problems(doc), [])


class RenderedContentTest(unittest.TestCase):
    """What each output must show from the record, and how it must show it."""

    def test_report_shows_every_recorded_detail(self):
        doc = sample()
        f = by_id(doc, "F-001")
        f["validation"]["method"] = "analysed"
        f["analysis"] = {"tool": "radon", "command": "radon cc api", "result": "CC 41"}
        doc["perspectives"] = doc["perspectives"][1:]
        for lang in ("en", "ja"):
            t = render.LABELS[lang]
            report = render.render_markdown(doc, lang)
            self.assertIn(f"| {t['window']} | {render.markdown_inline(doc['meta']['window'])} |",
                          report)
            self.assertIn("Schema constraints (SC2)", report)
            self.assertIn("C-01 · TYPES", report)
            self.assertIn(f"({t['inferred']})", report)
            self.assertIn(f"- **{t['analysis']}:** CC 41", report)
            self.assertIn(f"- **{t['analysis_command']}:** radon: "
                          f"{render.markdown_code('radon cc api')}", report)
            self.assertIn(t["not_recorded"], report)

    def test_verdict_counts_include_the_excluded_verdicts(self):
        counted = render.verdict_counts(sample()["findings"])
        self.assertEqual(counted["NotApplicable"], 1)
        self.assertEqual(sum(counted.values()), 5)

    def test_project_name_cannot_close_the_title(self):
        doc = sample()
        doc["meta"]["project"] = "</title><meta http-equiv=refresh content=0>"
        html = render.render_html(doc, "en")
        self.assertNotIn("<meta http-equiv=refresh", html)
        self.assertEqual(html.count("</title>"), 1)

    def test_csp_pins_the_script_by_hash(self):
        html = render.render_html(sample(), "en")
        self.assertIn(f"script-src {render.csp_hash(render.JS)}", html)
        self.assertNotIn("unsafe-inline", html)

    def test_links_refuse_unc_paths_and_bidi_controls(self):
        for url in ("\\\\host\\share", "//host/x", "https://example.org/\u202ex"):
            with self.subTest(url):
                self.assertFalse(render.is_safe_link(url))
        self.assertTrue(render.is_safe_link("docs/adr/0007.md"))

    def test_markdown_keeps_literal_text_literal(self):
        cases = {
            "12. starts a line": "12&#46; starts a line",
            "@scope/pkg": "@scope/pkg",
            "costs $5 and $6": "costs &#36;5 and &#36;6",
            "C:\\dir\\`x": "C:&#92;dir&#92;&#96;x",
        }
        for value, expected in cases.items():
            with self.subTest(value):
                self.assertEqual(render.block_safe(render.markdown_inline(value)), expected)
        self.assertEqual(render.markdown_code(" a\r\nb "), "<code>&#32;a<br>b&#32;</code>")

    def test_copy_for_llm_keeps_evidence_in_a_fence_longer_than_its_backticks(self):
        f = by_id(sample(), "F-001")
        f["validation"]["evidence"] = "uses ```` inside"
        text = render.finding_markdown(f, "en")
        self.assertIn("`````text\nuses ```` inside\n`````", text)
        self.assertEqual(render.fenced("plain"), "```text\nplain\n```")

    def test_each_step_is_its_own_item_on_the_dashboard(self):
        doc = sample()
        f = by_id(doc, "F-003")
        f["steps"][0] = "1. first line\nsecond line (verify: tests green)"
        html = render.render_html(doc, "en")
        items = "".join(f"<li>{render.html_text(step)}</li>" for step in f["steps"])
        self.assertIn(f"<ul class='steps'>{items}</ul>", html)
        # Steps are recorded numbered, so the list adds no bullet of its own.
        self.assertIn(".detail dd ul.steps{margin:0;padding-left:0;list-style:none}", render.CSS)

    def test_print_uses_the_light_palette_under_a_dark_system_theme(self):
        # The print rule must outrank `:root:not([data-theme="light"])` (0,2,0).
        css = render.CSS
        dark = re.search(r"prefers-color-scheme:dark\)\{([^{]+)\{", css)[1]
        self.assertEqual(dark, ':root:not([data-theme="light"])')
        light = re.search(r"^:root\{([^}]*)\}", css, re.M)[1]
        self.assertIn('@media print{html:root:not([data-theme="light"]){' + light + "}}", css)
        # Later in the sheet than the dark rule, so it wins at equal weight too.
        self.assertGreater(css.rindex("@media print{html:root:not"), css.index(dark))


class RoundTwoTest(Run):
    """Behaviour pinned after the second review: paths, prose, inferred rules, CLI output."""

    def test_locations_are_relative_to_the_repository_root(self):
        for loc, why in (("/home/a/repo/api/x.py:3", "relative"), ("~/repo/x.py:1", "relative"),
                         ("C:\\repo\\a.py:3", "relative"), ("C:repo.py:1", "relative"),
                         ("../a.py:1", "relative"), ("api/../b.py:2", "relative"),
                         ("\\\\host\\a.py:1", "with /"), ("api\\orders\\b2b.py:61", "with /")):
            with self.subTest(loc):
                doc = sample()
                by_id(doc, "F-003")["location"] = loc
                with self.assertRaisesRegex(findings.SchemaError,
                                            {"relative": "relative to the repository root",
                                             "with /": "separate directories with /"}[why]):
                    findings.validate(doc)
        for loc in ("a..b.py:3", ".env:2", "~notes.py:1"):
            with self.subTest(loc):
                doc = sample()
                by_id(doc, "F-003")["location"] = loc
                findings.validate(doc)

    def test_enforcement_sites_are_relative_too(self):
        doc = sample()
        by_id(doc, "F-003")["enforcement"]["sites"] = ["/abs/db/schema.rb:4"]
        with self.assertRaisesRegex(findings.SchemaError, "relative to the repository root"):
            findings.validate(doc)

    def test_underscores_in_prose_never_turn_into_emphasis(self):
        rendered = render.markdown_inline("accept __getattr__ proxies and _private, *really*")
        self.assertEqual(rendered, "accept &#95;&#95;getattr&#95;&#95; proxies and &#95;private, "
                                   "*really*")
        self.assertEqual(render.markdown_inline("see `__init__`"),
                         "see " + render.markdown_code("__init__"))

    def test_tildes_in_prose_never_turn_into_strikethrough(self):
        # GFM strikes through between single tildes too: `1~3 and 5~7`.
        for prose in ("retries 1~3 and 5~7 times", "~~old~~ name", "3~5件と7~9件"):
            with self.subTest(prose):
                self.assertNotIn("~", render.markdown_inline(prose))
        self.assertEqual(render.markdown_inline("a~b"), "a&#126;b")

    def test_a_location_names_a_file_not_a_directory(self):
        # `a.py/` and `a.py/.` would resolve to the file `a.py` under --repo.
        for loc in ("worker/sync.py/:14", "worker/sync.py/.:14", "worker/:14"):
            with self.subTest(loc), self.assertRaisesRegex(findings.SchemaError, "a file"):
                findings._location(loc, "location")
        findings._location("./worker/sync.py:14", "location")

    def test_an_inferred_rule_is_named_in_decisions(self):
        doc = sample()
        doc["decisions"] = [d for d in doc["decisions"] if "C-01" not in d]
        self.assertProblem(doc, "C-01: an inferred rule goes to decisions")
        doc["conventions"][0]["inferred"] = False
        self.assertFalse([p for p in self.problems(doc) if p.startswith("C-01")])

    def cli(self, script, *args, stdout=subprocess.PIPE):
        # A timeout: reading a FIFO as the record would otherwise block forever.
        return subprocess.run([sys.executable, "-B", str(SCRIPTS / script), *args],
                              stdout=stdout, stderr=subprocess.PIPE, text=True, timeout=60)

    @unittest.skipUnless(os.path.exists("/dev/full"), "needs /dev/full")
    def test_a_stdout_that_cannot_be_written_is_one_line(self):
        record = self.out / "findings.json"
        record.write_bytes(SAMPLE.read_bytes())
        with open("/dev/full", "w") as full:
            for script, args in (("findings.py", ["counts", str(record)]),
                                 ("render.py", [str(record), "--out", str(self.out)]),
                                 ("findings.py", ["check", str(self.out)])):
                with self.subTest(args[0]):
                    result = self.cli(script, *args, stdout=full)
                    self.assertEqual(result.returncode, 1)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertIn("stdout: ", result.stderr)

    @unittest.skipIf(os.name == "nt", "needs POSIX file descriptors")
    def test_a_closed_stdout_is_not_a_crash(self):
        # Started with fd 1 closed, Python sets sys.stdout to None.
        record = self.out / "findings.json"
        record.write_bytes(SAMPLE.read_bytes())
        result = subprocess.run([sys.executable, "-B", str(SCRIPTS / "findings.py"), "counts",
                                 str(record)], preexec_fn=lambda: os.close(1),
                                stderr=subprocess.PIPE, text=True, timeout=60)
        self.assertEqual((result.returncode, result.stderr), (0, ""))

    @unittest.skipIf(os.name == "nt", "needs POSIX file descriptors")
    def test_a_flush_that_fails_at_the_end_leaves_nothing_for_exit(self):
        # A full disk fails only when the buffered summary is flushed. Python
        # flushes again at exit; that must not turn the exit code into 120.
        script = (
            "import errno, io, os, sys\n"
            f"sys.path.insert(0, {str(SCRIPTS)!r})\n"
            "import findings\n"
            "null = os.stat(os.devnull).st_rdev\n"
            "class Raw(io.RawIOBase):\n"
            "    def writable(self): return True\n"
            "    def fileno(self): return 1\n"
            "    def write(self, b):\n"
            "        if os.fstat(1).st_rdev == null: return len(b)\n"
            "        raise OSError(errno.ENOSPC, 'No space left on device')\n"
            "sys.stdout = io.TextIOWrapper(io.BufferedWriter(Raw(), 1 << 16))\n"
            "sys.exit(findings.run(lambda: print('summary') or 0))\n")
        result = subprocess.run([sys.executable, "-B", "-c", script], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, timeout=60)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stderr, "stdout: [Errno 28] No space left on device\n")

    def test_a_closed_pipe_exits_quietly(self):
        record = self.out / "findings.json"
        record.write_bytes(SAMPLE.read_bytes())
        reader, writer = os.pipe()
        os.close(reader)
        try:
            result = self.cli("findings.py", "counts", str(record), stdout=writer)
        finally:
            os.close(writer)
        self.assertEqual((result.returncode, result.stderr), (1, ""))

    def test_empty_paths_are_a_command_line_error(self):
        record = self.out / "findings.json"
        record.write_bytes(SAMPLE.read_bytes())
        for script, args in (("render.py", [str(record), "--out", ""]),
                             ("findings.py", ["check", str(self.out), "--repo", ""]),
                             ("findings.py", ["counts", ""])):
            with self.subTest(args):
                result = self.cli(script, *args)
                self.assertEqual(result.returncode, 2)
                self.assertIn("must not be empty", result.stderr)
        self.assertFalse((Path.cwd() / "dashboard.html").exists())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs mkfifo")
    def test_render_refuses_a_record_that_is_not_a_regular_file(self):
        fifo = self.out / "record.fifo"
        os.mkfifo(fifo)
        result = self.cli("render.py", str(fifo), "--out", str(self.out / "o"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("not a regular file", result.stderr)
        self.assertFalse((self.out / "o").exists())


class SchemaRuleTest(unittest.TestCase):
    """Each field rule in reference/findings-schema.md refuses its own breach."""

    def refused(self, change, pattern):
        doc = sample()
        change(doc)
        with self.assertRaisesRegex(findings.SchemaError, pattern):
            findings.validate(doc, complete=True)

    def test_finding_field_rules(self):
        cases = {
            "gaps required": (lambda f: f["enforcement"].pop("gaps"), r"enforcement\.gaps"),
            "blank rollout_reason": (lambda f: f.update(rollout_reason=" "),
                                     r"rollout_reason: must be a nonblank string"),
            "rollout_reason type": (lambda f: f.update(rollout_reason=["x"]),
                                    r"rollout_reason: must be a nonblank string"),
            "empty location": (lambda f: f.update(location=[]), r"location: at least one"),
            "convention type": (lambda f: f.update(convention=["C-01"]), r"convention: must be a string"),
            "exposure type": (lambda f: f.update(exposure=3), r"exposure: must be a string"),
            "invariants type": (lambda f: f.update(invariants="x"), r"invariants: must be a list"),
            "blank assert": (lambda f: f.update(invariants=[" "]), r"invariants\[0\]"),
            "effort enum": (lambda f: f.update(effort="XL"), r"effort"),
            "status enum": (lambda f: f.update(status="Done"), r"status"),
            "analysed needs analysis": (lambda f: f["validation"].update(method="analysed"),
                                        r"analysis: required"),
            "blank analysis": (lambda f: f.update(analysis={"tool": "radon", "command": " ",
                                                            "result": "CC 9"}),
                               r"analysis\.command"),
            "reference url": (lambda f: f.update(references=[{"title": "ADR"}]),
                              r"references\[0\]\.url"),
        }
        for name, (change, pattern) in cases.items():
            with self.subTest(name):
                self.refused(lambda doc: change(by_id(doc, "F-001")), pattern)

    def test_record_rules(self):
        cases = {
            "meta.window type": (lambda d: d["meta"].update(window=12), r"meta\.window"),
            "meta.commit type": (lambda d: d["meta"].update(commit=None), r"meta\.commit"),
            "meta.method type": (lambda d: d["meta"].update(method=["git"]), r"meta\.method"),
            "duplicate finding": (lambda d: d["findings"].append(copy.deepcopy(d["findings"][0])),
                                  r"duplicate F-001"),
            "duplicate convention": (lambda d: d["conventions"].append(dict(d["conventions"][0])),
                                     r"duplicate C-01"),
            "concern enum": (lambda d: d["conventions"][0].update(concern="STYLE"), r"concern"),
            "inferred bool": (lambda d: d["conventions"][0].update(inferred="yes"),
                              r"inferred \(C-01\)"),
            "blank list item": (lambda d: d["limitations"].append(" "), r"limitations\[[0-9]+\]: must be a nonblank"),
        }
        for name, (change, pattern) in cases.items():
            with self.subTest(name):
                self.refused(change, pattern)


class CheckRuleTest(Run):
    def test_convention_status_follows_the_verdict(self):
        doc = sample()
        doc["conventions"][1]["status"] = "partly read"
        self.assertProblem(doc, "F-004: Valid finding cites C-02, recorded as partly read, not drifted")
        f = by_id(doc, "F-004")
        f["validation"]["verdict"] = "Likely"
        self.assertFalse([p for p in self.problems(doc) if "cites C-02" in p])

    def test_rollout_reason_shows_in_every_output(self):
        doc = sample()
        reason = by_id(doc, "F-004")["rollout_reason"]
        for lang, label in (("en", "rollout reason"), ("ja", "適用方法の理由")):
            out = render.rendered_outputs(doc, lang)
            report = out["report.md"].decode("utf-8")
            self.assertIn(f"- **{label}:** {render.markdown_inline(reason)}", report, lang)
            self.assertIn(label, out["dashboard.html"].decode("utf-8"), lang)
            self.assertIn(f"{label}", render.finding_markdown(by_id(doc, "F-004"), lang), lang)

    def test_verify_is_matched_in_any_case(self):
        doc = sample()
        f = by_id(doc, "F-003")
        f["steps"] = [step.replace("verify:", "Verify:") for step in f["steps"]]
        self.assertEqual(self.problems(doc), [])


class CountsTest(unittest.TestCase):
    def test_every_summary_count(self):
        doc = sample()
        by_id(doc, "F-003")["validation"]["verdict"] = "Likely"
        by_id(doc, "F-004")["validation"]["verdict"] = "Unlikely"
        by_id(doc, "F-002").update(status="Fixed")
        by_id(doc, "F-001").update(status="Accepted")
        counts = findings.template_counts(doc)
        self.assertEqual(
            {k: counts[k] for k in ("n_high", "n_high_valid", "n_medium", "n_medium_valid",
                                    "n_low", "n_low_valid", "n_likely", "n_unverified",
                                    "n_unlikely", "n_fixed", "n_accepted", "n_excluded")},
            {"n_high": 1, "n_high_valid": 1, "n_medium": 2, "n_medium_valid": 1, "n_low": 1,
             "n_low_valid": 0, "n_likely": 1, "n_unverified": 0, "n_unlikely": 1,
             "n_fixed": 1, "n_accepted": 1, "n_excluded": 1})


class MergeRuleTest(unittest.TestCase):
    def test_a_title_differing_only_in_blanks_is_the_same_finding(self):
        doc = sample()
        f = copy.deepcopy(by_id(doc, "F-001"))
        f["title"] = "  " + f["title"].replace(" ", "\n ") + " "
        findings.merge(doc, {"findings": [f]}, "frag")
        self.assertEqual(len(doc["findings"]), 5)

    def test_a_partial_correction_may_change_the_title_alone(self):
        doc = sample()
        old = by_id(doc, "F-001")
        findings.merge(doc, {"findings": [{"id": "F-001", "title": "Renamed",
                                           "location": old["location"]}]}, "frag")
        self.assertEqual(by_id(doc, "F-001")["title"], "Renamed")

    def test_a_fragment_list_keeps_one_copy_of_each_item(self):
        doc = sample()
        findings.merge(doc, {"next_steps": ["again", "again"]}, "frag")
        self.assertEqual(doc["next_steps"].count("again"), 1)


class LineCountTest(unittest.TestCase):
    def test_a_crlf_split_across_chunks_is_one_line_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.txt"
            path.write_bytes(b"x" * ((1 << 20) - 1) + b"\r\nlast")
            self.assertEqual(findings._count_lines(path), 2)


@unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "needs git and bash")
class ReconCommandTest(unittest.TestCase):
    """The migration and function-level churn commands in recon.md, run as written (recon.py: test_recon.py)."""

    RECON = (SKILL / "reference" / "recon.md").read_text(encoding="utf-8")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        # The developer's own git config (signing, hooks, default branch) stays out.
        self.env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        self.git("init", "-q")
        self.git("config", "user.email", "t@example.com")
        self.git("config", "user.name", "t")

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True,
                       env=self.env)

    def commit(self, message, files):
        for name, text in files.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def run_doc(self, command, **fill):
        for name, value in fill.items():
            command = command.replace(f"<{name}>", value)
        return subprocess.run(["bash", "-c", command], cwd=self.repo,
                              capture_output=True, text=True, env=self.env)

    def test_migrations_changed_in_the_window_are_listed(self):
        command = re.search(r"\n  ```\n  (git log .*?)\n  ```", self.RECON, re.S)[1]
        command = command.replace("\\\n", " ")
        self.commit("feat: orders", {"db/migrate/001_create_orders.rb": "1",
                                     "app/models/order.rb": "1"})
        self.commit("feat: totals", {"app/models/order.rb": "2"})
        self.commit("fix: edit an applied migration", {"db/migrate/001_create_orders.rb": "2"})
        self.commit("feat: wallets", {"db/migrate/002_create_wallets.rb": "1"})
        self.git("checkout", "-q", "-b", "side")
        self.commit("feat: side", {"db/migrate/003_side.rb": "1"})
        self.git("checkout", "-q", "-")
        self.git("merge", "-q", "--no-ff", "-m", "Merge branch 'side'", "side")
        out = self.run_doc(command, **{"window start": "2000-01-01T00:00",
                                       "migrations": "db/migrate"})
        self.assertEqual(out.stderr, "")
        rows = [line.split(None, 1) for line in out.stdout.splitlines()]
        for h, _ in rows:
            self.assertRegex(h, r"^[0-9a-f]{7,}$")
        # The merge itself lists nothing; the side branch's own commit does.
        self.assertEqual(sorted(tuple(rest.split("\t")) for _, rest in rows),
                         [("A", "db/migrate/001_create_orders.rb"),
                          ("A", "db/migrate/002_create_wallets.rb"),
                          ("A", "db/migrate/003_side.rb"),
                          ("M", "db/migrate/001_create_orders.rb")])

    def test_function_churn_prints_no_count_when_git_finds_no_function(self):
        command = re.search(r"`(n=\$\(git log .*?)`\n", self.RECON)[1]
        source = "export function price(a) {\n  return a;\n}\n"
        self.commit("one", {"a.ts": source})
        self.commit("two", {"a.ts": source.replace("a;", "a + 1;")})
        fill = {"window start": "2000-01-01", "file": "a.ts"}
        found = self.run_doc(command, function="price", **fill)
        self.assertEqual(found.stdout, "2\n")
        missing = self.run_doc(command, function="total", **fill)
        self.assertEqual(missing.stdout, "")
        self.assertNotEqual(missing.returncode, 0)

    def test_anchored_definitions_skip_longer_names(self):
        command = re.search(r"`(n=\$\(git log .*?)`\n", self.RECON)[1]
        for lang, source in (("Python", "def _merge_all():\n    pass\n\n\ndef merge(a):\n    return a\n"),
                             ("Go", "package a\n\nfunc mergeAll() {\n}\n\nfunc merge(a int) int {\n\treturn a\n}\n")):
            with self.subTest(lang):
                span = re.search(r"`(-L ':\^\w+ <function>\(:<file>')` in " + lang, self.RECON)[1]
                name = "a.py" if lang == "Python" else "a.go"
                self.commit("one " + lang, {name: source})
                self.commit("two " + lang, {name: source.replace("return a", "return a + 1")})
                out = self.run_doc(command.replace("-L :<function>:<file>", span),
                                   **{"window start": "2000-01-01T00:00", "file": name,
                                      "function": "merge"})
                self.assertEqual(out.stdout, "2\n", out.stderr)

    def test_the_method_range_ends_at_the_method_closing_brace(self):
        command = re.search(r"`(n=\$\(git log .*?)`\n", self.RECON)[1]
        span = re.search(r"`(-L '/\^<indent>.*?)`", self.RECON)[1]
        command = re.sub(r"-L :<function>:<file>", span, command)
        source = ("import { price } from './price';\n"
                  "class Cart {\n  price(a) {\n    if (a < 0) {\n      a = 0;\n    }\n"
                  "    return a;\n  }\n}\n")
        self.commit("one", {"a.ts": source})
        self.commit("two", {"a.ts": source.replace("a = 0;", "a = 1;")})
        self.commit("three", {"a.ts": source.replace("a = 0;", "a = 1;")
                              .replace("return a;", "return a * 2;")})
        out = self.run_doc(command, **{"window start": "2000-01-01", "file": "a.ts",
                                       "function": "price", "indent": "  "})
        self.assertEqual(out.stdout, "3\n", out.stderr)


@unittest.skipUnless(shutil.which("make"), "needs make")
class MakefileTest(unittest.TestCase):
    """link, status and unlink against a scratch skills directory, never the real hosts."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.skills = Path(self.tmp.name) / "skills dir"  # a space, as in real paths
        self.skills.mkdir()
        self.link = self.skills / "data-scan"

    def tearDown(self):
        self.tmp.cleanup()

    def env(self):
        # Run under `make test`, the parent's flags and command-line variables
        # (`-w`, `PROJECT=…`) would reach this make through MAKEFLAGS.
        drop = {"MAKEFLAGS", "MFLAGS", "MAKELEVEL", "MAKEOVERRIDES", "GNUMAKEFLAGS"}
        return {**{k: v for k, v in os.environ.items() if k not in drop}, "HOME": self.tmp.name}

    def make(self, *args):
        return subprocess.run(["make", "-s", "--no-print-directory", "-C", str(REPO), *args,
                               f"SKILLS_DIR={self.skills}"],
                              capture_output=True, text=True, env=self.env(), timeout=60)

    def test_link_status_unlink(self):
        self.assertEqual(self.make("status").stdout.split()[0], "absent")
        self.assertEqual(self.make("link").returncode, 0)
        self.assertEqual(self.link.resolve(), SKILL.resolve())
        self.assertEqual(self.make("link").returncode, 0)  # idempotent
        self.assertEqual(self.make("status").stdout.split()[0], "linked")
        self.assertEqual(self.make("unlink").stdout.split()[0], "unlinked")
        self.assertFalse(self.link.exists() or self.link.is_symlink())

    def test_status_names_foreign_and_dangling_links(self):
        other = Path(self.tmp.name) / "afile"
        other.write_text("x")
        self.link.symlink_to(other)
        self.assertEqual(self.make("status").stdout.split()[0], "foreign")
        result = self.make("link")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing", result.stderr)
        self.assertEqual(self.make("unlink").stdout.split()[0], "left")
        self.link.unlink()
        self.link.symlink_to(Path(self.tmp.name) / "missing")
        self.assertEqual(self.make("status").stdout.split()[0], "dangling")

    def test_an_empty_agent_is_an_error(self):
        result = subprocess.run(["make", "-s", "-C", str(REPO), "status", "AGENT="],
                                capture_output=True, text=True, timeout=60, env=self.env())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AGENT is empty", result.stderr)


class SkillOutputsTest(unittest.TestCase):
    def test_report_row_names_every_section(self):
        row = next(line for line in (SKILL / "SKILL.md").read_text(encoding="utf-8").splitlines()
                   if line.startswith("| `report.md` |")).lower()
        md = render.render_markdown(sample(), "en")
        sections = [h[3:].lower() for h in md.splitlines() if h.startswith("## ")]
        self.assertEqual([s for s in sections if s not in row], [])
        self.assertIn("verdict counts", row)


if __name__ == "__main__":
    unittest.main()
