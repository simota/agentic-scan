"""Offline checks for the architecture-scan skill's record and render scripts."""
from __future__ import annotations

import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from types import ModuleType
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
SKILL = REPO / "skills" / "architecture-scan"


def import_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", [str(path.parent)] + sys.path):
        spec.loader.exec_module(module)
    return module


findings = import_module(SKILL / "scripts" / "findings.py", "arch_findings")
render = import_module(SKILL / "scripts" / "render.py", "arch_render")


# Variables an outer make passes down that would change how the Makefile under
# test runs (jobs, flags, extra makefiles).
MAKE_ENV_LEAKS = ("MAKEFLAGS", "MFLAGS", "MAKEFILES")


def make_env(*drop: str) -> dict:
    """The environment for a nested `make`, without what the outer make leaks."""
    env = os.environ.copy()
    for name in (*MAKE_ENV_LEAKS, *drop):
        env.pop(name, None)
    return env


def finding(fid="A-001", severity="High", **extra) -> dict:
    record = {
        "id": fid, "title": "Refund job writes invoices directly", "severity": severity,
        "confidence": "Confirmed", "category": "Domain model and data ownership", "step": "DM1",
        "location": ["worker/refunds/job.py:58"],
        "scenario": "Refund flow", "blast_radius": "invoices table; 2 writers",
        "trace": "1. job.py:58 updates invoices", "impact": "Tax not recomputed",
        "fix": "Call BillingService.adjust()", "guard": "CI single-writer search",
        "validation": {"verdict": "Valid", "method": "static", "evidence": "job.py:58"},
    }
    record.update(extra)
    return record


def complete_doc() -> dict:
    return {
        "meta": {"project": "demo", "scope": "repo root", "date": "2026-10-09",
                 "assessor": "test", "lang": "en", "axis": "confirmed"},
        "rules": [{"id": "R-01", "statement": "one writer", "source": "adr", "status": "violated"}],
        "findings": [finding(rule="R-01"), finding("A-002", "Low")],
        "perspectives": [{"name": n, "status": "applied", "note": "applied"}
                         for n in findings.PERSPECTIVES],
        "checked_ok": ["no cycles"],
        "limitations": ["delivery semantics not observed"],
        "architecture": architecture(),
    }


def architecture(fid="A-001") -> dict:
    """The smallest before/after pair check accepts: the refund job's write moves to billing."""
    nodes = [{"id": "refunds", "label": "worker/refunds"}, {"id": "billing", "label": "api/billing"},
             {"id": "invoices", "label": "invoices", "kind": "store"}]
    return {
        "before": {"nodes": copy.deepcopy(nodes), "edges": [
            {"from": "refunds", "to": "invoices", "label": "writes", "finding": fid},
            {"from": "billing", "to": "invoices", "label": "writes"}]},
        "after": {"nodes": copy.deepcopy(nodes), "edges": [
            {"from": "refunds", "to": "billing", "label": "adjust()"},
            {"from": "billing", "to": "invoices", "label": "writes"}]},
    }


class MergeTests(unittest.TestCase):
    def run_merge(self, tmp: Path, *fragments) -> int:
        paths = []
        for i, frag in enumerate(fragments):
            p = tmp / f"frag-{i}.json"
            p.write_text(json.dumps(frag), encoding="utf-8")
            paths.append(str(p))
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return findings.main(["merge", str(tmp / "findings.json"), *paths])

    def test_merge_updates_by_id_and_appends_lists(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            self.assertEqual(self.run_merge(tmp, {"findings": [finding()], "limitations": ["a"]}), 0)
            update = {"findings": [{"id": "A-001", "status": "Fixed"}], "limitations": ["a", "b"]}
            self.assertEqual(self.run_merge(tmp, update), 0)
            doc = json.loads((tmp / "findings.json").read_text(encoding="utf-8"))
            self.assertEqual(doc["findings"][0]["status"], "Fixed")
            self.assertEqual(doc["limitations"], ["a", "b"])

    def test_perspective_replaced_by_name(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            first = {"perspectives": [{"name": "Coupling", "status": "not checked", "note": "x"}]}
            second = {"perspectives": [{"name": "Coupling", "status": "applied", "note": "y"}]}
            self.assertEqual(self.run_merge(tmp, first, second), 0)
            doc = json.loads((tmp / "findings.json").read_text(encoding="utf-8"))
            self.assertEqual(doc["perspectives"], second["perspectives"])

    def test_refused_merge_writes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            self.assertEqual(self.run_merge(tmp, {"findings": [finding(severity="Critical")]}), 1)
            self.assertFalse((tmp / "findings.json").exists())

    def test_duplicate_ids_in_one_fragment_refused(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.run_merge(Path(d), {"findings": [finding(), finding()]}), 1)

    def test_analysed_requires_analysis(self):
        bad = finding(validation={"verdict": "Valid", "method": "analysed", "evidence": "x"})
        with self.assertRaises(findings.SchemaError):
            findings.validate({"findings": [bad]})

    def test_definitive_verdict_requires_evidence(self):
        bad = finding(validation={"verdict": "FalsePositive", "method": "static"})
        with self.assertRaises(findings.SchemaError):
            findings.validate({"findings": [bad]})

    def test_location_must_be_path_line(self):
        with self.assertRaises(findings.SchemaError):
            findings.validate({"findings": [finding(location="worker/job.py")]})


class ContractTests(unittest.TestCase):
    def build(self, doc: dict) -> Path:
        out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, out)
        (out / "findings.json").write_text(json.dumps(doc), encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(render.main([str(out / "findings.json"), "--out", str(out)]), 0)
        return out

    def test_complete_run_passes(self):
        self.assertEqual(findings.contract_problems(self.build(complete_doc())), [])

    def test_sample_passes(self):
        doc = json.loads((REPO / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
        self.assertEqual(findings.contract_problems(self.build(doc)), [])

    def test_order_gaps_extra_files_and_missing_perspective_fail(self):
        doc = complete_doc()
        doc["findings"] = [finding("A-001", "Low"), finding("A-003", "High")]
        doc["perspectives"] = doc["perspectives"][1:]
        out = self.build(doc)
        (out / "notes.txt").write_text("x", encoding="utf-8")
        problems = "\n".join(findings.contract_problems(out))
        self.assertIn("gapless", problems)
        self.assertIn("severity order", problems)
        self.assertIn("notes.txt", problems)
        self.assertIn("Boundaries and layering", problems)
        self.assertEqual(
            [p for p in findings.contract_problems(out, ["notes.txt"]) if "notes.txt" in p], [])

    def test_order_problems_name_renumber_as_the_remedy(self):
        doc = complete_doc()
        doc["findings"] = [finding("A-001", "Low"), finding("A-003", "High")]
        order = [p for p in findings.contract_problems(self.build(doc))
                 if "gapless" in p or "severity order" in p]
        self.assertEqual(len(order), 2, order)
        for problem in order:
            self.assertIn("run renumber", problem)

    def test_an_assumed_severity_axis_sends_each_high_finding_to_decisions(self):
        doc = complete_doc()
        doc["meta"]["axis"] = "assumed"
        doc["findings"].append(finding("A-003", "High", validation={
            "verdict": "FalsePositive", "method": "static", "evidence": "job.py:58"}))
        problems = findings.contract_problems(self.build(doc))
        self.assertIn("A-001: its High severity rests on an assumed severity axis (meta.axis); "
                      "name it in decisions for a person to confirm", problems)
        self.assertFalse([p for p in problems if p.startswith(("A-002", "A-003"))], problems)
        doc["decisions"] = ["Confirm the core flows severity is judged against: A-001 rests on them"]
        out = self.build(doc)
        self.assertEqual(findings.contract_problems(out), [])
        self.assertIn("| Severity axis | assumed; not confirmed by the requester |",
                      (out / "report.md").read_text(encoding="utf-8"))
        self.assertIn("<dt>Severity axis</dt><dd>assumed; not confirmed by the requester</dd>",
                      (out / "dashboard.html").read_text(encoding="utf-8"))
        doc["meta"]["lang"] = "ja"
        self.assertIn("| 重大度の軸 | 仮定（依頼者は未確認） |",
                      (self.build(doc) / "report.md").read_text(encoding="utf-8"))

    def test_the_severity_axis_is_recorded_as_confirmed_or_assumed(self):
        doc = complete_doc()
        del doc["meta"]["axis"]
        self.assertIn("meta.axis: record whether the requester confirmed the list severity is "
                      "judged against (confirmed) or it was assumed (assumed)",
                      findings.contract_problems(self.build(doc)))
        doc["meta"]["axis"] = "guessed"
        with self.assertRaisesRegex(findings.SchemaError, "meta.axis"):
            findings.validate(doc, complete=True)

    def test_render_escapes_html_and_writes_both_languages(self):
        doc = complete_doc()
        doc["findings"][0]["title"] = "<b>raw</b>"
        out = self.build(doc)
        html = (out / "dashboard.html").read_text(encoding="utf-8")
        self.assertNotIn("<b>raw</b>", html)
        self.assertIn("&lt;b&gt;raw&lt;/b&gt;", html)
        ja = copy.deepcopy(doc)
        ja["meta"]["lang"] = "ja"
        self.assertIn("検出事項", (self.build(ja) / "report.md").read_text(encoding="utf-8"))


class DocumentTests(unittest.TestCase):
    def test_every_reference_is_cited_and_headed(self):
        skill = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        for ref in (SKILL / "reference").glob("*.md"):
            self.assertIn(f"reference/{ref.name}", skill, ref.name)
            self.assertIn("**Read when:**", ref.read_text(encoding="utf-8"), ref.name)

    def test_perspective_names_match_script(self):
        text = (SKILL / "reference" / "perspectives.md").read_text(encoding="utf-8")
        table = text.split("| Perspective |", 1)[1].split("\n\n", 1)[0]
        names = tuple(re.findall(r"^\| ([A-Z][^|]+?) \|", table, re.MULTILINE))
        self.assertEqual(names, findings.PERSPECTIVES)

    def test_frontmatter(self):
        head = (SKILL / "SKILL.md").read_text(encoding="utf-8").split("---")[1]
        self.assertIn("name: architecture-scan", head)
        self.assertIn("allowed-tools:", head)


if __name__ == "__main__":
    unittest.main()
