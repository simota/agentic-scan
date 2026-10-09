"""Offline checks for the performance-scan skill's record and render scripts."""
from __future__ import annotations

import copy
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
from types import ModuleType
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

SKILL = Path(__file__).resolve().parents[1] / "skills" / "performance-scan"


def import_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", [str(path.parent)] + sys.path):
        spec.loader.exec_module(module)
    return module


findings = import_module(SKILL / "scripts" / "findings.py", "perf_findings")
render = import_module(SKILL / "scripts" / "render.py", "perf_render")


def finding(fid="P-001", severity="High", **extra) -> dict:
    record = {
        "id": fid, "title": "Order list loads items per order", "severity": severity,
        "confidence": "Confirmed", "category": "Database access", "step": "DB1",
        "location": ["app/orders/serializers.py:42"],
        "workload": "Order list, hot", "scale_driver": "Items per order, uncapped",
        "cost_model": "1 + N queries", "request": "1. GET /api/orders?page=<n>",
        "impact": "Expected constant queries; actual 1 + N", "fix": "Prefetch items",
        "regression_test": "Query count equal for 1 and 50 orders",
        "validation": {"verdict": "Valid", "method": "static", "evidence": "views.py:18"},
    }
    record.update(extra)
    return record


def complete_doc() -> dict:
    return {
        "meta": {"project": "demo", "scope": "repo root", "date": "2026-10-09",
                 "assessor": "test", "lang": "en"},
        "budgets": [{"id": "B-01", "statement": "constant queries", "source": "baseline",
                     "status": "violated"}],
        "findings": [finding(), finding("P-002", "Low")],
        "perspectives": [{"name": n, "status": "applied", "note": "applied"}
                         for n in findings.PERSPECTIVES],
        "checked_ok": ["search paginates"],
        "limitations": ["production volume not observed"],
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
            update = {"findings": [{"id": "P-001", "status": "Fixed"}], "limitations": ["a", "b"]}
            self.assertEqual(self.run_merge(tmp, update), 0)
            doc = json.loads((tmp / "findings.json").read_text(encoding="utf-8"))
            self.assertEqual(doc["findings"][0]["status"], "Fixed")
            self.assertEqual(doc["limitations"], ["a", "b"])

    def test_refused_merge_writes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            bad = finding(severity="Critical")
            self.assertEqual(self.run_merge(tmp, {"findings": [bad]}), 1)
            self.assertFalse((tmp / "findings.json").exists())

    def test_duplicate_ids_in_one_fragment_refused(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.run_merge(Path(d), {"findings": [finding(), finding()]}), 1)

    def test_measured_requires_measurement(self):
        bad = finding(validation={"verdict": "Valid", "method": "measured", "evidence": "x"})
        with self.assertRaises(findings.SchemaError):
            findings.validate({"findings": [bad]})

    def test_definitive_verdict_requires_evidence(self):
        bad = finding(validation={"verdict": "FalsePositive", "method": "static"})
        with self.assertRaises(findings.SchemaError):
            findings.validate({"findings": [bad]})

    def test_location_must_be_path_line(self):
        with self.assertRaises(findings.SchemaError):
            findings.validate({"findings": [finding(location="app/orders.py")]})


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

    def test_order_gaps_extra_files_and_missing_perspective_fail(self):
        doc = complete_doc()
        doc["findings"] = [finding("P-001", "Low"), finding("P-003", "High")]
        doc["perspectives"] = doc["perspectives"][1:]
        out = self.build(doc)
        (out / "notes.txt").write_text("x", encoding="utf-8")
        problems = "\n".join(findings.contract_problems(out))
        self.assertIn("gapless", problems)
        self.assertIn("severity order", problems)
        self.assertIn("notes.txt", problems)
        self.assertIn("Database access", problems)
        self.assertEqual(
            [p for p in findings.contract_problems(out, ["notes.txt"]) if "notes.txt" in p], [])

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
        self.assertIn("name: performance-scan", head)
        self.assertIn("allowed-tools:", head)


if __name__ == "__main__":
    unittest.main()
