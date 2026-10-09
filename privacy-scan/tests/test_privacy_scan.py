"""Offline checks for the privacy-scan skill's record and render scripts."""
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

REPO = Path(__file__).resolve().parents[1]
SKILL = REPO / "skills" / "privacy-scan"


def import_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", [str(path.parent)] + sys.path):
        spec.loader.exec_module(module)
    return module


findings = import_module(SKILL / "scripts" / "findings.py", "priv_findings")
render = import_module(SKILL / "scripts" / "render.py", "priv_render")


def finding(fid="PV-001", severity="High", **extra) -> dict:
    record = {
        "id": fid, "title": "Error tracker receives request bodies", "severity": severity,
        "confidence": "Confirmed", "category": "Logs, telemetry and errors", "step": "LT2",
        "location": ["api/app.py:22"],
        "data": "shipping_address, phone", "subjects": "Customers at checkout",
        "flow": "1. POST /api/checkout. 2. Error captured with body", "impact": "Addresses sent",
        "fix": "Turn body capture off", "guard": "Captured event has no body for user@example.com",
        "validation": {"verdict": "Valid", "method": "static", "evidence": "app.py:22"},
    }
    record.update(extra)
    return record


def complete_doc() -> dict:
    return {
        "meta": {"project": "demo", "scope": "repo root", "date": "2026-10-09",
                 "assessor": "test", "lang": "en"},
        "commitments": [{"id": "C-01", "statement": "no PII in errors", "source": "policy", "status": "violated"}],
        "findings": [finding(), finding("PV-002", "Low")],
        "perspectives": [{"name": n, "status": "applied", "note": "applied"}
                         for n in findings.PERSPECTIVES],
        "checked_ok": ["deletion cascades"],
        "limitations": ["not legal advice"],
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
            update = {"findings": [{"id": "PV-001", "status": "Fixed"}], "limitations": ["a", "b"]}
            self.assertEqual(self.run_merge(tmp, update), 0)
            doc = json.loads((tmp / "findings.json").read_text(encoding="utf-8"))
            self.assertEqual(doc["findings"][0]["status"], "Fixed")
            self.assertEqual(doc["limitations"], ["a", "b"])

    def test_perspective_replaced_by_name(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            first = {"perspectives": [{"name": "Storage protection", "status": "not checked", "note": "x"}]}
            second = {"perspectives": [{"name": "Storage protection", "status": "applied", "note": "y"}]}
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

    def test_personal_values_refused(self):
        for text in ("Sent for jane.doe@acme-mail.co.jp", "card 4111 1111 1111 1111"):
            with self.assertRaises(findings.SchemaError, msg=text):
                findings.validate({"findings": [finding(impact=text)]})
        findings.validate({"findings": [finding(impact="Sent for user@example.com at api/app.py:22")]})
        with self.assertRaises(findings.SchemaError):
            findings.validate({"findings": [finding(validation={
                "verdict": "Valid", "method": "static", "evidence": "row for a@b.jp"})]})

    def test_location_must_be_path_line(self):
        with self.assertRaises(findings.SchemaError):
            findings.validate({"findings": [finding(location="api/app.py")]})


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
        doc["findings"] = [finding("PV-001", "Low"), finding("PV-003", "High")]
        doc["perspectives"] = doc["perspectives"][1:]
        out = self.build(doc)
        (out / "notes.txt").write_text("x", encoding="utf-8")
        problems = "\n".join(findings.contract_problems(out))
        self.assertIn("gapless", problems)
        self.assertIn("severity order", problems)
        self.assertIn("notes.txt", problems)
        self.assertIn("Data inventory and minimisation", problems)
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
        self.assertIn("name: privacy-scan", head)
        self.assertIn("allowed-tools:", head)


if __name__ == "__main__":
    unittest.main()
