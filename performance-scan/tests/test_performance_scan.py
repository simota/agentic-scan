"""Offline checks for the performance-scan skill's record and render scripts."""
from __future__ import annotations

import copy
import io
import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

# Re-exported for code that still imports these helpers from this module.
from support import (
    REPO, SKILL, complete_doc, contract_problems, element_text, finding, findings,
    HtmlTableReader, HtmlTreeReader, import_module, render, run_cli, run_main, snapshot,
    write_run_dir,
)

__all__ = [
    "REPO", "SKILL", "complete_doc", "contract_problems", "element_text", "finding",
    "findings", "HtmlTableReader", "HtmlTreeReader", "import_module", "render", "run_cli",
    "run_main", "snapshot", "write_run_dir",
]


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

    def test_budget_families_match_script(self):
        text = (SKILL / "reference" / "budgets.md").read_text(encoding="utf-8")
        families = tuple(re.findall(r"^- \*\*([A-Z]+)\*\* —", text, re.MULTILINE))
        self.assertEqual(families, findings.BUDGET_FAMILIES)

    def test_readme_hunt_step_count_matches_perspectives(self):
        text = (SKILL / "reference" / "perspectives.md").read_text(encoding="utf-8")
        steps = set(re.findall(r"^\| ([A-Z]{2}[0-9]+) \| (?!\*?Sound)", text, re.MULTILINE))
        readme = (SKILL.parents[1] / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"with {len(steps)} hunt steps", " ".join(readme.split()))

    def test_hunt_step_ids_match_script(self):
        text = (SKILL / "reference" / "perspectives.md").read_text(encoding="utf-8")
        hunts = text.split("## Sound constructs", 1)[0]
        steps = set(re.findall(r"^\| ([A-Z]{2}[0-9]+) \|", hunts, re.MULTILINE))
        self.assertEqual(steps, findings.HUNT_STEPS)

    def test_each_hunt_step_belongs_to_the_perspective_heading_it(self):
        text = (SKILL / "reference" / "perspectives.md").read_text(encoding="utf-8")
        hunts = text.split("## Hunt steps per perspective", 1)[1].split("## Sound constructs", 1)[0]
        owners = {}
        for name, prefix, body in re.findall(r"^### (.+?) \(([A-Z]{2})\).*?\n(.*?)(?=^### |\Z)",
                                             hunts, re.MULTILINE | re.DOTALL):
            for step in re.findall(r"^\| ([A-Z]{2}[0-9]+) \|", body, re.MULTILINE):
                self.assertTrue(step.startswith(prefix), step)
                owners[step] = name
        self.assertEqual(owners, findings.STEP_PERSPECTIVES)

    def test_chat_block_follows_the_rendered_field_order(self):
        text = (SKILL / "reference" / "report.md").read_text(encoding="utf-8")
        block = text.split("```", 2)[1]
        labels = [line.strip().split(":")[0] for line in block.splitlines()[2:] if ":" in line]
        en = render.LABELS["en"]
        rendered = [en[key] for key in render.FIELDS]
        self.assertEqual([label for label in labels if label in rendered], rendered)

    def test_every_sound_constructs_step_has_a_row_in_its_table(self):
        text = (SKILL / "reference" / "perspectives.md").read_text(encoding="utf-8")
        hunts, table = text.split("## Sound constructs", 1)
        marked = set(re.findall(r"^\| ([A-Z]{2}[0-9]+) \| \*\(sound constructs\)\*", hunts, re.MULTILINE))
        rows = set(re.findall(r"^\| ([A-Z]{2}[0-9]+) \|", table, re.MULTILINE))
        self.assertEqual(marked, rows)
        # Hunt tables have no sound-constructs rows hiding among them.
        self.assertNotIn("| Synchronised retries", hunts)

    def test_note_examples_credit_a_query_count_budget_with_db1_only(self):
        # perspectives.md: a QRY query-count row covers DB1 but never DB2-DB5,
        # and B-01 is the QRY baseline in every example.
        sources = [SKILL / "reference" / "perspectives.md", SKILL / "reference" / "findings-schema.md",
                   REPO / "examples" / "findings.sample.json"]
        credited = []
        for path in sources:
            text = path.read_text(encoding="utf-8")
            # Only notes that credit B-01 alone: "DB1-DB2 via B-01, B-02" also names SIZE budgets.
            for first, last in re.findall(r"DB([0-9])(?:[–-]DB([0-9]))? via B-01(?![0-9]|, B-)", text):
                steps = range(int(first), int(last or first) + 1)
                credited.append((path.name, [f"DB{n}" for n in steps]))
        self.assertTrue(credited)
        for name, steps in credited:
            self.assertEqual(steps, ["DB1"], name)

    def test_no_verdict_is_documented_as_a_default(self):
        # validate_finding requires validation.verdict; a missing one is refused.
        bad = finding(validation={"method": "static"})
        with self.assertRaises(findings.SchemaError):
            findings.validate_finding(bad, "f")
        text = (SKILL / "reference" / "validation.md").read_text(encoding="utf-8")
        row = re.search(r"^\| `Unverified` \|.*$", text, re.MULTILINE).group()
        self.assertNotIn("Default", row)

    def test_frontmatter(self):
        head = (SKILL / "SKILL.md").read_text(encoding="utf-8").split("---")[1]
        self.assertIn("name: performance-scan", head)
        self.assertIn("allowed-tools:", head)


if __name__ == "__main__":
    unittest.main()
