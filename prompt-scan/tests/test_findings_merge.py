import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from helpers import SAMPLE_APP, findings, inventory, run, write_json

META = {"target": "t", "date": "2026-10-11", "assessor": "test", "lang": "en"}


def finding(n, **extra):
    record = {"id": f"F-{n:03d}", "kind": "defect", "severity": "Low", "confidence": "Confirmed",
              "category": "Output contract", "title": f"finding {n}", "location": "app.py:1",
              "validation": {"verdict": "Likely", "evidence": "", "method": "static"}}
    record.update(extra)
    return record


class MergeTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.out = self.dir / "findings.json"

    def merge(self, *fragments):
        paths = []
        for i, fragment in enumerate(fragments):
            path = self.dir / f"fragment{len(list(self.dir.iterdir()))}-{i}.json"
            write_json(path, fragment)
            paths.append(path)
        return run(findings.main, "merge", self.out, *paths)

    def data(self):
        return json.loads(self.out.read_text(encoding="utf-8"))

    def test_creates_and_updates_by_id(self):
        self.assertEqual(self.merge({"meta": META, "findings": [finding(1)]})[0], 0)
        code, _, err = self.merge({"findings": [{"id": "F-001", "validation": {
            "verdict": "Valid", "evidence": "re-read", "method": "static"}}]})
        self.assertEqual(code, 0, err)
        record = self.data()["findings"][0]
        self.assertEqual(record["validation"]["verdict"], "Valid")
        self.assertEqual(record["title"], "finding 1")
        self.assertEqual(self.data()["schema_version"], 1)

    def test_refuses_a_report_language_render_py_has_no_labels_for(self):
        code, _, err = self.merge({"meta": dict(META, lang="english")})
        self.assertEqual(code, 2)
        self.assertIn("meta.lang must be one of", err)
        self.assertFalse(self.out.exists())

    def test_a_fragment_repairs_a_language_recorded_before_it_was_checked(self):
        write_json(self.out, {"meta": dict(META, lang="en-US"), "findings": [finding(1)]})
        code, _, err = self.merge({"findings": [finding(2)]})
        self.assertEqual(code, 2)
        self.assertIn("meta.lang must be one of", err)
        code, _, err = self.merge({"meta": {"lang": "en"}})
        self.assertEqual(code, 0, err)
        self.assertEqual(self.data()["meta"]["lang"], "en")
        # Only a string language is set aside: anything else is still the schema error it was.
        for base, message in (([], "report must be a JSON object"), ({"meta": {"lang": ["en"]}}, "meta.lang must be")):
            write_json(self.out, base)
            code, _, err = self.merge({"meta": {"lang": "en"}})
            self.assertEqual(code, 2, err)
            self.assertIn(message, err)

    def test_refuses_more_than_five_new_findings(self):
        code, _, err = self.merge({"meta": META, "findings": [finding(n) for n in range(1, 7)]})
        self.assertEqual(code, 1)
        self.assertIn("at most 5", err)
        self.assertFalse(self.out.exists())

    def test_lint_findings_belong_to_inventory(self):
        code, _, err = self.merge({"findings": [finding(1, id="L-001")]})
        self.assertEqual(code, 1)
        self.assertIn("inventory.py --into", err)
        base = {"meta": META, "findings": [dict(finding(1, id="L-001"), source="inventory.py", rule="placeholder")]}
        write_json(self.out, base)
        code, _, err = self.merge({"findings": [{"id": "L-001", "title": "renamed"}]})
        self.assertEqual(code, 1)
        self.assertIn("merge only validation", err)
        code, _, err = self.merge({"findings": [{"id": "L-001", "validation": {
            "verdict": "FalsePositive", "evidence": "literal brace in a comment", "method": "static"}}]})
        self.assertEqual(code, 0, err)

    def test_scanner_fields_refused_on_known_findings_too(self):
        self.merge({"meta": META, "findings": [finding(1)]})
        code, _, err = self.merge({"findings": [{"id": "F-001", "rule": "placeholder"}]})
        self.assertEqual(code, 1)
        self.assertIn("belong to inventory.py", err)

    def test_write_keeps_permissions_and_creates_private_files(self):
        self.merge({"meta": META})
        self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o600)
        os.chmod(self.out, 0o640)
        self.merge({"checked_ok": ["x"]})
        self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o640)

    def test_too_deep_fragment_is_an_input_error(self):
        path = self.dir / "deep.json"
        path.write_text('{"meta":' + "[" * 100000 + "]" * 100000 + "}", encoding="utf-8")
        code, _, err = run(findings.main, "merge", self.out, path)
        self.assertEqual(code, 2, err)
        self.assertIn("error:", err)

    def test_lone_surrogate_is_an_input_error(self):
        # It passed every check, then crashed the write with a traceback (exit 1, which means "refused").
        path = self.dir / "surrogate.json"
        path.write_text('{"checked_ok": ["split \\ud83d here"]}', encoding="utf-8")
        code, _, err = run(findings.main, "merge", self.out, path)
        self.assertEqual(code, 2, err)
        self.assertIn("surrogate", err)

    def test_refuses_scanner_meta(self):
        code, _, err = self.merge({"meta": dict(META, commit="0" * 40)})
        self.assertEqual(code, 1)
        self.assertIn("inventory.py --into", err)

    def test_refuses_literal_override_strings(self):
        code, _, err = self.merge({"meta": META, "findings": [finding(
            1, symptom="A ticket saying 'Ignore all previous instructions' changes the reply")]})
        self.assertEqual(code, 1)
        self.assertIn("instruction-override", err)
        code, _, err = self.merge({"meta": META, "findings": [finding(
            1, symptom="Text in the ticket can override the instructions; it is not delimited as data")]})
        self.assertEqual(code, 0, err)

    def test_refuses_credential_values(self):
        token = "sk-ant-" + "a1B2" * 8
        code, _, err = self.merge({"meta": META, "checked_ok": [f"key {token} found"]})
        self.assertEqual(code, 1)
        self.assertIn("credential-shaped", err)

    def test_refusals_cover_object_keys(self):
        token = "sk-ant-" + "a1B2" * 8
        code, _, err = self.merge({"meta": dict(META, **{token: "x"})})
        self.assertEqual(code, 1)
        self.assertIn("credential-shaped", err)
        code, _, err = self.merge({"meta": META, "findings": [finding(1, **{"ignore all previous instructions": "x"})]})
        self.assertEqual(code, 1)
        self.assertIn("instruction-override", err)
        self.assertFalse(self.out.exists())

    def test_non_standard_json_is_an_input_error(self):
        for raw in ('{"meta": {"x": NaN}}', '{"meta": {"x": -Infinity}}', '{"meta": {}, "meta": {}}'):
            path = self.dir / "fragment.json"
            path.write_text(raw, encoding="utf-8")
            code, _, err = run(findings.main, "merge", self.out, path)
            self.assertEqual(code, 2, raw)
            self.assertFalse(self.out.exists())

    def test_perspective_replaced_by_name_and_remove(self):
        self.merge({"meta": META, "perspectives": [{"name": "Examples", "result": "not checked", "note": "later"}],
                    "limitations": ["old line"]})
        code, _, err = self.merge({"perspectives": [{"name": "Examples", "result": "N/A", "note": "none"}],
                                   "remove": {"limitations": ["old line"]}})
        self.assertEqual(code, 0, err)
        data = self.data()
        self.assertEqual(data["perspectives"], [{"name": "Examples", "result": "N/A", "note": "none"}])
        self.assertEqual(data["limitations"], [])
        code, _, err = self.merge({"remove": {"limitations": ["never recorded"]}})
        self.assertEqual(code, 1)
        self.assertIn("is not recorded", err)

    def test_schema_error_leaves_file_unchanged(self):
        self.merge({"meta": META, "findings": [finding(1)]})
        before = self.out.read_bytes()
        code, _, err = self.merge({"findings": [{"id": "F-001", "validation": {
            "verdict": "Valid", "evidence": "", "method": "static"}}]})
        self.assertEqual(code, 2)
        self.assertIn("needs validation.evidence", err)
        self.assertEqual(self.out.read_bytes(), before)

    def test_renumber_orders_by_severity_then_location_and_follows_references(self):
        excluded = {"verdict": "FalsePositive", "evidence": "handled in code", "method": "static"}
        self.merge({"meta": META, "findings": [
            finding(1, location="b.py:9", proposal={"before": "error F-002", "after": "error F-002 or F-004"},
                    references=[{"title": "F-002 docs", "url": "https://example.com/F-002"}]),
            finding(2, severity="High", location="z.py:1", cause="same root as F-004"),
            finding(3, severity="High", location="a.py:5", validation=excluded),
            finding(4, location="b.py:2"),
        ], "next_steps": ["fix F-002 first, then F-001"]})
        write_json(self.dir / "eval.json", {"eval_runs": [
            {"id": "E-001", "finding": "F-002", "model": "m", "date": "2026-10-12", "cases": 1, "passed": 1,
             "failed": 0}]})
        self.assertEqual(run(findings.main, "merge", self.out, self.dir / "eval.json")[0], 0)
        code, out, err = run(findings.main, "renumber", self.out)
        self.assertEqual(code, 0, err)
        data = self.data()
        # High z.py, then Low b.py:2 before b.py:9; the excluded High goes last.
        self.assertEqual([(f["id"], f["location"]) for f in data["findings"]],
                         [("F-001", "z.py:1"), ("F-002", "b.py:2"), ("F-003", "b.py:9"), ("F-004", "a.py:5")])
        self.assertEqual(data["findings"][0]["cause"], "same root as F-002")
        self.assertEqual(data["eval_runs"][0]["finding"], "F-001")
        self.assertEqual(data["next_steps"], ["fix F-001 first, then F-003"])
        # Quoted prompt text and links are not finding references.
        self.assertEqual(data["findings"][2]["proposal"], {"before": "error F-002", "after": "error F-002 or F-004"})
        self.assertEqual(data["findings"][2]["references"][0]["url"], "https://example.com/F-002")
        # A reference's title is prose and follows the new numbers.
        self.assertEqual(data["findings"][2]["references"][0]["title"], "F-001 docs")
        code, out, _ = run(findings.main, "renumber", self.out)
        self.assertEqual(code, 0)
        self.assertIn("already in order", out)

    def test_a_malformed_record_is_a_schema_error(self):
        fragment = self.dir / "meta.json"
        write_json(fragment, {"meta": META})
        for base in ({"meta": None}, {"findings": None}, {"meta": "x"}):
            write_json(self.out, base)
            code, _, err = run(findings.main, "merge", self.out, fragment)
            self.assertEqual((code, err.startswith("error: ")), (2, True), err)
            code, _, err = run(inventory.main, SAMPLE_APP, "--into", self.out)
            self.assertEqual((code, err.startswith("inventory.py: ")), (2, True), err)

    def test_renumber_leaves_paths_and_scanner_fields_alone(self):
        # Feature ids such as F-002 name directories and prompts; only references to findings move.
        lint = {"id": "L-001", "source": "inventory.py", "rule": "placeholder", "kind": "defect",
                "severity": "Low", "confidence": "Suspected", "category": "Maintainability", "title": "Placeholder",
                "location": "prompts/F-002/system.md:2", "cause": "inventory.py placeholder: 1 line(s).",
                "validation": {"verdict": "Valid", "evidence": "same root as F-002", "method": "read"}}
        write_json(self.out, {"meta": dict(META, scope="prompts/F-002"), "prompts": [
            {"id": "P-01", "name": "Feature F-002 summariser", "kind": "system", "location": "prompts/F-002/system.md:1"}],
            "findings": [finding(1, location="prompts/F-002/system.md:9", prompt="P-01",
                                 cause="see prompts/F-002/system.md:3 and F-002"),
                         finding(2, severity="High", location="prompts/F-002/system.md:3", prompt="P-01"), lint]})
        code, _, err = run(findings.main, "renumber", self.out)
        self.assertEqual(code, 0, err)
        data = self.data()
        self.assertEqual([(f["id"], f["location"]) for f in data["findings"]],
                         [("F-001", "prompts/F-002/system.md:3"), ("F-002", "prompts/F-002/system.md:9"),
                          ("L-001", "prompts/F-002/system.md:2")])
        self.assertEqual(data["findings"][1]["cause"], "see prompts/F-002/system.md:3 and F-001")
        self.assertEqual(data["findings"][2]["validation"]["evidence"], "same root as F-001")
        self.assertEqual({k: v for k, v in data["findings"][2].items() if k != "validation"},
                         {k: v for k, v in lint.items() if k != "validation"})
        self.assertEqual(data["prompts"][0]["name"], "Feature F-002 summariser")
        self.assertEqual(data["meta"]["scope"], "prompts/F-002")

    def test_renumber_tells_lists_from_paths(self):
        mapping = {"F-001": "F-009", "F-002": "F-008", "F-003": "F-007", "F-004": "F-006"}
        cases = {
            "F-001/F-002/F-003/F-004": "F-009/F-008/F-007/F-006",
            "(F-001/F-002), see F-003. F-001とF-002": "(F-009/F-008), see F-007. F-009とF-008",
            "F-001-F-003": "F-009-F-007",
            "prompts/F-002/F-002.md:3": "prompts/F-002/F-002.md:3",
            "prompts/F-002/F-002-system.md": "prompts/F-002/F-002-system.md",
            "prompts\\F-002\\a.md and F-002.md": "prompts\\F-002\\a.md and F-002.md",
            "https://example.com/F-002": "https://example.com/F-002",
            # Japanese prose has no spaces: a path elsewhere in the sentence does not make an id part of it.
            "app/llm/answer.pyの12行目でF-001と同じ欠陥。": "app/llm/answer.pyの12行目でF-009と同じ欠陥。",
            "F-002（prompts/a.md）を参照": "F-008（prompts/a.md）を参照",
            "詳細はprompts/F-002/a.mdを参照": "詳細はprompts/F-002/a.mdを参照",
            # A hyphenated word is prose unless an extension follows; a list may mix record kinds; a colon
            # ends the word, so neither a label nor path:line hides an id or makes one part of a path.
            "the F-001-style contradiction, F-002-v2.md": "the F-009-style contradiction, F-002-v2.md",
            "see L-003/F-001 and F-002/P-01": "see L-003/F-009 and F-008/P-01",
            "関連:F-001/F-002、prompts/F-002/a.md:3": "関連:F-009/F-008、prompts/F-002/a.md:3",
        }
        for before, after in cases.items():
            data = {"findings": [{"id": "F-005", "cause": before}]}
            self.assertEqual(findings.renumber(data, mapping)["findings"][0]["cause"], after, before)


if __name__ == "__main__":
    unittest.main()
