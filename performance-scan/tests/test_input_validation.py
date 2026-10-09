"""Regression checks for inferred budgets and malformed merge records."""
import copy
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_performance_scan import complete_doc, findings, render


class BudgetInferredValidationTests(unittest.TestCase):
    def test_inferred_rejects_non_boolean_values_with_a_field_diagnostic(self):
        for value in ("true", "false", 0, 1, None, [], {}):
            with self.subTest(value=value):
                doc = complete_doc()
                doc["budgets"][0]["inferred"] = value
                with self.assertRaises(findings.SchemaError) as error:
                    findings.validate(doc)
                self.assertIn("budgets[0].inferred", str(error.exception))
                self.assertIn("bool", str(error.exception))

    def test_invalid_inferred_in_existing_record_or_fragment_preserves_merge_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "findings.json"
            fragment = root / "fragment.json"
            for origin in ("existing record", "fragment"):
                with self.subTest(origin=origin):
                    doc = complete_doc()
                    update = {"meta": {"project": "This update must not persist"}}
                    if origin == "existing record":
                        doc["budgets"][0]["inferred"] = "true"
                    else:
                        update["budgets"] = [{"id": "B-01", "inferred": "true"}]
                    target.write_text(json.dumps(doc) + "\n", encoding="utf-8")
                    original = target.read_bytes()
                    fragment.write_text(json.dumps(update), encoding="utf-8")
                    errors = io.StringIO()
                    with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                        result = findings.main(["merge", str(target), str(fragment)])
                    self.assertEqual(result, 1)
                    self.assertIn("refused:", errors.getvalue())
                    self.assertIn("budgets[0].inferred", errors.getvalue())
                    self.assertEqual(target.read_bytes(), original)

    def test_render_and_check_refuse_invalid_inferred_without_changing_saved_files(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            source = out / "findings.json"
            doc = complete_doc()
            source.write_text(json.dumps(doc), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(render.main([str(source), "--out", str(out)]), 0)
            doc["budgets"][0]["inferred"] = 1
            source.write_text(json.dumps(doc), encoding="utf-8")
            originals = {out / name: (out / name).read_bytes()
                         for name in ("findings.json", "report.md", "dashboard.html")}
            for command, main, args, expected in (
                    ("render", render.main, [str(source), "--out", str(out)], 2),
                    ("check", findings.main, ["check", str(out)], 1)):
                with self.subTest(command=command):
                    for path, content in originals.items():
                        path.write_bytes(content)
                    output, errors = io.StringIO(), io.StringIO()
                    with redirect_stdout(output), redirect_stderr(errors):
                        result = main(args)
                    self.assertEqual(result, expected)
                    self.assertIn("budgets[0].inferred", errors.getvalue())
                    self.assertNotIn("contract ok", output.getvalue())
                    for path, content in originals.items():
                        self.assertEqual(path.read_bytes(), content, path.name)

    def test_omitted_and_boolean_inferred_round_trip_with_correct_display(self):
        doc = complete_doc()
        budget = doc["budgets"][0]
        doc["budgets"] = [dict(budget), dict(budget, id="B-02", inferred=True),
                          dict(budget, id="B-03", inferred=False)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / "out"
            out.mkdir()
            source = out / "findings.json"
            fragment = root / "fragment.json"
            fragment.write_text(json.dumps(doc), encoding="utf-8")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(findings.main(["merge", str(source), str(fragment)]), 0)
            self.assertEqual(json.loads(source.read_text(encoding="utf-8")), doc)
            for lang, labels in (("en", ("—", "Yes — confirm with owner", "No")),
                                 ("ja", ("—", "推定・要確認", "いいえ"))):
                with self.subTest(lang=lang):
                    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        self.assertEqual(render.main([
                            str(source), "--out", str(out), "--lang", lang]), 0)
                        self.assertEqual(findings.main(["check", str(out)]), 0)
                    markdown = (out / "report.md").read_text(encoding="utf-8")
                    html = (out / "dashboard.html").read_text(encoding="utf-8")
                    for record, label in zip(doc["budgets"], labels):
                        with self.subTest(budget=record["id"]):
                            row = next(line for line in markdown.splitlines()
                                       if line.startswith(f"| {record['id']} |"))
                            self.assertIn(f"| {render.shown('violated', lang)} | {label} |", row)
                            row = next(row for row in re.findall(r"<tr>.*?</tr>", html)
                                       if row.startswith(f"<tr><td>{record['id']}</td>"))
                            self.assertIn(f"<td>{render.shown('violated', lang)}</td><td>{label}</td>", row)


class MergeRecordValidationTests(unittest.TestCase):
    def test_merge_rejects_record_objects_and_identity_types_as_schema_errors(self):
        cases = (
            ("findings", None, "findings[0]"),
            ("budgets", None, "budgets[0]"),
            ("perspectives", None, "perspectives[0]"),
            ("findings", {"id": []}, "findings[0].id"),
            ("budgets", {"id": {}}, "budgets[0].id"),
            ("perspectives", {"name": []}, "perspectives[0].name"),
            ("findings", {"id": 0}, "findings[0].id"),
            ("budgets", {"id": False}, "budgets[0].id"),
            ("perspectives", {}, "perspectives[0].name"),
            ("findings", {"id": " "}, "findings[0].id"),
        )
        for field, record, where in cases:
            with self.subTest(field=field, record=record):
                with self.assertRaises(findings.SchemaError) as error:
                    findings.merge(complete_doc(), {field: [record]}, "fragment.json")
                self.assertIn(where, str(error.exception))

    def test_malformed_merge_fragments_return_failure_and_preserve_target(self):
        cases = (
            ({"perspectives": [None]}, "perspectives[0]"),
            ({"findings": [{"id": []}]}, "findings[0].id"),
            ({"budgets": [{"id": {}}]}, "budgets[0].id"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "findings.json"
            fragment = root / "fragment.json"
            original = (json.dumps(complete_doc()) + "\n").encode("utf-8")
            for update, where in cases:
                with self.subTest(fragment=update):
                    target.write_bytes(original)
                    update = {"meta": {"project": "This update must not persist"}, **update}
                    fragment.write_text(json.dumps(update), encoding="utf-8")
                    errors = io.StringIO()
                    with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                        result = findings.main(["merge", str(target), str(fragment)])
                    self.assertEqual(result, 1)
                    self.assertIn("refused:", errors.getvalue())
                    self.assertIn(where, errors.getvalue())
                    self.assertNotIn("Traceback", errors.getvalue())
                    self.assertEqual(target.read_bytes(), original)

    def test_partial_id_updates_and_last_same_name_perspective_remain_supported(self):
        doc = complete_doc()
        expected = copy.deepcopy(doc)
        expected["findings"][0]["status"] = "Fixed"
        expected["budgets"][0]["inferred"] = True
        first = {"name": "Database access", "status": "not checked", "note": "Pending",
                 "old_only": "This field must be replaced"}
        last = {"name": "Database access", "status": "applied", "note": "Examined"}
        expected["perspectives"] = expected["perspectives"][1:] + [last]
        update = {"findings": [{"id": "P-001", "status": "Fixed"}],
                  "budgets": [{"id": "B-01", "inferred": True}],
                  "perspectives": [first, last]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "findings.json"
            target.write_text(json.dumps(doc), encoding="utf-8")
            fragment = root / "fragment.json"
            fragment.write_text(json.dumps(update), encoding="utf-8")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(findings.main(["merge", str(target), str(fragment)]), 0)
            self.assertEqual(json.loads(target.read_text(encoding="utf-8")), expected)


if __name__ == "__main__":
    unittest.main()
