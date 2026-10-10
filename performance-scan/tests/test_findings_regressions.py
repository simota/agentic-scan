"""Regression checks for finding fields, measurements and source locations."""
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from support import complete_doc, finding, findings, render, run_cli, run_main


MEASUREMENT = {
    "environment": "local synthetic data",
    "command": "python3 tests/query_count.py",
    "result": "query count is 3 for both 1 and 50 orders",
}


class JsonReadRegressionTests(unittest.TestCase):
    def test_read_json_reports_invalid_utf8_as_a_schema_error(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "findings.json"
            source.write_bytes(b"\xff")
            with self.assertRaises(findings.SchemaError) as error:
                findings.read_json(source)
            self.assertIn(str(source), str(error.exception))
            self.assertIn("utf-8", str(error.exception))

    def test_render_cli_rejects_invalid_utf8_without_writing_or_a_traceback(self):
        for existing in (False, True):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "findings.json"
                source.write_bytes(b"\xff")
                out = root / "out"
                originals = {"report.md": b"Previous report", "dashboard.html": b"Previous dashboard"}
                if existing:
                    out.mkdir()
                    for name, content in originals.items():
                        (out / name).write_bytes(content)
                result = run_cli("render.py", source, "--out", out)
                self.assertEqual(result.returncode, 2)
                self.assertIn("schema:", result.stderr)
                self.assertIn(str(source), result.stderr)
                self.assertIn("utf-8", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                if existing:
                    for name, content in originals.items():
                        self.assertEqual((out / name).read_bytes(), content)
                else:
                    self.assertFalse(out.exists())


class SchemaMessageTests(unittest.TestCase):
    def test_schema_errors_name_the_input_file(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "findings.json"
            source.write_text("[]", encoding="utf-8")
            code, _, err = run_main(render.main, source, "--out", directory)
            self.assertEqual(code, 2)
            self.assertEqual(err, f"schema: {source}: top level: must be an object\n")

    def test_error_messages_truncate_large_values(self):
        doc = complete_doc()
        doc["findings"][0]["severity"] = "x" * 10000
        with self.assertRaises(findings.SchemaError) as caught:
            findings.validate(doc)
        self.assertLess(len(str(caught.exception)), 200)


class MeasurementRegressionTests(unittest.TestCase):
    def test_invalid_measurements_preserve_merge_target_for_both_methods(self):
        invalid = [None, [], "not an object", {}]
        for key in MEASUREMENT:
            missing = dict(MEASUREMENT)
            del missing[key]
            invalid.append(missing)
            invalid.append(dict(MEASUREMENT, **{key: " \t"}))
            invalid.append(dict(MEASUREMENT, **{key: 0}))

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            target = root / "findings.json"
            target.write_text(json.dumps(complete_doc()) + "\n", encoding="utf-8")
            original = target.read_bytes()
            fragment = root / "fragment.json"
            for method in ("static", "measured"):
                for measurement in invalid:
                    with self.subTest(method=method, measurement=measurement):
                        fragment.write_text(json.dumps({"findings": [{
                            "id": "P-001", "title": "This update must not be persisted",
                            "validation": {"verdict": "Valid", "method": method,
                                           "evidence": "views.py:18"},
                            "measurement": measurement,
                        }]}), encoding="utf-8")
                        errors = io.StringIO()
                        with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                            result = findings.main(["merge", str(target), str(fragment)])
                        self.assertEqual(result, 1)
                        self.assertIn("findings[0].measurement", errors.getvalue())
                        self.assertEqual(target.read_bytes(), original)

    def test_render_rejects_invalid_static_measurement_before_writing_outputs(self):
        doc = complete_doc()
        doc["findings"][0]["measurement"] = {}
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            source = root / "findings.json"
            source.write_text(json.dumps(doc), encoding="utf-8")
            out = root / "out"
            errors = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                result = render.main([str(source), "--out", str(out)])
            self.assertEqual(result, 2)
            self.assertIn("findings[0].measurement.environment", errors.getvalue())
            self.assertFalse((out / "report.md").exists())
            self.assertFalse((out / "dashboard.html").exists())

    def test_valid_measurement_renders_for_static_and_measured_findings(self):
        for method in ("static", "measured"):
            with self.subTest(method=method):
                doc = complete_doc()
                doc["findings"][0]["validation"]["method"] = method
                doc["findings"][0]["measurement"] = dict(MEASUREMENT)
                findings.validate(doc, complete=True)
                self.assertIn(MEASUREMENT["result"], render.render_markdown(doc, "en"))
                self.assertIn(MEASUREMENT["result"], render.render_html(doc, "en"))


class LocationRegressionTests(unittest.TestCase):
    def test_space_paths_round_trip_through_merge_render_and_check(self):
        doc = complete_doc()
        doc["findings"][0]["location"] = "src/Order Service/orders.py:42"
        doc["findings"][1]["location"] = [
            "src/Order Service/export.py:27-35",
            "src/Order Service/cache:adapter.py:5-5",
        ]
        locations = [doc["findings"][0]["location"], *doc["findings"][1]["location"]]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            out = root / "out"
            out.mkdir()
            source = out / "findings.json"
            fragment = root / "fragment.json"
            fragment.write_text(json.dumps(doc), encoding="utf-8")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(findings.main(["merge", str(source), str(fragment)]), 0)
                self.assertEqual(render.main([str(source), "--out", str(out)]), 0)
                self.assertEqual(findings.main(["check", str(out)]), 0)
            self.assertEqual(json.loads(source.read_text(encoding="utf-8")), doc)
            html = (out / "dashboard.html").read_text(encoding="utf-8")
            for location in locations:
                self.assertIn(location, html)

    def test_invalid_locations_are_rejected(self):
        for location in (
            "", "src/orders.py", ":1", "   :1", "src/orders.py:",
            "src/orders.py:0", "src/orders.py:-1", "src/orders.py:1-0",
            "src/orders.py:8-4", "src/orders.py:1-", "src/orders.py:1-x",
            "src/orders.py:1 extra", "src/orders.py:1\n",
            "src/order\rservice.py:1", "src/order\nservice.py:1", [], [None], 1,
        ):
            with self.subTest(location=location):
                with self.assertRaises(findings.SchemaError):
                    findings.validate({"findings": [finding(location=location)]})

    def test_long_positive_line_numbers_round_trip_without_changing_locations(self):
        long_number = "1" * 4301
        zeros = "0" * 4301
        locations = [
            f"src/orders.py:{long_number}",
            f"src/orders.py:{zeros}1",
            f"src/orders.py:{long_number}-{long_number}",
            f"src/orders.py:{long_number}-{'2' * 4301}",
            f"src/orders.py:9-{long_number}",
            f"src/orders.py:{zeros}9-10",
            f"src/orders.py:1-{zeros}1",
        ]
        doc = complete_doc()
        doc["findings"] = [finding(f"P-{i:03d}", location=location)
                           for i, location in enumerate(locations, 1)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / "out"
            out.mkdir()
            source = out / "findings.json"
            fragment = root / "fragment.json"
            fragment.write_text(json.dumps(doc), encoding="utf-8")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(findings.main(["merge", str(source), str(fragment)]), 0)
                self.assertEqual(render.main([str(source), "--out", str(out)]), 0)
                self.assertEqual(findings.main(["check", str(out)]), 0)
            self.assertEqual(json.loads(source.read_text(encoding="utf-8")), doc)

    def test_long_zero_and_descending_line_numbers_are_schema_errors(self):
        zeros = "0" * 4301
        locations = {
            "zero start": f"src/orders.py:{zeros}",
            "zero end": f"src/orders.py:1-{zeros}",
            "equal-length descending": f"src/orders.py:{'2' * 4301}-{'1' * 4301}",
            "shorter end": f"src/orders.py:{'1' * 4302}-{'9' * 4301}",
            "zero-padded descending": f"src/orders.py:{zeros}2-{zeros}1",
        }
        for case, location in locations.items():
            with self.subTest(case=case):
                with self.assertRaises(findings.SchemaError) as error:
                    findings.validate({"findings": [finding(location=location)]})
                self.assertIn("findings[0].location", str(error.exception))


class OptionalFieldRegressionTests(unittest.TestCase):
    def invalid_documents(self):
        fields = (
            ("findings[0].contrast", ("findings", 0), "contrast"),
            ("findings[0].budget", ("findings", 0), "budget"),
            ("findings[0].validation.evidence", ("findings", 0, "validation"), "evidence"),
            ("findings[0].references[0].title", ("findings", 0, "references", 0), "title"),
            ("meta.commit", ("meta",), "commit"),
            ("budgets[0].reason", ("budgets", 0), "reason"),
        )
        for where, path, key in fields:
            for value in (None, False, 0, [], [1], {}):
                doc = complete_doc()
                doc["findings"][0]["title"] = "This update must not be persisted"
                doc["findings"][0]["validation"]["verdict"] = "Likely"
                doc["findings"][0]["references"] = [{"url": "https://example.test/docs"}]
                record = doc
                for part in path:
                    record = record[part]
                record[key] = value
                yield where, value, doc
        for value in (None, False, 0, "", {}):
            doc = complete_doc()
            doc["findings"][0]["references"] = value
            yield "findings[0].references", value, doc

    def test_optional_descriptive_fields_must_have_their_documented_types(self):
        cases = (
            (lambda d: d["meta"].update(method=1), "meta.method"),
            (lambda d: d["findings"][0].update(step=5), "findings[0].step"),
            (lambda d: d["budgets"][0].update(family="NET"), "budgets[0].family"),
            (lambda d: d["budgets"][0].update(family=None), "budgets[0].family"),
        )
        for change, where in cases:
            with self.subTest(where=where):
                doc = complete_doc()
                change(doc)
                with self.assertRaisesRegex(findings.SchemaError, "^" + re.escape(where)):
                    findings.validate(doc)
        doc = complete_doc()
        doc["meta"]["method"] = "Static review"
        doc["budgets"][0]["family"] = "QRY"
        findings.validate(doc, complete=True)

    def test_invalid_optional_fields_preserve_merge_target(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            target = root / "findings.json"
            original = (json.dumps(complete_doc()) + "\n").encode("utf-8")
            fragment = root / "fragment.json"
            for where, value, doc in self.invalid_documents():
                with self.subTest(field=where, value=value):
                    target.write_bytes(original)
                    fragment.write_text(json.dumps(doc), encoding="utf-8")
                    errors = io.StringIO()
                    with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                        result = findings.main(["merge", str(target), str(fragment)])
                    self.assertEqual(result, 1)
                    self.assertIn(where, errors.getvalue())
                    self.assertEqual(target.read_bytes(), original)

    def test_render_and_check_reject_invalid_optional_fields_without_changing_outputs(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            source = out / "findings.json"
            source.write_text(json.dumps(complete_doc()), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(render.main([str(source), "--out", str(out)]), 0)
            original = {path: path.read_bytes() for path in
                        (out / "report.md", out / "dashboard.html")}
            for where, value, doc in self.invalid_documents():
                with self.subTest(field=where, value=value):
                    for path, content in original.items():
                        path.write_bytes(content)
                    source.write_text(json.dumps(doc), encoding="utf-8")
                    errors = io.StringIO()
                    with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                        result = render.main([str(source), "--out", str(out)])
                    self.assertEqual(result, 2)
                    self.assertIn(where, errors.getvalue())
                    self.assertTrue(any(where in problem for problem in
                                        findings.contract_problems(out)))
                    for path, content in original.items():
                        self.assertEqual(path.read_bytes(), content)

    def test_optional_strings_may_be_empty_and_reference_title_may_be_omitted(self):
        doc = complete_doc()
        doc["meta"]["commit"] = ""
        doc["budgets"][0]["reason"] = ""
        doc["findings"][0].update({
            "contrast": "", "budget": "",
            "validation": {"verdict": "Likely", "method": "static", "evidence": ""},
            "references": [
                {"title": "", "url": "https://example.test/empty-title"},
                {"url": "https://example.test/fallback"},
            ],
        })
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            out = root / "out"
            out.mkdir()
            source = out / "findings.json"
            fragment = root / "fragment.json"
            fragment.write_text(json.dumps(doc), encoding="utf-8")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(findings.main(["merge", str(source), str(fragment)]), 0)
                self.assertEqual(render.main([str(source), "--out", str(out)]), 0)
                self.assertEqual(findings.main(["check", str(out)]), 0)
            self.assertEqual(json.loads(source.read_text(encoding="utf-8")), doc)
            self.assertIn("[https&#58;//example.test/fallback](<https://example.test/fallback>)",
                          (out / "report.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()


class ReviewRoundEightTests(unittest.TestCase):
    def test_an_unprintable_path_does_not_turn_success_into_a_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fragment = root / "fragment.json"
            fragment.write_text('{"meta": {"project": "p"}}', encoding="utf-8")
            target = root / "所見.json"
            result = run_cli("findings.py", "merge", target, fragment,
                             env_updates={"PYTHONIOENCODING": "cp1252"})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertIn("merged 1 fragment", result.stdout)
            self.assertTrue(target.is_file())

    def test_merge_creates_the_output_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fragment = root / "fragment.json"
            fragment.write_text('{"meta": {"project": "p"}}', encoding="utf-8")
            target = root / "new" / "out" / "findings.json"
            code, _, errors = run_main(findings.main, "merge", target, fragment)
            self.assertEqual(code, 0, errors)
            self.assertTrue(target.is_file())

    def test_budget_and_perspective_errors_name_the_record(self):
        doc = {"budgets": [{"id": "B-01", "statement": "s", "source": "x", "status": "holds"},
                           {"id": "B-02", "statement": "s", "source": "x", "status": "hold"}],
               "perspectives": []}
        with self.assertRaisesRegex(findings.SchemaError, r"budgets\[1\]\.status.*\(budget 'B-02'\)"):
            findings.validate(doc)
        doc = {"perspectives": [{"name": "Memory", "status": "done", "note": "n"}]}
        with self.assertRaisesRegex(findings.SchemaError, r"\(perspective 'Memory'\)"):
            findings.validate(doc)

    def test_a_location_path_holds_no_line_break_of_any_kind(self):
        for brk in ("\x0b", "\x0c", "\x1c", "\x85", " ", " "):
            with self.subTest(brk=repr(brk)), self.assertRaises(findings.SchemaError):
                findings.validate_finding(finding(location=[f"src/a.py{brk}x:3"]), "f")
        findings.validate_finding(finding(location=["src/a b.py:3"]), "f")
