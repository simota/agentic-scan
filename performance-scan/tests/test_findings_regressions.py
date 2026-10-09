"""Regression checks for finding fields, measurements and source locations."""
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_performance_scan import SKILL, complete_doc, finding, findings, render


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
                result = subprocess.run(
                    [sys.executable, str(SKILL / "scripts" / "render.py"),
                     str(source), "--out", str(out)],
                    capture_output=True, text=True, check=False)
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
