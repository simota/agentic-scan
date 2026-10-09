"""Regression checks for finding measurements and source locations."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_performance_scan import complete_doc, finding, findings, render


MEASUREMENT = {
    "environment": "local synthetic data",
    "command": "python3 tests/query_count.py",
    "result": "query count is 3 for both 1 and 50 orders",
}


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


if __name__ == "__main__":
    unittest.main()
