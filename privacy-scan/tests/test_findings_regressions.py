"""Regression checks for public prose validation and optional analysis records."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_privacy_scan import complete_doc, finding, findings, render


SAFE_ANALYSIS = {
    "tool": "source-scan", "command": "source-scan api/app.py",
    "result": "The email field reaches error tracking at api/app.py:22",
}
# Synthetic, non-deliverable address; intentionally outside the allowed examples.
SYNTHETIC_EMAIL = "synthetic-user@privacy-scan.localhost"
SYNTHETIC_NUMBER = "0000 0000 0000"


def doc_with_optional_prose():
    doc = complete_doc()
    doc["findings"][0]["analysis"] = dict(SAFE_ANALYSIS)
    doc["findings"][0]["references"] = [
        {"title": "Source documentation", "url": "https://example.com/privacy"},
    ]
    doc["decisions"] = ["Confirm vendor settings"]
    doc["next_steps"] = ["Disable request body capture"]
    return doc


def set_value(doc, path, value):
    target = doc
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value


class PersonalValueRegressionTests(unittest.TestCase):
    def test_all_public_prose_rejects_personal_values(self):
        paths = [
            *(('meta', key) for key in ("project", "scope", "date", "assessor", "method", "commit")),
            *(("findings", 0, key) for key in (
                *findings.TEXT_FIELDS, "contrast", "commitment")),
            ("findings", 0, "validation", "evidence"),
            *(("findings", 0, "analysis", key) for key in ("tool", "command", "result")),
            *(("findings", 0, "references", 0, key) for key in ("title", "url")),
            *(("commitments", 0, key) for key in ("statement", "source", "reason")),
            ("perspectives", 0, "note"),
            *((key, 0) for key in findings.LISTS),
        ]
        for path in paths:
            for kind, value in (("email", SYNTHETIC_EMAIL), ("number", SYNTHETIC_NUMBER)):
                with self.subTest(field=path, kind=kind):
                    doc = doc_with_optional_prose()
                    set_value(doc, path, value)
                    with self.assertRaises(findings.SchemaError):
                        findings.validate(doc, complete=True)

    def test_public_locations_reject_personal_values(self):
        for path in (
            "fixtures/" + SYNTHETIC_EMAIL + ".json:12",
            "fixtures/000000000000.json:12",
        ):
            with self.subTest(path=path):
                with self.assertRaises(findings.SchemaError):
                    findings.validate({"findings": [finding(location=[path])]})

    def test_punctuation_and_longer_numbers_are_refused(self):
        values = (
            "account:000000000000",
            "account=000000000000",
            "card 0000000000000000.",
            "account .000000000000.",
            "account-000000000000-",
            "account 00000000000000000000",
            "account " + "0" * 64,
            "account 0000-0000-0000",
        )
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(findings.SchemaError):
                    findings.validate({"findings": [finding(impact=value)]})

    def test_numbers_adjacent_to_text_are_refused(self):
        values = (
            "アカウント番号は000000000000です",
            "000000000000を送信する",
            "会員0000-0000-0000",
            "member000000000000",
            "000000000000members",
        )
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(findings.SchemaError):
                    findings.validate({"findings": [finding(impact=value)]})

    def test_number_threshold_remains_twelve_digits(self):
        for digits in ("00000000000", "000-0000-0000", "000 0000 0000"):
            with self.subTest(digits=digits, expected="allowed"):
                findings.validate({"findings": [finding(impact="番号" + digits + "です")]})
        for digits in ("000000000000", "0000-0000-0000", "0000 0000 0000"):
            with self.subTest(digits=digits, expected="refused"):
                with self.assertRaises(findings.SchemaError):
                    findings.validate({"findings": [finding(impact="番号" + digits + "です")]})

    def test_technical_values_and_reserved_examples_still_render(self):
        domains = ("example.com", "example.org", "example.net", "sub.example.com",
                   "host.example", "host.test", "host.invalid")
        for domain in domains:
            with self.subTest(domain=domain):
                findings.validate({"findings": [finding(impact="user@" + domain)]})
        doc = doc_with_optional_prose()
        doc["meta"]["commit"] = "0" * 40
        doc["meta"]["date"] = "2026-10-09"
        doc["findings"][0]["location"] = ["api/app.py:100000-200000"]
        doc["findings"][0]["analysis"]["result"] = (
            "user@example.com is a placeholder; inspect api/app.py:22-24")
        findings.validate(doc, complete=True)
        self.assertIn("api/app.py:100000-200000", render.render_markdown(doc, "en"))
        self.assertIn("0" * 40, render.render_html(doc, "en"))

    def test_refused_updates_preserve_the_existing_record(self):
        fragments = (
            {"checked_ok": [SYNTHETIC_EMAIL]},
            {"findings": [{"id": "PV-001", "impact": "account:000000000000"}]},
            {"findings": [{"id": "PV-001", "analysis": {}}]},
        )
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            target, fragment = out / "findings.json", out / "fragment.json"
            original = json.dumps(complete_doc(), indent=2) + "\n"
            for value in fragments:
                with self.subTest(fragment=value):
                    target.write_text(original, encoding="utf-8")
                    fragment.write_text(json.dumps(value), encoding="utf-8")
                    stderr = io.StringIO()
                    with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                        code = findings.main(["merge", str(target), str(fragment)])
                    self.assertEqual(code, 1)
                    self.assertEqual(target.read_text(encoding="utf-8"), original)
                    self.assertNotIn(SYNTHETIC_EMAIL, stderr.getvalue())
                    self.assertNotIn("000000000000", stderr.getvalue())

    def test_unsafe_analysis_is_refused_by_render_and_check(self):
        doc = doc_with_optional_prose()
        doc["findings"][0]["analysis"]["result"] = SYNTHETIC_EMAIL
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            record = out / "findings.json"
            record.write_text(json.dumps(doc), encoding="utf-8")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(render.main([str(record), "--out", str(out)]), 2)
            self.assertFalse((out / "report.md").exists())
            self.assertFalse((out / "dashboard.html").exists())
            for name in ("report.md", "dashboard.html"):
                (out / name).write_text("existing output", encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                self.assertEqual(findings.main(["check", str(out)]), 1)
            self.assertIn("findings[0].analysis.result", stderr.getvalue())
            self.assertNotIn(SYNTHETIC_EMAIL, stderr.getvalue())


class SchemaDiagnosticRegressionTests(unittest.TestCase):
    def test_rejected_values_stay_out_of_schema_errors(self):
        paths = (
            ("meta", "lang"),
            *(("findings", 0, key) for key in (
                "id", "severity", "confidence", "category", "status", "location")),
            ("findings", 0, "validation", "verdict"),
            ("findings", 0, "validation", "method"),
            ("commitments", 0, "id"),
            ("commitments", 0, "status"),
            ("perspectives", 0, "name"),
            ("perspectives", 0, "status"),
        )
        for path in paths:
            for value in (SYNTHETIC_EMAIL, SYNTHETIC_NUMBER):
                with self.subTest(path=path, value=value):
                    doc = complete_doc()
                    set_value(doc, path, value)
                    with self.assertRaises(findings.SchemaError) as raised:
                        findings.validate(doc, complete=True)
                    self.assertNotIn(value, str(raised.exception))
                    self.assertIn(str(path[-1]), str(raised.exception))

    def test_cli_rejections_hide_values_and_unknown_key_names(self):
        invalid = []
        for field in ("location", "severity"):
            doc = complete_doc()
            doc["findings"][0][field] = SYNTHETIC_EMAIL
            invalid.append(doc)
        for key in (SYNTHETIC_EMAIL, SYNTHETIC_NUMBER):
            doc = complete_doc()
            doc[key] = "unexpected field"
            invalid.append(doc)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / "output"
            out.mkdir()
            target, fragment = out / "findings.json", root / "fragment.json"
            original = json.dumps(complete_doc())
            for name in ("report.md", "dashboard.html"):
                (out / name).write_text("existing output", encoding="utf-8")
            for index, doc in enumerate(invalid):
                with self.subTest(case=index):
                    target.write_text(original, encoding="utf-8")
                    fragment.write_text(json.dumps(doc), encoding="utf-8")
                    stderr = io.StringIO()
                    with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                        self.assertEqual(findings.main([
                            "merge", str(target), str(fragment)]), 1)
                    self.assertEqual(target.read_text(encoding="utf-8"), original)
                    target.write_text(json.dumps(doc), encoding="utf-8")
                    with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                        self.assertEqual(render.main([
                            str(target), "--out", str(out)]), 2)
                        self.assertEqual(findings.main(["check", str(out)]), 1)
                    for value in (SYNTHETIC_EMAIL, SYNTHETIC_NUMBER):
                        self.assertNotIn(value, stderr.getvalue())
                    self.assertNotIn("Traceback", stderr.getvalue())
                    for name in ("report.md", "dashboard.html"):
                        self.assertEqual((out / name).read_text(encoding="utf-8"),
                                         "existing output")


class OptionalShapeRegressionTests(unittest.TestCase):
    def test_present_optional_prose_must_be_strings(self):
        paths = (
            *(("meta", key) for key in (
                "project", "scope", "date", "assessor", "method", "commit")),
            *(("findings", 0, key) for key in ("contrast", "commitment", "step")),
            ("findings", 0, "references", 0, "title"),
            ("commitments", 0, "reason"),
            ("commitments", 0, "family"),
        )
        for path in paths:
            for value in (None, False, 42, {}, [], [1]):
                with self.subTest(path=path, value=value):
                    doc = doc_with_optional_prose()
                    set_value(doc, path, value)
                    with self.assertRaises(findings.SchemaError):
                        findings.validate(doc)

    def test_evidence_type_is_checked_for_every_verdict(self):
        for verdict in findings.VERDICTS:
            for value in (None, 42, {}, [1]):
                with self.subTest(verdict=verdict, evidence=value):
                    doc = complete_doc()
                    doc["findings"][0]["validation"].update(
                        verdict=verdict, evidence=value)
                    with self.assertRaises(findings.SchemaError):
                        findings.validate(doc, complete=True)

    def test_record_collections_must_be_lists(self):
        paths = (("findings",), ("commitments",), ("perspectives",),
                 ("findings", 0, "references"))
        for path in paths:
            for value in (None, {}, "", 42):
                with self.subTest(path=path, value=value):
                    doc = complete_doc()
                    set_value(doc, path, value)
                    with self.assertRaises(findings.SchemaError):
                        findings.validate(doc, complete=True)

    def test_inferred_flag_requires_a_boolean_when_present(self):
        for value in (None, "true", 1, [], {}):
            with self.subTest(value=value):
                doc = complete_doc()
                doc["commitments"][0]["inferred"] = value
                with self.assertRaises(findings.SchemaError):
                    findings.validate(doc, complete=True)

    def test_malformed_merge_keys_are_refused_without_changing_record(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "findings.json"
            fragment = Path(directory) / "fragment.json"
            original = json.dumps(complete_doc())
            for collection, key in (("findings", "id"), ("commitments", "id"),
                                    ("perspectives", "name")):
                for value in (None, [], {}):
                    with self.subTest(collection=collection, value=value):
                        target.write_text(original, encoding="utf-8")
                        fragment.write_text(json.dumps({collection: [{key: value}]}),
                                            encoding="utf-8")
                        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                            self.assertEqual(findings.main([
                                "merge", str(target), str(fragment)]), 1)
                        self.assertEqual(target.read_text(encoding="utf-8"), original)

    def test_malformed_existing_containers_are_refused_before_merging(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "findings.json"
            fragment = Path(directory) / "fragment.json"
            for key in ("meta", "findings", "commitments", "perspectives", "checked_ok"):
                with self.subTest(key=key):
                    doc = complete_doc()
                    doc[key] = None
                    original = json.dumps(doc)
                    target.write_text(original, encoding="utf-8")
                    fragment.write_text(json.dumps({key: {} if key == "meta" else []}),
                                        encoding="utf-8")
                    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        self.assertEqual(findings.main([
                            "merge", str(target), str(fragment)]), 1)
                    self.assertEqual(target.read_text(encoding="utf-8"), original)

    def test_malformed_evidence_cannot_replace_existing_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / "output"
            out.mkdir()
            target, fragment = out / "findings.json", root / "fragment.json"
            doc = complete_doc()
            target.write_text(json.dumps(doc), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(render.main([str(target), "--out", str(out)]), 0)
                self.assertEqual(findings.main(["check", str(out)]), 0)
            originals = {name: (out / name).read_bytes() for name in findings.OUTPUTS}
            validation = {"verdict": "Likely", "method": "static", "evidence": [1]}
            fragment.write_text(json.dumps({"findings": [
                {"id": "PV-001", "validation": validation}]}), encoding="utf-8")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(findings.main(["merge", str(target), str(fragment)]), 1)
            self.assertEqual({name: (out / name).read_bytes() for name in originals}, originals)
            doc["findings"][0]["validation"] = validation
            target.write_text(json.dumps(doc), encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                self.assertEqual(render.main([str(target), "--out", str(out)]), 2)
                self.assertEqual(findings.main(["check", str(out)]), 1)
            self.assertIn("findings[0].validation.evidence", stderr.getvalue())
            for name in ("report.md", "dashboard.html"):
                self.assertEqual((out / name).read_bytes(), originals[name])

    def test_optional_strings_and_partial_updates_remain_supported(self):
        doc = {}
        findings.merge(doc, {"meta": {"project": "demo"}}, "first fragment")
        findings.validate(doc)
        findings.merge(doc, {"findings": [finding()]}, "second fragment")
        findings.merge(doc, {"findings": [{"id": "PV-001", "contrast": ""}]}, "update")
        findings.validate(doc)
        doc = doc_with_optional_prose()
        doc["meta"].update(commit="", method="")
        doc["findings"][0].update(contrast="", commitment="", step="")
        doc["findings"][0]["references"] = [{"url": "https://example.com/privacy"}]
        doc["commitments"][0].update(reason="", family="", inferred=False)
        for verdict in ("Likely", "Unverified", "Unlikely"):
            doc["findings"][0]["validation"] = {"verdict": verdict, "method": "static"}
            findings.validate(doc, complete=True)
            doc["findings"][0]["validation"]["evidence"] = ""
            findings.validate(doc, complete=True)
            render.render_markdown(doc, "en")
            render.render_html(doc, "en")


class AnalysisShapeRegressionTests(unittest.TestCase):
    def test_present_analysis_is_validated_for_both_methods(self):
        malformed = (None, [], "source-scan", {}, {"tool": "source-scan"},
                     dict(SAFE_ANALYSIS, result=""), dict(SAFE_ANALYSIS, command=42))
        for method in ("static", "analysed"):
            for analysis in malformed:
                with self.subTest(method=method, analysis=analysis):
                    record = finding(analysis=analysis)
                    record["validation"]["method"] = method
                    with self.assertRaises(findings.SchemaError):
                        findings.validate({"findings": [record]})

    def test_static_may_omit_analysis_but_analysed_requires_it(self):
        findings.validate({"findings": [finding()]})
        record = finding()
        record["validation"]["method"] = "analysed"
        with self.assertRaises(findings.SchemaError):
            findings.validate({"findings": [record]})

    def test_valid_analysis_still_renders_for_both_methods(self):
        for method in ("static", "analysed"):
            with self.subTest(method=method):
                doc = doc_with_optional_prose()
                doc["findings"][0]["validation"]["method"] = method
                findings.validate(doc, complete=True)
                self.assertIn(SAFE_ANALYSIS["result"], render.render_markdown(doc, "en"))
                self.assertIn(SAFE_ANALYSIS["result"], render.render_html(doc, "en"))

    def test_malformed_static_analysis_reports_a_schema_error(self):
        doc = complete_doc()
        doc["findings"][0]["analysis"] = {}
        with tempfile.TemporaryDirectory() as d:
            record, out = Path(d) / "findings.json", Path(d) / "output"
            record.write_text(json.dumps(doc), encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                self.assertEqual(render.main([str(record), "--out", str(out)]), 2)
            self.assertIn("findings[0].analysis.tool", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
