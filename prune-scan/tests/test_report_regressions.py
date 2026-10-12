"""Regression tests for report input boundaries, publication and contract checks."""

import contextlib
import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import contract_check  # noqa: E402
import render  # noqa: E402

SAMPLE = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
UNITS = json.loads((ROOT / "examples" / "units.sample.json").read_text(encoding="utf-8"))


class SnippetRegressionTests(unittest.TestCase):
    def test_sensitive_symlink_targets_are_never_excerpted(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            for index, name in enumerate((".env", "secrets.json", "id_rsa", "id_ecdsa", "id_ed25519",
                                          "id_ecdsa_sk", "id_ed25519_sk", "key.pem")):
                with self.subTest(name=name):
                    (repo / name).write_text("private material without a secret assignment\n", encoding="utf-8")
                    alias = repo / f"module{index}.py"
                    alias.symlink_to(name)
                    self.assertIsNone(render.snippet(repo, f"{name}:1"))
                    self.assertIsNone(render.snippet(repo, f"{alias.name}:1"))

    def test_symlink_loop_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "loop.py").symlink_to("loop.py")
            self.assertIsNone(render.snippet(repo, "loop.py:1"))

    def test_ordinary_internal_symlink_can_still_be_excerpted(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "source.py").write_text("print('public source')\n", encoding="utf-8")
            (repo / "alias.py").symlink_to("source.py")
            self.assertEqual(render.snippet(repo, "alias.py:1")["lines"], ["print('public source')"])

    def test_invalid_line_ranges_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "source.py").write_text("first\nsecond\nthird\n", encoding="utf-8")
            for location in ("source.py:0", "source.py:3-1", "source.py:1\n", "source.py:" + "9" * 5000):
                with self.subTest(location=location[:60]):
                    self.assertIsNone(render.snippet(repo, location))

    def test_long_ranges_produce_short_excerpts(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "source.py").write_text("visible line\n" * 1000, encoding="utf-8")
            excerpt = render.snippet(repo, "source.py:1-1000")
            self.assertLessEqual(len(excerpt["lines"]), 80)
            self.assertEqual(excerpt["hit"], [1, len(excerpt["lines"])])

    def test_binary_source_is_not_excerpted(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "data.bin").write_bytes(b"public text\n\0private binary bytes\n")
            self.assertIsNone(render.snippet(repo, "data.bin:1"))


class ReportFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name)
        self.data = copy.deepcopy(SAMPLE)
        self.data["limitations"].append("report.pdf not produced: no PDF engine in this test")
        self.write_record()
        (self.out / "units.json").write_text(json.dumps(UNITS), encoding="utf-8")
        (self.out / "inventory.json").write_text('{"tool": "inventory.py"}', encoding="utf-8")

    def write_record(self):
        (self.out / "findings.json").write_text(json.dumps(self.data), encoding="utf-8")

    def render(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = render.main([str(self.out / "findings.json"), "--out", str(self.out), *args])
        return code, stdout.getvalue(), stderr.getvalue()

    def render_html(self):
        code, _, error = self.render("--no-pdf")
        self.assertEqual(code, 0, error)


class RenderPublicationTests(ReportFixture):
    def test_invalid_json_is_rejected_before_any_output_is_changed(self):
        source = json.dumps(self.data)
        invalid = (source.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1', 1),
                   source[:-1] + ', "extra": NaN}', source[:-1] + ', "extra": "\\ud800"}')
        for content in invalid:
            with self.subTest(content=content[-60:]):
                (self.out / "findings.json").write_text(content, encoding="utf-8")
                code, _, error = self.render("--no-pdf")
                self.assertEqual(code, 2, error)
                self.assertFalse((self.out / "dashboard.html").exists())
                self.assertFalse((self.out / "report.html").exists())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO checks require POSIX")
    def test_fifo_json_inputs_do_not_block_render(self):
        for name in ("findings.json", "units.json"):
            with self.subTest(name=name):
                path = self.out / name
                before = path.read_bytes()
                path.unlink()
                os.mkfifo(path)
                try:
                    result = subprocess.run([sys.executable, str(SCRIPTS / "render.py"),
                                             str(self.out / "findings.json"), "--out", str(self.out), "--no-pdf"],
                                            capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                finally:
                    path.unlink()
                    path.write_bytes(before)

    def test_page_text_cannot_inject_markup_or_close_dashboard_script(self):
        payload = '</script><script>alert("unsafe")</script><img src=x onerror=alert(1)>'
        self.data["summary"] = payload
        self.data["findings"][0]["title"] = payload
        self.write_record()
        self.render_html()
        for name in ("dashboard.html", "report.html"):
            with self.subTest(name=name):
                page = (self.out / name).read_text(encoding="utf-8")
                self.assertNotIn(payload, page)
                self.assertNotIn('<img src=x onerror=alert(1)>', page)

    def test_failed_page_staging_preserves_existing_outputs(self):
        originals = {name: f"previous {name}" for name in render.OUTPUTS}
        for name, content in originals.items():
            (self.out / name).write_text(content, encoding="utf-8")
        write_output = render.output.write_output

        def fail_second_page(path, text):
            if Path(path).name == "report.html":
                raise OSError("simulated disk failure")
            return write_output(path, text)

        with mock.patch.object(render.output, "write_output", side_effect=fail_second_page):
            code, _, error = self.render("--no-pdf")
        self.assertEqual(code, 2, error)
        for name, content in originals.items():
            self.assertEqual((self.out / name).read_text(encoding="utf-8"), content)
        self.assertFalse(any(path.name.startswith(".scan-report-output-") for path in self.out.iterdir()))

    def test_failed_page_installation_restores_existing_outputs(self):
        originals = {name: f"previous {name}" for name in render.OUTPUTS}
        for name, content in originals.items():
            (self.out / name).write_text(content, encoding="utf-8")
        replace = os.replace

        def fail_install(source, target):
            if Path(source).parent.name == "new" and Path(target) == self.out / "report.html":
                raise OSError("simulated installation failure")
            return replace(source, target)

        with mock.patch.object(render.output.os, "replace", side_effect=fail_install):
            code, _, error = self.render("--no-pdf")
        self.assertEqual(code, 2, error)
        for name, content in originals.items():
            self.assertEqual((self.out / name).read_text(encoding="utf-8"), content)
        self.assertFalse(any(path.name.startswith(".scan-report-output-") for path in self.out.iterdir()))

    def test_render_refuses_to_overwrite_its_source(self):
        source = self.out / "report.html"
        source.write_text(json.dumps(self.data), encoding="utf-8")
        before = source.read_bytes()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = render.main([str(source), "--out", str(self.out), "--no-pdf"])
        self.assertEqual(code, 2)
        self.assertEqual(source.read_bytes(), before)
        self.assertFalse((self.out / "dashboard.html").exists())

    def test_render_refuses_to_overwrite_symlinked_units_source(self):
        inputs = self.out / "input"
        inputs.mkdir()
        source = inputs / "findings.json"
        source.write_text(json.dumps(self.data), encoding="utf-8")
        source_before = source.read_bytes()
        units = inputs / "units.json"
        for target_name in render.OUTPUTS:
            with self.subTest(target_name=target_name):
                for name in render.OUTPUTS:
                    (self.out / name).write_text(f"previous {name}", encoding="utf-8")
                (self.out / target_name).write_text(json.dumps(UNITS), encoding="utf-8")
                units.symlink_to(self.out / target_name)
                originals = {name: (self.out / name).read_bytes() for name in render.OUTPUTS}
                try:
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        code = render.main([str(source), "--out", str(self.out), "--no-pdf"])
                    self.assertEqual(code, 2)
                    self.assertEqual(source.read_bytes(), source_before)
                    self.assertTrue(units.is_symlink())
                    self.assertEqual(units.read_bytes(), originals[target_name])
                    for name, content in originals.items():
                        self.assertEqual((self.out / name).read_bytes(), content)
                finally:
                    units.unlink()

    def test_noncolliding_record_symlinks_can_still_be_rendered(self):
        inputs = self.out / "input"
        inputs.mkdir()
        originals = {name: (self.out / name).read_bytes() for name in ("findings.json", "units.json")}
        for name in originals:
            (inputs / name).symlink_to(self.out / name)
        stderr = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
            code = render.main([str(inputs / "findings.json"), "--out", str(self.out), "--no-pdf"])
        self.assertEqual(code, 0, stderr.getvalue())
        for name, content in originals.items():
            self.assertTrue((inputs / name).is_symlink())
            self.assertEqual((self.out / name).read_bytes(), content)
        for name in ("dashboard.html", "report.html"):
            self.assertIn(render.UNITS_STAMP, (self.out / name).read_text(encoding="utf-8"))

    def test_pdf_error_diagnostics_mask_values_as_well_as_names(self):
        def failing_engine(html_path, pdf_path, failures, timeout, redact):
            failures.append(("test", "failed", redact("api_key=SHOULD_NOT_APPEAR")))
            return None

        with mock.patch.object(render.pdf, "to_pdf", side_effect=failing_engine):
            code, _, error = self.render()
        self.assertEqual(code, 3, error)
        self.assertNotIn("SHOULD_NOT_APPEAR", error)
        self.assertIn("masked", error)

    def test_long_secret_is_redacted_before_engine_tail_is_truncated(self):
        def failing_engine(html_path, pdf_path, failures, timeout, redact):
            detail = render.pdf._tail("token=" + "x" * 350 + "SENSITIVE_FRAGMENT", redact)
            failures.append(("test", "failed", detail))
            return None

        with mock.patch.object(render.pdf, "to_pdf", side_effect=failing_engine):
            code, _, error = self.render()
        self.assertEqual(code, 3, error)
        self.assertNotIn("SENSITIVE_FRAGMENT", error)
        self.assertIn("masked", error)

    def test_pdf_argument_errors_are_reported_without_a_traceback(self):
        with mock.patch.object(render.pdf, "to_pdf", side_effect=ValueError("invalid PDF output path")):
            code, _, error = self.render()
        self.assertEqual(code, 2, error)
        self.assertIn("invalid PDF output path", error)
        self.assertFalse((self.out / "report.pdf").exists())

    def test_pdf_io_failure_is_reported_and_partial_output_removed(self):
        def failing_engine(html_path, pdf_path, *args, **kwargs):
            Path(pdf_path).write_bytes(b"partial")
            raise OSError("simulated PDF write failure")

        with mock.patch.object(render.pdf, "to_pdf", side_effect=failing_engine):
            code, _, error = self.render()
        self.assertEqual(code, 2, error)
        self.assertIn("simulated PDF write failure", error)
        self.assertFalse((self.out / "report.pdf").exists())

    def test_successful_engine_must_produce_a_complete_pdf(self):
        for content in (b"", b"not a PDF", b"%PDF-1.7\ntruncated content"):
            with self.subTest(content=content):
                def incomplete_engine(html_path, pdf_path, *args, **kwargs):
                    Path(pdf_path).write_bytes(content)
                    return "test"

                with mock.patch.object(render.pdf, "to_pdf", side_effect=incomplete_engine):
                    code, _, error = self.render()
                self.assertEqual(code, 3, error)
                self.assertFalse((self.out / "report.pdf").exists())


class ContractRegressionTests(ReportFixture):
    def setUp(self):
        super().setUp()
        self.render_html()
        self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])

    def test_non_regular_contract_files_are_reported_without_being_read(self):
        for name in contract_check.REQUIRED:
            with self.subTest(name=name):
                path = self.out / name
                before = path.read_bytes()
                path.unlink()
                path.mkdir()
                try:
                    errors = list(contract_check.problems(self.out, no_pdf=True))
                    self.assertTrue(any(f"{name}: must be a regular file" in error for error in errors), errors)
                finally:
                    path.rmdir()
                    path.write_bytes(before)

    def test_symlink_contract_files_are_not_read(self):
        outside = self.out / "outside.txt"
        outside.write_text("not valid JSON or HTML", encoding="utf-8")
        for name in contract_check.REQUIRED:
            with self.subTest(name=name):
                path = self.out / name
                before = path.read_bytes()
                path.unlink()
                path.symlink_to(outside)
                try:
                    errors = list(contract_check.problems(self.out, no_pdf=True, allow=(outside.name,)))
                    self.assertEqual(errors, [f"{name}: must be a regular file"])
                finally:
                    path.unlink()
                    path.write_bytes(before)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO checks require POSIX")
    def test_fifo_page_does_not_block_contract_checker(self):
        path = self.out / "report.html"
        path.unlink()
        os.mkfifo(path)
        result = subprocess.run([sys.executable, str(SCRIPTS / "contract_check.py"), str(self.out), "--no-pdf"],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("report.html: must be a regular file", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_non_object_inventory_is_a_contract_problem(self):
        for value in ([], None, True, 42, "inventory"):
            with self.subTest(value=value):
                (self.out / "inventory.json").write_text(json.dumps(value), encoding="utf-8")
                errors = list(contract_check.problems(self.out, no_pdf=True))
                self.assertTrue(any("inventory.json:" in error for error in errors), errors)

    def test_source_read_error_is_a_contract_problem(self):
        with mock.patch.object(contract_check, "read_json_source", side_effect=render.RecordError("simulated denied read")):
            errors = list(contract_check.problems(self.out, no_pdf=True))
        self.assertTrue(any("simulated denied read" in error for error in errors), errors)

    def test_inventory_rejects_ambiguous_or_nonstandard_json(self):
        for content in ('{"tool": "other", "tool": "inventory.py"}', '{"tool": "inventory.py", "rows": NaN}'):
            with self.subTest(content=content):
                (self.out / "inventory.json").write_text(content, encoding="utf-8")
                errors = list(contract_check.problems(self.out, no_pdf=True))
                self.assertTrue(any("inventory.json: not valid JSON" in error for error in errors), errors)

    def test_japanese_decision_references_need_no_spaces(self):
        self.data["decisions"] = ["P-021を残すか削除するか、オーナーに確認する。"]
        self.write_record()
        self.render_html()
        self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])

    def test_similar_identifiers_do_not_satisfy_decision_references(self):
        for identifier in ("XP-021", "P-0210", "P-021_suffix"):
            with self.subTest(identifier=identifier):
                self.data["decisions"] = [f"Review {identifier} with the owner."]
                self.write_record()
                self.render_html()
                errors = list(contract_check.problems(self.out, no_pdf=True))
                self.assertTrue(any("decisions: P-021" in error for error in errors), errors)

    def test_units_changes_make_both_pages_stale(self):
        units = copy.deepcopy(UNITS)
        units["units"][0]["name"] = "Updated review unit"
        (self.out / "units.json").write_text(json.dumps(units), encoding="utf-8")
        errors = list(contract_check.problems(self.out, no_pdf=True))
        for name in ("dashboard.html", "report.html"):
            self.assertTrue(any(name in error and "stale" in error for error in errors), errors)
        self.render_html()
        self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])

    def test_no_pdf_requires_an_actual_reason(self):
        for limitation in ("report.pdf not produced", "report.pdf not produced:   ",
                           "report.pdf not producedish: this is not the required limitation"):
            with self.subTest(limitation=limitation):
                self.data["limitations"] = [limitation]
                self.write_record()
                self.render_html()
                errors = list(contract_check.problems(self.out, no_pdf=True))
                self.assertTrue(any("--no-pdf needs" in error for error in errors), errors)

    def test_family_names_without_results_cannot_satisfy_coverage(self):
        self.data["perspectives"] = [{"name": family} for family in contract_check.FAMILIES]
        self.write_record()
        self.render_html()
        errors = list(contract_check.problems(self.out, no_pdf=True))
        self.assertTrue(any("perspectives: no result for" in error for error in errors), errors)
        for perspective in self.data["perspectives"]:
            perspective["result"] = "not checked"
        self.write_record()
        self.render_html()
        self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])

    def test_invalid_pdf_cannot_satisfy_contract(self):
        self.data["limitations"] = []
        self.write_record()
        self.render_html()
        for content in (b"", b"not a PDF", b"%PDF-1.7\npartial content"):
            with self.subTest(content=content):
                (self.out / "report.pdf").write_bytes(content)
                errors = list(contract_check.problems(self.out))
                self.assertTrue(any("report.pdf:" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
