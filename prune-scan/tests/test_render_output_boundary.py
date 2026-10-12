"""PR regressions for keeping rendered output away from its selected inputs."""

import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from test_findings_regressions import record, units_record
import render
import safe_output


@unittest.skipUnless(render.NOFOLLOW_DIR_FD, "requires descriptor-relative directory opens")
class RenderOutputBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.out = self.base / "workspace" / "out"
        self.out.mkdir(parents=True)
        self.sources = self.base / "outside" / "out"
        self.sources.mkdir(parents=True)

    def invoke(self, source, *, no_pdf=True):
        stdout, stderr = io.StringIO(), io.StringIO()
        args = [str(source), "--out", str(self.out)]
        if no_pdf:
            args.append("--no-pdf")
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = render.main(args)
        return code, stderr.getvalue()

    @contextlib.contextmanager
    def swapped_output(self, *, ancestor=False, symlink=True):
        selected = self.out.parent if ancestor else self.out
        replacement = self.sources.parent if ancestor else self.sources
        saved = self.base / "saved"
        selected.rename(saved)
        if symlink:
            selected.symlink_to(replacement, target_is_directory=True)
        else:
            replacement.rename(selected)
        try:
            yield
        finally:
            if symlink:
                selected.unlink()
            else:
                selected.rename(replacement)
            saved.rename(selected)

    def test_batch_publication_cannot_overwrite_a_source_after_directory_replacement(self):
        source = self.sources / "report.html"
        original = json.dumps(record()).encode()
        source.write_bytes(original)
        write_outputs = render.output.write_outputs
        for ancestor in (False, True):
            for symlink in (False, True):
                with self.subTest(ancestor=ancestor, symlink=symlink):
                    source.write_bytes(original)
                    swaps = contextlib.ExitStack()
                    swapped = False

                    def replace_before_staging(*args, **kwargs):
                        nonlocal swapped
                        swaps.enter_context(self.swapped_output(ancestor=ancestor, symlink=symlink))
                        swapped = True
                        return write_outputs(*args, **kwargs)

                    try:
                        with mock.patch.object(render.output, "write_outputs", side_effect=replace_before_staging):
                            code, error = self.invoke(source)
                    finally:
                        swaps.close()
                    self.assertTrue(swapped)
                    self.assertEqual(source.read_bytes(), original, "the selected findings source was overwritten")
                    self.assertEqual(code, 2, error)

    def check_pdf_replacement(self, outcome):
        source = self.sources / "report.pdf"
        original = json.dumps(record()).encode()
        source.write_bytes(original)
        for ancestor in (False, True):
            with self.subTest(ancestor=ancestor, outcome=outcome):
                source.write_bytes(original)
                swaps = contextlib.ExitStack()
                swapped = False

                def replace_during_pdf(html_path, pdf_path, *args, **kwargs):
                    nonlocal swapped
                    if outcome == "complete":
                        Path(pdf_path).write_bytes(b"%PDF-1.7\n%%EOF\n")
                    swaps.enter_context(self.swapped_output(ancestor=ancestor))
                    swapped = True
                    if outcome == "error":
                        raise OSError("simulated engine failure after directory replacement")
                    return "test" if outcome == "complete" else None

                try:
                    with mock.patch.object(render.pdf, "to_pdf", side_effect=replace_during_pdf):
                        code, error = self.invoke(source, no_pdf=False)
                finally:
                    swaps.close()
                self.assertTrue(swapped)
                self.assertTrue(source.exists(), "PDF cleanup deleted the selected findings source")
                self.assertEqual(source.read_bytes(), original)
                self.assertEqual(code, 2, error)

    def test_missing_pdf_engine_cannot_delete_a_source_after_directory_replacement(self):
        self.check_pdf_replacement("missing")

    def test_pdf_exception_cannot_delete_a_source_after_directory_replacement(self):
        self.check_pdf_replacement("error")

    def test_pdf_publication_cannot_replace_a_source_after_directory_replacement(self):
        self.check_pdf_replacement("complete")

    def test_findings_alias_retarget_cannot_hide_the_actual_input(self):
        source = self.out / "report.html"
        original = json.dumps(record()).encode()
        source.write_bytes(original)
        decoy = self.sources / "decoy.json"
        decoy.write_bytes(original)
        alias = self.base / "findings.json"
        alias.symlink_to(source)
        to_common = render.to_common

        def retarget_after_read(*args, **kwargs):
            common = to_common(*args, **kwargs)
            alias.unlink()
            alias.symlink_to(decoy)
            return common

        with mock.patch.object(render, "to_common", side_effect=retarget_after_read):
            code, error = self.invoke(alias)
        self.assertEqual(source.read_bytes(), original, "a later alias target concealed the actual source")
        self.assertEqual(code, 2, error)
        self.assertFalse((self.out / "dashboard.html").exists())

    def test_units_alias_retarget_cannot_hide_the_actual_input(self):
        source = self.sources / "findings.json"
        source.write_text(json.dumps(record()), encoding="utf-8")
        original = json.dumps(units_record()).encode()
        unit_source = self.out / "report.pdf"
        unit_source.write_bytes(original)
        decoy = self.sources / "decoy.json"
        decoy.write_bytes(original)
        alias = self.sources / "units.json"
        alias.symlink_to(unit_source)
        to_common = render.to_common

        def retarget_after_read(*args, **kwargs):
            common = to_common(*args, **kwargs)
            alias.unlink()
            alias.symlink_to(decoy)
            return common

        with mock.patch.object(render, "to_common", side_effect=retarget_after_read):
            code, error = self.invoke(source)
        self.assertTrue(unit_source.exists(), "a later alias target concealed the units source removed as stale PDF")
        self.assertEqual(unit_source.read_bytes(), original)
        self.assertEqual(code, 2, error)
        self.assertFalse((self.out / "dashboard.html").exists())

    def test_external_engine_receives_private_staging_and_complete_pdf_is_published(self):
        source = self.sources / "findings.json"
        source.write_text(json.dumps(record()), encoding="utf-8")
        content = b"%PDF-1.7\n%%EOF\n"

        def complete_pdf(html_path, pdf_path, *args, **kwargs):
            self.assertNotEqual(Path(html_path).parent.resolve(), self.out)
            self.assertNotEqual(Path(pdf_path).parent.resolve(), self.out)
            self.assertTrue(Path(html_path).is_file())
            Path(pdf_path).write_bytes(content)
            return "test"

        with mock.patch.object(render.pdf, "to_pdf", side_effect=complete_pdf):
            code, error = self.invoke(source, no_pdf=False)
        self.assertEqual(code, 0, error)
        self.assertEqual((self.out / "report.pdf").read_bytes(), content)
        self.assertTrue((self.out / "report.html").is_file())

    def test_missing_descriptor_support_refuses_before_changing_outputs(self):
        source = self.sources / "findings.json"
        source.write_text(json.dumps(record()), encoding="utf-8")
        previous = {name: f"previous {name}".encode() for name in render.OUTPUTS}
        for name, content in previous.items():
            (self.out / name).write_bytes(content)
        with mock.patch.object(render, "SAFE_OUTPUT", False, create=True):
            code, error = self.invoke(source)
        self.assertEqual(code, 2, error)
        self.assertIn("descriptor-relative", error)
        for name, content in previous.items():
            self.assertEqual((self.out / name).read_bytes(), content)

    def test_replacement_during_commit_stays_on_the_pinned_directory(self):
        source = self.sources / "report.html"
        original = json.dumps(record()).encode()
        replace = os.replace
        for ancestor in (False, True):
            with self.subTest(ancestor=ancestor):
                source.write_bytes(original)
                swaps = contextlib.ExitStack()
                swapped = False

                def replace_at_commit(source_name, target, **kwargs):
                    nonlocal swapped
                    if source_name == "new-dashboard.html" and "dst_dir_fd" in kwargs:
                        swaps.enter_context(self.swapped_output(ancestor=ancestor))
                        swapped = True
                    return replace(source_name, target, **kwargs)

                try:
                    with mock.patch.object(safe_output.os, "replace", side_effect=replace_at_commit):
                        code, error = self.invoke(source)
                finally:
                    swaps.close()
                self.assertTrue(swapped)
                self.assertEqual(code, 2, error)
                self.assertEqual(source.read_bytes(), original)
                self.assertFalse((self.sources / "dashboard.html").exists())
                self.assertIn(b"<!doctype html>", (self.out / "report.html").read_bytes())
                self.assertEqual(sorted(path.name for path in self.out.iterdir()),
                                 ["dashboard.html", "report.html"])

    def test_rollback_failure_keeps_the_unrestored_original_for_recovery(self):
        source = self.sources / "findings.json"
        source.write_text(json.dumps(record()), encoding="utf-8")
        previous = {name: f"previous {name}".encode() for name in render.OUTPUTS}
        for name, content in previous.items():
            (self.out / name).write_bytes(content)
        replace = os.replace

        def fail_install_and_restore(source_name, target, **kwargs):
            if (source_name in {"new-report.html", "old-report.html"}
                    and target == "report.html" and "dst_dir_fd" in kwargs):
                raise OSError("simulated installation and restoration failure")
            return replace(source_name, target, **kwargs)

        with mock.patch.object(safe_output.os, "replace", side_effect=fail_install_and_restore):
            code, error = self.invoke(source)
        self.assertEqual(code, 2, error)
        self.assertIn("recovery files", error)
        recovery = list(self.out.glob(".scan-report-output-*"))
        self.assertEqual(len(recovery), 1)
        self.assertIn(recovery[0].name, error)
        self.assertEqual((recovery[0] / "old-report.html").read_bytes(), previous["report.html"])
        self.assertEqual((self.out / "dashboard.html").read_bytes(), previous["dashboard.html"])
        self.assertEqual((self.out / "report.pdf").read_bytes(), previous["report.pdf"])

    def test_existing_html_permissions_and_new_file_privacy_are_preserved(self):
        source = self.sources / "findings.json"
        source.write_text(json.dumps(record()), encoding="utf-8")
        existing = self.out / "report.html"
        existing.write_text("previous report", encoding="utf-8")
        existing.chmod(0o640)
        code, error = self.invoke(source)
        self.assertEqual(code, 0, error)
        self.assertEqual(stat.S_IMODE(existing.stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE((self.out / "dashboard.html").stat().st_mode), 0o600)
        self.assertFalse(any(path.name.startswith(".scan-report-output-") for path in self.out.iterdir()))

    def test_temporary_cleanup_error_is_reported_without_a_traceback(self):
        source = self.sources / "findings.json"
        source.write_text(json.dumps(record()), encoding="utf-8")
        cleanup = tempfile.TemporaryDirectory.cleanup

        def failed_cleanup(temporary):
            cleanup(temporary)
            raise OSError("simulated temporary cleanup failure")

        with mock.patch.object(tempfile.TemporaryDirectory, "cleanup", failed_cleanup):
            code, error = self.invoke(source)
        self.assertEqual(code, 2, error)
        self.assertIn("simulated temporary cleanup failure", error)
        self.assertIn(b"<!doctype html>", (self.out / "report.html").read_bytes())
