"""A contract check must reject artifacts changed after their contents were read."""

import contextlib
import io
import os
import stat
import tempfile
from pathlib import Path
from unittest import mock

from test_report_regressions import ReportFixture
import contract_check
import render


class ContractArtifactIdentityTests(ReportFixture):
    # Mutate earlier artifacts while a later artifact is being validated. PDF
    # is last, so its mutation follows the completeness check's actual reads.
    LATER_READ = {
        "findings.json": "units.json",
        "units.json": "inventory.json",
        "inventory.json": "dashboard.html",
        "dashboard.html": "report.html",
        "report.html": "report.pdf",
        "report.pdf": "report.pdf",
    }

    def setUp(self):
        super().setUp()
        self.data["limitations"] = [line for line in self.data["limitations"]
                                    if not line.startswith(contract_check.NO_PDF)]
        self.write_record()
        self.render_html()
        (self.out / "report.pdf").write_bytes(b"%PDF-1.7\n%%EOF\n")
        self.originals = {name: (self.out / name).read_bytes() for name in self.LATER_READ}
        self.assertEqual(list(contract_check.problems(self.out)), [])

    @contextlib.contextmanager
    def path_support(self, fallback):
        supported = contract_check.NOFOLLOW_DIR_FD and not fallback
        with mock.patch.object(contract_check, "NOFOLLOW_DIR_FD", supported), \
                mock.patch.object(render, "NOFOLLOW_DIR_FD", supported):
            yield

    @contextlib.contextmanager
    def after_read(self, trigger, change):
        """Schedule a real filesystem change after an existing reader gets bytes."""
        read_json = contract_check.read_json_source
        open_artifact = contract_check.open_artifact
        pdf_complete = contract_check.pdf_complete
        fired = []
        records_started = False

        def fire(name):
            if name == trigger and not fired:
                fired.append(name)
                change()

        def read_record(path, *args, **kwargs):
            nonlocal records_started
            records_started = True
            source = read_json(path, *args, **kwargs)
            fire(Path(path).name)
            return source

        class ReadProxy:
            def __init__(self, handle, name):
                self.handle, self.name = handle, name

            def __getattr__(self, name):
                return getattr(self.handle, name)

            def read(self, *args, **kwargs):
                source = self.handle.read(*args, **kwargs)
                fire(self.name)
                return source

        @contextlib.contextmanager
        def open_page(path, *args, **kwargs):
            with open_artifact(path, *args, **kwargs) as handle:
                # The preliminary language hint reads report.html before JSON.
                # Only fire once the page itself is being contract-checked.
                if records_started and Path(path).suffix == ".html":
                    yield ReadProxy(handle, Path(path).name)
                else:
                    yield handle

        def complete_pdf(path, *args, **kwargs):
            complete = pdf_complete(path, *args, **kwargs)
            fire(Path(path).name)
            return complete

        with mock.patch.object(contract_check, "read_json_source", side_effect=read_record), \
                mock.patch.object(contract_check, "open_artifact", side_effect=open_page), \
                mock.patch.object(contract_check, "pdf_complete", side_effect=complete_pdf):
            yield fired

    def changed_source(self, name):
        source = self.originals[name]
        if name in ("findings.json", "units.json"):
            # Keep valid, equivalent JSON but change the hash stamped in HTML.
            changed = source.replace(b'": ', b'":\t', 1)
        elif name == "inventory.json":
            changed = source.replace(b"inventory.py", b"changed-tool", 1)
        elif name.endswith(".html"):
            changed = source.replace(b"</html>", b"</htmx>", 1)
        else:
            changed = source.replace(b"%%EOF", b"%%BAD", 1)
        self.assertNotEqual(changed, source)
        self.assertEqual(len(changed), len(source))
        return changed

    def replace_artifact(self, name):
        path = self.out / name
        before = path.stat()
        replacement = path.with_name(name + ".replacement")
        replacement.write_bytes(self.changed_source(name))
        os.chmod(replacement, stat.S_IMODE(before.st_mode))
        os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
        replacement.replace(path)
        self.assertFalse(os.path.samestat(before, path.stat()))

    def rewrite_artifact(self, name):
        path = self.out / name
        before = path.stat()
        path.write_bytes(self.changed_source(name))
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        after = path.stat()
        self.assertTrue(os.path.samestat(before, after))
        self.assertEqual(before.st_size, after.st_size)
        self.assertEqual(before.st_mtime_ns, after.st_mtime_ns)

    def restore_artifact(self, name):
        path = self.out / name
        if path.is_symlink():
            path.unlink()
        elif path.is_dir():
            path.rmdir()
        path.write_bytes(self.originals[name])

    def assert_changed_artifact(self, name, change, fallback):
        trigger = self.LATER_READ[name]
        with self.path_support(fallback), self.after_read(trigger, change) as fired:
            errors = list(contract_check.problems(self.out))
        self.assertEqual(fired, [trigger])
        self.assertTrue(any(error.startswith(name + ":") and "changed during validation" in error
                            for error in errors), errors)

    def test_atomic_replacement_after_read_cannot_pass_the_contract(self):
        for name in self.LATER_READ:
            for fallback in (False, True):
                with self.subTest(name=name, fallback=fallback):
                    try:
                        self.assert_changed_artifact(name, lambda: self.replace_artifact(name), fallback)
                    finally:
                        self.restore_artifact(name)

    def test_same_inode_same_size_rewrite_with_restored_mtime_is_rejected(self):
        for name in self.LATER_READ:
            for fallback in (False, True):
                with self.subTest(name=name, fallback=fallback):
                    try:
                        self.assert_changed_artifact(name, lambda: self.rewrite_artifact(name), fallback)
                    finally:
                        self.restore_artifact(name)

    def test_removed_or_nonregular_artifacts_after_read_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            for name in ("findings.json", "report.html", "report.pdf"):
                outside = Path(temporary) / name
                outside.write_bytes(self.originals[name])
                for kind in ("removed", "directory", "symlink"):
                    for fallback in (False, True):
                        with self.subTest(name=name, kind=kind, fallback=fallback):
                            def change():
                                path = self.out / name
                                path.unlink()
                                if kind == "directory":
                                    path.mkdir()
                                elif kind == "symlink":
                                    path.symlink_to(outside)

                            try:
                                self.assert_changed_artifact(name, change, fallback)
                            finally:
                                self.restore_artifact(name)

    def test_cli_reports_the_changed_record_without_printing_success(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with self.after_read("findings.json", lambda: self.replace_artifact("findings.json")) as fired, \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = contract_check.main([str(self.out)])
        self.assertEqual(fired, ["findings.json"])
        self.assertEqual(code, 1, stdout.getvalue() + stderr.getvalue())
        self.assertIn("findings.json: changed during validation", stderr.getvalue())
        self.assertNotIn("contract ok", stdout.getvalue())

    def no_pdf_contract(self):
        self.data["limitations"].append("report.pdf not produced: this test checks HTML")
        self.write_record()
        self.render_html()

    def test_unchanged_artifacts_pass_with_and_without_pdf(self):
        for no_pdf in (False, True):
            if no_pdf:
                self.no_pdf_contract()
            for fallback in (False, True):
                with self.subTest(no_pdf=no_pdf, fallback=fallback), self.path_support(fallback):
                    self.assertEqual(list(contract_check.problems(self.out, no_pdf=no_pdf)), [])

    def test_pdf_or_unrequested_file_created_during_no_pdf_check_is_rejected(self):
        self.no_pdf_contract()
        for name in ("report.pdf", "unrequested.txt"):
            for fallback in (False, True):
                with self.subTest(name=name, fallback=fallback):
                    path = self.out / name
                    try:
                        with self.path_support(fallback), self.after_read(
                                "inventory.json", lambda: path.write_bytes(b"%PDF-1.7\n%%EOF\n")) as fired:
                            errors = list(contract_check.problems(self.out, no_pdf=True))
                        self.assertEqual(fired, ["inventory.json"])
                        self.assertTrue(any(name in error for error in errors), errors)
                    finally:
                        path.unlink(missing_ok=True)

    def test_allowlisted_extra_file_can_appear_during_validation(self):
        path = self.out / "notes.txt"
        for fallback in (False, True):
            with self.subTest(fallback=fallback):
                try:
                    with self.path_support(fallback), self.after_read(
                            "inventory.json", lambda: path.write_text("requested notes", encoding="utf-8")) as fired:
                        errors = list(contract_check.problems(self.out, allow=(path.name,)))
                    self.assertEqual(fired, ["inventory.json"])
                    self.assertEqual(errors, [])
                finally:
                    path.unlink(missing_ok=True)
