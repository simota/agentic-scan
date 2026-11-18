"""Contract success must not ignore artifacts changed after their inspection."""

import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "prune-scan" / "scripts"))

import contract_check  # noqa: E402
import render  # noqa: E402


class ContractArtifactReviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.out = self.base / "out"
        self.out.mkdir()
        self.names = (*contract_check.REQUIRED, "report.pdf")

    def write_run(self, pdf=True):
        for path in self.out.iterdir():
            path.unlink()
        data = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
        data["limitations"] = [] if pdf else ["report.pdf not produced: this test checks HTML"]
        sources = {
            "findings.json": json.dumps(data).encode("utf-8"),
            "units.json": (ROOT / "examples" / "units.sample.json").read_bytes(),
            "inventory.json": b'{"tool": "inventory.py"}\n',
        }
        for name, source in sources.items():
            (self.out / name).write_bytes(source)
        stamps = "".join(
            f'<meta name="{stamp}" content="sha256:{hashlib.sha256(sources[name]).hexdigest()}">'
            for stamp, name in ((contract_check.STAMP, "findings.json"),
                                (contract_check.UNITS_STAMP, "units.json"))
        )
        for name in ("dashboard.html", "report.html"):
            page = f'<html lang="en"><head>{stamps}</head><body>{name}</body></html>'
            (self.out / name).write_text(page, encoding="utf-8")
        if pdf:
            # The contract checks this envelope, not the PDF object structure.
            (self.out / "report.pdf").write_bytes(b"%PDF-1.7\n" + b"x" * 4096 + b"\n%%EOF\n")

    @contextlib.contextmanager
    def path_support(self, fallback):
        supported = contract_check.NOFOLLOW_DIR_FD and not fallback
        with mock.patch.object(contract_check, "NOFOLLOW_DIR_FD", supported), \
                mock.patch.object(render, "NOFOLLOW_DIR_FD", supported):
            yield

    def check_after_inspection(self, mutate=None, *, pdf=True, allow=()):
        inspect = contract_check.directory_problems
        inspected = False

        def after_inspection(*args, **kwargs):
            nonlocal inspected
            yield from inspect(*args, **kwargs)
            inspected = True
            if mutate is not None:
                mutate()

        stdout, stderr = io.StringIO(), io.StringIO()
        argv = [str(self.out)] + ([] if pdf else ["--no-pdf"])
        for name in allow:
            argv.extend(("--allow", name))
        with mock.patch.object(contract_check, "directory_problems", side_effect=after_inspection), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = contract_check.main(argv)
        self.assertTrue(inspected)
        return status, stdout.getvalue(), stderr.getvalue()

    def assert_changed(self, result, name):
        status, stdout, stderr = result
        self.assertEqual(status, 1, stdout + stderr)
        self.assertIn(name, stderr)
        self.assertIn("changed during validation", stderr)
        self.assertNotIn("contract ok", stdout)

    def test_atomic_replacements_after_inspection_invalidate_every_artifact(self):
        for fallback in (False, True):
            for name in self.names:
                with self.subTest(name=name, fallback=fallback), self.path_support(fallback):
                    self.write_run()
                    path = self.out / name
                    replacement = self.base / "replacement"
                    replacement.write_bytes(path.read_bytes() + b"\nchanged\n")
                    result = self.check_after_inspection(lambda: replacement.replace(path))
                    self.assert_changed(result, name)

    def test_identical_replacement_is_still_a_different_inspected_file(self):
        for fallback in (False, True):
            with self.subTest(fallback=fallback), self.path_support(fallback):
                self.write_run()
                path = self.out / "findings.json"
                replacement = self.base / "replacement"
                replacement.write_bytes(path.read_bytes())
                self.assert_changed(self.check_after_inspection(lambda: replacement.replace(path)), path.name)

    def test_same_size_in_place_changes_with_restored_mtime_are_rejected(self):
        for fallback in (False, True):
            for name in self.names:
                with self.subTest(name=name, fallback=fallback), self.path_support(fallback):
                    self.write_run()
                    path = self.out / name
                    before = path.stat()
                    original = path.read_bytes()
                    offset = len(original) // 2

                    def overwrite():
                        content = original[:offset] + bytes((original[offset] ^ 1,)) + original[offset + 1:]
                        path.write_bytes(content)
                        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
                        after = path.stat()
                        self.assertTrue(os.path.samestat(before, after))
                        self.assertEqual(after.st_size, before.st_size)
                        self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)

                    self.assert_changed(self.check_after_inspection(overwrite), name)

    def test_symlink_replacements_after_inspection_are_rejected(self):
        for fallback in (False, True):
            for name in self.names:
                with self.subTest(name=name, fallback=fallback), self.path_support(fallback):
                    self.write_run()
                    path = self.out / name
                    outside = self.base / "outside"
                    outside.write_bytes(path.read_bytes())

                    def replace():
                        path.unlink()
                        path.symlink_to(outside)

                    self.assert_changed(self.check_after_inspection(replace), name)

    def test_removal_after_inspection_invalidates_every_artifact(self):
        for fallback in (False, True):
            for name in self.names:
                with self.subTest(name=name, fallback=fallback), self.path_support(fallback):
                    self.write_run()
                    self.assert_changed(self.check_after_inspection((self.out / name).unlink), name)

    def test_new_pdf_or_unapproved_extra_cannot_appear_after_inspection(self):
        for fallback in (False, True):
            for name in ("report.pdf", "unexpected.txt"):
                with self.subTest(name=name, fallback=fallback), self.path_support(fallback):
                    self.write_run(pdf=False)
                    result = self.check_after_inspection(lambda: (self.out / name).write_bytes(b"new"), pdf=False)
                    self.assert_changed(result, name)

    def test_allowed_extras_can_change_without_affecting_the_contract(self):
        for fallback in (False, True):
            for name in ("notes.txt", "report.pdf"):
                for change in ("create", "replace", "remove"):
                    with self.subTest(name=name, change=change, fallback=fallback), self.path_support(fallback):
                        self.write_run(pdf=False)
                        extra = self.out / name
                        if change != "create":
                            extra.write_bytes(b"old extra")
                        replacement = self.base / "extra"
                        replacement.write_bytes(b"new extra")
                        mutate = extra.unlink if change == "remove" else lambda: replacement.replace(extra)
                        status, stdout, stderr = self.check_after_inspection(mutate, pdf=False, allow=(name,))
                        self.assertEqual(status, 0, stderr)
                        self.assertIn("contract ok", stdout)

    def test_unchanged_runs_pass_with_and_without_pdf(self):
        for fallback in (False, True):
            for pdf in (False, True):
                with self.subTest(pdf=pdf, fallback=fallback), self.path_support(fallback):
                    self.write_run(pdf=pdf)
                    status, stdout, stderr = self.check_after_inspection(pdf=pdf)
                    self.assertEqual(status, 0, stderr)
                    self.assertIn("contract ok", stdout)

    def test_writes_during_the_inspected_read_cannot_become_a_clean_snapshot(self):
        open_artifact = contract_check.open_artifact
        for fallback in (False, True):
            for name in ("findings.json", "report.pdf"):
                with self.subTest(name=name, fallback=fallback), self.path_support(fallback):
                    self.write_run()
                    path = self.out / name
                    original = path.read_bytes()
                    changed = False

                    class ChangingReader:
                        def __init__(self, handle):
                            self.handle = handle

                        def __getattr__(self, attribute):
                            return getattr(self.handle, attribute)

                        def read(self, *args):
                            nonlocal changed
                            value = self.handle.read(*args)
                            if not changed:
                                changed = True
                                path.write_bytes(b"!" + original[1:])
                                path.write_bytes(original)
                            return value

                    @contextlib.contextmanager
                    def change_during_read(target, **kwargs):
                        with open_artifact(target, **kwargs) as handle:
                            yield ChangingReader(handle) if target.name == name else handle

                    with mock.patch.object(contract_check, "open_artifact", side_effect=change_during_read), \
                            mock.patch.object(render, "open_artifact", side_effect=change_during_read):
                        status, stdout, stderr = self.check_after_inspection()
                    self.assertTrue(changed)
                    self.assertEqual(path.read_bytes(), original)
                    self.assertEqual(status, 1, stdout + stderr)
                    self.assertIn(name, stderr)
                    self.assertNotIn("contract ok", stdout)

    def test_snapshot_descriptors_close_after_success_and_failed_recheck(self):
        open_artifact = contract_check.open_artifact
        for fallback in (False, True):
            for fail in (False, True):
                with self.subTest(fail=fail, fallback=fallback), self.path_support(fallback):
                    self.write_run()
                    opened = []
                    rechecking = False

                    @contextlib.contextmanager
                    def tracked_open(path, **kwargs):
                        if rechecking and fail and path.name == "findings.json":
                            raise OSError("simulated recheck denial")
                        with open_artifact(path, **kwargs) as handle:
                            opened.append(handle)
                            yield handle

                    def finish_inspection():
                        nonlocal rechecking
                        # Every inspected inode remains selected until the
                        # final check, so unlinking cannot recycle its number.
                        self.assertEqual(sum(not handle.closed for handle in opened), len(self.names))
                        rechecking = True

                    with mock.patch.object(contract_check, "open_artifact", side_effect=tracked_open):
                        result = self.check_after_inspection(finish_inspection)
                    self.assertTrue(opened)
                    self.assertTrue(all(handle.closed for handle in opened))
                    if fail:
                        self.assert_changed(result, "findings.json")
                    else:
                        status, stdout, stderr = result
                        self.assertEqual(status, 0, stderr)
                        self.assertIn("contract ok", stdout)

    def test_later_rechecks_cannot_hide_changes_to_an_already_rechecked_artifact(self):
        open_artifact = contract_check.open_artifact
        for fallback in (False, True):
            for replace in (False, True):
                with self.subTest(replace=replace, fallback=fallback), self.path_support(fallback):
                    self.write_run()
                    earlier = self.out / "findings.json"
                    changed_source = earlier.read_bytes() + b"\n"
                    replacement_path = self.base / "replacement"
                    rechecking = changed = False

                    class LaterReader:
                        def __init__(self, handle):
                            self.handle = handle

                        def __getattr__(self, attribute):
                            return getattr(self.handle, attribute)

                        def read(self, *args):
                            nonlocal changed
                            source = self.handle.read(*args)
                            if not changed:
                                changed = True
                                if replace:
                                    replacement_path.write_bytes(changed_source)
                                    replacement_path.replace(earlier)
                                else:
                                    earlier.write_bytes(changed_source)
                            return source

                    @contextlib.contextmanager
                    def change_during_later_recheck(path, **kwargs):
                        with open_artifact(path, **kwargs) as handle:
                            yield LaterReader(handle) if rechecking and path.name == "report.pdf" else handle

                    def finish_inspection():
                        nonlocal rechecking
                        rechecking = True

                    with mock.patch.object(contract_check, "open_artifact", side_effect=change_during_later_recheck):
                        result = self.check_after_inspection(finish_inspection)
                    self.assertTrue(changed)
                    self.assert_changed(result, earlier.name)


if __name__ == "__main__":
    unittest.main()
