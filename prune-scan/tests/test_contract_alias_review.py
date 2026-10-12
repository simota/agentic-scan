"""PR regressions for checking the directory the caller still selects through aliases."""

import contextlib
import io
import os
import shutil
import tempfile
from pathlib import Path
from unittest import mock

from test_report_regressions import ReportFixture
import contract_check
import render


class ContractAliasTests(ReportFixture):
    @contextlib.contextmanager
    def aliases(self, ancestor=False):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            selected = base / "valid" / "out"
            shutil.copytree(self.out, selected)
            invalid = base / "invalid" / "out"
            invalid.mkdir(parents=True)
            alias = base / "alias"
            alias.symlink_to(selected.parent if ancestor else selected, target_is_directory=True)
            requested = alias / "out" if ancestor else alias
            yield base, alias, requested, selected, invalid

    @contextlib.contextmanager
    def path_support(self, fallback):
        supported = contract_check.NOFOLLOW_DIR_FD and not fallback
        with mock.patch.object(contract_check, "NOFOLLOW_DIR_FD", supported), \
                mock.patch.object(render, "NOFOLLOW_DIR_FD", supported):
            yield

    def check_cli(self, requested):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = contract_check.main([str(requested), "--no-pdf"])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_retargeted_final_and_parent_aliases_cannot_pass_the_contract(self):
        self.render_html()
        read_source = contract_check.read_json_source
        for ancestor in (False, True):
            for fallback in (False, True):
                with self.subTest(ancestor=ancestor, fallback=fallback), self.aliases(ancestor) as paths:
                    _, alias, requested, _, invalid = paths
                    swapped = False

                    def retarget_after_inventory(path, *args, **kwargs):
                        nonlocal swapped
                        value = read_source(path, *args, **kwargs)
                        if Path(path).name == "inventory.json":
                            alias.unlink()
                            alias.symlink_to(invalid.parent if ancestor else invalid, target_is_directory=True)
                            swapped = True
                        return value

                    with self.path_support(fallback):
                        self.assertEqual(list(contract_check.problems(requested, no_pdf=True)), [])
                        with mock.patch.object(contract_check, "read_json_source", side_effect=retarget_after_inventory):
                            code, stdout, error = self.check_cli(requested)
                    self.assertTrue(swapped)
                    self.assertEqual(code, 1, stdout + error)
                    self.assertIn("directory changed during validation", error)
                    self.assertNotIn("contract ok", stdout)

    def test_dangling_or_looping_requested_alias_is_an_error(self):
        self.render_html()
        read_source = contract_check.read_json_source
        for looping in (False, True):
            for fallback in (False, True):
                with self.subTest(looping=looping, fallback=fallback), self.aliases() as paths:
                    base, alias, requested, _, _ = paths

                    def lose_alias_after_inventory(path, *args, **kwargs):
                        value = read_source(path, *args, **kwargs)
                        if Path(path).name == "inventory.json":
                            alias.unlink()
                            alias.symlink_to(alias if looping else base / "missing", target_is_directory=True)
                        return value

                    with self.path_support(fallback), \
                            mock.patch.object(contract_check, "read_json_source", side_effect=lose_alias_after_inventory):
                        code, stdout, error = self.check_cli(requested)
                    self.assertEqual(code, 1, stdout + error)
                    self.assertIn("directory changed during validation", error)

    def test_unchanged_final_and_parent_aliases_still_pass(self):
        self.render_html()
        for ancestor in (False, True):
            for fallback in (False, True):
                with self.subTest(ancestor=ancestor, fallback=fallback), self.aliases(ancestor) as paths:
                    _, _, requested, _, _ = paths
                    with self.path_support(fallback):
                        code, stdout, error = self.check_cli(requested)
                    self.assertEqual(code, 0, error)
                    self.assertIn("contract ok", stdout)

    def test_relative_requested_alias_is_anchored_before_the_working_directory_changes(self):
        self.render_html()
        read_source = contract_check.read_json_source
        original_cwd = Path.cwd()
        for fallback in (False, True):
            with self.subTest(fallback=fallback), self.aliases() as paths:
                base, alias, _, selected, invalid = paths
                changed_cwd = base / "new-cwd"
                changed_cwd.mkdir()
                (changed_cwd / "alias").symlink_to(selected, target_is_directory=True)

                def retarget_and_change_cwd(path, *args, **kwargs):
                    value = read_source(path, *args, **kwargs)
                    if Path(path).name == "inventory.json":
                        alias.unlink()
                        alias.symlink_to(invalid, target_is_directory=True)
                        os.chdir(changed_cwd)
                    return value

                try:
                    os.chdir(base)
                    with self.path_support(fallback), \
                            mock.patch.object(contract_check, "read_json_source", side_effect=retarget_and_change_cwd):
                        code, stdout, error = self.check_cli("alias")
                finally:
                    os.chdir(original_cwd)
                self.assertEqual(code, 1, stdout + error)
                self.assertIn("directory changed during validation", error)
