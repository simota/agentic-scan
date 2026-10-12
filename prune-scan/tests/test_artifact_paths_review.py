"""PR regressions for keeping a contract check on one artifact directory."""

import shutil
import tempfile
from pathlib import Path
from unittest import mock

from test_report_regressions import ReportFixture
import contract_check


class ArtifactDirectoryTests(ReportFixture):
    def check_directory_swap(self, ancestor=False):
        self.render_html()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name).resolve()
        workspace = base / "workspace"
        workspace.mkdir()
        selected = workspace / "out"
        shutil.copytree(self.out, selected)
        outside = base / "outside"
        outside.mkdir()
        shutil.copytree(selected, outside / "out")
        (selected / "findings.json").write_text("invalid original record", encoding="utf-8")
        target = workspace if ancestor else selected
        replacement = outside if ancestor else outside / "out"
        saved = base / "saved"
        read_source = contract_check.read_json_source
        swapped = False

        def swap_before_record(path, *args, **kwargs):
            nonlocal swapped
            if Path(path).name == "findings.json" and not swapped:
                target.rename(saved)
                target.symlink_to(replacement, target_is_directory=True)
                swapped = True
            return read_source(path, *args, **kwargs)

        try:
            with mock.patch.object(contract_check, "read_json_source", side_effect=swap_before_record):
                errors = list(contract_check.problems(selected, no_pdf=True))
            self.assertTrue(swapped)
            self.assertTrue(errors, "the valid outside artifacts replaced an invalid selected record")
        finally:
            if swapped:
                target.unlink()
                saved.rename(target)

    def test_output_directory_swap_cannot_substitute_a_valid_contract(self):
        self.check_directory_swap()

    def test_output_ancestor_swap_cannot_substitute_a_valid_contract(self):
        self.check_directory_swap(ancestor=True)

    def test_intentional_directory_alias_is_selected_before_inspection(self):
        self.render_html()
        alias = self.out.with_name(self.out.name + "-alias")
        alias.symlink_to(self.out, target_is_directory=True)
        try:
            self.assertEqual(list(contract_check.problems(alias, no_pdf=True)), [])
        finally:
            alias.unlink()

    def test_replaced_directory_is_reported_even_when_pinned_contents_are_valid(self):
        self.render_html()
        target = self.out.resolve()
        saved = target.with_name(target.name + "-saved")
        read_source = contract_check.read_json_source
        swapped = False

        def swap_after_record(path, *args, **kwargs):
            nonlocal swapped
            value = read_source(path, *args, **kwargs)
            if Path(path).name == "inventory.json" and not swapped:
                target.rename(saved)
                target.mkdir()
                swapped = True
            return value

        try:
            with mock.patch.object(contract_check, "read_json_source", side_effect=swap_after_record):
                errors = list(contract_check.problems(target, no_pdf=True))
            self.assertTrue(swapped)
            self.assertTrue(errors, "the requested path no longer holds the checked directory")
        finally:
            if swapped:
                target.rmdir()
                saved.rename(target)
