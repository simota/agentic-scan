"""PR regressions for keeping a contract check on one artifact directory."""

import shutil
import tempfile
from pathlib import Path
from unittest import mock

from test_report_regressions import ReportFixture
import contract_check
import render


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

    def check_normal_directory_swap_after_resolve(self, ancestor=False):
        self.render_html()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name).resolve()
        workspace = base / "workspace"
        selected = workspace / "out"
        shutil.copytree(self.out, selected)
        outside = base / "outside"
        shutil.copytree(self.out, outside / "out")
        (selected / "findings.json").write_text("invalid original record", encoding="utf-8")
        self.assertTrue(list(contract_check.problems(selected, no_pdf=True)))
        self.assertEqual(list(contract_check.problems(outside / "out", no_pdf=True)), [])
        target = workspace if ancestor else selected
        replacement = outside if ancestor else outside / "out"
        saved = base / "saved"
        resolve = Path.resolve
        swapped = False

        def swap_after_resolve(path, *args, **kwargs):
            nonlocal swapped
            resolved = resolve(path, *args, **kwargs)
            if path == selected and not swapped:
                target.rename(saved)
                swapped = True
                shutil.copytree(replacement, target)
            return resolved

        try:
            with mock.patch.object(Path, "resolve", swap_after_resolve):
                errors = list(contract_check.problems(selected, no_pdf=True))
            self.assertTrue(swapped)
            self.assertFalse(target.is_symlink())
            self.assertTrue(errors, "a normal directory substituted after resolve passed the contract")
        finally:
            if swapped:
                shutil.rmtree(target)
                saved.rename(target)

    def test_normal_output_directory_swap_after_resolve_cannot_substitute_a_valid_contract(self):
        self.check_normal_directory_swap_after_resolve()

    def test_normal_output_ancestor_swap_after_resolve_cannot_substitute_a_valid_contract(self):
        self.check_normal_directory_swap_after_resolve(ancestor=True)

    def check_normal_pdf_directory_swap_after_resolve(self, ancestor=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name).resolve()
        workspace = base / "workspace"
        selected = workspace / "out"
        selected.mkdir(parents=True)
        outside = base / "outside"
        (outside / "out").mkdir(parents=True)
        path = selected / "report.pdf"
        path.write_bytes(b"invalid original PDF")
        (outside / "out" / "report.pdf").write_bytes(b"%PDF-1.7\n%%EOF\n")
        self.assertFalse(render.pdf_complete(path))
        self.assertTrue(render.pdf_complete(outside / "out" / "report.pdf"))
        target = workspace if ancestor else selected
        replacement = outside if ancestor else outside / "out"
        saved = base / "saved"
        resolve = Path.resolve
        swapped = False

        def swap_after_resolve(candidate, *args, **kwargs):
            nonlocal swapped
            resolved = resolve(candidate, *args, **kwargs)
            if candidate == selected and not swapped:
                target.rename(saved)
                swapped = True
                shutil.copytree(replacement, target)
            return resolved

        try:
            with mock.patch.object(Path, "resolve", swap_after_resolve):
                complete = render.pdf_complete(path)
            self.assertTrue(swapped)
            self.assertFalse(target.is_symlink())
            self.assertFalse(complete, "a normal directory substituted after resolve passed PDF validation")
        finally:
            if swapped:
                shutil.rmtree(target)
                saved.rename(target)

    def test_normal_pdf_parent_swap_after_resolve_cannot_substitute_a_valid_pdf(self):
        self.check_normal_pdf_directory_swap_after_resolve()

    def test_normal_pdf_ancestor_swap_after_resolve_cannot_substitute_a_valid_pdf(self):
        self.check_normal_pdf_directory_swap_after_resolve(ancestor=True)

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
