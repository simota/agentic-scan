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
    def test_secret_key_assignments_are_masked(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            source = repo / "settings.py"
            for assignment in ("SECRET_KEY = 'DO_NOT_PUBLISH'", "AWS_SECRET_ACCESS_KEY = 'DO_NOT_PUBLISH'",
                               "config['api_key'] = 'DO_NOT_PUBLISH'"):
                with self.subTest(assignment=assignment):
                    source.write_text(assignment + "\n", encoding="utf-8")
                    excerpt = render.snippet(repo, "settings.py:1")
                    self.assertNotIn("DO_NOT_PUBLISH", json.dumps(excerpt))

    def test_multiline_secrets_are_not_excerpted_even_beyond_context(self):
        sources = (
            "API_TOKEN = (\n" + "\n" * 5 + "    'DO_NOT_PUBLISH'\n)\n",
            'api_key: |\n' + '\n' * 5 + '  DO_NOT_PUBLISH\n',
            'api_key = """\n' + '\n' * 5 + 'DO_NOT_PUBLISH\n"""\n',
            'const apiKey = `\n' + '\n' * 5 + 'DO_NOT_PUBLISH\n`;\n',
            'password: unquoted\n' + '\n' * 5 + '  DO_NOT_PUBLISH\n',
            'const apiKey = "first"\n' + '\n' * 5 + '+ "DO_NOT_PUBLISH";\n',
        )
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            for source in sources:
                with self.subTest(source=source[:30]):
                    (repo / "settings.txt").write_text(source, encoding="utf-8")
                    excerpt = render.snippet(repo, "settings.txt:7")
                    self.assertIsNone(excerpt)

    def test_block_comments_cannot_hide_secret_continuations(self):
        comments = (
            "/* value continues below */",
            "/* value continues\n * on another line\n */",
            "/* first comment */ /* second comment */",
            "/* outer comment\n /* nested comment */\n */",
            "/* unterminated comment",
        )
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            for comment in comments:
                with self.subTest(comment=comment):
                    source = 'const apiKey = "first"\n' + comment + '\n+ "DO_NOT_PUBLISH";\n'
                    (repo / "settings.ts").write_text(source, encoding="utf-8")
                    self.assertIsNone(render.snippet(repo, f"settings.ts:{len(source.splitlines())}"))

    def test_block_comments_between_secret_name_and_assignment_are_not_excerpted(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            for source in ('const apiKey /* deployment key */ = "DO_NOT_PUBLISH";\n',
                           'config["API_TOKEN"] /* deployment key */ = "DO_NOT_PUBLISH";\n'):
                with self.subTest(source=source):
                    (repo / "settings.ts").write_text(source, encoding="utf-8")
                    self.assertIsNone(render.snippet(repo, "settings.ts:1"))

    def test_block_comments_without_secret_identifiers_can_still_be_excerpted(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            lines = ["/* public feature description", " * visible details", " */", 'console.log("public");']
            (repo / "source.ts").write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.assertEqual(render.snippet(repo, "source.ts:4")["lines"], lines)

    def test_embedded_private_keys_are_not_excerpted(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            for kind in ("PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY",
                         "ENCRYPTED PRIVATE KEY", "PGP PRIVATE KEY BLOCK"):
                with self.subTest(kind=kind):
                    source = f'key = """-----BEGIN {kind}-----\n' + "\n" * 5 + "DO_NOT_PUBLISH\n"
                    (repo / "settings.py").write_text(source, encoding="utf-8")
                    self.assertIsNone(render.snippet(repo, "settings.py:7"))

    def test_secret_files_and_directories_are_never_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            for name in ("secret", "secrets", "config/secrets", ".secrets/value", "credentials/value",
                         "secrets/key.txt", ".env/value"):
                with self.subTest(name=name):
                    path = repo / name
                    if path.parent.exists() and not path.parent.is_dir():
                        path.parent.unlink()
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("DO_NOT_PUBLISH\n", encoding="utf-8")
                    with mock.patch.object(render.os, "open", side_effect=AssertionError("secret file read")):
                        self.assertIsNone(render.snippet(repo, f"{name}:1"))

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

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd,
                         "descriptor-relative no-follow opens require POSIX")
    def test_source_replaced_by_symlink_is_not_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            source = repo / "source.py"
            source.write_text("print('public')\n", encoding="utf-8")
            outside = Path(tmp) / "outside.py"
            outside.write_text("DO_NOT_PUBLISH\n", encoding="utf-8")
            resolve = Path.resolve

            def replace_source(path, *args, **kwargs):
                resolved = resolve(path, *args, **kwargs)
                if path == source:
                    source.unlink()
                    source.symlink_to(outside)
                return resolved

            with mock.patch.object(Path, "resolve", replace_source):
                self.assertIsNone(render.snippet(repo, "source.py:1"))

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd,
                         "descriptor-relative no-follow opens require POSIX")
    def test_source_parent_replaced_by_symlink_is_not_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            source_dir = repo / "src"
            source_dir.mkdir(parents=True)
            (source_dir / "source.py").write_text("print('public')\n", encoding="utf-8")
            outside = Path(tmp) / "outside"
            outside.mkdir()
            (outside / "source.py").write_text("DO_NOT_PUBLISH\n", encoding="utf-8")
            resolve = Path.resolve

            def replace_parent(path, *args, **kwargs):
                resolved = resolve(path, *args, **kwargs)
                if path == source_dir / "source.py":
                    source_dir.rename(repo / "original")
                    source_dir.symlink_to(outside, target_is_directory=True)
                return resolved

            with mock.patch.object(Path, "resolve", replace_parent):
                self.assertIsNone(render.snippet(repo, "src/source.py:1"))

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd,
                         "descriptor-relative no-follow opens require POSIX")
    def test_repository_ancestor_replaced_by_symlink_is_not_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            ancestor = Path(tmp) / "checkout"
            repo = ancestor / "repo"
            repo.mkdir(parents=True)
            source = repo / "source.py"
            source.write_text("print('public')\n", encoding="utf-8")
            outside = Path(tmp) / "outside"
            (outside / "repo").mkdir(parents=True)
            (outside / "repo" / "source.py").write_text("DO_NOT_PUBLISH\n", encoding="utf-8")
            resolve = Path.resolve

            def replace_ancestor(path, *args, **kwargs):
                resolved = resolve(path, *args, **kwargs)
                if path == source:
                    ancestor.rename(Path(tmp) / "original")
                    ancestor.symlink_to(outside, target_is_directory=True)
                return resolved

            with mock.patch.object(Path, "resolve", replace_ancestor):
                self.assertIsNone(render.snippet(repo, "source.py:1"))

    def check_regular_repository_replacement(self, *, ancestor, boundary, fallback=False):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            checkout = base / "checkout"
            repo = checkout / "repo"
            source = repo / "src" / "source.py"
            source.parent.mkdir(parents=True)
            source.write_text("print('selected repository')\n", encoding="utf-8")
            replacement = base / "replacement"
            target = checkout if ancestor else repo
            substitute = replacement / source.relative_to(target)
            substitute.parent.mkdir(parents=True)
            substitute.write_text("DO_NOT_PUBLISH\n", encoding="utf-8")
            replaced = False
            opened = []
            resolve, open_directory, open_file = Path.resolve, render.open_directory, os.open

            def replace_repository():
                nonlocal replaced
                self.assertFalse(replaced)
                target.rename(base / "selected")
                replacement.rename(target)
                replaced = True

            def resolve_with_replacement(path, *args, **kwargs):
                if boundary == "before_resolve" and path == repo:
                    replace_repository()
                selected = resolve(path, *args, **kwargs)
                if boundary == "after_resolve" and path == source:
                    replace_repository()
                return selected

            def pin_with_replacement(path, *args, **kwargs):
                descriptor = open_directory(path, *args, **kwargs)
                if boundary == "after_pin":
                    replace_repository()
                return descriptor

            def track_open(*args, **kwargs):
                descriptor = open_file(*args, **kwargs)
                opened.append(descriptor)
                return descriptor

            with mock.patch.object(Path, "resolve", resolve_with_replacement), \
                    mock.patch.object(render, "open_directory", pin_with_replacement), \
                    mock.patch.object(render, "NOFOLLOW_DIR_FD", False if fallback else render.NOFOLLOW_DIR_FD), \
                    mock.patch.object(os, "open", track_open):
                excerpt = render.snippet(repo, "src/source.py:1")
            self.assertTrue(replaced)
            if boundary == "after_pin":
                self.assertIsNotNone(excerpt)
                self.assertEqual(excerpt["lines"], ["print('selected repository')"])
            else:
                self.assertIsNone(excerpt)
            for descriptor in opened:
                with self.assertRaises(OSError, msg=f"descriptor {descriptor} was not closed"):
                    os.fstat(descriptor)

    def test_repository_identity_is_selected_before_resolving_paths(self):
        for ancestor in (False, True):
            for fallback in (False, True):
                with self.subTest(ancestor=ancestor, fallback=fallback):
                    self.check_regular_repository_replacement(ancestor=ancestor, boundary="before_resolve",
                                                              fallback=fallback)

    def test_regular_repository_replacement_after_resolution_is_not_read(self):
        for ancestor in (False, True):
            for fallback in (False, True):
                with self.subTest(ancestor=ancestor, fallback=fallback):
                    self.check_regular_repository_replacement(ancestor=ancestor, boundary="after_resolve",
                                                              fallback=fallback)

    @unittest.skipUnless(render.NOFOLLOW_DIR_FD, "requires descriptor-relative directory opens")
    def test_pinned_repository_survives_regular_directory_replacement(self):
        for ancestor in (False, True):
            with self.subTest(ancestor=ancestor):
                self.check_regular_repository_replacement(ancestor=ancestor, boundary="after_pin")

    def test_repository_symlink_alias_can_still_be_excerpted(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            (repo / "source.py").write_text("print('selected repository')\n", encoding="utf-8")
            alias = Path(tmp) / "alias"
            alias.symlink_to(repo, target_is_directory=True)
            self.assertEqual(render.snippet(alias, "source.py:1")["lines"], ["print('selected repository')"])


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
    def test_pdf_validation_does_not_follow_a_replaced_source(self):
        path = self.out / "report.pdf"
        path.write_bytes(b"not a PDF")
        outside = self.out / "outside.pdf"
        outside.write_bytes(b"%PDF-1.7\n%%EOF\n")
        lstat = Path.lstat

        def replace_after_stat(target, *args, **kwargs):
            info = lstat(target, *args, **kwargs)
            if target == path:
                path.unlink()
                path.symlink_to(outside)
            return info

        with mock.patch.object(Path, "lstat", replace_after_stat):
            self.assertFalse(render.pdf_complete(path))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO checks require POSIX")
    def test_artifact_open_refuses_fifo_without_blocking(self):
        path = self.out / "report.pdf"
        os.mkfifo(path)
        result = subprocess.run([sys.executable, "-c",
                                 "import sys; sys.path.insert(0, sys.argv[1]); import render; "
                                 "assert not render.pdf_complete(sys.argv[2])", str(SCRIPTS), str(path)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_dangling_units_symlink_cannot_disable_validation(self):
        self.render_html()
        originals = {name: (self.out / name).read_bytes() for name in ("dashboard.html", "report.html")}
        units = self.out / "units.json"
        units.unlink()
        units.symlink_to("missing-units.json")
        code, _, error = self.render("--no-pdf")
        self.assertEqual(code, 2, error)
        self.assertIn("units.json", error)
        for name, content in originals.items():
            self.assertEqual((self.out / name).read_bytes(), content)

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

    def test_language_detection_does_not_follow_a_replaced_page(self):
        self.render("--lang", "ja", "--no-pdf")
        path = self.out / "report.html"
        outside = self.out / "outside.html"
        outside.write_text('<html lang="en"><head></head><body></body></html>', encoding="utf-8")
        lstat = Path.lstat

        def replace_after_stat(target, *args, **kwargs):
            info = lstat(target, *args, **kwargs)
            if target == path:
                path.unlink()
                path.symlink_to(outside)
            return info

        with mock.patch.object(Path, "lstat", replace_after_stat):
            self.assertEqual(contract_check.rendered_lang(self.out), "ja")

    def test_contract_rejects_record_replaced_by_symlink_after_inspection(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = self.out / "findings.json"
            outside = Path(tmp) / "findings.json"
            outside.write_bytes(source.read_bytes())
            read_source = contract_check.read_json_source

            def replace_before_read(path, **kwargs):
                if path == source:
                    source.unlink()
                    source.symlink_to(outside)
                return read_source(path, **kwargs)

            with mock.patch.object(contract_check, "read_json_source", side_effect=replace_before_read):
                errors = list(contract_check.problems(self.out, no_pdf=True))
            self.assertTrue(any("record:" in error for error in errors), errors)

    def test_truncated_pages_cannot_satisfy_contract_with_current_stamps(self):
        for name in ("dashboard.html", "report.html"):
            with self.subTest(name=name):
                path = self.out / name
                before = path.read_text(encoding="utf-8")
                path.write_text(before.split("</head>", 1)[0], encoding="utf-8")
                try:
                    errors = list(contract_check.problems(self.out, no_pdf=True))
                    self.assertTrue(any(name in error and "incomplete" in error for error in errors), errors)
                finally:
                    path.write_text(before, encoding="utf-8")

    def test_inert_stamps_do_not_hide_stale_pages(self):
        for name in ("dashboard.html", "report.html"):
            path = self.out / name
            before = path.read_text(encoding="utf-8")
            first = before.index(f'<meta name="{render.STAMP}"')
            last = before.index(">", first) + 1
            for opening, closing in (("<!-- ", " -->"), ("<template>", "</template>"),
                                     ("<script>", "</script>")):
                with self.subTest(name=name, wrapper=opening):
                    page = before[:first] + opening + before[first:last] + closing + before[last:]
                    path.write_text(page, encoding="utf-8")
                    try:
                        errors = list(contract_check.problems(self.out, no_pdf=True))
                        self.assertTrue(any(name in error and "stale" in error for error in errors), errors)
                    finally:
                        path.write_text(before, encoding="utf-8")

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
