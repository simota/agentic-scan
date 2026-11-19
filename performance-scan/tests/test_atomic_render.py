"""Failed report generation must preserve both existing output artifacts."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

try:
    import resource
except ImportError:
    resource = None

from support import OUTPUTS as LEGACY_OUTPUTS, SKILL, complete_doc, render, run_cli, run_main


OUTPUTS = (*LEGACY_OUTPUTS, "assessment.html")


class AtomicRenderTests(unittest.TestCase):
    def run_render(self, source, out):
        result, _, errors = run_main(render.main, source, "--out", out)
        return result, errors

    def prepare(self, root, existing=True, project="Updated project"):
        # Resolved: render.py writes to real paths, and macOS temp dirs sit behind
        # /tmp and /var symlinks that would make the os.replace patches miss.
        root = root.resolve()
        source = root / "findings.json"
        out = root / "reports"
        out.mkdir()
        doc = complete_doc()
        source.write_text(json.dumps(doc), encoding="utf-8")
        if existing:
            result, errors = self.run_render(source, out)
            self.assertEqual(result, 0, errors)
        doc["meta"]["project"] = project
        # Escaped surrogates remain valid JSON and reach the UTF-8 encoder.
        source.write_text(json.dumps(doc), encoding="utf-8")
        return source, out, doc

    def snapshot(self, out):
        return {name: (out / name).read_bytes() for name in OUTPUTS if (out / name).exists()}

    def assert_unchanged(self, out, original):
        self.assertEqual(self.snapshot(out), original)
        self.assertEqual({path.name for path in out.iterdir()}, set(original))

    def assert_render_failure(self, result, errors):
        self.assertEqual(result, 1, errors)
        self.assertIn("render:", errors)
        self.assertNotIn("Traceback", errors)

    def render_with_file_limit(self, source, out, limit):
        child = (
            "import resource, signal, sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "import render\n"
            "_, hard = resource.getrlimit(resource.RLIMIT_FSIZE)\n"
            "resource.setrlimit(resource.RLIMIT_FSIZE, (int(sys.argv[4]), hard))\n"
            "signal.signal(signal.SIGXFSZ, signal.SIG_IGN)\n"
            "sys.exit(render.main([sys.argv[2], '--out', sys.argv[3]]))\n"
        )
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            [sys.executable, "-c", child, str(SKILL / "scripts"), str(source), str(out), str(limit)],
            capture_output=True, text=True, check=False, timeout=15, env=env)

    @unittest.skipUnless(resource is not None and hasattr(resource, "RLIMIT_FSIZE"),
                         "requires a per-process file size limit")
    def test_partial_write_failure_preserves_existing_or_absent_outputs(self):
        for existing in (True, False):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as d:
                source, out, doc = self.prepare(Path(d), existing)
                original = self.snapshot(out)
                self.assertGreater(len(render.render_markdown(doc, "en").encode("utf-8")), 1024)
                result = self.render_with_file_limit(source, out, 1024)
                self.assert_unchanged(out, original)
                self.assert_render_failure(result.returncode, result.stderr)

    @unittest.skipUnless(resource is not None and hasattr(resource, "RLIMIT_FSIZE"),
                         "requires a per-process file size limit")
    def test_dashboard_write_failure_after_report_staging_preserves_both_outputs(self):
        for existing in (True, False):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as d:
                source, out, doc = self.prepare(Path(d), existing)
                original = self.snapshot(out)
                report_size = len(render.render_markdown(doc, "en").encode("utf-8"))
                dashboard_size = len(render.render_html(doc, "en").encode("utf-8"))
                limit = (report_size + dashboard_size) // 2
                self.assertLess(report_size, limit)
                self.assertLess(limit, dashboard_size)
                result = self.render_with_file_limit(source, out, limit)
                self.assert_unchanged(out, original)
                self.assert_render_failure(result.returncode, result.stderr)

    def test_second_publish_failure_restores_existing_or_absent_outputs(self):
        for existing in (True, False):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as d:
                source, out, _ = self.prepare(Path(d), existing)
                original = self.snapshot(out)
                real_replace = os.replace
                first_report = []

                def fail_dashboard_once(source, destination):
                    if Path(destination) == out / "dashboard.html" and not first_report:
                        first_report.append((out / "report.md").read_bytes())
                        raise OSError("dashboard publish refused")
                    return real_replace(source, destination)

                with patch("os.replace", side_effect=fail_dashboard_once):
                    result, errors = self.run_render(source, out)
                self.assertEqual(len(first_report), 1)
                self.assertIn(b"Updated project", first_report[0])
                self.assert_unchanged(out, original)
                self.assert_render_failure(result, errors)
                self.assertIn("dashboard publish refused", errors)

    def test_interrupt_after_publish_restores_existing_or_absent_outputs(self):
        for existing in (True, False):
            for interrupt_after in range(1, len(OUTPUTS) + 1):
                with self.subTest(existing=existing, interrupt_after=interrupt_after), \
                        tempfile.TemporaryDirectory() as d:
                    source, out, _ = self.prepare(Path(d), existing)
                    original = self.snapshot(out)
                    real_replace = os.replace
                    published = []

                    def interrupt_after_publish(source, destination):
                        result = real_replace(source, destination)
                        if len(published) < interrupt_after:
                            published.append(Path(destination).read_bytes())
                            if len(published) == interrupt_after:
                                raise KeyboardInterrupt("publish interrupted")
                        return result

                    with patch("os.replace", side_effect=interrupt_after_publish), \
                            self.assertRaisesRegex(KeyboardInterrupt, "publish interrupted"):
                        self.run_render(source, out)
                    self.assertEqual(len(published), interrupt_after)
                    self.assertTrue(all(b"Updated project" in content for content in published))
                    self.assert_unchanged(out, original)

    def test_unencodable_text_preserves_existing_or_absent_outputs(self):
        for existing in (True, False):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as d:
                source, out, _ = self.prepare(Path(d), existing, project="\ud800")
                original = self.snapshot(out)
                result = run_cli("render.py", source, "--out", out)
                self.assert_unchanged(out, original)
                self.assert_render_failure(result.returncode, result.stderr)

    @unittest.skipUnless(os.name == "posix", "requires POSIX permission bits")
    def test_success_preserves_existing_output_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            source, out, _ = self.prepare(Path(d))
            modes = {"report.md": 0o640, "dashboard.html": 0o600, "assessment.html": 0o640}
            for name, mode in modes.items():
                (out / name).chmod(mode)
            result, errors = self.run_render(source, out)
            self.assertEqual(result, 0, errors)
            for name, mode in modes.items():
                self.assertEqual(stat.S_IMODE((out / name).stat().st_mode), mode)
                self.assertIn(b"Updated project", (out / name).read_bytes())
            self.assertEqual({path.name for path in out.iterdir()}, set(OUTPUTS))

    def test_success_updates_output_symlink_destinations_without_replacing_links(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            source, out, _ = self.prepare(root)
            destinations = root / "published files"
            destinations.mkdir()
            for name in OUTPUTS:
                (out / name).rename(destinations / name)
                try:
                    (out / name).symlink_to(Path("..") / destinations.name / name)
                except (OSError, NotImplementedError):
                    self.skipTest("symbolic links are unavailable")
            result, errors = self.run_render(source, out)
            self.assertEqual(result, 0, errors)
            for name in OUTPUTS:
                self.assertTrue((out / name).is_symlink())
                self.assertEqual((out / name).readlink(), Path("..") / destinations.name / name)
                self.assertIn(b"Updated project", (destinations / name).read_bytes())
                self.assertEqual((out / name).read_bytes(), (destinations / name).read_bytes())
            self.assertEqual({path.name for path in destinations.iterdir()}, set(OUTPUTS))
            self.assertEqual({path.name for path in out.iterdir()}, set(OUTPUTS))

    def test_rollback_failure_retains_original_backup_and_reports_its_path(self):
        with tempfile.TemporaryDirectory() as d:
            source, out, _ = self.prepare(Path(d))
            original = self.snapshot(out)
            real_replace = os.replace
            report_replacements = []

            def fail_publish_and_rollback(source, destination):
                if Path(destination) == out / "dashboard.html":
                    raise OSError("dashboard publish refused")
                if Path(destination) == out / "report.md":
                    report_replacements.append(Path(source))
                    if len(report_replacements) == 2:
                        raise OSError("report rollback refused")
                return real_replace(source, destination)

            with patch("os.replace", side_effect=fail_publish_and_rollback):
                result, errors = self.run_render(source, out)
            self.assert_render_failure(result, errors)
            self.assertEqual(len(report_replacements), 2)
            recovery = report_replacements[1]
            self.assertTrue(recovery.is_file(), errors)
            self.assertEqual(recovery.read_bytes(), original["report.md"])
            self.assertIn(str(recovery), errors)
            self.assertIn("report rollback refused", errors)
            self.assertEqual((out / "dashboard.html").read_bytes(), original["dashboard.html"])
            self.assertIn(b"Updated project", (out / "report.md").read_bytes())
            self.assertEqual({path for path in out.rglob("*") if path.is_file()},
                             {*(out / name for name in OUTPUTS), recovery})

    def test_schema_failure_keeps_exit_code_two_and_preserves_outputs(self):
        with tempfile.TemporaryDirectory() as d:
            source, out, doc = self.prepare(Path(d))
            original = self.snapshot(out)
            doc["findings"][0]["severity"] = "Critical"
            source.write_text(json.dumps(doc), encoding="utf-8")
            result, errors = self.run_render(source, out)
            self.assertEqual(result, 2)
            self.assertIn("schema:", errors)
            self.assertNotIn("Traceback", errors)
            self.assert_unchanged(out, original)


if __name__ == "__main__":
    unittest.main()
