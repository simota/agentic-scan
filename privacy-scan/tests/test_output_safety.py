"""Regression checks for preserving existing results when output writing fails."""
import errno
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from unittest.mock import patch

from test_privacy_scan import SKILL, complete_doc, findings, render

with patch.object(sys, "path", [str(SKILL / "scripts")] + sys.path):
    import output_io


class OutputSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.out = self.root / "output"
        self.out.mkdir()
        original = complete_doc()
        original["meta"]["project"] = "以前の診断"
        self.originals = {
            "findings.json": (json.dumps(original, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
            "report.md": "# 以前の診断\n\n保存済みのレポート。\n".encode("utf-8"),
            "dashboard.html": "<!doctype html><html><body>以前の診断</body></html>\n".encode("utf-8"),
        }
        for name, contents in self.originals.items():
            (self.out / name).write_bytes(contents)

    def call_main(self, main, arguments):
        """Keep assertions about saved bytes reachable even if the CLI crashes."""
        stdout, stderr = io.StringIO(), io.StringIO()
        result, error = None, None
        with redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                result = main(arguments)
            except Exception as exc:
                error = exc
        return result, error, stderr.getvalue()

    def assert_originals_preserved(self):
        self.assertEqual({path.name for path in self.out.iterdir()}, set(self.originals))
        for name, contents in self.originals.items():
            self.assertEqual((self.out / name).read_bytes(), contents, name)

    @contextmanager
    def fail_staging_write(self, fail_at):
        """Leave a real, partially written temporary file for cleanup to handle."""
        real_temporary_file = output_io.NamedTemporaryFile
        created = []

        def temporary_file(*args, **kwargs):
            stream = real_temporary_file(*args, **kwargs)
            created.append(Path(stream.name))
            if len(created) != fail_at:
                return stream

            class FailingWriter:
                name = stream.name

                def __enter__(self):
                    stream.__enter__()
                    return self

                def __exit__(self, *exception):
                    return stream.__exit__(*exception)

                def write(self, contents):
                    stream.write(contents[:1])
                    raise OSError(errno.ENOSPC, "synthetic output write failure")

            return FailingWriter()

        with patch.object(output_io, "NamedTemporaryFile", side_effect=temporary_file):
            yield created

    def test_merge_surrogate_does_not_truncate_existing_results(self):
        fragment = self.root / "fragment.json"
        fragment.write_text(json.dumps({"meta": {"project": "invalid \ud800 text"}}), encoding="utf-8")

        result, error, stderr = self.call_main(
            findings.main, ["merge", str(self.out / "findings.json"), str(fragment)])

        self.assert_originals_preserved()
        self.assertIsNone(error, repr(error))
        self.assertEqual(result, 1)
        self.assertTrue(stderr.strip())

    def test_render_surrogate_does_not_truncate_existing_results(self):
        document = complete_doc()
        document["meta"]["project"] = "invalid \ud800 text"
        source = self.root / "incoming.json"
        source.write_text(json.dumps(document), encoding="utf-8")

        result, error, stderr = self.call_main(
            render.main, [str(source), "--out", str(self.out)])

        self.assert_originals_preserved()
        self.assertIsNone(error, repr(error))
        self.assertEqual(result, 2)
        self.assertTrue(stderr.strip())

    def test_merge_write_failure_preserves_results_and_removes_temporary_file(self):
        fragment = self.root / "fragment.json"
        fragment.write_text(json.dumps({"meta": {"project": "更新する診断"}}), encoding="utf-8")

        with self.fail_staging_write(fail_at=1) as created:
            result, error, stderr = self.call_main(
                findings.main, ["merge", str(self.out / "findings.json"), str(fragment)])

        self.assertEqual(len(created), 1)
        self.assert_originals_preserved()
        self.assertIsNone(error, repr(error))
        self.assertEqual(result, 1)
        self.assertTrue(stderr.strip())
        self.assertTrue(all(not path.exists() for path in created))

    def test_later_render_write_failure_preserves_all_results_and_cleans_up(self):
        document = complete_doc()
        document["meta"]["project"] = "更新する診断"
        source = self.root / "incoming.json"
        source.write_text(json.dumps(document), encoding="utf-8")

        with self.fail_staging_write(fail_at=2) as created:
            result, error, stderr = self.call_main(
                render.main, [str(source), "--out", str(self.out)])

        self.assertEqual(len(created), 2)
        self.assert_originals_preserved()
        self.assertIsNone(error, repr(error))
        self.assertEqual(result, 1)
        self.assertTrue(stderr.strip())
        self.assertTrue(all(not path.exists() for path in created))

    def test_writer_encoding_failure_preserves_every_destination(self):
        replacements = {
            self.out / "report.md": "# 新しいレポート\n",
            self.out / "dashboard.html": "<html>invalid \ud800 text</html>\n",
        }

        with self.assertRaises(UnicodeError):
            output_io.write_utf8_files(replacements)

        self.assert_originals_preserved()

    def test_successful_merge_and_render_preserve_japanese_text(self):
        fragment = self.root / "fragment.json"
        update = {"meta": {"project": "受付情報の診断", "lang": "ja"},
                  "checked_ok": ["削除処理を確認しました。"]}
        fragment.write_text(json.dumps(update, ensure_ascii=False), encoding="utf-8")

        result, error, stderr = self.call_main(
            findings.main, ["merge", str(self.out / "findings.json"), str(fragment)])
        self.assertIsNone(error, repr(error))
        self.assertEqual(result, 0, stderr)
        result, error, stderr = self.call_main(
            render.main, [str(self.out / "findings.json"), "--out", str(self.out)])
        self.assertIsNone(error, repr(error))
        self.assertEqual(result, 0, stderr)

        self.assertEqual({path.name for path in self.out.iterdir()}, set(self.originals))
        for name in self.originals:
            contents = (self.out / name).read_bytes()
            text = contents.decode("utf-8")
            self.assertIn("受付情報の診断", text, name)
            self.assertIn("削除処理を確認しました。", text, name)
            if name != "dashboard.html":
                self.assertTrue(contents.endswith(b"\n"), name)
        saved = json.loads((self.out / "findings.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["meta"]["lang"], "ja")

    def test_merge_and_render_preserve_relative_symlinks_and_target_mode(self):
        stored = self.root / "stored"
        stored.mkdir()
        links = {}
        for name in self.originals:
            output = self.out / name
            output.replace(stored / name)
            links[name] = Path("..") / stored.name / name
            output.symlink_to(links[name])
        (stored / "report.md").chmod(0o640)
        fragment = self.root / "fragment.json"
        fragment.write_text(json.dumps({"meta": {"project": "リンク先の診断", "lang": "ja"}}),
                            encoding="utf-8")

        result, error, stderr = self.call_main(
            findings.main, ["merge", str(self.out / "findings.json"), str(fragment)])
        self.assertIsNone(error, repr(error))
        self.assertEqual(result, 0, stderr)
        result, error, stderr = self.call_main(
            render.main, [str(self.out / "findings.json"), "--out", str(self.out)])
        self.assertIsNone(error, repr(error))
        self.assertEqual(result, 0, stderr)

        for name, relative_target in links.items():
            with self.subTest(name=name):
                output, target = self.out / name, stored / name
                self.assertTrue(output.is_symlink())
                self.assertEqual(output.readlink(), relative_target)
                self.assertNotEqual(target.read_bytes(), self.originals[name])
                self.assertIn("リンク先の診断", target.read_text(encoding="utf-8"))
                self.assertEqual(output.read_bytes(), target.read_bytes())
        self.assertEqual(stat.S_IMODE((stored / "report.md").stat().st_mode), 0o640)
        for directory in (self.out, stored):
            self.assertEqual({path.name for path in directory.iterdir()}, set(self.originals))

    def test_merge_and_render_create_missing_relative_symlink_targets(self):
        stored = self.root / "stored"
        stored.mkdir()
        links = {}
        for name in self.originals:
            output = self.out / name
            output.unlink()
            links[name] = Path("..") / stored.name / name
            output.symlink_to(links[name])
        document = complete_doc()
        document["meta"].update(project="新しいリンク先の診断", lang="ja")
        fragment = self.root / "fragment.json"
        fragment.write_text(json.dumps(document), encoding="utf-8")

        result, error, stderr = self.call_main(
            findings.main, ["merge", str(self.out / "findings.json"), str(fragment)])
        self.assertIsNone(error, repr(error))
        self.assertEqual(result, 0, stderr)
        result, error, stderr = self.call_main(
            render.main, [str(self.out / "findings.json"), "--out", str(self.out)])
        self.assertIsNone(error, repr(error))
        self.assertEqual(result, 0, stderr)

        for name, relative_target in links.items():
            with self.subTest(name=name):
                output, target = self.out / name, stored / name
                self.assertTrue(output.is_symlink())
                self.assertEqual(output.readlink(), relative_target)
                self.assertTrue(target.is_file())
                self.assertIn("新しいリンク先の診断", target.read_text(encoding="utf-8"))
                self.assertEqual(output.read_bytes(), target.read_bytes())
        for directory in (self.out, stored):
            self.assertEqual({path.name for path in directory.iterdir()}, set(self.originals))


if __name__ == "__main__":
    unittest.main()
