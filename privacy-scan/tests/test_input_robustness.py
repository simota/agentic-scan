"""Regressions for interrupted writes, special or oversized inputs, and safe status output."""
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_privacy_scan import SKILL, complete_doc, findings, render


class InputTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs FIFOs")
    def test_fifo_fragments_are_refused_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "fragment.json"
            os.mkfifo(fifo)
            result = subprocess.run(
                [sys.executable, "-I", str(SKILL / "scripts" / "findings.py"), "merge",
                 str(Path(directory) / "findings.json"), str(fifo)],
                capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 1)
            self.assertIn("must be a regular file", result.stderr)

    def test_oversized_inputs_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fragment.json"
            with path.open("wb") as stream:
                stream.truncate(findings.MAX_INPUT_BYTES + 1)
            with self.assertRaises(findings.SchemaError) as raised:
                findings.read_json(path)
            self.assertIn("larger than", str(raised.exception))

    def test_oversized_outputs_are_reported_as_stale_without_reading_them(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            (out / "findings.json").write_text(json.dumps(complete_doc()), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                render.main([str(out / "findings.json"), "--out", str(out)])
            with (out / "report.md").open("r+b") as stream:
                stream.truncate(findings.MAX_INPUT_BYTES + 1)
            self.assertTrue(any(p.startswith("stale outputs")
                                for p in findings.contract_problems(out)))


class BlankOutputDirectoryTests(unittest.TestCase):
    def test_a_blank_out_is_refused_instead_of_writing_into_the_working_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / "findings.json"
            record.write_text(json.dumps(complete_doc()), encoding="utf-8")
            cwd = Path(directory) / "repo"
            cwd.mkdir()
            for out in ("", "  "):
                with self.subTest(out=out):
                    result = subprocess.run(
                        [sys.executable, "-I", str(SKILL / "scripts" / "render.py"), str(record),
                         "--out", out], cwd=cwd, capture_output=True, text=True, timeout=60)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn("--out must name the output directory", result.stderr)
                    self.assertEqual(list(cwd.iterdir()), [])


class InterruptedWriteTests(unittest.TestCase):
    def test_leftover_staging_files_are_named_as_such(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            (out / "findings.json").write_text(json.dumps(complete_doc()), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                render.main([str(out / "findings.json"), "--out", str(out)])
            (out / ".report.md.k2j3_x.tmp").write_text("partial", encoding="utf-8")
            problems = findings.contract_problems(out)
            self.assertIn("stale staging file from an interrupted write: .report.md.k2j3_x.tmp "
                          "(delete it)", problems)
            self.assertFalse(any("--allow" in p for p in problems))

    @unittest.skipUnless(hasattr(os, "symlink"), "needs symlinks")
    def test_a_link_named_like_a_staging_file_never_names_its_target_for_deletion(self):
        with tempfile.TemporaryDirectory() as directory:
            out, keep = Path(directory) / "out", Path(directory) / "keep"
            out.mkdir()
            keep.mkdir()
            (out / "findings.json").write_text(json.dumps(complete_doc()), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                render.main([str(out / "findings.json"), "--out", str(out)])
            (keep / "precious.txt").write_text("unrelated", encoding="utf-8")
            (out / ".report.md.k2j3_x.tmp").symlink_to(keep / "precious.txt")
            problems = findings.contract_problems(out)
            self.assertFalse(any("precious.txt" in p for p in problems), problems)
            self.assertIn("unexpected output: .report.md.k2j3_x.tmp "
                          "(pass --allow .report.md.k2j3_x.tmp if requested)", problems)

    @unittest.skipUnless(hasattr(signal, "SIGTERM") and os.name == "posix", "needs POSIX signals")
    def test_sigterm_during_a_write_removes_staging_files(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            # Block inside the write: the second staged file waits on a slow stream.
            script = (
                "import sys, time, pathlib\n"
                f"sys.path.insert(0, {str(SKILL / 'scripts')!r})\n"
                "import findings, output_io\n"
                "findings.prepare_cli()\n"
                "real = output_io.NamedTemporaryFile\n"
                "class Slow:\n"
                "    def __init__(self, *a, **k): self.f = real(*a, **k)\n"
                "    def __enter__(self): return self\n"
                "    def __exit__(self, *e): return self.f.__exit__(*e)\n"
                "    @property\n"
                "    def name(self): return self.f.name\n"
                "    def write(self, data):\n"
                "        self.f.write(data); self.f.flush()\n"
                "        if pathlib.Path(self.f.name).name.startswith('.b'):\n"
                "            print('ready', flush=True); time.sleep(30)\n"
                "output_io.NamedTemporaryFile = Slow\n"
                f"out = pathlib.Path({str(out)!r})\n"
                "output_io.write_utf8_files({out / 'a.txt': 'a', out / 'b.txt': 'b'})\n")
            process = subprocess.Popen([sys.executable, "-I", "-c", script],
                                       stdout=subprocess.PIPE, text=True)
            self.assertEqual(process.stdout.readline().strip(), "ready")
            self.assertTrue(any(p.suffix == ".tmp" for p in out.iterdir()))
            process.send_signal(signal.SIGTERM)
            self.assertEqual(process.wait(timeout=20), 128 + signal.SIGTERM)
            process.stdout.close()
            self.assertEqual(list(out.iterdir()), [])


class StatusOutputTests(unittest.TestCase):
    def test_unencodable_paths_do_not_turn_success_into_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "findings.json"
            source.write_text(json.dumps(complete_doc()), encoding="utf-8")
            # Every filesystem accepts this name, but a strict ASCII stdout cannot print it
            # (APFS, for one, refuses non-UTF-8 names such as surrogate escapes).
            out = os.path.join(directory, "out-\u00e9")
            env = {**os.environ, "PYTHONIOENCODING": "ascii:strict", "PYTHONDONTWRITEBYTECODE": "1"}
            result = subprocess.run(
                [sys.executable, str(SKILL / "scripts" / "render.py"), str(source), "--out", out],
                capture_output=True, env=env, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(os.path.exists(os.path.join(out, "report.md")))


if __name__ == "__main__":
    unittest.main()


class ReviewFollowUpTests(unittest.TestCase):
    def render_into(self, out):
        (out / "findings.json").write_text(json.dumps(complete_doc()), encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            render.main([str(out / "findings.json"), "--out", str(out)])

    def test_staging_files_beside_symlink_targets_are_found(self):
        with tempfile.TemporaryDirectory() as directory:
            # check reports resolved paths (on macOS, /var is a link to /private/var).
            root = Path(directory).resolve()
            out, stored = root / "out", root / "stored [v1]"
            out.mkdir()
            stored.mkdir()
            self.render_into(out)
            # report.md becomes a link to a differently named file in another directory.
            (out / "report.md").replace(stored / "assessment.md")
            (out / "report.md").symlink_to(stored / "assessment.md")
            (stored / ".assessment.md.k2j3_x.tmp").write_text("partial", encoding="utf-8")
            # Inside the output directory, a linked target's staging file is named after it.
            (out / "dashboard.html").replace(out / "board.html")
            (out / "dashboard.html").symlink_to(out / "board.html")
            (out / ".board.html.q9_z.tmp").write_text("partial", encoding="utf-8")
            problems = findings.contract_problems(out, allow=["board.html"])
            self.assertIn("stale staging file from an interrupted write: "
                          f"{stored / '.assessment.md.k2j3_x.tmp'} (delete it)", problems)
            self.assertIn("stale staging file from an interrupted write: .board.html.q9_z.tmp "
                          "(delete it)", problems)
            self.assertFalse(any("--allow .board" in p for p in problems), problems)

    def test_malformed_steps_are_refused(self):
        for step in ("LT2 extra", "lt2", "logs"):
            with self.subTest(step=step):
                doc = complete_doc()
                doc["findings"][0]["step"] = step
                self.assertTrue(any(p.startswith("PV-001.step: must be one hunt step ID")
                                    for p in findings.record_problems(doc)))
        doc = complete_doc()
        doc["findings"][0]["step"] = " "
        self.assertEqual(findings.record_problems(doc), [])


class CodeReviewFollowUpTests(unittest.TestCase):
    def test_symlink_loops_in_the_output_directory_do_not_crash_check(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory).resolve()
            (out / "findings.json").write_text(json.dumps(complete_doc()), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                render.main([str(out / "findings.json"), "--out", str(out)])
            (out / "loop").symlink_to(out / "loop")
            self.assertIn("unexpected output: loop (pass --allow loop if requested)",
                          findings.contract_problems(out))

    def test_cli_setup_works_outside_the_main_thread(self):
        import threading
        errors = []
        worker = threading.Thread(target=lambda: errors.append(
            None if findings.prepare_cli() is None else "unexpected"))
        worker.start()
        worker.join()
        self.assertEqual(errors, [None])

    def test_check_accepts_exactly_the_order_renumber_produces(self):
        doc = complete_doc()
        doc["findings"][0]["validation"] = {"verdict": "FalsePositive", "method": "static",
                                            "evidence": "scrubber at app.py:30"}
        problems = findings.record_problems(doc)
        self.assertTrue(any("excluded findings last" in p for p in problems), problems)
        findings.renumber(doc)
        self.assertEqual(findings.record_problems(doc), [])
        self.assertEqual([findings.excluded(f) for f in doc["findings"]], [False, True])

    def test_missing_inputs_name_the_path_once(self):
        with self.assertRaises(findings.SchemaError) as raised:
            findings.read_json("/nonexistent/fragment.json")
        self.assertEqual(str(raised.exception).count("fragment.json"), 1)
