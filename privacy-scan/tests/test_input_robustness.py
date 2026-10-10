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
            out = os.path.join(directory, "out\udcff")
            env = {**os.environ, "PYTHONIOENCODING": "utf-8:strict", "PYTHONDONTWRITEBYTECODE": "1"}
            result = subprocess.run(
                [sys.executable, str(SKILL / "scripts" / "render.py"), str(source), "--out", out],
                capture_output=True, env=env, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(os.path.exists(os.path.join(out, "report.md")))


if __name__ == "__main__":
    unittest.main()
