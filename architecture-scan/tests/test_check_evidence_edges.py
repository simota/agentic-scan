"""False accepts and a hang in `check`: evidence that is not a citation, odd locations."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_architecture_scan import SKILL, findings


class EvidenceTests(unittest.TestCase):
    def test_a_word_ending_in_file_is_not_a_build_file(self):
        for evidence in ("confirmed in the file:12 entry", "see profile:3", "the logfile:40 line"):
            with self.subTest(evidence=evidence):
                self.assertFalse(findings.cites_line(evidence))
        for evidence in ("Makefile:12", "makefile:3", "GNUmakefile:2", "Dockerfile:3",
                         "Jenkinsfile:9", "Gemfile:4", "Procfile:1", "Dockerfile.dev:2",
                         "justfile:3", "rakefile:3", "vagrantfile:3"):
            with self.subTest(evidence=evidence):
                self.assertTrue(findings.cites_line(evidence))

    def test_a_url_port_after_credentials_is_not_a_line(self):
        for evidence in ("connects to postgres://app:secret@db.example.org:5432/app",
                         "amqp://guest:guest@rabbit.svc:5672/", "redis://:pw@cache.local:6379"):
            with self.subTest(evidence=evidence):
                self.assertFalse(findings.cites_line(evidence))
        # A citation beside a URL still counts.
        self.assertTrue(findings.cites_line("postgres://app:pw@db.svc:5432 is read at app/db.py:7"))


class LocationTests(unittest.TestCase):
    def test_a_location_in_another_letter_case_is_missing(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            (repo / "worker").mkdir()
            (repo / "worker" / "job.py").write_text("x = 1\n", encoding="utf-8")
            for loc, ok in (("worker/job.py:1", True), ("./worker/job.py:1", True),
                            ("WORKER/job.py:1", False), ("worker/JOB.PY:1", False)):
                with self.subTest(location=loc):
                    doc = {"findings": [{"id": "A-001", "location": [loc]}]}
                    self.assertEqual(findings.location_problems(doc, repo) == [], ok)
            # Either Unicode form of a name on disk names that file.
            (repo / "worker" / "ga\u0301.py").write_text("x = 1\n", encoding="utf-8")
            for loc in ("worker/ga\u0301.py:1", "worker/g\u00e1.py:1"):
                with self.subTest(location=loc):
                    doc = {"findings": [{"id": "A-001", "location": [loc]}]}
                    self.assertEqual(findings.location_problems(doc, repo), [])
            # An absolute path inside the checkout was accepted before and still is.
            inside = f"{repo.resolve()}/worker/job.py:1"
            self.assertEqual(findings.location_problems({"findings": [{"id": "A-001", "location": [inside]}]}, repo), [])


@unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFOs")
class FifoTests(unittest.TestCase):
    def test_check_with_repo_reports_a_fifo_record_instead_of_hanging(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "out"
            out.mkdir()
            os.mkfifo(out / "findings.json")
            (out / "report.md").write_text("", encoding="utf-8")
            (out / "dashboard.html").write_text("", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SKILL / "scripts" / "findings.py"), "check", str(out),
                 "--repo", d], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("output is not a file: findings.json", result.stderr)


if __name__ == "__main__":
    unittest.main()
