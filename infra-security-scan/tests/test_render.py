import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-security-scan" / "scripts"))
import excerpts  # noqa: E402
import render  # noqa: E402

SAMPLE = REPO / "examples" / "findings.sample.json"
SAMPLE_JA = REPO / "examples" / "findings.sample.ja.json"


def sample():
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


def problems(data, partial=False):
    try:
        render.validate(data, partial=partial)
    except render.SchemaError as e:
        return e.problems
    return []


def run(argv):
    err = io.StringIO()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
        code = render.main(argv)
    return code, err.getvalue()


class ModuleBoundaryTest(unittest.TestCase):
    """The record tools validate and render without the scanner's parsers."""

    def loaded(self, module):
        import subprocess
        code = f"import sys, {module}; print(' '.join(sorted(m for m in ('iac_scan', 'excerpts') if m in sys.modules)))"
        return subprocess.run([sys.executable, "-I", "-c", f"import sys; sys.path.insert(0, {str(render.SKILL / 'scripts')!r}); {code}"],
                              capture_output=True, text=True, check=True).stdout.strip()

    def test_record_tools_do_not_load_the_scanner(self):
        for module in ("render", "findings", "contract_check"):
            with self.subTest(module=module):
                self.assertEqual(self.loaded(module), "")

    def test_excerpts_reuse_the_scanner_parsers(self):
        self.assertEqual(self.loaded("excerpts"), "excerpts iac_scan")


class ValidateTest(unittest.TestCase):
    def test_samples_validate(self):
        for path in (SAMPLE, SAMPLE_JA):
            with self.subTest(path=path.name):
                self.assertEqual(problems(render.load(path)), [])

    def test_perspective_names_come_from_reference(self):
        names = render.perspective_names()
        self.assertEqual(len(names), 13)
        self.assertIn("Pipeline and state", names)

    def test_enums_and_required_fields(self):
        data = sample()
        f = data["findings"][0]
        f["severity"] = "Critical"
        f["category"] = "Not a perspective"
        del f["actor"]
        data["findings"][6]["rule"] = ""
        found = "\n".join(problems(data))
        self.assertIn("severity must be one of", found)
        self.assertIn("category must be a perspective", found)
        self.assertIn("F-001: actor required", found)
        self.assertIn("I-001: rule required", found)

    def test_environment_dependent_needs_condition(self):
        data = sample()
        del data["findings"][3]["condition"]
        self.assertIn("F-004: condition required when confidence is Environment-dependent", problems(data))

    def test_valid_confirmed_needs_cited_edges(self):
        data = sample()
        data["findings"][0]["path"] += "\n4. Objects are listed by anyone"
        self.assertTrue(any("path:line on every edge" in p for p in problems(data)))

    def test_attack_path_references(self):
        data = sample()
        data["attack_paths"][0]["findings"].append("F-099")
        data["findings"][1]["attack_paths"] = ["AP-09"]
        data["attack_paths"][2]["note"] = ""
        found = "\n".join(problems(data))
        self.assertIn("AP-01: finding F-099 does not exist", found)
        self.assertIn("F-002: attack path AP-09 does not exist", found)
        self.assertIn("AP-03: note must name", found)

    def test_each_edge_is_cited_or_unknown(self):
        data = sample()
        data["attack_paths"][0]["edges"] = ["Internet reaches the service", "Role reads the table (iam.tf:4)"]
        self.assertIn("AP-01: edge 1 cites no path:line and is not marked UNKNOWN", problems(data, partial=True))
        # An UNKNOWN edge, with what would decide it, leaves the path unknown, not open.
        data["attack_paths"][0]["edges"][0] = "UNKNOWN: the WAF in front of the ALB is not in the inputs"
        self.assertIn("AP-01: an UNKNOWN edge makes the path unknown, not open", problems(data, partial=True))
        data["attack_paths"][0]["edges"][0] = "UNKNOWN: listener reachability depends on the deployment (alb.tf:12)"
        self.assertIn("AP-01: an UNKNOWN edge makes the path unknown, not open", problems(data, partial=True))
        data["attack_paths"][0].update(status="unknown", note="The WAF is not in the inputs")
        self.assertFalse([p for p in problems(data, partial=True) if p.startswith("AP-01")])

    def test_references_must_be_https_without_credentials(self):
        data = sample()
        data["findings"][0]["references"] = [{"title": "x", "url": "http://example.com"},
                                             {"title": "y", "url": "https://user:pw@example.com/"}]
        found = [p for p in problems(data) if "references" in p]
        self.assertEqual(len(found), 2)

    def test_evidence_required_for_definitive_verdicts(self):
        data = sample()
        data["findings"][2]["validation"] = {"verdict": "FalsePositive", "evidence": " "}
        self.assertIn("F-003: validation.evidence required for FalsePositive", problems(data))

    def test_partial_skips_meta(self):
        data = render.empty_record()
        self.assertEqual(problems(data, partial=True), [])
        self.assertIn("meta.project: required", problems(data))

    def test_unknown_top_level_and_bad_ids(self):
        data = sample()
        data["extra"] = 1
        data["findings"][0]["id"] = "X-1"
        found = "\n".join(problems(data))
        self.assertIn("unknown top-level keys", found)
        self.assertIn("id must be F-NNN or I-NNN", found)

    def test_attack_path_ids_can_grow_past_two_digits(self):
        data = sample()
        data["attack_paths"][0]["id"] = "AP-100"
        for finding in data["findings"]:
            if "attack_paths" in finding:
                finding["attack_paths"] = ["AP-100" if aid == "AP-01" else aid
                                            for aid in finding["attack_paths"]]
        self.assertEqual(problems(data), [])

    def test_minimum_id_widths_still_required(self):
        for fid in ("F-01", "I-99"):
            with self.subTest(fid=fid):
                data = sample()
                data["findings"][0]["id"] = fid
                self.assertTrue(any("at least three digits" in p for p in problems(data)))
        data = sample()
        data["attack_paths"][0]["id"] = "AP-9"
        self.assertTrue(any("at least two digits" in p for p in problems(data)))


class RenderTest(unittest.TestCase):
    def test_finding_order_uses_numeric_suffix_within_each_prefix(self):
        data = [{"id": fid, "severity": "High"}
                for fid in ("I-1000", "F-1000", "I-999", "F-999", "I-002")]
        self.assertEqual([f["id"] for f in render.ordered(data)],
                         ["F-999", "F-1000", "I-002", "I-999", "I-1000"])

    def test_render_english_escapes_markup(self):
        data = sample()
        data["findings"][0]["title"] = "Bucket <b>open</b> & public"
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "f.json"
            src.write_text(json.dumps(data), encoding="utf-8")
            out = Path(tmp) / "out"
            code, _ = run([str(src), "--out", str(out), "--no-pdf"])
            self.assertEqual(code, 0)
            dash = (out / "dashboard.html").read_text(encoding="utf-8")
            report = (out / "assessment.html").read_text(encoding="utf-8")
            for page in (dash, report):
                self.assertNotIn("<b>open</b>", page)
                self.assertIn("Bucket &lt;b&gt;open&lt;/b&gt; &amp; public", page)
            self.assertIn("AP-02", dash)
            self.assertIn('id="f-sev"', dash)
            self.assertIn("prefers-color-scheme:dark", dash)
            self.assertFalse((out / "assessment.pdf").exists())

    def test_markdown_payload_cannot_close_script(self):
        data = sample()
        data["findings"][0]["impact"] = "Expected: closed. Actual: </script> appears"
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "f.json"
            src.write_text(json.dumps(data), encoding="utf-8")
            run([str(src), "--out", tmp, "--no-pdf"])
            dash = (Path(tmp) / "dashboard.html").read_text(encoding="utf-8")
            md_block = dash.split('<script type="application/json" id="md">')[1].split("</script>")[0]
            self.assertIn("\\u003c/script\\u003e", md_block)
            self.assertNotIn("<", md_block)

    def test_comment_opener_cannot_swallow_dashboard_script(self):
        # "<!--<script>" switches the HTML tokenizer to the double-escaped
        # state, in which the real </script> no longer closes the data block.
        data = sample()
        data["findings"][0]["title"] = "web<!--<script>"
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "f.json"
            src.write_text(json.dumps(data), encoding="utf-8")
            run([str(src), "--out", tmp, "--no-pdf"])
            dash = (Path(tmp) / "dashboard.html").read_text(encoding="utf-8")
            md_block = dash.split('<script type="application/json" id="md">')[1].split("</script>")[0]
            self.assertNotIn("<!--", md_block)
            self.assertNotIn("<script", md_block)

    def test_render_japanese_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _ = run([str(SAMPLE_JA), "--out", tmp, "--lang", "ja", "--no-pdf"])
            self.assertEqual(code, 0)
            dash = (Path(tmp) / "dashboard.html").read_text(encoding="utf-8")
            report = (Path(tmp) / "assessment.html").read_text(encoding="utf-8")
            self.assertIn('lang="ja"', dash)
            self.assertIn("攻撃経路", dash)
            self.assertIn("LLM用にコピー", dash)
            self.assertIn("除外した検出事項", report)
            self.assertIn("誤検知", report)

    def test_schema_error_exits_2(self):
        data = sample()
        data["findings"][0]["severity"] = "Critical"
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "f.json"
            src.write_text(json.dumps(data), encoding="utf-8")
            code, err = run([str(src), "--out", str(Path(tmp) / "out"), "--no-pdf"])
            self.assertEqual(code, 2)
            self.assertIn("severity", err)
            self.assertFalse((Path(tmp) / "out").exists())

    def test_duplicate_keys_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "f.json"
            src.write_text('{"schema_version": 1, "schema_version": 1}', encoding="utf-8")
            code, err = run([str(src), "--out", tmp, "--no-pdf"])
            self.assertEqual(code, 2)
            self.assertIn("duplicate", err)


class PdfTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name)
        self.pdf = self.out / "assessment.pdf"
        self.pdf.write_bytes(b"previous assessment")
        self.html = self.out / "assessment.html"
        self.html.write_text("<html><body>Current assessment</body></html>", encoding="utf-8")
        self.env = patch.dict(os.environ, {"CHROME": ""})
        self.env.start()
        self.addCleanup(self.env.stop)
        candidates = patch.object(render.report_pdf, "CHROME_CANDIDATES", ["test-chrome"])
        candidates.start()
        self.addCleanup(candidates.stop)

    def test_missing_engines_remove_the_previous_pdf_on_rerender(self):
        with patch.object(shutil, "which", return_value=None):
            code, err = run([str(SAMPLE), "--out", str(self.out)])
        self.assertEqual(code, 0)
        self.assertIn("PDF not generated", err)
        # The warning names the next steps SKILL.md prescribes.
        self.assertIn("re-render with --no-pdf", err)
        self.assertIn("contract_check.py OUT --no-pdf", err)
        self.assertIn(sample()["meta"]["project"], self.html.read_text(encoding="utf-8"))
        self.assertTrue((self.out / "dashboard.html").exists())
        self.assertFalse(self.pdf.exists())

    def test_no_pdf_removes_the_previous_pdf_without_running_an_engine(self):
        with patch.object(render, "to_pdf") as generate:
            code, err = run([str(SAMPLE), "--out", str(self.out), "--no-pdf"])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        generate.assert_not_called()
        self.assertFalse(self.pdf.exists())

    def engine(self, name, body):
        """A fake PDF engine on PATH: the kit runs real processes, so fake them, not its internals."""
        bin_dir = self.out / "bin"
        bin_dir.mkdir(exist_ok=True)
        exe = bin_dir / name
        exe.write_text(
            "#!" + sys.executable + "\n"
            "import sys\nfrom pathlib import Path\n"
            "out = Path(next((a.split('=', 1)[1] for a in sys.argv[1:] "
            "if a.startswith('--print-to-pdf=')), sys.argv[-1]))\n" + body + "\n",
            encoding="utf-8",
        )
        exe.chmod(0o755)
        return exe

    def test_successful_chrome_output_replaces_the_previous_pdf(self):
        chrome = self.engine("chrome", "out.write_bytes(b'%PDF-1.7\\ncurrent chrome assessment\\n%%EOF\\n')")
        with patch.dict(os.environ, {"CHROME": str(chrome), "PATH": str(chrome.parent)}):
            self.assertEqual(render.to_pdf(self.html, self.pdf), "chrome")
        self.assertEqual(self.pdf.read_bytes(), b"%PDF-1.7\ncurrent chrome assessment\n%%EOF\n")

    def test_failed_chrome_output_is_discarded_before_weasyprint_fallback(self):
        chrome = self.engine("chrome", "out.write_bytes(b'%PDF-1.7\\npartial chrome output'); sys.exit(1)")
        self.engine("weasyprint", "out.write_bytes(b'%PDF-1.7\\ncurrent assessment\\n%%EOF\\n')")
        failures = []
        with patch.dict(os.environ, {"CHROME": str(chrome), "PATH": str(chrome.parent)}):
            self.assertEqual(render.to_pdf(self.html, self.pdf, failures), "weasyprint")
        self.assertTrue(failures[0].startswith("chrome"), failures)
        self.assertEqual(self.pdf.read_bytes(), b"%PDF-1.7\ncurrent assessment\n%%EOF\n")

    def test_failed_weasyprint_does_not_leave_partial_output(self):
        # On PATH, not mocked: the kit starts engines with Popen, and a mock of
        # subprocess.run would leave the engine unstarted and the test vacuous.
        weasyprint = self.engine("weasyprint", "out.write_bytes(b'%PDF-1.7\\npartial weasyprint output'); sys.exit(1)")
        failures = []
        with patch.dict(os.environ, {"PATH": str(weasyprint.parent)}):
            self.assertIsNone(render.to_pdf(self.html, self.pdf, failures))
        self.assertEqual(len(failures), 1, failures)
        self.assertIn("weasyprint (exited with status 1", failures[0])
        self.assertFalse(self.pdf.exists())

    def test_weasyprint_timeout_does_not_leave_partial_output(self):
        weasyprint = self.engine("weasyprint", "import time\nout.write_bytes(b'%PDF-1.7\\npartial')\ntime.sleep(30)")
        failures = []
        with patch.dict(os.environ, {"PATH": str(weasyprint.parent)}):
            self.assertIsNone(render.to_pdf(self.html, self.pdf, failures, timeout=1))
        self.assertEqual(failures, ["weasyprint (timed out after 1 s)"])
        self.assertFalse(self.pdf.exists())

    def test_engine_stderr_keeps_the_reason_and_hides_secrets(self):
        secret = "hunter" + "2-not-a-real-value"
        for padding in ("", "[1:ERROR:dbus/bus.cc] Failed to connect to the bus\\n" * 40):
            with self.subTest(long=bool(padding)):
                chrome = self.engine("test-chrome", (
                    "sys.stderr.write('" + padding + "[1:ERROR:token_service.cc] auth token refresh skipped\\n"
                    "--password " + secret + "\\n[2:FATAL:zygote_host] No usable sandbox!\\n'); sys.exit(1)"))
                failures = []
                with patch.dict(os.environ, {"PATH": str(chrome.parent)}):
                    self.assertIsNone(render.to_pdf(self.html, self.pdf, failures))
                # Scrubbed as one line, the token line hid every later line, and
                # stderr past MAX_SCRUB characters was hidden whole.
                self.assertIn("No usable sandbox!", failures[0])
                self.assertNotIn(secret, failures[0])


class ExcerptTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "repo"
        (self.repo / "envs").mkdir(parents=True)
        self.value = "hunter" + "2-not-a-real-value"
        (self.repo / "envs" / "db.tf").write_text(
            'resource "aws_db_instance" "main" {\n'
            '  engine   = "postgres"\n'
            f'  password = "{self.value}"\n'
            '  username = var.db_user\n'
            '  publicly_accessible = true\n'
            '}\n', encoding="utf-8")
        (self.repo / "prod.tfvars").write_text(f'db_password = "{self.value}"\n', encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def record(self, location):
        data = sample()
        data["findings"][0]["location"] = location
        return data

    def test_excerpt_redacts_secret_values(self):
        sources = excerpts.attach_sources(self.record("envs/db.tf:5"), self.repo)
        text = "\n".join(t for _, t, _ in sources["F-001"])
        self.assertIn("publicly_accessible = true", text)
        self.assertIn("password = [redacted]", text)
        self.assertNotIn(self.value, text)
        self.assertIn([n for n, _, hit in sources["F-001"] if hit], [[5]])

    def test_credential_shape_redacted(self):
        key = "AKIA" + "ABCDEFGHIJKLMNOP"
        (self.repo / "envs" / "p.tf").write_text(f'provider "aws" {{\n  region = "{key}"\n}}\n', encoding="utf-8")
        sources = excerpts.attach_sources(self.record("envs/p.tf:2"), self.repo)
        self.assertNotIn(key, "\n".join(t for _, t, _ in sources["F-001"]))

    def test_sensitive_files_and_escapes_skipped(self):
        for location in ("prod.tfvars:1", "../outside.tf:1", "envs/missing.tf:1"):
            with self.subTest(location=location):
                self.assertEqual(excerpts.attach_sources(self.record(location), self.repo), {})

    def test_excerpt_embedded_in_both_outputs(self):
        with tempfile.TemporaryDirectory() as out:
            src = Path(out) / "in.json"
            src.write_text(json.dumps(self.record("envs/db.tf:5")), encoding="utf-8")
            code, _ = run([str(src), "--out", str(Path(out) / "o"), "--no-pdf", "--repo", str(self.repo)])
            self.assertEqual(code, 0)
            for name in ("dashboard.html", "assessment.html"):
                page = (Path(out) / "o" / name).read_text(encoding="utf-8")
                self.assertIn('class="snippet"', page)
                self.assertNotIn(self.value, page)


if __name__ == "__main__":
    unittest.main()
