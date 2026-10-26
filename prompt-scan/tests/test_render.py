import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from helpers import EXAMPLES, SAMPLE_APP, SCRIPTS, clone, render, run, sample, write_json


class RenderTest(unittest.TestCase):
    def render(self, data, *extra):
        out = Path(tempfile.mkdtemp())
        write_json(out / "findings.json", data)
        code, _, err = run(render.main, out / "findings.json", "--out", out, "--no-pdf", *extra)
        self.assertEqual(code, 0, err)
        return out

    def test_samples_render_in_both_languages(self):
        for lang in ("en", "ja"):
            out = self.render(sample(lang), "--lang", lang, "--repo", SAMPLE_APP)
            report = (out / "report.html").read_text(encoding="utf-8")
            self.assertIn(render.LABELS[lang]["title"], report)
            self.assertIn("F-001", report)
            # The excerpt is embedded from the working tree (meta.commit is null in the samples).
            self.assertIn("data[&quot;response&quot;]", report)
            self.assertRegex(report, r'<meta name="prompt-scan-source" content="sha256:[0-9a-f]{64}">')
            self.assertFalse((out / "report.pdf").exists())

    def test_dashboard_payload_cannot_close_the_script(self):
        data = sample()
        data["findings"][0]["title"] = "</script><b>x</b>"
        dashboard = (self.render(data) / "dashboard.html").read_text(encoding="utf-8")
        payload = re.search(r'<script id="data" type="application/json">(.*?)</script>', dashboard, re.S).group(1)
        self.assertNotIn("</script>", payload)
        self.assertEqual(json.loads(payload)["findings"][0]["title"], "</script><b>x</b>")

    def test_report_uses_the_shared_format_and_escapes(self):
        data = sample("ja")
        data["findings"][0]["title"] = "<b>x</b> & y"
        report = (self.render(data, "--lang", "ja") / "report.html").read_text(encoding="utf-8")
        self.assertIn('content:"プロンプト診断"', report)  # The kit's running footer.
        self.assertIn('<article class="finding sev-High" id="F-001">', report)
        self.assertIn("&lt;b&gt;x&lt;/b&gt; &amp; y", report)
        self.assertNotIn("<b>x</b>", report)

    def test_previous_validation_without_evidence_renders(self):
        data = sample()
        data["findings"][-1]["previous_validation"] = {"verdict": "Likely", "evidence": None, "method": "static"}
        report = (self.render(data) / "report.html").read_text(encoding="utf-8")
        self.assertIn("Likely: </p>", report)

    def test_private_key_block_is_masked_whole(self):
        repo = Path(tempfile.mkdtemp())
        body = ["MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu", "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzv"]
        (repo / "p.md").write_text("\n".join(["intro", "-----BEGIN RSA PRIVATE KEY-----", *body,
                                               "-----END RSA PRIVATE KEY-----", "after"]) + "\n", encoding="utf-8")
        data = sample()
        first = data["findings"][0]
        first.pop("prompt")
        first["location"] = "p.md:2"
        data["prompts"], data["findings"] = [], [first]
        start, lines, _ = render.attach_sources(data, repo)[first["id"]]
        self.assertEqual((start, lines), (1, ["intro"] + ["[REDACTED]"] * 4))

    def test_sensitive_files_get_no_excerpt_and_more_token_formats_are_masked(self):
        repo = Path(tempfile.mkdtemp())
        # Built at run time, so no credential-shaped literal sits in the repository.
        tokens = ["github_pat_" + "A1" * 20, "glpat-" + "b2" * 10, "hf_" + "C3" * 17, "sk_" + "live_" + "D4" * 12,
                  "rk_" + "test_" + "E5" * 12, "ASIA" + "F6" * 8]
        (repo / ".env.local").write_text("SYSTEM_PROMPT=hello\nDB_PASSWORD=hunter2\n", encoding="utf-8")
        (repo / "deploy.key").write_text("line\n", encoding="utf-8")
        (repo / "p.md").write_text("".join(f"use {t}\n" for t in tokens), encoding="utf-8")
        (repo / "link.md").symlink_to(repo / ".env.local")
        data = sample()
        base = data["findings"][0]
        base.pop("prompt")
        data["prompts"], data["findings"] = [], []
        for n, location in enumerate([".env.local:1", "deploy.key:1", "link.md:1", "p.md:1-6"], 1):
            data["findings"].append(dict(base, id=f"F-{n:03d}", location=location))
        excerpts = render.attach_sources(data, repo)
        self.assertEqual(sorted(excerpts), ["F-004"])
        self.assertEqual(excerpts["F-004"][1], ["use [REDACTED]"] * len(tokens))

    def test_credential_and_login_files_by_other_names_get_no_excerpt(self):
        names = ["prod.env", "app.env.local", ".npmrc", ".pypirc", ".netrc", ".git-credentials", "credentials",
                 "id_rsa", "id_ed25519", "release.jks"]
        repo = Path(tempfile.mkdtemp())
        base = sample()["findings"][0]
        data = dict(sample(), prompts=[], findings=[])
        for n, name in enumerate(names + ["prompt.md", "environment.md"], 1):
            (repo / name).write_text("SYSTEM_PROMPT=hello\n", encoding="utf-8")
            data["findings"].append(dict(base, id=f"F-{n:03d}", location=f"{name}:1", prompt=None))
        self.assertEqual(sorted(render.attach_sources(data, repo)), [f"F-{len(names) + 1:03d}", f"F-{len(names) + 2:03d}"])

    def test_excerpt_context_masks_values_assigned_to_credential_names(self):
        repo = Path(tempfile.mkdtemp())
        # The key id is a recognised format; the lines around it are not, and the excerpt shows them.
        lines = ["aws_access_key_id = " + "AKIA" + "Q" * 16, "aws_secret_access_key = " + "wJalr/K7MDENG" * 3,
                 'db_password = "Tr0ub4dor&3 prod"', "export GITHUB_TOKEN=abc123  # ci", '"api_key": "k1", "n": 1',
                 "DATABASE_URL=postgres://billing:" + "S3cr3t" + "@db:5432/app",
                 # Not values: a number, template variables, prose and a key that only contains a word.
                 '"max_token": 500, "max_tokens": 9', "api_key: {api_key}", 'token = "${TOKEN}"',
                 "password: never reveal it", "token_limit=abc"]
        (repo / "p.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        data = dict(sample(), prompts=[], findings=[dict(sample()["findings"][0], id="F-001", location="p.md:4-8")])
        self.assertEqual(render.attach_sources(data, repo)["F-001"][1], [
            "aws_access_key_id = [REDACTED]", "aws_secret_access_key = [REDACTED]", "db_password = [REDACTED]",
            "export GITHUB_TOKEN=[REDACTED]  # ci", '"api_key": [REDACTED], "n": 1',
            "DATABASE_URL=postgres://billing:[REDACTED]@db:5432/app", lines[6], lines[7], lines[8], lines[9], lines[10]])

    def test_excerpt_masks_assignments_inside_code_brackets(self):
        cases = {'db.connect(password="hunter2")': "db.connect(password=[REDACTED])",
                 'cfg = {"token": "abc"}': 'cfg = {"token": [REDACTED]}', "opts[secret=xyz]": "opts[secret=[REDACTED]]",
                 "f(max_token=5)": "f(max_token=5)"}
        for line, masked in cases.items():
            self.assertEqual(render.mask_excerpt(line), masked)

    def test_a_commit_git_cannot_read_gives_no_excerpt(self):
        # Never fall back to the working tree, which may hold later edits the scan never saw.
        repo = Path(tempfile.mkdtemp())
        (repo / "p.md").write_text("later edit\n", encoding="utf-8")
        data = dict(sample(), prompts=[], findings=[dict(sample()["findings"][0], id="F-001", location="p.md:1")])
        data["meta"] = dict(data["meta"], commit="0" * 40, dirty=False)
        self.assertEqual(render.attach_sources(data, repo), {})

    def test_excerpt_masking_stays_linear_on_long_lines(self):
        for line in ("a." * 100000, "a-" * 100000, "http://" * 30000, "secret=" * 30000):
            started = time.monotonic()
            render.mask_excerpt(line)
            self.assertLess(time.monotonic() - started, 2, line[:20])

    def test_runs_in_isolated_mode(self):
        # -I leaves the script's directory off sys.path, as PYTHONSAFEPATH does.
        out = Path(tempfile.mkdtemp())
        r = subprocess.run([sys.executable, "-I", str(SCRIPTS / "render.py"), str(EXAMPLES / "findings.sample.json"),
                            "--out", str(out), "--no-pdf"], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_line_numbers_split_on_newlines_only(self):
        self.assertEqual(render.source_lines("a\x0cb\u2028c\r\nd\n"), ["a\x0cb\u2028c", "d"])

    def test_too_deep_json_is_a_schema_error(self):
        out = Path(tempfile.mkdtemp())
        (out / "findings.json").write_text('{"meta":' + "[" * 100000 + "]" * 100000 + "}", encoding="utf-8")
        code, _, err = run(render.main, out / "findings.json", "--out", out, "--no-pdf")
        self.assertEqual(code, 2, err)
        self.assertIn("render.py:", err)

    def test_lang_defaults_to_the_record(self):
        out = self.render(sample("en"))
        self.assertIn(render.LABELS["en"]["title"], (out / "report.html").read_text(encoding="utf-8"))

    def test_unknown_tree_state_is_shown(self):
        data = sample()
        data["meta"].update(commit="a" * 40, dirty=None)
        self.assertIn("aaaaaaaaaaaa (uncommitted changes not determined)", render.meta_lines(data, render.LABELS["en"]))
        data["meta"]["dirty"] = False
        self.assertIn("<span>aaaaaaaaaaaa</span>", render.meta_lines(data, render.LABELS["en"]))

    def test_ids_past_999_sort_numerically(self):
        self.assertEqual(sorted(["F-1000", "F-999", "L-002"], key=render.id_key), ["F-999", "F-1000", "L-002"])

    def test_no_pdf_removes_a_stale_pdf(self):
        out = Path(tempfile.mkdtemp())
        write_json(out / "findings.json", sample())
        (out / "report.pdf").write_bytes(b"%PDF stale")
        code, _, err = run(render.main, out / "findings.json", "--out", out, "--no-pdf")
        self.assertEqual(code, 0, err)
        self.assertFalse((out / "report.pdf").exists())

    def test_refuses_to_write_through_a_symlink(self):
        for name in ("dashboard.html", "report.html", "report.pdf"):
            out, elsewhere = Path(tempfile.mkdtemp()), Path(tempfile.mkdtemp()) / "victim"
            elsewhere.write_text("keep", encoding="utf-8")
            write_json(out / "findings.json", sample())
            (out / name).symlink_to(elsewhere)
            code, _, err = run(render.main, out / "findings.json", "--out", out, "--no-pdf")
            self.assertEqual(code, 2, name)
            self.assertIn("symlink", err)
            self.assertEqual(elsewhere.read_text(encoding="utf-8"), "keep")
            self.assertTrue((out / name).is_symlink())

    def test_failed_engine_exits_3_with_masked_stderr(self):
        out, bin_dir = Path(tempfile.mkdtemp()), Path(tempfile.mkdtemp())
        token = "sk-ant-" + "Qq7" * 10
        chrome = bin_dir / "chrome"
        chrome.write_text(f"#!/bin/sh\necho 'fatal {token}' >&2\nexit 1\n", encoding="utf-8")
        chrome.chmod(0o755)
        write_json(out / "findings.json", sample())
        # PATH holds no weasyprint, so the failed Chrome is the only engine.
        with mock.patch.dict(os.environ, {"CHROME": str(chrome), "PATH": str(bin_dir)}):
            code, _, err = run(render.main, out / "findings.json", "--out", out)
        self.assertEqual(code, 3, err)
        self.assertIn("chrome exited with status 1", err)
        self.assertIn("[REDACTED]", err)
        self.assertNotIn(token, err)
        self.assertTrue((out / "report.html").is_file())
        self.assertFalse((out / "report.pdf").exists())

    def test_excerpts_mask_credentials(self):
        repo = Path(tempfile.mkdtemp())
        token = "sk-ant-" + "Zz9" * 10
        (repo / "p.md").write_text(f"line one\nkey {token}\n", encoding="utf-8")
        data = sample()
        first = data["findings"][0]
        first.pop("prompt")
        first["location"] = "p.md:2"
        data["prompts"], data["findings"] = [], [first]
        out = self.render(data, "--repo", repo)
        for page in ("report.html", "dashboard.html"):
            text = (out / page).read_text(encoding="utf-8")
            self.assertNotIn(token, text)
            self.assertIn("[REDACTED]", text)

    def test_excerpt_comes_from_the_recorded_commit(self):
        root = Path(tempfile.mkdtemp())
        repo = root / "svc"
        (repo / "prompts").mkdir(parents=True)
        (repo / "prompts" / "a.md").write_text("one\ncommitted line\nthree\n", encoding="utf-8")
        git = ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.com"]
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run([*git, "add", "."], check=True)
        subprocess.run([*git, "commit", "-qm", "init"], check=True)
        commit = subprocess.run([*git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
        (repo / "prompts" / "a.md").write_text("one\nedited line\nthree\n", encoding="utf-8")
        data = sample()
        first = data["findings"][0]
        first.pop("prompt")
        first["location"] = "prompts/a.md:2"
        data["prompts"], data["findings"] = [], [first]
        data["meta"].update(commit=commit, dirty=False)
        # --repo is a subdirectory of the work tree, as when inventory.py scanned svc/.
        lines = render.attach_sources(data, repo)[first["id"]][1]
        self.assertIn("committed line", lines)
        self.assertNotIn("edited line", lines)
        # A dirty scan reviewed the working tree, so its excerpts come from there.
        for dirty in (True, None):
            data["meta"]["dirty"] = dirty
            self.assertIn("edited line", render.attach_sources(data, repo)[first["id"]][1], dirty)

    def test_excerpt_of_a_filtered_file_is_the_text_the_scan_read(self):
        root = Path(tempfile.mkdtemp())
        (root / "prompts").mkdir()
        (root / "prompts" / "a.md").write_text("You are a support bot.\nTODO: refunds\n", encoding="utf-8")
        (root / ".gitattributes").write_text("prompts/** filter=rot\n", encoding="utf-8")
        # The commit stores what the clean command produced (as git-crypt stores ciphertext); the smudge
        # command, which would turn it back, must not run while rendering.
        marker = root / "smudged"
        git = ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.com",
               "-c", "filter.rot.clean=tr A-Za-z N-ZA-Mn-za-m", "-c", f"filter.rot.smudge=touch {marker}; cat"]
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run([*git, "add", "."], check=True)
        subprocess.run([*git, "commit", "-qm", "init"], check=True)
        commit = subprocess.run([*git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
        data = sample()
        first = dict(data["findings"][0], location="prompts/a.md:2")
        first.pop("prompt")
        data["prompts"], data["findings"] = [], [first]
        data["meta"].update(commit=commit, dirty=False)
        self.assertEqual(render.attach_sources(data, root)[first["id"]][1], ["You are a support bot.", "TODO: refunds"])
        self.assertFalse(marker.exists())

    def test_excerpt_path_cannot_leave_the_repository(self):
        data = sample()
        data["findings"][0]["location"] = "../outside.txt:1"
        excerpts = render.attach_sources(data, SAMPLE_APP)
        self.assertNotIn("F-001", excerpts)
        self.assertIn("F-002", excerpts)

    def test_non_standard_json_is_a_schema_error(self):
        for raw in (b'{"findings": [], "perspectives": [{"name": "a", "result": "applied", "x": NaN}]}',
                    b'{"findings": [], "findings": []}',
                    # A lone surrogate parses but cannot be written: render.py crashed before writing anything.
                    b'{"findings": [], "checked_ok": ["split \\ud83d here"]}', b'{"findings": [], "\\udc00": 1}'):
            with self.assertRaises(render.SchemaError):
                render.load("findings.json", raw)

    def test_schema_errors(self):
        cases = [
            (lambda d: d["findings"][0].update(id="X-001"), "F-NNN or L-NNN"),
            (lambda d: d["findings"][0].update(kind="bug"), "kind must be one of"),
            (lambda d: d["findings"][0]["validation"].update(evidence=""), "needs validation.evidence"),
            (lambda d: d["findings"][0]["validation"].update(evidence=None), "needs validation.evidence"),
            (lambda d: d["findings"][0].update(prompt="P-99"), "recorded prompt ids"),
            (lambda d: d["findings"][0].update(prompt=[["P-01"]]), "recorded prompt ids"),
            (lambda d: d.update(eval_runs=[{"id": "E-001", "finding": ["F-001"], "model": "m", "date": "d",
                                            "cases": 1, "passed": 1, "failed": 0}]), "name a recorded finding"),
            (lambda d: d.update(extra=1), "unknown top-level keys"),
            (lambda d: d["meta"].update(commit="abc"), "full Git object id"),
            (lambda d: d["findings"][0].update(references=None), "references must be a list"),
            (lambda d: d.update(eval_runs=[{"id": "E-001", "finding": "L-001", "model": "m", "date": "d",
                                            "cases": 1, "passed": 1, "failed": 0}]), "must be an F-* id"),
            (lambda d: d.update(eval_runs=[{"id": "E-001", "finding": "F-001", "model": "m", "date": "d",
                                            "cases": 1, "passed": 1, "failed": 1}]), "exceeds cases"),
            (lambda d: d["findings"][0].update(location="app/llm/answer.py\x00:17"), "location must not contain"),
            # Any other value rendered in Japanese without a word: an English record tagged en-US, say.
            (lambda d: d["meta"].update(lang="en-US"), "meta.lang must be one of"),
        ]
        for mutate, message in cases:
            data = clone(sample())
            mutate(data)
            with self.assertRaises(render.SchemaError) as ctx:
                render.validate_data(data)
            self.assertIn(message, str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
