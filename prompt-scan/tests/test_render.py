import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from helpers import SAMPLE_APP, clone, render, run, sample, write_json


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
        data["meta"]["commit"] = commit
        # --repo is a subdirectory of the work tree, as when inventory.py scanned svc/.
        lines = render.attach_sources(data, repo)[first["id"]][1]
        self.assertIn("committed line", lines)
        self.assertNotIn("edited line", lines)

    def test_excerpt_path_cannot_leave_the_repository(self):
        data = sample()
        data["findings"][0]["location"] = "../outside.txt:1"
        excerpts = render.attach_sources(data, SAMPLE_APP)
        self.assertNotIn("F-001", excerpts)
        self.assertIn("F-002", excerpts)

    def test_schema_errors(self):
        cases = [
            (lambda d: d["findings"][0].update(id="X-001"), "F-NNN or L-NNN"),
            (lambda d: d["findings"][0].update(kind="bug"), "kind must be one of"),
            (lambda d: d["findings"][0]["validation"].update(evidence=""), "needs validation.evidence"),
            (lambda d: d["findings"][0].update(prompt="P-99"), "recorded prompt ids"),
            (lambda d: d["findings"][0].update(prompt=[["P-01"]]), "recorded prompt ids"),
            (lambda d: d.update(eval_runs=[{"id": "E-001", "finding": ["F-001"], "model": "m", "date": "d",
                                            "cases": 1, "passed": 1, "failed": 0}]), "name a recorded finding"),
            (lambda d: d.update(extra=1), "unknown top-level keys"),
            (lambda d: d["meta"].update(commit="abc"), "full Git object id"),
            (lambda d: d.update(eval_runs=[{"id": "E-001", "finding": "F-001", "model": "m", "date": "d",
                                            "cases": 1, "passed": 1, "failed": 1}]), "exceeds cases"),
        ]
        for mutate, message in cases:
            data = clone(sample())
            mutate(data)
            with self.assertRaises(render.SchemaError) as ctx:
                render.validate_data(data)
            self.assertIn(message, str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
