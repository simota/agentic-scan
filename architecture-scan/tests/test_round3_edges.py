"""Renumber scope, concurrent merges, blank optional fields, autolinks, excluded filter."""
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

from test_architecture_scan import SKILL, complete_doc, finding, findings, render


class RenumberScopeTests(unittest.TestCase):
    def test_literal_values_and_meta_keep_their_ids(self):
        doc = complete_doc()
        doc["meta"]["scope"] = "Re-scan of the previous run's A-001"
        doc["findings"] = [finding("A-001", "Low", location="docs/A-001/notes.md:4"),
                           finding("A-002", "High")]
        doc["findings"][0]["references"] = [{"title": "Ticket for A-001",
                                             "url": "https://jira.example/browse/A-001"}]
        doc["findings"][0]["analysis"] = {"tool": "rg", "command": "rg -n A-001 docs/",
                                          "result": "A-001 cited twice"}
        doc["rules"][0]["source"] = "docs/A-001.md:3"
        renamed, _ = findings.renumber(doc)
        low = renamed["findings"][1]
        self.assertEqual(low["id"], "A-002")
        self.assertEqual(low["location"], "docs/A-001/notes.md:4")
        self.assertEqual(low["references"][0], {"title": "Ticket for A-002",
                                                "url": "https://jira.example/browse/A-001"})
        self.assertEqual(low["analysis"]["command"], "rg -n A-001 docs/")
        self.assertEqual(low["analysis"]["result"], "A-002 cited twice")
        self.assertEqual(renamed["rules"][0]["source"], "docs/A-001.md:3")
        self.assertEqual(renamed["meta"]["scope"], "Re-scan of the previous run's A-001")


class ConcurrentMergeTests(unittest.TestCase):
    @unittest.skipIf(findings.fcntl is None, "merges run one at a time without fcntl")
    def test_parallel_merges_keep_every_finding(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            target = tmp / "out" / "findings.json"
            fragments = []
            for i in range(1, 25):
                path = tmp / f"f{i}.json"
                path.write_text(json.dumps({"findings": [finding(
                    f"A-{i:03d}", "Low", title=f"t{i}", location=f"m{i}.py:1")]}), encoding="utf-8")
                fragments.append(path)
            script = str(SKILL / "scripts" / "findings.py")
            procs = [subprocess.Popen([sys.executable, script, "merge", str(target), str(p)],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                     for p in fragments]
            for proc in procs:
                _, err = proc.communicate(timeout=60)
                self.assertEqual(proc.returncode, 0, err)
            ids = {f["id"] for f in findings.read_json(target)["findings"]}
            self.assertEqual(len(ids), 24)
            self.assertEqual(sorted(p.name for p in target.parent.iterdir()), ["findings.json"])


class RenderEdgeTests(unittest.TestCase):
    def test_blank_optional_fields_get_no_row(self):
        doc = complete_doc()
        doc["findings"][0].update(rule="", contrast="  ")
        doc["findings"][0]["validation"] = {"verdict": "Likely", "method": "static",
                                            "evidence": " "}
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                t = render.LABELS[lang]
                first = render.render_markdown(doc, lang).split("### A-002")[0]
                html = render.render_html(doc, lang).split("</details>")[0]
                for key in ("rule", "contrast", "evidence"):
                    self.assertNotIn(f"**{t[key]}:**", first)
                    self.assertNotIn(f"<dt>{t[key]}</dt>", html)

    def test_bare_urls_and_addresses_are_not_autolinked(self):
        rendered = render.markdown_inline("see www.example.com/x, http://e.example/a, "
                                          "HTTPS://E.example, ftp://f.example and bob@example.com")
        for trigger in ("www.", "http:", "HTTPS:", "ftp:", "@"):
            self.assertNotIn(trigger, rendered)
        self.assertIn("www&#46;example.com/x", rendered)
        self.assertIn("bob&#64;<!-- -->example.com", rendered)
        self.assertEqual(render.markdown_inline("`http://x`"), render.markdown_code("http://x"))

    def test_excluded_findings_have_their_own_filter(self):
        doc = complete_doc()
        doc["findings"][1]["validation"].update(verdict="FalsePositive", evidence="a.py:1")
        html = render.render_html(doc, "ja")
        self.assertEqual(html.count("<details data-sev='excluded'"), 1)
        self.assertIn("<option value='excluded'>除外した検出事項のみ</option>", html)


class EvidenceTokenTests(unittest.TestCase):
    def test_a_url_port_is_not_a_line(self):
        for evidence, ok in (("https://example.com:443/x", False), ("(job.py:58)", True),
                             ("see `job.py:58`", True), (r"C:\repo\a.py:3", True)):
            with self.subTest(evidence=evidence):
                self.assertEqual(findings.cites_line(evidence), ok)


if __name__ == "__main__":
    unittest.main()
