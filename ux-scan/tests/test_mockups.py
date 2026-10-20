"""Before/after mockups: schema, the mockups.html page and its output contract."""

import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "ux-scan" / "scripts"))

import contract_check  # noqa: E402
import findings  # noqa: E402
import mockups  # noqa: E402
import render  # noqa: E402

SAMPLE = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
FLOWS = json.loads((ROOT / "examples" / "flows.sample.json").read_text(encoding="utf-8"))


class Frames(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.frames, self.links, self.sections = [], [], []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "iframe":
            self.frames.append(attrs)
        elif tag == "a":
            self.links.append(attrs.get("href"))
        elif tag == "section" and "mockup" in (attrs.get("class") or "").split():
            self.sections.append(attrs)


def finding(data, fid):
    return next(f for f in data["findings"] if f["id"] == fid)


class MockupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.out = Path(self.temp.name) / "out"
        self.out.mkdir()
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        self.data = copy.deepcopy(SAMPLE)
        self.data["limitations"].append("report.pdf not produced: no engine in this test")
        self.save()

    def save(self):
        (self.out / "findings.json").write_text(json.dumps(self.data, ensure_ascii=False), encoding="utf-8")
        (self.out / "flows.json").write_text(json.dumps(FLOWS), encoding="utf-8")
        (self.out / "inventory.json").write_text(json.dumps({
            "tool": "inventory.py", "flows_sha256": findings.canonical_digest(FLOWS)}), encoding="utf-8")

    def render(self, lang="en", out=None):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            code = render.main([str(self.out / "findings.json"), "--out", str(out or self.out),
                                "--repo", str(self.repo), "--lang", lang, "--no-pdf"])
        self.assertEqual(code, 0, err.getvalue())

    def problems(self, **kwargs):
        return "\n".join(contract_check.problems(self.out, no_pdf=True, **kwargs))

    def test_sample_mockups_render_sandboxed_and_pass_the_contract(self):
        self.render()
        page = (self.out / "mockups.html").read_text(encoding="utf-8")
        parsed = Frames(page)
        self.assertEqual([s["id"] for s in parsed.sections], ["U-006", "U-014"])
        self.assertEqual(len(parsed.frames), 4)
        for frame in parsed.frames:
            self.assertEqual(frame["sandbox"], "")
            # Every side opens with the head that carries the frame's content policy.
            self.assertTrue(frame["srcdoc"].startswith(mockups.frame_document("", "en").split("<body>")[0]))
        self.assertEqual(parsed.frames[0]["srcdoc"],
                         mockups.frame_document(finding(self.data, "U-006")["mockup"]["before"], "en"))
        self.assertEqual(parsed.sections[0]["data-viewport"], "360x640")
        self.assertIn('<meta name="ux-scan-page-kind" content="mockups.html">', page)
        self.assertIn('href="mockups.html"', (self.out / "dashboard.html").read_text(encoding="utf-8"))
        self.assertIn("mockups.html#U-006", (self.out / "report.html").read_text(encoding="utf-8"))
        self.assertEqual(self.problems(), "")

    def test_markup_stays_inside_the_frame(self):
        finding(self.data, "U-006")["mockup"]["before"] = (
            '<script>alert(1)</script><meta name="ux-scan-page" content="sha256:' + "0" * 64 + '">"</iframe>')
        self.save()
        self.render()
        page = (self.out / "mockups.html").read_text(encoding="utf-8")
        self.assertNotIn("<script>alert(1)", page)
        self.assertEqual(len(Frames(page).frames), 4)
        self.assertEqual(self.problems(), "")

    def test_page_follows_the_record(self):
        self.render()
        (self.out / "mockups.html").unlink()
        self.assertIn("mockups.html: missing", self.problems())
        self.render()
        for f in self.data["findings"]:
            f.pop("mockup", None)
        self.save()
        self.assertIn("mockups.html: not part of the contract", self.problems())
        self.render()
        self.assertFalse((self.out / "mockups.html").exists())
        self.assertNotIn('href="mockups.html"', (self.out / "dashboard.html").read_text(encoding="utf-8"))
        self.assertEqual(self.problems(), "")

    def test_excluded_findings_publish_no_mockup(self):
        for f in self.data["findings"]:
            f.pop("mockup", None)
        excluded = next(f for f in self.data["findings"] if f["validation"]["verdict"] in findings.EXCLUDED)
        excluded["mockup"] = {"before": "<p>a</p>", "after": "<p>b</p>"}
        self.save()
        self.render()
        self.assertFalse((self.out / "mockups.html").exists())
        self.assertEqual(self.problems(), "")

    def test_stale_or_foreign_mockup_page_is_rejected(self):
        self.render()
        finding(self.data, "U-014")["mockup"]["after"] = "<p>changed</p>"
        self.save()
        self.assertIn("mockups.html: stale ux-scan-source", self.problems())
        self.render()
        (self.out / "mockups.html").write_bytes((self.out / "report.html").read_bytes())
        self.assertIn("mockups.html: wrong or missing page kind", self.problems())

    def test_second_language_render_includes_its_mockup_page(self):
        self.render()
        self.render(lang="ja", out=self.out / "ja")
        self.assertEqual(self.problems(allow=["ja"]), "")
        self.assertIn("Before（現状）", (self.out / "ja" / "mockups.html").read_text(encoding="utf-8"))
        (self.out / "ja" / "mockups.html").unlink()
        self.assertIn("ja/mockups.html: missing", self.problems(allow=["ja"]))

    def test_schema_rejects_malformed_mockups(self):
        base = {"before": "<p>a</p>", "after": "<p>b</p>"}
        for mockup, message in (
                ("<p>a</p>", "expected an object"),
                ({"before": "<p>a</p>"}, "mockup.after: required"),
                ({**base, "after": "  "}, "mockup.after: required"),
                ({**base, "image": "x.png"}, "unknown key 'image'"),
                ({**base, "viewport": "wide"}, "WIDTHxHEIGHT"),
                ({**base, "before": "x" * (findings.MAX_MOCKUP_CHARS + 1)}, "longer than"),
                ({**base, "note": "\x00"}, "without NUL")):
            with self.subTest(mockup=mockup if len(str(mockup)) < 80 else "long"):
                data = copy.deepcopy(SAMPLE)
                data["findings"][0]["mockup"] = mockup
                with self.assertRaisesRegex(findings.RecordError, message):
                    findings.check_findings(data, findings.flow_ids(FLOWS))

    def test_renumber_rewrites_the_note_but_not_the_markup(self):
        data = copy.deepcopy(SAMPLE)
        target = finding(data, "U-014")
        target["mockup"]["before"] = "<p>U-001</p>"
        target["mockup"]["note"] = "See U-001."
        data["findings"][0]["severity"] = "Info"
        mapping = findings.renumber_map(data["findings"])
        renumbered = findings.renumber(data, mapping)
        moved = next(f for f in renumbered["findings"] if f["title"] == target["title"])
        self.assertEqual(moved["mockup"]["before"], "<p>U-001</p>")
        self.assertEqual(moved["mockup"]["note"], f"See {mapping['U-001']}.")

    def test_viewport_falls_back_to_the_finding_then_the_flows(self):
        f = {"mockup": {"before": "a", "after": "b"}, "viewport": "768x1024"}
        self.assertEqual(mockups.viewport_of(f, FLOWS), "768x1024")
        del f["viewport"]
        self.assertEqual(mockups.viewport_of(f, FLOWS), FLOWS["viewports"][0])
        self.assertEqual(mockups.viewport_of(f, None), mockups.DEFAULT_VIEWPORT)


if __name__ == "__main__":
    unittest.main()
