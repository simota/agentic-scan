"""Before/after mockups: schema, the mockups.html page and its output contract."""

import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
import unittest.mock
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
        # U-006 carries one alternative: before, the fix and the alternative.
        self.assertEqual(len(parsed.frames), 5)
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
        self.assertEqual(len(Frames(page).frames), 5)
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
                ({**base, "before": "x" * (findings.MAX_MOCKUP_BYTES + 1)}, "larger than"),
                # The limit is documented in KiB: multibyte text counts by its UTF-8 size.
                ({**base, "after": "あ" * (findings.MAX_MOCKUP_BYTES // 3 + 1)}, "larger than"),
                ({**base, "note": "\x00"}, "without NUL")):
            with self.subTest(mockup=mockup if len(str(mockup)) < 80 else "long"):
                data = copy.deepcopy(SAMPLE)
                data["findings"][0]["mockup"] = mockup
                with self.assertRaisesRegex(findings.RecordError, message):
                    findings.check_findings(data, findings.flow_ids(FLOWS))
        data = copy.deepcopy(SAMPLE)
        data["findings"][0]["mockup"] = {**base, "after": "あ" * (findings.MAX_MOCKUP_BYTES // 3)}
        findings.check_findings(data, findings.flow_ids(FLOWS))  # 65,535 bytes: within the limit

    def test_alternatives_render_as_proposals_of_one_comparison(self):
        self.render()
        page = (self.out / "mockups.html").read_text(encoding="utf-8")
        mockup = finding(self.data, "U-006")["mockup"]
        frames = Frames(page).frames
        self.assertEqual([f["title"] for f in frames[:3]],
                         ["U-006 Before", "U-006 After — Drawer", "U-006 Alternative — Chip row"])
        self.assertEqual(frames[2]["srcdoc"], mockups.frame_document(mockup["alternatives"][0]["after"], "en"))
        self.assertIn('<div class="group proposals" role="group" aria-label="Proposal">'
                      '<button type="button" value="0" aria-pressed="true">Drawer</button>'
                      '<button type="button" value="1" aria-pressed="false">Chip row</button></div>', page)
        self.assertIn('<p class="mockup-note" data-proposal="1"><strong>Chip row:</strong> Below 640px', page)
        # A mockup without alternatives has no picker and no proposal markers.
        u014 = page[page.index('id="U-014"'):page.index("</section>", page.index('id="U-014"'))]
        self.assertNotIn("data-proposal", u014)
        self.assertNotIn("proposals", u014)
        self.assertEqual(self.problems(), "")

    def test_schema_rejects_malformed_alternatives(self):
        base = {"before": "<p>a</p>", "after": "<p>b</p>", "label": "Drawer"}
        alt = {"label": "Chips", "after": "<p>c</p>"}
        for alternatives, message in (
                ([], "1 to 3"),
                ({"label": "x"}, "1 to 3"),
                ([alt] * 4, "1 to 3"),
                (["<p>c</p>"], "expected an object"),
                ([{"after": "<p>c</p>"}], r"alternatives\[0\]\.label: required"),
                ([{"label": "Chips"}], r"alternatives\[0\]\.after: required"),
                ([{**alt, "viewport": "360x640"}], "unknown key 'viewport'"),
                ([{**alt, "label": " Drawer "}], "already used"),
                ([alt, {**alt, "after": "<p>d</p>"}], r"alternatives\[1\]\.label: 'Chips' is already used"),
                ([{**alt, "after": "x" * (findings.MAX_MOCKUP_BYTES + 1)}], "larger than"),
                ([{**alt, "after": '<link rel="prefetch" href="//x">'}], "<link>")):
            with self.subTest(alternatives=alternatives if len(str(alternatives)) < 80 else "long"):
                data = copy.deepcopy(SAMPLE)
                data["findings"][0]["mockup"] = {**base, "alternatives": alternatives}
                with self.assertRaisesRegex(findings.RecordError, message):
                    findings.check_findings(data, findings.flow_ids(FLOWS))
        # Every button needs a name of its own, the fix's included.
        data = copy.deepcopy(SAMPLE)
        data["findings"][0]["mockup"] = {"before": "<p>a</p>", "after": "<p>b</p>", "alternatives": [alt]}
        with self.assertRaisesRegex(findings.RecordError, r"mockup\.label: required"):
            findings.check_findings(data, findings.flow_ids(FLOWS))
        data["findings"][0]["mockup"]["label"] = "Drawer"
        findings.check_findings(data, findings.flow_ids(FLOWS))

    def test_renumber_keeps_alternative_markup_and_rewrites_its_note(self):
        data = copy.deepcopy(SAMPLE)
        target = finding(data, "U-014")
        target["mockup"]["alternatives"] = [{"label": "Menu", "after": "<p>U-001</p>", "note": "Like U-001."}]
        data["findings"][0]["severity"] = "Info"
        mapping = findings.renumber_map(data["findings"])
        moved = next(f for f in findings.renumber(data, mapping)["findings"] if f["title"] == target["title"])
        self.assertEqual(moved["mockup"]["alternatives"][0]["after"], "<p>U-001</p>")
        self.assertEqual(moved["mockup"]["alternatives"][0]["note"], f"Like {mapping['U-001']}.")

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

    def test_null_mockup_in_a_fragment_removes_it(self):
        merged = findings.merge(copy.deepcopy(SAMPLE), {"findings": [{"id": "U-006", "mockup": None}]})
        self.assertNotIn("mockup", finding(merged, "U-006"))
        self.assertIn("mockup", finding(merged, "U-014"))
        findings.check_findings(merged, findings.flow_ids(FLOWS))
        # Removing one that is not there is harmless; null is never stored.
        merged = findings.merge(merged, {"findings": [{"id": "U-006", "mockup": None}]})
        self.assertNotIn("mockup", finding(merged, "U-006"))
        # Only a fragment's null removes: a malformed record stays malformed and is refused.
        broken = copy.deepcopy(SAMPLE)
        finding(broken, "U-006")["mockup"] = None
        merged = findings.merge(broken, {"findings": [{"id": "U-006", "title": "Retitled"}]})
        self.assertIsNone(finding(merged, "U-006")["mockup"])
        with self.assertRaisesRegex(findings.RecordError, "mockup"):
            findings.check_findings(merged, findings.flow_ids(FLOWS))

    def test_link_elements_are_refused_since_they_can_fetch_past_the_policy(self):
        for markup in ('<link rel="preconnect" href="https://fonts.example">', "<LINK\nrel=dns-prefetch href=//x>"):
            with self.subTest(markup=markup):
                data = copy.deepcopy(SAMPLE)
                data["findings"][0]["mockup"] = {"before": "<p>a</p>" + markup, "after": "<p>b</p>"}
                with self.assertRaisesRegex(findings.RecordError, "<link>"):
                    findings.check_findings(data, findings.flow_ids(FLOWS))
        self.assertIn('http-equiv="x-dns-prefetch-control" content="off"', mockups.frame_document("", "en"))
        data = copy.deepcopy(SAMPLE)
        data["findings"][0]["mockup"] = {"before": "<p>&lt;link&gt; and <linkedin-card></linkedin-card></p>",
                                         "after": "<p>b</p>"}
        findings.check_findings(data, findings.flow_ids(FLOWS))  # escaped text and other tag names pass

    def test_invalid_record_leaves_the_translated_mockup_page_unjudged(self):
        self.render()
        self.render(lang="ja", out=self.out / "ja")
        self.data["findings"][0]["severity"] = "Severe"
        self.save()
        problems = self.problems(allow=["ja"])
        self.assertIn("record:", problems)
        self.assertNotIn("mockups.html: not part of", problems)

    def test_pdf_metadata_is_stamped_on_the_mockup_page(self):
        self.data["limitations"] = [x for x in self.data["limitations"] if not x.startswith(contract_check.NO_PDF)]
        self.save()

        def engine(html_path, pdf_path, *args, **kwargs):
            Path(pdf_path).write_bytes(b"%PDF-1.7\n% test engine output\n%%EOF\n")
            return "test-engine"

        with unittest.mock.patch.object(render.pdf, "to_pdf", side_effect=engine), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(render.main([str(self.out / "findings.json"), "--out", str(self.out),
                                          "--repo", str(self.repo), "--lang", "en"]), 0)
        self.assertIn('<meta name="ux-scan-pdf"', (self.out / "mockups.html").read_text(encoding="utf-8"))
        self.assertEqual("\n".join(contract_check.problems(self.out)), "")

    def test_viewport_falls_back_to_the_finding_then_the_flows(self):
        f = {"mockup": {"before": "a", "after": "b"}, "viewport": "768x1024"}
        self.assertEqual(mockups.viewport_of(f, FLOWS), "768x1024")
        del f["viewport"]
        self.assertEqual(mockups.viewport_of(f, FLOWS), FLOWS["viewports"][0])
        self.assertEqual(mockups.viewport_of(f, None), mockups.DEFAULT_VIEWPORT)


if __name__ == "__main__":
    unittest.main()
