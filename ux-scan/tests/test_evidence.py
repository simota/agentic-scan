"""Evidence files: schema, embedding in the report, evidence.html, the output contract and capture.py."""

import base64
import contextlib
import copy
import io
import json
import shutil
import struct
import sys
import tempfile
import unittest
import zlib
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "ux-scan" / "scripts"))

import capture  # noqa: E402
import contract_check  # noqa: E402
import evidence  # noqa: E402
import findings  # noqa: E402
import render  # noqa: E402

SAMPLE = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
FLOWS = json.loads((ROOT / "examples" / "flows.sample.json").read_text(encoding="utf-8"))

# Valid 1x1 GIF; the second frame makes it an animation rather than a video codec.
GIF = (base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAAKAAAALAAAAAABAAEAAAICRAEA")
       + base64.b64decode("IfkEAAoAAAAsAAAAAAEAAQAAAgJMAQA7"))


class Elements(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.tags = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def png(width=2, height=2):
    """A valid, tiny PNG."""
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    rows = b"".join(b"\x00" + b"\xff\x00\x00" * width for _ in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


def finding(data, fid):
    return next(f for f in data["findings"] if f["id"] == fid)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.out = Path(self.temp.name) / "out"
        self.out.mkdir()
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        shutil.copytree(ROOT / "examples" / "evidence", self.out / "evidence")
        self.data = copy.deepcopy(SAMPLE)
        self.data["limitations"].append("report.pdf not produced: no engine in this test")
        (self.out / "evidence" / "U-006-before-360.png").write_bytes(png())
        (self.out / "evidence" / "U-006-after-360.png").write_bytes(png(3, 3))
        (self.out / "evidence" / "U-006-walkthrough.webm").write_bytes(b"\x1a\x45\xdf\xa3 test video")
        finding(self.data, "U-006")["evidence"] += [
            {"kind": "screenshot", "file": "U-006-before-360.png", "viewport": "360x640",
             "caption": "Sidebar runs past the right edge"},
            {"kind": "video", "file": "U-006-walkthrough.webm", "caption": "Scrolling sideways to reach the list"},
            {"kind": "screenshot", "file": "U-006-after-360.png", "stage": "after", "viewport": "360x640",
             "caption": "Sidebar fits after the fix"}]
        self.save()

    def save(self):
        (self.out / "findings.json").write_text(json.dumps(self.data, ensure_ascii=False), encoding="utf-8")
        (self.out / "flows.json").write_text(json.dumps(FLOWS), encoding="utf-8")
        (self.out / "inventory.json").write_text(json.dumps({
            "tool": "inventory.py", "flows_sha256": findings.canonical_digest(FLOWS)}), encoding="utf-8")

    def render(self, lang="en", out=None, expect=0):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            code = render.main([str(self.out / "findings.json"), "--out", str(out or self.out),
                                "--repo", str(self.repo), "--lang", lang, "--no-pdf"])
        self.assertEqual(code, expect, err.getvalue())
        return err.getvalue()

    def problems(self, **kwargs):
        return "\n".join(contract_check.problems(self.out, no_pdf=True, **kwargs))

    def test_report_embeds_before_and_after_and_the_page_plays_video(self):
        self.render()
        self.assertEqual(self.problems(), "")
        report = (self.out / "report.html").read_text(encoding="utf-8")
        self.assertIn("data:image/png;base64,", report)
        self.assertIn("Before (as found)", report)
        self.assertIn("After (fixed)", report)
        self.assertIn("--stages:2", report)
        self.assertIn("src/styles/app.css:6: .sidebar", report)  # The log excerpt.
        page = (self.out / "evidence.html").read_text(encoding="utf-8")
        self.assertIn('<video controls preload="metadata" src="evidence/U-006-walkthrough.webm">', page)
        self.assertIn('<meta name="ux-scan-page-kind" content="evidence.html">', page)
        self.assertIn('href="evidence.html"', (self.out / "dashboard.html").read_text(encoding="utf-8"))

    def test_screenshots_align_before_logs_so_the_pair_stays_together(self):
        block = evidence._stages(finding(self.data, "U-006"), evidence.load(self.out, self.data),
                                 "evidence", evidence.LABELS["en"], True, "h5")
        rows = block.split('<div class="evidence-stages"')[1:]
        self.assertEqual(len(rows), 2)
        self.assertIn("U-006-before-360.png", rows[0])
        self.assertIn("U-006-after-360.png", rows[0])
        self.assertIn("U-006-source.log", rows[1])
        self.assertEqual(block.count("<h5>"), 2)  # One heading per stage.
        self.assertEqual(rows[1].count('class="evidence-stage'), 2)  # An empty After cell keeps the columns.

    def add_gif_recording(self):
        item = {"kind": "video", "file": "U-006-recording.gif", "stage": "after",
                "caption": 'Focus returns to "Save" <after closing>'}
        (self.out / "evidence" / item["file"]).write_bytes(GIF)
        finding(self.data, "U-006")["evidence"].append(item)
        self.save()
        return item

    def test_gif_recordings_use_linked_images_and_keep_print_fallback(self):
        item = self.add_gif_recording()
        self.render()
        tags = Elements((self.out / "evidence.html").read_text(encoding="utf-8")).tags
        source = "evidence/" + item["file"]
        images = [attrs for tag, attrs in tags if tag == "img" and attrs.get("src") == source]
        self.assertEqual(len(images), 1)
        self.assertEqual(images[0]["alt"], item["caption"])
        self.assertFalse(any(tag == "video" and attrs.get("src") == source for tag, attrs in tags))
        # Large recordings stay external; PDF/report output continues to name the file.
        report = (self.out / "report.html").read_text(encoding="utf-8")
        self.assertNotIn('src="' + source + '"', report)
        self.assertNotIn("data:image/gif", report)
        self.assertIn('href="' + source + '"', report)
        self.assertIn(evidence.LABELS["en"]["video_print"], report)
        self.assertNotIn("data", evidence.load(self.out, self.data)[item["file"]])
        self.assertEqual(self.problems(), "")

    def test_gif_recording_page_policy_allows_local_images_without_remote_sources(self):
        self.add_gif_recording()
        self.render()
        tags = Elements((self.out / "evidence.html").read_text(encoding="utf-8")).tags
        policy = next(attrs["content"] for tag, attrs in tags
                      if tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy")
        sources = next(part.split()[1:] for part in policy.split(";") if part.strip().startswith("img-src "))
        self.assertEqual(set(sources), {"'self'", "file:", "data:"})

    def test_mp4_recordings_keep_video_controls(self):
        name = "U-006-recording.mp4"
        # Header-only fixture checks rendering choice, not MP4 decoding/playback.
        (self.out / "evidence" / name).write_bytes(b"\x00\x00\x00\x18ftypisom")
        finding(self.data, "U-006")["evidence"].append(
            {"kind": "video", "file": name, "caption": "Recorded interaction"})
        self.save()
        self.render()
        tags = Elements((self.out / "evidence.html").read_text(encoding="utf-8")).tags
        videos = [attrs for tag, attrs in tags if tag == "video" and attrs.get("src") == "evidence/" + name]
        self.assertEqual(len(videos), 1)
        self.assertIn("controls", videos[0])
        self.assertEqual(videos[0]["preload"], "metadata")
        self.assertEqual(self.problems(), "")

    def test_gif_recording_second_language_links_and_digest_remain_valid(self):
        item = self.add_gif_recording()
        self.render()
        self.render(lang="ja", out=self.out / "ja")
        tags = Elements((self.out / "ja" / "evidence.html").read_text(encoding="utf-8")).tags
        self.assertTrue(any(tag == "img" and attrs.get("src") == "../evidence/" + item["file"]
                            for tag, attrs in tags))
        self.assertEqual(self.problems(allow=["ja"]), "")
        (self.out / "evidence" / item["file"]).write_bytes(GIF + b"changed")
        self.assertIn("stale ux-scan-evidence", self.problems(allow=["ja"]))

    def test_second_language_render_links_back_to_the_evidence(self):
        self.render()
        self.render(lang="ja", out=self.out / "ja")
        page = (self.out / "ja" / "evidence.html").read_text(encoding="utf-8")
        self.assertIn('src="../evidence/U-006-walkthrough.webm"', page)
        self.assertIn("After（修正後）", page)
        self.assertEqual(self.problems(allow=["ja"]), "")

    def test_replaced_evidence_makes_the_pages_stale(self):
        self.render()
        (self.out / "evidence" / "U-006-after-360.png").write_bytes(png(4, 4))
        self.assertIn("stale ux-scan-evidence", self.problems())

    def test_every_included_finding_needs_evidence_and_a_fixed_one_its_after(self):
        del finding(self.data, "U-003")["evidence"]
        finding(self.data, "U-001")["status"] = "Fixed"
        self.save()
        self.render()
        problems = self.problems()
        self.assertIn("U-003 carry no evidence", problems)
        self.assertIn("U-001 are Fixed without evidence of the fix", problems)
        self.assertNotIn("U-026", problems)

    def test_after_evidence_alone_does_not_show_the_defect(self):
        f = finding(self.data, "U-006")
        f["status"] = "Fixed"
        for item in f["evidence"]:
            item["stage"] = "after"
        self.save()
        self.render()
        self.assertIn("U-006 carry no evidence of the defect as found", self.problems())

    def test_missing_mistyped_and_uncited_files(self):
        (self.out / "evidence" / "U-006-before-360.png").write_bytes(b"not an image")
        self.assertIn("is not a .png file", self.render(expect=2))
        (self.out / "evidence" / "U-006-before-360.png").unlink()
        self.assertIn("U-006-before-360.png: missing", self.render(expect=2))
        (self.out / "evidence" / "U-006-before-360.png").write_bytes(png())
        self.render()
        (self.out / "evidence" / "stray.png").write_bytes(png())
        self.assertIn("evidence/stray.png: no finding cites it", self.problems())

    def test_symlinked_evidence_is_refused(self):
        target = self.out / "evidence" / "U-006-before-360.png"
        real = Path(self.temp.name) / "real.png"
        real.write_bytes(png())
        target.unlink()
        target.symlink_to(real)
        self.assertIn("not a symlink", self.render(expect=2))

    def test_log_excerpts_mask_secrets(self):
        (self.out / "evidence" / "U-003-source.log").write_text(
            "$ env\nAPI_TOKEN=sk-live-1234567890abcdef\nok\n", encoding="utf-8")
        self.render()
        report = (self.out / "report.html").read_text(encoding="utf-8")
        self.assertNotIn("sk-live-1234567890abcdef", report)
        self.assertIn("[masked: looks like a secret]", report)

    def test_schema_refuses_malformed_evidence(self):
        cases = {
            "kind": {"kind": "photo", "file": "a.png", "caption": "x"},
            "extension": {"kind": "log", "file": "a.png", "caption": "x"},
            "directory": {"kind": "log", "file": "../a.log", "caption": "x"},
            "subdir": {"kind": "log", "file": "logs/a.log", "caption": "x"},
            "caption": {"kind": "log", "file": "a.log", "caption": " "},
            "stage": {"kind": "log", "file": "a.log", "caption": "x", "stage": "during"},
            "key": {"kind": "log", "file": "a.log", "caption": "x", "path": "a.log"},
            "url": {"kind": "log", "file": "a.log", "caption": "x", "url": "javascript:alert(1)"},
        }
        for name, item in cases.items():
            with self.subTest(name=name):
                data = copy.deepcopy(SAMPLE)
                finding(data, "U-001")["evidence"] = [item]
                with self.assertRaises(findings.RecordError):
                    findings.check_findings(data)
        data = copy.deepcopy(SAMPLE)
        finding(data, "U-001")["evidence"] = []
        with self.assertRaises(findings.RecordError):
            findings.check_findings(data)

    def test_renumber_keeps_evidence_file_names(self):
        data = copy.deepcopy(SAMPLE)
        finding(data, "U-001")["severity"] = "Info"
        mapping = findings.renumber_map(data["findings"])
        moved = findings.renumber(data, mapping)
        item = next(f for f in moved["findings"] if f["title"] == finding(SAMPLE, "U-001")["title"])
        self.assertNotEqual(item["id"], "U-001")
        self.assertEqual(item["evidence"][0]["file"], "U-001-source.log")

    def test_a_record_without_evidence_writes_no_evidence_page(self):
        self.render()
        for f in self.data["findings"]:
            f.pop("evidence", None)
        self.save()
        self.render()
        self.assertFalse((self.out / "evidence.html").exists())
        self.assertNotIn('href="evidence.html"', (self.out / "dashboard.html").read_text(encoding="utf-8"))


class CaptureTests(unittest.TestCase):
    def test_log_records_command_status_and_masks_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "evidence" / "U-001-run.log"
            with contextlib.redirect_stdout(io.StringIO()):
                code = capture.main(["log", "--out", str(out), "--", sys.executable, "-c",
                                     "print('ok'); print('password = \"hunter2hunter2\"'); raise SystemExit(3)"])
            self.assertEqual(code, 0)
            text = out.read_text(encoding="utf-8")
            self.assertIn("exit: 3", text)
            self.assertIn("\nok\n", text)
            self.assertNotIn("hunter2hunter2", text)
            self.assertTrue(text.startswith("[masked: looks like a secret]\ncwd: "))

    def test_log_output_is_truncated_to_what_the_renderer_accepts(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "U-001-big.log"
            with contextlib.redirect_stdout(io.StringIO()):
                code = capture.main(["log", "--out", str(out), "--", sys.executable, "-c",
                                     "import sys; sys.stdout.write('x' * 99 + '\\n') ; [print('y' * 99) for _ in range(20000)]"])
            self.assertEqual(code, 0)
            self.assertLessEqual(out.stat().st_size, evidence.MAX_BYTES["log"])
            self.assertIn("[output truncated: ", out.read_text(encoding="utf-8"))

    def run_log(self, out, script):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(capture.main(["log", "--out", str(out), "--", sys.executable, "-c", script]), 0)
        return out.read_bytes()

    def test_a_secret_far_into_a_long_line_is_masked(self):
        token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        with tempfile.TemporaryDirectory() as tmp:
            saved = self.run_log(Path(tmp) / "U-001-long.log", f"print('x' * 800 + ' {token}')")
        self.assertNotIn(token.encode(), saved)

    def test_the_written_log_fits_the_renderer_after_replacement_characters(self):
        # Each invalid byte becomes a three-byte replacement character when decoded.
        with tempfile.TemporaryDirectory() as tmp:
            saved = self.run_log(Path(tmp) / "U-001-bytes.log",
                                 "import sys; [sys.stdout.buffer.write(b'\\xff' * 99 + b'\\n') for _ in range(9000)]")
        self.assertLessEqual(len(saved), evidence.MAX_BYTES["log"])
        self.assertIn(b"[output truncated: ", saved)

    def test_names_must_be_citable(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(capture.main(["log", "--out", str(Path(tmp) / "run.png"), "--", "true"]), 2)
            self.assertEqual(capture.main(["screenshot", "http://localhost:1/", "--out",
                                           str(Path(tmp) / "shot.png"), "--viewport", "wide"]), 2)
        self.assertIn("a log file is named like", err.getvalue())
        self.assertIn("--viewport", err.getvalue())


if __name__ == "__main__":
    unittest.main()
