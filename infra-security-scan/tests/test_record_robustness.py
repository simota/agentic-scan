"""Malformed or hostile records give exit 2 and a message, never a traceback or a
half-written output; references are found the same way by every tool."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-security-scan" / "scripts"))
import contract_check  # noqa: E402
import findings  # noqa: E402
import iac_scan  # noqa: E402
import redaction  # noqa: E402
import excerpts  # noqa: E402
import render  # noqa: E402

META = {"project": "p", "scope": "s", "date": "2026-10-09", "assessor": "test"}
SAMPLE = REPO / "examples" / "findings.sample.json"


def finding(fid, severity="Medium", location="main.tf:1", **extra):
    f = {"id": fid, "title": "t", "severity": severity, "confidence": "Suspected",
         "category": "Network exposure", "provider": "aws", "resources": ["aws_s3_bucket.b"],
         "location": location, "actor": "a", "path": "1. edge (main.tf:1)", "contrast": "none",
         "impact": "i", "fix": "f", "regression": "r", "validation": {"verdict": "Likely"}}
    f.update(extra)
    return f


def call(main, *argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main([str(a) for a in argv])
    return code, out.getvalue() + err.getvalue()


class RecordRobustnessTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.record = self.root / "findings.json"

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, data, name="findings.json"):
        path = self.root / name
        path.write_text(json.dumps(data) if not isinstance(data, str) else data, encoding="utf-8")
        return path

    def record_with(self, **changes):
        data = render.empty_record()
        data["meta"] = dict(META)
        data.update(changes)
        return data

    def test_malformed_records_exit_2(self):
        shapes = [[], {"findings": 5}, {"meta": []}, {"perspectives": ["x"]}, {"findings": [{"id": ["x"]}]},
                  {"next_steps": "x"}]
        deep = '{"next_steps": ' + "[" * 900 + "]" * 900 + "}"
        for shape in [*shapes, deep]:
            self.write(shape)
            frag = self.write({"limitations": ["l"]}, "frag.json")
            for argv in (("status", self.record), ("remove", self.record, "F-001"),
                         ("renumber", self.record), ("merge", self.record, frag)):
                code, out = call(findings.main, *argv)
                self.assertEqual(code, 2, (shape if not isinstance(shape, str) else "deep", argv, out))
            out_dir = self.root / "out"
            out_dir.mkdir(exist_ok=True)
            self.write(shape, "out/findings.json")
            code, out = call(contract_check.main, out_dir, "--no-pdf")
            self.assertEqual(code, 2, (shape if not isinstance(shape, str) else "deep", out))

    def test_values_python_cannot_convert_are_schema_errors(self):
        for change in ({"findings": [finding("F-001", location="a.tf:" + "1" * 5000)]},
                       {"findings": [finding("F-" + "1" * 5000)]},
                       {"findings": [finding("F-001", references=[{"title": "t", "url": "https://[::1"}])]},
                       {"findings": [finding("F-001", references=[{"title": "t", "url": "https://ex／ample.com/"}])]},
                       {"checked_ok": ["ok \ud800"]},
                       {"inventory": {"not_run": 5}},
                       {"inventory": {"resources": "many"}},
                       {"inventory": {"by_provider": {"aws": -5}}},
                       {"meta": {**META, "inputs": [{"kind": "iac", "path": "x", "note": {"a": 1}}]}},
                       {"findings": [finding("F-000")]}):
            with self.subTest(change=str(change)[:80]):
                with self.assertRaises(render.SchemaError):
                    render.validate(self.record_with(**change))

    def test_lone_surrogate_does_not_clobber_previous_outputs(self):
        out = self.root / "out"
        code, msg = call(render.main, SAMPLE, "--out", out, "--no-pdf")
        self.assertEqual(code, 0, msg)
        before = (out / "dashboard.html").read_bytes()
        data = json.loads(SAMPLE.read_text(encoding="utf-8"))
        data["checked_ok"].append("ok \ud800")
        bad = self.root / "bad.json"
        bad.write_text(json.dumps(data), encoding="utf-8")
        code, msg = call(render.main, bad, "--out", out, "--no-pdf")
        self.assertEqual(code, 2, msg)
        self.assertEqual((out / "dashboard.html").read_bytes(), before)

    def test_merge_refuses_a_lone_surrogate(self):
        frag = self.write({"findings": [finding("F-001", title="x\ud800y")]}, "frag.json")
        code, out = call(findings.main, "merge", self.record, frag)
        self.assertEqual(code, 2, out)
        self.assertFalse(self.record.exists())

    def test_non_utf8_file_name_is_noted_not_a_crash(self):
        repo = self.root / "repo"
        repo.mkdir()
        try:
            (repo / b"bad\xff.tf".decode("utf-8", "surrogateescape")).write_text("x = 1\n")
        except (OSError, UnicodeError):
            self.skipTest("file system refuses non-UTF-8 names")
        code, out = call(iac_scan.main, repo, "--out", self.root / "iac.json", "--into", self.record)
        self.assertEqual(code, 0, out)
        self.assertIn("file name is not UTF-8, skipped: bad\\xff.tf",
                      json.loads(self.record.read_text(encoding="utf-8"))["inventory"]["not_run"])

    def test_cited_edge_check_is_linear(self):
        f = finding("F-001", confidence="Confirmed", validation={"verdict": "Valid", "evidence": "e"},
                    path="1. " + "a.b" * 20000)
        start = time.monotonic()
        with self.assertRaises(render.SchemaError):
            render.validate(self.record_with(findings=[f]))
        self.assertLess(time.monotonic() - start, 2)

    def test_contract_order_ties_follow_ids(self):
        out = self.root / "out"
        out.mkdir()
        data = self.record_with(findings=[finding("F-002", "High", "a.tf:1"), finding("F-001", "High", "a.tf:1")])
        problems = contract_check.check(data, out, pdf=False)
        self.assertFalse([p for p in problems if "severity order" in p], problems)

    def test_references_in_urls_and_other_trackers_are_left_alone(self):
        url = "https://tracker.example.com/issue?key=F-002&x=1"
        data = self.record_with(findings=[
            finding("F-001", "Low", "b.tf:1", references=[{"title": "upstream F-002", "url": url}]),
            finding("F-002", "High", "a.tf:1", fix="see #F-123 and https://t.example/?F-777")],
            decisions=["F-002/F-001 share one fix; also F-001&F-002", "F-002は本番で再確認する"])
        self.write(data)
        code, out = call(findings.main, "renumber", self.record)
        self.assertEqual(code, 0, out)
        renumbered = json.loads(self.record.read_text(encoding="utf-8"))["findings"]
        low = next(f for f in renumbered if f["severity"] == "Low")
        self.assertEqual(low["references"][0], {"title": "upstream F-002", "url": url})
        high = next(f for f in renumbered if f["severity"] == "High")
        self.assertEqual(high["fix"], "see #F-123 and https://t.example/?F-777")
        decisions = json.loads(self.record.read_text(encoding="utf-8"))["decisions"]
        self.assertEqual(decisions, ["F-001/F-002 share one fix; also F-002&F-001", "F-001は本番で再確認する"])
        code, out = call(findings.main, "remove", self.record, "F-002")
        self.assertEqual(code, 1, out)  # still named in decisions

    def test_ids_in_file_paths_are_not_references(self):
        data = self.record_with(findings=[
            finding("F-001", "Low", "docs/F-001/main.tf:1", fix="see evidence/F-002/notes.md and docs/F-002"),
            finding("F-002", "High", "a.tf:1")], decisions=["F-002/F-001 share one fix"])
        self.write(data)
        code, out = call(findings.main, "renumber", self.record)
        self.assertEqual(code, 0, out)
        record = json.loads(self.record.read_text(encoding="utf-8"))
        low = next(f for f in record["findings"] if f["severity"] == "Low")
        self.assertEqual((low["location"], low["fix"]),
                         ("docs/F-001/main.tf:1", "see evidence/F-002/notes.md and docs/F-002"))
        self.assertEqual(record["decisions"], ["F-001/F-002 share one fix"])

    def test_dangling_baseline_references(self):
        data = self.record_with(findings=[finding("F-001", fix="root cause of I-999")],
                                decisions=["I-077の判定は保留"],
                                limitations=["I-004 (was I-003): Valid triage not carried over; affected "
                                             "resources changed. Recheck this baseline finding.",
                                             "I-005 is only reachable from the VPN"])
        # Only the carry-over note iac_scan.py writes may name an earlier scan's IDs.
        self.assertEqual(sorted(render.dangling_references(data)),
                         [("F-001.fix", "I-999"), ("decisions", "I-077"), ("limitations", "I-005")])

    def test_bidi_controls_are_shown_not_applied(self):
        self.assertEqual(render.esc("a‮b"), "a[U+202E]b")

    def test_piped_and_hashed_secrets_are_scrubbed(self):
        pw = "Zq" + "x9" * 5 + "Wp"
        apr1 = "$apr1$" + "x7Ab.9Qz" + "$" + "Kq3/Lm.Zp8wR1tY5uV2sB0"
        for line in (f"  - run: echo {pw} | docker login -u ci --password-stdin",
                     f"echo '{pw}' | sudo chpasswd", f"admin:{apr1}"):
            self.assertNotIn(pw if pw in line else apr1, redaction.scrub_line(line, "yaml"))
        self.assertEqual(redaction.scrub_line("echo hello | grep x"), "echo hello | grep x")
        self.assertTrue(excerpts.SENSITIVE_NAME.search("deploy/.htpasswd"))
        for line in (f"run: echo {pw} | sudo -S systemctl restart app", f'command = "echo {pw} | vault login -"',
                     f"run: htpasswd -bc /etc/nginx/.htpasswd admin {pw}"):
            self.assertNotIn(pw, redaction.scrub_line(line, "yaml"), line)
        self.assertEqual(redaction.scrub_line("htpasswd -c /etc/x admin"), "htpasswd -c /etc/x admin")

    def test_bidi_controls_stay_out_of_copied_markdown(self):
        data = json.loads(SAMPLE.read_text(encoding="utf-8"))
        data["findings"][0]["title"] = "safe\u202etxt.exe"
        page = render.render_dashboard(data, render.LABELS["en"], "en", {})
        self.assertNotIn("\u202e", page)


class PerspectiveNameTest(unittest.TestCase):
    def test_rule_categories_are_perspective_names(self):
        names = set(render.perspective_names())
        self.assertEqual(len(names), len(render.perspective_names()))
        for rule, (_, _, category, *_rest) in iac_scan.RULES.items():
            self.assertIn(category, names, rule)

    def test_only_the_first_table_names_perspectives(self):
        text = (render.SKILL / "reference" / "perspectives.md").read_text(encoding="utf-8")
        first = text.index("\n| ")
        end = text.index("\n\n", first)
        rows = [line for line in text[first:end].splitlines() if line.startswith("|")][2:]
        self.assertEqual(render.perspective_names(), [r.strip("|").split("|")[0].strip() for r in rows])


if __name__ == "__main__":
    unittest.main()
