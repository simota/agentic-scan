"""Report publication, input boundaries and output freshness regressions."""

import contextlib
import copy
import errno
import html
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "ux-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import contract_check  # noqa: E402
import findings  # noqa: E402
import render  # noqa: E402

SAMPLE = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
FLOWS = json.loads((ROOT / "examples" / "flows.sample.json").read_text(encoding="utf-8"))
# The mocked engine tests the envelope check; full PDF syntax is an engine responsibility.
PDF_ENVELOPE = b"%PDF-1.7\n% test engine output\n%%EOF\n"


class Tags(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.tags = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


class ReportRegressions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.out = self.root / "out"
        self.out.mkdir()
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.data = copy.deepcopy(SAMPLE)
        self.flows = copy.deepcopy(FLOWS)
        self.data["limitations"].append("report.pdf not produced: no engine in this test")
        self.save_inputs()

    def save_inputs(self):
        (self.out / "findings.json").write_text(json.dumps(self.data, ensure_ascii=False), encoding="utf-8")
        (self.out / "flows.json").write_text(json.dumps(self.flows), encoding="utf-8")
        (self.out / "inventory.json").write_text(json.dumps({
            "tool": "inventory.py", "flows_sha256": findings.canonical_digest(self.flows),
        }), encoding="utf-8")

    def invoke(self, *, no_pdf=True, lang="en", out=None, source=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        args = [str(source or self.out / "findings.json"), "--out", str(out or self.out),
                "--repo", str(self.repo), "--lang", lang]
        if no_pdf:
            args.append("--no-pdf")
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = render.main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def ready_for_pdf(self):
        self.data["limitations"] = [line for line in self.data["limitations"]
                                    if not line.startswith(contract_check.NO_PDF)]
        self.save_inputs()

    def successful_engine(self, html_path, pdf_path, *args, **kwargs):
        Path(pdf_path).write_bytes(PDF_ENVELOPE)
        return "test-engine"

    def test_snippets_refuse_secret_links_directories_and_outside_paths(self):
        (self.repo / ".env").write_text("DO_NOT_PUBLISH_THIS_VALUE\n", encoding="utf-8")
        (self.repo / "alias.ts").symlink_to(".env")
        (self.repo / "secrets").mkdir()
        (self.repo / "secrets" / "config.ts").write_text("DO_NOT_PUBLISH_THIS_VALUE\n", encoding="utf-8")
        (self.repo / "linked-dir").symlink_to("secrets", target_is_directory=True)
        (self.repo / "loop.ts").symlink_to("loop.ts")
        (self.repo / "id_ed25519").write_text("DO_NOT_PUBLISH_THIS_VALUE\n", encoding="utf-8")
        outside = self.root / "outside.ts"
        outside.write_text("DO_NOT_PUBLISH_THIS_VALUE\n", encoding="utf-8")
        (self.repo / "outside.ts").symlink_to(outside)
        for location in (".env:1", "alias.ts:1", "secrets/config.ts:1", "linked-dir/config.ts:1",
                         "loop.ts:1", "id_ed25519:1", "outside.ts:1", "../outside.ts:1"):
            with self.subTest(location=location):
                self.assertIsNone(render.snippet(self.repo, location))

    def test_excerpts_are_bounded_and_mask_secret_values(self):
        (self.repo / "a.ts").write_text("const api_key = 'HIDDEN_VALUE';\n" + "safe line\n" * 1000,
                                         encoding="utf-8")
        excerpt = render.snippet(self.repo, "a.ts:1-1001")
        self.assertLessEqual(len(excerpt["lines"]), render.MAX_SNIPPET_LINES)
        self.assertNotIn("HIDDEN_VALUE", "\n".join(excerpt["lines"]))
        self.assertLessEqual(excerpt["hit"][1], excerpt["start"] + len(excerpt["lines"]) - 1)
        (self.repo / "binary.ts").write_bytes(b"value\x00tail")
        self.assertIsNone(render.snippet(self.repo, "binary.ts:1"))

    def test_source_directory_replaced_before_read_cannot_leak_an_outside_excerpt(self):
        directory = self.repo / "src"
        directory.mkdir()
        (directory / "entry.ts").write_text("safe source", encoding="utf-8")
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "entry.ts").write_text("DO_NOT_PUBLISH_OUTSIDE_SOURCE", encoding="utf-8")
        reader = render.read_regular

        def replace_directory_then_read(path, *args, **kwargs):
            directory.rename(self.repo / "saved-src")
            directory.symlink_to(outside, target_is_directory=True)
            return reader(path, *args, **kwargs)

        with mock.patch.object(render, "read_regular", side_effect=replace_directory_then_read):
            self.assertIsNone(render.snippet(self.repo, "src/entry.ts:1"))

    def test_untrusted_text_remains_text_in_both_reports(self):
        payload = '</script><script>alert("report-injection")</script><img src=x onerror=alert(1)>'
        self.data["findings"][0]["title"] = payload
        self.data["findings"][0]["location"] = "a.ts:1"
        self.data["summary"] = payload
        (self.repo / "a.ts").write_text(payload, encoding="utf-8")
        self.save_inputs()
        code, _, error = self.invoke()
        self.assertEqual(code, 0, error)
        document = (self.out / "report.html").read_text(encoding="utf-8")
        dashboard = (self.out / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn(html.escape(payload), document)
        self.assertNotIn(payload, document)
        self.assertNotIn(payload, dashboard)
        self.assertEqual([tag for tag, _ in Tags(document).tags if tag in ("script", "img")], [])
        self.assertEqual([tag for tag, _ in Tags(dashboard).tags if tag in ("script", "img")],
                         ["script", "script"])
        embedded = re.search(r'<script id="data" type="application/json">(.*?)</script>', dashboard, re.S)
        self.assertEqual(json.loads(embedded.group(1))["findings"][0]["title"], payload)

    def test_flow_changes_invalidate_inventory_and_both_pages(self):
        self.assertEqual(self.invoke()[0], 0)
        self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])
        # Formatting alone does not change the flow model.
        (self.out / "flows.json").write_text(json.dumps(self.flows, indent=4), encoding="utf-8")
        self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])
        self.flows["flows"][0]["name"] = "A renamed primary flow"
        self.flows["viewports"][0] = "320x640"
        (self.out / "flows.json").write_text(json.dumps(self.flows), encoding="utf-8")
        errors = "\n".join(contract_check.problems(self.out, no_pdf=True))
        self.assertIn("inventory.json: stale", errors)
        self.assertIn("dashboard.html: stale ux-scan-flows", errors)
        self.assertIn("report.html: stale ux-scan-flows", errors)
        self.save_inputs()
        self.assertEqual(self.invoke()[0], 0)
        self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])

    def test_inventory_without_flows_cannot_satisfy_the_final_contract(self):
        self.assertEqual(self.invoke()[0], 0)
        (self.out / "inventory.json").write_text('{"tool":"inventory.py","flows_sha256":null}', encoding="utf-8")
        self.assertIn("inventory.json: stale", "\n".join(contract_check.problems(self.out, no_pdf=True)))

    def test_coverage_requires_family_tokens_and_nonempty_results(self):
        perspective = next(p for p in self.data["perspectives"] if p["name"].startswith("AX"))
        original = perspective["name"]
        perspective["name"] = "AXanything"
        self.save_inputs()
        self.assertEqual(self.invoke()[0], 0)
        errors = "\n".join(contract_check.problems(self.out, no_pdf=True))
        self.assertIn("must start with a family token", errors)
        self.assertIn("no entry for AX", errors)
        perspective["name"] = original
        perspective["result"] = " "
        self.save_inputs()
        self.assertEqual(self.invoke()[0], 0)
        self.assertIn("needs a non-empty result", "\n".join(contract_check.problems(self.out, no_pdf=True)))

    def test_not_applicable_coverage_requires_a_reason(self):
        perspective = self.data["perspectives"][0]
        perspective.update(result="N/A", note="")
        self.save_inputs()
        self.assertEqual(self.invoke()[0], 0)
        self.assertIn("N/A without a reason", "\n".join(contract_check.problems(self.out, no_pdf=True)))
        perspective["note"] = "This family is outside the agreed surface."
        self.save_inputs()
        self.assertEqual(self.invoke()[0], 0)
        self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])

    def test_excerpts_mask_suffixed_secret_names_and_url_credentials(self):
        (self.repo / "settings.py").write_text(
            "DEBUG = False\n"
            "SECRET_KEY = 'django-insecure-HIDDEN_ONE'\n"
            "AWS_SECRET_ACCESS_KEY = 'HIDDEN_TWO'\n"
            "const config = { secretKey: 'HIDDEN_THREE' };\n"
            "DATABASE_URL = postgres://user:HIDDEN_FOUR@db/app\n"
            "label = 'Password'\n", encoding="utf-8")
        lines = render.snippet(self.repo, "settings.py:3")["lines"]
        self.assertNotIn("HIDDEN", "\n".join(lines))
        self.assertIn("label = 'Password'", lines)
        for name in (".envrc", ".dev.vars", "prod.tfvars", ".git/config"):
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("value = 1\n", encoding="utf-8")
            with self.subTest(name=name):
                self.assertIsNone(render.snippet(self.repo, f"{name}:1"))

    def test_excerpt_lines_follow_editor_line_numbers(self):
        (self.repo / "a.js").write_bytes(
            "line1\n\fline2\nline3\nline4 \u2028 has LS\nline5\x85\nline6 TARGET\r\nline7\rline8\n".encode("utf-8"))
        excerpt = render.snippet(self.repo, "a.js:6")
        self.assertEqual(excerpt["start"], 3)
        self.assertEqual(excerpt["lines"][excerpt["hit"][0] - excerpt["start"]], "line6 TARGET")
        self.assertEqual(excerpt["lines"][-1], "line8")
        self.data["findings"][0]["location"] = "a.js:6"
        self.save_inputs()
        self.assertEqual(self.invoke()[0], 0)

    def test_japanese_reports_localize_the_mask(self):
        (self.repo / "a.ts").write_text("const token = 'HIDDEN';\n", encoding="utf-8")
        self.data["findings"][0]["location"] = "a.ts:1"
        self.save_inputs()
        self.assertEqual(self.invoke(lang="ja")[0], 0)
        page = (self.out / "report.html").read_text(encoding="utf-8")
        self.assertIn(render.LABELS["ja"]["masked"], page)
        self.assertNotIn("HIDDEN", page)

    def test_open_valid_finding_without_a_fix_is_not_offered_as_an_empty_fix(self):
        finding = self.data["findings"][0]
        self.assertEqual((finding["status"], finding["validation"]["verdict"]), ("Open", "Valid"))
        del finding["fix"]
        item = render.to_common(self.data, "en", self.flows)["findings"][0]
        self.assertEqual(item["action"]["label"], render.LABELS["en"]["verify"])

    def test_not_applicable_punctuation_is_not_a_reason(self):
        perspective = self.data["perspectives"][0]
        for result in ("N/A.", "N/A：", "n/a —", "N/A。"):
            with self.subTest(result=result):
                perspective.update(result=result, note="")
                self.save_inputs()
                self.assertEqual(self.invoke()[0], 0)
                self.assertIn("N/A without a reason", "\n".join(contract_check.problems(self.out, no_pdf=True)))
        perspective.update(result="N/A: no motion in the product")
        self.save_inputs()
        self.assertEqual(self.invoke()[0], 0)
        self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])

    def test_allowed_second_language_render_is_verified(self):
        self.assertEqual(self.invoke()[0], 0)
        self.assertIn("ja: expected a directory holding the ja render",
                      "\n".join(contract_check.problems(self.out, no_pdf=True, allow=["ja"])))
        self.assertEqual(self.invoke(lang="ja", out=self.out / "ja")[0], 0)
        self.assertEqual(list(contract_check.problems(self.out, no_pdf=True, allow=["ja"])), [])
        self.data["findings"][0]["title"] = "Changed after the translation"
        self.save_inputs()
        self.assertEqual(self.invoke()[0], 0)
        errors = "\n".join(contract_check.problems(self.out, no_pdf=True, allow=["ja"]))
        self.assertIn("ja/report.html: stale ux-scan-source", errors)
        self.assertIn("ja/dashboard.html: stale ux-scan-source", errors)
        self.assertEqual(self.invoke(lang="ja", out=self.out / "ja")[0], 0)
        self.assertEqual(list(contract_check.problems(self.out, no_pdf=True, allow=["ja"])), [])
        (self.out / "ja" / "notes.txt").write_text("extra", encoding="utf-8")
        (self.out / "ja" / "report.html").unlink()
        errors = "\n".join(contract_check.problems(self.out, no_pdf=True, allow=["ja"]))
        self.assertIn("ja/report.html: missing", errors)
        self.assertIn("ja/notes.txt: not part of", errors)
        (self.out / "ja" / "notes.txt").unlink()
        self.assertEqual(self.invoke(lang="en", out=self.out / "ja")[0], 0)
        self.assertIn("ja/report.html: missing or invalid report language",
                      "\n".join(contract_check.problems(self.out, no_pdf=True, allow=["ja"])))

    def test_contract_rejects_non_object_and_invalid_utf8_without_tracebacks(self):
        self.assertEqual(self.invoke()[0], 0)
        for source in (b"[]", b"null", b"42", b'"text"', b"\xff"):
            with self.subTest(source=source):
                (self.out / "inventory.json").write_bytes(source)
                result = subprocess.run([sys.executable, str(SCRIPTS / "contract_check.py"), str(self.out), "--no-pdf"],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("inventory.json:", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_flow_digest_errors_are_reported_without_tracebacks(self):
        self.assertEqual(self.invoke()[0], 0)
        self.flows["app"] = "\ud800"
        (self.out / "flows.json").write_text(json.dumps(self.flows), encoding="utf-8")
        result = subprocess.run([sys.executable, str(SCRIPTS / "contract_check.py"), str(self.out), "--no-pdf"],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("flows.json:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_contract_never_reads_symlinks_or_directories(self):
        self.assertEqual(self.invoke()[0], 0)
        protected = self.root / "protected.json"
        protected.write_text("DO_NOT_READ_THIS_FILE", encoding="utf-8")
        for name in contract_check.REQUIRED:
            path = self.out / name
            original = path.read_bytes()
            for kind in ("symlink", "directory"):
                with self.subTest(name=name, kind=kind):
                    path.unlink()
                    if kind == "symlink":
                        path.symlink_to(protected)
                    else:
                        path.mkdir()
                    errors = "\n".join(contract_check.problems(self.out, no_pdf=True))
                    self.assertIn("must be a regular file", errors)
                    self.assertNotIn("DO_NOT_READ_THIS_FILE", errors)
                    path.unlink() if kind == "symlink" else path.rmdir()
                    path.write_bytes(original)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFOs require POSIX")
    def test_contract_refuses_fifo_without_waiting_for_a_writer(self):
        self.assertEqual(self.invoke()[0], 0)
        path = self.out / "findings.json"
        path.unlink()
        os.mkfifo(path)
        result = subprocess.run([sys.executable, str(SCRIPTS / "contract_check.py"), str(self.out), "--no-pdf"],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("must be a regular file", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_contract_reports_read_errors_without_crashing(self):
        self.assertEqual(self.invoke()[0], 0)
        reader = contract_check.read_regular

        def fail_inventory(path, *args, **kwargs):
            if Path(path).name == "inventory.json":
                raise PermissionError(errno.EACCES, "permission denied")
            return reader(path, *args, **kwargs)

        with mock.patch.object(contract_check, "read_regular", side_effect=fail_inventory):
            self.assertIn("inventory.json:", "\n".join(contract_check.problems(self.out, no_pdf=True)))

    def test_metadata_in_comments_does_not_count_as_a_source_stamp(self):
        self.assertEqual(self.invoke()[0], 0)
        path = self.out / "report.html"
        source = path.read_text(encoding="utf-8")
        source = re.sub(r'<meta name="ux-scan-source" content="[^"]+">', lambda m: "<!--" + m[0] + "-->", source)
        path.write_text(source, encoding="utf-8")
        self.assertIn("report.html: stale ux-scan-source", "\n".join(contract_check.problems(self.out, no_pdf=True)))

    def test_truncated_html_with_intact_input_stamps_is_rejected(self):
        for name in ("dashboard.html", "report.html"):
            with self.subTest(name=name):
                self.assertEqual(self.invoke()[0], 0)
                path = self.out / name
                source = path.read_text(encoding="utf-8")
                path.write_text(source[:source.index("</head>") + len("</head>")], encoding="utf-8")
                errors = "\n".join(contract_check.problems(self.out, no_pdf=True))
                self.assertIn(f"{name}: altered or incomplete HTML", errors)

    def test_complete_html_changes_cannot_keep_an_old_page_fingerprint(self):
        for name in ("dashboard.html", "report.html"):
            for closing in ("</style>", "</body>") + (("</script>",) if name == "dashboard.html" else ()):
                with self.subTest(name=name, closing=closing):
                    self.assertEqual(self.invoke()[0], 0)
                    path = self.out / name
                    source = path.read_text(encoding="utf-8")
                    # Preserve valid HTML and every input stamp while changing its actual bytes.
                    path.write_text(source.replace(closing, "\n " + closing, 1), encoding="utf-8")
                    errors = "\n".join(contract_check.problems(self.out, no_pdf=True))
                    self.assertIn(f"{name}: altered or incomplete HTML", errors)

    def test_page_fingerprint_requires_one_canonical_tag_in_the_head(self):
        for change in ("missing", "duplicate", "duplicate-in-comment", "body", "malformed", "wrong-digest"):
            with self.subTest(change=change):
                self.assertEqual(self.invoke()[0], 0)
                path = self.out / "report.html"
                source = path.read_text(encoding="utf-8")
                tag = re.search(r'<meta name="ux-scan-page" content="sha256:[0-9a-f]{64}">', source)[0]
                if change == "missing":
                    changed = source.replace(tag, "", 1)
                elif change == "duplicate":
                    changed = source.replace(tag, tag + tag, 1)
                elif change == "duplicate-in-comment":
                    changed = source.replace(tag, tag + "<!--" + tag + "-->", 1)
                elif change == "body":
                    changed = source.replace(tag, "", 1).replace("<body>", "<body>" + tag, 1)
                elif change == "malformed":
                    changed = source.replace(tag, tag.replace("sha256:", "invalid:"), 1)
                else:
                    changed = source.replace(tag, '<meta name="ux-scan-page" content="sha256:' + "0" * 64 + '">', 1)
                path.write_text(changed, encoding="utf-8")
                errors = "\n".join(contract_check.problems(self.out, no_pdf=True))
                self.assertIn("report.html:", errors)
                self.assertIn("page fingerprint", errors)

    def test_mixed_language_pages_are_not_a_complete_render(self):
        self.assertEqual(self.invoke(lang="en")[0], 0)
        english = (self.out / "dashboard.html").read_bytes()
        self.assertEqual(self.invoke(lang="ja")[0], 0)
        (self.out / "dashboard.html").write_bytes(english)
        self.assertIn("pages: different render versions", "\n".join(contract_check.problems(self.out, no_pdf=True)))

    def test_mixed_renderer_revisions_are_rejected_with_unchanged_record_and_language(self):
        self.assertEqual(self.invoke()[0], 0)
        old_dashboard = (self.out / "dashboard.html").read_bytes()
        document = render.report.render_document

        def changed_document(*args):
            return document(*args).replace("</style>", "body { font-size: 18px; }</style>", 1)

        with mock.patch.object(render.report, "render_document", side_effect=changed_document):
            self.assertEqual(self.invoke()[0], 0)
        self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])
        (self.out / "dashboard.html").write_bytes(old_dashboard)
        self.assertIn("pages: different render versions", "\n".join(contract_check.problems(self.out, no_pdf=True)))

    def test_copied_or_swapped_pages_do_not_satisfy_their_output_roles(self):
        for replacements in (("dashboard.html",), ("report.html",), ("dashboard.html", "report.html")):
            with self.subTest(replacements=replacements):
                self.assertEqual(self.invoke()[0], 0)
                original = {name: (self.out / name).read_bytes() for name in ("dashboard.html", "report.html")}
                other_page = {"dashboard.html": "report.html", "report.html": "dashboard.html"}
                for name in replacements:
                    (self.out / name).write_bytes(original[other_page[name]])
                errors = "\n".join(contract_check.problems(self.out, no_pdf=True))
                for name in replacements:
                    self.assertIn(f"{name}: wrong or missing page kind", errors)
                # The copied pages retain valid hashes; the failure is their role.
                self.assertNotIn("page fingerprint", errors)

    def test_no_pdf_requires_an_explanation_and_cannot_allow_an_old_pdf(self):
        self.data["limitations"] = [contract_check.NO_PDF + ": "]
        self.save_inputs()
        self.assertEqual(self.invoke()[0], 0)
        errors = "\n".join(contract_check.problems(self.out, no_pdf=True))
        self.assertIn("needs the line", errors)
        (self.out / "report.pdf").write_bytes(PDF_ENVELOPE)
        errors = "\n".join(contract_check.problems(self.out, no_pdf=True, allow=["report.pdf"]))
        self.assertIn("report.pdf: must be absent", errors)

    def test_output_inside_the_reviewed_repository_is_refused(self):
        code, _, error = self.invoke(out=self.repo / "report")
        self.assertEqual(code, 2, error)
        self.assertIn("outside --repo", error)
        self.assertFalse((self.repo / "report").exists())

    def test_findings_input_cannot_be_replaced_or_deleted_as_an_output(self):
        record = (self.out / "findings.json").read_bytes()
        for name in render.OUTPUTS:
            for alias_at in (None, "input", "output", "hardlink"):
                with self.subTest(name=name, alias_at=alias_at):
                    directory = self.root / (name + "-" + str(alias_at))
                    directory.mkdir()
                    for output_name in render.OUTPUTS:
                        (directory / output_name).write_bytes(record if output_name == name else b"previous output")
                    before = {path.name: path.read_bytes() for path in directory.iterdir()}
                    source, out = directory / name, directory
                    if alias_at == "hardlink":
                        source = self.root / (directory.name + ".json")
                        os.link(directory / name, source)
                    elif alias_at is not None:
                        alias = directory.with_name(directory.name + "-alias")
                        alias.symlink_to(directory, target_is_directory=True)
                        if alias_at == "input":
                            source = alias / name
                        else:
                            out = alias
                    code, _, error = self.invoke(out=out, source=source)
                    self.assertEqual(code, 2, error)
                    self.assertIn("input", error)
                    self.assertIn("output", error)
                    self.assertEqual({path.name: path.read_bytes() for path in directory.iterdir()}, before)

    def test_unsafe_output_is_refused_before_any_write(self):
        self.assertEqual(self.invoke()[0], 0)
        old_dashboard = (self.out / "dashboard.html").read_bytes()
        protected = self.root / "protected.html"
        protected.write_bytes(b"keep this file")
        (self.out / "report.html").unlink()
        (self.out / "report.html").symlink_to(protected)
        code, _, error = self.invoke()
        self.assertEqual(code, 2, error)
        self.assertIn("refusing to write", error)
        self.assertEqual(protected.read_bytes(), b"keep this file")
        self.assertEqual((self.out / "dashboard.html").read_bytes(), old_dashboard)

    def test_pdf_is_fingerprinted_and_replacing_it_is_detected(self):
        self.ready_for_pdf()
        with mock.patch.object(render.pdf, "to_pdf", side_effect=self.successful_engine):
            code, _, error = self.invoke(no_pdf=False)
        self.assertEqual(code, 0, error)
        self.assertEqual(list(contract_check.problems(self.out)), [])
        (self.out / "report.pdf").write_bytes(PDF_ENVELOPE.replace(b"test engine", b"another engine"))
        errors = "\n".join(contract_check.problems(self.out))
        self.assertIn("dashboard.html: stale ux-scan-pdf", errors)
        self.assertIn("report.html: stale ux-scan-pdf", errors)

    def test_empty_and_truncated_engine_outputs_are_failures(self):
        self.ready_for_pdf()
        for bad_pdf in (b"", b"not a PDF\n%%EOF\n", b"%PDF-1.7\npartial content"):
            with self.subTest(pdf=bad_pdf):
                def incomplete_engine(html_path, pdf_path, *args, **kwargs):
                    Path(pdf_path).write_bytes(bad_pdf)
                    return "test-engine"
                with mock.patch.object(render.pdf, "to_pdf", side_effect=incomplete_engine):
                    code, _, error = self.invoke(no_pdf=False)
                self.assertEqual(code, 3, error)
                self.assertIn("not a complete PDF", error)
                self.assertFalse((self.out / "report.pdf").exists())

    def test_pdf_failure_diagnostics_mask_values_as_well_as_keys(self):
        self.ready_for_pdf()

        def failed_engine(html_path, pdf_path, failures, timeout, redact):
            failures.append(("test-engine", "failed", redact("api_key=DO_NOT_LEAK_VALUE")))
            return None

        with mock.patch.object(render.pdf, "to_pdf", side_effect=failed_engine):
            code, _, error = self.invoke(no_pdf=False)
        self.assertEqual(code, 3, error)
        self.assertIn("masked", error)
        self.assertNotIn("DO_NOT_LEAK_VALUE", error)

    def test_pdf_diagnostic_callback_withholds_truncated_secret_values(self):
        secret = "DO_NOT_LEAK_VALUE_" + "x" * 400
        for text in ("api_key=" + secret, secret[-300:], "engine echoed report text"):
            with self.subTest(text=text[:20]):
                masked = render.redact_diagnostic(text)
                self.assertIn("masked", masked)
                self.assertNotIn(text, masked)

    def test_pdf_failure_publication_masks_even_unredacted_engine_tails(self):
        self.ready_for_pdf()
        secret = "DO_NOT_LEAK_VALUE_" + "x" * 400

        def failed_engine(html_path, pdf_path, failures, timeout, redact):
            # The upstream engine truncates before its callback, so the key can be lost.
            tail = render.pdf._tail("api_key=" + secret, redact)
            failures.append(("chrome", "timed out after 10 s", tail))
            # Some engine failure paths append diagnostics without calling redact at all.
            failures.append(("weasyprint", "could not be started", secret))
            return None

        with mock.patch.object(render.pdf, "to_pdf", side_effect=failed_engine):
            code, _, error = self.invoke(no_pdf=False)
        self.assertEqual(code, 3, error)
        self.assertIn("chrome timed out after 10 s", error)
        self.assertIn("weasyprint could not be started", error)
        self.assertIn("masked", error)
        self.assertNotIn("DO_NOT_LEAK_VALUE", error)
        self.assertNotIn("x" * 100, error)

    def test_pdf_io_failure_is_reported_and_partial_output_removed(self):
        self.ready_for_pdf()

        def failed_engine(html_path, pdf_path, *args, **kwargs):
            Path(pdf_path).write_bytes(b"%PDF-1.7\npartial")
            raise OSError(errno.EIO, "simulated disk failure")

        with mock.patch.object(render.pdf, "to_pdf", side_effect=failed_engine):
            code, _, error = self.invoke(no_pdf=False)
        self.assertEqual(code, 2, error)
        self.assertIn("simulated disk failure", error)
        self.assertFalse((self.out / "report.pdf").exists())

    def test_non_utf8_engine_output_is_a_failure_and_removes_partial_pdf(self):
        self.ready_for_pdf()
        bin_dir = self.out.parent / "engine-bin"
        bin_dir.mkdir(exist_ok=True)
        engine = bin_dir / "weasyprint"
        for stream in (1, 2):
            with self.subTest(stream=stream):
                # A real child process on PATH, so the kit's own capture and decode path runs.
                engine.write_text(
                    "#!" + sys.executable + "\n"
                    "import os, sys\nfrom pathlib import Path\n"
                    "Path(sys.argv[-1]).write_bytes(b'%PDF-1.7\\npartial')\n"
                    f"os.write({stream}, b'DO_NOT_LEAK_ENGINE_OUTPUT\\xff')\nsys.exit(1)\n",
                    encoding="utf-8")
                engine.chmod(0o755)
                with mock.patch.dict(os.environ, {"CHROME": str(bin_dir / "missing-test-chrome"),
                                                  "PATH": str(bin_dir)}):
                    code, _, error = self.invoke(no_pdf=False)
                self.assertEqual(code, 3, error)
                self.assertIn("weasyprint", error)
                self.assertNotIn("DO_NOT_LEAK_ENGINE_OUTPUT", error)
                self.assertNotIn("Traceback", error)
                self.assertFalse((self.out / "report.pdf").exists())

    def test_html_staging_failure_preserves_previous_complete_reports(self):
        self.ready_for_pdf()
        with mock.patch.object(render.pdf, "to_pdf", side_effect=self.successful_engine):
            self.assertEqual(self.invoke(no_pdf=False)[0], 0)
        before = {name: (self.out / name).read_bytes() for name in render.OUTPUTS}
        self.data["summary"] = "Changed report content"
        self.save_inputs()
        writer = render.output.write_output

        def fail_second_page(path, text):
            if Path(path).name == "report.html":
                raise OSError(errno.ENOSPC, "simulated full disk")
            return writer(path, text)

        with mock.patch.object(render.output, "write_output", side_effect=fail_second_page):
            code, _, error = self.invoke(no_pdf=False)
        self.assertEqual(code, 2, error)
        self.assertEqual({name: (self.out / name).read_bytes() for name in render.OUTPUTS}, before)
        self.assertIn("stale", "\n".join(contract_check.problems(self.out)))

    def test_html_publication_failure_restores_both_pages_and_previous_pdf(self):
        self.ready_for_pdf()
        with mock.patch.object(render.pdf, "to_pdf", side_effect=self.successful_engine):
            self.assertEqual(self.invoke(no_pdf=False)[0], 0)
        before = {name: (self.out / name).read_bytes() for name in render.OUTPUTS}
        self.data["summary"] = "Changed report content"
        self.save_inputs()
        replace = render.output.os.replace

        def fail_second_page(source, destination):
            if Path(source).parent.name == "new" and Path(destination) == self.out / "report.html":
                raise OSError(errno.EIO, "simulated publication failure")
            return replace(source, destination)

        with mock.patch.object(render.output.os, "replace", side_effect=fail_second_page):
            code, _, error = self.invoke(no_pdf=False)
        self.assertEqual(code, 2, error)
        self.assertEqual({name: (self.out / name).read_bytes() for name in render.OUTPUTS}, before)
        self.assertFalse(any(path.name.startswith(".scan-report-output-") for path in self.out.iterdir()))

    def test_pdf_metadata_publication_failure_leaves_both_current_html_pages_without_pdf(self):
        self.ready_for_pdf()
        writer = render.output.write_output

        def fail_second_page(path, text):
            if Path(path).name == "report.html" and f'name="{render.PDF_STAMP}"' in text:
                raise OSError(errno.ENOSPC, "simulated full disk")
            return writer(path, text)

        with mock.patch.object(render.pdf, "to_pdf", side_effect=self.successful_engine), \
                mock.patch.object(render.output, "write_output", side_effect=fail_second_page):
            code, _, error = self.invoke(no_pdf=False)
        self.assertEqual(code, 2, error)
        self.assertFalse((self.out / "report.pdf").exists())
        for name in ("dashboard.html", "report.html"):
            source = (self.out / name).read_bytes()
            metadata = contract_check.PageMetadata(source.decode("utf-8"))
            self.assertNotIn(render.PDF_STAMP, metadata.stamps)
            self.assertEqual(metadata.stamps[render.PAGE_STAMP], [render.page_stamp(source)])
            self.assertEqual(metadata.stamps[render.STAMP], [render.source_stamp((self.out / "findings.json").read_bytes())])


if __name__ == "__main__":
    unittest.main()
