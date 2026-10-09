"""Regressions for Unicode input, source paths and the output contract."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_findings_regressions import doc_with_optional_prose, set_value
from test_privacy_scan import complete_doc, finding, findings, render


def field_name(path):
    result = ""
    for part in path:
        result += f"[{part}]" if isinstance(part, int) else ("." if result else "") + part
    return result


def write_outputs(out, doc=None):
    out.mkdir()
    (out / "findings.json").write_text(json.dumps(doc or complete_doc()), encoding="utf-8")
    for name in ("report.md", "dashboard.html"):
        (out / name).write_text("previous output", encoding="utf-8")


class UnicodeInputTests(unittest.TestCase):
    def test_surrogates_are_rejected_at_every_string_field_without_echoing_values(self):
        paths = (
            *(("meta", key) for key in
              ("project", "scope", "date", "assessor", "lang", "commit", "method")),
            *(("findings", 0, key) for key in
              ("id", "title", "severity", "confidence", "category", "step", "location",
               "data", "subjects", "flow", "impact", "fix", "guard", "contrast",
               "commitment", "status")),
            *(("findings", 0, "validation", key) for key in ("verdict", "method", "evidence")),
            *(("findings", 0, "analysis", key) for key in ("tool", "command", "result")),
            *(("findings", 0, "references", 0, key) for key in ("title", "url")),
            *(("commitments", 0, key) for key in
              ("id", "statement", "source", "status", "family", "reason")),
            *(("perspectives", 0, key) for key in ("name", "status", "note")),
            *((key, 0) for key in ("checked_ok", "decisions", "limitations", "next_steps")),
        )
        for surrogate in ("\ud800", "\udfff"):
            with self.subTest(surrogate=ascii(surrogate)):
                accepted = []
                for path in paths:
                    doc = doc_with_optional_prose()
                    value = "synthetic-private-marker" + surrogate
                    if path[-1] == "location":
                        value = "src/" + value + ".py:22"
                    set_value(doc, path, value)
                    try:
                        findings.validate(doc, complete=True)
                    except findings.SchemaError as exc:
                        message = str(exc)
                        self.assertIn(field_name(path), message)
                        self.assertNotIn("synthetic-private-marker", message)
                        self.assertNotIn(surrogate, message)
                    else:
                        accepted.append(field_name(path))
                self.assertEqual(accepted, [])

    def test_invalid_unicode_cannot_truncate_existing_record_or_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / "output"
            write_outputs(out)
            originals = {name: (out / name).read_bytes() for name in findings.OUTPUTS}
            fragment = root / "fragment.json"
            fragment.write_text(json.dumps({"meta": {"project": "synthetic-private-marker\ud800"}}),
                                encoding="utf-8")
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(findings.main([
                    "merge", str(out / "findings.json"), str(fragment)]), 1)
            self.assertEqual({name: (out / name).read_bytes() for name in findings.OUTPUTS},
                             originals)

            doc = complete_doc()
            doc["meta"]["project"] = "synthetic-private-marker\udfff"
            record = out / "findings.json"
            record.write_text(json.dumps(doc), encoding="utf-8")
            with redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(render.main([str(record), "--out", str(out)]), 2)
                self.assertEqual(findings.main(["check", str(out)]), 1)
            for name in ("report.md", "dashboard.html"):
                self.assertEqual((out / name).read_bytes(), originals[name])
            messages = stdout.getvalue() + stderr.getvalue()
            self.assertIn("meta.project", messages)
            self.assertNotIn("synthetic-private-marker", messages)
            self.assertNotIn("Traceback", messages)

    def test_valid_unicode_blank_optional_strings_and_partial_updates_remain_supported(self):
        doc = {}
        findings.merge(doc, {"meta": {"project": "合成レビュー 🔎"}}, "first fragment")
        findings.validate(doc)
        findings.merge(doc, {"findings": [finding(title="入力の確認 🔒")]}, "second fragment")
        findings.merge(doc, {"findings": [{"id": "PV-001", "contrast": "", "step": ""}]},
                       "update fragment")
        findings.validate(doc)
        self.assertEqual(doc["meta"]["project"], "合成レビュー 🔎")
        self.assertEqual(doc["findings"][0]["contrast"], "")
        doc = doc_with_optional_prose()
        doc["meta"].update(project="合成レビュー 🔎", method="", commit="")
        doc["findings"][0].update(contrast="", commitment="", step="")
        doc["commitments"][0].update(reason="", family="")
        findings.validate(doc, complete=True)
        self.assertIn("合成レビュー 🔎", render.render_markdown(doc, "en"))
        self.assertIn("合成レビュー 🔎", render.render_html(doc, "en"))


class SourcePathTests(unittest.TestCase):
    def test_spaces_in_file_names_and_directories_are_supported(self):
        locations = ["src/My Component.tsx:22", "Application Support/privacy.yml:22",
                     "src/利用者 画面.tsx:12-24", "src/利用者　画面.tsx:12"]
        for location in locations:
            with self.subTest(location=location):
                findings.validate({"findings": [finding(location=location)]})
        findings.validate({"findings": [finding(location=locations)]})

    def test_control_characters_and_line_separators_are_not_source_paths(self):
        for control in ("\0", "\t", "\n", "\r", "\v", "\f", "\x1f", "\x7f", "\x85",
                        "\u2028", "\u2029"):
            with self.subTest(control=ascii(control)):
                location = "src/synthetic-private-marker" + control + ".py:22"
                with self.assertRaises(findings.SchemaError) as raised:
                    findings.validate({"findings": [finding(location=location)]})
                self.assertIn("location", str(raised.exception))
                self.assertNotIn("synthetic-private-marker", str(raised.exception))
        for location in ("src/app.py", ":22", "   :22", "src/app.py:line"):
            with self.subTest(location=location):
                with self.assertRaises(findings.SchemaError):
                    findings.validate({"findings": [finding(location=location)]})

    def test_paths_still_reject_personal_values_and_exempt_technical_line_ranges(self):
        for location in ("fixtures/contact synthetic-user@privacy-scan.localhost.json:22",
                         "fixtures/account 000000000000.json:22"):
            with self.subTest(location=location):
                with self.assertRaises(findings.SchemaError) as raised:
                    findings.validate({"findings": [finding(location=location)]})
                self.assertIn("location", str(raised.exception))
                self.assertNotIn(location, str(raised.exception))
        findings.validate({"findings": [finding(location="src/My File.py:100000-200000")]})


class FinalContractTests(unittest.TestCase):
    def test_not_checked_commitments_need_nonblank_reasons(self):
        for reason in (None, "", " \t\n"):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as directory:
                doc = complete_doc()
                doc["commitments"][0]["status"] = "not checked"
                if reason is not None:
                    doc["commitments"][0]["reason"] = reason
                out = Path(directory) / "output"
                write_outputs(out, doc)
                self.assertTrue(any("commitments[0]" in problem and "reason" in problem
                                    for problem in findings.contract_problems(out)))

    def test_reasons_may_be_added_in_a_later_fragment(self):
        doc = complete_doc()
        doc["commitments"][0]["status"] = "not checked"
        findings.validate(doc)
        findings.merge(doc, {"commitments": [{"id": "C-01", "reason": "Deployment unknown"}]},
                       "reason fragment")
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "output"
            write_outputs(out, doc)
            self.assertEqual(findings.contract_problems(out), [])

    def test_required_outputs_cannot_be_directories(self):
        for name in sorted(findings.OUTPUTS):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                out = Path(directory) / "output"
                write_outputs(out)
                (out / name).unlink()
                (out / name).mkdir()
                self.assertTrue(any(name in problem
                                    for problem in findings.contract_problems(out, allow=[name])))

    def test_required_outputs_cannot_be_broken_symlinks(self):
        for name in sorted(findings.OUTPUTS):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                out = Path(directory) / "output"
                write_outputs(out)
                (out / name).unlink()
                (out / name).symlink_to(Path(directory) / "missing-file")
                self.assertTrue(any(name in problem
                                    for problem in findings.contract_problems(out)))

    def test_symlinks_to_existing_files_still_count_as_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / "output"
            write_outputs(out)
            for name in sorted(findings.OUTPUTS):
                saved = root / name
                (out / name).replace(saved)
                (out / name).symlink_to(saved)
            self.assertEqual(findings.contract_problems(out), [])


if __name__ == "__main__":
    unittest.main()
