"""Regression tests for lossless record updates and the published record contract."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import findings  # noqa: E402


def record():
    return {
        "schema_version": 1,
        "meta": {"project": "Example", "date": "2026-10-12", "assessor": "Tests"},
        "findings": [{
            "id": "P-001", "title": "Unused helper", "severity": "Low",
            "confidence": "Confirmed", "status": "Open", "perspective": "DC1",
            "unit_ref": "UN-01", "element": "old_helper", "location": "app.py:10",
            "basis": "No references or dynamic registrations.", "risk": "No known consumer.",
            "subtraction": {"action": "remove", "what": "old_helper", "remains": "The entry point.",
                            "loses": "Nothing."},
            "validation": {"verdict": "Valid", "evidence": "All callers were read.",
                           "dynamic_checked": "Registries, config and consumers checked."},
        }],
    }


def units_record():
    return {
        "app": "Example",
        "purpose": [{"id": "PB-01", "kind": "job", "source": "documented", "text": "Run the app.",
                     "evidence": "README.md:1"}],
        "entry_points": [{"id": "EP-01", "kind": "cli", "exposure": "internal", "name": "main",
                          "location": "app.py:1"}],
        "consumers": [{"name": "Operator", "kind": "ops", "in_repo": True, "evidence": "README.md:2"}],
        "units": [{"id": "UN-01", "kind": "area", "name": "App", "paths": ["app.py"],
                   "entry_points": ["EP-01"]},
                  {"id": "UN-02", "kind": "shared", "name": "Docs", "paths": ["README.md"],
                   "entry_points": []}],
    }


def run_cli(*args, recursion_limit=None):
    argv = [str(SCRIPTS / "findings.py"), *map(str, args)]
    if recursion_limit is not None:
        argv = ["-c", "import runpy, sys\n"
                "sys.setrecursionlimit(int(sys.argv[1]))\n"
                "sys.argv = sys.argv[2:]\n"
                "runpy.run_path(sys.argv[0], run_name='__main__')",
                str(recursion_limit), *argv]
    return subprocess.run([sys.executable, *argv],
                          capture_output=True, text=True)


class MergeInputTests(unittest.TestCase):
    def assert_refused(self, command, base, fragment, raw=False):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            target = out / ("units.json" if command == "units" else "findings.json")
            target.write_text(json.dumps(base), encoding="utf-8")
            before = target.read_bytes()
            source = out / "fragment.json"
            source.write_text(fragment if raw else json.dumps(fragment), encoding="utf-8")
            result = run_cli(command, target, source)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertTrue(result.stderr.startswith("findings.py:"), result.stderr)
            self.assertEqual(target.read_bytes(), before)

    def test_malformed_findings_fragments_are_refused_atomically(self):
        fragments = [
            [], {"findings": None}, {"findings": {}}, {"findings": [None]},
            {"findings": [{"id": []}]}, {"findings": [{"id": 1}]},
            {"findings": [{"id": "P-001", "status": "Fixed"}, {"id": "P-001", "status": "Open"}]},
            {"perspectives": [None]}, {"perspectives": [{"name": []}]},
            {"perspectives": [{"name": "DC Dead code", "result": "Done"},
                              {"name": "DC Dead code", "result": "Not checked"}]},
            {"limitations": [{}]}, {"remove": {"limitations": [None]}},
            {"findings": [{"id": "P-001", "title": "Two\nlines"}]}, {"summary": "Bad\x00text"},
        ]
        for fragment in fragments:
            with self.subTest(fragment=fragment):
                self.assert_refused("merge", record(), fragment)

    def test_malformed_units_fragments_are_refused_atomically(self):
        units = units_record()
        fragments = [
            {"units": None}, {"units": [None]}, {"units": [{"id": []}]},
            {"units": [units["units"][0], units["units"][0]]},
            {"purpose": [units["purpose"][0], units["purpose"][0]]},
            {"entry_points": [units["entry_points"][0], units["entry_points"][0]]},
            {"consumers": [{"name": {}}]},
            {"consumers": [units["consumers"][0], units["consumers"][0]]},
        ]
        for fragment in fragments:
            with self.subTest(fragment=fragment):
                self.assert_refused("units", units, fragment)

    def test_corrupt_base_is_not_silently_coalesced(self):
        data = record()
        data["findings"].append({**data["findings"][0], "status": "Fixed"})
        self.assert_refused("merge", data, {"summary": "An unrelated edit."})
        units = units_record()
        units["purpose"].append({**units["purpose"][0], "text": "A different job."})
        self.assert_refused("units", units, {"purpose": [units["purpose"][0]]})
        for base in (None, [], "invalid"):
            with self.subTest(base=base):
                self.assert_refused("merge", base, record())
                self.assert_refused("units", base, units_record())

    def test_empty_remove_for_absent_section_is_a_noop(self):
        data = record()
        merged = findings.merge(data, {"remove": {"limitations": []}})
        self.assertEqual(merged, data)

    def test_ambiguous_and_nonstandard_json_does_not_overwrite_record(self):
        for fragment in ('{"summary":"first","summary":"second"}',
                         '{"findings":[{"id":"P-001","status":"Fixed","status":"Open"}]}',
                         '{"extra":NaN}', '{"extra":Infinity}', '{"extra":-Infinity}',
                         '{"extra":1e400}', '{"summary":"\\ud800"}'):
            with self.subTest(fragment=fragment):
                self.assert_refused("merge", record(), fragment, raw=True)

    def test_later_bad_fragment_preserves_the_original_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, good, bad = (Path(tmp) / name for name in ("findings.json", "good.json", "bad.json"))
            target.write_text(json.dumps(record()), encoding="utf-8")
            before = target.read_bytes()
            good.write_text('{"findings":[{"id":"P-001","status":"Fixed"}]}', encoding="utf-8")
            bad.write_text('{"perspectives":[false]}', encoding="utf-8")
            result = run_cli("merge", target, good, bad)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertEqual(target.read_bytes(), before)


class JsonInputTests(unittest.TestCase):
    def test_shared_parser_preserves_utf8_and_reports_invalid_bytes(self):
        data = {"text": "日本語と絵文字 😀", "number": 1.25}
        source = json.dumps(data, ensure_ascii=False)
        self.assertEqual(findings.parse_json(source), data)
        self.assertEqual(findings.parse_json(source.encode("utf-8")), data)
        for source in (b'{"text":"\xff"}', b'{"value":NaN}', b'{"key":1,"key":2}'):
            with self.subTest(source=source):
                with self.assertRaisesRegex(findings.RecordError, "input.json"):
                    findings.parse_json(source, where="input.json")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFOs are not supported")
    def test_fifo_input_is_rejected_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "findings.json"
            os.mkfifo(source)
            result = subprocess.run([sys.executable, str(SCRIPTS / "findings.py"), "check", str(source)],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("regular JSON file", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_regular_file_symlinks_still_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, link = Path(tmp) / "source.json", Path(tmp) / "link.json"
            data = record()
            source.write_text(json.dumps(data), encoding="utf-8")
            try:
                link.symlink_to(source)
            except OSError:
                self.skipTest("File symlinks are not supported")
            self.assertEqual(findings.load_json(link), data)

    def test_broken_adjacent_record_links_cannot_skip_reference_validation(self):
        for command in ("check", "merge", "renumber", "units"):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp)
                target = out / ("units.json" if command == "units" else "findings.json")
                beside = out / ("findings.json" if command == "units" else "units.json")
                target.write_text(json.dumps(units_record() if command == "units" else record()),
                                  encoding="utf-8")
                before = target.read_bytes()
                try:
                    beside.symlink_to(out / "missing.json")
                except OSError:
                    self.skipTest("File symlinks are not supported")
                source = out / "fragment.json"
                source.write_text(json.dumps({"app": "Updated"} if command == "units"
                                             else {"summary": "Updated"}), encoding="utf-8")
                fragments = [source] if command in ("merge", "units") else []
                result = run_cli(command, target, *fragments)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn(beside.name, result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual(target.read_bytes(), before)
                self.assertTrue(beside.is_symlink())

    def test_broken_target_links_are_not_replaced_as_new_records(self):
        for command in ("merge", "units"):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp)
                target = out / ("units.json" if command == "units" else "findings.json")
                missing = out / "missing.json"
                try:
                    target.symlink_to(missing)
                except OSError:
                    self.skipTest("File symlinks are not supported")
                source = out / "fragment.json"
                source.write_text(json.dumps(units_record() if command == "units" else record()),
                                  encoding="utf-8")
                result = run_cli(command, target, source)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertTrue(target.is_symlink())
                self.assertEqual(target.readlink(), missing)
                self.assertFalse(missing.exists())

    def test_output_failure_is_reported_without_a_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "fragment.json"
            source.write_text(json.dumps(record()), encoding="utf-8")
            result = run_cli("merge", Path(tmp) / "missing" / "findings.json", source)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def assert_deep_update(self, command, fid, *, recursion_limit=None, expected_codes=(0, 2)):
        depth = 1100
        with tempfile.TemporaryDirectory() as tmp:
            target, fragment = Path(tmp) / "findings.json", Path(tmp) / "fragment.json"
            fragment.write_text('{"summary":"Updated"}', encoding="utf-8")
            data = record()
            data["findings"][0]["id"] = fid
            source = json.dumps(data)[:-1] + ',"extra":' + "[" * depth + json.dumps(fid) + "]" * depth + "}"
            target.write_text(source, encoding="utf-8")
            before = target.read_bytes()
            result = run_cli(command, target, *([fragment] if command == "merge" else []),
                             recursion_limit=recursion_limit)
            self.assertIn(result.returncode, expected_codes, result.stdout + result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            if result.returncode == 2:
                self.assertTrue(result.stderr.startswith("findings.py:"), result.stderr)
                self.assertEqual(target.read_bytes(), before)
                return
            if (command, fid) == ("renumber", "P-001"):
                self.assertEqual(target.read_bytes(), before)
            # The child may accept a depth beyond this interpreter's default limit.
            previous_limit = sys.getrecursionlimit()
            try:
                sys.setrecursionlimit(max(previous_limit, 5000))
                updated = json.loads(target.read_text(encoding="utf-8"))
            finally:
                sys.setrecursionlimit(previous_limit)
            nested = updated.pop("extra")
            for _ in range(depth):
                self.assertIsInstance(nested, list)
                self.assertEqual(len(nested), 1)
                nested = nested[0]
            self.assertEqual(nested, "P-001")
            expected = copy.deepcopy(data)
            if command == "merge":
                expected["summary"] = "Updated"
            else:
                expected["findings"][0]["id"] = "P-001"
            self.assertEqual(updated, expected)

    def test_deep_json_cannot_crash_or_partially_replace_a_record(self):
        # Decoding, encoding and rewrite limits vary across Python versions.
        for command, fid in (("merge", "P-001"), ("renumber", "P-002"), ("renumber", "P-001")):
            with self.subTest(command=command, fid=fid):
                self.assert_deep_update(command, fid)

    def test_deep_json_can_be_updated_with_sufficient_recursion_limit(self):
        for command, fid in (("merge", "P-001"), ("renumber", "P-002"), ("renumber", "P-001")):
            with self.subTest(command=command, fid=fid):
                self.assert_deep_update(command, fid, recursion_limit=5000, expected_codes=(0,))

    def test_deep_json_exceeding_rewrite_limit_preserves_the_original(self):
        self.assert_deep_update("renumber", "P-002", recursion_limit=300, expected_codes=(2,))


class RecordValidationTests(unittest.TestCase):
    def test_schema_version_requires_an_integer(self):
        for version in (True, 1.0, "1"):
            with self.subTest(version=version):
                data = record()
                data["schema_version"] = version
                with self.assertRaisesRegex(findings.RecordError, "schema_version"):
                    findings.check_findings(data)

    def test_meta_date_must_exist_in_the_calendar(self):
        for date in ("2026-02-29", "2026-02-31", "2026-13-01", "0000-01-01"):
            with self.subTest(date=date):
                data = record()
                data["meta"]["date"] = date
                with self.assertRaisesRegex(findings.RecordError, "meta.date"):
                    findings.check_findings(data)
        data = record()
        data["meta"]["date"] = "2024-02-29"
        findings.check_findings(data)

    def test_perspective_must_name_a_documented_hunt_step(self):
        for perspective in ("DC0", "DC5", "FF4", "DU4", "PX5", "OB6", "OB9"):
            with self.subTest(perspective=perspective):
                data = record()
                data["findings"][0]["perspective"] = perspective
                with self.assertRaisesRegex(findings.RecordError, "hunt step"):
                    findings.check_findings(data)

    def test_falsy_entry_point_values_are_not_lists(self):
        for value in (None, False, 0, "", {}):
            with self.subTest(value=value):
                units = units_record()
                units["units"][1]["entry_points"] = value
                with self.assertRaisesRegex(findings.RecordError, "entry_points"):
                    findings.check_units(units)

    def test_locations_do_not_accept_reversed_ranges(self):
        for key in ("location", "occurrences"):
            with self.subTest(key=key):
                data = record()
                data["findings"][0][key] = "app.py:10-2" if key == "location" else ["app.py:10-2"]
                with self.assertRaisesRegex(findings.RecordError, "line"):
                    findings.check_findings(data)

    def test_references_require_complete_http_urls(self):
        for url in ("https://example.com trailing", "https://example.com\n", "https://?query", "https://[broken",
                    "https://example.com\\@other.test", "https://%2Fexample.com", "https://ex%zzample.com"):
            with self.subTest(url=url):
                data = record()
                data["findings"][0]["references"] = [{"url": url}]
                with self.assertRaisesRegex(findings.RecordError, "http"):
                    findings.check_findings(data)

    def test_titles_and_text_match_the_renderer_contract(self):
        for title in ("Two\nlines", "Two\rlines", "Two\u2028lines", "Two\u2029lines"):
            with self.subTest(title=title):
                data = record()
                data["findings"][0]["title"] = title
                with self.assertRaisesRegex(findings.RecordError, "one line"):
                    findings.check_findings(data)
        for value in ("Bad\x00text", "Bad\ud800text"):
            with self.subTest(value=ascii(value)):
                data = record()
                data["findings"][0]["basis"] = value
                with self.assertRaisesRegex(findings.RecordError, "Unicode text"):
                    findings.check_findings(data)
                data = record()
                data["decisions"] = [value]
                with self.assertRaisesRegex(findings.RecordError, "Unicode text"):
                    findings.check_findings(data)
                units = units_record()
                units["purpose"][0]["text"] = value
                with self.assertRaisesRegex(findings.RecordError, "Unicode text"):
                    findings.check_units(units)

    def test_reference_labels_must_be_renderable_strings(self):
        for key in ("type", "title"):
            with self.subTest(key=key):
                data = record()
                data["findings"][0]["references"] = [{"url": "https://example.com", key: 42}]
                with self.assertRaisesRegex(findings.RecordError, "expected a string"):
                    findings.check_findings(data)

    def test_valid_multiline_prose_and_international_urls_still_render(self):
        import render
        from scan_report_kit import report

        data = record()
        data["findings"][0]["basis"] = "First observation.\nSecond observation."
        data["findings"][0]["references"] = [
            {"url": "https://例え.テスト/説明?q=値", "title": "資料", "type": "仕様"},
            {"url": "https://example.com/a%20b?query=x#part"},
        ]
        findings.check_findings(data)
        report.validate(render.to_common(data, "en"))

    def test_record_size_cannot_exceed_the_three_digit_id_capacity(self):
        data = record()
        data["findings"] = [{**copy.deepcopy(data["findings"][0]), "id": f"P-{i:03d}"} for i in range(1000)]
        with self.assertRaisesRegex(findings.RecordError, "999"):
            findings.check_findings(data, ordered=False)


class RenumberRegressionTests(unittest.TestCase):
    def two_findings(self):
        data = record()
        data["findings"].append({**copy.deepcopy(data["findings"][0]), "id": "P-002", "location": "app.py:20"})
        return data

    def test_check_rejects_gaps_and_noncanonical_order(self):
        variants = []
        data = record()
        data["findings"][0]["id"] = "P-002"
        variants.append(data)
        data = self.two_findings()
        data["findings"].reverse()
        variants.append(data)
        data = self.two_findings()
        data["findings"][0]["location"] = "app.py:30"
        variants.append(data)
        data = self.two_findings()
        data["findings"][0]["validation"]["verdict"] = "FalsePositive"
        variants.append(data)
        for data in variants:
            with self.subTest(data=data):
                with self.assertRaisesRegex(findings.RecordError, "renumber"):
                    findings.check_findings(data)
                findings.check_findings(data, ordered=False)

    def test_renumber_repairs_array_order_even_when_ids_do_not_move(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "findings.json"
            data = self.two_findings()
            data["findings"].reverse()
            target.write_text(json.dumps(data), encoding="utf-8")
            result = run_cli("renumber", target)
            self.assertEqual(result.returncode, 0, result.stderr)
            actual = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual([f["id"] for f in actual["findings"]], ["P-001", "P-002"])
            findings.check_findings(actual)
            before = target.read_bytes()
            result = run_cli("renumber", target)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("already in order", result.stdout)
            self.assertEqual(target.read_bytes(), before)

    def test_renumber_preserves_japanese_cross_references(self):
        data = self.two_findings()
        data["findings"][0]["severity"] = "Info"
        data["summary"] = "関連するP-002を先に確認し、P-001は後にする。"
        data["decisions"] = ["P-002とP-001の依存を確認。"]
        data["next_steps"] = ["XP-002 P-0020 P-002_extra"]
        data["extra"] = {"location": ["P-002を確認"], "meta": {"note": "P-001の補足"}}
        before = copy.deepcopy(data)
        result = findings.renumber(data, findings.renumber_map(data["findings"]))
        self.assertEqual(result["summary"], "関連するP-001を先に確認し、P-002は後にする。")
        self.assertEqual(result["decisions"], ["P-001とP-002の依存を確認。"])
        self.assertEqual(result["next_steps"], data["next_steps"])
        self.assertEqual(result["extra"], {"location": ["P-001を確認"], "meta": {"note": "P-002の補足"}})
        self.assertEqual(data, before)
        findings.check_findings(result)

    def test_renumber_preserves_source_identities_and_updates_finding_references(self):
        data = record()
        data["meta"].update(project="P-002", assessor="Reviewer P-002", repo="https://example.com/P-002",
                            scope="docs/P-002.md", method="P-002 audit method", commit="0a1b2c3d4e5f60718293a4b5c6d7e8f901234567")
        literal_fields = {
            "location": "docs/P-002.md:1", "occurrences": ["docs/P-002.md:2"],
            "element": "Document docs/P-002.md", "observed": "open('docs/P-002.md')",
            "category": "P-002 package",
            "references": [{"url": "https://example.com/docs/P-002.md", "type": "P-002 specification",
                            "title": "P-002 API documentation"}],
        }
        item = data["findings"][0]
        item.update(id="P-002", **literal_fields)
        for field in ("title", "basis", "impact", "risk"):
            item[field] = "P-002を確認。"
        for field in ("what", "remains", "loses"):
            item["subtraction"][field] = "P-002と関連。"
        for field in ("evidence", "dynamic_checked"):
            item["validation"][field] = "P-002で検証済み。"
        data["perspectives"] = [{"name": "DC P-002 package", "result": "P-002を報告", "note": "P-002を確認"}]
        data["summary"] = "P-002を先に確認。"
        data["decisions"] = ["P-002を削除。"]
        findings.check_findings(data, ordered=False)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            document = root / "docs" / "P-002.md"
            document.parent.mkdir()
            document.write_text("source first line\nsource second line\n", encoding="utf-8")
            target = root / "findings.json"
            target.write_text(json.dumps(data), encoding="utf-8")
            result = run_cli("renumber", target)
            self.assertEqual(result.returncode, 0, result.stderr)
            updated = json.loads(target.read_text(encoding="utf-8"))
            findings.check_findings(updated)
            self.assertEqual(updated["meta"], data["meta"])
            actual = updated["findings"][0]
            self.assertEqual(actual["id"], "P-001")
            self.assertEqual({field: actual[field] for field in literal_fields}, literal_fields)
            self.assertTrue((root / actual["location"].rpartition(":")[0]).is_file())
            for field in ("title", "basis", "impact", "risk"):
                self.assertEqual(actual[field], "P-001を確認。")
            for field in ("what", "remains", "loses"):
                self.assertEqual(actual["subtraction"][field], "P-001と関連。")
            for field in ("evidence", "dynamic_checked"):
                self.assertEqual(actual["validation"][field], "P-001で検証済み。")
            self.assertEqual(updated["summary"], "P-001を先に確認。")
            self.assertEqual(updated["decisions"], ["P-001を削除。"])
            self.assertEqual(updated["perspectives"],
                             [{"name": "DC P-002 package", "result": "P-001を報告", "note": "P-001を確認"}])
            before = target.read_bytes()
            result = run_cli("renumber", target)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(target.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
