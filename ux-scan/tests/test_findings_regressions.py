"""Record validation and transactional merge regressions."""

import contextlib
import copy
import io
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "ux-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import findings  # noqa: E402

SAMPLE = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
FLOWS = json.loads((ROOT / "examples" / "flows.sample.json").read_text(encoding="utf-8"))


def run(*args):
    return subprocess.run([sys.executable, str(SCRIPTS / "findings.py"), *map(str, args)],
                          capture_output=True, text=True, timeout=10)


class ValidationRegressions(unittest.TestCase):
    def test_check_requires_contiguous_ids_and_canonical_order(self):
        cases = {
            "array order": lambda d: d["findings"].reverse(),
            "gap": lambda d: d["findings"][-1].update(id="U-099"),
            "zero": lambda d: d["findings"][0].update(id="U-000"),
            "path order": lambda d: d["findings"][0].update(location="zzz.tsx:1"),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                data = copy.deepcopy(SAMPLE)
                mutate(data)
                findings.check_findings(data, ordered=False)
                with self.assertRaisesRegex(findings.RecordError, "renumber"):
                    findings.check_findings(data)

    def test_hunt_steps_match_the_documented_steps(self):
        reference = (ROOT / "skills" / "ux-scan" / "reference" / "perspectives.md").read_text(encoding="utf-8")
        documented = set(re.findall(r"^- ([A-Z]{2}[0-9]+) ", reference, re.MULTILINE))
        for family in findings.FAMILIES:
            for n in range(10):
                step = f"{family}{n}"
                with self.subTest(step=step):
                    data = copy.deepcopy(SAMPLE)
                    data["findings"][0]["perspective"] = step
                    if step in documented:
                        findings.check_findings(data)
                    else:
                        with self.assertRaisesRegex(findings.RecordError, "hunt step"):
                            findings.check_findings(data)

    def test_invalid_scalar_fields_are_rejected(self):
        cases = (
            (lambda d: d.update(schema_version=True), "schema_version"),
            (lambda d: d.update(schema_version=1.0), "schema_version"),
            (lambda d: d["meta"].update(date="2025-02-29"), "meta.date"),
            (lambda d: d["meta"].update(date="2026-13-01"), "meta.date"),
            (lambda d: d["meta"].update(viewports=["phone"]), "viewports"),
            (lambda d: d["findings"][0].update(viewport="phone"), "viewport"),
            (lambda d: d["findings"][0].update(location="a.tsx:10-2"), "location"),
            (lambda d: d["findings"][0].update(location="a\\..\\b.tsx:1"), "location"),
            (lambda d: d["findings"][0].update(location="a\x00.tsx:1"), "location"),
            (lambda d: d["findings"][0].update(references=[{"url": "https://example.com", "title": []}]), "title"),
            (lambda d: d["findings"][0].update(references=[{"url": "https://example.com", "type": 3}]), "type"),
            (lambda d: d["perspectives"].append(copy.deepcopy(d["perspectives"][0])), "duplicate"),
        )
        for mutate, message in cases:
            with self.subTest(message=message, mutate=mutate):
                data = copy.deepcopy(SAMPLE)
                mutate(data)
                with self.assertRaisesRegex(findings.RecordError, message):
                    findings.check_findings(data)
        data = copy.deepcopy(SAMPLE)
        data["meta"]["date"] = "2024-02-29"
        findings.check_findings(data)

    def test_invalid_reference_urls_are_rejected(self):
        for url in ("https://example.com bad", "https://?q=host", "http://user@", "https://[broken",
                    "https://example.com:bad/", "https://example.com\n/path"):
            with self.subTest(url=url):
                data = copy.deepcopy(SAMPLE)
                data["findings"][0]["references"] = [{"url": url}]
                with self.assertRaisesRegex(findings.RecordError, "http"):
                    findings.check_findings(data)

    def test_token_scales_require_finite_numbers_and_a_source(self):
        for key in findings.TOKEN_SCALES:
            for value in (float("nan"), float("inf"), -float("inf"), True):
                with self.subTest(key=key, value=value):
                    data = copy.deepcopy(FLOWS)
                    data["tokens"][key] = [value]
                    with self.assertRaisesRegex(findings.RecordError, f"tokens.{key}"):
                        findings.check_flows(data)
        data = copy.deepcopy(FLOWS)
        data["tokens"] = {}
        with self.assertRaisesRegex(findings.RecordError, "source"):
            findings.check_flows(data)
        del data["tokens"]
        findings.check_flows(data)

    def test_strict_json_rejects_duplicate_keys_and_nonfinite_numbers(self):
        for source in ('{"app":"first","app":"second"}', '{"x":NaN}', '{"x":Infinity}',
                       '{"x":-Infinity}', '{"x":1e999}'):
            with self.subTest(source=source):
                with self.assertRaises(findings.RecordError):
                    findings.loads_json(source, "fragment.json")

    def test_strict_json_rejects_unpaired_surrogates_in_keys_and_values(self):
        for source in (r'"\ud800"', r'["\udfff"]', r'{"\ud800":1}', r'{"note":"\ud800"}'):
            with self.subTest(source=source):
                with self.assertRaises(findings.RecordError):
                    findings.loads_json(source, "fragment.json")
        self.assertEqual(findings.loads_json(r'"\ud83d\ude80"'), "🚀")

    def test_canonical_digest_ignores_json_formatting_and_key_order(self):
        first = {"app": "日本語", "tokens": {"spacing": [4, 8], "source": "tokens.css:1"}}
        reordered = {"tokens": {"source": "tokens.css:1", "spacing": [4, 8]}, "app": "日本語"}
        digest = findings.canonical_digest(first)
        self.assertRegex(digest, r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(digest, findings.canonical_digest(reordered))
        self.assertEqual(digest, findings.canonical_digest(findings.loads_json(json.dumps(first, indent=4))))
        reordered["tokens"]["spacing"].reverse()
        self.assertNotEqual(digest, findings.canonical_digest(reordered))
        with self.assertRaises(findings.RecordError):
            findings.canonical_digest({"value": float("nan")})

    def test_merge_cannot_create_more_findings_than_can_be_renumbered(self):
        data = copy.deepcopy(SAMPLE)
        item = data["findings"][0]
        data["findings"] = [{**item, "id": f"U-{n:03d}"} for n in range(1000)]
        with self.assertRaisesRegex(findings.RecordError, "at most 999"):
            findings.check_findings(data, ordered=False)


class TransactionRegressions(unittest.TestCase):
    def assert_refused(self, result):
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("findings.py:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_malformed_findings_fragments_are_refused_without_replacing_target(self):
        fragments = (
            {"findings": None}, {"findings": {}}, {"findings": ""},
            {"findings": [{"id": []}]}, {"findings": [{"id": "U-001"}, {"id": "U-001"}]},
            {"limitations": [{}]}, {"limitations": "line"},
            {"perspectives": [42]}, {"perspectives": [{"name": []}]},
            {"perspectives": [{"name": "AX Accessibility"}, {"name": "AX Accessibility"}]},
            {"remove": {"limitations": [{}]}},
        )
        with tempfile.TemporaryDirectory() as tmp:
            target, fragment = Path(tmp) / "findings.json", Path(tmp) / "fragment.json"
            target.write_text(json.dumps(SAMPLE), encoding="utf-8")
            before = target.read_bytes()
            for value in fragments:
                with self.subTest(fragment=value):
                    fragment.write_text(json.dumps(value), encoding="utf-8")
                    self.assert_refused(run("merge", target, fragment))
                    self.assertEqual(target.read_bytes(), before)

    def test_malformed_flows_fragments_are_refused_without_replacing_target(self):
        fragments = (
            {"flows": None}, {"flows": {}}, {"flows": [{"id": []}]}, {"flows": [42]},
            {"flows": [FLOWS["flows"][0], FLOWS["flows"][0]]},
        )
        with tempfile.TemporaryDirectory() as tmp:
            target, fragment = Path(tmp) / "flows.json", Path(tmp) / "fragment.json"
            target.write_text(json.dumps(FLOWS), encoding="utf-8")
            before = target.read_bytes()
            for value in fragments:
                with self.subTest(fragment=value):
                    fragment.write_text(json.dumps(value), encoding="utf-8")
                    self.assert_refused(run("flows", target, fragment))
                    self.assertEqual(target.read_bytes(), before)

    def test_malformed_existing_records_are_not_normalized_away(self):
        cases = (
            ("merge", {"findings": [SAMPLE["findings"][0], SAMPLE["findings"][0]]}),
            ("merge", {"findings": [None]}),
            ("flows", {"flows": [FLOWS["flows"][0], FLOWS["flows"][0]]}),
            ("flows", {"flows": [None]}),
            ("merge", []), ("flows", []),
        )
        with tempfile.TemporaryDirectory() as tmp:
            target, fragment = Path(tmp) / "record.json", Path(tmp) / "fragment.json"
            for command, data in cases:
                with self.subTest(command=command, data=data):
                    target.write_text(json.dumps(data), encoding="utf-8")
                    fragment.write_text(json.dumps(SAMPLE if command == "merge" else FLOWS), encoding="utf-8")
                    before = target.read_bytes()
                    self.assert_refused(run(command, target, fragment))
                    self.assertEqual(target.read_bytes(), before)

    def test_all_fragments_must_succeed_before_any_write(self):
        for existing in (False, True):
            for command, record, bad in (("merge", SAMPLE, {"summary": []}),
                                         ("flows", FLOWS, {"viewports": ["phone"]})):
                with self.subTest(existing=existing, command=command), tempfile.TemporaryDirectory() as tmp:
                    target, first, second = (Path(tmp) / name for name in ("record.json", "first.json", "second.json"))
                    if existing:
                        target.write_text(json.dumps(record), encoding="utf-8")
                    before = target.read_bytes() if existing else None
                    first.write_text(json.dumps(record), encoding="utf-8")
                    second.write_text(json.dumps(bad), encoding="utf-8")
                    self.assert_refused(run(command, target, first, second))
                    self.assertEqual(target.read_bytes() if target.exists() else None, before)
                    # A later valid fragment must not hide an earlier invalid one.
                    self.assert_refused(run(command, target, second, first))
                    self.assertEqual(target.read_bytes() if target.exists() else None, before)

    def test_empty_removal_of_an_absent_section_is_a_noop(self):
        data = copy.deepcopy(SAMPLE)
        del data["limitations"]
        result = findings.merge(data, {"remove": {"limitations": []}})
        findings.check_findings(result)
        self.assertEqual(result["limitations"], [])

    def test_renumber_reorders_the_array_even_when_no_id_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "findings.json"
            data = copy.deepcopy(SAMPLE)
            data["findings"].reverse()
            target.write_text(json.dumps(data), encoding="utf-8")
            result = run("renumber", target)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(target.read_text(encoding="utf-8")), SAMPLE)
            self.assertEqual(run("check", target).returncode, 0)
            before = target.read_bytes()
            self.assertIn("already in order", run("renumber", target).stdout)
            self.assertEqual(target.read_bytes(), before)

    def test_renumber_rewrites_japanese_references_without_partial_id_matches(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = data["findings"][:2]
        data["findings"][0]["id"], data["findings"][1]["id"] = "U-002", "U-001"
        data["next_steps"] = ["先にU-002を修正、次にU-001を確認。XU-002 U-0020 U-002_extra"]
        changed = findings.renumber(data, findings.renumber_map(data["findings"]))
        self.assertEqual(changed["next_steps"], ["先にU-001を修正、次にU-002を確認。XU-002 U-0020 U-002_extra"])
        findings.check_findings(changed)

    def test_renumber_preserves_source_paths_and_external_urls(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = data["findings"][:1]
        item = data["findings"][0]
        item.update(id="U-002", location="src/U-002.tsx:1", occurrences=["src/U-002.tsx:1"],
                    references=[{"url": "https://example.com/issues/U-002", "title": "Evidence for U-002"}])
        data["next_steps"] = ["Fix U-002."]
        original = copy.deepcopy(data)
        changed = findings.renumber(data, findings.renumber_map(data["findings"]))
        self.assertEqual(data, original)
        updated = changed["findings"][0]
        self.assertEqual(updated["id"], "U-001")
        self.assertEqual(updated["location"], item["location"])
        self.assertEqual(updated["occurrences"], item["occurrences"])
        self.assertEqual(updated["references"][0]["url"], item["references"][0]["url"])
        self.assertEqual(updated["references"][0]["title"], "Evidence for U-001")
        self.assertEqual(changed["next_steps"], ["Fix U-001."])
        findings.check_findings(changed)

    def test_failed_atomic_replace_keeps_target_and_removes_temporary_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, fragment = Path(tmp) / "findings.json", Path(tmp) / "fragment.json"
            target.write_text(json.dumps(SAMPLE), encoding="utf-8")
            fragment.write_text('{"summary":"updated"}', encoding="utf-8")
            before = target.read_bytes()
            error = io.StringIO()
            with mock.patch("scan_report_kit.output.os.replace", side_effect=PermissionError("replace denied")):
                with contextlib.redirect_stderr(error):
                    result = findings.main(["merge", str(target), str(fragment)])
            self.assertEqual(result, 2)
            self.assertIn("replace denied", error.getvalue())
            self.assertEqual(target.read_bytes(), before)
            self.assertEqual({p.name for p in Path(tmp).iterdir()}, {target.name, fragment.name})

    def test_write_errors_and_nonregular_inputs_return_clean_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fragment = root / "fragment.json"
            fragment.write_text(json.dumps(SAMPLE), encoding="utf-8")
            self.assert_refused(run("merge", root / "missing" / "findings.json", fragment))
            self.assert_refused(run("check", root))
            target = root / "findings.json"
            target.symlink_to(fragment)
            self.assert_refused(run("merge", target, fragment))
            self.assertTrue(target.is_symlink())
            self.assertEqual(json.loads(fragment.read_text(encoding="utf-8")), SAMPLE)


if __name__ == "__main__":
    unittest.main()
