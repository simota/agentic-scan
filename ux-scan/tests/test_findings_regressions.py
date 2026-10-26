"""Record validation and transactional merge regressions."""

import contextlib
import copy
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
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
            (lambda d: d["findings"][0].update(location="src/.:1"), "location"),
            (lambda d: d["findings"][0].update(occurrences=["./.:1"]), "occurrences"),
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
                    "https://example.com:bad/", "https://example.com\n/path",
                    "https://exam\\ple.com/", "https://example.com<bad>/",
                    'https://example.com/"bad"', "https://[::1]example.com/",
                    "https://exa%2fmple.com/", "https://exa%3ample.com/",
                    "https://example%.com/", "https://example.com/\x80",
                    "https://example.com/\x9f", "https://example\uff5cmore.com/"):
            with self.subTest(url=url):
                data = copy.deepcopy(SAMPLE)
                data["findings"][0]["references"] = [{"url": url}]
                with self.assertRaisesRegex(findings.RecordError, "http"):
                    findings.check_findings(data)

    def test_titles_require_one_line_before_the_record_can_be_merged(self):
        for newline in ("\r", "\n", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"):
            with self.subTest(newline=repr(newline)):
                data = copy.deepcopy(SAMPLE)
                data["findings"][0]["title"] = "First" + newline + "second"
                with self.assertRaisesRegex(findings.RecordError, "title.*one line"):
                    findings.check_findings(data)

    def test_report_text_rejects_nul_and_surrogates_at_the_input_boundary(self):
        mutations = (
            lambda d, text: d.update(summary=text),
            lambda d, text: d["meta"].update(project=text),
            lambda d, text: d.update(limitations=[text]),
            lambda d, text: d["perspectives"][0].update(note=text),
            lambda d, text: d["findings"][0].update(observed=text),
            lambda d, text: d["findings"][0]["validation"].update(evidence=text),
            lambda d, text: d["findings"][0].update(references=[{"url": "https://example.com", "title": text}]),
        )
        for text in ("contains\x00NUL", "contains\ud800surrogate"):
            for mutate in mutations:
                with self.subTest(text=repr(text), mutate=mutate):
                    data = copy.deepcopy(SAMPLE)
                    mutate(data, text)
                    with self.assertRaisesRegex(findings.RecordError, "Unicode text"):
                        findings.check_findings(data)
            flows = copy.deepcopy(FLOWS)
            flows["flows"][0]["name"] = text
            with self.assertRaisesRegex(findings.RecordError, "Unicode text"):
                findings.check_flows(flows)

    def test_checked_unicode_and_reference_urls_are_renderable(self):
        import render
        from scan_report_kit import report

        urls = (
            "https://example.com/path?next=%2Fcheckout#section",
            "https://example.com/%ZZ",  # Host validation does not rewrite literal paths.
            "https://b%C3%BCcher.example/",
            "https://例え.テスト/日本語",
            "https://[2001:db8::1]:8443/path",
            "https://[fe80::1%25eth0]/",
        )
        data = copy.deepcopy(SAMPLE)
        data["summary"] = "日本語の説明と emoji 🚀\nThe next line is valid prose."
        data["findings"][0]["references"] = [{"url": url} for url in urls]
        ids = findings.flow_ids(findings.check_flows(copy.deepcopy(FLOWS)))
        findings.check_findings(data, ids)
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                report.validate(render.to_common(data, lang, FLOWS))

    def test_flow_locations_require_files_including_token_sources(self):
        for target in ("screen", "tokens"):
            with self.subTest(target=target):
                data = copy.deepcopy(FLOWS)
                if target == "screen":
                    data["flows"][0]["screens"][0]["location"] = "src/.:1"
                else:
                    data["tokens"]["source"] = "styles/.:1"
                with self.assertRaisesRegex(findings.RecordError, "repository-relative file"):
                    findings.check_flows(data)

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

    def test_success_messages_naming_a_path_the_console_cannot_encode_still_succeed(self):
        env = {**os.environ, "PYTHONIOENCODING": "cp1252", "PYTHONDONTWRITEBYTECODE": "1"}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "レビュー"
            commands = (
                [ROOT / "scripts" / "ci" / "prepare_sample.py", ROOT / "examples" / "findings.sample.json",
                 "--out", out, "--no-pdf"],
                [SCRIPTS / "findings.py", "renumber", out / "findings.json"],
                [SCRIPTS / "findings.py", "check", out / "findings.json"],
                [SCRIPTS / "inventory.py", ROOT / "examples" / "tasklane", "--flows", out / "flows.json",
                 "--out", out / "inventory.json"],
                [SCRIPTS / "render.py", out / "findings.json", "--out", out, "--lang", "en",
                 "--repo", ROOT / "examples" / "tasklane", "--no-pdf"],
                [SCRIPTS / "contract_check.py", out, "--no-pdf"],
            )
            for command in commands:
                with self.subTest(script=command[0].name, args=command[1]):
                    result = subprocess.run([sys.executable, *map(str, command)], capture_output=True, env=env,
                                            timeout=60)
                    self.assertEqual(result.returncode, 0, result.stderr.decode("cp1252", "replace"))
                    self.assertNotIn(b"Traceback", result.stderr)
            self.assertIn(b"\\u30ec\\u30d3\\u30e5\\u30fc", result.stdout)

    def test_malformed_findings_fragments_are_refused_without_replacing_target(self):
        fragments = (
            {"findings": None}, {"findings": {}}, {"findings": ""},
            {"findings": [{"id": []}]}, {"findings": [{"id": "U-001"}, {"id": "U-001"}]},
            {"limitations": [{}]}, {"limitations": "line"},
            {"perspectives": [42]}, {"perspectives": [{"name": []}]},
            {"perspectives": [{"name": "AX Accessibility"}, {"name": "AX Accessibility"}]},
            {"remove": {"limitations": [{}]}},
            {"findings": [{"id": "U-001", "title": "First\nsecond"}]},
            {"summary": "Contains\x00NUL"}, {"limitations": ["Contains\x00NUL"]},
            {"findings": [{"id": "U-001", "references": [{"url": "https://exa%2fmple.com/"}]}]},
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
            {"flows": [{**FLOWS["flows"][0], "name": "Contains\x00NUL"}]},
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

    def test_perspective_names_need_a_family_token_and_can_be_removed_by_name(self):
        data = copy.deepcopy(SAMPLE)
        bad = findings.merge(data, {"perspectives": [{"name": "Accessibility (AX)", "result": "applied"}]})
        with self.assertRaisesRegex(findings.RecordError, "family token"):
            findings.check_findings(bad)
        # A record that already holds the bad entry is repaired by a merge, not by hand.
        fixed = findings.merge(bad, {"remove": {"perspectives": ["Accessibility (AX)"]}})
        findings.check_findings(fixed)
        self.assertEqual(fixed["perspectives"], data["perspectives"])
        with self.assertRaisesRegex(findings.RecordError, "remove.perspectives: no such entry"):
            findings.merge(data, {"remove": {"perspectives": ["Accessibility (AX)"]}})
        twice = findings.merge(bad, {"remove": {"perspectives": ["Accessibility (AX)", "Accessibility (AX)"]}})
        self.assertEqual(twice["perspectives"], data["perspectives"])
        with tempfile.TemporaryDirectory() as tmp:
            target, fragment = Path(tmp) / "findings.json", Path(tmp) / "fragment.json"
            target.write_text(json.dumps(data), encoding="utf-8")
            fragment.write_text(json.dumps({"perspectives": [{"name": "Accessibility", "result": "applied"}]}),
                                encoding="utf-8")
            before = target.read_bytes()
            self.assert_refused(run("merge", target, fragment))
            self.assertEqual(target.read_bytes(), before)

    def test_null_removes_an_optional_finding_field_but_not_a_required_one(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"][0]["occurrences"] = [data["findings"][0]["location"]]
        data["findings"][0]["viewport"] = "360x640"
        result = findings.merge(data, {"findings": [{"id": "U-001", "occurrences": None, "viewport": None}]})
        findings.check_findings(result)
        self.assertNotIn("occurrences", result["findings"][0])
        self.assertNotIn("viewport", result["findings"][0])
        with self.assertRaisesRegex(findings.RecordError, "null in a fragment removes it"):
            findings.check_findings(findings.merge(data, {"findings": [{"id": "U-001", "occurrences": []}]}))
        with self.assertRaises(findings.RecordError):
            findings.check_findings(findings.merge(data, {"findings": [{"id": "U-001", "location": None}]}))
        # A misspelled field sent as null is refused, not dropped while the real field stays.
        with self.assertRaisesRegex(findings.RecordError, "occurences"):
            findings.check_findings(findings.merge(data, {"findings": [{"id": "U-001", "occurences": None}]}))

    def test_check_and_merge_refuse_symlinked_records_as_render_does(self):
        with tempfile.TemporaryDirectory() as tmp:
            real, linked = Path(tmp) / "real", Path(tmp) / "linked"
            real.mkdir()
            linked.mkdir()
            (real / "flows.json").write_text(json.dumps(FLOWS), encoding="utf-8")
            (linked / "findings.json").write_text(json.dumps(SAMPLE), encoding="utf-8")
            (linked / "flows.json").symlink_to(real / "flows.json")
            fragment = Path(tmp) / "fragment.json"
            fragment.write_text(json.dumps({"summary": "x"}), encoding="utf-8")
            for args in (("check", linked / "findings.json"), ("merge", linked / "findings.json", fragment)):
                with self.subTest(command=args[0]):
                    result = run(*args)
                    self.assertEqual(result.returncode, 2, result.stdout)
                    self.assertIn("regular file", result.stderr)
            (real / "findings.json").write_text(json.dumps(SAMPLE), encoding="utf-8")
            (linked / "flows.json").unlink()
            (linked / "flows.json").write_text(json.dumps(FLOWS), encoding="utf-8")
            (linked / "findings.json").unlink()
            (linked / "findings.json").symlink_to(real / "findings.json")
            result = run("check", linked / "findings.json")
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertIn("regular file", result.stderr)
            self.assertEqual(result.stderr.count(str(linked / "findings.json")), 1, result.stderr)

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

    def test_renumber_preserves_paths_urls_routes_and_code_in_prose(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = data["findings"][:1]
        item = data["findings"][0]
        item.update(id="U-002", location="src/U-002.tsx:1", occurrences=["src/U-002.tsx:1"],
                    screen="Customer detail (/customers/U-002)",
                    criterion="Pattern docs/U-002.md:12; https://example.com/spec/U-002",
                    observed='src/U-002.tsx:1 contains <a href="/customers/U-002">Details</a>.')
        item["validation"]["evidence"] = (
            "U-002.tsx:1 and .U-002 and https://example.com/?issue=U-002 confirm U-002.")
        data["next_steps"] = [
            'Fix `U-002`, preserve `const id = "U-002"`, and inspect <div id="U-002"/>.',
            'Check [U-002](https://example.com/spec/U-002) in src/[U-002].tsx:1.',
            'Fix U-002.\n```tsx\nconst id = "U-002";\n```\nThen verify U-002.',
            'Fix U-002.\n~~~tsx\nconst id = "U-002";\n~~~\nThen verify U-002.',
            'Fix U-002.\n```tsx\nconst id = "U-002";\n',
            'Fix U-002.\n```tsx\nconst id = "U-002";\n````\nThen verify U-002.',
            "U-002（docs/U-002.md:12）を修正。https://example.com/U-002。U-002を確認。",
            'Use <input data-key="U-002"> for U-002, then <button>.',
            "U-002 は <div> で再現。U-002 を <button> に直す。",
        ]
        original = copy.deepcopy(data)
        changed = findings.renumber(data, findings.renumber_map(data["findings"]))
        self.assertEqual(data, original)
        updated = changed["findings"][0]
        for key in ("location", "occurrences", "screen", "criterion", "observed"):
            self.assertEqual(updated[key], original["findings"][0][key], key)
        self.assertEqual(updated["validation"]["evidence"],
                         "U-002.tsx:1 and .U-002 and https://example.com/?issue=U-002 confirm U-001.")
        self.assertEqual(changed["next_steps"], [
            'Fix `U-001`, preserve `const id = "U-002"`, and inspect <div id="U-002"/>.',
            'Check [U-001](https://example.com/spec/U-002) in src/[U-002].tsx:1.',
            'Fix U-001.\n```tsx\nconst id = "U-002";\n```\nThen verify U-001.',
            'Fix U-001.\n~~~tsx\nconst id = "U-002";\n~~~\nThen verify U-001.',
            'Fix U-001.\n```tsx\nconst id = "U-002";\n',
            'Fix U-001.\n```tsx\nconst id = "U-002";\n````\nThen verify U-001.',
            "U-001（docs/U-002.md:12）を修正。https://example.com/U-002。U-001を確認。",
            'Use <input data-key="U-002"> for U-001, then <button>.',
            "U-001 は <div> で再現。U-001 を <button> に直す。",
        ])
        findings.check_findings(changed)

    def test_renumber_preserves_grouped_source_paths_and_relative_link_targets(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = data["findings"][:1]
        data["findings"][0]["id"] = "U-002"
        data["next_steps"] = [
            "Inspect app/(U-002)/page.tsx:1; fix U-002.",
            "Inspect app/(group)/sub/(U-002)/page.tsx:1; fix U-002.",
            "Inspect (app/(U-002)/page.tsx:1), then fix U-002.",
            "Inspect src/button(U-002).tsx:1; fix U-002.",
            "Check [U-002](app/(U-002)/page.tsx:1), then fix U-002.",
            "U-002(app/(U-002)/page.tsx:1)を修正。",
        ]
        changed = findings.renumber(data, findings.renumber_map(data["findings"]))
        self.assertEqual(changed["next_steps"], [
            "Inspect app/(U-002)/page.tsx:1; fix U-001.",
            "Inspect app/(group)/sub/(U-002)/page.tsx:1; fix U-001.",
            "Inspect (app/(U-002)/page.tsx:1), then fix U-001.",
            "Inspect src/button(U-002).tsx:1; fix U-001.",
            "Check [U-001](app/(U-002)/page.tsx:1), then fix U-001.",
            "U-001(app/(U-002)/page.tsx:1)を修正。",
        ])
        findings.check_findings(changed)

    def test_renumber_preserves_markdown_destinations_without_path_markers(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = data["findings"][:1]
        data["findings"][0]["id"] = "U-002"
        cases = (
            ("Check [U-002](U-002); fix U-002.", "Check [U-001](U-002); fix U-001."),
            ('[U-002](?ticket=U-002#U-002 "For U-002")', '[U-001](?ticket=U-002#U-002 "For U-001")'),
            ("[U-002](README#U-002)", "[U-001](README#U-002)"),
            ("[U-002](U-002(group(U-002)))", "[U-001](U-002(group(U-002)))"),
            (r"[U-002](U-002\(U-002\))", r"[U-001](U-002\(U-002\))"),
            ("![U-002](U-002)", "![U-001](U-002)"),
            ("[U-002](\n U-002 \n 'For U-002')", "[U-001](\n U-002 \n 'For U-001')"),
            ('[U-002](<U-002 for U-002> "For U-002")', '[U-001](<U-002 for U-002> "For U-001")'),
            # An ID range in a destination is not a reference, even when it contains unknown IDs.
            ("[U-002](U-001-U-002)", "[U-001](U-001-U-002)"),
        )
        data["next_steps"] = [source for source, _ in cases]
        original = copy.deepcopy(data)
        changed = findings.renumber(data, findings.renumber_map(data["findings"]))
        self.assertEqual(data, original)
        self.assertEqual(changed["next_steps"], [expected for _, expected in cases])
        findings.check_findings(changed)
        self.assertEqual(findings.renumber(changed, findings.renumber_map(changed["findings"])), changed)

    def test_renumber_preserves_reference_destinations_and_overlapping_code(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = data["findings"][:1]
        data["findings"][0]["id"] = "U-002"
        data["next_steps"] = [
            '[evidence][U-002]\n\n[U-002]: U-002 "For U-002"\n\nFix U-002.',
            "[U-002]:\n  ?ticket=U-002\n\nFix [U-002].",
            '`[U-002](U-002)` then U-002.',
            '```md\n[U-002]: U-002\n[U-002](U-002)\n```\nFix U-002.',
            '<!-- [U-002](U-002) --> Fix U-002.',
            '[U-002](U-002 "For U-002" is an unfinished link. Fix U-002.',
        ]
        changed = findings.renumber(data, findings.renumber_map(data["findings"]))
        self.assertEqual(changed["next_steps"], [
            '[evidence][U-001]\n\n[U-001]: U-002 "For U-001"\n\nFix U-001.',
            "[U-001]:\n  ?ticket=U-002\n\nFix [U-001].",
            '`[U-002](U-002)` then U-001.',
            '```md\n[U-002]: U-002\n[U-002](U-002)\n```\nFix U-001.',
            '<!-- [U-002](U-002) --> Fix U-001.',
            '[U-001](U-001 "For U-001" is an unfinished link. Fix U-001.',
        ])
        findings.check_findings(changed)

    def test_renumber_does_not_extend_a_link_destination_past_literal_boundaries(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = data["findings"][:1]
        data["findings"][0]["id"] = "U-002"
        data["next_steps"] = [
            '`[x](`U-002) then U-002.',
            '``[x](``U-002) then U-002.',
            # A source path in a link label must not hide the real destination on the next line.
            '[src/file](\nU-002) then U-002.',
        ]
        changed = findings.renumber(data, findings.renumber_map(data["findings"]))
        self.assertEqual(changed["next_steps"], [
            '`[x](`U-001) then U-001.',
            '``[x](``U-001) then U-001.',
            '[src/file](\nU-002) then U-001.',
        ])
        findings.check_findings(changed)

    def test_renumber_requires_a_complete_reference_definition(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = data["findings"][:1]
        data["findings"][0]["id"] = "U-002"
        cases = (
            ('[U-002]: U-002 title-invalid', '[U-001]: U-001 title-invalid'),
            ('[U-002]: U-002 "For U-002" trailing', '[U-001]: U-001 "For U-001" trailing'),
            ('[U-002]: U-002 "For U-002', '[U-001]: U-001 "For U-001'),
            ('[U-002]: U-002 (For U-002)', '[U-001]: U-002 (For U-001)'),
            ('[U-002]: U-002\n"For U-002"', '[U-001]: U-002\n"For U-001"'),
        )
        data["next_steps"] = [source + "\nFix U-002." for source, _ in cases]
        changed = findings.renumber(data, findings.renumber_map(data["findings"]))
        self.assertEqual(changed["next_steps"], [expected + "\nFix U-001." for _, expected in cases])
        findings.check_findings(changed)

    def test_renumber_preserves_code_delimiters_and_html_comments(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = data["findings"][:1]
        data["findings"][0]["id"] = "U-002"
        evidence = [
            '``a ``` U-002``',
            '~~~js`template`\nconst id = "U-002";\n~~~',
            '```js\r\nconst id = "U-002";\r\n```',
            '~~~~text\nU-002\n~~~\nU-002\n~~~~',
            '```js\n```',
            '~~~\n~~~',
            '<!-- U-002 with <b>markup</b> -->',
        ]
        data["next_steps"] = [f"{code}\nFix U-002." for code in evidence]
        data["next_steps"].extend(["Fix U-002. <!-- U-002 with <b>markup", "Fix `` U-002 ``."])
        changed = findings.renumber(data, findings.renumber_map(data["findings"]))
        self.assertEqual(changed["next_steps"], [f"{code}\nFix U-001." for code in evidence] + [
            # As in CommonMark, an unclosed inline comment is literal text.
            "Fix U-001. <!-- U-001 with <b>markup", "Fix `` U-001 ``.",
        ])
        findings.check_findings(changed)

    def test_renumber_expands_ranges_without_changing_the_referenced_findings(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = data["findings"][:3]
        for item, severity in zip(data["findings"], ("Low", "High", "Medium")):
            item["severity"] = severity
        data["next_steps"] = [
            "Fix U-001 to U-002.", "Fix U-001 through U-003.", "Fix U-003 to U-001.",
            "U-001からU-003までを修正。", "U-001〜U-003を修正。", "U-001～U-003を修正。",
            "Fix U-001-U-003; then U-001/U-003.", "Fix U-001–U-003.", "Fix U-001—U-003.",
            "Fix `U-001` to `U-002`.", "`U-001`から`U-003`までを修正。", "U-001/U-002を修正。",
            "Fix **U-001** to **U-002**.", "Fix *U-001* to *U-002*.", "Fix __U-001__ to __U-002__.",
            "Fix **`U-001`** to **`U-002`**.",
            "Fix __U-001__, _U-002_ and ~~U-003~~; preserve U-001_extra and XU-002.",
        ]
        changed = findings.renumber(data, findings.renumber_map(data["findings"]))
        self.assertEqual(changed["next_steps"], [
            "Fix U-003, U-001.", "Fix U-003, U-001, U-002.", "Fix U-002, U-001, U-003.",
            "U-003, U-001, U-002を修正。", "U-003, U-001, U-002を修正。", "U-003, U-001, U-002を修正。",
            "Fix U-003, U-001, U-002; then U-003/U-002.", "Fix U-003, U-001, U-002.", "Fix U-003, U-001, U-002.",
            "Fix `U-003`, `U-001`.", "`U-003`, `U-001`, `U-002`を修正。", "U-003/U-001を修正。",
            "Fix **U-003**, **U-001**.", "Fix *U-003*, *U-001*.", "Fix __U-003__, __U-001__.",
            "Fix **`U-003`**, **`U-001`**.",
            "Fix __U-003__, _U-001_ and ~~U-002~~; preserve U-001_extra and XU-002.",
        ])
        findings.check_findings(changed)
        self.assertEqual(findings.renumber(changed, findings.renumber_map(changed["findings"])), changed)

    def test_renumber_refuses_a_still_range_whose_missing_id_another_finding_moves_onto(self):
        data = copy.deepcopy(SAMPLE)
        kept = [item for item in data["findings"] if item["id"] in ("U-001", "U-003")]
        data["findings"] = kept
        mapping = findings.renumber_map(data["findings"])
        self.assertEqual(mapping, {"U-001": "U-001", "U-003": "U-002"})
        for prose in ("Fix U-001 to U-002 first.", "Fix U-002 to U-001 first.", "Then U-002."):
            with self.subTest(prose=prose):
                data["next_steps"] = [prose]
                with self.assertRaisesRegex(findings.RecordError, "U-002.*names no finding"):
                    findings.renumber(data, mapping)
        # A missing id nothing moves onto still stays as written.
        data["next_steps"] = ["Fix U-001 to U-001; U-004 is gone."]
        self.assertEqual(findings.renumber(data, mapping)["next_steps"], data["next_steps"])

    def test_renumber_treats_comparisons_as_prose_and_bullets_as_separate_ids(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = data["findings"][:4]
        for item, severity in zip(data["findings"], ("Low", "High", "Medium", "Info")):
            item["severity"] = severity
        data["summary"] = "Fix first:\n- U-001\n- U-004\n\n- **U-002**\n-U-003\nThen U-001 through\nU-003."
        data["next_steps"] = [
            "Below <640px fix U-002 first; above >1024px U-003 can wait.",
            "Widths < 360 break U-002 and widths > 1280 break U-003. Keep <b>U-001</b>.",
            "参照: https://www.w3.org/WAI/WCAG22/ とU-001も同様。https://www.w3.org/WAI/とU-001",
            "See https://example.com/日本?finding=U-001, https://example.com/日本U-001 and U-001.",
        ]
        changed = findings.renumber(data, findings.renumber_map(data["findings"]))
        self.assertEqual(changed["summary"],
                         "Fix first:\n- U-003\n- U-004\n\n- **U-001**\n-U-002\nThen U-003 through\nU-002.")
        self.assertEqual(changed["next_steps"], [
            "Below <640px fix U-001 first; above >1024px U-002 can wait.",
            "Widths < 360 break U-001 and widths > 1280 break U-002. Keep <b>U-003</b>.",
            "参照: https://www.w3.org/WAI/WCAG22/ とU-003も同様。https://www.w3.org/WAI/とU-001",
            "See https://example.com/日本?finding=U-001, https://example.com/日本U-001 and U-003.",
        ])
        findings.check_findings(changed)

    def test_renumber_follows_tag_grammar_url_brackets_and_underscore_emphasis(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = data["findings"][:3]
        for item, severity in zip(data["findings"], ("Medium", "High", "Low")):
            item["severity"] = severity
        data["next_steps"] = [
            "Viewports <sm (U-001) and >=lg (U-002); if a<b, U-001.",
            "Keep <Button variant=\"primary\" onClick={go}>U-001</Button> as written.",
            "詳細は[WCAG](https://www.w3.org/x)U-001の通り。参考(https://example.com)U-002、"
            "https://en.wikipedia.org/wiki/A_(B)?q=U-001 stays.",
            "_U-001 to U-003_, _see U-001_ and __U-002, U-001__; keep a_U-001 and U-001_b.",
            "Fix U-001 to\n\nU-002.",
            "See https://example.com/a_(b_(c))?ref=U-001 and <Button style={{ color: \"red\" }} data-f=\"U-001\">.",
            "<Button style={{ content: \"}\" }} data-f=\"U-001\"> <B a={`}${x}`} b=\"U-001\"> {don't} U-001",
            "foo__U-001, U-001__bar, ___U-001___ and __U-001__.",
        ]
        changed = findings.renumber(data, findings.renumber_map(data["findings"]))
        self.assertEqual(changed["next_steps"], [
            "Viewports <sm (U-002) and >=lg (U-001); if a<b, U-002.",
            "Keep <Button variant=\"primary\" onClick={go}>U-002</Button> as written.",
            "詳細は[WCAG](https://www.w3.org/x)U-002の通り。参考(https://example.com)U-001、"
            "https://en.wikipedia.org/wiki/A_(B)?q=U-001 stays.",
            "_U-002, U-001, U-003_, _see U-002_ and __U-001, U-002__; keep a_U-001 and U-001_b.",
            "Fix U-002 to\n\nU-001.",
            "See https://example.com/a_(b_(c))?ref=U-001 and <Button style={{ color: \"red\" }} data-f=\"U-001\">.",
            "<Button style={{ content: \"}\" }} data-f=\"U-001\"> <B a={`}${x}`} b=\"U-001\"> {don't} U-002",
            "foo__U-001, U-001__bar, ___U-002___ and __U-002__.",
        ])
        findings.check_findings(changed)

    def test_angular_markup_in_prose_stays_literal(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = data["findings"][:2]
        data["findings"][0]["severity"], data["findings"][1]["severity"] = "Low", "High"
        data["next_steps"] = ["<button (click)=\"open('U-001')\" *ngIf=\"x\"> U-001 <input #q aria-label=\"U-001\">"]
        changed = findings.renumber(data, findings.renumber_map(data["findings"]))
        self.assertEqual(changed["next_steps"],
                         ["<button (click)=\"open('U-001')\" *ngIf=\"x\"> U-002 <input #q aria-label=\"U-001\">"])

    def test_escaped_quotes_and_long_underscore_runs(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = data["findings"][:2]
        data["findings"][0]["severity"], data["findings"][1]["severity"] = "Low", "High"
        data["next_steps"] = ['<Button label={"a \\"quoted\\""} data-id="U-001"> foo____U-001 U-001____bar ____U-001 U-001']
        changed = findings.renumber(data, findings.renumber_map(data["findings"]))
        self.assertEqual(changed["next_steps"],
                         # An unmatched delimiter run keeps its id literal, as in every other position.
                         ['<Button label={"a \\"quoted\\""} data-id="U-001"> foo____U-001 U-001____bar ____U-001 U-002'])

    def test_jsx_expressions_are_scanned_as_javascript(self):
        mapping = {"U-001": "U-002", "U-002": "U-001"}
        kept = ['<Button pattern={/[}]/} data-id="U-001">', '<B a={x / 2} b="U-001">',
                '<B a={`${ {a: "}"}.a }`} b="U-001">', '<B a={/* } */ x} b="U-001">',
                '<B a={c // }\n} b="U-001">', '<B a={{ deep: { deeper: { deepest: {} } } }} b="U-001">']
        for tag in kept:
            with self.subTest(tag=tag):
                self.assertEqual(findings._rewrite_prose(tag + " U-001", mapping), tag + " U-002")
        for prose in ("<sm (U-001) and >lg", "<B a={unclosed U-001"):
            with self.subTest(prose=prose):
                self.assertEqual(findings._rewrite_prose(prose, mapping), prose.replace("U-001", "U-002"))

    def test_round_three_prose_cases(self):
        mapping = {"U-001": "U-002", "U-002": "U-001"}
        cases = {
            "Press the ` key (U-001).\n\nSee `U-002`.": "Press the ` key (U-002).\n\nSee `U-001`.",
            "Press ` then U-001.\n```\nx ` y\n```\nThen U-002 and U-001.":
                "Press ` then U-002.\n```\nx ` y\n```\nThen U-001 and U-002.",
            '<a onClick={() => { return /}/.test(x) }} title="U-001"> U-001':
                '<a onClick={() => { return /}/.test(x) }} title="U-001"> U-002',
            '<a b={typeof /}/} c="U-001"> U-001': '<a b={typeof /}/} c="U-001"> U-002',
            '<Foo render={() => <b>x</b>} title="U-001" /> U-001': '<Foo render={() => <b>x</b>} title="U-001" /> U-002',
            '<a b={i++ / 2} c="U-001"> U-001': '<a b={i++ / 2} c="U-001"> U-002',
            '<X p={x < /}/.test(y)} data-id="U-001" /> U-001': '<X p={x < /}/.test(y)} data-id="U-001" /> U-002',
            '<X p={a && <b>x</b>} data-id="U-001" /> U-001': '<X p={a && <b>x</b>} data-id="U-001" /> U-002',
            "Use <!-- in templates (U-001). Later U-002.": "Use <!-- in templates (U-002). Later U-001.",
            "<!-- open\nU-001": "<!-- open\nU-001",
            '<a :[key]="U-001" v-slot:[name]="x" @[evt]="go"> U-001': '<a :[key]="U-001" v-slot:[name]="x" @[evt]="go"> U-002',
        }
        for prose, expected in cases.items():
            with self.subTest(prose=prose):
                self.assertEqual(findings._rewrite_prose(prose, mapping), expected)
        # A keyword used as a property divides: obj.return / 2 is no regex.
        for tag in ('<X p={obj.return / 2} data-id="U-001" />', '<X p={a.typeof / b.in / 2} data-id="U-001" />'):
            with self.subTest(tag=tag):
                self.assertEqual(findings._rewrite_prose(tag + " U-001", mapping), tag + " U-002")
        # Svelte modifiers and Lit bindings are attributes too.
        for tag in ('<button on:click|once={go} data-id="U-001">', '<my-el ?disabled=${x} data-id="U-001">',
                    '<button @click=${this.go} data-id="U-001">', '<my-el .value=${v} data-id="U-001">'):
            with self.subTest(tag=tag):
                self.assertEqual(findings._rewrite_prose(tag + " U-001", mapping), tag + " U-002")
        # ".." is a range separator, a capitalised word after an id is a sentence, and a fence
        # opening after a list marker or blockquote protects its code.
        cases = {
            "Fix U-001..U-002 first.": "Fix U-002, U-001 first.",
            "See U-001.Then U-002.": "See U-002.Then U-001.",
            "Open U-001.md and .U-002": "Open U-001.md and .U-002",
            "- ```js\n  const a = 1;\n\n  // U-001\n  ```\nU-001": "- ```js\n  const a = 1;\n\n  // U-001\n  ```\nU-002",
            "1. ```\n   U-001\n   ```": "1. ```\n   U-001\n   ```",
            "1. Run:\n\n   ```\n   first\n\n   see U-001\n   ```\nU-001":
                "1. Run:\n\n   ```\n   first\n\n   see U-001\n   ```\nU-002",
            # Four columns past the list item's content (column 3) is indented code, not a fence.
            "1. Run:\n\n       ```\n       see U-001\n       ```\nU-001":
                "1. Run:\n\n       ```\n       see U-002\n       ```\nU-002",
            # A list marker indented four columns at the root is indented code too.
            "    - ```\nU-002 should update": "    - ```\nU-001 should update",
            # Leaving the list item ends its fence: the root marker opens a new one.
            "- ```\n  U-001\n```\nU-001 code": "- ```\n  U-001\n```\nU-001 code",
            "- ```\n  U-001\n  ```\nU-001": "- ```\n  U-001\n  ```\nU-002",
            # Leaving the blockquote (a non-lazy line) ends its fence the same way.
            "> ```\n> U-001\n```\nU-001 code": "> ```\n> U-001\n```\nU-001 code",
            # The space after > is optional.
            ">```js\n>U-001\n>````\nU-001": ">```js\n>U-001\n>````\nU-002",
            # An ordered list not starting at 1 cannot interrupt a paragraph, so no fence opens there;
            # 1. can, and so can a later item of an existing list.
            "Text U-001\n2. ```js\n   U-001\n   ````\nU-001": "Text U-002\n2. ```js\n   U-002\n   ````\nU-001",
            "Text\n1. ```\n   U-001\n   ```\nU-001": "Text\n1. ```\n   U-001\n   ```\nU-002",
            "1. a\n2. ```\n   U-001\n   ```\nU-001": "1. a\n2. ```\n   U-001\n   ```\nU-002",
            # A heading, thematic break or setext underline is no paragraph, so 2. may follow it.
            "# Heading\n2. ```\n   U-001\n   ```\nU-001": "# Heading\n2. ```\n   U-001\n   ```\nU-002",
            "---\n2. ```\n   U-001\n   ```\nU-001": "---\n2. ```\n   U-001\n   ```\nU-002",
            "Title\n===\n2. ```\n   U-001\n   ```\nU-001": "Title\n===\n2. ```\n   U-001\n   ```\nU-002",
            "Heading\n--\n2. ~~~\n   U-001\n   ~~~\nU-001": "Heading\n--\n2. ~~~\n   U-001\n   ~~~\nU-002",
            # A lightly indented fence continuing a list item ends with that item.
            "- item\n\n  ```\n  U-001\nroot U-001": "- item\n\n  ```\n  U-001\nroot U-002",
            "- item\n\n  ```\n  U-001\n  ```\nU-001": "- item\n\n  ```\n  U-001\n  ```\nU-002",
            # The same holds for a list item inside a blockquote, and a tab after "> " is measured
            # from the line start, so the closer below matches its opener.
            "> - item\n>   ```\n>   U-001\n> root U-001": "> - item\n>   ```\n>   U-001\n> root U-002",
            "> \t```\n> \tU-001\n> \t```\n> U-001": "> \t```\n> \tU-001\n> \t```\n> U-002",
            # Five or more spaces after a list marker are one space of padding plus content.
            "-     item\n\n  ```\n  U-001\nroot U-001": "-     item\n\n  ```\n  U-001\nroot U-002",
            # A closed HTML comment is a completed block, not paragraph text.
            "<!-- done -->\n2. ```\n   U-001\n   ```\nU-001": "<!-- done -->\n2. ```\n   U-001\n   ```\nU-002",
            # So is any HTML block that ends on its line.
            **{block + "\n2. ```\n   U-001\n   ```\nU-001": block + "\n2. ```\n   U-001\n   ```\nU-002"
               for block in ("<?done?>", "<!DOCTYPE html>", "<![CDATA[x]]>", "<script>done</script>")},
            # After a blank line, a line back at the outer item's column closes the nested item.
            "- outer\n  - nested\n\n  outer\n\n    ```\n    U-001\n  ```\n  U-001":
                "- outer\n  - nested\n\n  outer\n\n    ```\n    U-001\n  ```\n  U-002",
            # A parent list item is found however far above the fence it opens.
            "- item\n" + "\n  text\n" * 60 + "\n  ```\n  U-001\nroot U-001":
                "- item\n" + "\n  text\n" * 60 + "\n  ```\n  U-001\nroot U-002",
            # Inside a blockquote the rule reads the quoted paragraph.
            "> paragraph U-001\n> 2. ~~~\n>    U-001\n> ~~~~\nU-001": "> paragraph U-002\n> 2. ~~~\n>    U-002\n> ~~~~\nU-002",
            "> # H\n> 2. ~~~\n>    U-001\n>    ~~~\nU-001": "> # H\n> 2. ~~~\n>    U-001\n>    ~~~\nU-002",
            "> ```\n> U-001\n> ```\nU-001": "> ```\n> U-001\n> ```\nU-002",
            # A marker indented four or more columns past the opener is code, not the closer.
            "```\n    ```\nU-001 code\n```\nU-001": "```\n    ```\nU-001 code\n```\nU-002",
            "```js `x` U-001": "```js `x` U-002",
            "```\n> ```\nU-001 code\n```\nU-001": "```\n> ```\nU-001 code\n```\nU-002",
            # Four columns of indentation outside a list item is indented code, not a fence.
            "    ```\nU-002 should update": "    ```\nU-001 should update",
        }
        for prose, expected in cases.items():
            with self.subTest(prose=prose):
                self.assertEqual(findings._rewrite_prose(prose, mapping), expected)
        ranged = {"U-001": "U-005", "U-002": "U-002", "U-003": "U-004"}
        self.assertEqual(findings._rewrite_prose("Fix U-001 to U-003____bar", ranged), "Fix U-005 to U-003____bar")
        self.assertEqual(findings._rewrite_prose("foo____U-001 to U-003", ranged), "foo____U-001 to U-004")

    def test_unclosed_inline_comments_stay_fast(self):
        import time
        started = time.monotonic()
        result = findings._rewrite_prose("x <!-- " * 40000 + "U-001", {"U-001": "U-002"})
        self.assertLess(time.monotonic() - started, 3)
        self.assertTrue(result.endswith("U-002"))

    def test_code_spans_stay_fast_with_many_unclosed_backtick_runs(self):
        import time
        text = "".join("`" * (n % 7 + 1) + " word " for n in range(40000))
        started = time.monotonic()
        findings._rewrite_prose(text + " U-001", {"U-001": "U-002"})
        self.assertLess(time.monotonic() - started, 3)

    def test_prose_scanning_stays_fast_on_unbalanced_markup_and_brackets(self):
        import time
        for text in ("<a " * 50000, "<a {" * 20000, "https://x.org/" + "(" * 50000, "{" * 50000 + "U-001",
                     "<a b={" + "'\"`" * 20000, "<a b={{{{" + "\"'" * 20000):
            with self.subTest(text=text[:8]):
                data = copy.deepcopy(SAMPLE)
                data["findings"] = data["findings"][:2]
                data["findings"][0]["severity"], data["findings"][1]["severity"] = "Low", "High"
                data["summary"], data["next_steps"] = text, []
                started = time.monotonic()
                findings.renumber(data, findings.renumber_map(data["findings"]))
                self.assertLess(time.monotonic() - started, 3)

    def test_nested_unknown_keys_and_invisible_location_characters_are_refused(self):
        cases = (
            (lambda d: d["findings"][0].update(occurences=["a.tsx:1"]), "unknown key 'occurences'"),
            (lambda d: d["findings"][0].update(references=[{"href": "https://x.org"}]), "unknown key 'href'"),
            (lambda d: d["findings"][0]["validation"].update(evidnce="x"), "unknown key 'evidnce'"),
            (lambda d: d["meta"].update(comit="abc"), "unknown key 'comit'"),
            (lambda d: d["perspectives"][0].update(resutl="x"), "unknown key 'resutl'"),
            (lambda d: d["findings"][0].update(occurrences=[]), "occurrences"),
            (lambda d: d["findings"][0].update(location="src/a\u2028b.tsx:1"), "location"),
            (lambda d: d["findings"][0].update(location="src/a\x85.tsx:1"), "location"),
            (lambda d: d["findings"][0].update(location="src/a.tsx :1"), "location"),
            (lambda d: d["findings"][0].update(location="src/a\u200b.tsx:1"), "location"),
        )
        for mutate, message in cases:
            with self.subTest(message=message):
                data = copy.deepcopy(SAMPLE)
                mutate(data)
                with self.assertRaisesRegex(findings.RecordError, message):
                    findings.check_findings(data, ordered=False)
        flows = copy.deepcopy(FLOWS)
        flows["flows"][0]["screens"][0]["path"] = "x"
        with self.assertRaisesRegex(findings.RecordError, "unknown key 'path'"):
            findings.check_flows(flows)

    def test_missing_output_directory_is_named(self):
        with tempfile.TemporaryDirectory() as tmp:
            fragment = Path(tmp) / "fragment.json"
            fragment.write_text(json.dumps({"flows": []}), encoding="utf-8")
            for cmd, name in (("merge", "findings.json"), ("flows", "flows.json")):
                result = run(cmd, Path(tmp) / "missing" / name, fragment)
                self.assertEqual(result.returncode, 2)
                self.assertIn("output directory does not exist", result.stderr)

    def test_unknown_sections_are_refused(self):
        data = copy.deepcopy(SAMPLE)
        data["limitation"] = ["typo"]
        with self.assertRaisesRegex(findings.RecordError, "unknown key 'limitation'"):
            findings.check_findings(data)
        with self.assertRaisesRegex(findings.RecordError, "unknown key 'finding'"):
            findings.merge(copy.deepcopy(SAMPLE), {"finding": []})
        flows = copy.deepcopy(FLOWS)
        flows["viewport"] = ["360x640"]
        with self.assertRaisesRegex(findings.RecordError, "unknown key 'viewport'"):
            findings.check_flows(flows)
        with self.assertRaisesRegex(findings.RecordError, "unknown key 'findings'"):
            findings.merge_flows(copy.deepcopy(FLOWS), {"findings": []})

    def test_flows_can_drop_tokens_and_flows_recorded_in_error(self):
        flows = copy.deepcopy(FLOWS)
        flows["tokens"] = {"source": "src/styles/tokens.css:2"}
        with self.assertRaisesRegex(findings.RecordError, "at least one scale"):
            findings.check_flows(flows)
        dropped = findings.check_flows(findings.merge_flows(copy.deepcopy(FLOWS), {"tokens": None}))
        self.assertNotIn("tokens", dropped)
        last = next(fl["id"] for fl in FLOWS["flows"] if fl["priority"] == "secondary")
        removed = findings.check_flows(findings.merge_flows(copy.deepcopy(FLOWS), {"remove": {"flows": [last]}}))
        self.assertNotIn(last, findings.flow_ids(removed))
        for remove in ({"flows": ["FL-99"]}, {"flows": "FL-01"}, {"screens": []}, []):
            with self.subTest(remove=remove), self.assertRaises(findings.RecordError):
                findings.merge_flows(copy.deepcopy(FLOWS), {"remove": remove})
        with tempfile.TemporaryDirectory() as tmp:
            target, fragment = Path(tmp) / "flows.json", Path(tmp) / "fragment.json"
            target.write_text(json.dumps(FLOWS), encoding="utf-8")
            cited = SAMPLE["findings"][0]["flow_ref"]
            (Path(tmp) / "findings.json").write_text(json.dumps(SAMPLE), encoding="utf-8")
            fragment.write_text(json.dumps({"remove": {"flows": [cited]}}), encoding="utf-8")
            before = target.read_bytes()
            self.assert_refused(run("flows", target, fragment))
            self.assertEqual(target.read_bytes(), before)

    def test_renumber_leaves_unchanged_ranges_and_protects_source_ranges(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = data["findings"][:2]
        data["next_steps"] = ["Fix U-001 to U-002."]
        self.assertEqual(findings.renumber(data, findings.renumber_map(data["findings"])), data)
        data["findings"][0]["severity"] = "Low"
        data["next_steps"] = [
            "Inspect src/U-001-U-002.tsx:1 and https://example.com/U-001-U-002; fix U-001 to U-002."]
        changed = findings.renumber(data, findings.renumber_map(data["findings"]))
        self.assertEqual(changed["next_steps"], [
            "Inspect src/U-001-U-002.tsx:1 and https://example.com/U-001-U-002; fix U-002, U-001."])
        findings.check_findings(changed)

    def test_renumber_keeps_ranges_with_padded_code_ids_and_whole_range_emphasis(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = data["findings"][:3]
        for item, severity in zip(data["findings"], ("Low", "High", "Medium")):
            item["severity"] = severity
        cases = (
            ("Fix ` U-001 ` to ` U-003 `.", "Fix ` U-003 `, ` U-001 `, ` U-002 `."),
            ("Fix `` U-001 `` through `` U-003 ``.", "Fix `` U-003 ``, `` U-001 ``, `` U-002 ``."),
            ("Fix `U-001 ` to ` U-003`.", "Fix `U-003 `, `U-001 `, `U-002 `."),
            ("Fix **U-001 to U-003**.", "Fix **U-003, U-001, U-002**."),
            ("Fix __U-001 to U-003__.", "Fix __U-003, U-001, U-002__."),
            ("Fix _U-001からU-003まで_.", "Fix _U-003, U-001, U-002_."),
            # まで after a space goes with the range, as it does unspaced.
            ("U-001 から U-003 まで修正する。", "U-003, U-001, U-002修正する。"),
            ("_U-001 から U-003\u3000まで_。", "_U-003, U-001, U-002_。"),
            ("**U-001 〜 U-003\u00a0まで**", "**U-003, U-001, U-002**"),
            # A trailing slash keeps ids a path, as it does for one id.
            ("Keep U-001/U-003/ and U-001/.", "Keep U-001/U-003/ and U-001/."),
            ("Fix ~~U-001–U-003~~.", "Fix ~~U-003, U-001, U-002~~."),
            ("Fix __` U-001 ` to ` U-003 `__.", "Fix __` U-003 `, ` U-001 `, ` U-002 `__."),
            ("Fix ___U-001__ to __U-003___.", "Fix ___U-003__, __U-001__, __U-002___."),
            ("Fix ___U-001_ to _U-003___.", "Fix ___U-003_, _U-001_, _U-002___."),
            ("Fix __**U-001** to **U-003**__.", "Fix __**U-003**, **U-001**, **U-002**__."),
            ("Fix **__U-001__ to __U-003__**.", "Fix **__U-003__, __U-001__, __U-002__**."),
            ("Fix _U-001 to __U-003___.", "Fix ___U-003__, __U-001__, __U-002___."),
            ("Fix __U-001 to _U-003___.", "Fix ___U-003_, _U-001_, _U-002___."),
            ("Fix ____U-001 to U-003____.", "Fix ____U-003, U-001, U-002____."),
            ("Fix ____U-003 to U-001____.", "Fix ____U-002, U-001, U-003____."),
            ("Fix ______U-001____ to _U-003___.", "Fix ______U-003____, ____U-001____, ____U-002______."),
            ("Fix ____U-001____ to _____U-003_____.", "Fix ____U-003____, ____U-001____, ____U-002____."),
            ("Fix ____` U-001 ` to ` U-003 `____.", "Fix ____` U-003 `, ` U-001 `, ` U-002 `____."),
            ("Fix ____U-001からU-003まで____.", "Fix ____U-003, U-001, U-002____."),
            ("Fix _____U-001____ through ___U-003____.", "Fix _____U-003____, ____U-001____, ____U-002_____."),
            # Unused delimiter characters remain literal outside the range.
            ("Fix __U-001 to U-003_.", "Fix __U-003, U-001, U-002_."),
            ("Fix _U-001 to U-003__.", "Fix _U-003, U-001, U-002__."),
            # A whole range inside one code span stays literal source text.
            ("Keep ` U-001 to U-003 `; fix U-001.", "Keep ` U-001 to U-003 `; fix U-003."),
        )
        data["next_steps"] = [source for source, _ in cases]
        original = copy.deepcopy(data)
        changed = findings.renumber(data, findings.renumber_map(data["findings"]))
        self.assertEqual(data, original)
        self.assertEqual(changed["next_steps"], [expected for _, expected in cases])
        findings.check_findings(changed)
        self.assertEqual(findings.renumber(changed, findings.renumber_map(changed["findings"])), changed)

    def test_renumber_rewrites_references_inside_underscore_emphasis_without_changing_identifiers(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = data["findings"][:3]
        for item, severity in zip(data["findings"], ("Low", "High", "Medium")):
            item["severity"] = severity
        cases = (
            ("__U-001 and U-003__", "__U-003 and U-002__"),
            ("__U-001/U-003__", "__U-003/U-002__"),
            ("_U-001, U-003_", "_U-003, U-002_"),
            ("___U-001 and U-003___", "___U-003 and U-002___"),
            ("_U-001 and __U-003___", "_U-003 and __U-002___"),
            ("__U-001 and _U-003___", "__U-003 and _U-002___"),
            ("___U-001_ and U-003__", "___U-003_ and U-002__"),
            ("___U-001__ and U-003_", "___U-003__ and U-002_"),
            ("____U-001__ and U-003__", "____U-003__ and U-002__"),
            ("___U-001 and ___U-003______", "___U-003 and ___U-002______"),
            ("__U-001 and ___U-003_____", "__U-003 and ___U-002_____"),
            ("_U-001 and __U-003__ and U-002_", "_U-003 and __U-002__ and U-001_"),
            ("_U-001/__U-003___", "_U-003/__U-002___"),
            ("__U-001__/_U-003_", "__U-003__/_U-002_"),
            ("__U-001 and `const id = U-003`__", "__U-003 and `const id = U-003`__"),
            ("__`const id = U-001` and U-003__", "__`const id = U-001` and U-002__"),
            ("__U-001 and `U-003`__", "__U-003 and `U-002`__"),
            ("__U-001 and src/U-003.tsx:1__", "__U-003 and src/U-003.tsx:1__"),
            ("__U-001 and [evidence](?issue=U-003)__", "__U-003 and [evidence](?issue=U-003)__"),
            ("__U-001 and `literal __ U-003`__", "__U-003 and `literal __ U-003`__"),
            ("__U-001_suffix and prefix_U-003 and U-002__", "__U-001_suffix and prefix_U-003 and U-001__"),
            ("Keep prefix_U-001, U-003_suffix and XU-002.", "Keep prefix_U-001, U-003_suffix and XU-002."),
            ("変数_U-001 と U-003_値", "変数_U-001 と U-003_値"),
            ("é_U-001 and U-003_é", "é_U-001 and U-003_é"),
            ("e\u0301_U-001 and U-003_e\u0301", "e\u0301_U-001 and U-003_e\u0301"),
            ("e\u0301_U-001 and U-003_\u0301e", "e\u0301_U-001 and U-003_\u0301e"),
            ("head\u203f_U-001 and U-003_\u203ftail", "head\u203f_U-001 and U-003_\u203ftail"),
            ("先にU-001を修正し、次にU-003を確認。", "先にU-003を修正し、次にU-002を確認。"),
            ("__é U-001 and U-003 e\u0301__", "__é U-003 and U-002 e\u0301__"),
            ("Fix ____U-001 and U-003____.", "Fix ____U-003 and U-002____."),
            ("__U-001 and src/__U-003__.tsx:1__", "__U-003 and src/__U-003__.tsx:1__"),
            ("__U-001 and src/_U-003__", "__U-003 and src/_U-003__"),
            ("Keep U-001/_U-003 and U-001/U-003_suffix.", "Keep U-001/_U-003 and U-001/U-003_suffix."),
            ("Keep `__U-001 and U-003__`; fix U-002.", "Keep `__U-001 and U-003__`; fix U-001."),
        )
        data["next_steps"] = [source for source, _ in cases]
        original = copy.deepcopy(data)
        changed = findings.renumber(data, findings.renumber_map(data["findings"]))
        self.assertEqual(data, original)
        self.assertEqual(changed["next_steps"], [expected for _, expected in cases])
        findings.check_findings(changed)
        self.assertEqual(findings.renumber(changed, findings.renumber_map(changed["findings"])), changed)

    def test_renumber_respects_escaped_underscores_and_block_boundaries(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = data["findings"][:3]
        for item, severity in zip(data["findings"], ("Low", "High", "Medium")):
            item["severity"] = severity
        cases = (
            (r"\_U-001 and U-003_", r"\_U-001 and U-003_"),
            (r"_U-001 and U-003\_", r"_U-001 and U-003\_"),
            (r"_U-001 to U-003\_", r"_U-001 to U-003\_"),
            (r"_U-001 and \_literal and U-003_", r"_U-003 and \_literal and U-002_"),
            # Escaped source tokens stay literal; the remaining delimiter run,
            # or a run after an even number of backslashes, still opens emphasis.
            (r"\__U-001 and U-003__", r"\__U-001 and U-002__"),
            (r"\\_U-001 and U-003_", r"\\_U-001 and U-002_"),
            ("_U-001\nU-003_", "_U-003\nU-002_"),
            ("_U-001\n\nU-003_", "_U-001\n\nU-003_"),
            ("__U-001\n \t\nU-003__", "__U-001\n \t\nU-003__"),
            ("_U-001\n```\nU-002\n```\nU-003_", "_U-001\n```\nU-002\n```\nU-003_"),
            ("____U-001\n\n to U-003____", "____U-001\n\n to U-003____"),
            ("____U-001\n~~~\nU-002\n~~~\n to U-003____", "____U-001\n~~~\nU-002\n~~~\n to U-003____"),
            ("U-001\n\n to U-003", "U-003\n\n to U-002"),
            ("__U-001__\n\n to __U-003__", "__U-003__\n\n to __U-002__"),
            # A range stays on one line; each id across lines is renumbered alone.
            ("U-001\n to \nU-003", "U-003\n to \nU-002"),
        )
        data["next_steps"] = [source + "; then U-002." for source, _ in cases]
        original = copy.deepcopy(data)
        changed = findings.renumber(data, findings.renumber_map(data["findings"]))
        self.assertEqual(data, original)
        self.assertEqual(changed["next_steps"], [expected + "; then U-001." for _, expected in cases])
        findings.check_findings(changed)
        self.assertEqual(findings.renumber(changed, findings.renumber_map(changed["findings"])), changed)

    def test_renumber_preserves_unicode_identifiers_in_ranges_styled_ids_and_lists(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = data["findings"][:3]
        for item, severity in zip(data["findings"], ("Low", "High", "Medium")):
            item["severity"] = severity
        contexts = (("変数", "値"), ("変数", ""), ("", "値"),
                    ("é", "é"), ("é", ""), ("", "é"),
                    ("e\u0301", "\u0301e"), ("e\u0301", ""), ("", "\u0301e"),
                    ("head\u203f", "\u203ftail"))
        # Every Other_ID_Start / Other_ID_Continue character in Unicode 18.0.0,
        # including ID characters that Python's narrower XID test rejects.
        other_identifier_chars = (
            "\u1885\u1886\u2118\u212e\u309b\u309c"
            "\u00b7\u0387\u1369\u136a\u136b\u136c\u136d\u136e\u136f\u1370\u1371"
            "\u19da\u200c\u200d\u30fb\uff65"
        )
        contexts += tuple(pair for char in other_identifier_chars
                          for pair in (("foo" + char, char + "bar"), ("foo" + char, ""), ("", char + "bar")))
        patterns = ("_U-001 to U-003_", "__U-001 to U-003__", "____U-001 to U-003____", "__U-001__",
                    "_U-001_ to U-003", "U-001 to _U-003_", "__U-001/U-003__", "_U-001 and U-003_")
        cases = []
        for before, after in contexts:
            for pattern in patterns:
                # For ranges with only one formatted endpoint, attach the
                # identifier context only at that endpoint's underscore.
                prefix = before if pattern.startswith("_") else ""
                suffix = after if pattern.endswith("_") else ""
                if not prefix and not suffix:
                    continue
                token = prefix + pattern + suffix
                cases.append((token + "; 次にU-002を修正。", token + "; 次にU-001を修正。"))
        data["next_steps"] = [source for source, _ in cases]
        original = copy.deepcopy(data)
        changed = findings.renumber(data, findings.renumber_map(data["findings"]))
        self.assertEqual(data, original)
        self.assertEqual(changed["next_steps"], [expected for _, expected in cases])
        findings.check_findings(changed)
        self.assertEqual(findings.renumber(changed, findings.renumber_map(changed["findings"])), changed)

    def test_renumber_handles_long_underscore_inputs(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = data["findings"][:1]
        data["findings"][0]["id"] = "U-002"
        data["next_steps"] = ["Fix U-002."]
        markers = "_" * 20_000
        cases = (
            ("_item " * 20_000 + "U-002", "_item " * 20_000 + "U-001"),
            (markers + "U-002 and U-002" + markers, markers + "U-001 and U-001" + markers),
            (markers + "U-002 to U-002" + markers, markers + "U-001" + markers),
        )
        for source, expected in cases:
            with self.subTest(source=source[:40]), tempfile.TemporaryDirectory() as tmp:
                data["summary"] = source
                target = Path(tmp) / "findings.json"
                target.write_text(json.dumps(data), encoding="utf-8")
                result = run("renumber", target)  # The CLI has a bounded completion timeout.
                self.assertEqual(result.returncode, 0, result.stderr)
                changed = json.loads(target.read_text(encoding="utf-8"))
                self.assertEqual(changed["summary"], expected)
                findings.check_findings(changed)

    def test_renumber_round_eight_references(self):
        mapping = {"U-001": "U-003", "U-002": "U-004", "U-003": "U-001", "U-004": "U-002"}
        for prose, expected in (
            # Slash-joined ids in emphasis or code spans are references, not a source path.
            ("**U-001**/**U-002**", "**U-003**/**U-004**"),
            ("*U-001*/*U-002*", "*U-003*/*U-004*"),
            ("~~U-001~~/~~U-002~~", "~~U-003~~/~~U-004~~"),
            ("U-001/*U-002*", "U-003/*U-004*"),
            ("U-001/`U-002`", "U-003/`U-004`"),
            ("`U-001`/U-002", "`U-003`/U-004"),
            ("src/**U-001**.tsx:3", "src/**U-001**.tsx:3"),
            # A lone id beside a slash is a path unless the slash joins it to a code span.
            ("see /U-001", "see /U-001"),
            ("U-001/ and /U-001/", "U-001/ and /U-001/"),
            ("U-001/* and U-001/**", "U-001/* and U-001/**"),
            ("`U-001`/U-002/x", "`U-003`/U-002/x"),
            ("`U-001`/U-002.", "`U-003`/U-004."),
            ("`U-001`/U-002/U-003", "`U-003`/U-004/U-001"),
            ("`U-001`/U-002/`U-003`", "`U-003`/U-004/`U-001`"),
            ("**`U-001`**/U-002", "**`U-003`**/U-004"),
            ("U-001/ `U-002`", "U-003/ `U-004`"),
            ("`U-001` /U-002", "`U-003` /U-004"),
            # Hyphen, dash and space variants connect a range like their ASCII forms.
            ("U-001\u2010U-003", "U-003, U-004, U-001"),
            ("U-001\u2011U-003", "U-003, U-004, U-001"),
            ("U-001\uff0dU-003", "U-003, U-004, U-001"),
            ("U-001\u2015U-003", "U-003, U-004, U-001"),
            ("U-001\u2012U-003", "U-003, U-004, U-001"),
            ("U-001\u3000〜\u3000U-003", "U-003, U-004, U-001"),
            ("U-001\u00a0to\u00a0U-003", "U-003, U-004, U-001"),
            ("_U-001\u2010U-003_", "_U-003, U-004, U-001_"),
        ):
            with self.subTest(prose=prose):
                self.assertEqual(findings._rewrite_prose(prose, mapping), expected)

    def test_renumber_fence_openers_stay_linear(self):
        # Nested quote and list markers on a line that is not a fence used to backtrack exponentially.
        for prefix in ("> ", ">  ", "-  ", "1.  ", "- > "):
            with self.subTest(prefix=prefix):
                started = time.monotonic()
                self.assertEqual(findings._rewrite_prose(prefix * 400 + "x U-001", {"U-001": "U-002"}),
                                 prefix * 400 + "x U-002")
                self.assertLess(time.monotonic() - started, 2)
        # Fence openers after markers are recognized as before.
        for prose, expected in (
            ("> > ```\n> > U-001\n> > ```\nU-001", "> > ```\n> > U-001\n> > ```\nU-002"),
            ("-  1.  ```\n        U-001\n        ```\nU-001", "-  1.  ```\n        U-001\n        ```\nU-002"),
            (">```\nU-001\n```\nU-001", ">```\nU-002\n```\nU-001"),
            ("-```\nU-001", "-```\nU-002"),
            ("  - >  ~~~\nU-001\n~~~\nU-001", "  - >  ~~~\nU-002\n~~~\nU-001"),
        ):
            with self.subTest(prose=prose):
                self.assertEqual(findings._rewrite_prose(prose, {"U-001": "U-002"}), expected)

    def test_renumber_refuses_a_missing_id_that_another_finding_moves_to(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = data["findings"][:2]
        data["findings"][0]["severity"] = "Low"
        data["findings"][1]["id"] = "U-003"
        for text in ("Fix U-002 first; U-001 is cosmetic.", "Fix **U-002** first."):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as tmp:
                data["next_steps"] = [text]
                target = Path(tmp) / "findings.json"
                target.write_text(json.dumps(data), encoding="utf-8")
                before = target.read_bytes()
                result = run("renumber", target)
                self.assert_refused(result)
                self.assertIn("U-002", result.stderr)
                self.assertEqual(target.read_bytes(), before)
        # A missing id nothing moves to stays as written.
        data["next_steps"] = ["See U-009."]
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "findings.json"
            target.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(run("renumber", target).returncode, 0)
            self.assertEqual(json.loads(target.read_text(encoding="utf-8"))["next_steps"], ["See U-009."])

    def test_reference_urls_refuse_invisible_format_characters(self):
        for url in ("https://x\u200b.org/", "https://example.org/a\u202eb", "https://example.org/\u2028"):
            with self.subTest(url=url):
                with self.assertRaises(findings.RecordError):
                    findings._http(url, "references[0].url")
        # Join controls are part of words in Persian and Indic scripts, but never of a host.
        for url in ("https://goo\u200dgle.com/", "https://\u200c.com/"):
            with self.subTest(url=url):
                with self.assertRaises(findings.RecordError):
                    findings._http(url, "url")
        findings._http("https://fa.wikipedia.org/wiki/\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645", "url")

    def test_renumber_refuses_a_moving_range_with_missing_ids_without_writing(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = data["findings"][:2]
        data["findings"][0]["severity"] = "Low"
        data["findings"][1]["id"] = "U-003"
        for text in ("Fix U-001 to U-003.", "Fix ` U-001 ` to ` U-003 `.",
                     "Fix __U-001 to U-003__.", "Fix __` U-001 ` to ` U-003 `__.",
                     "Fix ____U-001 to U-003____.", "Fix _U-001 to ____U-003_____."):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as tmp:
                data["next_steps"] = [text]
                findings.check_findings(data, ordered=False)
                target = Path(tmp) / "findings.json"
                target.write_text(json.dumps(data), encoding="utf-8")
                before = target.read_bytes()
                result = run("renumber", target)
                self.assert_refused(result)
                self.assertIn("unknown U-002", result.stderr)
                self.assertEqual(target.read_bytes(), before)
                self.assertEqual({p.name for p in Path(tmp).iterdir()}, {target.name})

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

    def test_concurrent_record_updates_are_refused_by_the_records_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, fragment = Path(tmp) / "findings.json", Path(tmp) / "fragment.json"
            target.write_text(json.dumps(SAMPLE), encoding="utf-8")
            fragment.write_text('{"summary":"updated"}', encoding="utf-8")
            before = target.read_bytes()
            (Path(tmp) / findings.RECORDS_LOCK).mkdir()  # Another merge, flows or renumber is running.
            for cmd in (["merge", str(target), str(fragment)], ["renumber", str(target)],
                        ["flows", str(Path(tmp) / "flows.json"), str(fragment)]):
                error = io.StringIO()
                with self.subTest(cmd=cmd[0]), contextlib.redirect_stderr(error):
                    self.assertEqual(findings.main(cmd), 2)
                    self.assertIn("records are locked", error.getvalue())
                    self.assertIn("rmdir", error.getvalue())
            self.assertEqual(target.read_bytes(), before)
            (Path(tmp) / findings.RECORDS_LOCK).rmdir()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(findings.main(["merge", str(target), str(fragment)]), 0)
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
