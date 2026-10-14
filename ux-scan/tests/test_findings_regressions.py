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
                    'https://example.com/"bad"', "https://[::1]example.com/"):
            with self.subTest(url=url):
                data = copy.deepcopy(SAMPLE)
                data["findings"][0]["references"] = [{"url": url}]
                with self.assertRaisesRegex(findings.RecordError, "http"):
                    findings.check_findings(data)

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
                         ['<Button label={"a \\"quoted\\""} data-id="U-001"> foo____U-001 U-001____bar ____U-002 U-002'])

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

    def test_renumber_refuses_a_moving_range_with_missing_ids_without_writing(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = data["findings"][:2]
        data["findings"][0]["severity"] = "Low"
        data["findings"][1]["id"] = "U-003"
        data["next_steps"] = ["Fix U-001 to U-003."]
        findings.check_findings(data, ordered=False)
        with tempfile.TemporaryDirectory() as tmp:
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
