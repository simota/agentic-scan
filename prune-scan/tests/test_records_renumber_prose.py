"""Keep source evidence literal when renumbering references in review prose."""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_findings_regressions import SCRIPTS, record, run_cli
import findings


class RenumberProseTests(unittest.TestCase):
    def findings_record(self, location="docs/P-002.md:1"):
        data = record()
        data["findings"][0].update(id="P-002", location=location)
        return data

    def renumbered(self, data):
        original = copy.deepcopy(data)
        findings.check_findings(data, ordered=False)
        result = findings.renumber(data, findings.renumber_map(data["findings"]))
        findings.check_findings(result)
        self.assertEqual(data, original, "renumber must not mutate its input")
        return result

    def test_source_paths_remain_literal_in_every_narrative_section(self):
        data = self.findings_record()
        prose = "P-002: docs/P-002.md:1 が根拠。docs/P-002.md を削除して、P-002を解決する。"
        expected = "P-001: docs/P-002.md:1 が根拠。docs/P-002.md を削除して、P-001を解決する。"
        item = data["findings"][0]
        for field in ("title", "basis", "impact", "risk"):
            item[field] = prose
        for field in findings.SUBTRACTION_FIELDS:
            item["subtraction"][field] = prose
        for field in ("evidence", "dynamic_checked"):
            item["validation"][field] = prose
        data["summary"] = prose
        for section in findings.LIST_KEYS:
            data[section] = [prose]
        data["perspectives"] = [{"name": "DC Dead code", "result": prose, "note": prose}]
        data["extra"] = {"location": [prose], "meta": {"note": "P-002の補足"}}

        updated = self.renumbered(data)
        item = updated["findings"][0]
        self.assertEqual(item["location"], "docs/P-002.md:1")
        for field in ("title", "basis", "impact", "risk"):
            self.assertEqual(item[field], expected)
        for field in findings.SUBTRACTION_FIELDS:
            self.assertEqual(item["subtraction"][field], expected)
        for field in ("evidence", "dynamic_checked"):
            self.assertEqual(item["validation"][field], expected)
        self.assertEqual(updated["summary"], expected)
        for section in findings.LIST_KEYS:
            self.assertEqual(updated[section], [expected])
        self.assertEqual(updated["perspectives"],
                         [{"name": "DC Dead code", "result": expected, "note": expected}])
        self.assertEqual(updated["extra"], {"location": [expected], "meta": {"note": "P-001の補足"}})

    def test_unlisted_source_names_and_locations_remain_literal(self):
        literals = ("src/P-002.py:10-12", "P-002.json", "src/P-002/component.py",
                    "資料/P-002.md", "P-002/資料.py", "src\\P-002.py", "P-002:123",
                    "legacy-P-002.js", "foo-P-002(archive).md")
        for literal in literals:
            with self.subTest(literal=literal):
                data = self.findings_record(location="app.py:10")
                data["summary"] = f"{literal} を確認し、P-002を解決する。"
                updated = self.renumbered(data)
                self.assertEqual(updated["summary"], f"{literal} を確認し、P-001を解決する。")

    def test_urls_remain_literal_while_link_labels_and_adjacent_prose_change(self):
        cases = (
            ("P-002: https://example.test/P-002?id=P-002#P-002",
             "P-001: https://example.test/P-002?id=P-002#P-002"),
            ("[P-002](https://example.test/P-002)P-002を確認。",
             "[P-001](https://example.test/P-002)P-001を確認。"),
            ("参照https://example.test/P-002。P-002を確認。",
             "参照https://example.test/P-002。P-001を確認。"),
            ("<HTTPS://example.test/P-002> と P-002。",
             "<HTTPS://example.test/P-002> と P-001。"),
            ("https://example.test/spec(P-002)/notes を使って P-002を確認。",
             "https://example.test/spec(P-002)/notes を使って P-001を確認。"),
            ("（https://example.test/P-002）P-002を確認。",
             "（https://example.test/P-002）P-001を確認。"),
        )
        for prose, expected in cases:
            with self.subTest(prose=prose):
                data = self.findings_record(location="app.py:10")
                data["summary"] = prose
                self.assertEqual(self.renumbered(data)["summary"], expected)

    def test_known_paths_with_spaces_and_nonstandard_names_remain_literal(self):
        for path in ("docs/P-002 review.md", "P-002.資料", "P-002-notes"):
            with self.subTest(path=path):
                data = self.findings_record(location=path + ":10")
                data["findings"][0]["occurrences"] = ["notes/P-002 appendix:20"]
                data["summary"] = f"{path} と notes/P-002 appendix を削除し、P-002を解決する。"
                self.assertEqual(self.renumbered(data)["summary"],
                                 f"{path} と notes/P-002 appendix を削除し、P-001を解決する。")

    def test_known_citation_urls_preserve_punctuation_used_as_prose_delimiters(self):
        data = self.findings_record(location="app.py:10")
        url = "https://example.test/資料。P-002"
        data["findings"][0]["references"] = [{"url": url}]
        data["summary"] = f"{url} を根拠に P-002 を解決する。"
        updated = self.renumbered(data)
        self.assertEqual(updated["findings"][0]["references"], [{"url": url}])
        self.assertEqual(updated["summary"], f"{url} を根拠に P-001 を解決する。")

    def test_bare_ids_are_references_even_when_a_source_basename_is_an_id(self):
        data = self.findings_record(location="P-002:10")
        data["summary"] = ("P-002:10 を根拠に、`P-002`とP-002を確認。P-002. P-002: done. "
                           "P-002(checked) と P-002（確認済み）を参照。")
        self.assertEqual(self.renumbered(data)["summary"],
                         "P-002:10 を根拠に、`P-001`とP-001を確認。P-001. P-001: done. "
                         "P-001(checked) と P-001（確認済み）を参照。")

    def test_slash_separated_ids_remain_references(self):
        data = self.findings_record(location="app.py:10")
        second = copy.deepcopy(data["findings"][0])
        second.update(id="P-001", severity="Info")
        data["findings"].append(second)
        data["summary"] = "関連P-002/P-001を確認。P-002/P-001. P-002・P-001。"
        self.assertEqual(self.renumbered(data)["summary"],
                         "関連P-001/P-002を確認。P-001/P-002. P-001・P-002。")

    def test_cli_preserves_parenthesized_and_unicode_filenames(self):
        data = self.findings_record(location="src/app.py:10")
        item = data["findings"][0]
        item["element"] = "P-002(archive).md"
        item["subtraction"]["what"] = "P-002(archive).md と P-002-仕様.md を削除して P-002 を解決する。"
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in ("P-002(archive).md", "P-002-仕様.md"):
                (directory / name).write_text("Reviewed source.\n", encoding="utf-8")
            target = directory / "findings.json"
            target.write_text(json.dumps(data), encoding="utf-8")
            completed = run_cli("renumber", target)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            updated = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(updated["findings"][0]["element"], "P-002(archive).md")
            self.assertEqual(updated["findings"][0]["subtraction"]["what"],
                             "P-002(archive).md と P-002-仕様.md を削除して P-001 を解決する。")
            for name in ("P-002(archive).md", "P-002-仕様.md"):
                self.assertEqual((directory / name).read_text(encoding="utf-8"), "Reviewed source.\n")

    def test_cli_preserves_unicode_extensions_beside_finding_references(self):
        data = self.findings_record(location="src/app.py:10")
        second = copy.deepcopy(data["findings"][0])
        second.update(id="P-001", severity="Info")
        data["findings"].append(second)
        data["findings"][0]["element"] = "P-002.資料"
        data["findings"][0]["subtraction"]["what"] = "P-002.資料 を削除して P-002 を解決する。"
        data["summary"] = "P-002.資料を削除してP-001を直す。"
        cases = (
            ("P-002(archive).資料を削除してP-001を直す。",
             "P-002(archive).資料を削除してP-002を直す。"),
            ("foo-P-002.資料 を確認してP-001を直す。",
             "foo-P-002.資料 を確認してP-002を直す。"),
            ("P-002(P-001.資料)を確認。", "P-001(P-001.資料)を確認。"),
            ("P-002.данные と P-002.résumé-P-001 を削除してP-001を直す。",
             "P-002.данные と P-002.résumé-P-001 を削除してP-002を直す。"),
            ("P-002.📄を削除してP-001を直す。", "P-002.📄を削除してP-002を直す。"),
            ("P-002.\u0301txtを削除してP-001を直す。", "P-002.\u0301txtを削除してP-002を直す。"),
            ("P-002.re\u0301sume\u0301-P-001 を削除してP-001を直す。",
             "P-002.re\u0301sume\u0301-P-001 を削除してP-002を直す。"),
            ("P-002(P-001.📄)を確認。", "P-001(P-001.📄)を確認。"),
            ("P-002.👩\u200d💻-P-001 を削除してP-001を直す。",
             "P-002.👩\u200d💻-P-001 を削除してP-002を直す。"),
            ("P-002/P-001.資料 と P-002\\P-001.資料 を削除してP-001を直す。",
             "P-002/P-001.資料 と P-002\\P-001.資料 を削除してP-002を直す。"),
            ("P-002/P-001(archive).md と P-002\\P-001(archive).📄 を削除してP-001を直す。",
             "P-002/P-001(archive).md と P-002\\P-001(archive).📄 を削除してP-002を直す。"),
            ("P-002/P-001. P-001 を直す。P-002。P-002.",
             "P-001/P-002. P-002 を直す。P-001。P-001."),
            ("P-002/P-001(確認済み)を確認。", "P-001/P-002(確認済み)を確認。"),
        )
        data["decisions"] = [before for before, _ in cases]
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "findings.json"
            target.write_text(json.dumps(data), encoding="utf-8")
            completed = run_cli("renumber", target)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            updated = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(updated["findings"][0]["element"], "P-002.資料")
            self.assertEqual(updated["findings"][0]["subtraction"]["what"],
                             "P-002.資料 を削除して P-001 を解決する。")
            self.assertEqual(updated["summary"], "P-002.資料を削除してP-002を直す。")
            self.assertEqual(updated["decisions"], [after for _, after in cases])

    def test_cli_preserves_unicode_stems_and_their_source_identity(self):
        data = self.findings_record(location="src/app.py:10")
        second = copy.deepcopy(data["findings"][0])
        second.update(id="P-001", severity="Info")
        data["findings"].append(second)
        item = data["findings"][0]
        item["element"] = "P-002資料.md"
        item["subtraction"]["what"] = "P-002資料.mdを削除してP-002を解決する。"
        sources = (
            "P-002資料.md", "資料P-002補足.md", "P-002まとめ.md", "P-002はじめに.md",
            "P-002資料v2.md", "P-002はじめにv2.md", "P-002данные.md", "P-002école.md", "P-002\u0301.md",
            "P-002テ\u3099ータ.md", "P-002📄.md", "P-002👩\u200d💻.md", "P-002資料.資料",
            "P-002は\u3099じめに.md", "P-002は\u0301じめに.md", "P-002て\u3099はじめに.md",
            "P-002資料(archive).md", "P-002(archive)資料.md", "P-002資料P-001.md",
            "P-002資料-P-001.md", "P-002資料/P-001.md", "P-002/P-001資料.md",
            "P-002資料/P-001補足.md", "P-002資料\\P-001補足.md", "P-002資料/P-001",
            "./P-002ではlegacy.py", "./P-002はP-001資料.md", "P-002資料:5", "P-002資料:5-7",
        )
        data["decisions"] = [f"{source} を削除してP-001を直す。" for source in sources]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "P-002資料.md"
            source.write_text("Reviewed source.\n", encoding="utf-8")
            target = directory / "findings.json"
            target.write_text(json.dumps(data), encoding="utf-8")
            completed = run_cli("renumber", target)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            updated = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(updated["findings"][0]["element"], "P-002資料.md")
            self.assertEqual(updated["findings"][0]["subtraction"]["what"],
                             "P-002資料.mdを削除してP-001を解決する。")
            self.assertEqual(updated["decisions"],
                             [f"{source} を削除してP-002を直す。" for source in sources])
            self.assertEqual(source.read_text(encoding="utf-8"), "Reviewed source.\n")
            checked = run_cli("check", target)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            before = target.read_bytes()
            completed = run_cli("renumber", target)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(target.read_bytes(), before)

    def test_cli_disambiguates_unicode_names_and_japanese_references(self):
        data = self.findings_record(location="src/app.py:10")
        second = copy.deepcopy(data["findings"][0])
        second.update(id="P-001", severity="Info")
        data["findings"].append(second)
        cases = (
            ("P-002資料.mdを削除してP-001を直す。", "P-002資料.mdを削除してP-002を直す。"),
            ("P-002ではP-001資料.mdを削除する。", "P-001ではP-001資料.mdを削除する。"),
            ("P-002では不要なlegacy.pyを削除する。", "P-001では不要なlegacy.pyを削除する。"),
            ("P-002の指摘はlegacy.pyにある。", "P-001の指摘はlegacy.pyにある。"),
            ("P-002て\u3099はlegacy.pyを確認。", "P-001て\u3099はlegacy.pyを確認。"),
            ("P-002か\u3099app.pyを対象にする。", "P-001か\u3099app.pyを対象にする。"),
            ("P-002て\u3099test.pyを検証。", "P-001て\u3099test.pyを検証。"),
            ("P-002まて\u3099test.pyで確認。", "P-001まて\u3099test.pyで確認。"),
            ("P-002(P-001資料.md)を確認。", "P-001(P-001資料.md)を確認。"),
            ("P-002(確認済み)ではP-001資料.mdを削除。", "P-001(確認済み)ではP-001資料.mdを削除。"),
            ("P-002資料についてP-001を直す。", "P-001資料についてP-002を直す。"),
            ("P-002/P-001を確認。P-002/P-001ではapp.pyを削除。",
             "P-001/P-002を確認。P-001/P-002ではapp.pyを削除。"),
            ("P-002/P-001について確認。P-002/P-001にある処理を確認。",
             "P-001/P-002について確認。P-001/P-002にある処理を確認。"),
            ("P-002/P-001資料 を確認してP-001を直す。", "P-001/P-002資料 を確認してP-002を直す。"),
            ("./P-002/P-001資料 を削除してP-001を直す。", "./P-002/P-001資料 を削除してP-002を直す。"),
            ("P-002の仕様.mdを確認。", "P-001の仕様.mdを確認。"),
            ("./P-002の仕様.mdを削除してP-001を直す。", "./P-002の仕様.mdを削除してP-002を直す。"),
            ("./資料P-002の仕様.mdを削除してP-001を直す。", "./資料P-002の仕様.mdを削除してP-002を直す。"),
            ("P-002にあるapp.py を削除してP-001を直す。", "P-002にあるapp.py を削除してP-002を直す。"),
            ("P-002 にあるapp.pyを削除。", "P-001 にあるapp.pyを削除。"),
            ("./P-002にあるapp.py を削除してP-001を直す。", "./P-002にあるapp.py を削除してP-002を直す。"),
            ("P-002資料:5-7を確認してP-001を直す。", "P-002資料:5-7を確認してP-002を直す。"),
        )
        data["decisions"] = [before for before, _ in cases]
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "findings.json"
            target.write_text(json.dumps(data), encoding="utf-8")
            completed = run_cli("renumber", target)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            updated = json.loads(target.read_text(encoding="utf-8"))
            for actual, (before, expected) in zip(updated["decisions"], cases):
                with self.subTest(before=before):
                    self.assertEqual(actual, expected)

    def test_known_source_names_override_the_japanese_particle_boundary(self):
        data = self.findings_record(location="P-002の仕様.md:10")
        data["summary"] = "P-002の仕様.mdを削除してP-002を直す。"
        self.assertEqual(self.renumbered(data)["summary"], "P-002の仕様.mdを削除してP-001を直す。")

    def test_cli_scans_long_unicode_stems_and_failed_candidates_once(self):
        data = self.findings_record(location="src/app.py:10")
        stem = "-".join(["P-002資料"] * 16000)
        filename = stem + ".md"
        data["summary"] = stem
        data["decisions"] = [f"{filename}を削除してP-002を直す。", f"P-002({filename})を確認。"]
        data["next_steps"] = ["P-002では" * 16000 + "P-002資料.mdを削除。"]
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "findings.json"
            target.write_text(json.dumps(data), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(SCRIPTS / "findings.py"), "renumber", str(target)],
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            updated = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(updated["summary"], "-".join(["P-001資料"] * 16000))
            self.assertEqual(updated["decisions"],
                             [f"{filename}を削除してP-001を直す。", f"P-001({filename})を確認。"])
            self.assertEqual(updated["next_steps"], ["P-001では" * 16000 + "P-002資料.mdを削除。"])

    def test_known_source_matches_preserve_overlaps_and_unicode_offsets(self):
        data = self.findings_record(location="app.py:10")
        second = copy.deepcopy(data["findings"][0])
        second.update(id="P-001", severity="Info")
        data["findings"].append(second)
        data["findings"][0]["occurrences"] = ["P-002 P-002:1", "P-002 P-001 note:1",
                                               "P-001 note:1", "note P-002 end:1"]
        data["summary"] = "😀P-002 P-002 P-002 と P-002 P-001 note P-002 end。P-001を直す。"
        self.assertEqual(self.renumbered(data)["summary"],
                         "😀P-002 P-002 P-002 と P-002 P-001 note P-002 end。P-002を直す。")

    def test_known_source_matching_restarts_at_each_narrative_field(self):
        data = self.findings_record(location="P-002 note P-002:1")
        data["summary"] = "P-002 note "
        data["findings"][0]["basis"] = "P-002"
        data["extra"] = {"note": "P-002 note P-002"}
        updated = self.renumbered(data)
        self.assertEqual(updated["summary"], "P-001 note ")
        self.assertEqual(updated["findings"][0]["basis"], "P-001")
        self.assertEqual(updated["extra"], {"note": "P-002 note P-002"})

    def test_cli_does_not_treat_partial_source_names_as_evidence(self):
        cases = (
            ("P-002 note", "P-002 noteworthy", "P-001 noteworthy"),
            ("P-002 note", "P-002 noted earlier", "P-001 noted earlier"),
            ("P-002 note", "P-002 note2 and P-002 note_suffix", "P-001 note2 and P-001 note_suffix"),
            ("view P-002", "Please review P-002 tomorrow", "Please review P-001 tomorrow"),
            ("view P-002", "1view P-002 and quick_view P-002", "1view P-001 and quick_view P-001"),
            ("view P-002 note", "Please review P-002 noteworthy", "Please review P-001 noteworthy"),
            ("P-002 note", "P-002 noteworthy; (P-002 note); 元のP-002 noteを削除してP-002を直す。",
             "P-001 noteworthy; (P-002 note); 元のP-002 noteを削除してP-001を直す。"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "findings.json"
            for source, before, expected in cases:
                with self.subTest(source=source, before=before):
                    data = self.findings_record(location=source + ":1")
                    data["summary"] = before
                    target.write_text(json.dumps(data), encoding="utf-8")
                    completed = run_cli("renumber", target)
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    updated = json.loads(target.read_text(encoding="utf-8"))
                    self.assertEqual(updated["summary"], expected)
                    self.assertEqual(updated["findings"][0]["location"], source + ":1")

    def test_cli_preserves_valid_suffix_when_longer_source_has_no_boundary(self):
        cases = (
            (("view P-002 note P-001", "note P-001"),
             "Please review P-002 note P-001; fix P-001.",
             "Please review P-001 note P-001; fix P-002."),
            (("view P-002 note", "P-002 note"),
             "Please review P-002 note; fix P-001.",
             "Please review P-002 note; fix P-002."),
            (("P-002 note", "P-002 noteworthy"),
             "Remove P-002 noteworthy; fix P-001.",
             "Remove P-002 noteworthy; fix P-002."),
        )
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "findings.json"
            for sources, before, expected in cases:
                with self.subTest(sources=sources):
                    data = self.findings_record(location=sources[0] + ":1")
                    data["findings"][0]["occurrences"] = [source + ":1" for source in sources[1:]]
                    second = copy.deepcopy(data["findings"][0])
                    second.update(id="P-001", severity="Info")
                    data["findings"].append(second)
                    data["summary"] = before
                    target.write_text(json.dumps(data), encoding="utf-8")
                    completed = run_cli("renumber", target)
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    updated = json.loads(target.read_text(encoding="utf-8"))
                    self.assertEqual(updated["summary"], expected)

    def test_known_source_boundaries_follow_the_source_edge_characters(self):
        cases = (("P-002 note", "P-002 note"),
                 ("(P-002)", "before(P-002)after"),
                 ("-P-002-", "before-P-002-after"),
                 ("資料P-002資料", "before資料P-002資料after"))
        for source, prose in cases:
            with self.subTest(source=source):
                data = self.findings_record(location=source + ":1")
                data["summary"] = prose
                data["next_steps"] = ["P-002を直す。"]
                updated = self.renumbered(data)
                self.assertEqual(updated["summary"], prose)
                self.assertEqual(updated["next_steps"], ["P-001を直す。"])

    def test_cli_updates_id_labels_without_absorbing_the_following_path(self):
        data = self.findings_record(location="src/app.py:10")
        second = copy.deepcopy(data["findings"][0])
        second.update(id="P-001", severity="Info")
        data["findings"].append(second)
        data["summary"] = "P-002:src/app.py の問題。P-001:src/other.py の問題。"
        data["decisions"] = ["P-002/P-001:done", "P-002:src/P-001.py:10 を根拠に P-001を確認。",
                             "P-002:123 と P-002/P-001:10 はファイル位置。",
                             "P-002:P-001:done", "P-002:P-001:10"]
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "findings.json"
            target.write_text(json.dumps(data), encoding="utf-8")
            completed = run_cli("renumber", target)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            updated = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(updated["summary"], "P-001:src/app.py の問題。P-002:src/other.py の問題。")
            self.assertEqual(updated["decisions"],
                             ["P-001/P-002:done", "P-001:src/P-001.py:10 を根拠に P-002を確認。",
                              "P-002:123 と P-002/P-001:10 はファイル位置。",
                              "P-001:P-002:done", "P-001:P-001:10"])

    def test_cli_updates_japanese_references_beside_source_names(self):
        data = self.findings_record(location="src/app.py:10")
        second = copy.deepcopy(data["findings"][0])
        second.update(id="P-001", severity="Info")
        data["findings"].append(second)
        data["summary"] = "P-002ではlegacy.pyを削除する。P-001はapp.pyの未使用関数を対象にする。"
        data["next_steps"] = ["P-002をtest.pyで検証。"]
        data["decisions"] = ["P-002-仕様.mdを削除してP-001を直す。",
                             "P-002(archive).mdを削除してP-001を直す。",
                             "P-001ではP-002-仕様.mdを削除する。"]
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "findings.json"
            target.write_text(json.dumps(data), encoding="utf-8")
            completed = run_cli("renumber", target)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            updated = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(updated["summary"],
                             "P-001ではlegacy.pyを削除する。P-002はapp.pyの未使用関数を対象にする。")
            self.assertEqual(updated["next_steps"], ["P-001をtest.pyで検証。"])
            self.assertEqual(updated["decisions"],
                             ["P-002-仕様.mdを削除してP-002を直す。",
                              "P-002(archive).mdを削除してP-002を直す。",
                              "P-002ではP-002-仕様.mdを削除する。"])

    def test_cli_updates_parenthetical_notes_before_japanese_source_prose(self):
        data = self.findings_record(location="src/app.py:10")
        second = copy.deepcopy(data["findings"][0])
        second.update(id="P-001", severity="Info")
        data["findings"].append(second)
        data["summary"] = "P-002(確認済み)ではlegacy.pyを削除する。P-001(checked)はapp.pyの未使用関数を対象にする。"
        data["next_steps"] = ["P-002(確認済み)をtest.pyで検証。"]
        data["decisions"] = ["P-002(archive).mdを削除してP-001(確認済み)を直す。",
                             "P-002(archive)-仕様.mdを削除してP-001を直す。",
                             "P-002(archive)(copy).mdを削除してP-001を直す。",
                             "P-002(P-001-仕様.md)を確認。",
                             "P-002(P-001-仕様.md).jsonを削除してP-001を直す。"]
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "findings.json"
            target.write_text(json.dumps(data), encoding="utf-8")
            completed = run_cli("renumber", target)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            updated = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(updated["summary"],
                             "P-001(確認済み)ではlegacy.pyを削除する。P-002(checked)はapp.pyの未使用関数を対象にする。")
            self.assertEqual(updated["next_steps"], ["P-001(確認済み)をtest.pyで検証。"])
            self.assertEqual(updated["decisions"],
                             ["P-002(archive).mdを削除してP-002(確認済み)を直す。",
                              "P-002(archive)-仕様.mdを削除してP-002を直す。",
                              "P-002(archive)(copy).mdを削除してP-002を直す。",
                              "P-001(P-001-仕様.md)を確認。",
                              "P-002(P-001-仕様.md).jsonを削除してP-002を直す。"])

    def test_cli_renumbers_long_hyphenated_id_list_without_rescanning_suffixes(self):
        data = self.findings_record(location="app.py:10")
        data["summary"] = "-".join(["P-002"] * 16000)
        filename = "P-002(archive)." + ".".join(["P-002"] * 16000)
        data["decisions"] = [f"{filename} を確認してP-002を直す。"]
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "findings.json"
            target.write_text(json.dumps(data), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(SCRIPTS / "findings.py"), "renumber", str(target)],
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            updated = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(updated["summary"], "-".join(["P-001"] * 16000))
            self.assertEqual(updated["decisions"], [f"{filename} を確認してP-001を直す。"])

    def test_cli_indexes_many_sources_once_for_all_narrative_fields(self):
        data = self.findings_record(location="app.py:10")
        item = data["findings"][0]
        item["occurrences"] = [f"docs/path-{index:05d}/P-002.md:10" for index in range(10000)]
        item["occurrences"].append("P-002 appendix:1")
        prose = "P-002 " + "x" * 1000000 + " P-002 appendix; resolve P-002."
        expected = "P-001 " + "x" * 1000000 + " P-002 appendix; resolve P-001."
        for field in ("basis", "impact", "risk"):
            item[field] = prose
        for field in findings.SUBTRACTION_FIELDS:
            item["subtraction"][field] = prose
        for field in ("evidence", "dynamic_checked"):
            item["validation"][field] = prose
        data["summary"] = prose
        for field in ("next_steps", "decisions", "checked_ok"):
            data[field] = [prose]
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "findings.json"
            target.write_text(json.dumps(data), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(SCRIPTS / "findings.py"), "renumber", str(target)],
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            updated = json.loads(target.read_text(encoding="utf-8"))
            item = updated["findings"][0]
            for field in ("basis", "impact", "risk"):
                self.assertEqual(item[field], expected)
            for field in findings.SUBTRACTION_FIELDS:
                self.assertEqual(item["subtraction"][field], expected)
            for field in ("evidence", "dynamic_checked"):
                self.assertEqual(item["validation"][field], expected)
            self.assertEqual(updated["summary"], expected)
            for field in ("next_steps", "decisions", "checked_ok"):
                self.assertEqual(updated[field], [expected])

    def test_cli_renumbers_long_label_chain_without_copying_each_suffix(self):
        data = self.findings_record(location="app.py:10")
        data["summary"] = "P-002:" * 250000 + "done"
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "findings.json"
            target.write_text(json.dumps(data), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(SCRIPTS / "findings.py"), "renumber", str(target)],
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            updated = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(updated["summary"], "P-001:" * 250000 + "done")

    def test_cli_keeps_evidence_and_removal_targets_consistent_and_is_idempotent(self):
        data = self.findings_record()
        data["findings"][0]["basis"] = "docs/P-002.md:1 に P-002 の根拠がある。"
        data["findings"][0]["subtraction"]["what"] = "docs/P-002.md を削除して P-002 を解決する。"
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "docs" / "P-002.md"
            source.parent.mkdir()
            source.write_text("Reviewed source.\n", encoding="utf-8")
            target = directory / "findings.json"
            target.write_text(json.dumps(data), encoding="utf-8")
            completed = run_cli("renumber", target)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            updated = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(updated["findings"][0]["basis"],
                             "docs/P-002.md:1 に P-001 の根拠がある。")
            self.assertEqual(updated["findings"][0]["subtraction"]["what"],
                             "docs/P-002.md を削除して P-001 を解決する。")
            self.assertEqual(source.read_text(encoding="utf-8"), "Reviewed source.\n")
            before = target.read_bytes()
            completed = run_cli("renumber", target)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("already in order", completed.stdout)
            self.assertEqual(target.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
