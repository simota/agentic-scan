"""Pin the results of the guard's and renderers' shortcuts to their full computations.

Each shortcut skips work only when that work cannot change the outcome. These
tests compare the shortcut with the computation it replaces, so a later change
to a pattern that breaks that premise fails here.
"""
import itertools
from pathlib import Path
import random
import re
import subprocess
import sys
import tempfile
import textwrap
import unicodedata
import unittest

from test_contract_consistency import build
from test_privacy_scan import complete_doc, findings, personal_values, render


class GuardShortcutTests(unittest.TestCase):
    def test_format_characters_and_ideographic_dots_are_still_normalised_away(self):
        refused = (
            "contact user@exa\u200bmple\u3002jp",       # zero-width space, ideographic stop
            "contact user\u00ad@privacy-scan\uff0elocalhost",  # soft hyphen, full-width stop
            "contact user@privacy-scan\uff61localhost\u2060",  # half-width stop, word joiner
            "card 4111\u200b1111\u200b1111\u200b1111",
        )
        for value in refused:
            with self.subTest(value=value), self.assertRaises(findings.SchemaError):
                findings._no_personal_values(value, "w")
        for value in ("see user@example\u3002com", "logs\u200b/2026/1016/0930.log"):
            with self.subTest(value=value):
                findings._no_personal_values(value, "w")

    def test_normalisation_matches_a_per_character_filter(self):
        rng = random.Random(5)
        pool = ["a", "1", "@", ".", "\u3002", "\uff0e", "\uff61", "\u200b", "\u00ad", "\u2060",
                "\ufeff", "\u061c", "\U000e0001", "日", " "]
        dots = str.maketrans("\u3002\uff0e\uff61", "...")
        for _ in range(500):
            value = "".join(rng.choice(pool) for _ in range(rng.randint(0, 30)))
            expected = "".join(c for c in value.translate(dots) if unicodedata.category(c) != "Cf")
            shortcut = value
            for dot in personal_values.IDNA_DOT_CHARS:
                shortcut = shortcut.replace(dot, ".")
            for char in {c for c in set(shortcut) if unicodedata.category(c) == "Cf"}:
                shortcut = shortcut.replace(char, "")
            self.assertEqual(shortcut, expected)

    def test_masking_never_creates_a_long_number(self):
        # The guard masks only when the raw text already holds a long run.
        rng = random.Random(11)
        atoms = ["1", "23", "4567", " ", "-", "\u2212", "ー", "\n", "2026-10-09", "10:22:33", ":",
                 "123e4567-e89b-12d3-a456-426614174000", "ab12" * 8, "sha256", "x", "#"]
        for _ in range(3000):
            value = "".join(rng.choice(atoms) for _ in range(rng.randint(0, 30)))
            if not personal_values.LONG_NUMBER.search(value):
                self.assertIsNone(personal_values.LONG_NUMBER.search(
                    personal_values._mask_technical_numbers(value)), value)

    def test_long_numbers_beside_technical_values_are_still_refused(self):
        for value in ("id 123e4567-e89b-12d3-a456-426614174000 123456789012",
                      "2026-10-09 123456789012", "digest " + "ab12" * 8 + " 1234 5678 9012"):
            with self.subTest(value=value), self.assertRaises(findings.SchemaError):
                findings._no_personal_values(value, "w")
        for value in ("2026-10-09 - 2026-10-31", "123e4567-e89b-12d3-a456-426614174000"):
            with self.subTest(value=value):
                findings._no_personal_values(value, "w")

    def test_cfws_chain_jumps_match_a_scan_of_every_position(self):
        rng = random.Random(3)
        atoms = [" ", "\t", "\r\n ", "\n\t", "\n", "(", ")", "\\", "a", "@", "x(c)", "( n )"]
        for _ in range(2000):
            value = "".join(rng.choice(atoms) for _ in range(rng.randint(0, 25)))
            before, after = personal_values._email_cfws(value)
            expected_after, expected_before = {}, {}
            hops = _direct_spans(value)
            for pos in range(len(value) - 1, -1, -1):
                if pos in hops:
                    end = hops[pos]
                    expected_after[pos] = expected_after.get(end, end)
            starts = {end: start for start, end in hops.items()}
            for pos in range(len(value) + 1):
                if pos in starts:
                    start = starts[pos]
                    expected_before[pos] = expected_before.get(start, start)
            self.assertEqual((before, after), (expected_before, expected_after), repr(value))


class PackageVersionBacktrackingTests(unittest.TestCase):
    # The former suffix pattern, which accepts the same strings slowly.
    FORMER = re.compile(r"\d+\.\d+\.\d+[-+](?:alpha|beta|rc|canary|next|pre|preview|dev|snapshot"
                        r"|nightly|build|experimental|insiders)(?:[.-]?[0-9A-Za-z]+)*", re.IGNORECASE)

    def test_suffix_pattern_accepts_the_same_strings(self):
        for suffix in itertools.chain.from_iterable(
                itertools.product("a1.-_日", repeat=k) for k in range(6)):
            for head in ("1.2.3-beta", "1.2.3+BUILD", "1.2-beta", "1.2.3-"):
                value = head + "".join(suffix)
                self.assertEqual(bool(personal_values.PACKAGE_VERSION.fullmatch(value)),
                                 bool(self.FORMER.fullmatch(value)), value)

    def test_version_running_on_into_prose_is_judged_without_backtracking(self):
        # Under the former pattern this took hours: every split of the run was tried.
        script = textwrap.dedent(r'''
            import sys
            sys.path.insert(0, sys.argv[1])
            from test_privacy_scan import findings
            for tail in ("に更新した", "_", "!"):
                value = "sdk@1.2.3-canary" + "abcdef0123456789" * 64 + tail
                try:
                    findings.validate({"limitations": [value]})
                except findings.SchemaError:
                    pass
            findings.validate({"limitations": ["sdk@1.2.3-canary" + "abcdef0123456789" * 64]})
        ''')
        try:
            result = subprocess.run(
                [sys.executable, "-B", "-c", script, str(Path(__file__).resolve().parent)],
                capture_output=True, text=True, timeout=10)
        except subprocess.TimeoutExpired:
            raise self.failureException("package-version matching backtracked") from None
        self.assertEqual(result.returncode, 0, result.stderr)


def _direct_spans(value):
    """The comment and folding-whitespace spans `_email_cfws` indexes, before chaining."""
    spans = {m.start(): m.end() for m in personal_values.EMAIL_FWS.finditer(value)}
    stack, escaped_until = [], 0
    for marker in personal_values.EMAIL_COMMENT_MARKERS.finditer(value):
        pos = marker.start()
        if pos < escaped_until:
            continue
        char = value[pos]
        if char == "(":
            stack.append(pos)
        elif char == ")":
            if stack:
                spans[stack.pop()] = pos + 1
        elif char == "\\":
            if stack:
                if value[pos + 1:pos + 2] in ("\r", "\n"):
                    stack.clear()
                else:
                    escaped_until = pos + 2
        elif not personal_values._email_fold(value, pos):
            stack.clear()
    return spans


class RenderShortcutTests(unittest.TestCase):
    def test_markdown_escapes_match_a_translate_table(self):
        table = str.maketrans({c: "\\" + c for c in "\\`*_[]|~#$"})
        rng = random.Random(9)
        pool = list("\\`*_[]|~#$ab日\n")
        for _ in range(2000):
            value = "".join(rng.choice(pool) for _ in range(rng.randint(0, 20)))
            self.assertEqual(render._escape_markdown(value), value.translate(table))

    def test_autolink_and_url_scans_need_their_markers(self):
        rng = random.Random(13)
        pool = ["http", "HTTPS", "ftp", "www", "WWW", ":", "/", ".", "a", "日", " ", "_"]
        for _ in range(3000):
            value = "".join(rng.choice(pool) for _ in range(rng.randint(0, 12)))
            if "://" not in value and "www." not in value:
                self.assertIsNone(render.AUTOLINK_START.search(value), value)
                self.assertIsNone(render.URL_TOKEN.search(value), value)
        self.assertEqual(render.markdown_text("see ftp://f.example/x"), "see ftp\\://f.example/x")
        self.assertEqual(render.markdown_text("see www.x.example"),
                         "see [www.x.example](<http://www.x.example>)")
        self.assertEqual(render.markdown_text("日本語_*x*"), "日本語\\_\\*x\\*")


class StaleOutputShortcutTests(unittest.TestCase):
    def test_recorded_language_report_with_other_language_dashboard_is_stale(self):
        with tempfile.TemporaryDirectory() as directory:
            doc = complete_doc()  # meta.lang is en
            out = build(directory, doc)
            self.assertEqual(findings.contract_problems(out), [])
            (out / "dashboard.html").write_text(render.render_html(doc, "ja"), encoding="utf-8")
            self.assertTrue(any("stale outputs" in p for p in findings.contract_problems(out)))

    def test_either_language_is_accepted_whatever_meta_lang_says(self):
        for recorded in ("ja", "en"):
            for rendered in ("ja", "en"):
                with self.subTest(recorded=recorded, rendered=rendered), \
                        tempfile.TemporaryDirectory() as directory:
                    doc = complete_doc()
                    doc["meta"]["lang"] = recorded
                    out = build(directory, doc, lang=rendered)
                    self.assertEqual(findings.contract_problems(out), [])


if __name__ == "__main__":
    unittest.main()
