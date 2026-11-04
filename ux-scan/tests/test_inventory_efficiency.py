"""Behaviour that inventory.py's shortcuts must keep: each one skips work, never a result."""

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "ux-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import inventory  # noqa: E402

try:  # Python 3.11 moved the parser; 3.10 still ships it as sre_parse.
    from re import _constants as sre_constants, _parser as sre_parse
except ImportError:  # pragma: no cover - Python 3.10
    import sre_constants
    import sre_parse

# leading() writes "<global flags>(?=<chars>)(?:<pattern>)".
LEADING = re.compile(r"(\(\?[aiLmsux]+\))?\(\?=(.+?)\)\(\?:(.*)\)", re.S)
ZERO_WIDTH = {sre_constants.AT, sre_constants.ASSERT, sre_constants.ASSERT_NOT}
REPEATS = {sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT, getattr(sre_constants, "POSSESSIVE_REPEAT", None)}


def first_literals(items, ignore_case):
    """(chars, nullable): the characters a match of items can start with, each with its case mode.

    Anything other than literals, groups, alternations, repeats and zero-width
    assertions at the start of a match raises, so a new kind of opening is
    noticed rather than silently left out of the lookahead.
    """
    found = set()
    for op, av in items:
        if op is sre_constants.LITERAL:
            found.add((chr(av), ignore_case))
            return found, False
        if op in ZERO_WIDTH:
            continue
        if op is sre_constants.SUBPATTERN:
            _, add, remove, sub = av
            case = (ignore_case or bool(add & re.I)) and not remove & re.I
            chars, nullable = first_literals(sub, case)
        elif op is sre_constants.BRANCH:
            chars, nullable = set(), False
            for alternative in av[1]:
                more, empty = first_literals(alternative, ignore_case)
                chars, nullable = chars | more, nullable or empty
        elif op in REPEATS:
            low, _, sub = av
            chars, nullable = first_literals(sub, ignore_case)
            nullable = nullable or low == 0
        else:
            raise AssertionError(f"cannot tell the first character after {op}")
        found |= chars
        if not nullable:
            return found, False
    return found, True


class LeadingPatternTests(unittest.TestCase):
    def leading_patterns(self):
        found = {}
        for name, value in vars(inventory).items():
            if isinstance(value, re.Pattern) and (m := LEADING.fullmatch(value.pattern)):
                found[name] = (value, m.group(1) or "", m.group(2), m.group(3))
        return found

    def test_every_match_starts_with_a_character_its_lookahead_admits(self):
        patterns = self.leading_patterns()
        self.assertGreaterEqual(len(patterns), 20)  # The wrapper is still recognised.
        for name, (compiled, head, chars, bare) in patterns.items():
            with self.subTest(pattern=name):
                self.assertEqual(compiled.pattern, f"{head}(?={chars})(?:{bare})")
                flags = re.compile(head + bare).flags
                starts, nullable = first_literals(sre_parse.parse(bare, flags), bool(flags & re.I))
                self.assertFalse(nullable, "a match could start without consuming a character")
                admit = re.compile(f"{head}(?:{chars})")
                for char, ignore_case in starts:
                    variants = {char, char.lower(), char.upper()} if ignore_case else {char}
                    for variant in variants:
                        self.assertTrue(admit.fullmatch(variant), f"{name}: {variant!r} opens a match")

    def test_lookahead_changes_no_match_span_or_group(self):
        texts = [path.read_text(encoding="utf-8") for path in sorted((ROOT / "examples" / "tasklane").rglob("*"))
                 if path.is_file()]
        texts.append('<a href="/x">x</a> <Link to={"/y"}>y</Link> navigate("/z") push({ pathname: "/w" })'
                     ' class="truncate" whiteSpace: "nowrap" fetch(u) axios.get(u) useQuery isLoading'
                     ' .catch(e) ErrorBoundary items.length === 0 v-for="i in x" confirm("Are you sure")'
                     ' <Route path="/r" /> { path: "/p" } export const viewport = { maximumScale: 1 }'
                     ' margin-left: 4px; marginLeft: 4, padding: 8px; fontSize: 12, zIndex: 3,'
                     ' min-width: 400px; outline: "none" --brand: red; transition: all 1s')
        for name, (compiled, head, _, bare) in self.leading_patterns().items():
            plain = re.compile(head + bare)
            with self.subTest(pattern=name):
                for text in texts:
                    self.assertEqual([(m.span(), m.groups()) for m in compiled.finditer(text)],
                                     [(m.span(), m.groups()) for m in plain.finditer(text)])


class SkippedWorkTests(unittest.TestCase):
    def test_physical_properties_are_reported_for_rtl_locales_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.css").write_text(".a { margin-left: 4px; text-align: right; }\n"
                                          ".b { padding-right: 2px }\n", encoding="utf-8")
            (root / "Card.tsx").write_text("export const s = { marginLeft: 8 };\n", encoding="utf-8")
            flows = {"viewports": ["375x812"], "flows": []}
            plain = inventory.inventory(root)
            ltr = inventory.inventory(root, {**flows, "locales": ["en", "de"]})
            rtl = inventory.inventory(root, {**flows, "locales": ["en", "ar-EG"]})
            self.assertNotIn("physical_properties", plain)
            self.assertNotIn("physical_properties", ltr)
            self.assertEqual([(row["property"], row["count"]) for row in rtl["physical_properties"]], [
                ("margin-left", 1), ("marginLeft", 1), ("padding-right", 1), ("text-align: right", 1)])
            self.assertEqual({k: v for k, v in rtl.items() if k != "physical_properties"}, ltr | {
                "flows_sha256": rtl["flows_sha256"]})

    def test_malformed_locales_fail_as_before_rather_than_skip_the_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "app.css").write_text(".a { margin-left: 4px }", encoding="utf-8")
            with self.assertRaises(AttributeError):
                inventory.inventory(tmp, {"locales": [7]})

    def test_confirmation_is_looked_for_only_where_a_destructive_handler_needs_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Bare.tsx").write_text('<button onClick={() => deleteTask(id)}>Delete</button>\n',
                                           encoding="utf-8")
            (root / "Guarded.tsx").write_text('<button onClick={() => deleteTask(id)}>Delete</button>\n'
                                              '<ConfirmDialog />\n', encoding="utf-8")
            (root / "Quiet.tsx").write_text('<p>Remove clutter with a confirm step</p>\n', encoding="utf-8")
            calls = []
            confirm = inventory.CONFIRM

            class Counting:
                def search(self, *args):
                    calls.append(args[0][:20])
                    return confirm.search(*args)

            inventory.CONFIRM = Counting()
            try:
                data = inventory.inventory(root)
            finally:
                inventory.CONFIRM = confirm
            self.assertEqual([row["location"] for row in data["destructive_actions"]], ["Bare.tsx:1"])
            self.assertEqual(len(calls), 2)  # Bare.tsx and Guarded.tsx; Quiet.tsx has no handler.

    def test_only_regular_files_that_are_not_links_are_listed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "real.css").write_text(".a{}", encoding="utf-8")
            (root / "link.css").symlink_to(root / "real.css")
            (root / "dangling.css").symlink_to(root / "missing.css")
            (root / "package-lock.json").write_text("{}", encoding="utf-8")
            if hasattr(os, "mkfifo"):
                os.mkfifo(root / "pipe.css")
            self.assertEqual([p.name for p in inventory.iter_files(root)], ["real.css"])

    def test_locale_bundles_need_a_json_name(self):
        self.assertEqual(inventory.locale_bundle("locales/de.json"), ("locales/{lang}.json", "de"))
        self.assertIsNone(inventory.locale_bundle(Path("locales/de.js")))  # A Path passes the cheap test too.
        for rel in ("locales/de.js", "locales/de.json.bak", "locales/.json", "locales/de.JSON"):
            with self.subTest(rel=rel):
                self.assertIsNone(inventory.locale_bundle(rel))


class RecordTests(unittest.TestCase):
    def test_records_compare_and_print_like_the_dataclasses_they_replace(self):
        rule = inventory.CssRule(3, ".a", [], body_start=5)
        self.assertEqual(repr(rule), "CssRule(start=3, selector='.a', declarations=[], closed=False, "
                                     "body_start=5, end=None)")
        self.assertEqual(rule, inventory.CssRule(3, ".a", [], False, 5))
        self.assertNotEqual(rule, inventory.CssRule(3, ".b", []))
        self.assertNotEqual(rule, (3, ".a", [], False, 5, None))
        with self.assertRaises(TypeError):
            hash(rule)
        tag = inventory.MarkupTag("img", {}, False, 0, 5, True, False, {})
        self.assertIsNone(tag.body)
        self.assertEqual(repr(tag), "MarkupTag(name='img', attrs={}, spread=False, start=0, end=5, "
                                    "self_closing=True, closing=False, attribute_spans={}, body=None)")


if __name__ == "__main__":
    unittest.main()
