"""Behaviour that inventory.py's shortcuts must keep: each one skips work, never a result."""

import os
import random
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
    from re import _compiler as sre_compile, _constants as sre_constants, _parser as sre_parse
except ImportError:  # pragma: no cover - Python 3.10
    import sre_compile
    import sre_constants
    import sre_parse

# The patterns that words() rewrote, as they were written before: (?<!…) or \b, then the words.
WORD_LED_BEFORE = {
    "CSS_SPACING": (
        '(?<![\\w-])(?:margin|padding|gap|row-gap|column-gap|grid-gap|grid-row-gap|grid-column-gap'
        ')(?:-(?:top|right|bottom|left|inline|block)(?:-start|-end)?)?\\s*:\\s*([^;{}\\n]+(?:\\n(?=(?'
        ':[^;{}:\\n]|#\\{[^{}\\n]*\\})*(?:[\\n;}]|\\Z))(?:[^;{}:\\n]|#\\{[^{}\\n]*\\})*)*)'
    ),
    "CSS_SPACING_LINE": (
        '(?<![\\w-])(?:margin|padding|gap|row-gap|column-gap|grid-gap|grid-row-gap|grid-column-gap'
        ')(?:-(?:top|right|bottom|left|inline|block)(?:-start|-end)?)?[^\\S\\n]*:[^\\S\\n]*([^;{}\\n]+'
        ')'
    ),
    "JS_SPACING": (
        '(?<![\\w$-])(?:margin|padding|gap|rowGap|columnGap|row-gap|column-gap)(?:Top|Right|Bottom'
        '|Left|Inline|Block|X|Y|-top|-right|-bottom|-left|-inline|-block)?(?:Start|End|-start|-en'
        'd)?[\\"\']?\\s*:\\s*(?:(-?\\d+(?:\\.\\d+)?)\\s*(?=[,}\\n])|[\\"\'`]([^\\"\'`\\n]{1,60})[\\"\'`])'
    ),
    "CSS_FONT_SIZE": (
        '(?<![\\w-])font-size\\s*:\\s*([^;{}\\n]+(?:\\n(?=(?:[^;{}:\\n]|#\\{[^{}\\n]*\\})*(?:[\\n;}]|\\Z))(?'
        ':[^;{}:\\n]|#\\{[^{}\\n]*\\})*)*)'
    ),
    "CSS_FONT_SIZE_LINE": '(?<![\\w-])font-size[^\\S\\n]*:[^\\S\\n]*([^;{}\\n]+)',
    "JS_FONT_SIZE": (
        '(?<![\\w$-])(?:fontSize|font-size)[\\"\']?\\s*:\\s*(?:(\\d+(?:\\.\\d+)?)\\s*(?=[,}\\n])|[\\"\'`]([^\\'
        '"\'`\\n]{1,40})[\\"\'`])'
    ),
    "CSS_Z": '(?<![\\w-])z-index\\s*:\\s*(-?\\d+)',
    "JS_Z": '(?<![\\w$-])(?:zIndex|z-index)[\\"\']?\\s*:\\s*[\\"\']?(-?\\d+)',
    "CSS_WIDTH": (
        '(?<![\\w-])(width|min-width)\\s*:\\s*(\\d+(?:\\.\\d+)?)((?i:px|rem|em))\\b(?!\\s*(?:(?i:!importa'
        'nt)\\s*)?\\))'
    ),
    "JS_WIDTH": (
        '(?<![\\w$-])(width|minWidth|min-width)[\\"\']?\\s*:\\s*(?:(\\d+(?:\\.\\d+)?)\\s*(?=[,}\\n])|[\\"\']('
        '\\d+(?:\\.\\d+)?)((?i:px|rem|em))[\\"\'])'
    ),
    "JS_OUTLINE_NONE": (
        '\\boutline\\s*:\\s*(?:[\\"\'](?:none|0(?:\\.0+)?(?:px|em|rem)?)(?![\\w.%-])[\\"\']|0(?=\\s*[,}\\n])'
        ')'
    ),
    "CSS_MOTION": '(?<![\\w-])(transition|animation)(?:-duration|-name)?\\s*:\\s*(?!\\s*none\\b)([^;{}\\n]+)',
    "JS_MOTION": '\\b(transition|animation)\\s*:\\s*[\\"\'`](?!none)',
    "TRUNCATION": (
        'text-overflow\\s*:\\s*ellipsis|line-clamp\\s*:|white-space\\s*:\\s*nowrap|textOverflow\\s*:\\s*'
        '[\\"\']ellipsis|WebkitLineClamp|whiteSpace\\s*:\\s*[\\"\']nowrap|class(?:Name)?\\s*=\\s*(?:\\{[^}'
        ']{0,200}?)?[\\"\'`][^\\"\'`]*\\b(?:truncate|line-clamp-\\d)\\b|(?<![\\w-])(?:v-bind)?:class\\s*=\\'
        's*\\"[^\\"]{0,200}?\\b(?:truncate|line-clamp-\\d)\\b|\\bclass:(?:truncate|line-clamp-\\d)\\b'
    ),
    "CUSTOM_PROPERTY": '(?<![\\w-])--[\\w-]+\\s*:',
    "FETCH": (
        '\\bfetch\\(|\\baxios[.(]|\\buse(?:Query|SWR|InfiniteQuery|Fetch|LoaderData)\\b|\\$fetch\\(|\\bcr'
        'eateResource\\b|\\buseAsyncData\\b'
    ),
    "ROUTE": (
        '<Route\\b(?:=>|<[^<>]*>|[^<>]){0,2000}?\\bpath\\s*=\\s*(?:\\{\\s*(?=[\\"\'`](?:(?!\\$\\{)[^\\"\'`])+'
        '[\\"\'`]\\s*\\}))?[\\"\'`]((?:(?!\\$\\{)[^\\"\'`])+)[\\"\'`]|\\bpath\\s*:\\s*[\\"\'](/[^\\"\']*)[\\"\']'
    ),
    "NEXT_VIEWPORT": '\\bexport\\s+const\\s+viewport\\b[^=\\n]*=\\s*\\{((?:[^{}]|\\{[^{}]{0,200}\\}){0,1000})\\}',
}

# Words that open matches of the patterns above, glued to every kind of neighbour.
WORD_PIECES = ["margin", "padding", "gap", "rowGap", "row-gap", "grid-column-gap", "-top", "Top", "Start", "font-size",
               "fontSize", "z-index", "zIndex", "width", "min-width", "minWidth", "outline", "transition", "animation",
               "--", "--brand", "fetch", "$fetch", "axios", "use", "Query", "createResource", "useAsyncData", "<Route",
               "path", "export", "const", "viewport", "text-overflow", "ellipsis", "line-clamp", "white-space",
               "nowrap", "whiteSpace", "class", "className", "v-bind", ":class", "class:", "truncate", "line-clamp-2",
               "-duration", "none", "0", "12", "400px", "1.5rem", ":", " ", "\n", "=", '"', "'", "`", "{", "}", "(",
               ")", ",", ";", "[", "$", "-", "_", "a", "\u00e9", "\u2160", "/x", "!important", "\t"]


def word_texts(count, seed=0):
    """Deterministic strings of WORD_PIECES, so a word starts a text, ends one and follows each neighbour."""
    rng = random.Random(seed)
    return ["".join(rng.choice(WORD_PIECES) for _ in range(rng.randint(1, 14))) for _ in range(count)]


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
        self.assertGreaterEqual(len(patterns), 7)  # The wrapper is still recognised.
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


def fast_scan(compiled):
    """Whether the engine can skip to a literal prefix or first-character set instead of trying every position."""
    parsed = sre_parse.parse(compiled.pattern, compiled.flags)
    prefix, _, _ = sre_compile._get_literal_prefix(parsed, compiled.flags)
    return bool(prefix or sre_compile._get_charset_prefix(parsed, compiled.flags))


class WordLedPatternTests(unittest.TestCase):
    def test_words_match_what_a_leading_boundary_matched(self):
        texts = word_texts(4000)
        for boundary, alternatives in ((r"[\w-]", ("margin", "row-gap", "--")), (r"[\w$-]", ("zIndex", "z-index")),
                                       (r"\w", ("fetch", "class:", "use"))):
            words = inventory.words(boundary, *alternatives)
            before = [f"(?<!{boundary})(?:{'|'.join(map(re.escape, alternatives))})"]
            if boundary == r"\w":  # Before a word character, \b is the same test.
                before.append(rf"\b(?:{'|'.join(map(re.escape, alternatives))})")
            for reference in before:
                with self.subTest(reference=reference):
                    plain, rewritten = re.compile(reference + "(.?)"), re.compile(words + "(.?)")
                    for text in texts:
                        self.assertEqual([(m.span(), m.groups()) for m in rewritten.finditer(text)],
                                         [(m.span(), m.groups()) for m in plain.finditer(text)], text)
                        for pos in (1, len(text) // 2):  # A search from pos still reads the text before it.
                            got, want = rewritten.search(text, pos), plain.search(text, pos)
                            self.assertEqual(got and got.span(), want and want.span(), text)

    def test_rewritten_patterns_match_what_they_matched_before(self):
        texts = [path.read_text(encoding="utf-8") for path in sorted((ROOT / "examples" / "tasklane").rglob("*"))
                 if path.is_file()] + word_texts(3000, seed=1)
        for name, before in WORD_LED_BEFORE.items():
            compiled, plain = getattr(inventory, name), re.compile(before)
            with self.subTest(pattern=name):
                self.assertEqual(compiled.flags, plain.flags)
                for text in texts:
                    self.assertEqual([(m.span(), m.groups()) for m in compiled.finditer(text)],
                                     [(m.span(), m.groups()) for m in plain.finditer(text)], text[:200])

    def test_rewritten_patterns_let_the_engine_skip_ahead(self):
        for name in WORD_LED_BEFORE:
            with self.subTest(pattern=name):
                self.assertTrue(fast_scan(getattr(inventory, name)))
                self.assertFalse(fast_scan(re.compile(WORD_LED_BEFORE[name])))  # The reason for words().

    def test_files_without_a_quoted_slash_hold_no_link(self):
        # Every LINK match holds a LINK_TARGET match, so a file without one can skip LINK.
        texts = [path.read_text(encoding="utf-8") for path in sorted((ROOT / "examples" / "tasklane").rglob("*"))
                 if path.is_file()] + word_texts(3000, seed=2)
        texts += ['<a href="/x">', "to={ '/y' }", ':to="\'/z\'"', '[routerLink]="[ \'/w\']"', "navigate(`/v`)",
                  'push({ pathname: "/u" })', 'href={{ path: "/t" }}', "href=x", "to: '/s'", 'to="[ /w"', 'href=" /q"']
        found = 0
        for text in texts:
            for m in inventory.LINK.finditer(text):
                found += 1
                self.assertTrue(inventory.LINK_TARGET.search(m.group(0)), m.group(0))
        self.assertGreaterEqual(found, 11)


# The JSX comment tokenizer as written before its // line form opened with literal characters.
JSX_TOKEN_BEFORE = r"""\{/\*|^[ \t]*//[^\n]*|/\*|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`"""
TOKEN_PIECES = ["//", "/*", "*/", "{/*", " ", "  ", "\t", "\n", "\r", "\u2028", "x", '"', "'", "`", "\\", "a//b",
                "  //c", "\n//", "\n \t//"]


class CheaperEquivalentTests(unittest.TestCase):
    def test_comment_tokens_are_found_where_they_were_before(self):
        rng = random.Random(3)
        texts = [path.read_text(encoding="utf-8") for path in sorted((ROOT / "examples" / "tasklane").rglob("*"))
                 if path.is_file()]
        texts += ["".join(rng.choice(TOKEN_PIECES) for _ in range(rng.randint(0, 12))) for _ in range(6000)]
        for name, before in (("JSX_TOKEN", JSX_TOKEN_BEFORE), ("SCRIPT_TOKEN", JSX_TOKEN_BEFORE.removeprefix(r"\{/\*|"))):
            compiled, plain = getattr(inventory, name), re.compile(before, re.S | re.M)
            with self.subTest(pattern=name):
                self.assertEqual(compiled.flags, plain.flags)
                self.assertTrue(fast_scan(compiled))
                for text in texts:
                    # mask_markup_comments resumes its search at any offset, so compare from each one.
                    for pos in range(len(text) + 1) if len(text) < 80 else (0, 1, len(text) // 2):
                        got, want = compiled.search(text, pos), plain.search(text, pos)
                        self.assertEqual(got and got.span(), want and want.span(), (text[:80], pos))

    def test_blank_keeps_newlines_and_spaces_out_everything_else(self):
        rng = random.Random(4)
        for text in ["", "\n", "a", "\n\n", "/* x */"] + ["".join(rng.choice("ab \n\r\t\u2028\x85\u00e9\U0001d11e\0")
                                                        for _ in range(rng.randint(0, 30))) for _ in range(3000)]:
            self.assertEqual(inventory.blank(text), re.sub(r"[^\n]", " ", text), repr(text))

    def test_walked_paths_are_read_below_root_however_root_is_spelled(self):
        with tempfile.TemporaryDirectory() as parent:
            # A repository named app is not a route tree; only directories below root are read as one.
            tmp = os.path.join(parent, "app")
            (Path(tmp) / "app" / "build").mkdir(parents=True)
            (Path(tmp) / "app" / "build" / "page.tsx").write_text("export default 1\n", encoding="utf-8")
            (Path(tmp) / "build").mkdir()
            (Path(tmp) / "build" / "page.tsx").write_text("export default 1\n", encoding="utf-8")
            expected = [Path(tmp, "app", "build", "page.tsx")]
            cwd = os.getcwd()
            try:
                os.chdir(tmp)
                for spelling in (tmp, tmp + os.sep, tmp + os.sep + ".", ".", "." + os.sep):
                    with self.subTest(root=spelling):
                        found = [Path(tmp, p.relative_to(spelling)) for p in inventory.iter_files(spelling)]
                        self.assertEqual(found, expected)
            finally:
                os.chdir(cwd)
            self.assertEqual([r["route"] for r in inventory.inventory(tmp)["routes"]], ["/build"])


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
