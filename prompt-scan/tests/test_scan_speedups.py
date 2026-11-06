"""The shortcuts inventory.py takes to scan faster find exactly what a search of every line finds."""
import os
from pathlib import Path
import re
import unittest

try:  # Python 3.11+
    import re._parser as sre_parse
except ImportError:  # Python 3.9, 3.10
    import sre_parse

from helpers import excerpt, inventory
from test_inventory import make_repo

ZERO_WIDTH = {sre_parse.AT, sre_parse.ASSERT, sre_parse.ASSERT_NOT}


def literals(items, cap=64):
    """The finite set of strings a parsed sequence matches, ignoring zero-width tests; None when unbounded."""
    found = {""}
    for op, av in items:
        if op is sre_parse.LITERAL:
            options = {chr(av)}
        elif op is sre_parse.IN and all(o is sre_parse.LITERAL for o, _ in av):
            options = {chr(c) for _, c in av}
        elif op is sre_parse.SUBPATTERN:
            options = literals(av[-1], cap)
        elif op is sre_parse.BRANCH:
            branches = [literals(b, cap) for b in av[1]]
            options = None if None in branches else set().union(*branches)
        elif op in ZERO_WIDTH:
            continue
        else:
            return None
        if options is None or len(found) * len(options) > cap:
            return None
        found = {a + b for a in found for b in options}
    return found


def covered(items, needles):
    """Whether every match of a parsed sequence contains one of needles."""
    run = {""}
    for op, av in items:
        if op in ZERO_WIDTH:
            continue
        options = literals([(op, av)])
        if options is not None and len(run) * len(options) <= 64:
            run = {a + b for a in run for b in options}
            continue
        if run != {""} and all(any(n in s for n in needles) for s in run):
            return True
        run = {""}
        if op is sre_parse.SUBPATTERN and covered(av[-1], needles):
            return True
        if op is sre_parse.BRANCH and all(covered(b, needles) for b in av[1]):
            return True
        if op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT) and av[0] >= 1 and covered(av[2], needles):
            return True
    return run != {""} and all(any(n in s for n in needles) for s in run)


def per_line(pattern, text):
    """What scan() and lint_file() searched before: every line on its own."""
    return [i for i, line in enumerate(excerpt.source_lines(text)) if pattern.search(line)]


TRICKY = [
    "",
    "x",
    "client.messages.create(\n",
    "client.messages.create\n(model='claude-x')",  # The call runs over a line break: no line matches.
    "a\r\nclient.messages.create(\r\nb\r\n",
    "a\rclient.chat.completions.create(\r\n",  # A lone \r stays inside the line.
    "x = 'gpt-4o'\x0cy = generateText( z\n",  # Form feed and U+2028 do not end a line.
    "SYSTEM_PROMPT\n= 1\nsystem_prompt = 2\n",
    '{"role":\n"system"}\n{"role": "system"}',
    "\n\n'claude-opus-5-5' 'claude-x' \"gemini-pro\"\n\n`o3`",
    "no newline at the end: streamText(",
    "HumanMessage SystemMessagePromptTemplate\nnotHumanMessage\n",
    "key sk-ant-" + "a" * 30 + "\nghp_" + "b" * 36 + "\nAKIA" + "C" * 16 + "\n",
    "-----BEGIN RSA PRIVATE KEY-----\r\nAKIA" + "C" * 16 + "x\n",
    "xoxb-1234567890 and rk_live_" + "z" * 16 + "\n",
]


class NeedleTest(unittest.TestCase):
    def test_needles_cover_every_call_pattern(self):
        for api, pattern, needles in inventory.CALL_PATTERNS:
            with self.subTest(api=api):
                self.assertFalse(pattern.flags & re.IGNORECASE)
                self.assertTrue(covered(sre_parse.parse(pattern.pattern), needles))

    def test_needles_cover_the_secret_pattern(self):
        self.assertFalse(excerpt.SECRET_RE.flags & re.IGNORECASE)
        self.assertTrue(covered(sre_parse.parse(excerpt.SECRET_RE.pattern), excerpt.SECRET_NEEDLES))

    def test_the_coverage_check_rejects_a_missing_needle(self):
        pattern = sre_parse.parse(inventory.CALL_PATTERNS[4][1].pattern)  # ai-sdk
        self.assertFalse(covered(pattern, ("generateText", "streamText", "generateObject")))
        self.assertFalse(covered(sre_parse.parse(excerpt.SECRET_RE.pattern), excerpt.SECRET_NEEDLES[1:]))

    def test_template_lines_without_a_brace_or_backtick_are_skipped_safely(self):
        # template_uses() skips a line without "{", and without_code_spans() one without "`".
        for pattern in inventory.VARIABLE_RES:
            self.assertTrue(covered(sre_parse.parse(pattern.pattern), ("{",)), pattern.pattern)
        self.assertTrue(covered(sre_parse.parse(inventory.INLINE_CODE.pattern), ("`",)))
        for line in ["plain", "a `b` c", "``x``", "`{{ v }}` {{ w }}", "{x} `y", "``` fence"]:
            self.assertEqual(inventory.without_code_spans(line), inventory.INLINE_CODE.sub("", line))

    def test_has_secret_needle(self):
        self.assertFalse(excerpt.has_secret_needle("plain prompt text, high and right"))
        self.assertTrue(excerpt.has_secret_needle("token: ghp_" + "a" * 36))


class MatchLinesTest(unittest.TestCase):
    def test_finds_every_line_a_per_line_search_finds(self):
        patterns = [p for _, p, _ in inventory.CALL_PATTERNS] + [inventory.MODEL_RE, excerpt.SECRET_RE]
        for text in TRICKY:
            lines = excerpt.source_lines(text)
            for pattern in patterns:
                with self.subTest(text=text, pattern=pattern.pattern[:30]):
                    found = inventory.match_lines(pattern, text)
                    self.assertEqual(found, sorted(set(found)))
                    self.assertTrue(set(per_line(pattern, text)) <= set(found))
                    self.assertTrue(all(i <= len(lines) for i in found))

    def test_scan_matches_a_per_line_search(self):
        root = make_repo({
            "app.py": "x = 1\r\nc.messages.create(\r\n  model='claude-opus-5-5')\r\nc.messages.create\n(\n"
                      "SYSTEM_PROMPT = 'gpt-4o'\x0cgenerateText( \n",
            "conf.json": '{"model": "gemini-pro",\n "role": "system"}',
        })
        result = inventory.scan(root)
        self.assertEqual([(c["line"], c["api"]) for c in result["call_sites"]],
                         [(2, "anthropic.messages"), (6, "ai-sdk"), (6, "prompt-variable")])
        self.assertEqual(result["models"], [
            {"id": "claude-opus-5-5", "locations": ["app.py:3"]},
            {"id": "gemini-pro", "locations": ["conf.json:1"]},
            {"id": "gpt-4o", "locations": ["app.py:6"]},
        ])

    def test_secret_lines_with_and_without_needles(self):
        text = "a\nkey sk-proj-" + "a" * 24 + "\nb\nAKIA" + "C" * 16 + "\n"
        hits = inventory.lint_file("prompts/a.md", text, 1)
        self.assertEqual([(h["rule"], h["location"]) for h in hits], [("secret-literal", "prompts/a.md:2")])
        self.assertEqual(inventory.lint_file("prompts/a.md", "nothing secret\n", 1), [])


class WalkTest(unittest.TestCase):
    def test_paths_and_skips_are_what_a_stat_per_check_gave(self):
        root = make_repo({"a/b/prompts/p.md": "hi\n", "c/app.py": "x\n", "a/build/z.md": "y\n",
                          "node_modules/x/i.js": "z\n", "a/b/key.pem": "k\n", ".env": "e\n"})
        os.symlink("../c/app.py", root / "a/link.py")
        os.symlink("/nonexistent", root / "a/dangling.prompt")
        os.symlink("../c", root / "a/dirlink")
        os.symlink("../a/b/prompts/p.md", root / "c/x.prompt")
        if hasattr(os, "mkfifo"):
            os.mkfifo(root / "a/fifo.prompt")

        def reference():
            files, skipped, unread = [], [], []
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                skipped += [(Path(dirpath) / d).relative_to(root).as_posix() for d in sorted(dirnames)
                            if d in inventory.SKIP_DIRS - inventory.VCS_DIRS
                            or d not in inventory.SKIP_DIRS and (Path(dirpath) / d).is_symlink()]
                dirnames[:] = sorted(d for d in dirnames if d not in inventory.SKIP_DIRS)
                for name in sorted(filenames):
                    path = Path(dirpath) / name
                    rel = path.relative_to(root).as_posix()
                    if path.is_symlink() or not path.is_file() or excerpt.sensitive(name):
                        if path.is_symlink() and not excerpt.sensitive(name) and inventory.prompt_kind(rel):
                            unread.append({"path": rel, "reason": "symlink"})
                        continue
                    files.append((path, rel))
            return files, skipped, unread

        skipped, unread = [], []
        files = list(inventory.walk(root, skipped, unread))
        self.assertEqual((files, skipped, unread), reference())
        self.assertEqual([rel for _, rel in files], ["a/b/prompts/p.md", "c/app.py"])


class EstimateTokensTest(unittest.TestCase):
    def test_counts_as_one_character_at_a_time_did(self):
        def reference(text):
            ascii_chars = sum(1 for c in text if ord(c) < 128)
            return ascii_chars // 4 + (len(text) - ascii_chars)
        for text in ["", "abc", "日本語", "\udcff�", "x\U0001F600y", "\x7f\x80",
                     "é" * 1023 + "a" * 2050, ("prompt 説明 " * 400)]:
            with self.subTest(text=text[:10]):
                self.assertEqual(inventory.estimate_tokens(text), reference(text))


if __name__ == "__main__":
    unittest.main()
