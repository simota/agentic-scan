"""Scan cost that grows with the input's shape, not its size: tsconfig comments and many dependencies.

Each fast path is checked against the slower reading it replaces, so the speed-up changes no result.
"""

import random
import re
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "prune-scan" / "scripts"))

import inventory  # noqa: E402
from test_deep_review_fixes import scan  # noqa: E402

# The single-regex reading jsonc_cleaned replaced; exponential on tsc --init's template.
BACKTRACKING_JSONC = re.compile(r'"(?:\\.|[^"\\\n])*"|(//[^\n]*|/\*[\s\S]*?(?:\*/|\Z)|'
                                r',(?=\s*(?:(?://[^\n]*|/\*(?:[^*]|\*(?!/))*\*/)\s*)*[}\]]))')


def backtracking_cleaned(text):
    return BACKTRACKING_JSONC.sub(lambda m: "" if m.group(1) else m.group(0), text)


# The shape tsc --init writes: every option a // line with a /* */ note after it.
TSC_INIT = ('{\n  "compilerOptions": {\n    /* Projects */\n    "target": "es2016",'
            '                                  /* Set the JavaScript language version. */\n'
            + "".join(f'    // "option{i}": true,                         /* Describe option {i}. */\n'
                      for i in range(200))
            + '    "baseUrl": "./src",                      /* Specify the base directory. */\n'
            + '    "paths": {"@app/*": ["app/*"]}\n  }\n}\n')


class JsoncCommentTests(unittest.TestCase):
    def test_tsc_init_template_is_read_in_linear_time(self):
        start = time.perf_counter()
        data = inventory.jsonc_object(TSC_INIT)
        self.assertLess(time.perf_counter() - start, 1.0)
        self.assertEqual(data["compilerOptions"]["baseUrl"], "./src")
        self.assertEqual(data["compilerOptions"]["paths"], {"@app/*": ["app/*"]})

    def test_tsc_init_template_configures_aliases_in_an_inventory(self):
        result = scan({
            "tsconfig.json": TSC_INIT,
            "src/main.ts": 'import { run } from "@app/run";\nrun();\n',
            "src/app/run.ts": "export function run() {}\n",
        })
        self.assertNotIn("src/app/run.ts", [row["path"] for row in result["orphan_files"]])

    def test_cleaning_matches_the_backtracking_reading(self):
        cases = ["{\"a\": 1,}", "[1, 2, ]", "{\"a\": 1, // note\n}", "{\"a\": 1, /* x */ /* y */ }",
                 "[1, // has ] inside\n 2]", "[1, // a /* b */ c\n]", "[1, /* open", "[1, /*/ */]",
                 "{\"s\": \",}\", \"t\": 2,\n\n}", "[1,  ]", "[1, // x /* spans\n */ ]", ","]
        alphabet = ["/", "*", ",", "}", "]", "{", "[", "\n", " ", "\t", "a", '"', "\\", "//", "/*", "*/", " "]
        rnd = random.Random(11)
        cases += ["".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 12))) for _ in range(20000)]
        for text in cases:
            self.assertEqual(inventory.jsonc_cleaned(text), backtracking_cleaned(text), repr(text))


class DependencyIndexTests(unittest.TestCase):
    def files(self):
        rnd = random.Random(5)
        alphabet = ["a", "b", "x", "-", ".", "_", "1", "é", "@", "~"]
        names = sorted({"".join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 6))).strip("@") or "a"
                        for _ in range(150)})
        words = [rnd.choice(["", "@", "/", "x", ".", "-"]) + rnd.choice(names) + rnd.choice(["", "-", ".", "x", "/"])
                 for _ in range(400)]
        return {
            "package.json": '{"scripts": {"t": "%s"}, "devDependencies": {%s}}' % (
                " ".join(words[:40]), ", ".join(f'"{n}": "1"' for n in names)),
            "requirements.txt": "".join(n + "\n" for n in names if n[0].isalnum()),
            "Makefile": "all:\n\t" + " ".join(words) + "\n",
        }

    def test_indexed_mentions_equal_per_name_mentions(self):
        files = self.files()
        indexed = scan(files)["unimported_dependencies"]
        with mock.patch.object(inventory, "INDEX_MIN_NAMES", 10 ** 9):
            direct = scan(files)["unimported_dependencies"]
        self.assertEqual(indexed, direct)
        self.assertTrue(any(row["mentions"] for row in direct))
        # Both ecosystems are listed: the names are taken without consuming the parsed manifest.
        self.assertEqual({row["manifest"] for row in direct}, {"package.json", "requirements.txt"})

    def test_name_first_patterns_count_what_lookbehind_first_patterns_count(self):
        rnd = random.Random(9)
        alphabet = ["a", "b", "-", ".", "_", "@", "/", "é", " ", "\n", "x1"]
        for _ in range(3000):
            name = "".join(rnd.choice(alphabet[:8]) for _ in range(rnd.randint(0, 4)))
            text = "".join(rnd.choice(alphabet + [name] * 4) for _ in range(rnd.randint(0, 30)))
            literal = re.escape(name)
            for before in (r"[\w@/-]", r"[\w-]"):
                self.assertEqual(
                    len(re.findall(r"%s(?<!%s%s)(?![\w-])" % (literal, before, literal), text)),
                    len(re.findall(r"(?<!%s)%s(?![\w-])" % (before, literal), text)), (name, text, before))

    def test_word_runs_present_keeps_only_runs_of_the_names(self):
        names = [f"pkg-{i}" for i in range(inventory.INDEX_MIN_NAMES)]
        self.assertEqual(inventory.word_runs_present("run pkg-7 and other words", names), {"pkg", "7"})
        self.assertIsNone(inventory.word_runs_present("pkg-7", names[:3]))
        self.assertIsNone(inventory.word_runs_present("", names))


if __name__ == "__main__":
    unittest.main()
