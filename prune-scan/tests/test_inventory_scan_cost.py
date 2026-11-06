"""Scan cost that grows with the input's shape, not its size: tsconfig comments.

Each fast path is checked against the slower reading it replaces, so the speed-up changes no result.
"""

import random
import re
import sys
import time
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
