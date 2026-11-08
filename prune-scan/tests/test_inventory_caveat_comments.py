"""caveat_comments: workaround tags and caveat phrases in prose line comments (CM1, CM2)."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import inventory  # noqa: E402
from test_deep_review_fixes import scan  # noqa: E402


class CaveatCommentTests(unittest.TestCase):
    def test_tags_and_phrases_in_each_comment_syntax(self):
        result = scan({
            "a.py": "x = 1  # not a line comment: HACK\n# Workaround for the old proxy.\ny = 2\n",
            "b.ts": "// HACK: callers must Number() it.\nlet z = 0;\n",
            "c.sql": "-- keep in sync with server/models.py\nSELECT 1;\n",
            "d.sh": "#!/bin/sh\n# Do not run twice.\n",
        })
        self.assertEqual([(row["word"], row["location"]) for row in result["caveat_comments"]],
                         [("workaround", "a.py:2"), ("HACK", "b.ts:1"), ("keep in sync", "c.sql:1"),
                          ("do not", "d.sh:2")])
        self.assertEqual(result["caveat_comments"][1]["text"], "// HACK: callers must Number() it.")

    def test_prose_without_a_caveat_and_lower_case_tags_are_not_candidates(self):
        result = scan({
            "a.py": "# Parse the price in cents.\n# a note on rounding: half up.\nx = 1\n",
            "b.js": "// todo list rendering\nlet x;\n",
        })
        self.assertEqual(result["caveat_comments"], [])

    def test_commented_out_code_is_dc3_not_a_caveat(self):
        result = scan({"a.py": "x = 1\n# y = f(x)  # TODO\n# if y:\n#     return (y)\n# z = [y]\n"})
        self.assertEqual([row["location"] for row in result["commented_code"]], ["a.py:2-5"])
        self.assertEqual(result["caveat_comments"], [])

    def test_larder_fixture(self):
        result = inventory.inventory(ROOT / "examples" / "larder", today="2026-11-05")
        self.assertEqual([(row["word"], row["location"]) for row in result["caveat_comments"]], [
            ("kept for", "server/app.py:47"), ("kept for", "server/utils.py:9"), ("HACK", "web/src/api.ts:5"),
            ("kept until", "web/src/components/OldButton.tsx:1")])


if __name__ == "__main__":
    unittest.main()
