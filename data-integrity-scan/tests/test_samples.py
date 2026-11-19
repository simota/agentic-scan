"""The English and Japanese findings samples describe the same record."""

import json
import re
import unittest
from pathlib import Path


EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
JAPANESE = re.compile(r"[ぁ-ゖァ-ヺ㐀-鿿]")
NUMBER = re.compile(r"[0-9]+(?:\.[0-9]+)?")
PROSE_PATHS = {
    "$.meta.project", "$.meta.scope", "$.meta.assessor", "$.meta.method",
    "$.conventions[].idiom",
    "$.findings[].title", "$.findings[].hazard", "$.findings[].scenario",
    "$.findings[].blast_radius", "$.findings[].trace", "$.findings[].impact",
    "$.findings[].exposure", "$.findings[].enforcement.gaps",
    "$.findings[].rollout_reason", "$.findings[].invariants[]", "$.findings[].steps[]",
    "$.findings[].fix", "$.findings[].validation.evidence",
    "$.plan[].title", "$.plan[].prerequisite", "$.plan[].pr_title",
    "$.perspectives[].note",
    "$.checked_ok[]", "$.decisions[]", "$.limitations[]", "$.next_steps[]",
}


def load(suffix):
    return json.loads((EXAMPLES / f"findings.sample{suffix}.json").read_text(encoding="utf-8"))


class SampleParityTests(unittest.TestCase):
    def test_each_sample_names_its_language(self):
        self.assertEqual(load("")["meta"]["lang"], "en")
        self.assertEqual(load(".ja")["meta"]["lang"], "ja")

    def test_samples_have_the_same_structure_and_translated_prose(self):
        translations = {}

        def compare(en, ja, path="$"):
            with self.subTest(path=path):
                self.assertIs(type(en), type(ja))
                if isinstance(en, dict):
                    self.assertEqual(list(en), list(ja))
                    for key in en:
                        compare(en[key], ja[key], f"{path}.{key}")
                elif isinstance(en, list):
                    self.assertEqual(len(en), len(ja))
                    for index, (original, translated) in enumerate(zip(en, ja)):
                        compare(original, translated, f"{path}[{index}]")
                elif path != "$.meta.lang":
                    field = re.sub(r"\[\d+\]", "[]", path)
                    source_with_prose = field == "$.conventions[].source" and " " in en
                    if field in PROSE_PATHS or source_with_prose:
                        self.assertIsInstance(ja, str)
                        self.assertNotRegex(en, JAPANESE)
                        self.assertRegex(ja, JAPANESE)
                        self.assertCountEqual(NUMBER.findall(en), NUMBER.findall(ja))
                        self.assertEqual(ja, translations.setdefault(en, ja))
                    else:
                        self.assertEqual(en, ja)

        compare(load(""), load(".ja"))
