"""The English and Japanese findings samples represent the same record."""
import json
import re
import unittest
from pathlib import Path

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
JAPANESE = re.compile(r"[ぁ-ヿ㐀-鿿]")
PROSE_PATHS = {
    "meta.project", "meta.scope", "meta.assessor", "meta.method",
    "conventions[].idiom",
    "findings[].title", "findings[].hazard", "findings[].scenario",
    "findings[].blast_radius", "findings[].trace", "findings[].impact",
    "findings[].exposure", "findings[].counterexample.input",
    "findings[].counterexample.expected", "findings[].counterexample.actual",
    "findings[].counterexample.oracle", "findings[].enforcement.gaps",
    "findings[].change_reason", "findings[].invariants[]", "findings[].steps[]",
    "findings[].fix", "findings[].validation.evidence",
    "plan[].title", "plan[].pr_title", "perspectives[].note",
    "checked_ok[]", "decisions[]", "limitations[]", "next_steps[]",
}


def load(suffix):
    return json.loads((EXAMPLES / f"findings.sample{suffix}.json").read_text(encoding="utf-8"))


def is_prose(path, value):
    return (
        path in PROSE_PATHS
        or (path == "conventions[].source" and value.startswith("majority: "))
        or (path == "plan[].prerequisite" and value != "none")
    )


class SampleParityTests(unittest.TestCase):
    def test_samples_have_matching_structure_and_translated_prose(self):
        self.assert_sample_parity(load(""), load(".ja"), {}, "")

    def assert_sample_parity(self, en, ja, translations, path):
        self.assertIs(type(ja), type(en), path)
        if isinstance(en, dict):
            self.assertEqual(list(ja), list(en), path)
            for key in en:
                child = f"{path}.{key}" if path else key
                self.assert_sample_parity(en[key], ja[key], translations, child)
        elif isinstance(en, list):
            self.assertEqual(len(ja), len(en), path)
            for index, (original, localized) in enumerate(zip(en, ja)):
                with self.subTest(path=path, index=index):
                    self.assert_sample_parity(original, localized, translations, f"{path}[]")
        elif path != "meta.lang":
            if isinstance(en, str) and is_prose(path, en):
                self.assertNotEqual(ja, en, path)
                self.assertRegex(ja, JAPANESE, path)
                self.assertEqual(ja, translations.setdefault(en, ja), path)
            else:
                self.assertEqual(ja, en, path)

    def test_each_sample_names_its_language(self):
        self.assertEqual(load("")["meta"]["lang"], "en")
        self.assertEqual(load(".ja")["meta"]["lang"], "ja")


if __name__ == "__main__":
    unittest.main()
