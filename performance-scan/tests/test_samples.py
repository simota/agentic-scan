"""The English and Japanese samples are the same record in two languages."""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
JAPANESE = re.compile(r"[\u3040-\u30ff\u3400-\u9fff\uff01-\uff60]")


def load(suffix):
    return json.loads((EXAMPLES / f"findings.sample{suffix}.json").read_text(encoding="utf-8"))


def differences(en, ja, path="$"):
    """Yield every place where the two records differ in anything but translated prose."""
    if isinstance(ja, dict):
        if not isinstance(en, dict) or list(en) != list(ja):
            yield f"{path}: keys differ"
            return
        for key in ja:
            yield from differences(en[key], ja[key], f"{path}.{key}")
    elif isinstance(ja, list):
        if not isinstance(en, list) or len(en) != len(ja):
            yield f"{path}: length differs"
            return
        for i, (a, b) in enumerate(zip(en, ja)):
            yield from differences(a, b, f"{path}[{i}]")
    elif isinstance(ja, str) and JAPANESE.search(ja):
        if not isinstance(en, str) or JAPANESE.search(en):
            yield f"{path}: not translated"
    elif en != ja and path != "$.meta.lang":
        yield f"{path}: {en!r} != {ja!r}"


class SampleParityTests(unittest.TestCase):
    def test_japanese_sample_mirrors_english_sample(self):
        diffs = list(differences(load(""), load(".ja")))
        self.assertEqual(diffs, [], "\n".join(diffs[:20]))

    def test_each_sample_names_its_language(self):
        self.assertEqual(load("")["meta"]["lang"], "en")
        self.assertEqual(load(".ja")["meta"]["lang"], "ja")

    def test_japanese_sample_translates_prose(self):
        ja = load(".ja")
        for key in ("project", "scope", "assessor", "method"):
            self.assertRegex(ja["meta"][key], JAPANESE, f"meta.{key}")
        for i, budget in enumerate(ja["budgets"]):
            for key in ("statement", "source", "reason"):
                if key in budget:
                    self.assertRegex(budget[key], JAPANESE, f"budgets[{i}].{key}")
        for i, finding in enumerate(ja["findings"]):
            for key in ("title", "workload", "scale_driver", "cost_model", "request",
                        "contrast", "impact", "fix", "regression_test"):
                if key in finding:
                    self.assertRegex(finding[key], JAPANESE, f"findings[{i}].{key}")
            if "evidence" in finding["validation"]:
                self.assertRegex(finding["validation"]["evidence"], JAPANESE,
                                 f"findings[{i}].validation.evidence")
        for i, perspective in enumerate(ja["perspectives"]):
            self.assertRegex(perspective["note"], JAPANESE, f"perspectives[{i}].note")
        for key in ("checked_ok", "decisions", "limitations", "next_steps"):
            for i, line in enumerate(ja[key]):
                self.assertRegex(line, JAPANESE, f"{key}[{i}]")


if __name__ == "__main__":
    unittest.main()
