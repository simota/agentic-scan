"""Every script and template the documents cite exists; the description fits listings."""
from pathlib import Path
import re
import unittest

REPO = Path(__file__).resolve().parents[1]
SKILL = REPO / "skills" / "privacy-scan"
DOCS = [REPO / "README.md", *SKILL.glob("*.md"), *SKILL.glob("reference/*.md"),
        *SKILL.glob("templates/*.md")]
CITATION = re.compile(r"(?:skills/privacy-scan/)?((?:scripts|templates)/[A-Za-z0-9._{},<>-]+)")


def expand(cited):
    """`issue.{ja,en}.md` and `issue.<lang>.md` name one file per language."""
    cited = cited.rstrip(".")
    if "{ja,en}" in cited or "<lang>" in cited:
        return [cited.replace("{ja,en}", lang).replace("<lang>", lang) for lang in ("ja", "en")]
    return [cited]


class CitationTests(unittest.TestCase):
    def test_cited_scripts_and_templates_exist(self):
        cited = set()
        for doc in DOCS:
            for match in CITATION.finditer(doc.read_text(encoding="utf-8")):
                for path in expand(match.group(1)):
                    cited.add(path)
                    self.assertTrue((SKILL / path).is_file(), f"{doc.name} cites {path}")
        # Guard the pattern itself: it must see the files the docs rely on.
        self.assertTrue({"scripts/findings.py", "scripts/render.py",
                         "templates/issue.ja.md", "templates/report.en.md"} <= cited)

    def test_expansion_covers_both_languages(self):
        self.assertEqual(expand("templates/issue.{ja,en}.md"),
                         ["templates/issue.ja.md", "templates/issue.en.md"])
        self.assertEqual(expand("templates/report.<lang>.md."),
                         ["templates/report.ja.md", "templates/report.en.md"])


class TemplateAndStepTests(unittest.TestCase):
    def test_language_pairs_use_the_same_placeholders(self):
        for name in ("issue", "report"):
            with self.subTest(template=name):
                found = [sorted(re.findall(r"{{[^}]*}}", (SKILL / "templates" / f"{name}.{lang}.md")
                                           .read_text(encoding="utf-8")))
                         for lang in ("ja", "en")]
                self.assertEqual(found[0], found[1])

    def test_hunt_step_ids_are_unique_within_the_hunt_tables(self):
        text = (SKILL / "reference" / "perspectives.md").read_text(encoding="utf-8")
        hunts = text.split("## Hunt steps per perspective", 1)[1].split("## Sound constructs", 1)[0]
        steps = re.findall(r"^\| ([A-Z]{2}\d+) \|", hunts, re.MULTILINE)
        self.assertEqual(len(steps), len(set(steps)))
        for prefix in ("MN", "TP", "EX"):
            numbers = [int(s[2:]) for s in steps if s.startswith(prefix)]
            self.assertEqual(numbers, list(range(1, len(numbers) + 1)), prefix)


class FrontmatterTests(unittest.TestCase):
    def test_description_is_one_short_line(self):
        text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("---\n"))
        block = text.split("\n---\n", 1)[0].splitlines()
        index = next(i for i, line in enumerate(block) if line.startswith("description:"))
        value = block[index].split(":", 1)[1].strip()
        # Folded or continued scalars would hide their length from `make check`.
        self.assertNotIn(value[:1], (">", "|"))
        self.assertFalse(block[index + 1:index + 2] and block[index + 1][:1] in (" ", "\t"))
        self.assertLessEqual(len(value.strip('"')), 400)


if __name__ == "__main__":
    unittest.main()


class TemplateCountTests(unittest.TestCase):
    def test_every_count_placeholder_comes_from_findings_counts(self):
        import json
        from test_privacy_scan import findings
        sample = json.loads((REPO / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
        produced = set(findings.counts(sample))
        for lang in ("ja", "en"):
            text = (SKILL / "templates" / f"report.{lang}.md").read_text(encoding="utf-8")
            used = set(re.findall(r"{{(n_[a-z_]+)}}", text))
            with self.subTest(lang=lang):
                self.assertTrue(used)
                self.assertLessEqual(used, produced)

    def test_counts_exclude_excluded_findings_from_severities(self):
        from test_privacy_scan import complete_doc, findings
        doc = complete_doc()
        doc["findings"][1]["validation"] = {"verdict": "FalsePositive", "method": "static",
                                            "evidence": "scrubber at app.py:30"}
        doc["findings"][0]["validation"]["verdict"] = "Likely"
        result = findings.counts(doc)
        self.assertEqual((result["n_high"], result["n_high_valid"], result["n_low"],
                          result["n_excluded"], result["n_likely"]), (1, 0, 0, 1, 1))
