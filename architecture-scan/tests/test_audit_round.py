"""Defects found by a full review of the scripts, docs and Makefile."""
import copy
import shutil
import subprocess
import unittest

from test_architecture_scan import complete_doc, findings, render


class RuleReplacementTests(unittest.TestCase):
    def test_a_replaced_rule_keeps_its_place_in_the_ledger(self):
        doc = complete_doc()
        first = copy.deepcopy(doc["rules"][0])
        doc["rules"] = [dict(first, id=rid) for rid in ("R-01", "R-05", "R-06")]
        replacement = dict(first, id="R-05", statement="billing is the only writer")
        findings.merge(doc, {"remove": {"rules": ["R-05"]}, "rules": [replacement]}, "f")
        self.assertEqual([r["id"] for r in doc["rules"]], ["R-01", "R-05", "R-06"])
        self.assertEqual(doc["rules"][1]["statement"], "billing is the only writer")

    def test_another_new_rule_does_not_take_the_removed_rules_place(self):
        doc = complete_doc()
        first = copy.deepcopy(doc["rules"][0])
        doc["rules"] = [dict(first, id=rid) for rid in ("R-01", "R-05", "R-06")]
        fragment = {"remove": {"rules": ["R-05", "R-06"]},
                    "rules": [dict(first, id="R-99"), dict(first, id="R-05")]}
        findings.merge(doc, fragment, "f")
        self.assertEqual([r["id"] for r in doc["rules"]], ["R-01", "R-05", "R-99"])
        self.assertTrue(all(type(r) is dict for r in doc["rules"]))

    def test_a_rule_cannot_be_removed_twice(self):
        doc = complete_doc()
        with self.assertRaisesRegex(findings.SchemaError, "not recorded"):
            findings.merge(doc, {"remove": {"rules": ["R-01", "R-01"]}}, "f")

    def test_a_new_rule_without_a_removal_is_still_appended(self):
        doc = complete_doc()
        rule = dict(copy.deepcopy(doc["rules"][0]), id="R-99")
        findings.merge(doc, {"rules": [rule]}, "f")
        self.assertEqual(doc["rules"][-1]["id"], "R-99")


class StepNumberTests(unittest.TestCase):
    def test_a_step_with_thousands_of_digits_is_a_schema_error(self):
        doc = complete_doc()
        doc["findings"][0]["step"] = doc["findings"][0].get("step", "CP1")[:2] + "1" * 5000
        with self.assertRaisesRegex(findings.SchemaError, r"step: .* must be a hunt step ID"):
            findings.validate(doc)


class VerdictBannerTests(unittest.TestCase):
    def test_an_unlikely_finding_is_not_called_definitive(self):
        doc = complete_doc()
        doc["findings"][0]["validation"] = {"verdict": "Valid", "method": "static",
                                            "evidence": "a.py:1"}
        doc["findings"][1]["validation"] = {"verdict": "Unlikely", "method": "static"}
        html = render.render_html(doc, "en")
        self.assertNotIn("Every included finding has a definitive verdict", html)
        self.assertIn("1 included finding is not yet Valid (Likely, Unlikely or Unverified).", html)
        self.assertIn("Likely・Unlikely・Unverified", render.render_html(doc, "ja"))


class BlankLookingValueTests(unittest.TestCase):
    def test_invisible_values_get_no_row_and_fall_back(self):
        doc = complete_doc()
        doc["findings"][0]["contrast"] = "\u200b"
        doc["findings"][0]["references"] = [{"url": "https://e.example/a", "title": "\u200b "}]
        doc["meta"]["method"] = "\u200b"
        doc["meta"]["commit"] = "\u3164"
        markdown = render.render_markdown(doc, "en")
        html = render.render_html(doc, "en")
        for out in (markdown, html):
            with self.subTest(out=out[:20]):
                self.assertNotIn("\u200b", out)
                self.assertNotIn("\u3164", out)
                self.assertIn("UNKNOWN", out)
        self.assertIn("[https&#58;//e.example/a](<https://e.example/a>)", markdown)
        self.assertIn(render.LABELS["en"]["static_note"], markdown)
        self.assertNotIn(">Contrast<", html)


class ReadOnlyNoteTests(unittest.TestCase):
    def test_a_recorded_method_replaces_the_read_only_note(self):
        doc = complete_doc()
        self.assertIn(render.DASH["en"]["report_note"], render.render_html(doc, "en"))
        doc["meta"]["method"] = "Static review; GUARD: ci/test.py added for R-01"
        html = render.render_html(doc, "en")
        self.assertNotIn(render.DASH["en"]["report_note"], html)
        self.assertIn(render.DASH["en"]["report_note_method"], html)


class DashboardScriptTests(unittest.TestCase):
    """The script must survive an empty register and a malformed URL fragment."""

    def test_the_register_is_wired_only_when_the_search_box_exists(self):
        self.assertIn("var list=byId('f-q')?byId('register-list'):null", render.JS)
        self.assertIn("function show(){if(!list)return;", render.JS)

    def test_a_malformed_fragment_is_ignored(self):
        self.assertIn("try{id=decodeURIComponent(location.hash.slice(1));}catch(err){return;}",
                      render.JS)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_script_parses(self):
        result = subprocess.run(["node", "--check", "-"], input=render.JS, text=True,
                                capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_search_reads_recorded_values_not_the_page_labels(self):
        self.assertNotIn("d.textContent.toLowerCase()", render.JS)
        self.assertIn(".detail dd", render.JS)


if __name__ == "__main__":
    unittest.main()
