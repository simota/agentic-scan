"""The inventory's stages after the file scan, each called on its own."""

import sys
import unittest
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "ux-scan" / "scripts"))

import inventory  # noqa: E402


def rows(*values):
    return [{"value": v, "count": 1, "locations": ["a.css:1"]} for v in values]


class OffScaleTests(unittest.TestCase):
    def test_values_on_the_scale_and_negative_spacing_are_on_scale(self):
        off = inventory.off_scale(rows("8px", "-8px", "13px"), "spacing", [4, 8, 12], set())
        self.assertEqual([r["value"] for r in off], ["13px"])

    def test_an_upper_bound_just_below_a_breakpoint_is_that_breakpoint(self):
        found = rows("767.98px", "767px", "766px")
        self.assertEqual([r["value"] for r in inventory.off_scale(found, "breakpoints", [768], set())], ["766px"])
        # Used as a lower bound somewhere, 767px is its own breakpoint and off the scale.
        self.assertEqual([r["value"] for r in inventory.off_scale(found, "breakpoints", [768], {"767px"})],
                         ["767px", "766px"])
        # Only breakpoints get that tolerance.
        self.assertEqual(len(inventory.off_scale(rows("767px"), "spacing", [768], set())), 1)

    def test_z_index_allows_0_and_plus_or_minus_1(self):
        found = [{"value": v, "count": 1, "locations": []} for v in (-1, 0, 1, 10, 99)]
        self.assertEqual([r["value"] for r in inventory.off_scale(found, "z_index", [10], set())], [99])


class AgainstFlowsTests(unittest.TestCase):
    def test_only_scales_the_flows_name_are_measured_and_widths_need_an_applying_rule(self):
        result = {"spacing": rows("13px"), "font_sizes": rows("15px"), "breakpoints": [], "z_index": [],
                  "fixed_widths": rows("480px", "400px", "1200px")}
        conditions = defaultdict(list, {"480px": [(0, False)], "400px": [(0, True)], "1200px": [(1024, False)]})
        measured = inventory.against_flows(result, {"tokens": {"spacing": [4, 8]}, "viewports": ["360x640", "1280x800"]},
                                           set(), conditions)
        self.assertEqual(list(measured), ["off_scale", "smallest_viewport"])
        self.assertEqual(list(measured["off_scale"]), ["spacing"])
        self.assertEqual(measured["smallest_viewport"], 360)
        # Capped by max-width, or applying only from 1024px up, a width does not overflow 360.
        self.assertEqual([r["wider_than_smallest_viewport"] for r in result["fixed_widths"]], [True, False, False])

    def test_no_viewports_means_no_smallest_viewport(self):
        result = {"spacing": [], "fixed_widths": rows("480px")}
        self.assertEqual(inventory.against_flows(result, {"tokens": {}}, set(), defaultdict(list)), {"off_scale": {}})
        self.assertNotIn("wider_than_smallest_viewport", result["fixed_widths"][0])


class LocaleExpansionTests(unittest.TestCase):
    def test_english_is_the_base_and_only_wide_growth_is_listed(self):
        locales = {"app": {"en": ("en.json", {"save": "Save", "ok": "OK", "title": "Settings"}),
                           "de": ("de.json", {"save": "Speichern", "ok": "OK", "title": "Einstellungen"})}}
        self.assertEqual(inventory.locale_expansion(locales), [
            {"bundle": "app", "base": "en", "lang": "de", "file": "de.json",
             "keys": [{"key": "save", "base_width": 4, "width": 9, "ratio": 2.25},
                      {"key": "title", "base_width": 8, "width": 13, "ratio": 1.62}]}])

    def test_a_bundle_in_one_language_has_nothing_to_compare(self):
        self.assertEqual(inventory.locale_expansion({"app": {"ja": ("ja.json", {"a": "保存"})}}), [])


class CapRowsTests(unittest.TestCase):
    def test_every_cut_is_counted(self):
        many = rows(*(f"{n}px" for n in range(inventory.MAX_ROWS + 3)))
        result = inventory.cap_rows({"spacing": many, "font_sizes": [], "parse_warnings": [],
                                     "off_scale": {"spacing": list(many)}, "locale_expansion": []})
        self.assertEqual(len(result["spacing"]), inventory.MAX_ROWS)
        self.assertEqual(result["truncated"], {"spacing": 3, "off_scale.spacing": 3})
        self.assertEqual(list(result)[-2:], ["limits", "truncated"])


if __name__ == "__main__":
    unittest.main()
