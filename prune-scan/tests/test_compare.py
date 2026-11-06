"""compare.py: a follow-up review against an earlier one, matched by what findings name, not by id."""

import contextlib
import copy
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import compare  # noqa: E402
import findings  # noqa: E402

SAMPLE = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
SAMPLE_JA = json.loads((ROOT / "examples" / "findings.sample.ja.json").read_text(encoding="utf-8"))
UNITS = json.loads((ROOT / "examples" / "units.sample.json").read_text(encoding="utf-8"))
REMOVED = ("server/legacy_export.py", "web/public/fonts/OldSans.woff2", "web/src/components/OldButton.tsx")


def quiet(*argv):
    with contextlib.redirect_stdout(io.StringIO()):
        return findings.main(list(map(str, argv)))


def by_id(record, fid):
    return next(f for f in record["findings"] if f["id"] == fid)


class FollowUp(unittest.TestCase):
    """The sample review, then a follow-up after three files were deleted and the record renumbered."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.repo = self.tmp / "repo"
        shutil.copytree(ROOT / "examples" / "larder", self.repo)
        for path in REMOVED:
            (self.repo / path).unlink()
        self.old, self.new = self.tmp / "old", self.tmp / "new"
        for d in (self.old, self.new):
            d.mkdir()
            (d / "units.json").write_text(json.dumps(UNITS), encoding="utf-8")
        self.write(self.old, SAMPLE)
        later = copy.deepcopy(SAMPLE)
        later["meta"]["date"] = "2026-11-20"
        later["findings"] = [f for f in later["findings"] if f["id"] not in ("P-002", "P-011", "P-031", "P-032")]
        by_id(later, "P-006")["status"] = "Fixed"
        by_id(later, "P-021")["severity"] = "Info"
        by_id(later, "P-022")["validation"] = {"verdict": "NotApplicable", "evidence": "Deprecation window open."}
        by_id(later, "P-023")["status"] = "Accepted"
        self.write(self.new, later)
        self.assertEqual(quiet("renumber", self.new / "findings.json"), 0)

    def write(self, directory, record):
        (directory / "findings.json").write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")

    def run_compare(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = compare.main([str(self.old), str(self.new), *map(str, args)])
        return status, out.getvalue(), err.getvalue()

    def comparison(self, *args):
        status, out, err = self.run_compare("--json", self.tmp / "cmp.json", *args)
        self.assertEqual(status, 0, err)
        return json.loads((self.tmp / "cmp.json").read_text(encoding="utf-8")), out

    def test_findings_are_matched_across_renumbered_ids(self):
        result, out = self.comparison()
        f = result["findings"]
        self.assertEqual([r["id"] for r in f["missing"]], ["P-002", "P-011", "P-031", "P-032"])
        self.assertEqual([r["id"] for r in f["resolved"]], ["P-006"])
        self.assertEqual([r["id"] for r in f["accepted"]], ["P-023"])
        self.assertEqual([(r["id"], r["later_verdict"]) for r in f["ruled_out"]], [("P-022", "NotApplicable")])
        self.assertEqual(f["new"], [])
        changed = {r["id"]: r["changes"] for r in f["persisting"] if r["changes"]}
        self.assertEqual(changed, {"P-021": {"severity": ["Low", "Info"]}})
        # Every persisting finding points at the later finding with the same element.
        later = json.loads((self.new / "findings.json").read_text(encoding="utf-8"))
        for row in f["persisting"]:
            self.assertEqual(by_id(later, row["later_id"])["element"], by_id(SAMPLE, row["id"])["element"])
        self.assertTrue(out.startswith("prune-scan follow-up: 36 -> 29 open; resolved 1, accepted 1, ruled out 1, "
                                       "missing 4, persisting 29, new 0, reopened 0"))
        self.assertIn("High 5->4", out)

    def test_repo_tells_deleted_files_from_files_still_present(self):
        result, out = self.comparison("--repo", self.repo)
        missing = {r["id"]: r for r in result["findings"]["missing"]}
        self.assertEqual(missing["P-011"]["paths_gone"], ["server/legacy_export.py"])
        self.assertEqual(missing["P-002"]["paths_gone"], [])
        self.assertEqual(missing["P-002"]["paths_present"], ["server/app.py"])
        self.assertIn("[still present: confirm]", out)

    def test_new_and_reopened_findings(self):
        later = json.loads((self.new / "findings.json").read_text(encoding="utf-8"))
        extra = copy.deepcopy(by_id(SAMPLE, "P-035"))
        extra.update(id="P-099", element="CSS class .btn-old", location="web/src/styles/app.css:4")
        later["findings"].append(extra)
        self.write(self.new, later)
        earlier = copy.deepcopy(SAMPLE)
        by_id(earlier, "P-010")["status"] = "Fixed"
        self.write(self.old, earlier)
        result, _ = self.comparison()
        self.assertEqual([r["element"] for r in result["findings"]["new"]], ["CSS class .btn-old"])
        self.assertEqual([r["earlier_id"] for r in result["findings"]["reopened"]], ["P-010"])

    def test_fragment_carries_missing_findings_as_fixed_and_merges(self):
        fragment_path = self.tmp / "carry.json"
        result, out = self.comparison("--repo", self.repo, "--fragment", fragment_path)
        fragment = json.loads(fragment_path.read_text(encoding="utf-8"))
        carried = fragment["findings"]
        self.assertEqual([f["id"] for f in carried], ["P-034", "P-035", "P-036", "P-037"])
        self.assertEqual({f["status"] for f in carried}, {"Fixed"})
        self.assertEqual(result["carried"]["ids"], [["P-002", "P-034"], ["P-011", "P-035"],
                                                    ["P-031", "P-036"], ["P-032", "P-037"]])
        legacy = next(f for f in carried if f["element"] == "Module server/legacy_export.py")
        self.assertIn("server/legacy_export.py no longer exists", legacy["validation"]["evidence"])
        debug = next(f for f in carried if f["element"] == "Route GET /debug/dump")
        self.assertIn("server/app.py still exists", debug["validation"]["evidence"])
        self.assertIn("fragment: 4 carried as Fixed", out)
        target = self.new / "findings.json"
        self.assertEqual(quiet("merge", target, fragment_path), 0)
        self.assertEqual(quiet("renumber", target), 0)
        self.assertEqual(quiet("check", target), 0)
        merged = json.loads(target.read_text(encoding="utf-8"))
        fixed = sorted(f["element"] for f in merged["findings"] if f["status"] == "Fixed")
        self.assertEqual(len(fixed), 5)
        self.assertIn("Route GET /debug/dump", fixed)

    def test_carried_prose_points_at_the_same_findings_in_the_later_record(self):
        earlier = copy.deepcopy(SAMPLE)
        by_id(earlier, "P-011")["risk"] = "Remove after P-021 is decided and with P-002."
        self.write(self.old, earlier)
        result, _ = self.comparison("--fragment", self.tmp / "carry.json")
        carried = json.loads((self.tmp / "carry.json").read_text(encoding="utf-8"))["findings"]
        legacy = next(f for f in carried if f["element"] == "Module server/legacy_export.py")
        later_label = next(r["later_id"] for r in result["findings"]["persisting"] if r["id"] == "P-021")
        debug_id = dict(map(tuple, result["carried"]["ids"]))["P-002"]
        self.assertEqual(legacy["risk"], f"Remove after {later_label} is decided and with {debug_id}.")
        self.assertEqual(legacy["location"], "server/legacy_export.py:1")

    def test_units_are_mapped_by_name_when_ids_change(self):
        units = copy.deepcopy(UNITS)
        for u in units["units"]:
            u["id"] = "UN-1" + u["id"][3:]  # UN-01 -> UN-101
        later = json.loads((self.new / "findings.json").read_text(encoding="utf-8"))
        for f in later["findings"]:
            f["unit_ref"] = "UN-1" + f["unit_ref"][3:]
        self.write(self.new, later)
        (self.new / "units.json").write_text(json.dumps(units), encoding="utf-8")
        self.comparison("--fragment", self.tmp / "carry.json")
        carried = json.loads((self.tmp / "carry.json").read_text(encoding="utf-8"))["findings"]
        legacy = next(f for f in carried if f["element"] == "Module server/legacy_export.py")
        self.assertEqual(legacy["unit_ref"], "UN-101")

    def test_a_finding_no_later_unit_covers_is_named_not_carried(self):
        units = copy.deepcopy(UNITS)
        dropped = next(u for u in units["units"] if u["id"] == "UN-02")["entry_points"]
        units["units"] = [u for u in units["units"] if u["id"] != "UN-02"]
        units["entry_points"] = [e for e in units["entry_points"] if e["id"] not in dropped]
        for u in units["units"]:
            u["paths"] = [p for p in u["paths"] if not p.startswith("web")]
        later = json.loads((self.new / "findings.json").read_text(encoding="utf-8"))
        later["findings"] = [f for f in later["findings"] if f["unit_ref"] != "UN-02"]
        self.write(self.new, later)
        self.assertEqual(quiet("renumber", self.new / "findings.json"), 0)
        (self.new / "units.json").write_text(json.dumps(units), encoding="utf-8")
        result, out = self.comparison("--fragment", self.tmp / "carry.json")
        skipped = {s["id"] for s in result["carried"]["skipped"]}
        self.assertIn("P-031", skipped)
        self.assertIn("not carried P-031", out)

    def test_findings_the_later_baseline_cannot_hold_are_named_not_carried(self):
        units = copy.deepcopy(UNITS)
        for item in units["purpose"]:
            if item["id"] == "PB-05":  # P-007's non-goal is now only inferred: a Confirmed finding cannot rest on it.
                item["source"] = "inferred"
        (self.new / "units.json").write_text(json.dumps(units), encoding="utf-8")
        later = json.loads((self.new / "findings.json").read_text(encoding="utf-8"))
        later["findings"] = [f for f in later["findings"] if f.get("purpose_ref") != "PB-05"]
        self.write(self.new, later)
        quiet("renumber", self.new / "findings.json")
        earlier = copy.deepcopy(SAMPLE)
        by_id(earlier, "P-031")["validation"]["verdict"] = "Unlikely"
        self.write(self.old, earlier)
        result, _ = self.comparison("--fragment", self.tmp / "carry.json")
        skipped = {s["id"]: s["reason"] for s in result["carried"]["skipped"]}
        self.assertIn("inferred purpose item", skipped["P-007"])
        self.assertIn("Unlikely", skipped["P-031"])
        carried = dict(map(tuple, result["carried"]["ids"]))
        self.assertIn("P-011", carried)
        self.assertNotIn("P-007", carried)

    def test_japanese_notes(self):
        self.write(self.old, SAMPLE_JA)
        later = copy.deepcopy(SAMPLE_JA)
        later["findings"] = [f for f in later["findings"] if f["id"] != "P-011"]
        self.write(self.new, later)
        self.assertEqual(quiet("renumber", self.new / "findings.json"), 0)
        self.comparison("--repo", self.repo, "--fragment", self.tmp / "carry.json", "--lang", "ja")
        carried = json.loads((self.tmp / "carry.json").read_text(encoding="utf-8"))["findings"]
        self.assertEqual(len(carried), 1)
        self.assertIn("server/legacy_export.pyはリポジトリに存在しない。", carried[0]["validation"]["evidence"])

    def test_inventory_rows_match_across_line_shifts(self):
        old_inv = self.old / "inventory.json"
        rows = [{"name": "slugify", "kind": "def", "location": "server/utils.py:12"},
                {"name": "gone_fn", "kind": "def", "location": "server/utils.py:30"}]
        old_inv.write_text(json.dumps({"tool": "inventory.py", "unreferenced_symbols": rows,
                                       "css_unreferenced": []}), encoding="utf-8")
        new_rows = [{"name": "slugify", "kind": "def", "location": "server/utils.py:4"}]
        (self.new / "inventory.json").write_text(json.dumps({
            "tool": "inventory.py", "unreferenced_symbols": new_rows, "truncated": {"css_unreferenced": 1},
            "css_unreferenced": [{"class": "btn-old", "location": "web/src/styles/app.css:4"}]}), encoding="utf-8")
        result, out = self.comparison()
        sections = result["inventory"]["sections"]
        self.assertEqual(sections["unreferenced_symbols"]["appeared"], [])
        self.assertEqual([r["name"] for r in sections["unreferenced_symbols"]["gone"]], ["gone_fn"])
        self.assertEqual([r["class"] for r in sections["css_unreferenced"]["appeared"]], ["btn-old"])
        self.assertIn("new candidate css_unreferenced: web/src/styles/app.css:4 btn-old", out)
        self.assertIn("truncated sections (counts are partial): css_unreferenced", out)

    def test_inventory_only_directories(self):
        a, b = self.tmp / "a", self.tmp / "b"
        for d, path in ((a, ROOT / "examples" / "larder"), (b, self.repo)):
            d.mkdir()
            proc = subprocess.run([sys.executable, str(SCRIPTS / "inventory.py"), str(path),
                                   "--out", str(d / "inventory.json")], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(compare.main([str(a), str(b / "inventory.json")]), 0, err.getvalue())
        self.assertIn("new candidate css_unreferenced: web/src/styles/app.css:4 btn-old", out.getvalue())
        self.assertNotIn("follow-up:", out.getvalue())
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            self.assertEqual(compare.main([str(a), str(b), "--fragment", str(self.tmp / "f.json")]), 2)
        self.assertIn("--fragment needs findings.json", err.getvalue())

    def test_refusals_write_nothing(self):
        for args, message in (
                (["--json", self.repo / "cmp.json", "--repo", self.repo], "outside the reviewed repository"),
                (["--json", self.new / "findings.json"], "overwrite an input"),
                (["--json", self.tmp / "same.json", "--fragment", self.tmp / "same.json"], "same file"),
        ):
            with self.subTest(args=args):
                status, _, err = self.run_compare(*args)
                self.assertEqual(status, 2)
                self.assertIn(message, err)
        self.assertFalse((self.repo / "cmp.json").exists())
        self.assertFalse((self.tmp / "same.json").exists())
        self.assertIsNotNone(json.loads((self.new / "findings.json").read_text(encoding="utf-8"))["findings"])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(compare.main([str(self.old), str(self.old)]), 2)
            empty = self.tmp / "empty"
            empty.mkdir()
            self.assertEqual(compare.main([str(self.old), str(empty)]), 2)
        self.assertIn("same directory", err.getvalue())
        self.assertIn("nothing to compare", err.getvalue())

    def test_an_invalid_record_is_refused(self):
        broken = json.loads((self.new / "findings.json").read_text(encoding="utf-8"))
        broken["findings"][0]["severity"] = "Critical"
        self.write(self.new, broken)
        status, _, err = self.run_compare()
        self.assertEqual(status, 2)
        self.assertIn("severity", err)

    def test_fixed_findings_render_without_a_next_action(self):
        fragment_path = self.tmp / "carry.json"
        self.comparison("--repo", self.repo, "--fragment", fragment_path)
        target = self.new / "findings.json"
        quiet("merge", target, fragment_path)
        quiet("renumber", target)
        out = self.tmp / "pages"
        out.mkdir()
        shutil.copy(target, out / "findings.json")
        shutil.copy(self.new / "units.json", out / "units.json")
        proc = subprocess.run([sys.executable, str(SCRIPTS / "render.py"), str(out / "findings.json"), "--out",
                               str(out), "--lang", "en", "--repo", str(self.repo), "--no-pdf"],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Route GET /debug/dump", (out / "report.html").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
