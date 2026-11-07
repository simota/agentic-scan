"""progress.py: what a review in progress still owes, and compare.py --carry-forward."""

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
SCRIPTS = ROOT / "skills" / "ux-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import compare  # noqa: E402
import findings  # noqa: E402
import progress  # noqa: E402

SAMPLE = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
FLOWS = json.loads((ROOT / "examples" / "flows.sample.json").read_text(encoding="utf-8"))


def by_id(data, fid):
    return next(f for f in data["findings"] if f["id"] == fid)


class ProgressTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(tempfile.mkdtemp())
        cls.inventory = cls.root / "inventory.json"
        flows = cls.root / "flows.json"
        flows.write_text(json.dumps(FLOWS), encoding="utf-8")
        subprocess.run([sys.executable, str(SCRIPTS / "inventory.py"), str(ROOT / "examples" / "tasklane"),
                        "--flows", str(flows), "--out", str(cls.inventory)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root)

    def setUp(self):
        self.out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.out)

    def review(self, data=SAMPLE, flows=FLOWS, inventory=True, evidence=True):
        """A review directory holding the given records and every evidence file they cite."""
        if flows is not None:
            (self.out / "flows.json").write_text(json.dumps(flows), encoding="utf-8")
        if inventory:
            shutil.copy(self.inventory, self.out / "inventory.json")
        if data is not None:
            (self.out / "findings.json").write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            if evidence:
                (self.out / "evidence").mkdir(exist_ok=True)
                for f in data["findings"]:
                    for item in f.get("evidence", []):
                        shutil.copy(ROOT / "examples" / "evidence" / item["file"], self.out / "evidence")
        return progress.progress(self.out)

    def todo(self, result, kind=None):
        return [i for i in result["items"] if i["level"] == "todo" and (kind is None or i["kind"] == kind)]

    def run_main(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = progress.main([str(self.out), *args])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_the_finished_sample_owes_nothing_but_a_judgement_on_mockups(self):
        result = self.review()
        self.assertTrue(result["done"], self.todo(result))
        self.assertEqual(sum(u["undecided"] for u in result["units"]), 0)
        self.assertEqual([u["id"] for u in result["units"]], ["FL-01", "FL-02", "FL-05", "FL-03", "FL-04"])
        confirm = [i for i in result["items"] if i["level"] == "confirm"]
        self.assertEqual(len(confirm), 1)
        # The sample's limitations name its visible findings without mockups; the rest are not visible.
        self.assertEqual(confirm[0]["ids"], ["U-003", "U-004", "U-007", "U-008"])
        code, out, _ = self.run_main("--strict")
        self.assertEqual(code, 0)
        self.assertIn("Nothing left", out)

    def test_an_empty_directory_starts_with_the_flows(self):
        result = progress.progress(self.out)
        self.assertFalse(result["done"])
        records = [i["text"] for i in self.todo(result, "records")]
        self.assertEqual(len(records), 3)
        self.assertIn("flows.json is missing", records)
        self.assertEqual(progress._next(result), self.todo(result, "records")[0]["do"])
        self.assertEqual(self.todo(result, "perspectives")[0]["text"],
                         "no entry for " + ", ".join(findings.FAMILIES))
        code, out, _ = self.run_main("--strict", "--lang", "ja")
        self.assertEqual(code, 1)
        self.assertIn("残り", out)

    def test_after_flows_and_inventory_every_candidate_is_listed_per_unit(self):
        result = self.review(data=None)
        candidates = self.todo(result, "candidates")
        self.assertGreater(len(candidates), 20)
        click = next(i for i in candidates if i["location"] == "src/components/TaskList.tsx:15")
        self.assertEqual(click["unit"], "FL-02")
        self.assertIn("(AX2)", click["text"])
        css = next(i for i in candidates if i["location"] == "src/styles/app.css:4")
        self.assertEqual(css["unit"], "FL-05")  # The shared unit takes files no flow screen lists.
        units = {u["id"]: u for u in result["units"]}
        self.assertEqual(units["FL-02"]["undecided"], sum(i.get("unit") == "FL-02" for i in candidates))
        # A unit with no finding and no trace is owed too.
        self.assertEqual(len(self.todo(result, "units")), len(FLOWS["flows"]))

    def test_a_stale_inventory_is_named(self):
        flows = copy.deepcopy(FLOWS)
        flows["viewports"] = ["320x640", "1280x800"]
        result = self.review(flows=flows)
        self.assertIn("inventory.json predates the current flows", [i["text"] for i in self.todo(result, "records")])

    def test_a_candidate_is_decided_by_a_finding_or_a_line_naming_its_location(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"] = [f for f in data["findings"] if f["id"] != "U-017"]  # .btn:focus at app.css:4
        for f in data["findings"]:
            for key in ("U-017",):
                f["validation"]["evidence"] = f["validation"]["evidence"].replace(key, "")
        data["next_steps"] = []
        result = self.review(data)
        left = {i["location"] for i in self.todo(result, "candidates")}
        self.assertIn("src/styles/app.css:4", left)
        # The tail of a path is enough, as people write it.
        data["checked_ok"].append("app.css:4 .btn:focus: a :focus-visible rule in base.css restores the ring.")
        left = {i["location"] for i in self.todo(self.review(data), "candidates")}
        self.assertNotIn("src/styles/app.css:4", left)
        self.assertIn("src/styles/app.css:12", left)  # Named only in next_steps, which were cleared.
        # A different file with the same name is not a mention.
        self.assertFalse(progress._same_file("src/styles/app.css", "les/app.css"))

    def test_finding_gaps_are_listed_with_their_ids(self):
        data = copy.deepcopy(SAMPLE)
        by_id(data, "U-002")["validation"] = {"verdict": "Unverified"}
        by_id(data, "U-003").pop("evidence")
        by_id(data, "U-004")["status"] = "Fixed"
        result = self.review(data)
        (self.out / "evidence" / "stray.png").write_bytes(b"\x89PNG\r\n\x1a\n")
        (self.out / "evidence" / "U-005-source.log").unlink()
        result = progress.progress(self.out)
        texts = [i["text"] for i in self.todo(result, "findings")]
        self.assertIn("still Unverified: U-002", texts)
        self.assertIn("no evidence of the defect (stage before): U-003", texts)
        self.assertIn("Fixed without evidence of the fix (stage after): U-004", texts)
        self.assertIn("cited evidence not in evidence/: U-005-source.log", texts)
        self.assertIn("evidence/ files no finding cites: stray.png", texts)
        self.assertFalse(result["done"])

    def test_numbering_out_of_order_points_at_renumber(self):
        data = copy.deepcopy(SAMPLE)
        data["findings"].reverse()
        item = next(i for i in self.todo(self.review(data), "findings") if i["text"].startswith("numbering"))
        self.assertIn("findings.py renumber", item["do"])

    def test_limitations_name_findings_singly_or_as_ranges(self):
        self.assertEqual(progress.named_ids(["U-003〜U-005 and U-008", "U-010 to U-009"]),
                         {"U-003", "U-004", "U-005", "U-008", "U-009", "U-010"})

    def test_markdown_escapes_markup_and_writes_no_review_output(self):
        self.review(data=None)
        code, out, _ = self.run_main()
        self.assertEqual(code, 0)
        self.assertIn("&lt;div> click without", out)
        self.assertNotIn("<div>", out)
        self.review()
        before = (self.out / "findings.json").read_bytes()
        code, _, err = self.run_main("--out", str(self.out / "findings.json"))
        self.assertEqual(code, 2)
        self.assertIn("output must be different", err)
        self.assertEqual((self.out / "findings.json").read_bytes(), before)

    def test_an_invalid_record_is_refused(self):
        (self.out / "findings.json").write_text("{", encoding="utf-8")
        code, _, err = self.run_main()
        self.assertEqual(code, 2)
        self.assertIn("progress.py:", err)


class CarryForwardTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)

    def record(self, name, data):
        directory = self.dir / name
        directory.mkdir()
        (directory / "flows.json").write_text(json.dumps(FLOWS), encoding="utf-8")
        path = directory / "findings.json"
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return path

    def test_acceptances_and_regressions_become_a_fragment_that_merges(self):
        base = copy.deepcopy(SAMPLE)
        by_id(base, "U-005")["status"] = "Fixed"
        by_id(base, "U-009")["status"] = "Accepted"
        before, cur = self.record("before", base), self.record("after", SAMPLE)
        fragment = self.dir / "carry.json"
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            code = compare.main([str(before), str(cur), "--out", str(self.dir / "progress.md"),
                                 "--carry-forward", str(fragment)])
        self.assertEqual(code, 0)
        self.assertIn("1 acceptance(s) carried", stdout.getvalue())
        carried = json.loads(fragment.read_text(encoding="utf-8"))
        self.assertEqual(carried["findings"], [{"id": "U-009", "status": "Accepted"}])
        self.assertEqual(len(carried["decisions"]), 2)
        self.assertTrue(carried["decisions"][0].startswith("U-005 regressed"))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(findings.main(["merge", str(cur), str(fragment)]), 0)
        merged = json.loads(cur.read_text(encoding="utf-8"))
        self.assertEqual(by_id(merged, "U-009")["status"], "Accepted")

    def test_nothing_to_carry_and_a_fragment_over_the_comparison_are_handled(self):
        path = self.record("same", SAMPLE)
        fragment = self.dir / "carry.json"
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(compare.main([str(path), str(path), "--out", "-", "--carry-forward", str(fragment)]), 0)
        self.assertIn("nothing to carry forward", stdout.getvalue())
        self.assertEqual(json.loads(fragment.read_text(encoding="utf-8")), {})
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(compare.main([str(path), str(path), "--out", str(fragment),
                                           "--carry-forward", str(fragment)]), 2)
        self.assertIn("other than --out", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
