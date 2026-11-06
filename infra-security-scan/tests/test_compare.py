"""compare.py and render.py --previous: what changed between two assessments."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-scan" / "scripts"))
import compare  # noqa: E402
import render  # noqa: E402

SAMPLE = REPO / "examples" / "findings.sample.json"
SAMPLE_JA = REPO / "examples" / "findings.sample.ja.json"


def sample(path=SAMPLE):
    return json.loads(path.read_text(encoding="utf-8"))


def by_id(data, fid):
    return next(f for f in data["findings"] if f["id"] == fid)


def retest(previous):
    """The sample after a remediation round, renumbered as renumber would."""
    cur = copy.deepcopy(previous)
    cur["meta"]["date"] = "2026-11-01"
    cur["meta"]["commit"] = "a" * 40
    cur["findings"] = [f for f in cur["findings"] if f["id"] != "F-001"]      # fixed
    by_id(cur, "F-006")["severity"] = "Medium"                                # regraded
    by_id(cur, "I-001")["validation"] = {"verdict": "FalsePositive", "evidence": "attached to no instance"}
    by_id(cur, "F-003")["validation"] = {"verdict": "Valid", "evidence": "the plan sets it public"}  # reopened
    by_id(cur, "F-002")["location"] = "envs/shared/aws/oidc.tf:20-36"        # moved, unchanged otherwise
    new = copy.deepcopy(by_id(cur, "F-005"))
    new.update(id="F-099", title="KMS key policy lets any principal in the account decrypt",
               category="Secrets and keys", resources=["aws_kms_key.data"], location="modules/kms/main.tf:3",
               attack_paths=[])
    cur["findings"].append(new)
    for a in cur["attack_paths"]:
        if a["id"] == "AP-04":
            a.update(status="blocked", note="The bucket binding is gone", findings=[])
    # Renumbering after the round shifts every review ID down by one.
    mapping = {f"F-{n:03d}": f"F-{n - 1:03d}" for n in range(2, 7)} | {"F-099": "F-006"}
    for f in cur["findings"]:
        f["id"] = mapping.get(f["id"], f["id"])
        f["attack_paths"] = f.get("attack_paths", [])
    for a in cur["attack_paths"]:
        a["findings"] = [mapping.get(x, x) for x in a.get("findings", [])]
    return cur


def ids(items, side):
    return [item[side]["id"] for item in items]


class CompareTest(unittest.TestCase):
    def setUp(self):
        self.prev = sample()
        self.cur = retest(self.prev)
        self.result = compare.compare(self.prev, self.cur)

    def test_findings_match_by_content_across_renumbering(self):
        fs = self.result["findings"]
        self.assertEqual(ids(fs["resolved"], "previous"), ["F-001"])
        self.assertEqual(ids(fs["new"], "current"), ["F-006"])
        self.assertEqual(fs["new"][0]["current"]["title"], "KMS key policy lets any principal in the account decrypt")
        self.assertEqual(ids(fs["excluded"], "previous"), ["I-001"])
        self.assertEqual([(i["previous"]["id"], i["current"]["id"]) for i in fs["reopened"]], [("F-003", "F-002")])
        pairs = {i["previous"]["id"]: i["current"]["id"] for i in fs["persisting"]}
        self.assertEqual(pairs["F-002"], "F-001")
        self.assertEqual(pairs["F-006"], "F-005")
        self.assertEqual(pairs["I-002"], "I-002")

    def test_changes_name_what_moved(self):
        persisting = {i["previous"]["id"]: i for i in self.result["findings"]["persisting"]}
        self.assertEqual(persisting["F-006"]["changes"], [{"field": "severity", "from": "Low", "to": "Medium"}])
        self.assertEqual([c["field"] for c in persisting["F-002"]["changes"]], ["location"])
        self.assertEqual(persisting["F-005"]["changes"], [])

    def test_counts_and_attack_paths(self):
        self.assertEqual(self.result["counts"]["previous"]["High"], 3)
        self.assertEqual(self.result["counts"]["current"]["High"], 1)
        self.assertEqual(self.result["open_attack_paths"], {"previous": 3, "current": 2})
        changed = self.result["attack_paths"]["changed"]
        self.assertEqual([(c["previous"]["status"], c["current"]["status"]) for c in changed], [("open", "blocked")])
        self.assertEqual(self.result["attack_paths"]["new"], [])
        self.assertEqual(self.result["attack_paths"]["removed"], [])

    def test_a_retitled_finding_on_the_same_resources_persists(self):
        # A Japanese re-assessment of an English one: titles differ, resources and perspective do not.
        result = compare.compare(sample(), sample(SAMPLE_JA))
        fs = result["findings"]
        self.assertEqual((fs["new"], fs["resolved"]), ([], []))
        self.assertEqual(len(fs["persisting"]), 8)

    def test_same_resources_in_another_perspective_are_different_findings(self):
        cur = copy.deepcopy(self.prev)
        by_id(cur, "F-006")["category"] = "Network exposure"
        fs = compare.compare(self.prev, cur)["findings"]
        self.assertEqual(ids(fs["new"], "current"), ["F-006"])
        self.assertEqual(ids(fs["resolved"], "previous"), ["F-006"])

    def test_baseline_hits_match_on_rule_and_resources(self):
        cur = copy.deepcopy(self.prev)
        hit = by_id(cur, "I-002")
        hit.update(id="I-007", location="envs/staging/aws/bastion.tf:41")
        fs = compare.compare(self.prev, cur)["findings"]
        moved = next(i for i in fs["persisting"] if i["previous"]["id"] == "I-002")
        self.assertEqual(moved["current"]["id"], "I-007")
        hit["rule"] = "AWS-EBS-001"
        fs = compare.compare(self.prev, cur)["findings"]
        self.assertEqual(ids(fs["new"], "current"), ["I-007"])

    def test_a_covered_baseline_hit_follows_its_review_finding(self):
        prev = copy.deepcopy(self.prev)
        by_id(prev, "F-005")["validation"]["evidence"] += " Root cause of I-003."
        cur = copy.deepcopy(prev)
        cur["findings"] = [f for f in cur["findings"] if f["id"] != "I-003"]
        fs = compare.compare(prev, cur)["findings"]
        self.assertNotIn("I-003", ids(fs["resolved"], "previous"))

    def test_a_file_that_left_the_inputs_is_not_called_resolved(self):
        files = {"envs/prod/aws/rds.tf", "envs/shared/aws/oidc.tf"}
        fs = compare.compare(self.prev, self.cur, current_files=files)["findings"]
        self.assertEqual(ids(fs["out_of_inputs"], "previous"), ["F-001"])
        self.assertEqual(fs["resolved"], [])
        self.assertIn(["note_files"], compare.compare(self.prev, self.cur)["notes"])

    def test_notes_warn_about_swapped_or_unrelated_records(self):
        notes = compare.compare(self.cur, self.prev)["notes"]
        self.assertIn(["note_order", "2026-11-01", "2026-10-08"], notes)
        other = copy.deepcopy(self.cur)
        other["meta"]["project"] = "another-estate"
        text = compare.as_text(compare.compare(self.prev, other), compare.LABELS["en"])
        self.assertIn("different projects (acme-platform / another-estate)", text)

    def test_text_header_without_meta(self):
        bare = {"findings": [], "attack_paths": []}
        text = compare.as_text(compare.compare(bare, bare), compare.LABELS["en"])
        self.assertTrue(text.startswith("Changes since the previous assessment: - → -\n"))

    def test_credential_shapes_from_either_record_are_not_repeated(self):
        prev = copy.deepcopy(self.prev)
        key = "AKIA" + "Q" * 16  # built at runtime: never a literal in the repository
        by_id(prev, "F-001")["title"] = f"Bucket readable; key {key} in its policy"
        text = json.dumps(compare.compare(prev, self.cur))
        self.assertNotIn(key, text)
        self.assertIn("[redacted]", text)


class CompareCliTest(unittest.TestCase):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = compare.main([str(a) for a in args])
        return code, out.getvalue(), err.getvalue()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.prev_dir = Path(self.tmp.name) / "prev"
        self.cur_dir = Path(self.tmp.name) / "cur"
        self.prev_dir.mkdir()
        self.cur_dir.mkdir()
        (self.prev_dir / "findings.json").write_text(SAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
        (self.cur_dir / "findings.json").write_text(json.dumps(retest(sample())), encoding="utf-8")

    def test_output_directories_and_formats(self):
        code, out, _ = self.run_cli(self.prev_dir, self.cur_dir)
        self.assertEqual(code, 0)
        self.assertIn("High 3 → 1", out)
        self.assertIn("Resolved (1)\n  F-001 [High]", out)
        self.assertIn("F-006 → F-005 [Medium] Production VPC has no flow logs (envs/prod/aws/vpc.tf:1) — "
                      "severity Low → Medium", out)
        code, out, _ = self.run_cli(self.prev_dir, self.cur_dir, "--format", "markdown", "--lang", "ja")
        self.assertIn("## 前回診断からの変化", out)
        self.assertIn("| 今回 | 1 | 7 | 0 | 0 | 2 |", out)
        code, out, _ = self.run_cli(self.prev_dir, self.cur_dir, "--format", "json")
        doc = json.loads(out)
        self.assertEqual(doc["previous"]["digest"], render.record_digest(sample()))
        self.assertTrue(all(isinstance(n, str) for n in doc["notes"]))

    def test_iac_json_beside_the_record_supplies_the_inputs(self):
        (self.cur_dir / "iac.json").write_text(json.dumps(
            {"tool": "iac_scan", "files": [{"path": "envs/shared/aws/oidc.tf", "kind": "terraform"}], "findings": []}),
            encoding="utf-8")
        _, out, _ = self.run_cli(self.prev_dir, self.cur_dir, "--format", "json")
        doc = json.loads(out)
        self.assertEqual(ids(doc["findings"]["out_of_inputs"], "previous"), ["F-001"])
        self.assertEqual(doc["notes"], [])

    def test_fail_on_gates_regressions(self):
        # Nothing new reaches High: a Medium regression passes a High gate.
        code, _, err = self.run_cli(self.prev_dir, self.cur_dir, "--fail-on", "High")
        self.assertEqual((code, err), (0, ""))
        code, _, err = self.run_cli(self.prev_dir, self.cur_dir, "--fail-on", "Medium")
        self.assertEqual(code, 1)
        self.assertIn("new F-006 [Medium]", err)
        self.assertIn("reopened F-002 [Medium]", err)
        self.assertIn("raised F-005 Low -> Medium", err)
        # The sample against itself has nothing to gate.
        code, _, err = self.run_cli(self.prev_dir, self.prev_dir, "--fail-on", "Info")
        self.assertEqual((code, err), (0, ""))

    def test_a_newly_open_path_trips_the_gate(self):
        prev = sample()
        for a in prev["attack_paths"]:
            if a["id"] == "AP-01":
                a.update(status="blocked", note="was blocked")
        (self.prev_dir / "findings.json").write_text(json.dumps(prev), encoding="utf-8")
        code, _, err = self.run_cli(self.prev_dir, SAMPLE, "--fail-on", "High")
        self.assertEqual(code, 1)
        self.assertIn("newly open AP-01", err)

    def test_unreadable_inputs_exit_2(self):
        code, _, err = self.run_cli(Path(self.tmp.name), self.cur_dir)
        self.assertEqual(code, 2)
        self.assertIn("no findings.json", err)
        (self.prev_dir / "findings.json").write_text('{"findings": 3}', encoding="utf-8")
        code, _, err = self.run_cli(self.prev_dir, self.cur_dir)
        self.assertEqual(code, 2)
        self.assertIn("schema:", err)


class RenderPreviousTest(unittest.TestCase):
    def render(self, current, previous, lang="en", extra=()):
        with tempfile.TemporaryDirectory() as tmp:
            cur = Path(tmp) / "cur.json"
            cur.write_text(json.dumps(current), encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = render.main([str(cur), "--out", str(Path(tmp) / "out"), "--lang", lang, "--no-pdf",
                                    "--previous", str(previous), *extra])
            if code:
                return code, err.getvalue(), None
            return code, (Path(tmp) / "out" / "dashboard.html").read_text(encoding="utf-8"), \
                (Path(tmp) / "out" / "assessment.html").read_text(encoding="utf-8")

    def test_both_reports_show_the_changes(self):
        code, dash, doc = self.render(retest(sample()), SAMPLE)
        self.assertEqual(code, 0)
        for page in (dash, doc):
            self.assertIn("Changes since the previous assessment", page)
            self.assertIn('<tr class="chg-resolved"><td><span class="chg chg-resolved">Resolved</span></td>'
                          '<td class="nowrap">—</td><td class="nowrap">F-001</td>', page)
            self.assertIn('<a href="#F-006">F-006</a>', page)
            self.assertIn("severity Low → Medium", page)
            self.assertIn("Resolved means the configuration no longer shows the finding", page)
        nav = dash.split('<nav class="sidebar"')[1].split("</nav>")[0]
        self.assertIn('<a href="#changes">Changes</a>', nav)

    def test_the_register_can_filter_by_change(self):
        _, dash, _ = self.render(retest(sample()), SAMPLE)
        self.assertIn('<div class="filters has-change">', dash)
        self.assertIn('<select id="f-chg"><option value="">All</option><option value="new">New</option>'
                      '<option value="reopened">Reopened</option><option value="changed">Persisting, changed</option>'
                      '<option value="persisting">Persisting</option><option value="excluded">Excluded by triage</option>'
                      '</select>', dash)
        self.assertRegex(dash, r'<tr class="row" id="F-006"[^>]* data-chg="new"')
        self.assertRegex(dash, r'<tr class="row" id="F-005"[^>]* data-chg="changed"')
        self.assertRegex(dash, r'<tr class="row" id="F-001"[^>]* data-chg="persisting"')
        self.assertIn('<span class="chg chg-new">New</span>', dash)
        self.assertIn("(!f.chg||!f.chg.value||r.dataset.chg===f.chg.value)", dash)

    def test_without_previous_nothing_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stdout(io.StringIO()):
                render.main([str(SAMPLE), "--out", tmp, "--no-pdf"])
            dash = (Path(tmp) / "dashboard.html").read_text(encoding="utf-8")
        self.assertNotIn('id="f-chg"', dash)
        self.assertNotIn('id="changes"', dash)
        self.assertIn('<div class="filters">', dash)
        self.assertIn('data-chg=""', dash)

    def test_japanese_labels(self):
        _, dash, doc = self.render(retest(sample(SAMPLE_JA)), SAMPLE_JA, lang="ja")
        self.assertIn("前回診断からの変化", doc)
        self.assertIn("深刻度 低 → 中", dash)

    def test_the_same_record_or_an_unreadable_previous_is_refused(self):
        code, err, _ = self.render(sample(), SAMPLE)
        self.assertEqual(code, 2)
        self.assertIn("this same record", err)
        code, err, _ = self.render(sample(), REPO / "no-such-dir")
        self.assertEqual(code, 2)
        self.assertIn("--previous", err)

    def test_the_stamp_still_names_only_the_current_record(self):
        current = retest(sample())
        _, dash, doc = self.render(current, SAMPLE)
        stamp = f'<meta name="infra-scan-record" content="sha256:{render.record_digest(current)}">'
        self.assertIn(stamp, dash)
        self.assertIn(stamp, doc)


if __name__ == "__main__":
    unittest.main()
