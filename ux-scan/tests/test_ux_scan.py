"""ux-scan regression tests: inventory, record checks, merge, renumber, render and the run contract."""
import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "ux-scan" / "scripts"
FIXTURE = ROOT / "examples" / "tasklane"
sys.path.insert(0, str(SCRIPTS))

import findings  # noqa: E402
import inventory  # noqa: E402
import render  # noqa: E402

FLOWS = json.loads((ROOT / "examples" / "flows.sample.json").read_text(encoding="utf-8"))
SAMPLE = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
SAMPLE_JA = json.loads((ROOT / "examples" / "findings.sample.ja.json").read_text(encoding="utf-8"))


def run(script, *args):
    return subprocess.run([sys.executable, str(SCRIPTS / script), *map(str, args)], capture_output=True, text=True)


def locations(rows):
    return [row["location"] for row in rows]


class InventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plain = inventory.inventory(FIXTURE)
        cls.inv = inventory.inventory(FIXTURE, FLOWS)

    def test_routes_orphans_and_tokens(self):
        self.assertEqual([r["route"] for r in self.plain["routes"]], ["/", "/signup", "/settings", "/archive"])
        self.assertEqual([r["route"] for r in self.plain["orphan_routes"]], ["/signup", "/archive"])
        self.assertEqual([t["path"] for t in self.plain["token_sources"]], ["src/styles/tokens.css"])
        self.assertNotIn("off_scale", self.plain)

    def test_literals_are_measured_against_the_scales(self):
        off = self.inv["off_scale"]
        self.assertEqual({r["value"] for r in off["spacing"]}, {"10px", "13px", "18px"})
        self.assertEqual([r["value"] for r in off["font_sizes"]], ["15px"])
        self.assertEqual([r["value"] for r in off["breakpoints"]], ["700px"])
        self.assertEqual({r["value"] for r in off["z_index"]}, {9999, 99999})
        # Token definitions (--space-1: 4px) are not spacing literals.
        self.assertNotIn("src/styles/tokens.css:2", [loc for r in self.plain["spacing"] for loc in r["locations"]])
        self.assertEqual(self.inv["smallest_viewport"], 360)
        self.assertEqual(self.inv["fixed_widths"], [{"value": "480px", "count": 1, "locations": ["src/styles/app.css:6"],
                                                     "wider_than_smallest_viewport": True}])
        self.assertNotIn("physical_properties", self.inv)  # No RTL locale ships.

    def test_css_rule_candidates(self):
        self.assertEqual(self.plain["focus_outline"], [{"selector": ".btn:focus", "location": "src/styles/app.css:4",
                                                        "replacement_in_rule": False,
                                                        "focus_visible_rule_in_file": False}])
        self.assertEqual([(t["selector"], t["below_24"]) for t in self.plain["tap_targets"]], [(".icon-btn", True)])
        self.assertTrue(self.plain["viewport_meta"][0]["blocks_zoom"])
        self.assertEqual(self.plain["motion"]["declarations"], 2)
        self.assertEqual(self.plain["motion"]["reduced_motion"], [])
        self.assertIn("text-overflow: ellipsis", {r["pattern"] for r in self.plain["truncation"]})

    def test_markup_candidates(self):
        self.assertEqual([(c["element"], c["location"]) for c in self.plain["click_handlers"]],
                         [("div", "src/components/TaskList.tsx:15"), ("a", "src/pages/Settings.tsx:9")])
        self.assertEqual(self.plain["images"], [{"missing": ["alt", "dimensions"], "location": "src/components/TaskList.tsx:14"}])
        self.assertEqual(locations(self.plain["icon_buttons"]), ["src/components/TaskList.tsx:16"])
        email, password = self.plain["inputs"]
        self.assertEqual(email["missing"], ["label", "autocomplete", "type=email"])
        self.assertTrue(email["placeholder_only"])
        self.assertEqual(password["missing"], ["label", "autocomplete"])
        # Labelled inputs (htmlFor) and inputs with autocomplete are not candidates.
        self.assertEqual(len(self.plain["inputs"]), 2)
        self.assertEqual({s["file"]: s["missing"] for s in self.plain["state_branches"]},
                         {"src/components/SignupForm.tsx": ["loading"],
                          "src/components/TaskList.tsx": ["loading", "error", "empty"]})
        self.assertEqual([d["call"] for d in self.plain["destructive_actions"]], ["api.remove"])

    def test_locale_expansion(self):
        (bundle,) = self.plain["locale_expansion"]
        self.assertEqual((bundle["base"], bundle["lang"]), ("en", "de"))
        self.assertEqual(bundle["keys"][0], {"key": "task.new", "base_width": 8, "width": 22, "ratio": 2.75})

    def test_markup_edge_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "a.jsx").write_text(
                '<div role="button" tabIndex={0} onKeyDown={k} onClick={go}>ok</div>\n'
                '<span onClick={() => a > b && go()}>x</span>\n'
                '<label>Email <input type="email" name="email" autoComplete="email" /></label>\n'
                '<input {...field} />\n'
                '<button aria-label="Close"><X /></button>\n'
                '<button>{t("save")}</button>\n'
                '<CloseIconButton onClick={close} />\n'
                '<li tabIndex={3}>x</li>\n', encoding="utf-8")
            inv = inventory.inventory(repo)
            self.assertEqual(locations(inv["click_handlers"]), ["a.jsx:2"])
            self.assertEqual(inv["inputs"], [])
            self.assertEqual([(b["element"], b["location"]) for b in inv["icon_buttons"]], [("CloseIconButton", "a.jsx:7")])
            self.assertEqual(inv["positive_tabindex"], [{"element": "li", "value": 3, "location": "a.jsx:8"}])

    def test_rtl_locale_adds_physical_properties(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "a.css").write_text(".x { margin-left: 8px; }\n.y { margin-inline-start: 8px; }\n", encoding="utf-8")
            flows = {**FLOWS, "locales": ["en", "ar"]}
            rows = inventory.inventory(repo, flows)["physical_properties"]
            self.assertEqual([(r["property"], r["locations"]) for r in rows], [("margin-left", ["a.css:1"])])

    def test_skips_dependencies_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            (repo / "node_modules" / "x").mkdir(parents=True)
            (repo / "node_modules" / "x" / "a.css").write_text("a{z-index:5}", encoding="utf-8")
            (repo / "b.css").write_text("b{z-index:7}", encoding="utf-8")
            outside = Path(tmp) / "outside.css"
            outside.write_text("c{z-index:9}", encoding="utf-8")
            (repo / "link.css").symlink_to(outside)
            self.assertEqual([r["value"] for r in inventory.inventory(repo)["z_index"]], [7])

    def test_off_scale_is_measured_before_caps(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            common = "".join(f".c{v} {{ margin: {v}px; }}\n" * 2 for v in range(3, 3 + inventory.MAX_ROWS + 5))
            (repo / "a.css").write_text(common + ".rare { padding: 999.5px; }\n", encoding="utf-8")
            flows = copy.deepcopy(FLOWS)
            flows["tokens"]["spacing"] = list(range(3, 3 + inventory.MAX_ROWS + 5))
            inv = inventory.inventory(repo, flows)
            self.assertEqual(len(inv["spacing"]), inventory.MAX_ROWS)
            self.assertNotIn("999.5px", [r["value"] for r in inv["spacing"]])
            self.assertEqual([r["value"] for r in inv["off_scale"]["spacing"]], ["999.5px"])
            self.assertEqual(inv["truncated"], {"spacing": 6})
            self.assertEqual(inv["limits"]["locations_per_row"], 5)
            self.assertEqual(inventory.inventory(FIXTURE, FLOWS)["truncated"], {})

    def test_cli_rejects_bad_flows(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "flows.json"
            bad.write_text(json.dumps({"app": "X", "flows": [{"id": "bad"}]}), encoding="utf-8")
            r = run("inventory.py", FIXTURE, "--flows", bad, "--out", Path(tmp) / "inv.json")
            self.assertEqual(r.returncode, 2)
            self.assertIn("flows", r.stderr)
            self.assertFalse((Path(tmp) / "inv.json").exists())


class RecordTests(unittest.TestCase):
    def bad(self, mutate, message):
        data = copy.deepcopy(SAMPLE)
        mutate(data)
        with self.assertRaisesRegex(findings.RecordError, message):
            findings.check_findings(data, findings.flow_ids(FLOWS))

    def test_samples_and_flows_are_valid(self):
        ids = findings.flow_ids(findings.check_flows(copy.deepcopy(FLOWS)))
        findings.check_findings(copy.deepcopy(SAMPLE), ids)
        findings.check_findings(copy.deepcopy(SAMPLE_JA), ids)

    def test_samples_cover_every_family_and_agree(self):
        for sample in (SAMPLE, SAMPLE_JA):
            self.assertEqual({p["name"][:2] for p in sample["perspectives"]}, set(findings.FAMILIES))
            self.assertEqual({f["perspective"][:2] for f in sample["findings"]}, set(findings.FAMILIES))
        strip = lambda d: [(f["id"], f["severity"], f["location"], f["perspective"], f["flow_ref"],  # noqa: E731
                            f["validation"]["verdict"]) for f in d["findings"]]
        self.assertEqual(strip(SAMPLE), strip(SAMPLE_JA))

    def test_rejects_bad_ids_refs_locations_and_order(self):
        self.bad(lambda d: d["findings"][0].update(id="F-001"), "U- and three digits")
        self.bad(lambda d: d["findings"][0].update(flow_ref="FL-99"), "not a flow in flows.json")
        self.bad(lambda d: d["findings"][0].update(flow_ref="checkout"), "flow id")
        self.bad(lambda d: d["findings"][0].update(location="/etc/passwd:1"), "repository-relative")
        self.bad(lambda d: d["findings"][0].update(location="../x.tsx:3"), "repository-relative")
        self.bad(lambda d: d["findings"][0].update(perspective="NM2"), "hunt step")
        self.bad(lambda d: d["findings"][0].update(criterion=""), "criterion: required")
        self.bad(lambda d: d["findings"][0].update(confidence="Canon-dependent"), "confidence")
        self.bad(lambda d: d["findings"][0].update(severity="Low"), "severity order")
        self.bad(lambda d: d["findings"][0]["validation"].update(verdict="Maybe"), "verdict")
        self.bad(lambda d: d["findings"][0].update(references=[{"url": "javascript:alert(1)"}]), "http")

    def test_flows_rules(self):
        def bad(mutate, message):
            flows = copy.deepcopy(FLOWS)
            mutate(flows)
            with self.assertRaisesRegex(findings.RecordError, message):
                findings.check_flows(flows)
        bad(lambda f: f["flows"][0].update(id="F1"), "FL- and two or three digits")
        bad(lambda f: f["flows"][0].update(priority="core"), "priority")
        bad(lambda f: f["flows"][1].update(id="FL-01"), "duplicate")
        bad(lambda f: f["flows"][0]["screens"][0].update(location="Signup"), "path:line")
        bad(lambda f: f.update(viewports=["phone"]), "WIDTHxHEIGHT")
        bad(lambda f: f["tokens"].update(spacing=["8px"]), "list of numbers")
        bad(lambda f: f["tokens"].update(radius=[4]), "unknown key")
        bad(lambda f: [fl.update(priority="secondary") for fl in f["flows"] if fl["priority"] == "primary"], "no primary")

    def test_merge_replaces_fields_and_refuses_bad_fragments(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "flows.json").write_text(json.dumps(FLOWS), encoding="utf-8")
            first = {k: v for k, v in SAMPLE.items() if k != "findings"}
            first["findings"] = SAMPLE["findings"][:2]
            frag1, frag2, bad = out / "f1.json", out / "f2.json", out / "bad.json"
            frag1.write_text(json.dumps(first), encoding="utf-8")
            frag2.write_text(json.dumps({"findings": [{"id": "U-002", "status": "Fixed"}]}), encoding="utf-8")
            bad.write_text(json.dumps({"findings": [{"id": "U-001", "flow_ref": "FL-42"}]}), encoding="utf-8")
            target = out / "findings.json"
            self.assertEqual(run("findings.py", "merge", target, frag1, frag2).returncode, 0)
            merged = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual([f["status"] for f in merged["findings"]], ["Open", "Fixed"])
            before = target.read_bytes()
            r = run("findings.py", "merge", target, bad)
            self.assertEqual(r.returncode, 2)
            self.assertIn("FL-42", r.stderr)
            self.assertEqual(target.read_bytes(), before)

    def test_merge_appends_list_sections_and_removes_exact_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            target = out / "findings.json"
            target.write_text(json.dumps(SAMPLE), encoding="utf-8")
            line = "report.pdf not produced: no PDF engine"
            add, perspective, drop, bad = (out / n for n in ("add.json", "p.json", "drop.json", "bad.json"))
            add.write_text(json.dumps({"limitations": [line, SAMPLE["limitations"][0]]}), encoding="utf-8")
            perspective.write_text(json.dumps({"perspectives": [{"name": "MO Motion", "result": "2 findings"}]}),
                                   encoding="utf-8")
            drop.write_text(json.dumps({"remove": {"limitations": [line]}}), encoding="utf-8")
            bad.write_text(json.dumps({"remove": {"limitations": ["not there"]}}), encoding="utf-8")
            self.assertEqual(run("findings.py", "merge", target, add, perspective).returncode, 0)
            merged = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(merged["limitations"], [*SAMPLE["limitations"], line])
            self.assertEqual(len(merged["perspectives"]), len(SAMPLE["perspectives"]))
            self.assertEqual(next(p for p in merged["perspectives"] if p["name"] == "MO Motion")["result"], "2 findings")
            self.assertEqual(run("findings.py", "merge", target, drop).returncode, 0)
            self.assertEqual(json.loads(target.read_text(encoding="utf-8"))["limitations"], SAMPLE["limitations"])
            r = run("findings.py", "merge", target, bad)
            self.assertEqual(r.returncode, 2)
            self.assertIn("no such line", r.stderr)

    def test_merge_accepts_any_order_and_renumber_restores_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "flows.json").write_text(json.dumps(FLOWS), encoding="utf-8")
            data = copy.deepcopy(SAMPLE)
            n = len(data["findings"])
            for i, f in enumerate(data["findings"]):  # Lowest severity first: out of order.
                f["id"] = f"U-{n - i:03d}"
            high = next(f for f in data["findings"] if f["severity"] == "High")
            data["next_steps"] = [f"fix {high['id']} first"]
            frag, target = out / "f.json", out / "findings.json"
            frag.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(run("findings.py", "merge", target, frag).returncode, 0)
            r = run("findings.py", "check", target)
            self.assertEqual(r.returncode, 2)
            self.assertIn("renumber", r.stderr)
            r = run("findings.py", "renumber", target)
            self.assertEqual(r.returncode, 0, r.stderr)
            renumbered = json.loads(target.read_text(encoding="utf-8"))
            moved = next(f["id"] for f in renumbered["findings"] if f["title"] == high["title"])
            self.assertEqual(renumbered["next_steps"], [f"fix {moved} first"])
            self.assertEqual(run("findings.py", "check", target).returncode, 0)
            before = target.read_bytes()
            r = run("findings.py", "renumber", target)
            self.assertIn("already in order", r.stdout)
            self.assertEqual(target.read_bytes(), before)

    def test_samples_are_already_in_renumber_order(self):
        for sample in (SAMPLE, SAMPLE_JA):
            mapping = findings.renumber_map(sample["findings"])
            self.assertEqual([k for k, v in mapping.items() if k != v], [])

    def test_flows_merge_by_id_and_protects_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            target, frag = out / "flows.json", out / "flow.json"
            first = {k: v for k, v in FLOWS.items() if k != "flows"}
            first["flows"] = FLOWS["flows"][:1]
            (out / "f0.json").write_text(json.dumps(first), encoding="utf-8")
            frag.write_text(json.dumps({"flows": FLOWS["flows"][1:]}), encoding="utf-8")
            self.assertEqual(run("findings.py", "flows", target, out / "f0.json", frag).returncode, 0)
            ids = [fl["id"] for fl in json.loads(target.read_text(encoding="utf-8"))["flows"]]
            self.assertEqual(ids, [fl["id"] for fl in FLOWS["flows"]])
        with tempfile.TemporaryDirectory() as tmp:
            # A flows.json written after the findings must cover every flow_ref: refused, nothing written.
            out = Path(tmp)
            target, partial = out / "flows.json", out / "partial.json"
            (out / "findings.json").write_text(json.dumps(SAMPLE), encoding="utf-8")
            whole = copy.deepcopy(FLOWS)
            whole["flows"] = [fl for fl in whole["flows"] if fl["id"] != "FL-04"]
            partial.write_text(json.dumps(whole), encoding="utf-8")
            r = run("findings.py", "flows", target, partial)
            self.assertEqual(r.returncode, 2)
            self.assertIn("FL-04", r.stderr)
            self.assertFalse(target.exists())


class RenderTests(unittest.TestCase):
    def test_common_format_mapping(self):
        common = render.to_common(copy.deepcopy(SAMPLE), "en", FLOWS, FIXTURE)
        by_id = {f["id"]: f for f in common["findings"]}
        self.assertEqual(by_id["U-001"]["action"]["label"], "Fix")
        self.assertNotIn("Fix", [x["label"] for x in by_id["U-001"]["fields"]])
        self.assertEqual(by_id["U-015"]["action"]["label"], "Verify first")
        self.assertTrue(by_id["U-022"]["excluded"])
        self.assertEqual(next(x["text"] for x in by_id["U-001"]["fields"] if x["label"] == "Flow"),
                         "FL-01: Sign up (primary)")
        self.assertEqual(next(x["text"] for x in by_id["U-005"]["fields"] if x["label"] == "Viewport"), "360x640")
        self.assertEqual(by_id["U-002"]["category"], "Accessibility")
        self.assertIn("onClick={() => api.open(task.id)}", "\n".join(by_id["U-002"]["snippet"]["lines"]))
        self.assertEqual(common["report"]["running_footer"], "UX REVIEW")

    def test_snippet_refuses_secrets_and_escapes(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / ".env").write_text("TOKEN=abc\n", encoding="utf-8")
            (repo / "a.ts").write_text("const label = 'Hi';\nconst api_key = 'sk-123';\n", encoding="utf-8")
            self.assertIsNone(render.snippet(repo, ".env:1"))
            self.assertIsNone(render.snippet(repo, "../outside.ts:1"))
            lines = render.snippet(repo, "a.ts:1")["lines"]
            self.assertNotIn("sk-123", "\n".join(lines))

    def test_render_and_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            out.mkdir()
            shutil.copy(ROOT / "examples" / "flows.sample.json", out / "flows.json")
            shutil.copy(ROOT / "examples" / "findings.sample.ja.json", out / "findings.json")
            self.assertEqual(run("inventory.py", FIXTURE, "--flows", out / "flows.json",
                                 "--out", out / "inventory.json").returncode, 0)
            r = run("render.py", out / "findings.json", "--out", out, "--lang", "ja", "--repo", FIXTURE, "--no-pdf")
            self.assertEqual(r.returncode, 0, r.stderr)
            page = (out / "report.html").read_text(encoding="utf-8")
            self.assertIn('content:"UX診断"', page)
            self.assertIn("UX診断書", page)
            self.assertIn("FL-01: Sign up (主要)", page)
            # --no-pdf needs its limitation; with it, the contract holds.
            self.assertEqual(run("contract_check.py", out, "--no-pdf").returncode, 1)
            data = json.loads((out / "findings.json").read_text(encoding="utf-8"))
            data["limitations"].append("report.pdf not produced: no PDF engine in the test environment")
            (out / "findings.json").write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            stale = run("contract_check.py", out, "--no-pdf")
            self.assertEqual(stale.returncode, 1)
            self.assertIn("stale", stale.stderr)
            # The re-render hint keeps the language and the excerpts.
            self.assertIn("--lang ja --repo <repo> --no-pdf", stale.stderr)
            run("render.py", out / "findings.json", "--out", out, "--lang", "ja", "--no-pdf")
            ok = run("contract_check.py", out, "--no-pdf")
            self.assertEqual(ok.returncode, 0, ok.stderr)
            (out / "notes.txt").write_text("x", encoding="utf-8")
            self.assertIn("notes.txt", run("contract_check.py", out, "--no-pdf").stderr)
            (out / "notes.txt").unlink()
            # Every family must be recorded, and no finding may stay Unverified.
            data = json.loads((out / "findings.json").read_text(encoding="utf-8"))
            data["perspectives"] = [p for p in data["perspectives"] if not p["name"].startswith("MO")]
            data["findings"][0]["validation"]["verdict"] = "Unverified"
            (out / "findings.json").write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            run("render.py", out / "findings.json", "--out", out, "--lang", "ja", "--no-pdf")
            r = run("contract_check.py", out, "--no-pdf")
            self.assertEqual(r.returncode, 1)
            self.assertIn("no entry for MO", r.stderr)
            self.assertIn("U-001 still Unverified", r.stderr)
            self.assertNotIn("stale", r.stderr)
            (out / "flows.json").unlink()
            self.assertIn("flows.json: missing", run("contract_check.py", out, "--no-pdf").stderr)


if __name__ == "__main__":
    unittest.main()
