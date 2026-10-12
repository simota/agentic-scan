"""prune-scan regression tests: inventory, record checks, merge, renumber, render and the run contract."""
import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
FIXTURE = ROOT / "examples" / "larder"
TODAY = "2026-10-12"
sys.path.insert(0, str(SCRIPTS))

import findings  # noqa: E402
import inventory  # noqa: E402
import render  # noqa: E402

UNITS = json.loads((ROOT / "examples" / "units.sample.json").read_text(encoding="utf-8"))
SAMPLE = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
SAMPLE_JA = json.loads((ROOT / "examples" / "findings.sample.ja.json").read_text(encoding="utf-8"))


def run(script, *args):
    return subprocess.run([sys.executable, str(SCRIPTS / script), *map(str, args)], capture_output=True, text=True)


def names(rows, key="name"):
    return [row[key] for row in rows]


class InventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inv = inventory.inventory(FIXTURE, today=TODAY)
        cls.tagged = inventory.inventory(FIXTURE, findings.check_units(copy.deepcopy(UNITS)), TODAY)

    def test_symbols_and_orphan_files(self):
        self.assertEqual([(s["name"], s["location"]) for s in self.inv["unreferenced_symbols"]],
                         [("get_items_v0", "server/compat.py:5"), ("on_startup", "server/hooks.py:4"),
                          ("format_price_legacy", "server/utils.py:8"), ("slugify", "server/utils.py:13")])
        self.assertEqual(self.inv["decorated_symbols_skipped"], 12)  # Route handlers and the before_request hook.
        self.assertEqual(self.inv["orphan_files"], [
            {"path": "server/compat.py", "test_importers": []},
            {"path": "server/legacy_export.py", "test_importers": ["tests/test_legacy_export.py"]},
            {"path": "web/src/components/OldButton.tsx", "test_importers": []}])

    def test_dependencies(self):
        rows = {r["name"]: r for r in self.inv["unimported_dependencies"]}
        self.assertEqual(sorted(rows), ["jest", "lodash", "simplejson", "six", "stripe", "typescript", "vite", "vitest"])
        self.assertEqual(rows["lodash"]["status"], "unreferenced")
        self.assertEqual(rows["jest"]["status"], "script_only")
        self.assertTrue(rows["typescript"]["implicit_tool"])
        self.assertEqual(rows["stripe"]["location"], "requirements.txt:5")
        self.assertEqual([(d["group"], d["names"]) for d in self.inv["duplicate_purpose"]],
                         [("dates", ["dayjs", "moment"]), ("test runner (JS)", ["jest", "vitest"])])
        self.assertEqual(names(self.inv["platform_replaceable"]), ["node-fetch", "simplejson", "six"])
        self.assertEqual(self.inv["platform_replaceable"][0]["imports"], 1)

    def test_env_vars_names_only(self):
        self.assertEqual(self.inv["env_declaration_files"], [".env.example"])
        self.assertEqual(self.inv["env_declared_not_read"], [{"name": "LEGACY_CDN_URL", "location": ".env.example:4"}])
        self.assertEqual(names(self.inv["env_read_not_declared"]),
                         ["NOTIFY_WEBHOOK_URL", "PAGE_SIZE", "SLACK_WEBHOOK_URL", "SMS_GATEWAY_URL"])
        self.assertNotIn("cdn-old.larder.example", json.dumps(self.inv))

    def test_feature_flags(self):
        flags = {f["name"]: f for f in self.inv["feature_flags"]}
        self.assertEqual(flags["new_checkout"]["value"], True)
        self.assertEqual(flags["new_checkout"]["definitions"], ["server/flags.py:4", "web/src/flags.ts:3"])
        self.assertEqual(flags["new_checkout"]["checks"], 2)
        self.assertEqual((flags["holiday_banner"]["value"], flags["holiday_banner"]["locations"]),
                         (False, ["web/src/pages/Home.tsx:18"]))

    def test_content_candidates(self):
        self.assertEqual([(r["key"], r["langs"], r["location"]) for r in self.inv["i18n_unreferenced"]],
                         [("checkout.legacy_notice", ["en", "ja"], "web/src/i18n/en.json:7"),
                          ("promo.holiday", ["en", "ja"], "web/src/i18n/en.json:6")])
        self.assertEqual(self.inv["i18n_dynamic_prefixes"], ["item.status."])
        self.assertEqual(self.inv["assets_unreferenced"],
                         [{"path": "web/public/fonts/OldSans.woff2", "bytes": 8, "public": True}])
        self.assertEqual(self.inv["css_unreferenced"], [{"class": "legacy-grid", "location": "web/src/styles/app.css:7"}])

    def test_routes(self):
        self.assertEqual([(r["route"], r["location"]) for r in self.inv["unreferenced_routes"]],
                         [("/api/export/csv", "server/app.py:51"), ("/debug/dump", "server/app.py:56"),
                          ("/webhooks/stripe", "server/app.py:61"), ("/auth/callback", "server/app.py:72"),
                          ("/reports", "web/src/App.tsx:14")])
        by_route = {r["route"]: r for r in self.inv["routes"]}
        self.assertEqual(by_route["/api/v1/items"]["mentioned_in"], ["docs/clients.md"])
        # Parameters match template literals: /api/items/${id}/label is a use of the label route.
        self.assertEqual(by_route["/api/items/<int:item_id>/label"]["mentioned_in"], ["web/src/pages/Item.tsx"])
        self.assertEqual(by_route["/items/:id"]["mentioned_in"], ["web/src/pages/Home.tsx"])
        self.assertEqual(len(self.inv["routes"]), len({(r["route"], r["location"]) for r in self.inv["routes"]}))

    def test_tooling_tests_markers_and_schema(self):
        self.assertEqual([(r["source"], r["name"]) for r in self.inv["uninvoked_scripts"]],
                         [("Makefile", "protos"), ("package.json", "test:jest")])
        self.assertEqual(self.inv["unreferenced_files"], [{"path": "docs/v1-migration.md", "kind": "doc"},
                                                          {"path": "server/db/seed_demo.sql", "kind": "sql"}])
        self.assertEqual(names(self.inv["skipped_tests"], "location"), ["tests/test_items.py:10"])
        self.assertEqual(self.inv["commented_code"], [{"location": "server/utils.py:17-22", "lines": 6}])
        self.assertEqual([(m["marker"], m["date"], m["overdue"], m["location"]) for m in self.inv["markers"]],
                         [("ended", "2025-03-31", True, "server/ab_test.py:1"),
                          ("deprecated", "2024-01", True, "server/app.py:47"),
                          ("remove after", "2025-06-30", True, "server/compat.py:1")])
        self.assertFalse(inventory.inventory(FIXTURE, today="2024-01-01")["markers"][2]["overdue"])
        self.assertEqual(self.inv["sql_tables_unreferenced"], [{"table": "old_audit_log", "location": "server/db/schema.sql:27"}])
        self.assertEqual([(c["table"], c["column"], c["location"]) for c in self.inv["sql_columns_unreferenced"]],
                         [("items", "legacy_sku", "server/db/schema.sql:7"), ("users", "fax_number", "server/db/schema.sql:14")])

    def test_units_tag_rows(self):
        self.assertNotIn("by_unit", self.inv)
        self.assertEqual(self.tagged["by_unit"]["UN-03"], 4)  # Schema rows go to the most specific unit.
        self.assertEqual(self.tagged["sql_tables_unreferenced"][0]["unit"], "UN-03")
        self.assertEqual(self.tagged["env_declared_not_read"][0]["unit"], "UN-05")
        self.assertEqual(self.tagged["unreferenced_symbols"][0]["unit"], "UN-01")
        self.assertEqual(self.tagged["truncated"], {})
        self.assertEqual(self.tagged["limits"]["rows"], inventory.MAX_ROWS)

    def test_edge_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            (repo / "node_modules" / "x").mkdir(parents=True)
            (repo / "node_modules" / "x" / "dead.py").write_text("def hidden():\n    pass\n", encoding="utf-8")
            (repo / "pkg").mkdir()
            (repo / "pkg" / "plugins.py").write_text(
                "@register\ndef via_decorator():\n    pass\n\n\ndef by_name():\n    pass\n\n\ndef dead():\n    pass\n",
                encoding="utf-8")
            (repo / "pkg" / "main.py").write_text('import pkg.plugins as p\nHANDLER = "by_name"\nprint(p, HANDLER)\n',
                                                  encoding="utf-8")
            (repo / "ui.tsx").write_text("export default function Card() {}\nconst k = `chip-${x}`;\nconsole.log(k);\n", encoding="utf-8")
            (repo / "a.css").write_text(".chip-red { }\n.chip { }\n.gone { }\n", encoding="utf-8")
            (repo / ".env").write_text("REAL_SECRET=hunter2\n", encoding="utf-8")
            (repo / "pyproject.toml").write_text(
                '[project]\nname = "x"\ndependencies = [\n  "attrs>=23",\n  "requests",\n]\n', encoding="utf-8")
            (repo / "go.mod").write_text("module x\n\nrequire (\n\tgithub.com/pkg/errors v0.9.1\n)\n", encoding="utf-8")
            (repo / "Cargo.toml").write_text('[package]\nname = "x"\n\n[dependencies]\nserde = "1"\n', encoding="utf-8")
            (repo / "lib.rs").write_text("use serde::Serialize;\n", encoding="utf-8")
            outside = Path(tmp) / "outside.py"
            outside.write_text("def linked():\n    pass\n", encoding="utf-8")
            (repo / "link.py").symlink_to(outside)
            inv = inventory.inventory(repo, today=TODAY)
            self.assertEqual(names(inv["unreferenced_symbols"]), ["dead"])
            self.assertEqual(inv["unreferenced_symbols"][0]["kind"], "def")
            self.assertEqual(inv["decorated_symbols_skipped"], 1)
            self.assertEqual(names(inv["css_unreferenced"], "class"), ["chip", "gone"])  # chip-red is under a dynamic prefix.
            self.assertNotIn("hunter2", json.dumps(inv))
            self.assertNotIn("REAL_SECRET", json.dumps(inv))
            self.assertEqual(sorted((r["manifest"], r["name"]) for r in inv["unimported_dependencies"]),
                             [("go.mod", "github.com/pkg/errors"), ("pyproject.toml", "attrs"),
                              ("pyproject.toml", "requests")])
            self.assertEqual(inv["env_read_not_declared"], [])  # No example env file: nothing to compare against.

    def test_caps_apply_after_measuring(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "a.css").write_text("".join(f".unused-{n} {{ }}\n" for n in range(inventory.MAX_ROWS + 7)),
                                        encoding="utf-8")
            inv = inventory.inventory(repo, today=TODAY)
            self.assertEqual(len(inv["css_unreferenced"]), inventory.MAX_ROWS)
            self.assertEqual(inv["truncated"], {"css_unreferenced": 7})

    def test_cli_rejects_bad_units_and_today(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "units.json"
            bad.write_text(json.dumps({"app": "X", "purpose": []}), encoding="utf-8")
            r = run("inventory.py", FIXTURE, "--units", bad, "--out", Path(tmp) / "inv.json")
            self.assertEqual(r.returncode, 2)
            self.assertIn("units", r.stderr)
            self.assertFalse((Path(tmp) / "inv.json").exists())
            self.assertEqual(run("inventory.py", FIXTURE, "--today", "soon", "--out", Path(tmp) / "inv.json").returncode, 2)


class RecordTests(unittest.TestCase):
    def bad(self, mutate, message, finding="P-001"):
        data = copy.deepcopy(SAMPLE)
        mutate(next(f for f in data["findings"] if f["id"] == finding))
        with self.assertRaisesRegex(findings.RecordError, message):
            findings.check_findings(data, findings.check_units(copy.deepcopy(UNITS)))

    def test_samples_and_units_are_valid(self):
        units = findings.check_units(copy.deepcopy(UNITS))
        findings.check_findings(copy.deepcopy(SAMPLE), units)
        findings.check_findings(copy.deepcopy(SAMPLE_JA), units)

    def test_samples_cover_every_family_and_agree(self):
        for sample in (SAMPLE, SAMPLE_JA):
            self.assertEqual({p["name"][:2] for p in sample["perspectives"]}, set(findings.FAMILIES))
            self.assertEqual({f["perspective"][:2] for f in sample["findings"]}, set(findings.FAMILIES))
        strip = lambda d: [(f["id"], f["severity"], f["confidence"], f["location"], f.get("occurrences"),  # noqa: E731
                            f["perspective"], f["unit_ref"], f.get("entry_ref"), f.get("purpose_ref"),
                            f["subtraction"]["action"], f["validation"]["verdict"]) for f in d["findings"]]
        self.assertEqual(strip(SAMPLE), strip(SAMPLE_JA))
        self.assertEqual(len(SAMPLE["decisions"]), len(SAMPLE_JA["decisions"]))

    def test_samples_carry_purpose_findings(self):
        units = {p["id"]: p for p in UNITS["purpose"]}
        purpose = [f for f in SAMPLE["findings"] if f["perspective"][:2] in findings.PURPOSE_FAMILIES]
        self.assertGreaterEqual(len(purpose), 4)
        self.assertTrue(any(units[f["purpose_ref"]]["source"] == "inferred" for f in purpose))
        dependent = [f["id"] for f in SAMPLE["findings"] if f["confidence"] == "Purpose-dependent"]
        self.assertEqual(dependent, ["P-021"])
        self.assertTrue(any(line.startswith("P-021") for line in SAMPLE["decisions"]))

    def test_rejects_bad_fields(self):
        self.bad(lambda f: f.update(id="U-001"), "P- and three digits")
        self.bad(lambda f: f.update(unit_ref="UN-99"), "not a unit in units.json")
        self.bad(lambda f: f.update(unit_ref="server"), "unit id")
        self.bad(lambda f: f.update(entry_ref="EP-99"), "not an entry point")
        self.bad(lambda f: f.update(location="/etc/passwd:1"), "repository-relative")
        self.bad(lambda f: f.update(location="../x.py:3"), "repository-relative")
        self.bad(lambda f: f.update(perspective="AX2"), "hunt step")
        self.bad(lambda f: f.update(basis=""), "basis: required")
        self.bad(lambda f: f.update(risk=""), "risk: required")
        self.bad(lambda f: f.update(confidence="Runtime-dependent"), "confidence")
        self.bad(lambda f: f.update(severity="Low"), "severity order")
        self.bad(lambda f: f["validation"].update(verdict="Maybe"), "verdict")
        self.bad(lambda f: f["validation"].pop("dynamic_checked"), "dynamic_checked: required")
        self.bad(lambda f: f["subtraction"].update(action="delete"), "subtraction.action")
        self.bad(lambda f: f["subtraction"].pop("remains"), "remains: required")
        self.bad(lambda f: f.pop("subtraction"), "subtraction: required")
        self.bad(lambda f: f.update(references=[{"url": "javascript:alert(1)"}]), "http")

    def test_purpose_and_confidence_rules(self):
        self.bad(lambda f: f.pop("purpose_ref"), "purpose_ref: required", "P-007")  # PX needs its purpose item.
        self.bad(lambda f: f.update(purpose_ref="PB-99"), "not a purpose item", "P-007")
        self.bad(lambda f: f.update(confidence="Confirmed"), "cannot be Confirmed", "P-021")  # PB-06 is inferred.
        self.bad(lambda f: f.pop("purpose_ref"), "purpose_ref: required", "P-021")
        self.bad(lambda f: f["validation"].update(verdict="Valid"), "at most Likely", "P-003")
        self.bad(lambda f: f["validation"].update(verdict="Valid"), "at most Likely", "P-021")

    def test_units_rules(self):
        def bad(mutate, message):
            units = copy.deepcopy(UNITS)
            mutate(units)
            with self.assertRaisesRegex(findings.RecordError, message):
                findings.check_units(units)
        bad(lambda u: u["purpose"][0].update(id="P1"), "PB- and two or three digits")
        bad(lambda u: u["purpose"][0].update(source="guessed"), "source")
        bad(lambda u: u.update(purpose=[p for p in u["purpose"] if p["kind"] != "job"]), "no core job")
        bad(lambda u: u["entry_points"][0].update(exposure="world"), "exposure")
        bad(lambda u: u["entry_points"][1].update(id="EP-01"), "duplicate")
        bad(lambda u: u["consumers"].append(dict(u["consumers"][0])), "duplicate")
        bad(lambda u: u["consumers"][0].pop("in_repo"), "in_repo")
        bad(lambda u: u.update(consumers=[]), "consumers")
        bad(lambda u: u["units"][0].update(paths=["../other"]), "repository-relative")
        bad(lambda u: u["units"][0]["entry_points"].append("EP-99"), "not an entry point")
        bad(lambda u: u["units"][0]["entry_points"].remove("EP-06"), "EP-06 belong to no unit")

    def test_merge_replaces_fields_and_refuses_bad_fragments(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "units.json").write_text(json.dumps(UNITS), encoding="utf-8")
            first = {k: v for k, v in SAMPLE.items() if k != "findings"}
            first["findings"] = SAMPLE["findings"][:2]
            frag1, frag2, bad = out / "f1.json", out / "f2.json", out / "bad.json"
            frag1.write_text(json.dumps(first), encoding="utf-8")
            frag2.write_text(json.dumps({"findings": [{"id": "P-002", "status": "Fixed"}]}), encoding="utf-8")
            bad.write_text(json.dumps({"findings": [{"id": "P-001", "unit_ref": "UN-42"}]}), encoding="utf-8")
            target = out / "findings.json"
            self.assertEqual(run("findings.py", "merge", target, frag1, frag2).returncode, 0)
            merged = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual([f["status"] for f in merged["findings"]], ["Open", "Fixed"])
            before = target.read_bytes()
            r = run("findings.py", "merge", target, bad)
            self.assertEqual(r.returncode, 2)
            self.assertIn("UN-42", r.stderr)
            self.assertEqual(target.read_bytes(), before)

    def test_merge_appends_list_sections_and_removes_exact_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            target = out / "findings.json"
            target.write_text(json.dumps(SAMPLE), encoding="utf-8")
            line = "report.pdf not produced: no PDF engine"
            add, perspective, drop, bad = (out / n for n in ("add.json", "p.json", "drop.json", "bad.json"))
            add.write_text(json.dumps({"limitations": [line, SAMPLE["limitations"][0]]}), encoding="utf-8")
            perspective.write_text(json.dumps({"perspectives": [{"name": "OB Over-built", "result": "3 findings"}]}),
                                   encoding="utf-8")
            drop.write_text(json.dumps({"remove": {"limitations": [line]}}), encoding="utf-8")
            bad.write_text(json.dumps({"remove": {"limitations": ["not there"]}}), encoding="utf-8")
            self.assertEqual(run("findings.py", "merge", target, add, perspective).returncode, 0)
            merged = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(merged["limitations"], [*SAMPLE["limitations"], line])
            self.assertEqual(len(merged["perspectives"]), len(SAMPLE["perspectives"]))
            self.assertEqual(next(p for p in merged["perspectives"] if p["name"] == "OB Over-built")["result"], "3 findings")
            self.assertEqual(run("findings.py", "merge", target, drop).returncode, 0)
            self.assertEqual(json.loads(target.read_text(encoding="utf-8"))["limitations"], SAMPLE["limitations"])
            r = run("findings.py", "merge", target, bad)
            self.assertEqual(r.returncode, 2)
            self.assertIn("no such line", r.stderr)

    def test_merge_accepts_any_order_and_renumber_restores_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "units.json").write_text(json.dumps(UNITS), encoding="utf-8")
            data = copy.deepcopy(SAMPLE)
            n = len(data["findings"])
            for i, f in enumerate(data["findings"]):  # Lowest severity first: out of order.
                f["id"] = f"P-{n - i:03d}"
            high = next(f for f in data["findings"] if f["severity"] == "High")
            data["next_steps"] = [f"remove {high['id']} first"]
            data["decisions"] = []
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
            self.assertEqual(renumbered["next_steps"], [f"remove {moved} first"])
            self.assertEqual([f["id"] for f in renumbered["findings"]], [f["id"] for f in SAMPLE["findings"]])
            self.assertEqual(run("findings.py", "check", target).returncode, 0)
            before = target.read_bytes()
            r = run("findings.py", "renumber", target)
            self.assertIn("already in order", r.stdout)
            self.assertEqual(target.read_bytes(), before)

    def test_samples_are_already_in_renumber_order(self):
        for sample in (SAMPLE, SAMPLE_JA):
            mapping = findings.renumber_map(sample["findings"])
            self.assertEqual([k for k, v in mapping.items() if k != v], [])

    def test_units_merge_by_id_and_protects_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            target, f0, f1 = out / "units.json", out / "u0.json", out / "u1.json"
            first = {**UNITS, "consumers": UNITS["consumers"][:2]}
            f0.write_text(json.dumps(first), encoding="utf-8")
            f1.write_text(json.dumps({"consumers": UNITS["consumers"][1:],
                                      "purpose": [{**UNITS["purpose"][0], "text": "Replaced."}]}), encoding="utf-8")
            r = run("findings.py", "units", target, f0, f1)
            self.assertEqual(r.returncode, 0, r.stderr)
            merged = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(names(merged["consumers"]), names(UNITS["consumers"]))
            self.assertEqual(merged["purpose"][0]["text"], "Replaced.")
            self.assertEqual(len(merged["purpose"]), len(UNITS["purpose"]))
        with tempfile.TemporaryDirectory() as tmp:
            # A units change must keep every reference in findings.json beside it valid: refused, nothing written.
            out = Path(tmp)
            target, frag = out / "units.json", out / "frag.json"
            (out / "findings.json").write_text(json.dumps(SAMPLE), encoding="utf-8")
            partial = copy.deepcopy(UNITS)
            partial["units"] = [u for u in partial["units"] if u["id"] != "UN-03"]
            frag.write_text(json.dumps(partial), encoding="utf-8")
            r = run("findings.py", "units", target, frag)
            self.assertEqual(r.returncode, 2)
            self.assertIn("UN-03", r.stderr)
            self.assertFalse(target.exists())
            # Making a documented purpose item inferred breaks the Confirmed findings resting on it.
            inferred = copy.deepcopy(UNITS)
            next(p for p in inferred["purpose"] if p["id"] == "PB-05")["source"] = "inferred"
            frag.write_text(json.dumps(inferred), encoding="utf-8")
            r = run("findings.py", "units", target, frag)
            self.assertEqual(r.returncode, 2)
            self.assertIn("cannot be Confirmed", r.stderr)


class RenderTests(unittest.TestCase):
    def test_common_format_mapping(self):
        common = render.to_common(copy.deepcopy(SAMPLE), "en", UNITS, FIXTURE)
        by_id = {f["id"]: f for f in common["findings"]}
        field = lambda fid, label: next(x["text"] for x in by_id[fid]["fields"] if x["label"] == label)  # noqa: E731
        self.assertEqual(by_id["P-002"]["action"], {"label": "Subtract", "text": "Remove: The /debug/dump route."})
        self.assertNotIn("Subtraction", [x["label"] for x in by_id["P-002"]["fields"]])
        self.assertEqual(by_id["P-003"]["action"]["label"], "Verify first")
        self.assertEqual(field("P-003", "Subtraction")[:8], "Remove: ")
        self.assertTrue(by_id["P-037"]["excluded"])
        self.assertNotIn("action", by_id["P-037"])
        self.assertEqual(field("P-021", "Purpose item"),
                         "PB-06: Ordinary household equipment: a browser or phone, no barcode or label printers. (inferred)")
        self.assertEqual(field("P-002", "Review unit"), "UN-01: Server API")
        self.assertEqual(field("P-002", "Entry point"), "EP-06: GET /debug/dump")
        self.assertEqual(by_id["P-012"]["category"], "Over-built")
        self.assertIn("app.config.items()", "\n".join(by_id["P-002"]["snippet"]["lines"]))
        self.assertNotIn("snippet", by_id["P-015"])  # .env.example is never excerpted.
        self.assertEqual(common["report"]["running_footer"], "PRUNE REVIEW")

    def test_subtraction_summary_leads_next_steps(self):
        now, reduce, decide = render.subtraction_groups(SAMPLE["findings"])
        self.assertEqual(reduce, ["P-005", "P-014", "P-027"])
        self.assertEqual(decide, ["P-003", "P-008", "P-009", "P-012", "P-021", "P-022", "P-024", "P-025"])
        self.assertEqual(len(now), 25)
        self.assertNotIn("P-037", now + reduce + decide)
        common = render.to_common(copy.deepcopy(SAMPLE), "en", UNITS)
        self.assertTrue(common["next_steps"][0].startswith("Subtraction - remove now (25): P-001, P-002"))
        self.assertEqual(common["next_steps"][3:], SAMPLE["next_steps"])
        ja = render.to_common(copy.deepcopy(SAMPLE_JA), "ja", UNITS)
        self.assertTrue(ja["next_steps"][1].startswith("引き算 - 縮小・統合 (3件)"))
        unlikely = copy.deepcopy(SAMPLE["findings"])
        unlikely[0]["validation"]["verdict"] = "Unlikely"
        self.assertNotIn("P-001", sum(render.subtraction_groups(unlikely), []))

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
            shutil.copy(ROOT / "examples" / "units.sample.json", out / "units.json")
            shutil.copy(ROOT / "examples" / "findings.sample.ja.json", out / "findings.json")
            self.assertEqual(run("inventory.py", FIXTURE, "--units", out / "units.json",
                                 "--out", out / "inventory.json").returncode, 0)
            r = run("render.py", out / "findings.json", "--out", out, "--lang", "ja", "--repo", FIXTURE, "--no-pdf")
            self.assertEqual(r.returncode, 0, r.stderr)
            page = (out / "report.html").read_text(encoding="utf-8")
            self.assertIn('content:"不要要素診断"', page)
            self.assertIn("不要要素診断書", page)
            self.assertIn("引き算 - 今すぐ削除", page)
            self.assertIn("PB-05: Social, sharing or comparison features between households. (文書化済み)", page)
            # --no-pdf needs its limitation; with it, the contract holds.
            self.assertEqual(run("contract_check.py", out, "--no-pdf").returncode, 1)
            data = json.loads((out / "findings.json").read_text(encoding="utf-8"))
            data["limitations"].append("report.pdf not produced: no PDF engine in the test environment")
            (out / "findings.json").write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            stale = run("contract_check.py", out, "--no-pdf")
            self.assertEqual(stale.returncode, 1)
            self.assertIn("stale", stale.stderr)
            self.assertIn("--lang ja --repo <repo> --no-pdf", stale.stderr)
            run("render.py", out / "findings.json", "--out", out, "--lang", "ja", "--no-pdf")
            ok = run("contract_check.py", out, "--no-pdf")
            self.assertEqual(ok.returncode, 0, ok.stderr)
            (out / "notes.txt").write_text("x", encoding="utf-8")
            self.assertIn("notes.txt", run("contract_check.py", out, "--no-pdf").stderr)
            (out / "notes.txt").unlink()
            # Every family recorded, nothing Unverified, every Purpose-dependent finding in decisions.
            data = json.loads((out / "findings.json").read_text(encoding="utf-8"))
            data["perspectives"] = [p for p in data["perspectives"] if not p["name"].startswith("OB")]
            data["findings"][0]["validation"]["verdict"] = "Unverified"
            data["decisions"] = [d for d in data["decisions"] if not d.startswith("P-021")]
            (out / "findings.json").write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            run("render.py", out / "findings.json", "--out", out, "--lang", "ja", "--no-pdf")
            r = run("contract_check.py", out, "--no-pdf")
            self.assertEqual(r.returncode, 1)
            self.assertIn("no entry for OB", r.stderr)
            self.assertIn("P-001 still Unverified", r.stderr)
            self.assertIn("decisions: P-021", r.stderr)
            self.assertNotIn("stale", r.stderr)
            (out / "units.json").unlink()
            self.assertIn("units.json: missing", run("contract_check.py", out, "--no-pdf").stderr)


if __name__ == "__main__":
    unittest.main()
