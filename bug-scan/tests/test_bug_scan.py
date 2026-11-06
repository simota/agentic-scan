"""Offline tests for the bug-scan scripts. They build throwaway git repositories and records."""
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "bug-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import common  # noqa: E402
import compare  # noqa: E402
import contract_check  # noqa: E402
import diagrams  # noqa: E402
import findings  # noqa: E402
import history  # noqa: E402
import import_findings  # noqa: E402
import ledger  # noqa: E402
import render  # noqa: E402
import surfaces  # noqa: E402


def sample():
    return (common.load_json(ROOT / "examples" / "findings.sample.json"), common.load_json(ROOT / "examples" / "surfaces.sample.json"),
            common.load_json(ROOT / "examples" / "history.sample.json"))


def run_git(repo, *args, env=None):
    base = {**os.environ, "GIT_AUTHOR_NAME": "Secret Person", "GIT_AUTHOR_EMAIL": "secret.person@corp.invalidmail.io",
            "GIT_COMMITTER_NAME": "Secret Person", "GIT_COMMITTER_EMAIL": "secret.person@corp.invalidmail.io",
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env={**base, **(env or {})})


class TempDir(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="bug-scan-test-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def commit(self, repo, path, text, message, date="2026-03-01T00:00:00"):
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        run_git(repo, "add", "-A")
        run_git(repo, "commit", "-m", message, env={"GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date})

    def repo(self):
        repo = self.dir / "repo"
        repo.mkdir()
        run_git(repo, "init", "-q", "-b", "main")
        self.commit(repo, "api/orders/validate.py", "def check(x):\n    return x != ''\n", "feat: add validation")
        self.commit(repo, "api/orders/validate.py", "def check(x):\n    return x.strip() != ''\n", "fix: reject blank input", "2026-03-02T00:00:00")
        self.commit(repo, "api/orders/other.py", "def extra():\n    pass\n", "fix: add a missing handler", "2026-03-03T00:00:00")
        self.commit(repo, "tests/test_orders.py", "def test_x():\n    pass\n", "test: cover orders", "2026-03-04T00:00:00")
        return repo


class HistoryTests(TempDir):
    def test_fix_is_traced_to_the_commit_that_wrote_the_line(self):
        data = history.mine(self.repo(), "", 200, 2, 5000)
        self.assertEqual(data["quality"]["commits"], 4)
        self.assertEqual(data["quality"]["fix_by_prefix"], 2)
        reject = next(c for c in data["fix_candidates"] if "reject blank" in c["subject"])
        self.assertFalse(reject["pure_addition"])
        self.assertEqual(reject["origins"][0]["kind"], "feature")
        self.assertEqual(reject["files"], ["api/orders/validate.py"])

    def test_pure_addition_has_no_origin(self):
        data = history.mine(self.repo(), "", 200, 2, 5000)
        added = next(c for c in data["fix_candidates"] if "missing handler" in c["subject"])
        self.assertTrue(added["pure_addition"])
        self.assertEqual(added["origins"], [])

    def test_no_author_or_email_reaches_the_output(self):
        repo = self.repo()
        self.commit(repo, "a.py", "x = 1\n", "fix: report from someone@corp.invalidmail.io", "2026-03-05T00:00:00")
        text = json.dumps(history.mine(repo, "", 200, 2, 5000))
        self.assertNotIn("Secret Person", text)
        self.assertNotIn("invalidmail", text)

    def test_blame_limit_marks_what_was_skipped(self):
        data = history.mine(self.repo(), "", 1, 2, 5000)
        self.assertTrue(any(c.get("origins_skipped") for c in data["fix_candidates"]))

    def test_origin_older_than_the_window_can_still_be_cited(self):
        repo = self.dir / "old"
        repo.mkdir()
        run_git(repo, "init", "-q", "-b", "main")
        self.commit(repo, "a.py", "x = 1\n", "feat: a", "2020-01-01T00:00:00")
        self.commit(repo, "a.py", "x = 2\n", "fix: a", "2026-03-02T00:00:00")
        data = history.mine(repo, "2026-01-01", 200, 2, 5000)
        origin = data["fix_candidates"][0]["origins"][0]
        self.assertEqual((origin["date"], origin["kind"]), ("2020-01-01", "feature"))
        self.assertEqual(len(origin["commit"]), 40)
        self.assertIn(origin["commit"], data["commits"])

    def test_module_counts_and_tests(self):
        data = history.mine(self.repo(), "", 200, 2, 5000)
        orders = next(m for m in data["modules"] if m["module"] == "api/orders")
        self.assertEqual(orders["commits"], 3)
        self.assertEqual(orders["test_files"], 1)

    def test_releases_use_tags_or_say_unknown(self):
        repo = self.repo()
        head = common.git(repo, "rev-parse", "HEAD").strip()
        self.assertEqual(history.releases(repo, [head])[head]["basis"], "UNKNOWN")
        run_git(repo, "tag", "v1.0")
        self.assertEqual(history.releases(repo, [head])[head]["first"], "v1.0")

    def test_not_a_repository_is_refused(self):
        with self.assertRaises(common.RecordError):
            history.mine(self.dir, "", 200, 2, 5000)


class SurfaceTests(TempDir):
    def test_scan_finds_each_kind_and_links(self):
        root = self.dir / "app"
        (root / "app" / "checkout").mkdir(parents=True)
        (root / "api").mkdir()
        (root / "worker").mkdir()
        (root / "migrations").mkdir()
        (root / "app" / "checkout" / "page.tsx").write_text("fetch('/orders')\n", encoding="utf-8")
        (root / "api" / "routes.py").write_text("@app.post('/orders')\ndef create():\n    db.orders.insert()\n    os.environ['API_KEY']\n    get('https://pay.vendor.io/x')\n", encoding="utf-8")
        (root / "worker" / "job.py").write_text("@shared_task\ndef refund():\n    pass\n", encoding="utf-8")
        (root / "migrations" / "1.sql").write_text("CREATE TABLE orders (id int);\n", encoding="utf-8")
        data = surfaces.scan(root)
        by_kind = {k: [s["name"] for s in data["surfaces"] if s["kind"] == k] for k in common.SURFACE_KINDS}
        self.assertEqual(by_kind["screen"], ["/checkout"])
        self.assertEqual(by_kind["api"], ["POST /orders"])
        self.assertEqual(by_kind["job"], ["refund"])
        self.assertEqual(by_kind["db"], ["orders"])
        self.assertEqual(by_kind["ext"], ["pay.vendor.io"])
        self.assertEqual(by_kind["cfg"], ["API_KEY"])
        ids = {s["name"]: s["id"] for s in data["surfaces"]}
        pairs = {(l["from"], l["to"]) for l in data["links"]}
        self.assertIn((ids["/checkout"], ids["POST /orders"]), pairs)
        self.assertIn((ids["POST /orders"], ids["orders"]), pairs)
        self.assertTrue(all(s["basis"] == "inferred" for s in data["surfaces"]))
        self.assertTrue(all(l["basis"] == "inferred" for l in data["links"]))

    def test_tests_and_vendored_code_are_skipped_and_source_is_not_stored(self):
        root = self.dir / "app"
        (root / "tests").mkdir(parents=True)
        (root / "node_modules" / "x").mkdir(parents=True)
        (root / "tests" / "test_a.py").write_text("@app.get('/from-test')\n", encoding="utf-8")
        (root / "node_modules" / "x" / "i.js").write_text("app.get('/from-vendor', h)\n", encoding="utf-8")
        (root / "a.py").write_text("@app.get('/real')\nsecret_body = 'DO-NOT-STORE'\n", encoding="utf-8")
        data = surfaces.scan(root)
        self.assertEqual([s["name"] for s in data["surfaces"]], ["GET /real"])
        self.assertNotIn("DO-NOT-STORE", json.dumps(data))

    def test_merge_confirms_and_removes_links_and_refuses_bad_ones(self):
        path = self.dir / "s.json"
        common.write_json(path, dict(surfaces=[dict(id="SC-01", kind="screen", name="a", basis="inferred"), dict(id="API-01", kind="api", name="b", basis="inferred")],
                                     links=[{"from": "SC-01", "to": "API-01", "basis": "inferred"}]))
        fragment = self.dir / "f.json"
        common.write_json(fragment, {"links": [{"from": "SC-01", "to": "API-01", "basis": "traced"}]})
        surfaces.merge(path, [fragment])
        self.assertEqual(common.load_json(path)["links"][0]["basis"], "traced")
        common.write_json(fragment, {"links": [{"from": "SC-01", "to": "API-99", "basis": "traced"}]})
        with self.assertRaises(common.RecordError):
            surfaces.merge(path, [fragment])


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.record, self.surfaces, self.history = sample()

    def errors(self, record=None):
        return findings.contract_errors(record if record is not None else self.record, self.surfaces, self.history)

    def by_id(self, record, fid):
        return next(f for f in record["findings"] if f["id"] == fid)

    def assert_refused(self, mutate, fragment):
        record = copy.deepcopy(self.record)
        mutate(record)
        errors = self.errors(record)
        self.assertTrue(any(fragment in e for e in errors), f"expected {fragment!r} in {errors[:5]}")

    def test_sample_passes(self):
        self.assertEqual(self.errors(), [])

    def test_each_rule_refuses(self):
        def event(record, strength):
            return next(e for e in record["fix_events"] if (e.get("origin") or {}).get("strength") == strength)

        cases = [
            (lambda r: event(r, "Traced")["origin"].pop("reason"), "Traced needs"),
            (lambda r: event(r, "Blamed")["origin"].update(commits=[]), "Blamed needs"),
            (lambda r: event(r, "Unattributable")["origin"].update(commits=["abcd1234"]), "Unattributable cannot"),
            (lambda r: r["fix_events"][0].update(commit="deadbeef"), "not in history.json"),
            (lambda r: r["fix_events"][0].update(gate_missed=["G-99"]), "gate G-99"),
            (lambda r: r["fix_events"][0].update(module="nowhere"), "not a module"),
            (lambda r: r["meta"].pop("sample"), "meta.sample"),
            (lambda r: r["meta"]["sample"].update(read=1), "meta.sample.read"),
            (lambda r: r["meta"]["sample"].update(candidates=999), "meta.sample.candidates"),
            (lambda r: self.by_id(r, "BG-001").pop("repro"), "repro is required"),
            (lambda r: self.by_id(r, "BG-001").pop("sibling_sites"), "sibling_sites is required"),
            (lambda r: self.by_id(r, "BG-001").pop("data_remediation"), "data_remediation is required"),
            (lambda r: self.by_id(r, "BG-001").pop("affected_releases"), "affected_releases is required"),
            (lambda r: self.by_id(r, "BG-001").pop("detection"), "detection is required"),
            (lambda r: self.by_id(r, "BG-001")["risk"].update(level="Low"), "fixed table"),
            (lambda r: self.by_id(r, "BG-001").update(events=["E-999"]), "E-999"),
            (lambda r: self.by_id(r, "BG-001").update(surfaces=[dict(id="API-99")]), "API-99"),
            (lambda r: self.by_id(r, "BG-001")["relations"].append(dict(type="blocks", to="BG-099", strength="Traced", evidence="x")), "BG-099"),
            (lambda r: self.by_id(r, "BG-001")["relations"].append(dict(type="blocks", to="BG-002", strength="Traced")), "evidence is required"),
            (lambda r: self.by_id(r, "BG-001")["repro"].update(state="verified", last_run=""), "verified reproduction"),
            (lambda r: self.by_id(r, "BG-001")["validation"].update(evidence="read it"), "path:line"),
            (lambda r: self.by_id(r, "BG-001")["validation"].update(verdict="Unverified"), "other than Unverified"),
            (lambda r: self.by_id(r, "BG-001").update(events=self.by_id(r, "BG-001")["events"][:1]), "at least 3 Traced"),
            (lambda r: self.by_id(r, "BG-001").update(author="Someone"), "unknown key 'author'"),
            (lambda r: self.by_id(r, "BG-001").update(fix="ask real.person@corp.co.jp"), "e-mail"),
            (lambda r: self.by_id(r, "BG-001")["repro"]["steps"].append("password = hunter2secret"), "secret"),
            (lambda r: self.by_id(r, "BG-002").pop("risk"), "risk"),
            (lambda r: self.by_id(r, "BG-006").pop("detection"), "detection is required"),
            (lambda r: self.by_id(r, "BG-006").pop("fixed_in"), "fixed_in is required"),
            (lambda r: r.update(checked_ok=[]), "checked_ok"),
            (lambda r: r.update(limitations=[]), "limitations"),
            (lambda r: r["perspectives"].pop(0), "BP01 is not recorded"),
            (lambda r: r["findings"].reverse(), "renumber"),
            (lambda r: r.update(next_steps=["Fix BG-777"]), "BG-777"),
            (lambda r: self.by_id(r, "BG-002").update(key=self.by_id(r, "BG-001")["key"]), "same tracking key"),
        ]
        for mutate, fragment in cases:
            with self.subTest(fragment=fragment):
                self.assert_refused(mutate, fragment)

    def test_reserved_mail_domains_are_allowed_for_synthetic_input(self):
        record = copy.deepcopy(self.record)
        self.by_id(record, "BG-001")["repro"]["steps"].append("buyer@example.com でログインする")
        self.assertEqual(self.errors(record), [])

    def test_low_records_do_not_need_the_full_range(self):
        record = copy.deepcopy(self.record)
        low = next(f for f in record["findings"] if f.get("severity") == "Low")
        for name in ("repro", "sibling_sites", "data_remediation", "affected_releases", "detection", "path", "fix"):
            low.pop(name, None)
        self.assertEqual(self.errors(record), [])

    def test_closed_records_may_omit_severity_and_risk(self):
        closed = next(f for f in self.record["findings"] if f["status"] == "Fixed")
        self.assertNotIn("severity", closed)
        self.assertNotIn("risk", closed)


class MergeTests(TempDir):
    def write(self, name, data):
        path = self.dir / name
        common.write_json(path, data)
        return path

    def base(self, **extra):
        return dict(id="BG-001", title="t", status="Open", pattern="BP01", location=["a.py:1"], **extra)

    def test_key_is_computed_stable_and_refused_in_a_fragment(self):
        out = self.dir / "findings.json"
        findings.merge(out, [self.write("a.json", dict(findings=[self.base()]))])
        key = common.load_json(out)["findings"][0]["key"]
        findings.merge(out, [self.write("b.json", dict(findings=[dict(id="BG-001", location=["a.py:99"], title="renamed")]))])
        self.assertEqual(common.load_json(out)["findings"][0]["key"], key)
        with self.assertRaises(common.RecordError):
            findings.merge(out, [self.write("c.json", dict(findings=[dict(id="BG-001", key="x")]))])

    def test_a_refused_batch_writes_nothing(self):
        out = self.dir / "findings.json"
        findings.merge(out, [self.write("a.json", dict(findings=[self.base()]))])
        before = out.read_text(encoding="utf-8")
        good = self.write("g.json", dict(next_steps=["do"]))
        bad = self.write("b.json", dict(findings=[dict(id="BG-002", title="t", status="Nope")]))
        with self.assertRaises(common.RecordError):
            findings.merge(out, [good, bad])
        self.assertEqual(out.read_text(encoding="utf-8"), before)

    def test_null_and_remove(self):
        out = self.dir / "findings.json"
        findings.merge(out, [self.write("a.json", dict(findings=[self.base(fix="x")], next_steps=["one", "two"]))])
        findings.merge(out, [self.write("b.json", dict(findings=[dict(id="BG-001", fix=None)], remove=dict(next_steps=["one"])))])
        record = common.load_json(out)
        self.assertNotIn("fix", record["findings"][0])
        self.assertEqual(record["next_steps"], ["two"])
        with self.assertRaises(common.RecordError):
            findings.merge(out, [self.write("c.json", dict(remove=dict(next_steps=["missing"])))])

    def test_duplicate_json_keys_and_nan_are_refused(self):
        path = self.dir / "dup.json"
        path.write_text('{"a": 1, "a": 2}', encoding="utf-8")
        with self.assertRaises(common.RecordError):
            common.load_json(path)
        path.write_text('{"a": NaN}', encoding="utf-8")
        with self.assertRaises(common.RecordError):
            common.load_json(path)

    def test_renumber_orders_and_rewrites_mentions_but_not_literals(self):
        out = self.dir / "findings.json"
        low = dict(id="BG-001", title="low", status="Open", severity="Low", pattern="BP01", location=["BG-001.py:1"], fix="see BG-002")
        high = dict(id="BG-002", title="high", status="Open", severity="High", pattern="BP01", location=["b.py:1"], relations=[dict(type="blocks", to="BG-001", strength="Traced", evidence="BG-001 waits")])
        done = dict(id="BG-003", title="done", status="Fixed", pattern="BP01", location=["a.py:1"], fixed_in="abcd")
        findings.merge(out, [self.write("a.json", dict(findings=[low, high, done], next_steps=["BG-002 first", "BG-002を先に"]))])
        findings.renumber(out)
        record = common.load_json(out)
        self.assertEqual([f["title"] for f in record["findings"]], ["high", "low", "done"])
        self.assertEqual(record["findings"][0]["relations"][0], dict(type="blocks", to="BG-002", strength="Traced", evidence="BG-002 waits"))
        self.assertEqual(record["findings"][1]["fix"], "see BG-001")
        self.assertEqual(record["findings"][1]["location"], ["BG-001.py:1"])
        self.assertEqual(record["next_steps"], ["BG-001 first", "BG-001を先に"])

    def test_variant_separates_a_regression_from_the_past_defect(self):
        one = dict(pattern="BP11", location=["a.py:1"], surfaces=[dict(id="API-01")])
        self.assertEqual(findings.key_of(one), findings.key_of(dict(one, location=["a.py:80"], title="renamed")))
        self.assertNotEqual(findings.key_of(one), findings.key_of(dict(one, variant="blank-only")))
        self.assertNotEqual(findings.key_of(one), findings.key_of(dict(one, pattern="BP01")))

    def test_counts_keep_traced_apart(self):
        record, _, _ = sample()
        counts = findings.counts(record)
        self.assertEqual((counts["n_high"], counts["n_defects"], counts["n_traced"], counts["n_unattributable"]), (1, 32, 15, 11))


class RenderTests(TempDir):
    def setUp(self):
        super().setUp()
        self.record, self.surfaces, self.history = sample()

    def out_dir(self, record=None):
        out = self.dir / "out"
        out.mkdir(exist_ok=True)
        common.write_json(out / "findings.json", record or self.record)
        common.write_json(out / "surfaces.json", self.surfaces)
        common.write_json(out / "history.json", self.history)
        return out

    def test_build_is_deterministic_in_both_languages(self):
        for lang in ("ja", "en"):
            with self.subTest(lang=lang):
                self.assertEqual(render.build(self.record, self.surfaces, self.history, lang), render.build(self.record, self.surfaces, self.history, lang))

    def test_every_figure_and_table_is_present(self):
        dashboard, document = render.build(self.record, self.surfaces, self.history, "ja")
        for number in range(1, 10):
            self.assertIn(f'id="fig-d{number}"', dashboard)
            self.assertIn(f'id="fig-d{number}"', document)
        self.assertEqual(dashboard.count("<svg viewBox"), 9)
        self.assertEqual(dashboard.count("<table><thead>"), 9)
        self.assertIn('href="#figures"', dashboard)

    def test_counts_agree_with_the_record(self):
        figure = {f["number"]: f for f in diagrams.figures(self.record, self.surfaces, self.history, "ja")}
        self.assertEqual(sum(r[-1] for r in figure[1]["rows"]), 32)
        self.assertEqual(sum(r[3] for r in figure[2]["rows"]), 32)
        self.assertEqual(sum(r[2] for r in figure[2]["rows"]), 15)
        self.assertEqual(sum(r[2] for r in figure[4]["rows"]), 32)

    def test_recorded_text_cannot_break_out_of_the_drawing(self):
        record = copy.deepcopy(self.record)
        payload = '"><script>alert(1)</script><svg onload=x>'
        record["findings"][0]["title"] = payload
        record["gates"][0]["name"] = payload
        record["issues"][0]["at"] = payload
        surface_catalog = copy.deepcopy(self.surfaces)
        surface_catalog["surfaces"][0]["name"] = payload
        dashboard, document = render.build(record, surface_catalog, self.history, "ja")
        self.assertNotIn("<script>alert", dashboard)
        self.assertNotIn("<script>alert", document)
        self.assertNotIn("onload=x>", document)

    def test_thin_history_omits_d1_and_d3_with_the_reason(self):
        record = copy.deepcopy(self.record)
        keep = [e for e in record["fix_events"] if e.get("type") in common.DEFECT_TYPES][:5]
        record["fix_events"] = keep
        figure = {f["number"]: f for f in diagrams.figures(record, self.surfaces, self.history, "ja")}
        self.assertIn("5", figure[1]["omitted"])
        self.assertIn("5", figure[3]["omitted"])
        self.assertIsNone(figure[2]["omitted"])
        shallow = copy.deepcopy(self.history)
        shallow["quality"]["shallow"] = True
        figure = {f["number"]: f for f in diagrams.figures(self.record, self.surfaces, shallow, "ja")}
        self.assertTrue(figure[1]["omitted"] and figure[3]["omitted"])

    def test_an_empty_record_renders(self):
        record = dict(meta=dict(project="p", date="2026-01-01", lang="en"))
        dashboard, _ = render.build(record, dict(surfaces=[], links=[]), dict(), "en")
        self.assertIn("Nothing recorded to draw", dashboard)

    def test_contract_check_end_to_end(self):
        record = copy.deepcopy(self.record)
        record["limitations"].append("report.pdf not produced: test run")
        out = self.out_dir(record)
        self.assertEqual(render.main([str(out / "findings.json"), "--out", str(out), "--no-pdf"]), 0)
        self.assertEqual(contract_check.check(out, no_pdf=True), [])
        (out / "extra.txt").write_text("x", encoding="utf-8")
        self.assertTrue(any("unexpected extra.txt" in e for e in contract_check.check(out, no_pdf=True)))
        self.assertEqual(contract_check.check(out, no_pdf=True, allow=("extra.txt",)), [])
        with open(out / "dashboard.html", "a", encoding="utf-8") as handle:
            handle.write("<!-- edited -->")
        self.assertTrue(any("fresh render" in e for e in contract_check.check(out, no_pdf=True, allow=("extra.txt",))))

    def test_no_pdf_needs_the_stated_limitation(self):
        out = self.out_dir()
        render.main([str(out / "findings.json"), "--out", str(out), "--no-pdf"])
        self.assertTrue(any("report.pdf not produced" in e for e in contract_check.check(out, no_pdf=True)))

    def test_repo_check_refuses_missing_and_past_end_and_outside(self):
        repo = self.dir / "checkout"
        repo.mkdir()
        (repo / "a.py").write_text("one\ntwo\n", encoding="utf-8")
        base = dict(id="BG-001", status="Open")
        self.assertEqual(contract_check.location_errors(dict(findings=[dict(base, location=["a.py:2"])]), repo), [])
        self.assertIn("past the end", contract_check.location_errors(dict(findings=[dict(base, location=["a.py:3"])]), repo)[0])
        self.assertIn("does not exist", contract_check.location_errors(dict(findings=[dict(base, location=["b.py:1"])]), repo)[0])
        self.assertIn("outside", contract_check.location_errors(dict(findings=[dict(base, location=["../x.py:1"])]), repo)[0])
        sibling = dict(base, location=["a.py:1"], sibling_sites=[dict(location="c.py:1", state="affected", evidence="e")])
        self.assertIn("c.py", contract_check.location_errors(dict(findings=[sibling]), repo)[0])


class LedgerTests(TempDir):
    def record(self, *items, date="2026-01-01"):
        return dict(meta=dict(date=date), findings=[dict(id=f"BG-{n:03d}", title=t, status=s, key=k, pattern="BP01", location=[f"{k}.py:1"]) for n, (k, t, s) in enumerate(items, 1)])

    def test_new_then_continuing_then_not_seen_never_fixed(self):
        book = dict(version=1, entries=[])
        _, changes = ledger.reconcile(book, self.record(("k1", "a", "Open")), "2026-01-01")
        self.assertEqual(changes["new"], ["k1"])
        _, changes = ledger.reconcile(book, self.record(("k1", "a", "Open")), "2026-02-01")
        self.assertEqual(changes["continuing"], ["k1"])
        fragment, changes = ledger.reconcile(book, self.record(), "2026-03-01")
        self.assertEqual(changes["not_seen"], ["k1"])
        self.assertEqual(book["entries"][0]["status"], "NotSeen")
        self.assertIn("does not prove a fix", fragment["decisions"][0])

    def test_first_seen_survives_and_flows_back(self):
        book = dict(version=1, entries=[])
        ledger.reconcile(book, self.record(("k1", "a", "Open")), "2026-01-01")
        fragment, _ = ledger.reconcile(book, self.record(("k1", "a", "Open")), "2026-06-01")
        self.assertEqual(fragment["findings"][0]["first_seen"], "2026-01-01")
        self.assertEqual(fragment["findings"][0]["last_seen"], "2026-06-01")

    def test_found_again_after_fixed_is_reopened(self):
        book = dict(version=1, entries=[])
        ledger.reconcile(book, self.record(("k1", "a", "Fixed")), "2026-01-01")
        fragment, changes = ledger.reconcile(book, self.record(("k1", "a", "Open")), "2026-02-01")
        self.assertEqual(changes["reopened"], ["k1"])
        self.assertEqual(fragment["findings"][0]["status"], "Reopened")

    def test_human_status_is_not_overwritten(self):
        book = dict(version=1, entries=[])
        ledger.reconcile(book, self.record(("k1", "a", "Open")), "2026-01-01")
        book["entries"][0].update(status="Accepted", owner="payments team")
        fragment, _ = ledger.reconcile(book, self.record(("k1", "a", "Open")), "2026-02-01")
        self.assertEqual(fragment["findings"][0]["status"], "Accepted")
        self.assertEqual(fragment["findings"][0]["owner"], "payments team")
        ledger.reconcile(book, self.record(), "2026-03-01")
        self.assertEqual(book["entries"][0]["status"], "Accepted")

    def test_same_file_new_key_is_a_decision_not_a_link(self):
        book = dict(version=1, entries=[])
        first = self.record(("k1", "a", "Open"))
        ledger.reconcile(book, first, "2026-01-01")
        second = self.record(("k2", "a again", "Open"))
        second["findings"][0]["location"] = first["findings"][0]["location"]
        fragment, changes = ledger.reconcile(book, second, "2026-02-01")
        self.assertEqual(changes["new"], ["k2"])
        self.assertTrue(any("may be the same defect" in d for d in fragment["decisions"]))

    def test_ledger_inside_the_repo_is_refused(self):
        repo = self.dir / "repo"
        repo.mkdir()
        record = self.dir / "findings.json"
        common.write_json(record, self.record(("k1", "a", "Open")))
        code = ledger.main(["reconcile", str(repo / "ledger.json"), str(record), "--repo", str(repo), "--fragment", str(self.dir / "f.json")])
        self.assertEqual(code, 2)
        self.assertFalse((repo / "ledger.json").exists())

    def test_fragment_merges_into_the_sample(self):
        record, surfaces_data, history_data = sample()
        book = dict(version=1, entries=[])
        fragment, _ = ledger.reconcile(book, record, record["meta"]["date"])
        findings.merge_fragment(record, fragment)
        self.assertEqual(findings.contract_errors(record, surfaces_data, history_data), [])


class CompareAndImportTests(TempDir):
    def test_compare_by_key_and_says_not_found_is_not_fixed(self):
        record, _, _ = sample()
        later = copy.deepcopy(record)
        gone = later["findings"].pop(1)
        later["findings"][0]["status"] = "Triaged"
        later["findings"][0]["risk"]["level"] = "Medium"
        later["fix_events"] = later["fix_events"][:5]
        result = compare.compare(record, later)
        self.assertEqual([r["key"] for r in result["not_found_again"]], [gone["key"]])
        changed = next(r for r in result["persisting"] if r["changes"])
        self.assertEqual(changed["changes"]["status"]["after"], "Triaged")
        self.assertIn("risk", changed["changes"])
        self.assertIn("does not prove a fix", compare.markdown(result))
        self.assertTrue(result["patterns"])

    def test_compare_warns_when_scopes_differ(self):
        record, _, _ = sample()
        later = copy.deepcopy(record)
        later["meta"]["scope"] = "api/ only"
        self.assertIn("different scopes", compare.markdown(compare.compare(record, later)))

    def test_import_reads_only_common_fields_and_keeps_ids_apart(self):
        other = dict(findings=[
            dict(id="F-001", title="t", severity="High", location="a.py:1", impact="i", request="GET /x", validation=dict(verdict="Valid")),
            dict(id="F-002", title="false", severity="High", location=["b.py:1"], validation=dict(verdict="FalsePositive")),
            dict(id="F-003", title="mail a@corp.co.jp", severity="Low", location=["c.py:2", "not a location"], validation=dict(verdict="Valid"))])
        fragment, skipped = import_findings.to_fragment(other, "security-scan")
        self.assertEqual(skipped, 1)
        self.assertEqual([i["key"] for i in fragment["imports"]], ["security-scan:F-001", "security-scan:F-003"])
        self.assertEqual(set(fragment["imports"][0]), {"key", "scan", "title", "severity", "location", "impact"})
        self.assertEqual(fragment["imports"][1]["location"], ["c.py:2"])
        self.assertNotIn("corp.co.jp", fragment["imports"][1]["title"])
        record = dict(meta=dict(project="p"))
        findings.merge_fragment(record, fragment)
        self.assertEqual(findings.shape_errors(record), [])

    def test_import_refuses_what_is_not_findings_shaped(self):
        with self.assertRaises(common.RecordError):
            import_findings.to_fragment(dict(proposals=[]), "brand-feature-scan")
        with self.assertRaises(common.RecordError):
            import_findings.to_fragment(dict(findings=[]), "../evil")


class RealRepositoryIsUntouched(TempDir):
    def test_scanning_changes_nothing_in_the_repository(self):
        repo = self.repo_with_file()
        before = common.git(repo, "status", "--porcelain")
        head = common.git(repo, "rev-parse", "HEAD")
        history.mine(repo, "", 200, 2, 5000)
        surfaces.scan(repo)
        self.assertEqual(common.git(repo, "status", "--porcelain"), before)
        self.assertEqual(common.git(repo, "rev-parse", "HEAD"), head)

    def repo_with_file(self):
        repo = self.dir / "r"
        repo.mkdir()
        run_git(repo, "init", "-q", "-b", "main")
        self.commit(repo, "a.py", "x = 1\n", "feat: a")
        return repo


class GitHardening(TempDir):
    def test_repository_hooks_and_diff_drivers_do_not_run(self):
        repo = self.dir / "r"
        repo.mkdir()
        run_git(repo, "init", "-q", "-b", "main")
        self.commit(repo, "a.py", "x = 1\n", "feat: a")
        self.commit(repo, "a.py", "x = 2\n", "fix: a", "2026-03-02T00:00:00")
        marker = self.dir / "pwned"
        script = self.dir / "evil.sh"
        script.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
        script.chmod(0o755)
        run_git(repo, "config", "core.fsmonitor", str(script))
        run_git(repo, "config", "diff.external", str(script))
        (repo / ".gitattributes").write_text("*.py diff=evil\n", encoding="utf-8")
        run_git(repo, "config", "diff.evil.textconv", str(script))
        history.mine(repo, "", 200, 2, 5000)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
