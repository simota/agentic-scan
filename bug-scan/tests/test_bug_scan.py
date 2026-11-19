"""Offline tests for the bug-scan scripts. They build throwaway git repositories and records."""
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "bug-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import common  # noqa: E402
import compare  # noqa: E402
import contract_check  # noqa: E402
import csv  # noqa: E402
import io  # noqa: E402
import diagrams  # noqa: E402
import export  # noqa: E402
import findings  # noqa: E402
import history  # noqa: E402
import impact  # noqa: E402
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

    def test_one_blame_per_file_matches_one_blame_per_hunk(self):
        repo = self.dir / "hunks"
        repo.mkdir()
        run_git(repo, "init", "-q", "-b", "main")
        self.commit(repo, "a.py", "".join(f"line{i}\n" for i in range(1, 21)), "feat: a", "2026-01-01T00:00:00")
        self.commit(repo, "a.py", "".join(f"line{i}\n" if i % 7 else f"LINE{i}\n" for i in range(1, 21)), "feat: b", "2026-01-02T00:00:00")
        parent = common.git(repo, "rev-parse", "HEAD").strip()
        ranges = [(2, 2), (7, 1), (14, 3)]
        one_each = [row.split()[0] for start, count in ranges
                    for row in common.git(repo, "blame", "-s", "-l", f"-L{start},{start + count - 1}", parent, "--", "a.py").splitlines()]
        combined = history.blame_ranges(repo, parent, "a.py", ranges)
        self.assertEqual(combined, Counter(one_each))
        self.assertEqual(list(combined), list(dict.fromkeys(one_each)))  # first-seen order breaks most_common ties
        # A range past the end refuses the combined call; the ranges that do resolve are kept.
        kept = history.blame_ranges(repo, parent, "a.py", [(2, 2), (500, 3)])
        self.assertEqual(sum(kept.values()), 2)

    def test_describe_all_matches_describe_and_falls_back(self):
        repo = self.repo()
        shas = common.git(repo, "rev-list", "HEAD").split()
        expected = {sha: history.describe(repo, sha) for sha in shas}
        self.assertEqual(history.describe_all(repo, shas), expected)
        self.assertEqual(list(history.describe_all(repo, shas[::-1])), shas[::-1])
        short = shas[0][:12]
        self.assertEqual(history.describe_all(repo, [short, shas[1]]), {short: history.describe(repo, short), shas[1]: expected[shas[1]]})
        self.assertEqual(history.describe_all(repo, []), {})
        batch, history.DESCRIBE_BATCH = history.DESCRIBE_BATCH, 3
        self.addCleanup(setattr, history, "DESCRIBE_BATCH", batch)
        self.assertEqual(history.describe_all(repo, shas + [short]), {**expected, short: history.describe(repo, short)})

    def test_full_hashes_skip_rev_parse_and_boundaries_still_resolve(self):
        repo = self.repo()
        head = common.git(repo, "rev-parse", "HEAD").strip()
        cache = {}
        self.assertEqual(history.full_sha(repo, head, cache, len(head)), head)
        self.assertEqual(history.full_sha(repo, "^" + head[:39], cache, len(head)), head)
        self.assertEqual(history.full_sha(repo, head[:12], {}, len(head)), head)


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

    def test_line_numbers_match_a_full_count_in_any_order(self):
        text = "a\nbb\n\nccc\nd" * 50
        line = surfaces.Lines(text)
        for offset in [0, 3, 3, 9, 120, 7, 0, len(text), 40]:
            self.assertEqual(line(offset), text.count("\n", 0, offset) + 1)

    def test_literal_gates_never_hide_a_match(self):
        for patterns in (surfaces.API_PATTERNS, surfaces.JOB_PATTERNS, surfaces.TABLE_PATTERNS, surfaces.CFG_PATTERNS):
            for pattern, literal in patterns:
                if literal is None:
                    continue
                self.assertFalse(pattern.flags & re.IGNORECASE, pattern.pattern)
                samples = ['path("a/", v)', "re_path(r'^x', v)", "class A < ApplicationJob", "class B < ActiveJob::Base",
                           "cron.schedule('* * * * *', tick)", "create_table :orders", "model User {", "class O(models.Model):",
                           "process.env.API_KEY"]
                for sample in samples:
                    for match in pattern.finditer(sample):
                        self.assertIn(literal, match.group(0), pattern.pattern)

    def test_each_kind_stops_at_its_cap_and_counts_the_rest(self):
        catalog = surfaces.Catalog()
        for i in range(surfaces.MAX_PER_KIND + 5):
            catalog.add("cfg", f"V{i}", "n", "a.py:1")
            catalog.add("cfg", f"v{i}", "n", "a.py:1")  # same name, other case: not a new surface
        catalog.add("api", "GET /x", "n", "a.py:1")
        self.assertEqual(sum(1 for i in catalog.items if i["kind"] == "cfg"), surfaces.MAX_PER_KIND)
        self.assertEqual(catalog.dropped, {"cfg": 10})  # a dropped name is not remembered, so its other case counts too
        self.assertEqual(catalog.items[-1]["name"], "GET /x")

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

    def test_a_person_can_withdraw_an_acceptance_and_link_a_filed_issue(self):
        book = dict(version=1, entries=[])
        ledger.reconcile(book, self.record(("k1", "a", "Open")), "2026-01-01")
        entry = book["entries"][0]
        with self.assertRaises(common.RecordError):
            ledger.set_entry(entry, "2026-01-02", "nothing to withdraw", status="Open")
        ledger.set_entry(entry, "2026-01-02", "accepted for now", status="Accepted", owner="payments team")
        ledger.set_entry(entry, "2026-01-03", "filed", ref="https://tracker.example.com/T-12")
        ledger.set_entry(entry, "2026-01-03", "filed twice", ref="https://tracker.example.com/T-12")
        self.assertEqual(entry["external_refs"], ["https://tracker.example.com/T-12"])
        fragment, _ = ledger.reconcile(book, self.record(("k1", "a", "Triaged")), "2026-02-01")
        self.assertEqual(fragment["findings"][0]["status"], "Accepted")
        self.assertEqual(fragment["findings"][0]["external_refs"], ["https://tracker.example.com/T-12"])
        ledger.set_entry(entry, "2026-02-02", "revisit after the coupon rewrite", status="Open")
        fragment, _ = ledger.reconcile(book, self.record(("k1", "a", "Triaged")), "2026-03-01")
        self.assertEqual(fragment["findings"][0]["status"], "Triaged")
        self.assertEqual([e["status"] for e in entry["status_log"]][-3:], ["Accepted", "Open", "Triaged"])
        with self.assertRaises(common.RecordError):
            ledger.set_entry(entry, "2026-03-02", "x", ref="https://user:hunter2pass@tracker.example.com/T-1")

    def test_refs_already_on_the_record_are_kept_and_not_repeated(self):
        book = dict(version=1, entries=[])
        record = self.record(("k1", "a", "Open"))
        ledger.reconcile(book, record, "2026-01-01")
        ledger.set_entry(book["entries"][0], "2026-01-02", "filed", ref="https://tracker.example.com/T-1")
        record["findings"][0]["external_refs"] = ["https://tracker.example.com/T-0", "https://tracker.example.com/T-1"]
        fragment, _ = ledger.reconcile(book, record, "2026-02-01")
        self.assertEqual(fragment["findings"][0]["external_refs"], ["https://tracker.example.com/T-0", "https://tracker.example.com/T-1"])

    def test_list_filters_and_set_needs_a_change(self):
        path = self.dir / "ledger.json"
        book = dict(version=1, entries=[])
        ledger.reconcile(book, self.record(("k1", "a", "Open"), ("k2", "b", "Open")), "2026-01-01")
        ledger.reconcile(book, self.record(("k1", "a", "Open")), "2026-02-01")
        common.write_json(path, book)
        self.assertEqual([e["key"] for e in ledger.listing(book, "NotSeen")], ["k2"])
        self.assertIn("does not prove a fix", ledger.listing_markdown(ledger.listing(book)))
        self.assertEqual(ledger.main(["set", str(path), "k1", "--reason", "nothing"]), 2)
        self.assertEqual(ledger.main(["list", str(self.dir / "absent.json")]), 2)

    def test_fragment_merges_into_the_sample(self):
        record, surfaces_data, history_data = sample()
        book = dict(version=1, entries=[])
        fragment, _ = ledger.reconcile(book, record, record["meta"]["date"])
        findings.merge_fragment(record, fragment)
        self.assertEqual(findings.contract_errors(record, surfaces_data, history_data), [])


class ExportTests(TempDir):
    def setUp(self):
        super().setUp()
        self.run_dir = self.dir / "run"
        self.run_dir.mkdir()
        for name in ("findings", "surfaces", "history"):
            shutil.copy(ROOT / "examples" / f"{name}.sample.json", self.run_dir / f"{name}.json")
        self.record_path = self.run_dir / "findings.json"
        self.record, _, _ = sample()

    def test_issue_drafts_cover_each_unresolved_record_and_nothing_else(self):
        out = self.dir / "issues"
        drafted, skipped = export.export_issues(self.record_path, out, minimum="Info")
        unresolved = [f["id"] for f in self.record["findings"] if common.unresolved(f)]
        self.assertEqual([f["id"] for f in drafted], unresolved)
        self.assertEqual(sorted(p.name for p in out.iterdir()), sorted([f"{i}.md" for i in unresolved] + ["index.md"]))
        self.assertEqual(len(drafted) + len(skipped), len(self.record["findings"]))
        first = (out / "BG-001.md").read_text(encoding="utf-8")
        record = self.record["findings"][0]
        for text in (record["title"], record["key"], "api/orders/validate.py:42", "api/admin/coupons.py:27", record["repro"]["steps"][1], "ledger.py set"):
            self.assertIn(text, first)
        self.assertNotIn("web/checkout/CouponForm.tsx:44", first.split("## ")[-3], "a safe sibling is not a to-do")

    def test_issue_drafts_follow_the_language_and_the_threshold(self):
        drafted, _ = export.export_issues(self.record_path, self.dir / "en", lang="en", minimum="Medium")
        self.assertEqual({f.get("severity") for f in drafted}, {"High", "Medium"})
        text = (self.dir / "en" / "BG-001.md").read_text(encoding="utf-8")
        self.assertIn("## Reproduction", text)
        self.assertIn("Derived from code (not run)", text)

    def test_drafts_cannot_notify_people_or_leak_secrets(self):
        self.record["findings"][0]["fix"] = "ask @octocat or mail ops.lead@corp-mail.io; token = abcdef123456; see a@example.com"
        common.write_json(self.record_path, self.record)
        self.assertEqual(export.main(["issues", str(self.record_path), "--out", str(self.dir / "issues")]), 2, "the record itself refuses them")
        text = export.issue_markdown(self.record["findings"][0], self.record, {}, "ja")
        self.assertIn("`@octocat`", text)
        self.assertNotIn("ops.lead@corp-mail.io", text)
        self.assertNotIn("abcdef123456", text)

    def test_exports_are_refused_inside_the_run_directory(self):
        for argv in (["issues", str(self.record_path), "--out", str(self.run_dir / "issues")],
                     ["sarif", str(self.record_path), "--out", str(self.run_dir / "r.sarif")],
                     ["csv", str(self.record_path), "--out", str(self.run_dir / "r.csv")]):
            self.assertEqual(export.main(argv), 2)
        self.assertEqual(sorted(p.name for p in self.run_dir.iterdir()), ["findings.json", "history.json", "surfaces.json"])

    def test_sarif_holds_unresolved_records_with_stable_fingerprints(self):
        data, skipped = export.to_sarif(self.record, {})
        self.assertEqual(data["version"], "2.1.0")
        run = data["runs"][0]
        results = {r["properties"]["bugScanId"]: r for r in run["results"]}
        expected = {f["id"] for f in self.record["findings"] if common.unresolved(f)}
        self.assertEqual(set(results) | set(skipped), expected)
        first = results["BG-001"]
        self.assertEqual(first["level"], "error")
        self.assertEqual(first["partialFingerprints"]["bugScanKey/v1"], self.record["findings"][0]["key"])
        self.assertEqual(first["locations"][0]["physicalLocation"]["region"]["startLine"], 42)
        related = [r["physicalLocation"]["artifactLocation"]["uri"] for r in first["relatedLocations"]]
        self.assertIn("api/admin/coupons.py", related)
        self.assertNotIn("web/checkout/CouponForm.tsx", related)
        self.assertEqual(len({r["id"] for r in first["relatedLocations"]}), len(first["relatedLocations"]))
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        self.assertEqual(rule_ids, {r["ruleId"] for r in run["results"]})
        moved = copy.deepcopy(self.record)
        moved["findings"][0]["location"] = ["api/orders/validate.py:50"]
        again, _ = export.to_sarif(moved, {})
        self.assertEqual(again["runs"][0]["results"][0]["partialFingerprints"], first["partialFingerprints"])

    def test_csv_keeps_every_record_and_disarms_formulas(self):
        self.record["findings"][0]["title"] = "=HYPERLINK(\"http://x.invalid\")"
        text = export.to_csv(self.record, {})
        rows = list(csv.DictReader(io.StringIO(text.lstrip("\ufeff"))))
        self.assertEqual([r["id"] for r in rows], [f["id"] for f in self.record["findings"]])
        self.assertTrue(rows[0]["title"].startswith("'="))
        self.assertEqual(rows[0]["location"], "api/orders/validate.py:42; api/orders/routes.py:31")


class ImpactTests(TempDir):
    def setUp(self):
        super().setUp()
        self.record, _, _ = sample()
        repo = self.dir / "repo"
        repo.mkdir()
        run_git(repo, "init", "-q", "-b", "main")
        for path, lines in (("api/orders/validate.py", 80), ("api/admin/coupons.py", 30), ("web/checkout/api.ts", 50), ("docs/readme.md", 5)):
            target = repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("".join(f"line {n}\n" for n in range(1, lines + 1)), encoding="utf-8")
        run_git(repo, "add", "-A")
        run_git(repo, "commit", "-qm", "base")
        self.repo = repo

    def edit(self, path, line, text="changed"):
        target = self.repo / path
        rows = target.read_text(encoding="utf-8").splitlines()
        rows[line - 1] = text
        target.write_text("\n".join(rows) + "\n", encoding="utf-8")

    def test_a_change_at_a_recorded_line_names_the_defect_its_siblings_and_the_fixed_one(self):
        self.edit("api/orders/validate.py", 41)
        self.edit("api/admin/coupons.py", 5)
        result = impact.analyse(self.record, impact.changed_files(self.repo, "HEAD", None))
        self.assertEqual([r["id"] for r in result["sites"]], ["BG-001"])
        self.assertEqual(result["sites"][0]["at"][0], dict(location="api/orders/validate.py:42", match="line"))
        self.assertEqual(sorted(r["at"]["location"] for r in result["siblings"]), ["api/admin/coupons.py:27", "api/orders/validate.py:67"])
        self.assertTrue(all(r["at"]["match"] == "file" for r in result["siblings"]))
        self.assertEqual([r["id"] for r in result["fixed_here"]], ["BG-007"])
        self.assertEqual(result["patterns"][0]["module"], "api/orders")
        self.assertEqual(impact.gate(result, "High"), ["BG-001"])
        self.assertIn("I-05", [i["id"] for i in result["issues"]])

    def test_a_change_far_from_the_line_is_file_level_and_unrelated_files_are_counted(self):
        self.edit("api/orders/validate.py", 1)
        self.edit("docs/readme.md", 2)
        result = impact.analyse(self.record, impact.changed_files(self.repo, "HEAD", None))
        self.assertEqual(result["sites"][0]["at"][0]["match"], "file")
        self.assertEqual(result["untouched_by_record"], ["docs/readme.md"])

    def test_committed_ranges_untracked_files_and_the_gate_exit_code(self):
        self.edit("web/checkout/api.ts", 41)
        run_git(self.repo, "commit", "-qam", "change")
        (self.repo / "api" / "orders" / "brand new.py").write_text("x\n", encoding="utf-8")
        committed = impact.changed_files(self.repo, "HEAD~1", "HEAD")
        self.assertEqual(list(committed), ["web/checkout/api.ts"])
        result = impact.analyse(self.record, committed)
        self.assertEqual([r["id"] for r in result["fixed_here"]], ["BG-008"])
        self.assertEqual(result["sites"], [])
        self.assertIn("api/orders/brand new.py", impact.changed_files(self.repo, "HEAD", None))
        out = self.dir / "run"
        out.mkdir()
        common.write_json(out / "findings.json", self.record)
        self.edit("api/orders/validate.py", 42)
        self.assertEqual(impact.main([str(out), "--repo", str(self.repo), "--base", "HEAD", "--fail-on", "High"]), 1)
        self.assertEqual(impact.main([str(out), "--repo", str(self.repo), "--base", "HEAD", "--fail-on", "High", "--format", "json"]), 1)
        self.assertEqual(impact.main([str(out), "--files", "docs/readme.md", "--fail-on", "Info"]), 0)
        self.assertEqual(impact.main([str(out), "--repo", str(self.repo), "--base=--output=x"]), 2)

    def test_excluded_records_never_count(self):
        self.record["findings"][0]["validation"]["verdict"] = "FalsePositive"
        result = impact.analyse(self.record, {"api/orders/validate.py": impact.WHOLE_FILE})
        self.assertNotIn("BG-001", [r["id"] for r in result["sites"] + result["siblings"]])

    def test_quoted_and_renamed_paths_keep_the_base_side_name(self):
        patch = ('diff --git "a/api/\\303\\244.py" "b/api/\\303\\244.py"\n--- "a/api/\\303\\244.py"\n+++ "b/api/\\303\\244.py"\n@@ -3,0 +4 @@\n+x\n'
                 "diff --git a/old.py b/new.py\n--- a/old.py\n+++ b/new.py\n@@ -10,2 +10,2 @@\n-a\n-b\n+c\n+d\n")
        changed = impact.parse_diff(patch)
        self.assertEqual(changed, {"api/ä.py": [(3, 4)], "old.py": [(10, 11)]})
        self.assertEqual(impact.touch("old.py:14", changed), "line")
        self.assertEqual(impact.touch("old.py:15", changed), "file")

    def test_the_repository_is_not_changed(self):
        self.edit("api/orders/validate.py", 41)
        before = subprocess.run(["git", "-C", str(self.repo), "status", "--porcelain=v2"], capture_output=True, text=True).stdout
        impact.analyse(self.record, impact.changed_files(self.repo, "HEAD", None))
        after = subprocess.run(["git", "-C", str(self.repo), "status", "--porcelain=v2"], capture_output=True, text=True).stdout
        self.assertEqual(before, after)


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


class BoundaryTests(TempDir):
    """Malformed input from a fragment or file is refused by name; it neither crashes nor gets half-read."""

    def merge_text(self, text):
        fragment = self.dir / "f.json"
        fragment.write_text(text, encoding="utf-8")
        findings.merge(self.dir / "findings.json", [fragment])

    def test_each_malformed_fragment_is_refused(self):
        one = '{"id":"BG-001","title":"t","status":"Open"'
        for text in ('{"gates": 3}', '{"findings": "x"}', '{"meta": "x"}', "[]", '{"summary": 3}', '{"next_steps": "do"}', '{"remove": []}',
                     '{"remove": {"next_steps": "x"}}', '{"perspectives": ["x"]}', '{"perspectives": "x"}',
                     '{"findings":[' + one + ',"pattern":"BP01","surfaces":[{"op":"x"}]}]}', '{"findings":[' + one + ',"surfaces":3}]}',
                     '{"findings":[' + one + ',"pattern":["x"]}]}', '{"findings":[{"id":"BG-001","title":"t","status":["Open"]}]}',
                     '{"findings":[' + one + ',"location":3}]}', '{"findings":[{"id":["x"],"title":"t","status":"Open"}]}',
                     '{"findings":[' + one + ',"relations":3}]}', '{"findings":[' + one + ',"path":"x"}]}', '{"findings":[' + one + ',"sibling_sites":3}]}',
                     '{"issues":[{"id":"I-1","kind":"k","at":"a","feeds":3}]}'):
            with self.subTest(text=text), self.assertRaises(common.RecordError):
                self.merge_text(text)
        self.assertFalse((self.dir / "findings.json").exists())

    def test_contract_check_survives_a_structurally_wrong_record(self):
        self.assertTrue(findings.contract_errors(dict(gates=3, meta="x")))

    def test_concurrent_merges_keep_every_update(self):
        script = ("import json,sys;sys.dont_write_bytecode=True;sys.path.insert(0,sys.argv[1]);import findings\n"
                  "for i in range(15):\n"
                  "    p=f'{sys.argv[2]}/{sys.argv[3]}_{i}.json';json.dump({'next_steps':[f'{sys.argv[3]}-{i}']},open(p,'w'));findings.merge(sys.argv[2]+'/findings.json',[p])\n")
        workers = [subprocess.Popen([sys.executable, "-c", script, str(SCRIPTS), str(self.dir), str(w)]) for w in range(5)]
        self.assertEqual([w.wait() for w in workers], [0] * 5)
        self.assertEqual(len(common.load_json(self.dir / "findings.json")["next_steps"]), 75)
        self.assertFalse((self.dir / ".findings.lock").exists())

    def test_render_names_a_reference_that_points_nowhere(self):
        record, surface_data, history_data = sample()
        broken = copy.deepcopy(record)
        broken["findings"][0]["relations"] = [dict(type="blocks", to="BG-099", strength="Traced", evidence="x")]
        with self.assertRaisesRegex(common.RecordError, "BG-099"):
            render.build(broken, surface_data, history_data, "en")
        broken = copy.deepcopy(record)
        next(e for e in broken["fix_events"] if e.get("gate_missed"))["gate_missed"] = ["G-99"]
        with self.assertRaisesRegex(common.RecordError, "G-99"):
            render.build(broken, surface_data, history_data, "en")

    def test_ledger_refuses_entries_and_records_it_cannot_track(self):
        path = self.dir / "ledger.json"
        common.write_json(path, dict(version=1, entries=[dict(key="k")]))
        with self.assertRaisesRegex(common.RecordError, "status_log"):
            ledger.read_ledger(path)
        with self.assertRaisesRegex(common.RecordError, "BG-001"):
            ledger.reconcile(dict(version=1, entries=[]), dict(findings=[dict(id="BG-001", title="t", status="Open")]), "2026-01-01")

    def test_surface_merge_refuses_a_bad_fragment(self):
        path = self.dir / "s.json"
        common.write_json(path, dict(surfaces=[], links=[]))
        fragment = self.dir / "f.json"
        for text in ("[]", '{"surfaces": ["x"]}', '{"surfaces": [{"name": "n"}]}', '{"remove_links": ["ab"]}'):
            fragment.write_text(text, encoding="utf-8")
            with self.subTest(text=text), self.assertRaises(common.RecordError):
                surfaces.merge(path, [fragment])


class FigureIntegrityTests(unittest.TestCase):
    """A figure and its table say what the record says: nothing dropped silently, no false record counted."""

    def setUp(self):
        self.record, self.surfaces, self.history = sample()
        self.t = diagrams.TEXT["en"]

    def falsify(self, record):
        target = record["findings"][0]
        target["validation"]["verdict"] = "FalsePositive"
        return target

    def test_a_false_positive_is_not_counted_or_highlighted(self):
        def open_count(record, surface):
            drawing = diagrams.d8(record, self.surfaces, self.t)["svg"]
            return int(re.search(r"(\d+) open", drawing.split(f'data-s="{surface}"')[1]).group(1))

        record = copy.deepcopy(self.record)
        surface = record["findings"][0]["surfaces"][0]["id"]
        before = open_count(record, surface)
        target = self.falsify(record)
        self.assertEqual(open_count(record, surface), before - 1)
        self.assertNotIn(f"#{diagrams.record_links(record)[target['id']]}", diagrams.d6(record, self.t, "en")["svg"])
        self.assertNotIn("box-hi", diagrams.d7(record, self.surfaces, self.t)["svg"].split(target["title"][:10])[0][-400:])

    def test_feeds_may_be_a_single_string(self):
        record = copy.deepcopy(self.record)
        record["issues"][0]["feeds"] = "BP01"
        self.assertEqual(findings.shape_errors(record), [])
        self.assertEqual(diagrams.d6(record, self.t, "en")["rows"][0][2], "BP01")

    def test_tables_hold_what_the_drawing_leaves_out(self):
        self.assertEqual(len(diagrams.d3(self.record, self.history, self.t)["rows"]), sum(len(g["edges"]) for g in diagrams.chains(self.record, self.history)))
        record = copy.deepcopy(self.record)
        base = next(f for f in record["findings"] if f.get("path"))
        record["findings"] += [dict(copy.deepcopy(base), id=f"BG-{100 + i}") for i in range(12)]
        d5 = diagrams.d5(record, self.t)
        self.assertEqual(len({row[0] for row in d5["rows"]}), sum(1 for f in record["findings"] if f.get("path")))
        self.assertIn("Only the top 10", d5["foot"])
        many = copy.deepcopy(self.history)
        many["modules"] = [dict(module=f"m{i}", commits=i + 1, fix_candidates=0, test_files=0) for i in range(40)]
        d4 = diagrams.d4(self.record, many, self.t)
        self.assertEqual(len(d4["rows"]), 40)
        self.assertIn("top 30 of 40", d4["foot"])

    def test_english_pages_use_english_separators_and_labels(self):
        figure = {f["number"]: f for f in diagrams.figures(self.record, self.surfaces, self.history, "en")}
        self.assertNotIn(" ・ ", figure[5]["svg"] + figure[6]["svg"] + figure[7]["svg"] + figure[8]["svg"])
        japanese = {f["number"]: f for f in diagrams.figures(self.record, self.surfaces, self.history, "ja")}
        self.assertNotIn(" commits,", japanese[4]["svg"])


class PageStructureTests(unittest.TestCase):
    def setUp(self):
        self.record, self.surfaces, self.history = sample()
        self.dashboard, self.document = render.build(self.record, self.surfaces, self.history, "ja")

    def test_the_register_leads_and_contents_follow_page_order(self):
        page = [self.dashboard.index(mark) for mark in ('<section id="findings"', '<section id="overview"',
                                                       '<section id="figures"', '<div class="lists"')]
        self.assertEqual(page, sorted(page))
        self.assertTrue(self.dashboard.split("<main>\n", 1)[1].startswith('<section id="findings"'))
        nav = self.dashboard[self.dashboard.index('class="nav-links"'):self.dashboard.index('class="facets"')]
        self.assertEqual(re.findall(r'href="#([a-z-]+)"', nav),
                         ["triage", "findings", "overview", "priority-section", "coverage", "figures", "lists"])

    def test_the_printable_report_has_no_focus_stop_that_does_nothing(self):
        self.assertNotIn('tabindex="0"', self.document)
        self.assertIn('tabindex="0"', self.dashboard)

    def test_every_figure_part_has_a_name_and_every_record_link_lands(self):
        for page in (self.dashboard, self.document):
            parts = re.findall(r"<[a-z]+ [^<>]*data-tip=[^<>]*>", page[page.index('id="figures"'):])
            self.assertGreater(len(parts), 50)
            self.assertTrue(all("aria-label=" in part for part in parts))
        hrefs = set(re.findall(r'<a href="#(finding-\d+)" aria-label', self.document))
        self.assertTrue(hrefs)
        for href in hrefs:
            self.assertIn(f"id='{href}'", self.document)

    def test_figures_are_groups_and_table_heads_are_scoped(self):
        self.assertNotIn('role="img" aria-label="' + diagrams.TEXT["ja"]["d7"] + '"', self.dashboard)
        self.assertNotRegex(self.dashboard, r"<th>")

    def test_figure_text_meets_aa_on_every_shade_in_both_themes(self):
        def tokens(block):
            return dict(item.split(":") for item in block.split(";"))

        def luminance(colour):
            digits = colour[1:] if len(colour) == 7 else "".join(c * 2 for c in colour[1:])
            channels = [int(digits[i:i + 2], 16) / 255 for i in (0, 2, 4)]
            r, g, b = [c / 12.92 if c <= .03928 else ((c + .055) / 1.055) ** 2.4 for c in channels]
            return .2126 * r + .7152 * g + .0722 * b

        def ratio(a, b):
            high, low = sorted((luminance(a), luminance(b)), reverse=True)
            return (high + .05) / (low + .05)

        pairs = [("ink", "h0"), ("ink", "h1"), ("ink", "h2"), ("on3", "h3"), ("on4", "h4"), ("ink", "surface"), ("ink2", "surface"), ("muted", "surface"),
                 ("ink", "tint"), ("ink2", "tint"), ("ink2", "off")]
        for name, block in (("light", diagrams.LIGHT), ("dark", diagrams.DARK)):
            theme = tokens(block)
            for text_token, shade in pairs:
                with self.subTest(theme=name, text=text_token, shade=shade):
                    self.assertGreaterEqual(ratio(theme[f"--bs-{text_token}"], theme[f"--bs-{shade}"]), 4.5)


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
