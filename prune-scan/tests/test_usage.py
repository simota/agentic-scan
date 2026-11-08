"""usage.py: access-log evidence for the inventory's routes and public assets, tied to findings."""

import contextlib
import gzip
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import inventory  # noqa: E402
import usage  # noqa: E402

LOG = ROOT / "examples" / "access.sample.log"


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = usage.main([str(a) for a in argv])
    return code, out.getvalue(), err.getvalue()


def inventory_row(route, method="GET", kind="server", location="app.py:1"):
    return {"route": route, "method": method, "kind": kind, "location": location}


class SampleLog(unittest.TestCase):
    """The Larder inventory against examples/access.sample.log, with the sample findings."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        out = cls.tmp / "out"
        out.mkdir()
        shutil.copy(ROOT / "examples" / "units.sample.json", out / "units.json")
        shutil.copy(ROOT / "examples" / "findings.sample.json", out / "findings.json")
        with contextlib.redirect_stdout(io.StringIO()):
            assert inventory.main([str(ROOT / "examples" / "larder"), "--units", str(out / "units.json"),
                                   "--out", str(out / "inventory.json")]) == 0
        cls.out = out
        code, cls.text, err = run(out, LOG, "--findings", out / "findings.json", "--json", cls.tmp / "usage.json")
        assert code == 0, err
        cls.result = json.loads((cls.tmp / "usage.json").read_text(encoding="utf-8"))
        cls.rows = {r["target"]: r for r in cls.result["targets"]}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def test_counts_every_route_and_public_asset(self):
        self.assertEqual(self.result["requests_parsed"], 53)
        self.assertEqual(self.result["lines_unparsed"], 1)  # The nginx notice line.
        self.assertEqual(self.rows["GET /api/items"]["requests"], 20)  # 18 CLF + 1 JSON line + HEAD.
        self.assertEqual(self.rows["GET /api/items"]["statuses"], {"2xx": 20})
        self.assertEqual(self.rows["DELETE /api/items/<int:item_id>"]["requests"], 2)
        # A trailing slash on the request is the same route.
        self.assertEqual(self.rows["GET /api/items/<int:item_id>/label"]["requests"], 2)
        self.assertEqual(self.rows["GET /auth/callback"]["requests"], 3)
        for zero in ("GET /api/export/csv", "GET /debug/dump", "POST /webhooks/stripe", "GET /api/v1/items",
                     "/reports", "/fonts/OldSans.woff2"):
            self.assertEqual(self.rows[zero]["requests"], 0, zero)
        self.assertEqual(self.rows["/fonts/OldSans.woff2"]["path"], "web/public/fonts/OldSans.woff2")
        self.assertEqual(self.rows["/items/:id"]["requests"], 1)
        self.assertEqual(self.result["window"], {"first": "2026-09-01T14:45:00Z", "last": "2026-10-07T12:52:00Z"})

    def test_evidence_names_source_window_and_query(self):
        line = self.rows["GET /api/export/csv"]["evidence"]
        self.assertEqual(line, "access.sample.log, 2026-09-01 to 2026-10-07 UTC (53 requests parsed, "
                               "1 lines not read as requests): 0 requests to GET /api/export/csv")
        self.assertIn("full page loads only", self.rows["/reports"]["evidence"])

    def test_findings_are_tied_by_location_and_read_by_family(self):
        tied = {f["id"]: f for f in self.result["findings"]}
        self.assertEqual(sorted(tied), ["P-002", "P-003", "P-007", "P-008", "P-013", "P-021", "P-022", "P-031"])
        self.assertEqual(tied["P-008"]["requests"], 0)
        self.assertTrue(tied["P-008"]["reading"].startswith("no request in the window"))
        self.assertTrue(tied["P-013"]["reading"].startswith("no full page load"))
        # A purpose finding that is used: usage names who loses it, it does not overturn the finding.
        self.assertIn("does not settle a purpose", tied["P-007"]["reading"])
        self.assertIn("does not settle a purpose", tied["P-021"]["reading"])  # PX1: a purpose family too.
        self.assertIn("evidence of use", usage.TEXT["en"]["used"])
        self.assertNotIn("P-038", tied)  # FalsePositive findings are not tied.

    def test_no_client_detail_reaches_the_output(self):
        dumped = json.dumps(self.result) + self.text
        for private in ("192.0.2.", "198.51.100.", "203.0.113.", "Mozilla", "Larder/3.1", "code=", "4%2F0AbCdEf",
                        "3f9a8b7c6d5e4f30a1b2"):
            self.assertNotIn(private, dumped)
        unmatched = {u["path"]: u["requests"] for u in self.result["unmatched"]}
        self.assertEqual(unmatched["/reset/{id}"], 1)
        self.assertEqual(unmatched["/assets/index-4f2a9c.js"], 3)

    def test_text_summary_lists_zero_traffic_first(self):
        first, second = self.text.splitlines()[:2]
        self.assertTrue(first.startswith("prune-scan usage: 53 requests (2026-09-01 to 2026-10-07)"))
        self.assertEqual(second, "no request in the window:")

    def test_japanese_evidence(self):
        code, _, err = run(self.out, LOG, "--lang", "ja", "--json", self.tmp / "ja.json")
        self.assertEqual(code, 0, err)
        rows = {r["target"]: r for r in json.loads((self.tmp / "ja.json").read_text(encoding="utf-8"))["targets"]}
        self.assertEqual(rows["GET /debug/dump"]["evidence"],
                         "access.sample.log、2026-09-01〜2026-10-07 UTC(解析したリクエスト 53 件、"
                         "リクエストとして読めなかった行 1 行):GET /debug/dump へのリクエスト 0 件")


class Parsing(unittest.TestCase):
    def test_log_formats(self):
        clf = '1.2.3.4 - - [10/Oct/2026:13:55:36 -0700] "GET /a?b=1 HTTP/1.1" 404 5 "-" "ua"'
        method, target, status, when = usage.parse_line(clf)
        self.assertEqual((method, target, status), ("GET", "/a?b=1", 404))
        self.assertEqual(usage.iso(when), "2026-10-10T20:55:36Z")
        alb = ('https 2026-09-01T00:00:01.512345Z app/x 1.2.3.4:5 10.0.0.1:80 0.0 0.1 0.0 200 200 0 1 '
               '"GET https://h.example:443/api/items HTTP/1.1" "ua"')
        self.assertEqual(usage.parse_line(alb)[:2], ("GET", "https://h.example:443/api/items"))
        self.assertEqual(usage.iso(usage.parse_time("2026-09-01T00:00:01.5Z")), "2026-09-01T00:00:01Z")
        self.assertEqual(usage.parse_time("2026-09-01 02:00:00+0200").hour, 0)
        self.assertEqual(usage.iso(usage.parse_time(1788220800000)), "2026-09-01T00:00:00Z")  # Milliseconds.
        self.assertIsNone(usage.parse_time("yesterday"))
        gcp = json.dumps({"httpRequest": {"requestMethod": "POST", "requestUrl": "https://x/api", "status": 201},
                          "timestamp": "2026-09-01T00:00:00.123456789Z"})
        self.assertEqual(usage.parse_line(gcp)[:3], ("POST", "https://x/api", 201))
        nginx_json = json.dumps({"request": "DELETE /api/items/3 HTTP/2.0", "status": "204", "time": 1789000000})
        self.assertEqual(usage.parse_line(nginx_json)[:3], ("DELETE", "/api/items/3", 204))
        ecs = json.dumps({"@timestamp": "2026-09-01T00:00:00Z", "url": {"path": "/api/items", "query": "q=1"},
                          "http": {"request": {"method": "get"}, "response": {"status_code": 200}}})
        self.assertEqual(usage.parse_line(ecs)[:3], ("GET", "/api/items", 200))
        for junk in ("", "not a request", "{broken", "[1, 2]", json.dumps({"msg": "no request"})):
            self.assertIsNone(usage.parse_line(junk), junk)

    def test_request_path(self):
        self.assertEqual(usage.request_path("https://h:443/api//items/?x=1#f"), "/api/items")
        self.assertEqual(usage.request_path("/caf%C3%A9"), "/café")
        self.assertEqual(usage.request_path("/"), "/")
        self.assertIsNone(usage.request_path("*"))

    def test_route_syntax(self):
        cases = [("/items/<path:rest>", "GET", "/items/a/b", True), ("/items/<int:id>", "GET", "/items/a/b", False),
                 ("items/<int:pk>/", "PATH", "/items/3", True), ("^api/reports/?$", "RE_PATH", "/api/reports", True),
                 ("^api/(?P<pk>[0-9]+)/$", "RE_PATH", "/api/12", True), ("/files/*", "GET", "/files/x/y", True),
                 ("/u/{id}", "GET", "/u/9", True), ("/u/:id", "GET", "/u", False),
                 ("/blog/[...slug]", "", "/blog/a/b", True), ("/", "", "/", True), ("/", "", "/x", False)]
        for route, method, path, expected in cases:
            with self.subTest(route=route, path=path):
                self.assertEqual(bool(usage.route_regex(route, method).match(path)), expected)

    def test_mask_path(self):
        self.assertEqual(usage.mask_path("/orders/12345/items/9f8e7d6c5b4a"), "/orders/{id}/items/{id}")
        self.assertEqual(usage.mask_path("/u/jane@example.com/x"), "/u/{redacted}/x")
        self.assertEqual(usage.mask_path("/t/" + "z" * 41), "/t/{redacted}")
        self.assertEqual(usage.mask_path("/hook/xoxb-1234567890-abcdefghij"), "/hook/{id}")
        self.assertEqual(usage.mask_path("/static/app-4f2a9c.js"), "/static/app-4f2a9c.js")


class Matching(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def counted(self, routes, lines, *extra, assets=()):
        inv = {"tool": "inventory.py", "routes": routes, "assets_unreferenced": list(assets),
               "truncated": {"routes": 3}}
        (self.tmp / "inventory.json").write_text(json.dumps(inv), encoding="utf-8")
        log = self.tmp / "access.log"
        log.write_text("\n".join(lines) + "\n", encoding="utf-8")
        code, text, err = run(self.tmp / "inventory.json", log, "--json", self.tmp / "u.json", *extra)
        self.assertEqual(code, 0, err)
        return json.loads((self.tmp / "u.json").read_text(encoding="utf-8")), text

    @staticmethod
    def line(method, path, status=200):
        return f'1.2.3.4 - - [01/Sep/2026:00:00:00 +0000] "{method} {path} HTTP/1.1" {status} 1 "-" "-"'

    def test_methods_head_and_the_most_literal_route(self):
        routes = [inventory_row("/items/<id>"), inventory_row("/items/new"), inventory_row("/items/<id>", "POST"),
                  inventory_row("/any", "ROUTE")]
        result, _ = self.counted(routes, [self.line("GET", "/items/new"), self.line("HEAD", "/items/3"),
                                          self.line("POST", "/items/3"), self.line("PUT", "/items/3"),
                                          self.line("DELETE", "/any"), self.line("GET", "/any", 500)])
        hits = [(r["target"], r["requests"]) for r in result["targets"]]
        self.assertEqual(hits, [("GET /items/<id>", 1), ("GET /items/new", 1), ("POST /items/<id>", 1),
                                ("/any", 2)])
        self.assertEqual(result["targets"][3]["methods"], {"DELETE": 1, "GET": 1})
        self.assertEqual(result["targets"][3]["statuses"], {"2xx": 1, "5xx": 1})
        self.assertEqual(result["unmatched"], [{"path": "/items/{id}", "requests": 1}])  # PUT has no route.
        self.assertEqual(result["inventory_truncated"], {"routes": 3})

    def test_mount_prefix_applies_to_server_routes_only(self):
        routes = [inventory_row("/items"), inventory_row("/reports", "", "client")]
        result, _ = self.counted(routes, [self.line("GET", "/api/items"), self.line("GET", "/api/reports")],
                                 "--mount", "api/")
        self.assertEqual([r["requests"] for r in result["targets"]], [1, 0])
        self.assertEqual(result["mounts"], ["/api"])
        self.assertIn("(also under /api)", result["targets"][0]["evidence"])

    def test_gzip_logs_and_multiple_sources(self):
        routes = [inventory_row("/a")]
        result, _ = self.counted(routes, [self.line("GET", "/a")])
        self.assertEqual(result["requests_parsed"], 1)
        rotated = self.tmp / "access.log.1.gz"
        with gzip.open(rotated, "wt", encoding="utf-8") as fh:
            fh.write(self.line("GET", "/a") + "\n" + self.line("GET", "/b") + "\n")
        code, _, err = run(self.tmp / "inventory.json", self.tmp / "access.log", rotated, "--json",
                           self.tmp / "u.json")
        self.assertEqual(code, 0, err)
        result = json.loads((self.tmp / "u.json").read_text(encoding="utf-8"))
        self.assertEqual(result["targets"][0]["requests"], 2)
        self.assertEqual(result["sources"], ["access.log", "access.log.1.gz"])

    def test_public_asset_paths(self):
        assets = [{"path": "web/public/img/a.png", "public": True}, {"path": "src/img/b.png", "public": False}]
        result, _ = self.counted([], [self.line("GET", "/img/a.png"), self.line("GET", "/img/b.png")], assets=assets)
        self.assertEqual([(r["target"], r["requests"]) for r in result["targets"]], [("/img/a.png", 1)])

    def test_invalid_inputs_exit_2(self):
        (self.tmp / "inventory.json").write_text(json.dumps({"tool": "inventory.py"}), encoding="utf-8")
        log = self.tmp / "a.log"
        log.write_text("", encoding="utf-8")
        cases = [
            ([self.tmp / "missing.json", log], "missing.json"),
            ([log, log], "a.log"),  # Not JSON, so not an inventory.
            ([self.tmp / "inventory.json", self.tmp / "nope.log"], "not a file"),
            ([self.tmp / "inventory.json", log, "--mount", "/"], "--mount"),
            ([self.tmp / "inventory.json", log, "--json", log], "overwrite an input"),
            ([self.tmp / "inventory.json", log, "--findings", log], "a.log"),
        ]
        for argv, message in cases:
            with self.subTest(argv=argv):
                code, _, err = run(*argv)
                self.assertEqual(code, 2)
                self.assertIn(message, err)
        broken = self.tmp / "broken.gz"
        broken.write_bytes(b"\x1f\x8b\x08\x00garbage")
        code, _, err = run(self.tmp / "inventory.json", broken)
        self.assertEqual(code, 2)
        self.assertIn("cannot read", err)


if __name__ == "__main__":
    unittest.main()
