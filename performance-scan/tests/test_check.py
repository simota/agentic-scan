"""Run-contract rules that ``findings.py check`` enforces beyond the schema."""
import tempfile
import time
import unittest
from pathlib import Path

from support import complete_doc, contract_problems, finding, findings, render


class CheckRuleTests(unittest.TestCase):
    def test_excluded_findings_come_last_and_are_not_ranked(self):
        excluded = {"verdict": "FalsePositive", "method": "static", "evidence": "x.py:1"}
        doc = complete_doc()
        doc["findings"] = [finding("P-001", "Low"), finding("P-002", "High", validation=excluded)]
        self.assertEqual(contract_problems(doc), [])
        doc["findings"] = [finding("P-001", "Low", validation=excluded), finding("P-002", "High")]
        self.assertEqual(contract_problems(doc), [
            "P-002: excluded findings (P-001) must be numbered after all others"])
        doc["findings"] = [finding("P-001", "Low"), finding("P-002", "High")]
        self.assertEqual(contract_problems(doc), [
            "findings must be numbered in severity order (High first): P-002 (High) follows "
            "P-001 (Low)"])

    def test_definitive_evidence_suspected_valid_and_holding_budgets(self):
        doc = complete_doc()
        doc["findings"][0]["validation"]["evidence"] = "looks fine"
        doc["findings"][1].update(confidence="Suspected")
        doc["findings"][0]["budget"] = "B-01"
        doc["budgets"][0]["status"] = "holds"
        self.assertEqual(contract_problems(doc), [
            "P-001.validation.evidence: Valid evidence must cite a path:line",
            "P-002: a Suspected finding cannot be Valid; confirm the code link "
            "(Confirmed or Environment-dependent) or record Likely",
            "B-01: status holds, but P-001 is a Valid, unfixed violation of it"])
        doc["findings"][0]["status"] = "Accepted"  # an accepted cost still violates it
        self.assertIn("B-01: status holds, but P-001 is a Valid, unfixed violation of it",
                      contract_problems(doc))
        doc["findings"][0]["status"] = "Fixed"
        doc["findings"][0]["validation"]["evidence"] = "C:\\app\\x.py:12 shows it"
        doc["findings"][1]["validation"]["verdict"] = "Likely"
        self.assertEqual(contract_problems(doc), [])

    def test_required_lists_and_unique_ids(self):
        doc = complete_doc()
        doc["limitations"], doc["checked_ok"] = [], []
        self.assertEqual(contract_problems(doc), [
            "limitations: state what static reading cannot show",
            "checked_ok: list what was examined and held"])
        doc = complete_doc()
        doc["findings"][1]["id"] = "P-001"
        with self.assertRaisesRegex(findings.SchemaError, r"duplicate P-001"):
            findings.validate(doc)

    def test_check_names_a_path_that_is_not_a_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "findings.json"
            path.write_text("{}", encoding="utf-8")
            for target in (path, Path(directory) / "missing"):
                self.assertEqual(findings.contract_problems(target), [f"not a directory: {target}"])

    def test_check_refuses_text_that_render_cannot_encode(self):
        doc = complete_doc()
        doc["findings"][0]["title"] = "\ud800"
        problems = contract_problems(doc)
        self.assertEqual(len(problems), 1)
        self.assertIn("surrogates not allowed", problems[0])


class CrossReferenceTests(unittest.TestCase):
    def test_check_requires_finding_budgets_to_name_ledger_entries(self):
        doc = complete_doc()
        doc["findings"][0]["budget"] = "B-01"
        doc["findings"][1]["budget"] = ""
        self.assertEqual(contract_problems(doc), [])
        doc["findings"][1]["budget"] = "B-99"
        self.assertEqual(contract_problems(doc), ["P-002.budget: 'B-99' is not in budgets"])

    def test_check_requires_a_nonblank_reason_for_unchecked_budgets(self):
        doc = complete_doc()
        doc["budgets"][0].update(status="not checked", reason=" ")
        self.assertEqual(contract_problems(doc), ["B-01: a not-checked budget needs a reason"])
        # Merging still accepts the blank reason so a later fragment can fill it.
        findings.validate(doc)


class CitationTests(unittest.TestCase):
    def test_evidence_must_name_a_file_position(self):
        cites = ["app/orders/views.py:18 lacks prefetch", "app/orders/views.py#L18",
                 "views.py：18", "C:\\app\\x.py:12", "Makefile:12 sets -O0", "src/main:40",
                 "BUILD:10 declares the target", "WORKSPACE:7", "config/app.local/settings.py:3",
                 ".env.local:3", ".env.example:1 sets DATABASE_POOL_SIZE=5", "Dockerfile.dev:12",
                 "Procfile.dev:2", "config/settings.local:3", "tests/app.test:5", "README.org:10",
                 "makefile:12", "Service.svc:12", "Jenkinsfile:4", "src/v2.1/app.ts:7",
                 "internal/store/orders.go:42", "go.sum:10", "src/a:1", "lib/x/b:7",
                 "src/設定:12", "Program.CS:20", "index.PY:4", "Taskfile:1", "Pipfile:2",
                 "CHANGELOG:4", "./NOTES:3", "analysis.Rmd:42", "report.Rnw:10",
                 "fixtures/123:4", "testdata/1:8", "x/y:1", "a/b:1", "project.Rproj:1",
                 "foo.1:3", "Dockerfile.22.04:2", "python3.11:3", "docker/22.04:3",
                 "fixtures/1.5:3", "src/1.2:3", "./2.0.txt:3", "docs/1.2.py:4",
                 "db/001_init.sql:4", "./v8.json:2", "lib/v8.json:2", "V1_1__init.sql:3", "DB/123:4", "./HTTP/2:3", "v8/123:4", "V1/2:4", "certs/TLSv1.3:2", "http2.go:5", "./SSH-2.0:3", "http2-server.go:4", "http2_test.go:9",
                 "ssh-2.0.txt:1", "./SSH-2.0-OpenSSH_9.6:2", "ws/2:3", "ip/4:1", "SQL/001:3", "SQL\\001:3", "./SMB/3.1.1:2", "db/1.5:3", "./OData/4.0:2", "src/1.2.3:4", "http2-tests/README:3",
                 "ssh-2.0-fixtures/Makefile:7", "icon@2x.png:3", "libfoo.so.1.2.3:2", "jquery-3.6.0.min.js:1", "./Python-3.12.1:2", "Python-3.12.1.tar.gz:1", "python3.11.txt:2", "log4j-2.17.1.jar:3", "http2-server.go:7", "vendor/lodash@4.17.21.tgz:1",
                 "img/logo@1.5x.png:2", "Node.js-20.11.0.tar.xz:1", "app.config-1.2.json:3", "python-dateutil-2.8.2.tar.gz:1",
                 "foo-2x-bar.txt:2", "node-v20.11.0-linux-x64.tar.xz:1", "foo-v2-bar.txt:1", "rpc-tests/2.0/run.py:3", "pkg/mod/golang.org/x/sync@v0.17.0/errgroup/errgroup.go:30",
                 ".pnpm/react@18.2.0/index.js:4", "@types/node/index.d.ts:2", "./react@18.2.0.js:1", "tls_v1\\x:2",
                 "schema.PROTO:3", "./a:1", "/a:1", "C:\\a:1", "orders.go:42:7", "analysis.R:3",
                 "README.MD:2", "vendor/github.com/foo/bar.go:3", "internal/db/DB.Go:4", "app/views.py：１８", "go.mod:5", "CODEOWNERS:2",
                 "config/docker-compose.override.local:4"]
        not_cites = ["confirmed against https://staging.example:8080/api/orders",
                     "measured locally at 12:30", "ratio 1:10", "redis at localhost:6379",
                     "views.py line 18", "pool size read from db.prod.example.com:5432",
                     "10.0.0.5:5432 is the replica", "cache.internal:11211",
                     "上限：100件のため問題なし", "件数：50", "timeout:30", "pool max:10",
                     "node:18 image", "N:1 relation", "redis:6379", "postgres.default.svc:5432",
                     "db.example.co.uk:5432", "api.example.de:443", "api.corp.dev:443",
                     "example.org:443", "db.dev:5432", "api.app:443",
                     # Ambiguous without a directory: written as a host, read as one.
                     "settings.local:3", "app.test:5",
                     "TTL:300", "MAX_CONNECTIONS:100 is below the worker count", "TTL：300 なので問題なし",
                     "Read/write ratio 1.5:1", "v1.2.3:4", "N/A:1", "I/O:5 per request",
                     "HTTP/1.1:200", "123.dev:443", "at 10.30:15", "3.14:1 ratio", "TIMEOUT:30",
                     "MAX_ROWS:100", "HTTP:200", "Profile:2", "golang.org/x/sync:1",
                     "github.com/foo/bar:3", "DB.EXAMPLE.COM:443", "Api.Example.Com:443",
                     "R/W:2", "1/2:3", "HTTP/2:200", "TLS/1.3:1", "v1.2.3-rc1:4", "1.2.3-beta:4",
                     "v1.2.3+build.5:4", "v1.2.3-rc.1+build.5:4", "1.2.3rc1:4", "2.0b3:1", "5.3.20.RELEASE:1",
                     "1.0.Final:2", "1.0-SNAPSHOT:3", "1.2.3.post1:4", "1.2.3.dev1:4",
                     "5.0.0.BUILD-SNAPSHOT:2", "2.0.txt:3", "1!2.3:4", "2!1.0.post1:2",
                     "v1!2.3:4", "v2rc1.post2:4", "v2rc1+local.3:4", "V2.json:1", "v8.json:2", "V1__:2", "v3__x.sql:2", "~v1.2.3:4", "^v2.0.0:3", ">=v1.2.3:4",
                     "=v1.2.3:4", "!=v1.2.3:4", "^2.0.0:3", "~>v1.2:1",
                     "react@18.2.0:4", "pkg@v1.2.3:4", "python==1.2.3:4", "django>=4.2:1",
                     "@types/node@20.1.0:2", "lodash@4.17.21.tgz:1",
                     "version1.2.3:4", "Python-3.12.1:2", "OpenSSL_3.0.0:2", "release-2024.01.15:1",
                     "Python-3.12.1rc1:2", "OpenSSL_3.0.0-alpha:2", "version1.2.3+build.5:4",
                     "log4j-2.17.1:4", "OpenSSL3-3.0.0:2", "h2o_2.2.6:1",
                     "Python-3.12.1.post1:2", "Django-4.2.1.dev1:3", "Spring-5.3.20.RELEASE:4",
                     "Spring-5.3.20.BUILD-SNAPSHOT:1",
                     "github.com/acme/pkg@v1.2.3:4", "golang.org/x/sync@v0.17.0:3", "deps/pkg@1.2.3-rc1:2",
                     "Node.js-20.11.0:2", "ASP.NET-8.0.0:3", ".NET-8.0.0:4", "C++-17.0.1:1",
                     "python-dateutil-2.8.2:4", "my_product-1.2.3:4", "Apache-HTTP-Server-2.4.62:3",
                     "Python-v3.12.1:2", "OpenSSL_v3.0.0:2", "Node.js-v20.11.0:2", "app-V1.2:1",
                     "JSON-RPC/2.0:1", "XML-RPC/1.0:1", "json-rpc/2.0:1", "Foo-Bar/1.2:1", "１/２：３", "١/٢:3", "２０２４/１２３:3",
                     "001_init.sql:4", ".5:1", "~1.5:1",
                     "SMTP/2:1", "SSH/2.0:22", "https/1.1:200", "tls/1.3:1", "Ssh/2.0:22", "TLSv1.3:443", "SSH-2.0:22", "tls_v1.2:1", "HTTP2:1", "SSLv3:1", "TLSv1.3-draft28:1", "HTTP/3-draft-29:1",
                     "SSH-2.0-OpenSSH_9.6:22", "TLSv1.2+:1", "SFTP/3.0:22", "SMB/3.1.1:445", "RDP/10.0:3389",
                     "nfs/4.1:2049", "XYZ/2.0:1", "SMB2:445", "OData/4.0:1", "Stomp/1.2:1", "CoAP/1.0:1", "stomp/1.2:1", "coap/1.0:1", "odata/4.0:1", "rtmp/1.0:1", "src/.:3", "src/..:3", "./..:3", "src\\..:3", "..:3", "src/:3"]
        for text in cites:
            self.assertTrue(findings.cites_location(text), text)
        for text in not_cites:
            self.assertFalse(findings.cites_location(text), text)

    def test_long_evidence_without_a_colon_is_checked_in_linear_time(self):
        started = time.monotonic()
        self.assertFalse(findings.cites_location("a" * 200000))
        self.assertTrue(findings.cites_location("a" * 200000 + " views.py:3"))
        for token in ("a" * 200000 + ":1", "a/" * 100000 + ":1", "a." * 100000 + ":1",
                      "A" * 200000 + "/1:1", "設" * 200000 + ":1"):
            findings.cites_location(token)
            findings.citation_rejections(token)
        self.assertLess(time.monotonic() - started, 2)

    def test_a_directory_is_named_as_one(self):
        for text in ("src/..:3", "./.:1", "src\\..:3"):
            self.assertEqual(findings.citation_rejections(text)[0][1], "a directory, not a file", text)


class UnknownKeyTests(unittest.TestCase):
    def test_typos_in_records_are_refused_everywhere_but_meta(self):
        cases = (
            (lambda d: d["findings"][0].update(budjet="B-99"), r"^findings\[0\]: unknown keys \['budjet'\]"),
            (lambda d: d["findings"][0]["validation"].update(evidense="x"), r"^findings\[0\]\.validation: unknown"),
            (lambda d: d["findings"][0].update(measurement={"environment": "e", "command": "c",
                                                            "result": "r", "note": "n"}),
             r"^findings\[0\]\.measurement: unknown"),
            (lambda d: d["findings"][0].update(references=[{"url": "https://a.test", "label": "x"}]),
             r"^findings\[0\]\.references\[0\]: unknown"),
            (lambda d: d["budgets"][0].update(reasn="x"), r"^budgets\[0\]: unknown"),
            (lambda d: d["perspectives"][0].update(notes="x"), r"^perspectives\[0\]: unknown"),
        )
        for change, pattern in cases:
            with self.subTest(pattern=pattern):
                doc = complete_doc()
                change(doc)
                with self.assertRaisesRegex(findings.SchemaError, pattern):
                    findings.validate(doc)
        doc = complete_doc()
        doc["meta"]["host_notes"] = ["kept, not rendered"]
        findings.validate(doc, complete=True)


class StaleReasonTests(unittest.TestCase):
    def test_a_reason_shows_only_while_the_budget_is_not_checked(self):
        doc = complete_doc()
        doc["budgets"][0].update(status="holds", reason="API latency unknown")
        self.assertNotIn("API latency unknown", render.render_markdown(doc, "en"))
        self.assertNotIn("API latency unknown", render.render_html(doc, "en"))
        doc["budgets"][0]["status"] = "not checked"
        self.assertIn("API latency unknown", render.render_markdown(doc, "en"))


class CitationMessageTests(unittest.TestCase):
    def test_check_names_each_rejected_candidate(self):
        doc = complete_doc()
        doc["findings"][0]["validation"]["evidence"] = "GOMAXPROCS:8 and github.com/foo/bar:3 apply"
        problem = next(p for p in contract_problems(doc) if p.startswith("P-001.validation"))
        self.assertIn("'GOMAXPROCS:8' is not a file name", problem)
        self.assertIn("'github.com/foo/bar:3' is a module or host path", problem)

    def test_budgets_named_in_impact_are_cited_by_that_finding(self):
        doc = complete_doc()
        doc["budgets"].append({"id": "B-02", "statement": "s", "source": "x", "status": "violated"})
        doc["findings"][1]["impact"] = "Also violates B-02 (and not B-020)"
        row = next(line for line in render.render_markdown(doc, "en").splitlines()
                   if line.startswith("| B-02 |"))
        self.assertTrue(row.endswith(" | P-002 |"), row)


class CitationCorpusTests(unittest.TestCase):
    """A broad sample of real citations and look-alikes across stacks."""

    FILES = """app/models/order.rb:12 src/main/java/com/acme/Order.java:40 Order.java:40 Program.cs:5
        main.go:3 cmd/api/main.go:9 src/lib.rs:7 App.tsx:30 pages/index.vue:4 styles.scss:8
        pyproject.toml:12 package.json:4 Cargo.toml:3 Gemfile.lock:9 Dockerfile:7 Dockerfile.prod:2
        docker-compose.yml:14 .env:2 .env.production:4 .gitlab-ci.yml:20 CMakeLists.txt:8
        BUILD.bazel:4 schema.prisma:22 db/schema.rb:100 V3__add_index.sql:2 nginx.conf:30
        values.yaml:11 Chart.yaml:2 README:3 LICENSE:1 Startup.cs:44 Web.config:9 config.ru:2
        Procfile:1 Rakefile:5 requirements.txt:3 server.mjs:8 a.h:3 Foo.kt:9 build.gradle.kts:12
        pom.xml:30 vite.config.ts:6 ../x/y.py:3 C:\\src\\a.py:4 main.py#L10-L20 a.py:1-3
        orders.go:42:7 orders_test.go:3 Vagrantfile:2 terraform/main.tf:12 config/routes.rb:5""".split()
    LOOK_ALIKES = """12:30 R/W:2 localhost:6379 10.0.0.5:5432 node:18 postgres:16 ubuntu:22.04
        sha256:abc pool:10 N:1 port:8080 ratio:2 件数：50 cache.internal:11211""".split()

    def test_corpus(self):
        self.assertEqual([t for t in self.FILES if not findings.cites_location(t)], [])
        self.assertEqual([t for t in self.LOOK_ALIKES if findings.cites_location(t)], [])


class ImpactBudgetTests(unittest.TestCase):
    def test_budgets_named_in_impact_must_exist(self):
        doc = complete_doc()
        doc["findings"][1]["impact"] = "Also violates B-99 and B-01"
        self.assertEqual(contract_problems(doc), ["P-002.impact: B-99 is not in budgets"])

    def test_a_holds_budget_named_in_impact_is_a_contradiction_too(self):
        doc = complete_doc()
        doc["budgets"].append({"id": "B-02", "statement": "s", "source": "x", "status": "holds"})
        doc["findings"][0]["impact"] = "Also violates B-02"
        self.assertEqual(contract_problems(doc),
                         ["B-02: status holds, but P-001 is a Valid, unfixed violation of it"])


class JapaneseMentionTests(unittest.TestCase):
    def test_budget_ids_next_to_japanese_text_are_mentions(self):
        self.assertEqual(findings.BUDGET_MENTION.findall("予算B-02を超過し、B-01も"), ["B-02", "B-01"])
        self.assertEqual(findings.BUDGET_MENTION.findall("AB-01 B-01a B-01_x B-001"), ["B-001"])
        doc = complete_doc()
        doc["budgets"].append({"id": "B-02", "statement": "s", "source": "x", "status": "holds"})
        doc["findings"][0]["impact"] = "予算B-02を超過"
        self.assertEqual(contract_problems(doc),
                         ["B-02: status holds, but P-001 is a Valid, unfixed violation of it"])

    def test_partly_read_budgets_show_their_reason(self):
        doc = complete_doc()
        doc["budgets"][0].update(status="partly read", reason="only the list endpoint was read")
        self.assertIn("only the list endpoint was read", render.render_markdown(doc, "en"))

if __name__ == "__main__":
    unittest.main()
