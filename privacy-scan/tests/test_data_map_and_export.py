"""The personal data map in the record, its comparison across runs, and exports."""
import copy
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_privacy_scan import REPO, SKILL, complete_doc, findings, import_module, render

compare = import_module(SKILL / "scripts" / "compare.py", "priv_compare_dm")
drafts = import_module(SKILL / "scripts" / "drafts.py", "priv_drafts_dm")
export = import_module(SKILL / "scripts" / "export.py", "priv_export")
SAMPLE = REPO / "examples" / "findings.sample.json"


def element(eid="D-01", **extra):
    record = {"id": eid, "element": "shipping_address", "category": "contact",
              "subjects": "Customers", "sensitive": False, "collected": ["api/checkout/views.py:40"],
              "stores": ["orders table (primary)"], "recipients": ["Error tracking vendor"]}
    record.update(extra)
    return record


def mapped_doc():
    doc = complete_doc()
    doc["data_map"] = [element(),
                       element("D-02", element="date_of_birth", sensitive=True, collected=[],
                               recipients=["error tracking  VENDOR", "Ad network"],
                               retention="Until closure", note="Used for age gate")]
    doc["findings"][0]["elements"] = "D-01, D-02"
    return doc


def run(main, args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(args)
    return code, out.getvalue(), err.getvalue()


class DataMapSchemaTests(unittest.TestCase):
    def test_a_complete_element_is_accepted_and_optional_fields_may_be_left_out(self):
        doc = mapped_doc()
        findings.validate(doc, complete=True)
        minimal = {k: v for k, v in element().items() if k != "collected"}
        doc["data_map"] = [minimal]
        doc["findings"][0]["elements"] = "D-01"
        findings.validate(doc, complete=True)
        self.assertEqual(findings.record_problems(doc), [])

    def test_shape_errors_name_the_field(self):
        cases = [
            ({"id": "E-01"}, "data_map[0].id: must look like D-01"),
            ({"sensitive": "yes"}, "data_map[0].sensitive: must be a boolean"),
            ({"stores": "orders"}, "data_map[0].stores: must be a list"),
            ({"recipients": [""]}, "data_map[0].recipients[0]: must be a nonblank string"),
            ({"collected": ["app.py:1:2"]}, "data_map[0].collected[0]: must be path:line"),
            ({"extra": "x"}, "data_map[0]: unknown fields are not allowed"),
            ({"retention": 30}, "data_map[0].retention: must be a string when present"),
        ]
        for change, message in cases:
            doc = mapped_doc()
            doc["data_map"][0].update(change)
            with self.subTest(change=change), self.assertRaises(findings.SchemaError) as ctx:
                findings.validate(doc)
            self.assertIn(message, str(ctx.exception))
        doc = mapped_doc()
        del doc["data_map"][0]["recipients"]
        with self.assertRaisesRegex(findings.SchemaError, "data_map\\[0\\]: missing recipients"):
            findings.validate(doc)
        doc = mapped_doc()
        doc["data_map"][1]["id"] = "D-01"
        with self.assertRaisesRegex(findings.SchemaError, "data_map\\[1\\].id: must be unique"):
            findings.validate(doc)

    def test_the_personal_value_guard_covers_every_data_map_text(self):
        for key, value in (("stores", ["dump of jane@corp-mail.jp"]), ("recipients", ["call 0312345678901"]),
                           ("note", "owner jane@corp-mail.jp"), ("element", "id 123456789012"),
                           ("collected", ["fixtures/jane@corp-mail.jp.json:3"])):
            doc = mapped_doc()
            doc["data_map"][0][key] = value
            with self.subTest(key=key), self.assertRaises(findings.SchemaError) as ctx:
                findings.validate(doc)
            self.assertIn(f"data_map[0].{key}", str(ctx.exception))
            self.assertNotIn("jane", str(ctx.exception))
        doc = mapped_doc()
        doc["findings"][0]["elements"] = "D-01 jane@corp-mail.jp"
        with self.assertRaisesRegex(findings.SchemaError, "findings\\[0\\].elements"):
            findings.validate(doc)

    def test_check_reports_an_element_citation_missing_from_the_map(self):
        doc = mapped_doc()
        doc["findings"][1]["elements"] = "D-02, D-07"
        self.assertEqual(findings.record_problems(doc),
                         ["findings[1].elements: D-07 is not in the data map"])

    def test_merge_updates_elements_by_id_and_renumber_leaves_collected_paths_alone(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            first = mapped_doc()
            first["data_map"][0]["collected"] = ["legacy/PV-002/form.py:3"]
            first["findings"] = [first["findings"][1] | {"id": "PV-009"}, first["findings"][0]
                                 | {"id": "PV-002"}]
            (tmp / "a.json").write_text(json.dumps(first), encoding="utf-8")
            (tmp / "b.json").write_text(json.dumps({"data_map": [{"id": "D-01", "recipients": []}]}),
                                        encoding="utf-8")
            target = str(tmp / "findings.json")
            self.assertEqual(run(findings.main, ["merge", target, str(tmp / "a.json"),
                                                 str(tmp / "b.json")])[0], 0)
            self.assertEqual(run(findings.main, ["renumber", target])[0], 0)
            doc = json.loads(Path(target).read_text(encoding="utf-8"))
        self.assertEqual(doc["data_map"][0]["recipients"], [])
        self.assertEqual(doc["data_map"][0]["stores"], ["orders table (primary)"])
        self.assertEqual(doc["data_map"][0]["collected"], ["legacy/PV-002/form.py:3"])
        self.assertEqual([f["id"] for f in doc["findings"]], ["PV-001", "PV-002"])

    def test_counts_and_recipients_ignore_case_and_spacing_and_keep_the_first_spelling(self):
        doc = mapped_doc()
        self.assertEqual(findings.recipients(doc),
                         {"Error tracking vendor": ["D-01", "D-02"], "Ad network": ["D-02"]})
        n = findings.counts(doc)
        self.assertEqual((n["n_elements"], n["n_sensitive_elements"], n["n_recipients"]), (2, 1, 2))
        self.assertEqual(findings.counts(complete_doc())["n_elements"], 0)

    def test_excluded_findings_are_not_listed_against_an_element(self):
        doc = mapped_doc()
        doc["findings"][1]["elements"] = "D-01"
        doc["findings"][1]["validation"] = {"verdict": "FalsePositive", "method": "static",
                                            "evidence": "scrubbed at app.py:9"}
        self.assertEqual(findings.element_citations(doc), {"D-01": ["PV-001"], "D-02": ["PV-001"]})


class DataMapRenderingTests(unittest.TestCase):
    def test_markdown_shows_the_map_and_who_receives_what(self):
        markdown = render.render_markdown(mapped_doc(), "en")
        self.assertIn("## Personal data map\n\n2 elements, 1 in a sensitive category, 2 recipients\n",
                      markdown)
        self.assertIn("| D-01 | shipping\\_address | contact | Customers | api/checkout/views.py:40 | "
                      "orders table (primary) | Error tracking vendor |  | PV-001 |", markdown)
        self.assertIn("| D-02 | date\\_of\\_birth (sensitive) | contact | Customers |  | orders table "
                      "(primary) | error tracking  VENDOR<br>Ad network | Until closure<br>Used for age "
                      "gate | PV-001 |", markdown)
        self.assertIn("### Who receives personal data\n\n| Recipient | Elements received |\n|---|---|\n"
                      "| Error tracking vendor | D-01 shipping\\_address<br>D-02 date\\_of\\_birth "
                      "(sensitive) |\n| Ad network | D-02 date\\_of\\_birth (sensitive) |", markdown)
        self.assertIn("- **data map:** D-01, D-02", markdown)
        # The map sits between the ledger and the coverage table.
        self.assertLess(markdown.index("## Privacy commitments"), markdown.index("## Personal data map"))
        self.assertLess(markdown.index("## Personal data map"), markdown.index("## Perspective coverage"))

    def test_a_record_without_a_map_renders_as_before(self):
        for doc in (complete_doc(), {**complete_doc(), "data_map": []}):
            self.assertNotIn("data map", render.render_markdown(doc, "en").lower())
            self.assertNotIn("id='data-map'", render.render_html(doc, "en"))

    def test_an_element_nobody_receives_adds_no_recipient_table(self):
        doc = mapped_doc()
        for r in doc["data_map"]:
            r["recipients"] = []
        markdown = render.render_markdown(doc, "en")
        self.assertIn("## Personal data map", markdown)
        self.assertNotIn("Who receives", markdown)

    def test_dashboard_marks_sensitive_rows_and_labels_cells_in_japanese(self):
        html = render.render_html(mapped_doc(), "ja")
        self.assertIn("<section id='data-map'>", html)
        self.assertIn("<h2>個人データマップ</h2><p class='muted'>要素 2 件（うち要配慮・機微 1 件）、受領者 2 件</p>",
                      html)
        self.assertIn("<tr data-sensitive><td class='nowrap' data-label='ID'>D-02</td>", html)
        self.assertIn("<td data-label='要素'>date_of_birth (機微)</td>", html)
        self.assertIn("<h3>個人データの受領者</h3>", html)
        self.assertEqual(html.count("<tr data-sensitive>"), 1)

    def test_rendered_prose_in_the_map_is_escaped(self):
        doc = mapped_doc()
        doc["data_map"][0]["stores"] = ["<script>x</script> | cache"]
        self.assertIn("&lt;script&gt;x&lt;/script&gt; \\| cache", render.render_markdown(doc, "en"))
        self.assertNotIn("<script>x", render.render_html(doc, "en"))

    def test_the_sample_with_its_map_passes_the_run_contract_in_both_languages(self):
        doc = json.loads(SAMPLE.read_text(encoding="utf-8"))
        self.assertTrue(doc["data_map"])
        for lang in ("ja", "en"):
            with tempfile.TemporaryDirectory() as d:
                (Path(d) / "findings.json").write_text(SAMPLE.read_text(encoding="utf-8"),
                                                       encoding="utf-8")
                self.assertEqual(run(render.main, [str(Path(d) / "findings.json"), "--out", d,
                                                   "--lang", lang])[0], 0)
                self.assertEqual(findings.contract_problems(d), [])


class DataMapComparisonTests(unittest.TestCase):
    def test_new_recipients_stores_elements_and_flags_are_listed(self):
        old, new = mapped_doc(), mapped_doc()
        new["data_map"][0]["recipients"].append("CRM vendor")
        new["data_map"][0]["stores"] = []
        new["data_map"][1]["sensitive"] = False
        new["data_map"][1]["id"] = "D-03"  # renumbered, matched by element name
        new["data_map"].append(element("D-04", element="precise_location", sensitive=True,
                                       recipients=["Ad network"]))
        old["data_map"].append(element("D-05", element="fax_number", recipients=[]))
        new["findings"][0]["elements"] = "D-01"
        result = compare.compare(old, new)["data_map"]
        self.assertEqual(result["changed"], [
            {"old_id": "D-01", "id": "D-01", "element": "shipping_address",
             "recipients_added": ["CRM vendor"], "stores_removed": ["orders table (primary)"]},
            {"old_id": "D-02", "id": "D-03", "element": "date_of_birth",
             "sensitive": {"from": True, "to": False}}])
        self.assertEqual([r["id"] for r in result["added"]], ["D-04"])
        self.assertEqual([r["id"] for r in result["removed"]], ["D-05"])
        markdown = compare.render_markdown(compare.compare(old, new), "en", render.markdown_text,
                                           render.markdown_code)
        self.assertIn("### Personal data map\n\n"
                      "- D-01 shipping\\_address: now sent to CRM vendor; no longer stored in orders "
                      "table (primary)\n"
                      "- D-03 date\\_of\\_birth: sensitive category True → False (D-02)\n"
                      "- D-04 precise\\_location (sensitive): added; now sent to Ad network\n"
                      "- D-05 fax\\_number: no longer in the data map\n", markdown)

    def test_spelling_changes_alone_are_not_changes(self):
        old, new = mapped_doc(), mapped_doc()
        new["data_map"][0]["recipients"] = ["error  tracking vendor"]
        result = compare.compare(old, new)
        self.assertEqual(result["data_map"], {"changed": [], "added": [], "removed": []})
        markdown = compare.render_markdown(result, "ja", render.markdown_text, render.markdown_code)
        self.assertTrue(markdown.endswith("### 個人データマップ\n\n変化なし\n"), markdown)

    def test_records_without_a_map_compare_as_before(self):
        result = compare.compare(complete_doc(), complete_doc())
        self.assertNotIn("data_map", result)
        markdown = compare.render_markdown(result, "en", render.markdown_text, render.markdown_code)
        self.assertNotIn("data map", markdown.lower())


class OwnerReportRecipientTests(unittest.TestCase):
    def test_the_owner_report_lists_recipients_and_drops_the_section_without_a_map(self):
        report = drafts.owner_report(mapped_doc(), "en")
        self.assertIn("## 5. Who receives personal data\n\n"
                      "- Error tracking vendor: D-01 shipping\\_address, D-02 date\\_of\\_birth (sensitive)\n"
                      "- Ad network: D-02 date\\_of\\_birth (sensitive)\n\n## 6. Checked and sound",
                      report)
        report = drafts.owner_report(complete_doc(), "ja")
        self.assertNotIn("個人データの受領者", report)
        self.assertIn("## 6. 確認して問題なかった項目", report)


class ExportTests(unittest.TestCase):
    def export(self, doc, fmt, extra=()):
        with tempfile.TemporaryDirectory() as d:
            record, scratch = Path(d) / "out" / "findings.json", Path(d) / "scratch"
            record.parent.mkdir()
            record.write_text(json.dumps(doc), encoding="utf-8")
            target = scratch / f"export.{fmt}"
            code, out, err = run(export.main, [str(record), "--format", fmt, "--out", str(target),
                                               *extra])
            text = target.read_text(encoding="utf-8") if target.exists() else None
        return code, text, err

    def test_sarif_holds_active_findings_with_levels_regions_and_suppressions(self):
        doc = mapped_doc()
        doc["findings"][0]["location"] = ["api/my app.py:22-30", "new/redact.py:0"]
        doc["findings"].append(findings_finding("PV-003", "Medium", status="Fixed"))
        doc["findings"].append(findings_finding("PV-004", "Low", status="Accepted", step=""))
        doc["findings"].append(findings_finding("PV-005", "Low", validation={
            "verdict": "NotApplicable", "method": "static", "evidence": "dead code"}))
        code, text, err = self.export(doc, "sarif")
        self.assertEqual(code, 0, err)
        sarif = json.loads(text)
        self.assertEqual(sarif["version"], "2.1.0")
        run_ = sarif["runs"][0]
        results = run_["results"]
        self.assertEqual([r["properties"]["id"] for r in results], ["PV-001", "PV-002", "PV-004"])
        self.assertEqual([r["level"] for r in results], ["error", "note", "note"])
        first = results[0]["locations"]
        self.assertEqual(first[0]["physicalLocation"],
                         {"artifactLocation": {"uri": "api/my%20app.py", "uriBaseId": "%SRCROOT%"},
                          "region": {"startLine": 22, "endLine": 30}})
        self.assertNotIn("region", first[1]["physicalLocation"])
        self.assertEqual(results[2]["suppressions"][0]["status"], "accepted")
        self.assertNotIn("suppressions", results[0])
        self.assertEqual([r["id"] for r in run_["tool"]["driver"]["rules"]], ["privacy/LT2", "privacy/LT"])
        self.assertEqual(results[0]["properties"]["elements"], "D-01, D-02")
        self.assertIn("not legal advice", run_["properties"]["disclaimer"])

    def test_fingerprints_survive_renumbering_and_differ_between_findings(self):
        doc = mapped_doc()
        before = export.fingerprint(doc["findings"][0])
        moved = copy.deepcopy(doc["findings"][0])
        moved["id"] = "PV-007"
        moved["location"] = ["api/app.py:99"]
        moved["title"] = "  error tracker RECEIVES request bodies "
        self.assertEqual(export.fingerprint(moved), before)
        self.assertNotEqual(export.fingerprint(doc["findings"][1]), before)

    def test_csv_lists_every_finding_and_neutralises_formula_cells(self):
        doc = mapped_doc()
        doc["findings"][0]["title"] = "=HYPERLINK(\"http://x.example\")"
        doc["findings"][1]["fix"] = "@SUM(1)"
        doc["findings"][1]["validation"] = {"verdict": "FalsePositive", "method": "static",
                                            "evidence": "scrubbed"}
        code, text, err = self.export(doc, "csv")
        self.assertEqual(code, 0, err)
        self.assertTrue(text.startswith("﻿id,severity,"))
        rows = list(csv.DictReader(io.StringIO(text.lstrip("﻿"))))
        self.assertEqual([r["id"] for r in rows], ["PV-001", "PV-002"])
        self.assertEqual(rows[0]["title"], "'=HYPERLINK(\"http://x.example\")")
        self.assertEqual(rows[1]["fix"], "'@SUM(1)")
        self.assertEqual((rows[0]["excluded"], rows[1]["excluded"]), ("no", "yes"))
        self.assertEqual(rows[0]["elements"], "D-01, D-02")

    def test_datamap_csv_lists_elements_with_their_findings(self):
        code, text, err = self.export(mapped_doc(), "datamap-csv")
        self.assertEqual(code, 0, err)
        rows = list(csv.DictReader(io.StringIO(text.lstrip("﻿"))))
        self.assertEqual([(r["id"], r["sensitive"], r["findings"]) for r in rows],
                         [("D-01", "no", "PV-001"), ("D-02", "yes", "PV-001")])
        self.assertEqual(rows[1]["recipients"], "error tracking  VENDOR\nAd network")

    def test_refusals(self):
        code, text, err = self.export(complete_doc(), "datamap-csv")
        self.assertEqual((code, text), (1, None))
        self.assertIn("no data_map", err)
        with tempfile.TemporaryDirectory() as d:
            record = Path(d) / "findings.json"
            record.write_text(json.dumps(mapped_doc()), encoding="utf-8")
            for target in (Path(d) / "x.sarif", record):
                code, _, err = run(export.main, [str(record), "--format", "sarif", "--out", str(target)])
                self.assertEqual(code, 1)
                self.assertIn("inside the run's output directory", err)
            other = Path(d) / "other"
            other.mkdir()
            (other / "report.md").write_text("x", encoding="utf-8")
            code, _, err = run(export.main, [str(record), "--format", "csv", "--out",
                                             str(other / "x.csv")])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(record.read_text(encoding="utf-8")), mapped_doc())
        broken = mapped_doc()
        broken["meta"].pop("scope")
        self.assertEqual(self.export(broken, "csv")[0], 1)


def findings_finding(fid, severity, **extra):
    from test_privacy_scan import finding
    return finding(fid, severity, location=[f"svc/{fid.lower()}.py:3"], **extra)


if __name__ == "__main__":
    unittest.main()
