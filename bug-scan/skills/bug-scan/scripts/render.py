#!/usr/bin/env python3
"""Render findings.json into dashboard.html, report.html and report.pdf.

    render.py <out>/findings.json --out <out> [--lang ja|en] [--no-pdf]

surfaces.json and history.json are read from beside the record. The shared register, filters and
report come from scan-report-kit; the figures are inserted around them. Exit codes: 0 written, 2 the
record is invalid or an output could not be written, 3 no PDF could be produced. Standard library only.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import diagrams  # noqa: E402
from common import RecordError, as_list, load_json, pattern_name  # noqa: E402
from findings import closed, excluded, shape_errors  # noqa: E402
from scan_report_kit import output, pdf, report  # noqa: E402

TEXT = {
    "ja": dict(
        kind="バグ混入診断", title="バグ混入診断報告書", dashboard_title="バグ混入診断の結果", footer="バグ混入診断報告書",
        register="不具合リスト", figures="図解", fix_action="修正方針", g_repro="再現手順", g_risk="リスクと危険性", g_surface="対象", g_relation="関連",
        g_after="修正後に確認すること", g_release="リリースと検知", g_track="追跡情報", status="状態", severity_note="重大度", none_recorded="記録なし",
        repro_state=dict(static="静的に導出（未実行）", test="テストで確認", verified="実行して確認", **{"not-reproduced": "実行したが再現せず"}, unknown="手順未確定"),
        preconditions="前提", fixture="データ", environment="環境", steps="手順", expected="期待", actual="実際", last_run="最終確認", state="状態",
        risk="リスク", likelihood="発生可能性", impact="影響", detectability="検知しやすさ", basis="判定根拠", classes="危険性の分類", irreversible="元に戻せない", silent="気づかず進む", reach="影響範囲", recovery="復旧方法",
        yn=dict(yes="はい", no="いいえ", unknown="不明"), level=dict(Low="低", Medium="中", High="高"),
        surfaces_label="対象", actors="操作する人", conditions="発生条件", relations="関連", sibling="横展開先", sib_state=dict(affected="同種あり", safe="影響なし", unknown="未確認"),
        data="データ修復", needed="修復の要否", locate="対象の探し方", method="修復方法", count="対象件数", rel_first="含む最初", rel_last="含む最後", rel_fixed="修正リリース", rel_basis="根拠",
        det_source="検知元", det_stage="検知段階", det_at="検知した日", det_days="混入→検知（日）", det_fix="検知→修正（日）", det_basis="根拠",
        pattern="パターン", module="モジュール", key="追跡キー", introduced="混入", fixed="修正", first_seen="初回検出", last_seen="最終確認", events="修正履歴", tests="既存テスト", tests_missing="足りないテスト",
        guard="再発防止", regression="回帰テスト", fix_order="修正の順序", owner="担当", refs="外部参照", verdict_evidence="検証の根拠",
    ),
    "en": dict(
        kind="Bug injection review", title="Bug Injection Report", dashboard_title="Bug Injection Results", footer="BUG INJECTION REPORT",
        register="Defect list", figures="Figures", fix_action="Fix direction", g_repro="Reproduction", g_risk="Risk and hazard", g_surface="Surfaces", g_relation="Relations",
        g_after="To check after the fix", g_release="Releases and detection", g_track="Tracking", status="Status", severity_note="Severity", none_recorded="not recorded",
        repro_state=dict(static="Derived from code (not run)", test="Confirmed by a test", verified="Run and confirmed", **{"not-reproduced": "Run, not reproduced"}, unknown="Steps not settled"),
        preconditions="Preconditions", fixture="Data", environment="Environment", steps="Steps", expected="Expected", actual="Actual", last_run="Last checked", state="State",
        risk="Risk", likelihood="Likelihood", impact="Impact", detectability="Detectability", basis="Basis", classes="Hazard classes", irreversible="Irreversible", silent="Silent", reach="Reach", recovery="Recovery",
        yn=dict(yes="yes", no="no", unknown="unknown"), level=dict(Low="Low", Medium="Medium", High="High"),
        surfaces_label="Surfaces", actors="Actors", conditions="Conditions", relations="Relations", sibling="Sibling sites", sib_state=dict(affected="affected", safe="safe", unknown="unknown"),
        data="Data remediation", needed="Needed", locate="How to locate", method="Method", count="Count", rel_first="First containing", rel_last="Last containing", rel_fixed="First fixed", rel_basis="Basis",
        det_source="Source", det_stage="Stage", det_at="Detected on", det_days="Days to detect", det_fix="Days to fix", det_basis="Basis",
        pattern="Pattern", module="Module", key="Tracking key", introduced="Introduced in", fixed="Fixed in", first_seen="First seen", last_seen="Last seen", events="Fix events", tests="Existing tests", tests_missing="Missing tests",
        guard="Guard", regression="Regression test", fix_order="Fix order", owner="Owner", refs="External references", verdict_evidence="Evidence",
    ),
}
KIT_STATUS = dict(Open="Open", Triaged="Open", Reopened="Open", Unverified="Open", Accepted="Accepted", Fixed="Fixed", Verified="Fixed")


def rows_field(label, group, rows):
    rows = [[str(a), str(b)] for a, b in rows if b not in (None, "", [])]
    return dict(label=label, group=group, rows=rows) if rows else None


def text_field(label, group, value):
    return dict(label=label, group=group, text=str(value)) if value not in (None, "") else None


def lines(values):
    return "\n".join(str(v) for v in values)


def common_finding(finding, record, surfaces, t, lang):
    catalog = {s["id"]: s for s in surfaces.get("surfaces", [])}
    fields = []
    repro = finding.get("repro")
    if repro:
        group = t["g_repro"]
        fields.append(rows_field(t["state"], group, [
            (t["state"], t["repro_state"][repro["state"]]), (t["last_run"], repro.get("last_run")), (t["preconditions"], lines(repro.get("preconditions", []))),
            (t["fixture"], repro.get("fixture")), (t["environment"], repro.get("environment")),
            (t["steps"], "\n".join(f"{n}. {s}" for n, s in enumerate(repro.get("steps", []), 1))), (t["expected"], repro.get("expected")), (t["actual"], repro.get("actual"))]))
    risk, hazard = finding.get("risk"), finding.get("hazard")
    if risk:
        fields.append(rows_field(t["risk"], t["g_risk"], [
            (t["risk"], t["level"][risk["level"]]), (t["likelihood"], t["level"][risk["likelihood"]]), (t["impact"], t["level"][risk["impact"]]),
            (t["detectability"], risk.get("detectability")), (t["basis"], risk.get("basis"))]))
    if hazard:
        fields.append(rows_field(t["classes"], t["g_risk"], [
            (t["classes"], "、".join(hazard["classes"]) if lang == "ja" else ", ".join(hazard["classes"])), (t["irreversible"], t["yn"][hazard["irreversible"]]),
            (t["silent"], t["yn"][hazard["silent"]]), (t["reach"], hazard.get("reach")), (t["recovery"], hazard.get("recovery"))]))
    surface_rows = []
    for surface in finding.get("surfaces", []):
        item = catalog.get(surface["id"], {})
        surface_rows.append((surface["id"], " ".join(str(v) for v in (item.get("name"), f"[{surface['op']}]" if surface.get("op") else "", item.get("location")) if v)))
    fields.append(rows_field(t["surfaces_label"], t["g_surface"], surface_rows))
    fields.append(rows_field(t["actors"], t["g_surface"], [(t["actors"], lines(finding.get("actors", []))), (t["conditions"], lines(finding.get("conditions", [])))]))
    relation_rows = [(f"{r['type']} → {r['to']}", f"{r['strength']}: {r['evidence']}") for r in finding.get("relations", [])]
    fields.append(rows_field(t["relations"], t["g_relation"], relation_rows))
    sibling_rows = [(s["location"], f"{t['sib_state'][s['state']]}: {s['evidence']}") for s in finding.get("sibling_sites", [])]
    fields.append(rows_field(t["sibling"], t["g_after"], sibling_rows))
    data = finding.get("data_remediation")
    if data:
        fields.append(rows_field(t["data"], t["g_after"], [(t["needed"], t["yn"][data["needed"]]), (t["locate"], data.get("locate")), (t["method"], data.get("method")), (t["count"], data.get("count"))]))
    releases, detection = finding.get("affected_releases"), finding.get("detection")
    if releases:
        fields.append(rows_field(t["g_release"], t["g_release"], [(t["rel_first"], releases["first"]), (t["rel_last"], releases["last"]), (t["rel_fixed"], releases.get("fixed_first")), (t["rel_basis"], releases["basis"])]))
    if detection:
        fields.append(rows_field(t["det_source"], t["g_release"], [
            (t["det_source"], detection["source"]), (t["det_stage"], detection["stage"]), (t["det_at"], detection.get("detected_at")),
            (t["det_days"], detection.get("days_to_detect")), (t["det_fix"], detection.get("days_to_fix")), (t["det_basis"], detection.get("basis"))]))
    introduced = finding.get("introduced_in") or {}
    tracking = [
        (t["status"], finding["status"]), (t["severity_note"], finding.get("severity") or t["none_recorded"]),
        (t["pattern"], f"{finding.get('pattern')} {pattern_name(finding.get('pattern'), lang)}" if finding.get("pattern") else None), (t["module"], finding.get("module")),
        (t["key"], finding.get("key")), (t["introduced"], f"{introduced.get('commit', '')} {introduced.get('strength', '')} {introduced.get('reason', '')}".strip()),
        (t["fixed"], finding.get("fixed_in")), (t["first_seen"], finding.get("first_seen")), (t["last_seen"], finding.get("last_seen")),
        (t["events"], ", ".join(finding.get("events", []))), (t["tests"], finding.get("tests")), (t["tests_missing"], finding.get("tests_missing")),
        (t["guard"], finding.get("guard")), (t["regression"], finding.get("regression_test")), (t["fix_order"], finding.get("fix_order")),
        (t["owner"], finding.get("owner")), (t["verdict_evidence"], (finding.get("validation") or {}).get("evidence")), (t["refs"], lines(finding.get("external_refs", []))),
    ]
    fields.append(rows_field(t["g_track"], t["g_track"], tracking))
    out = dict(id=finding["id"], title=finding["title"], severity=finding.get("severity") or "Info", status=KIT_STATUS[finding["status"]],
               fields=[f for f in fields if f])
    if finding.get("confidence"):
        out["confidence"] = finding["confidence"]
    verdict = (finding.get("validation") or {}).get("verdict")
    if verdict:
        out["verdict"] = verdict
    if finding.get("pattern"):
        out["category"] = pattern_name(finding["pattern"], lang)
    locations = as_list(finding.get("location"))
    if locations:
        out["location"] = ", ".join(locations)
    if excluded(finding):
        out["excluded"] = True
    if finding.get("fix") and not closed(finding):
        out["action"] = dict(label=t["fix_action"], text=finding["fix"])
    return out


def to_common(record, surfaces, lang):
    t = TEXT[lang]
    meta = record["meta"]
    perspectives = [dict(name=f"{p['name']} {pattern_name(p['name'], lang)}", result=p["status"], note=p.get("note", "")) for p in record.get("perspectives", [])]
    data = dict(format=report.FORMAT,
                meta={k: meta[k] for k in ("project", "date", "assessor", "scope", "method", "commit") if meta.get(k)},
                report=dict(kind=t["kind"], title=t["title"], dashboard_title=t["dashboard_title"], running_footer=t["footer"]),
                labels=dict(register=t["register"]),
                findings=[common_finding(f, record, surfaces, t, lang) for f in record.get("findings", [])],
                perspectives=perspectives)
    if record.get("summary"):
        data["summary"] = record["summary"]
    for name in ("limitations", "decisions", "next_steps", "checked_ok"):
        data[name] = list(record.get(name, []))
    return data


def insert_once(html, anchor, addition, before=True):
    if html.count(anchor) < 1:
        raise RecordError(f"scan-report-kit output has no {anchor!r}; re-check the vendored kit")
    index = html.index(anchor)
    return html[:index] + addition + html[index:] if before else html[:index + len(anchor)] + addition + html[index + len(anchor):]


def build(record, surfaces, history, lang):
    """Return (dashboard, report) as text. Deterministic, so the contract can compare a fresh render."""
    errors = shape_errors(record)
    if errors:
        raise RecordError("; ".join(errors[:8]))
    if not record.get("meta", {}).get("project") or not record.get("meta", {}).get("date"):
        raise RecordError("meta.project and meta.date are required to render")
    common = report.validate(to_common(record, surfaces, lang))
    figs = diagrams.figures(record, surfaces, history, lang)
    t = TEXT[lang]
    dashboard = report.render_dashboard(common, lang)
    dashboard = insert_once(dashboard, "</head>", f"<style>{diagrams.dashboard_css()}</style>")
    dashboard = insert_once(dashboard, '<section id="findings"', diagrams.section_html(figs, lang, printable=False))
    dashboard = insert_once(dashboard, '</ol><div class="facets">', f'<li><a href="#figures">{diagrams.e(t["figures"])}</a></li>')
    dashboard = insert_once(dashboard, "</body>", f'<div id="bs-tip" role="status"></div><script>{diagrams.SCRIPT}</script>')
    document = report.render_document(common, lang)
    document = insert_once(document, "</head>", f"<style>{diagrams.document_css()}</style>")
    document = insert_once(document, '<section id="finding-register"', diagrams.section_html(figs, lang, printable=True))
    return dashboard, document


def load_inputs(record_path):
    base = Path(record_path).parent
    record = load_json(record_path)
    surfaces = load_json(base / "surfaces.json")
    history = load_json(base / "history.json")
    return record, surfaces, history


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("record")
    parser.add_argument("--out", required=True)
    parser.add_argument("--lang", choices=("ja", "en"))
    parser.add_argument("--no-pdf", action="store_true")
    args = parser.parse_args(argv)
    try:
        record, surfaces, history = load_inputs(args.record)
        lang = args.lang or record.get("meta", {}).get("lang") or "ja"
        dashboard, document = build(record, surfaces, history, lang)
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        output.write_outputs(out, {"dashboard.html": dashboard, "report.html": document}, remove=("report.pdf",) if args.no_pdf else ())
    except (RecordError, OSError, ValueError, report.FormatError) as error:
        print(f"render.py: {error}", file=sys.stderr)
        return 2
    print(f"wrote {out / 'dashboard.html'} and {out / 'report.html'}")
    if args.no_pdf:
        return 0
    failures = []
    try:
        engine = pdf.to_pdf(out / "report.html", out / "report.pdf", failures)
    except (OSError, ValueError) as error:
        engine = None
        failures.append(("pdf", str(error), ""))
    if not engine:
        reason = "; ".join(f"{name}: {why}" for name, why, *_ in failures) or "no Chrome, Chromium or WeasyPrint found"
        print(f"render.py: report.pdf not produced ({reason}). report.html is ready to print. Retry once outside the host's sandbox if the browser "
              "could not start inside it. When no engine can produce it, merge the limitation 'report.pdf not produced: <reason>', "
              "render with --no-pdf, then contract_check.py <out> --no-pdf", file=sys.stderr)
        return 3
    print(f"wrote {out / 'report.pdf'} ({engine})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
