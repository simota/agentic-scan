#!/usr/bin/env python3
"""Render a ux-scan findings.json into a dashboard, a report and its PDF.

    python3 render.py FINDINGS --out DIR [--lang ja|en] [--repo REPO] [--no-pdf]

Maps the record into scan-report-kit's common format (scan-report/1) and writes
DIR/dashboard.html, DIR/report.html and DIR/report.pdf (headless Chrome, else
WeasyPrint; CHROME picks the binary, UX_SCAN_PDF_TIMEOUT the seconds). With
--repo, each finding's location is embedded as a short excerpt; secret-looking
files are never read and secret-looking lines are masked. Every page carries the
SHA-256 of the findings.json it shows. Standard library only.
Exit status: 0 written, 2 invalid record or unwritable output, 3 no PDF produced.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import EXCLUDED, RecordError, check_findings, check_flows, flow_ids  # noqa: E402
from scan_report_kit import output, pdf, report  # noqa: E402

OUTPUTS = ("dashboard.html", "report.html", "report.pdf")
STAMP = "ux-scan-source"
SENSITIVE = re.compile(r"(?i)(?:^|/)(?:\.env(?:\..*)?|.*\.(?:pem|key|p12|pfx|jks|keystore)|id_[rd]sa.*|\.netrc|"
                       r".*credentials.*|.*secrets?\..*|\.npmrc|\.pypirc)$")
SECRET_LINE = re.compile(r"(?i)(?:secret|token|passw(?:or)?d|api[_-]?key|private[_-]?key|client[_-]?secret)\s*[\"']?\s*[:=]")
LOC = re.compile(r"^(?P<path>[^:]+):(?P<start>[0-9]+)(?:-(?P<end>[0-9]+))?$")
CONTEXT = 3

FAMILIES = {
    "en": {"IA": "Information architecture", "LG": "Layout and grid", "RS": "Responsive",
           "VH": "Visual hierarchy", "CC": "Components and consistency", "ST": "Interaction states",
           "FM": "Forms and input", "FB": "Feedback and status", "CP": "Content and microcopy",
           "AX": "Accessibility", "MO": "Motion", "IN": "Internationalized layout", "PP": "Perceived performance"},
    "ja": {"IA": "情報設計・ナビゲーション", "LG": "レイアウト・グリッド", "RS": "レスポンシブ",
           "VH": "視覚階層・タイポグラフィ", "CC": "コンポーネント・一貫性", "ST": "インタラクション状態",
           "FM": "フォーム・入力", "FB": "フィードバック・状態表示", "CP": "コンテンツ・文言",
           "AX": "アクセシビリティ", "MO": "モーション", "IN": "多言語レイアウト", "PP": "体感性能"},
}
PRIORITY = {"en": {"primary": "primary", "secondary": "secondary", "shared": "shared"},
            "ja": {"primary": "主要", "secondary": "副次", "shared": "共通"}}
LABELS = {
    "en": {"kind": "UX review", "title": "UX Review Report", "dashboard_title": "UX Review Results",
           "running_footer": "UX REVIEW", "fix": "Fix", "verify": "Verify first",
           "verify_text": "Confirm the user reaches this state and it is not compensated elsewhere before changing it.",
           "observed": "Observed", "expected": "Expected", "criterion": "Criterion", "flow": "Flow",
           "screen": "Screen", "viewport": "Viewport", "occurrences": "Occurrences", "impact": "Impact",
           "evidence": "Verification", "intent": "Intent checked"},
    "ja": {"kind": "UX診断", "title": "UX診断書", "dashboard_title": "UX診断結果",
           "running_footer": "UX診断", "fix": "修正", "verify": "先に検証",
           "verify_text": "変更する前に、利用者が実際にこの状態に到達し、他の箇所で補われていないことを確認してください。",
           "observed": "現状", "expected": "あるべき状態", "criterion": "判断基準", "flow": "フロー",
           "screen": "画面", "viewport": "ビューポート", "occurrences": "出現箇所", "impact": "影響",
           "evidence": "検証根拠", "intent": "意図の確認"},
}


def snippet(repo, location):
    """Lines around location from repo, or None when unreadable, outside repo or secret-looking."""
    m = LOC.match(location)
    if not repo or not m or SENSITIVE.search(m["path"]):
        return None
    root = Path(repo).resolve()
    path = (root / m["path"]).resolve()
    try:
        path.relative_to(root)
        if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
            return None
        lines = path.read_text(encoding="utf-8").splitlines()
    except (ValueError, OSError, UnicodeDecodeError):
        return None
    start, end = int(m["start"]), int(m["end"] or m["start"])
    if start > len(lines):
        return None
    first, last = max(1, start - CONTEXT), min(len(lines), end + CONTEXT)
    shown = ["[masked: looks like a secret]" if SECRET_LINE.search(line) else line[:240]
             for line in lines[first - 1:last]]
    return {"start": first, "hit": [start, min(end, last)], "lines": shown}


def to_common(data, lang, flows=None, repo=None):
    """data (findings.json) as a scan-report/1 record."""
    T, fam, prio = LABELS[lang], FAMILIES[lang], PRIORITY[lang]
    by_flow = {fl["id"]: fl for fl in (flows or {}).get("flows", [])}
    findings = []
    for f in data["findings"]:
        verdict = f["validation"]["verdict"]
        flow = by_flow.get(f["flow_ref"])
        fields = [(T["observed"], f.get("observed", "")), (T["expected"], f.get("expected", "")),
                  (T["criterion"], f["criterion"]),
                  (T["flow"], f"{f['flow_ref']}: {flow['name']} ({prio[flow['priority']]})" if flow else f["flow_ref"]),
                  (T["screen"], f["screen"]), (T["viewport"], f.get("viewport", "")),
                  (T["impact"], f.get("impact", "")), (T["fix"], f.get("fix", "")),
                  (T["occurrences"], "\n".join(f.get("occurrences", []))),
                  (T["evidence"], f["validation"].get("evidence", "")),
                  (T["intent"], f["validation"].get("intent_checked", ""))]
        fix_is_action = f["status"] == "Open" and verdict == "Valid"
        if fix_is_action:  # Shown once, as the next action.
            fields = [(k, v) for k, v in fields if k != T["fix"]]
        item = {"id": f["id"], "title": f["title"], "severity": f["severity"], "status": f["status"],
                "confidence": f["confidence"], "verdict": verdict,
                "category": f.get("category") or fam.get(f["perspective"][:2], f["perspective"]),
                "location": f["location"], "excluded": verdict in EXCLUDED,
                "fields": [{"label": k, "text": v} for k, v in fields if v],
                "references": f.get("references", [])}
        if f["status"] == "Open" and verdict not in EXCLUDED:
            item["action"] = ({"label": T["fix"], "text": f.get("fix", "")} if fix_is_action
                              else {"label": T["verify"], "text": T["verify_text"]})
        excerpt = snippet(repo, f["location"])
        if excerpt:
            item["snippet"] = excerpt
        findings.append(item)
    meta = data["meta"]
    return {
        "format": report.FORMAT,
        "meta": {k: meta[k] for k in ("project", "date", "assessor", "scope", "method", "commit") if meta.get(k)},
        "report": {k: T[k] for k in ("kind", "title", "dashboard_title", "running_footer")},
        "summary": data.get("summary", ""),
        "findings": findings,
        "perspectives": data.get("perspectives", []),
        **{k: data.get(k, []) for k in ("limitations", "decisions", "next_steps", "checked_ok")},
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("findings")
    p.add_argument("--out", required=True)
    p.add_argument("--lang", choices=sorted(LABELS), default="en")
    p.add_argument("--repo", help="reviewed repository root: embeds excerpts for path:line locations")
    p.add_argument("--no-pdf", action="store_true", help="skip PDF generation")
    a = p.parse_args(argv)
    try:
        source = Path(a.findings).read_bytes()
        flows_path = Path(a.findings).with_name("flows.json")
        flows = check_flows(json.loads(flows_path.read_text(encoding="utf-8"))) if flows_path.exists() else None
        data = check_findings(json.loads(source.decode("utf-8")), flow_ids(flows) if flows else None)
        common = report.validate(to_common(data, a.lang, flows, a.repo))
        stamp = f'<meta name="{STAMP}" content="sha256:{hashlib.sha256(source).hexdigest()}">'
        pages = {name: page.replace("<head>", "<head>" + stamp, 1) for name, page in (
            ("dashboard.html", report.render_dashboard(common, a.lang)),
            ("report.html", report.render_document(common, a.lang)))}
    except (OSError, ValueError, RecordError, report.FormatError) as e:
        print(f"render.py: {e}", file=sys.stderr)
        return 2
    out = Path(a.out)
    try:
        out.mkdir(parents=True, exist_ok=True)
        bad = output.unsafe_target(out, OUTPUTS)
        if bad:
            print(f"render.py: refusing to write {bad}: it exists as a symlink or non-regular file", file=sys.stderr)
            return 2
        for name, page in pages.items():
            output.write_output(out / name, page)
            print(f"wrote {out / name}")
        if a.no_pdf:
            (out / "report.pdf").unlink(missing_ok=True)
            return 0
    except OSError as e:
        print(f"render.py: cannot write outputs to {out}: {e.strerror or e}", file=sys.stderr)
        return 2
    failures = []
    timeout = pdf.pdf_timeout(len(data["findings"]), env="UX_SCAN_PDF_TIMEOUT")
    engine = pdf.to_pdf(out / "report.html", out / "report.pdf", failures, timeout,
                        redact=lambda s: SECRET_LINE.sub("[masked]", s))
    if not engine:
        detail = "; ".join(f"{n} {why}" + (f" [{tail}]" if tail else "") for n, why, tail in failures)
        print("render.py: " + (f"PDF engine failed: {detail}" if failures else "no PDF engine found (Chrome/Chromium or weasyprint)")
              + ". report.html is ready to print. If no engine can run: merge the limitation "
              "'report.pdf not produced: no PDF engine', re-run with --no-pdf, then contract_check.py <out> --no-pdf",
              file=sys.stderr)
        return 3
    print(f"wrote {out / 'report.pdf'} ({engine})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
