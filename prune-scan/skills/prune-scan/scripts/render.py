#!/usr/bin/env python3
"""Render a prune-scan findings.json into a dashboard, a report and its PDF.

    python3 render.py FINDINGS --out DIR [--lang ja|en] [--repo REPO] [--no-pdf]

Maps the record into scan-report-kit's common format (scan-report/1) and writes
DIR/dashboard.html, DIR/report.html and DIR/report.pdf (headless Chrome, else
WeasyPrint; CHROME picks the binary, PRUNE_SCAN_PDF_TIMEOUT the seconds). The
rendered next steps open with the subtraction summary (remove now, reduce or
consolidate, decide with a human), computed from the findings. With --repo,
each finding's location is embedded as a short excerpt; secret-looking files
are never read and secret-looking lines are masked. Every page carries the
SHA-256 of the findings.json and, when supplied, units.json it shows.
Standard library only.
Exit status: 0 written, 2 invalid record or unwritable output, 3 no PDF produced.
"""

import argparse
import hashlib
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import EXCLUDED, RecordError, check_findings, check_units, parse_json, read_json_source  # noqa: E402
from scan_report_kit import output, pdf, report  # noqa: E402

OUTPUTS = ("dashboard.html", "report.html", "report.pdf")
STAMP = "prune-scan-source"
UNITS_STAMP = "prune-scan-units"
SENSITIVE = re.compile(r"(?i)(?:^|/)(?:\.env(?:\..*)?|.*\.(?:pem|key|p12|pfx|jks|keystore)|"
                       r"id_(?:[rd]sa|ecdsa|ed25519|xmss).*|\.netrc|"
                       r".*credentials.*|.*secrets?\..*|\.npmrc|\.pypirc)$")
SECRET_LINE = re.compile(r"(?i)(?:secret|token|passw(?:or)?d|api[_-]?key|private[_-]?key|client[_-]?secret)\s*[\"']?\s*[:=]")
LOC = re.compile(r"^(?P<path>[^:]+):(?P<start>[0-9]+)(?:-(?P<end>[0-9]+))?$")
CONTEXT = 3
MAX_SNIPPET_LINES = 80
MAX_SOURCE_BYTES = 2 * 1024 * 1024

FAMILIES = {
    "en": {"DC": "Dead code", "UF": "Unused features", "FF": "Feature flags and experiments", "DP": "Dependencies",
           "CF": "Configuration and environment", "DA": "Data and schema", "AS": "Assets and content",
           "TT": "Tests and tooling", "DU": "Duplication", "AP": "API surface", "PI": "Permissions and integrations",
           "PX": "Purpose fit", "OB": "Over-built"},
    "ja": {"DC": "デッドコード", "UF": "未使用の機能", "FF": "フィーチャーフラグ・実験", "DP": "依存関係",
           "CF": "設定・環境変数", "DA": "データ・スキーマ", "AS": "アセット・コンテンツ", "TT": "テスト・ツール",
           "DU": "重複", "AP": "API 表面", "PI": "権限・外部連携", "PX": "目的との適合", "OB": "作り込み過剰"},
}
ACTIONS = {"en": {"remove": "Remove", "reduce": "Reduce", "consolidate": "Consolidate"},
           "ja": {"remove": "削除", "reduce": "縮小", "consolidate": "統合"}}
SOURCES = {"en": {"documented": "documented", "stated": "stated by the requester", "inferred": "inferred"},
           "ja": {"documented": "文書化済み", "stated": "依頼者の言明", "inferred": "推定"}}
LABELS = {
    "en": {"kind": "Prune review", "title": "Prune Review Report", "dashboard_title": "Prune Review Results",
           "running_footer": "PRUNE REVIEW", "subtract": "Subtract", "verify": "Verify first",
           "verify_text": "Confirm nothing outside the repository uses it (clients, other services, operations, "
                          "data duties) and, for purpose findings, that the owner agrees, before removing it.",
           "element": "Element", "observed": "Observed", "basis": "Why it does not earn its place",
           "purpose": "Purpose item", "impact": "Cost of keeping", "subtraction": "Subtraction",
           "remains": "What remains", "loses": "What is lost", "risk": "Risk of removal", "unit": "Review unit",
           "entry": "Entry point", "occurrences": "Occurrences", "evidence": "Verification",
           "dynamic": "Dynamic and external use checked",
           "now": "Subtraction - remove now", "reduce": "Subtraction - reduce or consolidate",
           "decide": "Subtraction - decide with a human", "count": "{n}"},
    "ja": {"kind": "不要要素診断", "title": "不要要素診断書", "dashboard_title": "不要要素診断結果",
           "running_footer": "不要要素診断", "subtract": "引き算", "verify": "先に検証",
           "verify_text": "削除する前に、リポジトリの外(クライアント、他サービス、運用、データの保存義務)で使われていないこと、"
                          "目的に関する指摘はオーナーの合意を確認してください。",
           "element": "対象", "observed": "現状", "basis": "役に立っていない根拠", "purpose": "目的項目",
           "impact": "持ち続けるコスト", "subtraction": "引き算", "remains": "残る形", "loses": "失うもの",
           "risk": "削除のリスク", "unit": "レビュー単位", "entry": "入口", "occurrences": "出現箇所",
           "evidence": "検証根拠", "dynamic": "動的・外部利用の確認",
           "now": "引き算 - 今すぐ削除", "reduce": "引き算 - 縮小・統合", "decide": "引き算 - 人が判断",
           "count": "{n}件"},
}


def snippet(repo, location):
    """Lines around location from repo, or None when unreadable, outside repo or secret-looking."""
    m = LOC.fullmatch(location)
    if not repo or not m or SENSITIVE.search(m["path"]):
        return None
    try:
        start, end = int(m["start"]), int(m["end"] or m["start"])
        if start < 1 or end < start:
            return None
        root = Path(repo).resolve()
        path = (root / m["path"]).resolve()
        resolved = path.relative_to(root).as_posix()
        if SENSITIVE.search(resolved) or not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES:
            return None
        with path.open("rb") as handle:
            source = handle.read(MAX_SOURCE_BYTES + 1)
        if len(source) > MAX_SOURCE_BYTES or b"\0" in source:
            return None
        lines = source.decode("utf-8").splitlines()
    except (ValueError, OSError, RuntimeError):
        return None
    if start > len(lines):
        return None
    first, last = max(1, start - CONTEXT), min(len(lines), end + CONTEXT)
    last = min(last, first + MAX_SNIPPET_LINES - 1)
    shown = ["[masked: looks like a secret]" if SECRET_LINE.search(line) else line[:240]
             for line in lines[first - 1:last]]
    return {"start": first, "hit": [start, min(end, last)], "lines": shown}


def pdf_complete(path):
    """Check stored artifacts for the run contract too; not a full PDF parser."""
    path = Path(path)
    try:
        if path.is_symlink() or not path.is_file():
            return False
        with path.open("rb") as handle:
            header = handle.read(8)
            handle.seek(0, os.SEEK_END)
            handle.seek(max(0, handle.tell() - 1024))
            tail = handle.read()
        return bool(re.fullmatch(rb"%PDF-[12]\.[0-9]", header) and re.search(rb"%%EOF\s*\Z", tail))
    except OSError:
        return False


def redact_diagnostic(text):
    """Engine stderr may echo a secret value: mask the complete diagnostic."""
    return "[masked: looks like a secret]" if SECRET_LINE.search(text) else text


def act_now(f):
    """An open finding ready to subtract: Valid, which findings.py allows only with Confirmed confidence.

    The one rule behind both the card's next action and the subtraction summary.
    """
    return f["status"] == "Open" and f["validation"]["verdict"] == "Valid"


def subtraction_groups(findings):
    """Open, counted findings as (remove now, reduce or consolidate, decide with a human) id lists."""
    now, reduce, decide = [], [], []
    for f in findings:
        verdict = f["validation"]["verdict"]
        if f["status"] != "Open" or verdict in EXCLUDED or verdict == "Unlikely":
            continue
        if act_now(f):
            (now if f["subtraction"]["action"] == "remove" else reduce).append(f["id"])
        else:
            decide.append(f["id"])
    return now, reduce, decide


def subtraction_lines(findings, lang):
    T = LABELS[lang]
    return [f"{T[key]} ({T['count'].format(n=len(ids))}): {', '.join(ids)}"
            for key, ids in zip(("now", "reduce", "decide"), subtraction_groups(findings)) if ids]


def to_common(data, lang, units=None, repo=None):
    """data (findings.json) as a scan-report/1 record."""
    T, fam, acts, srcs = LABELS[lang], FAMILIES[lang], ACTIONS[lang], SOURCES[lang]
    by_unit = {u["id"]: u for u in (units or {}).get("units", [])}
    by_entry = {e["id"]: e for e in (units or {}).get("entry_points", [])}
    by_purpose = {p["id"]: p for p in (units or {}).get("purpose", [])}
    findings = []
    for f in data["findings"]:
        verdict = f["validation"]["verdict"]
        sub = f["subtraction"]
        unit, entry, purpose = by_unit.get(f["unit_ref"]), by_entry.get(f.get("entry_ref")), by_purpose.get(f.get("purpose_ref"))
        subtract_text = f"{acts[sub['action']]}: {sub['what']}"
        fields = [(T["element"], f["element"]), (T["observed"], f.get("observed", "")),
                  (T["basis"], f["basis"]),
                  (T["purpose"], (f"{purpose['id']}: {purpose['text']} ({srcs[purpose['source']]})" if purpose
                                  else f.get("purpose_ref", ""))),
                  (T["impact"], f.get("impact", "")), (T["subtraction"], subtract_text),
                  (T["remains"], sub["remains"]), (T["loses"], sub["loses"]), (T["risk"], f["risk"]),
                  (T["unit"], f"{f['unit_ref']}: {unit['name']}" if unit else f["unit_ref"]),
                  (T["entry"], f"{entry['id']}: {entry['name']}" if entry else f.get("entry_ref", "")),
                  (T["occurrences"], "\n".join(f.get("occurrences", []))),
                  (T["evidence"], f["validation"].get("evidence", "")),
                  (T["dynamic"], f["validation"].get("dynamic_checked", ""))]
        ready = act_now(f)
        if ready:  # Shown once, as the next action.
            fields = [(k, v) for k, v in fields if k != T["subtraction"]]
        item = {"id": f["id"], "title": f["title"], "severity": f["severity"], "status": f["status"],
                "confidence": f["confidence"], "verdict": verdict,
                "category": f.get("category") or fam.get(f["perspective"][:2], f["perspective"]),
                "location": f["location"], "excluded": verdict in EXCLUDED,
                "fields": [{"label": k, "text": v} for k, v in fields if v],
                "references": f.get("references", [])}
        if f["status"] == "Open" and verdict not in EXCLUDED:
            item["action"] = ({"label": T["subtract"], "text": subtract_text} if ready
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
        **{k: data.get(k, []) for k in ("limitations", "decisions", "checked_ok")},
        "next_steps": subtraction_lines(data["findings"], lang) + data.get("next_steps", []),
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
        source = read_json_source(a.findings)
        units_path = Path(a.findings).with_name("units.json")
        units_source = read_json_source(units_path) if units_path.exists() else None
        units = check_units(parse_json(units_source, str(units_path))) if units_source is not None else None
        data = check_findings(parse_json(source, a.findings), units)
        common = report.validate(to_common(data, a.lang, units, a.repo))
        stamp = f'<meta name="{STAMP}" content="sha256:{hashlib.sha256(source).hexdigest()}">'
        if units_source is not None:
            stamp += f'<meta name="{UNITS_STAMP}" content="sha256:{hashlib.sha256(units_source).hexdigest()}">'
        pages = {name: page.replace("<head>", "<head>" + stamp, 1) for name, page in (
            ("dashboard.html", report.render_dashboard(common, a.lang)),
            ("report.html", report.render_document(common, a.lang)))}
    except (OSError, ValueError, RecordError, report.FormatError) as e:
        print(f"render.py: {e}", file=sys.stderr)
        return 2
    out = Path(a.out)
    try:
        if Path(a.findings).resolve() in {(out / name).resolve() for name in OUTPUTS}:
            print("render.py: output would overwrite the findings source; choose a different --out directory",
                  file=sys.stderr)
            return 2
        out.mkdir(parents=True, exist_ok=True)
        bad = output.unsafe_target(out, OUTPUTS)
        if bad:
            print(f"render.py: refusing to write {bad}: it exists as a symlink or non-regular file", file=sys.stderr)
            return 2
        # Stage both pages and remove the previous PDF in one rollback-capable
        # update. A failed write or installation restores the old report.
        output.write_outputs(out, pages, remove=("report.pdf",))
        for name in pages:
            print(f"wrote {out / name}")
        if a.no_pdf:
            return 0
    except (OSError, ValueError, RuntimeError) as e:
        print(f"render.py: cannot write outputs to {out}: {getattr(e, 'strerror', None) or e}", file=sys.stderr)
        return 2
    failures = []
    timeout = pdf.pdf_timeout(len(data["findings"]), env="PRUNE_SCAN_PDF_TIMEOUT")
    try:
        engine = pdf.to_pdf(out / "report.html", out / "report.pdf", failures, timeout,
                            redact=redact_diagnostic)
        if engine and not pdf_complete(out / "report.pdf"):
            failures.append((engine, "did not produce a complete PDF; its output was discarded", ""))
            engine = None
        if not engine:
            (out / "report.pdf").unlink(missing_ok=True)
    except (OSError, ValueError) as e:
        try:
            (out / "report.pdf").unlink(missing_ok=True)
        except OSError:
            pass
        print(f"render.py: cannot write PDF to {out}: {redact_diagnostic(str(e))}", file=sys.stderr)
        return 2
    if not engine:
        detail = "; ".join(f"{n} {why}" + (f" [{tail}]" if tail else "") for n, why, tail in failures)
        print("render.py: " + (f"PDF engine failed: {detail}" if failures else "no PDF engine found (Chrome/Chromium or weasyprint)")
              + ". report.html is ready to print. Retry once with a higher PRUNE_SCAN_PDF_TIMEOUT (outside the "
              "sandbox if the browser cannot start inside it); if no engine can run: merge the limitation "
              "'report.pdf not produced: <reason>', re-run with --no-pdf, then contract_check.py <out> --no-pdf",
              file=sys.stderr)
        return 3
    print(f"wrote {out / 'report.pdf'} ({engine})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
