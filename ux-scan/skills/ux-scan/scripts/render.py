#!/usr/bin/env python3
"""Render a ux-scan findings.json into a dashboard, a report and its PDF.

    python3 render.py FINDINGS --out DIR [--lang ja|en] [--repo REPO] [--no-pdf]

Maps the record into scan-report-kit's common format (scan-report/1) and writes
DIR/dashboard.html, DIR/report.html and DIR/report.pdf (headless Chrome, else
WeasyPrint; CHROME picks the binary, UX_SCAN_PDF_TIMEOUT the seconds). With
--repo, each finding's location is embedded as a short excerpt; secret-looking
files and symlinks are never read and secret-looking lines are masked. Every
page fingerprints its findings, flows, render and (when produced) PDF.
Outputs must be outside --repo. Standard library only.
Exit status: 0 written, 2 invalid record or unwritable output, 3 no PDF produced.
"""

import argparse
import hashlib
import os
import re
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import EXCLUDED, RecordError, canonical_digest, check_findings, check_flows, flow_ids, loads_json  # noqa: E402
from scan_report_kit import output, pdf, report  # noqa: E402

OUTPUTS = ("dashboard.html", "report.html", "report.pdf")
STAMP = "ux-scan-source"
FLOWS_STAMP = "ux-scan-flows"
RENDER_STAMP = "ux-scan-render"
PDF_STAMP = "ux-scan-pdf"
SENSITIVE = re.compile(r"(?i)(?:^|/)(?:\.env(?:\..*)?|.*\.(?:pem|key|p12|pfx|jks|keystore)|id_[rd]sa.*|\.netrc|"
                       r"id_(?:ecdsa|ed25519).*|.*credentials.*|.*secrets?(?:\..*)?|\.npmrc|\.pypirc)$")
SECRET_LINE = re.compile(r"(?i)(?:secret|token|passw(?:or)?d|api[_-]?key|private[_-]?key|client[_-]?secret)\s*[\"']?\s*[:=]")
LOC = re.compile(r"^(?P<path>[^:]+):(?P<start>[0-9]+)(?:-(?P<end>[0-9]+))?$")
CONTEXT = 3
MAX_SNIPPET_LINES = 40
MAX_SNIPPET_BYTES = 2 * 1024 * 1024

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


def read_regular(path, max_bytes=None):
    """Read a regular file without following a link or waiting on a FIFO."""
    path = Path(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError(f"{path}: must be a regular file (not a symlink)")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{path}: must be a regular file")
        if max_bytes is not None and info.st_size > max_bytes:
            raise ValueError(f"{path}: exceeds {max_bytes} bytes")
        source = handle.read() if max_bytes is None else handle.read(max_bytes + 1)
        if max_bytes is not None and len(source) > max_bytes:
            raise ValueError(f"{path}: exceeds {max_bytes} bytes")
        return source


def source_stamp(source):
    return "sha256:" + hashlib.sha256(source).hexdigest()


def pdf_stamp(source):
    """Reject empty or visibly truncated PDF output, then fingerprint its bytes.

    This checks the PDF envelope, not the complete PDF syntax.
    """
    if (not re.match(br"%PDF-[12]\.[0-9][\r\n]", source[:10])
            or not source.rstrip(b" \t\r\n\f").endswith(b"%%EOF")):
        raise ValueError("not a complete PDF (expected a %PDF header and %%EOF trailer)")
    return source_stamp(source)


def stamp_page(page, stamps):
    # Names and values come only from the fixed identifiers and computed hashes.
    tags = "".join(f'<meta name="{name}" content="{value}">' for name, value in stamps.items())
    return page.replace("<head>", "<head>" + tags, 1)


def redact_diagnostic(text):
    # Mask the whole diagnostic: replacing only the key leaves its secret value behind.
    return "[masked: looks like a secret]" if SECRET_LINE.search(text) else text


def snippet(repo, location):
    """Lines around location from repo, or None when unreadable, outside repo or secret-looking."""
    m = LOC.fullmatch(location)
    if not repo or not m or SENSITIVE.search(m["path"]):
        return None
    try:
        start, end = int(m["start"]), int(m["end"] or m["start"])
        relative = Path(m["path"])
        if relative.is_absolute() or ".." in relative.parts or not 1 <= start <= end:
            return None
        root = Path(repo).resolve(strict=True)
        path = root
        for part in relative.parts:
            path = path / part
            if SENSITIVE.search(part) or path.is_symlink():
                return None
        path = path.resolve(strict=True)
        relative = path.relative_to(root)
        if any(SENSITIVE.search(part) for part in relative.parts):
            return None
        text = read_regular(path, MAX_SNIPPET_BYTES).decode("utf-8")
        if "\0" in text:
            return None
        lines = text.splitlines()
    except (ValueError, OSError, RuntimeError):
        return None
    if start > len(lines):
        return None
    first = max(1, start - CONTEXT)
    last = min(len(lines), end + CONTEXT, first + MAX_SNIPPET_LINES - 1)
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
        out = Path(a.out)
        if a.repo:
            repo = Path(a.repo).resolve(strict=True)
            if not repo.is_dir():
                raise ValueError(f"{a.repo}: not a repository directory")
            if out.resolve().is_relative_to(repo):
                raise ValueError("--out must be outside --repo; the reviewed repository is read-only")
        source = read_regular(a.findings)
        flows_path = Path(a.findings).with_name("flows.json")
        flows_source = read_regular(flows_path) if os.path.lexists(flows_path) else None
        flows = check_flows(loads_json(flows_source.decode("utf-8"), str(flows_path))) if flows_source is not None else None
        data = check_findings(loads_json(source.decode("utf-8"), str(a.findings)), flow_ids(flows) if flows else None)
        common = report.validate(to_common(data, a.lang, flows, a.repo))
        stamps = {STAMP: source_stamp(source),
                  FLOWS_STAMP: canonical_digest(flows) if flows is not None else "absent",
                  RENDER_STAMP: canonical_digest({"lang": a.lang, "record": common})}
        pages = {name: stamp_page(page, stamps) for name, page in (
            ("dashboard.html", report.render_dashboard(common, a.lang)),
            ("report.html", report.render_document(common, a.lang)))}
    except (OSError, ValueError, RuntimeError, RecordError, report.FormatError) as e:
        print(f"render.py: {e}", file=sys.stderr)
        return 2
    try:
        out.mkdir(parents=True, exist_ok=True)
        bad = output.unsafe_target(out, OUTPUTS)
        if bad:
            print(f"render.py: refusing to write {bad}: it exists as a symlink or non-regular file", file=sys.stderr)
            return 2
        # Once any new HTML is published, an earlier run's PDF must not survive.
        (out / "report.pdf").unlink(missing_ok=True)
        for name, page in pages.items():
            output.write_output(out / name, page)
            print(f"wrote {out / name}")
        if a.no_pdf:
            return 0
    except OSError as e:
        print(f"render.py: cannot write outputs to {out}: {e.strerror or e}", file=sys.stderr)
        return 2
    failures = []
    timeout = pdf.pdf_timeout(len(data["findings"]), env="UX_SCAN_PDF_TIMEOUT")
    try:
        engine = pdf.to_pdf(out / "report.html", out / "report.pdf", failures, timeout,
                            redact=redact_diagnostic)
        if engine:
            try:
                digest = pdf_stamp(read_regular(out / "report.pdf"))
            except (OSError, ValueError) as e:
                failures.append((engine, str(e), ""))
                engine = None
        if not engine:
            (out / "report.pdf").unlink(missing_ok=True)
        else:
            for name, page in pages.items():
                output.write_output(out / name, stamp_page(page, {PDF_STAMP: digest}))
    except OSError as e:
        try:
            (out / "report.pdf").unlink(missing_ok=True)
        except OSError:
            pass
        print(f"render.py: cannot write PDF outputs to {out}: {e.strerror or e}", file=sys.stderr)
        return 2
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
