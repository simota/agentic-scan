#!/usr/bin/env python3
"""Render a ux-scan findings.json into a dashboard, a report and its PDF.

    python3 render.py FINDINGS --out DIR [--lang ja|en] [--repo REPO] [--no-pdf]

Maps the record into scan-report-kit's common format (scan-report/1) and writes
DIR/dashboard.html, DIR/report.html and DIR/report.pdf (headless Chrome, else
WeasyPrint; CHROME picks the binary, UX_SCAN_PDF_TIMEOUT the seconds). With
--repo, each finding's location is embedded as a short excerpt; secret-looking
files and symlinks are never read and secret-looking lines are masked. Every
page fingerprints its findings, flows, render, complete HTML and (when produced) PDF.
Outputs must be outside --repo. Standard library only.
Exit status: 0 written, 2 invalid record or unwritable output, 3 no PDF produced.
"""

import argparse
import hashlib
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from file_io import read_regular  # noqa: E402
from secret_lines import SHOWN_CHARACTERS, continued_secret_lines, private_key_lines, secret_line  # noqa: E402,F401
from findings import EXCLUDED, RecordError, canonical_digest, check_findings, check_flows, flow_ids, loads_json  # noqa: E402
from scan_report_kit import output, pdf, report  # noqa: E402

OUTPUTS = ("dashboard.html", "report.html", "report.pdf")
STAMP = "ux-scan-source"
FLOWS_STAMP = "ux-scan-flows"
RENDER_STAMP = "ux-scan-render"
PDF_STAMP = "ux-scan-pdf"
PAGE_STAMP = "ux-scan-page"
PAGE_KIND_STAMP = "ux-scan-page-kind"
PAGE_TAG = re.compile(rb'<meta name="ux-scan-page" content="sha256:[0-9a-f]{64}">')
SENSITIVE = re.compile(r"(?i)(?:^|/)(?:\.env(?:[-_.].*)?|.*\.env|\.envrc|\.dev\.vars|.*\.tfvars(?:\.json)?|\.git|"
                       r".*\.(?:pem|key|p8|p12|pfx|jks|keystore)|id_[rd]sa.*|\.netrc|\.htpasswd|kubeconfig|\.docker|"
                       r"id_(?:ecdsa|ed25519).*|.*credentials.*|.*service[-_]?account.*\.json|.*secrets?(?:\..*)?|"
                       r"\.npmrc|\.pypirc|.*\.tfstate(?:\.backup)?|client_secret.*\.json|.*adminsdk.*\.json|"
                       r"google-services\.json|\.pgpass|_netrc|\.vault-token|\.s3cfg|\.boto)$")
# Only these end a line for path:line, as in editors and grep -n.
SOURCE_LINE_END = re.compile(r"\r\n|\r|\n")
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
           "evidence": "Verification", "intent": "Intent checked", "masked": "[masked: looks like a secret]",
           "viewports": "Viewports", "locales": "Locales"},
    "ja": {"kind": "UX診断", "title": "UX診断書", "dashboard_title": "UX診断結果",
           "running_footer": "UX診断", "fix": "修正", "verify": "先に検証",
           "verify_text": "変更する前に、利用者が実際にこの状態に到達し、他の箇所で補われていないことを確認してください。",
           "observed": "現状", "expected": "あるべき状態", "criterion": "判断基準", "flow": "フロー",
           "screen": "画面", "viewport": "ビューポート", "occurrences": "出現箇所", "impact": "影響",
           "evidence": "検証根拠", "intent": "意図の確認", "masked": "[秘密情報らしき行のため非表示]",
           "viewports": "ビューポート", "locales": "ロケール"},
}


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


def seal_page(page):
    """Fingerprint the final HTML bytes, omitting only the tag added here."""
    # write_output uses text mode, which translates newlines on Windows.
    source = page.replace("\n", os.linesep).encode("utf-8")
    return stamp_page(page, {PAGE_STAMP: source_stamp(source)})


def page_stamp(source):
    """Fingerprint exact HTML bytes after removing its one canonical page tag.

    Reject missing, malformed or repeated canonical tags rather than guessing
    which bytes to exclude. The caller also verifies the tag is head metadata.
    """
    matches = list(PAGE_TAG.finditer(source))
    if len(matches) != 1:
        raise ValueError("expected exactly one canonical page fingerprint tag")
    tag = matches[0]
    return source_stamp(source[:tag.start()] + source[tag.end():])


def redact_diagnostic(text):
    # Engines may echo report/source text, and the upstream callback receives a
    # truncated tail that can already have lost a secret's identifying key.
    return "[masked: PDF engine diagnostic]" if text else ""


def snippet(repo, location, masked="[masked: looks like a secret]"):
    """Lines around location from repo, or None when unreadable, outside repo or secret-looking."""
    m = LOC.fullmatch(location)
    if not repo or not m or SENSITIVE.search(m["path"]):
        return None
    try:
        start, end = int(m["start"]), int(m["end"] or m["start"])
        relative = Path(m["path"])
        if relative.is_absolute() or ".." in relative.parts or not 1 <= start <= end:
            return None
        if any(SENSITIVE.search(part) for part in relative.parts):
            return None
        root = Path(repo).absolute()
        text = read_regular(root / relative, MAX_SNIPPET_BYTES, root=root).decode("utf-8")
        if "\0" in text:
            return None
        lines = SOURCE_LINE_END.split(text)
        if lines[-1] == "":
            lines.pop()
    except (ValueError, OSError, RuntimeError):
        return None
    if start > len(lines):
        return None
    first = max(1, start - CONTEXT)
    last = min(len(lines), end + CONTEXT, first + MAX_SNIPPET_LINES - 1)
    # Private-key blocks are found across the whole file, since an excerpt may
    # start inside one. Other Unicode line breaks stay inside their line, shown
    # as a visible marker.
    hidden = private_key_lines(lines) | continued_secret_lines(lines, first - 2, last)
    shown = [masked if index in hidden or secret_line(line)
             else report.LINE_BREAKS.sub("\u2424", line[:SHOWN_CHARACTERS])
             for index, line in enumerate(lines[first - 1:last], first - 1)]
    return {"start": first, "hit": [start, min(end, last)], "lines": shown}


def judged_scope(meta, flows, T):
    """The scope with the supported viewports and locales it was judged against.

    flows.json is the record severity is judged against, so its values win
    over the optional copies in meta.
    """
    parts = [meta.get("scope", "")]
    for key in ("viewports", "locales"):
        values = (flows or {}).get(key) or meta.get(key)
        if values:
            parts.append(f"{T[key]}: {', '.join(values)}")
    return " · ".join(p for p in parts if p)


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
        fix_is_action = f["status"] == "Open" and verdict == "Valid" and bool(f.get("fix", "").strip())
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
        excerpt = snippet(repo, f["location"], T["masked"])
        if excerpt:
            item["snippet"] = excerpt
        findings.append(item)
    meta = data["meta"]
    return {
        "format": report.FORMAT,
        "meta": {**{k: meta[k] for k in ("project", "date", "assessor", "scope", "method", "commit") if meta.get(k)},
                 **({"scope": scope} if (scope := judged_scope(meta, flows, T)) else {})},
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
        source_path = Path(a.findings).resolve()
        for name in OUTPUTS:
            target = out / name
            if source_path == target.resolve() or (target.exists() and source_path.samefile(target)):
                raise ValueError("findings input must be different from every generated output")
        repo = None
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
        common = report.validate(to_common(data, a.lang, flows, repo))
        pages = {"dashboard.html": report.render_dashboard(common, a.lang),
                 "report.html": report.render_document(common, a.lang)}
        stamps = {STAMP: source_stamp(source),
                  FLOWS_STAMP: canonical_digest(flows) if flows is not None else "absent",
                  RENDER_STAMP: canonical_digest({
                      "lang": a.lang, "record": common,
                      # Bind the pair even when only renderer assets changed.
                      "pages": {name: source_stamp(page.encode("utf-8")) for name, page in pages.items()},
                  })}
        pages = {name: stamp_page(page, {**stamps, PAGE_KIND_STAMP: name}) for name, page in pages.items()}
    except (OSError, ValueError, RuntimeError, RecordError, report.FormatError) as e:
        print(f"render.py: {e}", file=sys.stderr)
        return 2
    try:
        out.mkdir(parents=True, exist_ok=True)
        bad = output.unsafe_target(out, OUTPUTS)
        if bad:
            print(f"render.py: refusing to write {bad}: it exists as a symlink or non-regular file", file=sys.stderr)
            return 2
        # Stage both pages before replacing either. A failed publication must
        # restore the old pair and PDF together, not leave mixed report versions.
        output.write_outputs(out, {name: seal_page(page) for name, page in pages.items()},
                             remove=("report.pdf",))
        for name in pages:
            print(f"wrote {out / name}")
        if a.no_pdf:
            return 0
    except OSError as e:
        print(f"render.py: cannot write outputs to {out}: {e.strerror or e}", file=sys.stderr)
        return 2
    failures = []
    timeout = pdf.pdf_timeout(len(data["findings"]), env="UX_SCAN_PDF_TIMEOUT")
    try:
        try:
            engine = pdf.to_pdf(out / "report.html", out / "report.pdf", failures, timeout,
                                redact=redact_diagnostic)
        except UnicodeError:
            # The upstream WeasyPrint runner decodes captured process output.
            # An encoding error is an engine failure, and may follow a partial
            # PDF write. Keep its diagnostic private and use the normal cleanup.
            failures.append(("PDF engine", "invalid text encoding in process output", ""))
            engine = None
        if engine:
            try:
                digest = pdf_stamp(read_regular(out / "report.pdf"))
            except (OSError, ValueError) as e:
                failures.append((engine, str(e), ""))
                engine = None
        if not engine:
            (out / "report.pdf").unlink(missing_ok=True)
        else:
            output.write_outputs(out, {name: seal_page(stamp_page(page, {PDF_STAMP: digest}))
                                       for name, page in pages.items()})
    except OSError as e:
        try:
            (out / "report.pdf").unlink(missing_ok=True)
        except OSError:
            pass
        print(f"render.py: cannot write PDF outputs to {out}: {e.strerror or e}", file=sys.stderr)
        return 2
    if not engine:
        # Also cover engine-start failures that bypass the upstream callback.
        detail = "; ".join(f"{n} {why}" + (f" {redact_diagnostic(tail)}" if tail else "")
                           for n, why, tail in failures)
        print("render.py: " + (f"PDF engine failed: {detail}" if failures else "no PDF engine found (Chrome/Chromium or weasyprint)")
              + ". report.html is ready to print. If no engine can run: merge the limitation "
              "'report.pdf not produced: no PDF engine', re-run with --no-pdf, then contract_check.py <out> --no-pdf",
              file=sys.stderr)
        return 3
    print(f"wrote {out / 'report.pdf'} ({engine})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
