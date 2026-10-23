#!/usr/bin/env python3
"""Render a prune-scan findings.json into a dashboard, a report and its PDF.

    python3 render.py FINDINGS --out DIR [--lang ja|en] [--repo REPO] [--no-pdf]

Maps the record into scan-report-kit's common format (scan-report/1) and writes
DIR/dashboard.html, DIR/report.html and DIR/report.pdf (headless Chrome, else
WeasyPrint; CHROME picks the binary, PRUNE_SCAN_PDF_TIMEOUT the seconds). The
rendered next steps open with the subtraction summary (remove now, reduce or
consolidate, decide with a human), computed from the findings. With --repo,
each finding's location is embedded as a short excerpt; secret-looking files
are never read, and sources containing secret-looking names or private key
blocks are omitted. Every page carries the SHA-256 of the findings.json and,
when supplied, units.json it shows.
Standard library only.
Exit status: 0 written, 2 invalid record, PRUNE_SCAN_PDF_TIMEOUT or unwritable output, 3 no PDF produced.
"""

import argparse
import hashlib
import math
import os
import re
import stat
import sys
import tempfile
from contextlib import ExitStack, contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import (EXCLUDED, RecordError, check_findings, check_units, parse_json,  # noqa: E402
                      record_exists)
from safe_paths import open_directory  # noqa: E402
from safe_output import SAFE_OUTPUT, checked_target, publish_outputs_at, tolerant_stdout  # noqa: E402
from safe_source import PRIVATE_KEY, SECRET_NAME, physical_lines, sensitive_source  # noqa: E402
from scan_report_kit import output, pdf, report  # noqa: E402
from scan_report_kit.report import LINE_BREAKS  # noqa: E402

OUTPUTS = ("dashboard.html", "report.html", "report.pdf")
STAMP = "prune-scan-source"
UNITS_STAMP = "prune-scan-units"
SENSITIVE = re.compile(r"(?i)(?:^|/)(?:\.env(?:\.[^/]*)?|[^/]*\.(?:pem|key|p12|pfx|jks|keystore|ppk|p8|gpg|asc|ovpn)|"
                       r"id_(?:[rd]sa|ecdsa|ed25519|xmss)[^/]*|\.netrc|"
                       r"[^/]*credentials[^/]*|[^/]*secrets?(?:[._-][^/]*)?|\.npmrc|\.pypirc|"
                       r"\.?htpasswd|\.?pgpass[^/]*|auth\.json|\.dockercfg|\.docker|\.kube|kubeconfig[^/]*|"
                       r"[^/]*\.tfstate(?:\.[^/]*)?|[^/]*\.kdbx)(?:/|$)")
SECRET_LINE = re.compile(SECRET_NAME.pattern + r"[\s\"'\]]*[:=]", re.I)
LOC = re.compile(r"^(?P<path>[^:]+):(?P<start>[0-9]+)(?:-(?P<end>[0-9]+))?$")
CONTEXT = 3
MAX_SNIPPET_LINES = 80
MAX_SOURCE_BYTES = 2 * 1024 * 1024
NOFOLLOW_DIR_FD = os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")

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


def read_source(root, relative, *, expected_stat, directory=None):
    """Read a bounded regular source without following links planted after resolve.

    Pin the selected repository identity and every directory on POSIX.
    On platforms without descriptor-relative opens, verify each component and
    the opened file's identity; excerpts remain optional on read errors.
    """
    path = root / relative
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    if NOFOLLOW_DIR_FD:
        parent = (open_directory(root, readable=False, expected_stat=expected_stat)
                  if directory is None else os.dup(directory))
        directories = (getattr(os, "O_PATH", getattr(os, "O_SEARCH", os.O_RDONLY))
                       | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in relative.parts[:-1]:
                child = os.open(part, directories, dir_fd=parent)
                os.close(parent)
                parent = child
            fd = os.open(relative.name, flags, dir_fd=parent)
        finally:
            os.close(parent)
    else:
        components = [root, *(root / Path(*relative.parts[:i]) for i in range(1, len(relative.parts) + 1))]
        before = [component.lstat() for component in components]
        if (not os.path.samestat(expected_stat, before[0])
                or any(stat.S_ISLNK(info.st_mode) for info in before) or not stat.S_ISREG(before[-1].st_mode)):
            return None
        fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SOURCE_BYTES:
            return None
        if not NOFOLLOW_DIR_FD:
            if (not os.path.samestat(before[-1], info)
                    or any(not os.path.samestat(old, component.lstat())
                           for old, component in zip(before, components))):
                return None
        source = handle.read(MAX_SOURCE_BYTES + 1)
    return source if len(source) <= MAX_SOURCE_BYTES and b"\0" not in source else None


def secret_path(path):
    """A secret-looking file or directory, or a file named for a secret (passwords.txt, .vault-token)."""
    return bool(SENSITIVE.search(path) or SECRET_NAME.search(path.rpartition("/")[2]))


def snippet(repo, location, *, selected=None):
    """Lines around location from repo, or None when unreadable, outside repo or secret-looking."""
    m = LOC.fullmatch(location)
    if not repo or not m or secret_path(m["path"]):
        return None
    try:
        start, end = int(m["start"]), int(m["end"] or m["start"])
        if start < 1 or end < start:
            return None
        directory = None
        if selected is None:
            requested = Path(repo)
            selected_info = requested.stat()
            root = requested.resolve()
        else:
            root, selected_info, directory = selected
        # Resolve links through the same repository whose descriptor will read
        # the source. A replacement tree can otherwise redirect beta.py to
        # alpha.py, then make the original alpha.py appear as beta.py's excerpt.
        identity = os.fstat(directory) if directory is not None else selected_info
        if not os.path.samestat(identity, root.stat()):
            return None
        path = (root / m["path"]).resolve()
        if not os.path.samestat(identity, root.stat()):
            return None
        relative = path.relative_to(root)
        if secret_path(relative.as_posix()):
            return None
        source = read_source(root, relative, expected_stat=selected_info, directory=directory)
        if source is None:
            return None
        text = source.decode("utf-8")
        # A recognized secret name suppresses the entire bounded source:
        # values may continue across methods, operators and comments in
        # different languages, even beyond the selected excerpt's lines.
        if sensitive_source(text):
            return None
        lines = physical_lines(text)
    except (ValueError, OSError, RuntimeError):
        return None
    if start > len(lines):
        return None
    first, last = max(1, start - CONTEXT), min(len(lines), end + CONTEXT)
    last = min(last, first + MAX_SNIPPET_LINES - 1)
    # Other line separators stay inside their physical line, as one space.
    shown = [LINE_BREAKS.sub(" ", line)[:240] for line in lines[first - 1:last]]
    return {"start": first, "hit": [start, min(end, last)], "lines": shown}


@contextmanager
def open_artifact(path, *, directory=None):
    """Open a regular artifact in a pinned directory, without links or FIFO waits.

    A contract check supplies one directory descriptor for all of its reads.
    Standalone callers select the parent before inspection and pin that path.
    """
    path = Path(path)
    owned_directory = None
    if directory is None and NOFOLLOW_DIR_FD:
        try:
            parent_info = path.parent.stat()
            parent = path.parent.resolve(strict=True)
        except RuntimeError as error:
            raise OSError(str(error)) from error
        owned_directory = directory = open_directory(parent, readable=False, expected_stat=parent_info)
    try:
        name = path if directory is None else path.name
        options = {} if directory is None else {"dir_fd": directory}
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0), **options)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            current = path.lstat() if directory is None else os.stat(name, dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(info, current):
                raise OSError(f"{path}: expected a regular artifact file")
            yield handle
    finally:
        if owned_directory is not None:
            os.close(owned_directory)


def pdf_envelope_complete(header, tail):
    """Recognize the stored PDF envelope; this is not a full PDF parser."""
    return bool(re.fullmatch(rb"%PDF-[12]\.[0-9]", header) and re.search(rb"%%EOF\s*\Z", tail))


def pdf_complete(path, *, directory=None):
    """Check stored artifacts for the run contract too; not a full PDF parser."""
    try:
        with open_artifact(path, directory=directory) as handle:
            header = handle.read(8)
            handle.seek(0, os.SEEK_END)
            handle.seek(max(0, handle.tell() - 1024))
            tail = handle.read()
        return pdf_envelope_complete(header, tail)
    except OSError:
        return False


def redact_diagnostic(text):
    """Engine stderr may echo a secret value: mask the complete diagnostic."""
    return "[masked: looks like a secret]" if SECRET_LINE.search(text) or PRIVATE_KEY.search(text) else text


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


@contextmanager
def selected_repository(repo):
    """Retain one repository identity for every excerpt in a conversion.

    The descriptor prevents both pathname replacement and inode reuse from
    selecting another repository. Unsupported runtimes keep the original stat
    for the per-read fallback checks. An unavailable selection stays unavailable.
    """
    directory = None
    try:
        if not repo:
            selected = None
        else:
            requested = Path(repo)
            info = requested.stat()
            root = requested.resolve()
            if not stat.S_ISDIR(info.st_mode):
                raise OSError("repository is not a directory")
            if NOFOLLOW_DIR_FD:
                directory = open_directory(root, readable=False, expected_stat=info)
            selected = root, info, directory
    except (OSError, ValueError, RuntimeError):
        selected = None
    try:
        yield selected
    finally:
        if directory is not None:
            os.close(directory)


def to_common(data, lang, units=None, repo=None):
    """data (findings.json) as a scan-report/1 record."""
    with selected_repository(repo) as selected:
        return _to_common(data, lang, units, repo if selected is not None else None, selected)


def _to_common(data, lang, units, repo, selected):
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
        if f["status"] == "Open" and verdict not in (*EXCLUDED, "Unlikely"):  # Unlikely: evidence of use; kept.
            item["action"] = ({"label": T["subtract"], "text": subtract_text} if ready
                              else {"label": T["verify"], "text": T["verify_text"]})
        excerpt = snippet(repo, f["location"], selected=selected)
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


@contextmanager
def selected_json_source(path):
    """Keep the actual regular input open through publication, including input aliases."""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise RecordError(f"{path}: expected a regular JSON file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            source = handle.read()
        yield source, info
    finally:
        os.close(descriptor)


def check_selected_output(path, directory):
    """Do not report success at a pathname that now denotes a different directory."""
    if not os.path.samestat(path.stat(), os.fstat(directory)):
        raise OSError(f"{path}: output directory changed since it was selected")


def private_staging(out, repo):
    """Keep vendor pathname-based generation outside the selected output and source tree."""
    temporary = Path(tempfile.gettempdir()).resolve(strict=True)
    excluded = [out]
    if repo:
        excluded.append(Path(repo).resolve())
    if any(temporary == path or path in temporary.parents for path in excluded):
        raise OSError("temporary storage must be outside --out and --repo; choose a different TMPDIR")
    return tempfile.TemporaryDirectory(prefix="prune-scan-render-", dir=temporary)


def valid_pdf_timeout(value):
    """Unset or blank keeps the default; anything else must be finite seconds above zero."""
    if value is None or not value.strip():
        return True
    try:
        seconds = float(value)
    except ValueError:
        return False
    return math.isfinite(seconds) and seconds > 0


def render_outputs(a, resources):
    """Read inputs once and retain the selected output directory through every commit."""
    if not SAFE_OUTPUT:
        print("render.py: descriptor-relative output support is required to preserve input sources",
              file=sys.stderr)
        return 2
    if not a.no_pdf and not valid_pdf_timeout(os.environ.get("PRUNE_SCAN_PDF_TIMEOUT")):
        # The vendored kit falls back to its default on a bad value, which
        # would waste the one retry SKILL.md allows at the same timeout.
        print("render.py: PRUNE_SCAN_PDF_TIMEOUT must be a positive number of seconds, e.g. 300",
              file=sys.stderr)
        return 2
    try:
        source, source_info = resources.enter_context(selected_json_source(a.findings))
        protected = [source_info]
        units_path = Path(a.findings).with_name("units.json")
        units_source = None
        if record_exists(units_path):
            units_source, units_info = resources.enter_context(selected_json_source(units_path))
            protected.append(units_info)
        units = check_units(parse_json(units_source, str(units_path))) if units_source is not None else None
        data = check_findings(parse_json(source, a.findings), units)
    except (OSError, ValueError, RecordError) as e:
        print(f"render.py: {e}", file=sys.stderr)
        return 2
    out = Path(a.out)
    try:
        out.mkdir(parents=True, exist_ok=True)
        selected = out.stat()
        resolved = out.resolve(strict=True)
        directory = open_directory(resolved, readable=False, expected_stat=selected)
        resources.callback(os.close, directory)
    except (OSError, ValueError, RuntimeError) as e:
        print(f"render.py: cannot select output directory {out}: {e}", file=sys.stderr)
        return 2
    try:
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
    try:
        for name in OUTPUTS:
            checked_target(directory, name, protected=protected, regular=True)
        staging = Path(resources.enter_context(private_staging(resolved, a.repo)))
        # Vendor staging and PDF engines never receive a mutable public path.
        output.write_outputs(staging, pages, remove=("report.pdf",))
        check_selected_output(out, directory)
        publish_outputs_at(directory, {name: staging / name for name in pages},
                           remove=("report.pdf",), protected=protected)
        check_selected_output(out, directory)
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
        engine = pdf.to_pdf(staging / "report.html", staging / "report.pdf", failures, timeout,
                            redact=redact_diagnostic)
        if engine and not pdf_complete(staging / "report.pdf"):
            failures.append((engine, "did not produce a complete PDF; its output was discarded", ""))
            engine = None
        check_selected_output(out, directory)
        if engine:
            publish_outputs_at(directory, {"report.pdf": staging / "report.pdf"}, protected=protected)
            check_selected_output(out, directory)
        # Old PDFs were removed with the HTML transaction. Failed engine output
        # exists only in private staging, so no public-path unlink is needed.
    except (OSError, ValueError) as e:
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


def main(argv=None):
    tolerant_stdout()
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("findings")
    p.add_argument("--out", required=True)
    p.add_argument("--lang", choices=sorted(LABELS), default="en")
    p.add_argument("--repo", help="reviewed repository root: embeds excerpts for path:line locations")
    p.add_argument("--no-pdf", action="store_true", help="skip PDF generation")
    a = p.parse_args(argv)
    try:
        with ExitStack() as resources:
            return render_outputs(a, resources)
    except OSError as e:
        print(f"render.py: cannot clean up temporary output: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
