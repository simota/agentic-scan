"""Render a common-format report (docs/format.md) into dashboard.html and report.html.

Standard library only. The visual system is docs/design.md; the stylesheets and
the dashboard runtime come from style.py so every scan shares one look.
"""

import html
import ipaddress
import json
import re
from datetime import date
from unicodedata import normalize
from urllib.parse import unquote, urlsplit

from . import style

FORMAT = "scan-report/1"
SEVERITIES = ["High", "Medium", "Low", "Info"]
STATUSES = ["Open", "Fixed", "Accepted"]
LANE_TONES = {"with_fix": "high", "without_fix": "medium", "closed": "ink", "excluded": "accent"}
VERDICT_TONES = {"Valid": "strong", "Likely": "mid", "Unverified": "hatch", "Unlikely": "weak", "": "weak"}
LIST_KEYS = ("limitations", "decisions", "next_steps", "checked_ok")
META_KEYS = ("project", "date", "assessor", "scope", "method", "commit")
REPORT_KEYS = ("kind", "title", "dashboard_title", "running_footer")
FINDING_KEYS = ("id", "title", "severity", "status", "confidence", "verdict", "category", "location", "excluded")
# Line numbers must stay exact in both Python and the JavaScript dashboard.
MAX_LINE_NUMBER = 2 ** 53 - 1
LINE_BREAKS = re.compile(r"[\r\n\v\f\x1c-\x1e\x85\u2028\u2029]")

LABELS = {
    "en": {
        "kind": "Assessment", "title": "Assessment Report", "dashboard_title": "Assessment Results",
        "running_footer": "ASSESSMENT",
        "date": "Date", "assessor": "Assessor", "scope": "Scope", "method": "Method", "commit": "Commit",
        "abstract": "Abstract", "summary": "Summary", "no_summary": "No summary was recorded.",
        "severity": "Severity", "status": "Status", "confidence": "Confidence", "verdict": "Verdict",
        "category": "Category", "location": "Location", "title_col": "Finding", "action": "Next action",
        "open_by_severity": "Open findings by severity", "open": "Open", "closed": "Fixed or accepted",
        "total": "Total", "limitations": "Limitations", "limitations_empty": "No limitations were recorded.",
        "priority": "Priority", "priority_note": "Open findings, most severe first.",
        "priority_caption": "Open findings in priority order", "ref": "Ref",
        "no_open": "No open findings.", "no_findings": "No findings were recorded.",
        "decisions": "Decisions", "next_steps": "Next steps", "checked_ok": "Checked without findings",
        "not_recorded": "Not recorded.", "coverage": "Coverage",
        "coverage_note": "What was examined, and with what result.", "coverage_caption": "Perspectives examined",
        "perspective": "Perspective", "result": "Result", "note": "Note",
        "coverage_missing": "No coverage was recorded.",
        "register": "Finding register", "register_note": "Every included finding, by severity.",
        "register_caption": "Finding register", "details": "Findings",
        "excluded": "Excluded records", "excluded_note": "Recorded but excluded from the counts above.",
        "excluded_short": "Excluded", "snippet": "Source excerpt", "references": "References",
        "source": "source", "none": "—",
        "risk_summary": "{n} open High or Medium findings need attention.",
        "risk_summary_one": "1 open High or Medium finding needs attention.",
        "open_summary": "{n} open findings, none High or Medium.",
        "open_summary_one": "1 open finding, not High or Medium.",
        "urgent": "Open High + Medium", "open_total": "Open", "closed_total": "Fixed / Accepted",
        "included": "Included", "excluded_count": "Excluded",
        "report_link": "Printable report", "theme": "Theme", "jump": "Skip to findings",
        "overview": "Overview", "by_severity": "By severity", "by_category": "By category", "by_status": "By status",
        "count_basis": "Counts cover included findings only.",
        "filters_record_set": "Records", "included_set": "Included", "excluded_set": "Excluded", "all_records": "All",
        "all": "All", "search": "Search ID, title, location, text", "sort": "Sort",
        "sort_priority": "Priority", "sort_id": "ID", "reset": "Reset",
        "showing": "Showing {shown} of {total}", "no_matches": "No records match the filters.",
        "no_records": "No records.", "show_details": "Show details", "hide_details": "Hide details",
        "copy_llm": "Copy for LLM", "copied": "Copied", "copy_failed": "Copy failed", "link": "Link",
        "view_all": "View all findings", "queue_more": "Showing {shown} of {total} open findings.",
        "source_note": "Generated from the recorded report data; this page changes nothing.",
        "no_script": "This dashboard needs JavaScript. Read the printable report instead:",
        "contents": "Contents", "records": "Decisions and next steps", "shortcuts": "Keyboard",
        "key_search": "Search", "key_move": "Next / previous finding", "key_toggle": "Show or hide details",
    },
    "ja": {
        "kind": "診断", "title": "診断報告書", "dashboard_title": "診断結果", "running_footer": "診断報告書",
        "date": "日付", "assessor": "実施者", "scope": "範囲", "method": "方法", "commit": "コミット",
        "abstract": "要旨", "summary": "概要", "no_summary": "概要は記録されていません。",
        "severity": "重大度", "status": "状態", "confidence": "確度", "verdict": "判定",
        "category": "分類", "location": "場所", "title_col": "指摘", "action": "次の対応",
        "open_by_severity": "重大度別の未対応指摘", "open": "未対応", "closed": "修正済み・受容",
        "total": "合計", "limitations": "制約", "limitations_empty": "制約は記録されていません。",
        "priority": "優先順位", "priority_note": "未対応の指摘を重大度の高い順に示します。",
        "priority_caption": "優先順の未対応指摘", "ref": "参照",
        "no_open": "未対応の指摘はありません。", "no_findings": "指摘は記録されていません。",
        "decisions": "判断事項", "next_steps": "次の手順", "checked_ok": "問題が見つからなかった確認",
        "not_recorded": "記録されていません。", "coverage": "確認範囲",
        "coverage_note": "何を確認し、どのような結果だったかを示します。", "coverage_caption": "確認した観点",
        "perspective": "観点", "result": "結果", "note": "備考",
        "coverage_missing": "確認範囲は記録されていません。",
        "register": "指摘一覧", "register_note": "除外を除くすべての指摘を重大度順に示します。",
        "register_caption": "指摘一覧", "details": "指摘",
        "excluded": "除外した記録", "excluded_note": "記録はありますが、上の件数には含めていません。",
        "excluded_short": "除外", "snippet": "ソース抜粋", "references": "参考資料",
        "source": "ソース", "none": "—",
        "risk_summary": "対応が必要な High・Medium の未対応指摘が{n}件あります。",
        "open_summary": "未対応の指摘が{n}件あります（High・Medium はありません）。",
        "urgent": "未対応 High + Medium", "open_total": "未対応", "closed_total": "修正済み / 受容",
        "included": "対象", "excluded_count": "除外",
        "report_link": "印刷用報告書", "theme": "表示切替", "jump": "指摘一覧へ移動",
        "overview": "概要グラフ", "by_severity": "重大度別", "by_category": "分類別", "by_status": "状態別",
        "count_basis": "件数は除外を除く指摘のみを数えています。",
        "filters_record_set": "記録", "included_set": "対象", "excluded_set": "除外", "all_records": "すべて",
        "all": "すべて", "search": "ID・タイトル・場所・本文を検索", "sort": "並び順",
        "sort_priority": "優先度", "sort_id": "ID", "reset": "リセット",
        "showing": "{total}件中{shown}件を表示", "no_matches": "条件に一致する記録はありません。",
        "no_records": "記録はありません。", "show_details": "詳細を表示", "hide_details": "詳細を隠す",
        "copy_llm": "LLM 用にコピー", "copied": "コピーしました", "copy_failed": "コピーできませんでした",
        "link": "リンク",
        "view_all": "すべての指摘を見る", "queue_more": "未対応{total}件中{shown}件を表示しています。",
        "source_note": "記録されたレポートデータから生成しています。このページは何も変更しません。",
        "no_script": "このダッシュボードには JavaScript が必要です。印刷用報告書をご覧ください:",
        "contents": "目次", "records": "判断事項と次の手順", "shortcuts": "キー操作",
        "key_search": "検索", "key_move": "次・前の指摘", "key_toggle": "詳細の表示・非表示",
    },
}
LABEL_KEYS = set().union(*(labels.keys() for labels in LABELS.values()))
CONSOLE_LABELS = {
    "en": dict(
        read_only="read-only", readout="Record counts", readout_open="open", readout_closed="closed",
        readout_excluded="excluded", severity_h="Severity",
        severity_note="{n} included records; {x} excluded are not counted",
        tile_sub="open {open} · closed {closed}", legend_cell="1 cell = 1 record.",
        legend_open="open", legend_closed="fixed, verified or accepted", verdict_h="Verdict",
        verdict_note="all {n} records; excluded verdicts kept as their own block",
        perspective_h="Perspectives", perspective_note="{n} perspectives", triage="Triage",
        triage_note="every record in one lane; pick a card to inspect it",
        lane_with_fix="FIX DIRECTION RECORDED", lane_without_fix="NO FIX DIRECTION",
        lane_closed="CLOSED", lane_excluded="EXCLUDED", lane_empty="No records in this lane.",
        priority_note="Open findings grouped by fix direction, most severe first within each lane.",
        inspector_h="Inspector", inspector_empty="No finding selected.", open_record="Open in register",
        where_h="Where", evidence_h="Evidence", evidence_method="{method}", fix_h="Fix direction",
        copy="Copy finding Markdown", report_link="Printable report", theme="Toggle color theme",
    ),
    "ja": dict(
        read_only="読み取り専用", readout="記録件数", readout_open="open", readout_closed="closed",
        readout_excluded="excluded", severity_h="Severity", severity_note="集計対象 {n} 件（除外 {x} 件は数えない）",
        tile_sub="未解決 {open} · 対応済 {closed}", legend_cell="1 マス = 1 件。",
        legend_open="未解決", legend_closed="対応済み（Fixed / Verified / Accepted）", verdict_h="Verdict",
        verdict_note="記録 {n} 件の判定。除外の判定は独立した区画",
        perspective_h="Perspectives", perspective_note="観点 {n}", triage="Triage",
        triage_note="全件をいずれかのレーンに置いています。カードを選ぶと詳細を表示します",
        lane_with_fix="FIX DIRECTION RECORDED / 修正方針あり", lane_without_fix="NO FIX DIRECTION / 修正方針なし",
        lane_closed="CLOSED / 対応済・受容", lane_excluded="EXCLUDED / 誤検知・除外", lane_empty="該当する記録はありません。",
        priority_note="未対応の指摘を修正方針の有無で分け、各区分で重大度順に示します。",
        inspector_h="詳細", inspector_empty="指摘が選択されていません。", open_record="一覧で開く",
        where_h="該当箇所", evidence_h="根拠", evidence_method="{method}", fix_h="修正方針",
        copy="指摘の Markdown をコピー", report_link="印刷用レポート", theme="配色を切り替え",
    ),
}


class FormatError(Exception):
    pass


def _string(value, where):
    if not isinstance(value, str):
        raise FormatError(f"{where}: expected a string")
    if "\x00" in value:
        raise FormatError(f"{where}: expected Unicode text without NUL characters")
    if re.search(r"[\ud800-\udfff]", value):
        raise FormatError(f"{where}: expected Unicode text without surrogate code points")
    return value


def _text(obj, key, where, *, required=False):
    value = _string(obj.get(key, ""), f"{where}.{key}")
    if required and not value.strip():
        raise FormatError(f"{where}.{key}: required")
    return value


def _strings(data, key):
    value = data.get(key, [])
    if not isinstance(value, list):
        raise FormatError(f"{key}: expected a list of strings")
    for i, item in enumerate(value):
        _string(item, f"{key}[{i}]")
    return value


def http_url(value, where):
    _string(value, where)
    # Do not let urlsplit silently strip controls or accept a URL that a
    # browser interprets differently (notably backslashes in the authority).
    if any(char.isspace() or ord(char) < 32 or 127 <= ord(char) < 160 or char == "\\" for char in value):
        raise FormatError(f"{where}: expected an http(s) URL")
    try:
        parts = urlsplit(value)
        host = parts.hostname
        valid = parts.scheme in ("http", "https") and bool(host)
        # Accessing port validates its numeric syntax and range.
        parts.port
        if valid:
            if re.search(r"%(?![0-9a-fA-F]{2})", host):
                valid = False
            else:
                # urlsplit separates components; it does not validate domain
                # names. Check decoded and NFKC-normalized host text so encoded
                # delimiters cannot hide an unusable host. Keep paths/queries
                # untouched and retain the original URL in the report. Python's
                # IDNA2003 codec rejects valid modern IDNs (e.g. RTL labels ending
                # in digits), so do not use it as a domain validity gate.
                decoded = unquote(host, encoding="utf-8", errors="strict")
                bracketed = parts.netloc.rsplit("@", 1)[-1].startswith("[")
                normalized = normalize("NFKC", decoded)
                # Older Python releases accept any bracketed text as a host,
                # and text between "]" and the port. Require an IPv6 literal
                # (an RFC 6874 zone stays allowed) followed only by a port.
                if bracketed:
                    ipaddress.IPv6Address(decoded)
                forbidden = "#/<>?@[\\]^|\ufffd" + ("" if bracketed else ":%")
                valid = (not any(char.isspace() or ord(char) < 32 or 127 <= ord(char) < 160
                                 or char in forbidden for char in decoded + normalized)
                         and (not bracketed
                              or re.fullmatch(r"\[[^\]]*\](?::[0-9]*)?", parts.netloc.rsplit("@", 1)[-1])))
    except ValueError:
        raise FormatError(f"{where}: expected an http(s) URL") from None
    if not valid:
        raise FormatError(f"{where}: expected an http(s) URL")
    return value


def _object(value, where):
    if not isinstance(value, dict):
        raise FormatError(f"{where}: expected an object")
    return value


def _field_layout(field, where):
    """Optional group (a tab or subsection) and table (columns, rows) of one body section."""
    if "group" in field and not _text(field, "group", where).strip():
        raise FormatError(f"{where}.group: expected a nonblank string")
    if "group" in field and LINE_BREAKS.search(field["group"]):
        raise FormatError(f"{where}.group: expected one line")
    width = None
    if "columns" in field:
        columns = field["columns"]
        if not isinstance(columns, list) or not columns:
            raise FormatError(f"{where}.columns: expected a nonempty list of strings")
        for k, column in enumerate(columns):
            _string(column, f"{where}.columns[{k}]")
        width = len(columns)
        if "rows" not in field:
            raise FormatError(f"{where}.rows: required with columns")
    if "rows" in field:
        rows = field["rows"]
        if not isinstance(rows, list) or not rows:
            raise FormatError(f"{where}.rows: expected a nonempty list of rows")
        for k, row in enumerate(rows):
            if not isinstance(row, list) or not row:
                raise FormatError(f"{where}.rows[{k}]: expected a nonempty list of strings")
            width = width or len(row)
            if len(row) != width:
                raise FormatError(f"{where}.rows[{k}]: expected {width} cells")
            for n, cell in enumerate(row):
                _string(cell, f"{where}.rows[{k}][{n}]")


def field_groups(fields):
    """Fields without a group, then each group in order of first appearance: [(group or None, [fields])]."""
    groups = {None: []}
    for field in fields:
        groups.setdefault(field.get("group"), []).append(field)
    return [(name, items) for name, items in groups.items() if items]


def validate(data):
    """Check data against docs/format.md and return it; raises FormatError."""
    _object(data, "report")
    if data.get("format") != FORMAT:
        raise FormatError(f"format: expected {FORMAT!r}")
    meta = _object(data.get("meta"), "meta")
    for key in META_KEYS:
        _text(meta, key, "meta", required=key in ("project", "date"))
    try:
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", meta["date"]):
            raise ValueError
        date.fromisoformat(meta["date"])
    except ValueError:
        raise FormatError("meta.date: expected a valid date in YYYY-MM-DD form") from None
    report = _object(data.get("report", {}), "report")
    for key in REPORT_KEYS:
        _text(report, key, "report")
    labels = _object(data.get("labels", {}), "labels")
    for key, value in labels.items():
        _string(key, "labels key")
        _string(value, f"labels.{key}")
    _text(data, "summary", "report")
    for key in LIST_KEYS:
        _strings(data, key)
    perspectives = data.get("perspectives", [])
    if not isinstance(perspectives, list):
        raise FormatError("perspectives: expected a list")
    for i, p in enumerate(perspectives):
        _object(p, f"perspectives[{i}]")
        _text(p, "name", f"perspectives[{i}]", required=True)
        _text(p, "result", f"perspectives[{i}]")
        _text(p, "note", f"perspectives[{i}]")
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise FormatError("findings: expected a list")
    seen = set()
    for i, f in enumerate(findings):
        where = f"findings[{i}]"
        _object(f, where)
        fid = _text(f, "id", where, required=True)
        if fid in seen:
            raise FormatError(f"{where}.id: duplicate {fid!r}")
        seen.add(fid)
        title = _text(f, "title", where, required=True)
        if LINE_BREAKS.search(title):
            raise FormatError(f"{where}.title: expected one line")
        if f.get("severity") not in SEVERITIES:
            raise FormatError(f"{where}.severity: expected one of {SEVERITIES}")
        if f.get("status") not in STATUSES:
            raise FormatError(f"{where}.status: expected one of {STATUSES}")
        for key in ("category", "location", "confidence", "verdict"):
            _text(f, key, where)
        if not isinstance(f.get("excluded", False), bool):
            raise FormatError(f"{where}.excluded: expected a boolean")
        if "action" in f:
            action = _object(f["action"], f"{where}.action")
            _text(action, "label", f"{where}.action", required=True)
            _text(action, "text", f"{where}.action")
        fields = f.get("fields", [])
        if not isinstance(fields, list):
            raise FormatError(f"{where}.fields: expected a list")
        for j, field in enumerate(fields):
            _object(field, f"{where}.fields[{j}]")
            _text(field, "label", f"{where}.fields[{j}]", required=True)
            _text(field, "text", f"{where}.fields[{j}]")
            _field_layout(field, f"{where}.fields[{j}]")
        if "snippet" in f:
            s = _object(f["snippet"], f"{where}.snippet")
            hit = s.get("hit")
            if (type(s.get("start")) is not int or not 1 <= s["start"] <= MAX_LINE_NUMBER
                    or not isinstance(s.get("lines"), list)
                    or not (isinstance(hit, list) and len(hit) == 2 and all(type(n) is int for n in hit))):
                raise FormatError(f"{where}.snippet: expected start >= 1, lines and hit [first, last]")
            if not 1 <= hit[0] <= hit[1] <= MAX_LINE_NUMBER:
                raise FormatError(f"{where}.snippet.hit: expected ordered positive line numbers <= {MAX_LINE_NUMBER}")
            if s["start"] + len(s["lines"]) - 1 > MAX_LINE_NUMBER:
                raise FormatError(f"{where}.snippet: displayed line numbers must be <= {MAX_LINE_NUMBER}")
            for j, line in enumerate(s["lines"]):
                _string(line, f"{where}.snippet.lines[{j}]")
                if LINE_BREAKS.search(line):
                    raise FormatError(f"{where}.snippet.lines[{j}]: expected one line")
        refs = f.get("references", [])
        if not isinstance(refs, list):
            raise FormatError(f"{where}.references: expected a list")
        for j, ref in enumerate(refs):
            _object(ref, f"{where}.references[{j}]")
            http_url(ref.get("url"), f"{where}.references[{j}].url")
            _text(ref, "type", f"{where}.references[{j}]")
            _text(ref, "title", f"{where}.references[{j}]")
    return data


def given(text):
    """Recorded optional text that is not blank: blank text counts as absent."""
    return bool(str(text or "").strip())


def labels_for(data, lang):
    """Built-in labels for lang, then the report's own kind/title strings, then its overrides."""
    if not isinstance(lang, str) or lang not in LABELS:
        raise FormatError(f"lang: expected one of {list(LABELS)}")
    L = dict(LABELS[lang])
    names = data.get("report", {})
    L.update({k: names[k] for k in REPORT_KEYS if given(names.get(k))})
    L.update({k: v for k, v in data.get("labels", {}).items() if k in LABEL_KEYS})
    return L


def esc(s):
    # HTML input preprocessing normalizes literal CR and CRLF to LF before
    # parsing text or attributes. A character reference keeps recorded text
    # intact, including Windows line endings in multiline evidence.
    return html.escape(str(s or "")).replace("\r", "&#13;")


def prose_html(text):
    # Browsers do not treat DOM CRs as line breaks, while PDF engines may
    # normalize them to LF. Keep each CR in a hidden text node so textContent
    # stays exact, then display one break using CRLF's LF or an explicit br.
    parts = []
    for part in re.split(r"(\r\n?)", str(text or "")):
        if part.startswith("\r"):
            parts.append("<span hidden>&#13;</span>" + ("\n" if part == "\r\n" else "<br>"))
        else:
            parts.append(esc(part))
    return "".join(parts)


def plural(L, key, n):
    """The label for count n; a `_one` variant carries the singular form."""
    return L[key + "_one" if n == 1 and key + "_one" in L else key].replace("{n}", str(n))


def anchor(index):
    return f"finding-{index + 1}"


def included(data):
    return [f for f in data["findings"] if not f.get("excluded")]


def priority(findings):
    """Open findings first, then by severity; ties keep their recorded order."""
    return sorted(findings, key=lambda f: (f["status"] != "Open", SEVERITIES.index(f["severity"])))


def counts(data):
    fs = included(data)
    by = {(s, st): 0 for s in SEVERITIES for st in STATUSES}
    for f in fs:
        by[(f["severity"], f["status"])] += 1
    open_count = sum(by[(s, "Open")] for s in SEVERITIES)
    urgent = by[("High", "Open")] + by[("Medium", "Open")]
    return {"by": by, "open": open_count, "urgent": urgent, "included": len(fs),
            "excluded": len(data["findings"]) - len(fs),
            "fixed": sum(by[(s, "Fixed")] for s in SEVERITIES),
            "accepted": sum(by[(s, "Accepted")] for s in SEVERITIES)}


def headline(data, L):
    c = counts(data)
    if not c["included"]:
        return L["no_findings"]
    if c["urgent"]:
        return plural(L, "risk_summary", c["urgent"])
    return plural(L, "open_summary", c["open"]) if c["open"] else L["no_open"]


def console_lane(finding):
    if finding.get("excluded"):
        return "excluded"
    if finding["status"] != "Open":
        return "closed"
    return "with_fix" if finding.get("action") else "without_fix"


def console_model(data, lang, *, skill="scan-report-kit", details=None, verdicts=(), excluded_verdicts=()):
    L = labels_for(data, lang)
    labels = {**CONSOLE_LABELS[lang], **{k: L[k] for k in ("copied", "copy_failed", "location", "not_recorded")},
              "fix_missing": L["not_recorded"], "evidence_missing": L["not_recorded"],
              "empty_records": L["no_records"], "perspectives_empty": L["coverage_missing"]}
    anchors = {f["id"]: anchor(i) for i, f in enumerate(data["findings"])}
    findings, by_perspective = [], {}
    details = details or {}
    for f in priority(data["findings"]):
        d = details.get(f["id"], {})
        lane = console_lane(f)
        location = f.get("location", "")
        item = dict(id=f["id"], severity=f["severity"], status=f["status"],
                    status_label=L["excluded_short"] if lane == "excluded" else d.get("status", f["status"]),
                    verdict=f.get("verdict", ""), title=f["title"], location=location,
                    lane=lane, open=lane in ("with_fix", "without_fix"), excluded=lane == "excluded",
                    anchor=anchors[f["id"]],
                    tags=[f[k] for k in ("category", "confidence") if given(f.get(k))],
                    where=[{"label": L["location"], "value": location, "mono": True}] if given(location) else [],
                    evidence={k: d.get("evidence", {}).get(k, "") for k in ("text", "method")},
                    fix=d.get("fix", f.get("action", {}).get("text", "")))
        findings.append(item)
        if d.get("perspective"):
            by_perspective.setdefault(d["perspective"], []).append(item)
    perspectives = []
    for p in data.get("perspectives", []):
        matched = by_perspective.get(p["name"], [])
        first_open = next((f for f in matched if f["open"]), None)
        if first_open:
            tone = first_open["severity"].lower()
        elif any(f["lane"] == "closed" for f in matched):
            tone = "ink"
        else:
            tone = "accent" if matched else "muted"
        perspectives.append({**{k: p[k] for k in ("name", "result", "note") if k in p},
                             "tone": tone, "on": first_open is not None})
    order = dict.fromkeys((*verdicts, *(f["verdict"] for f in findings)))
    excluded_verdicts = set(excluded_verdicts) | {f["verdict"] for f in findings if f["excluded"]}
    m, c = data["meta"], counts(data)
    return {
        "meta": {"skill": skill, "title": m["project"], "title_id": "cx-title",
                 "context": [part for part in (m.get("date"), m.get("commit"), m.get("scope"), labels["read_only"]) if given(part)],
                 "headline": headline(data, L)},
        "counts": {"open": c["open"], "closed": c["fixed"] + c["accepted"], "excluded": c["excluded"], "total": len(findings)},
        "severities": SEVERITIES,
        "verdicts": [{"key": v, "label": v or L["not_recorded"], "tone": VERDICT_TONES.get(v, "strong"),
                      "excluded": v in excluded_verdicts}
                     for v in sorted(order, key=excluded_verdicts.__contains__)],
        "lanes": [{"key": k, "label": labels["lane_" + k], "tone": tone} for k, tone in LANE_TONES.items()],
        "perspectives": perspectives, "findings": findings, "labels": labels,
    }


def console_band_html(cm, kind):
    meta, counts, L = cm["meta"], cm["counts"], cm["labels"]
    context = "".join(f"<span>{esc(part)}</span>" for part in meta["context"])
    readout = "".join(f"<div><dt>{esc(L['readout_' + k])}</dt><dd>{counts[k]}</dd></div>"
                      for k in ("open", "closed", "excluded"))
    return (f"<header class='cx-band'><div class='cx-band-in'><div>"
            f"<p class='cx-wm'><span><span class='cx-perm' aria-hidden='true'>r--</span> agentic-scan</span>"
            f"<span class='cx-skill'>{esc(meta['skill'])}</span></p><p class='cx-kind'>{esc(kind)}</p>"
            f"<h1>{esc(meta['title'])}</h1><p class='cx-ctx'>{context}</p></div>"
            f"<dl class='cx-readout' aria-label='{esc(L['readout'])}'>{readout}</dl></div></header>")


def console_tiles_html(cm):
    L = cm["labels"]
    tiles = []
    for severity in cm["severities"]:
        items = [f for f in cm["findings"] if f["severity"] == severity and not f["excluded"]]
        opened = [f for f in items if f["open"]]
        filled = min(len(opened), 120)
        cells = "<i class='cx-on'></i>" * filled + "<i></i>" * (min(len(items), 120) - filled)
        if len(items) > 120:
            cells += f"<span class='cx-more'>+{len(items) - 120}</span>"
        ids = " ".join(f["id"] for f in opened[:6]) + (" …" if len(opened) > 6 else "")
        sub = L["tile_sub"].format(open=len(opened), closed=len(items) - len(opened)) + (f" · {ids}" if ids else "")
        tiles.append(f"<div class='cx-tile cx-c-{severity.lower()}' data-severity='{severity}'>"
                     f"<span class='cx-l'>{severity}</span><span class='cx-n'>{len(items)}</span>"
                     f"<span class='cx-cells' aria-hidden='true'>{cells}</span><span class='cx-s'>{esc(sub)}</span></div>")
    c = cm["counts"]
    note = L["severity_note"].format(n=c["total"] - c["excluded"], x=c["excluded"])
    return (f"<section class='cx-sev' aria-labelledby='cx-sev-h'><h2 class='cx-ph' id='cx-sev-h'><b>{esc(L['severity_h'])}</b>"
            f"<span>{esc(note)}</span></h2><div class='cx-tiles'>{''.join(tiles)}</div>"
            f"<p class='cx-legend'>{esc(L['legend_cell'])}<i class='cx-on'></i>{esc(L['legend_open'])} "
            f"<i></i>{esc(L['legend_closed'])}</p></section>")


def snippet_html(snippet):
    first, last = snippet["hit"]
    rows = []
    for i, line in enumerate(snippet["lines"]):
        n = snippet["start"] + i
        cls = " class='hit'" if first <= n <= last else ""
        rows.append(f"<span{cls}><b>{n:>5}</b> {esc(line)}</span>")
    return "<pre class='snippet'>" + "".join(rows) + "</pre>"


def field_table_html(field):
    """A body section's table: optional column heads, each row headed by its first cell."""
    if "rows" not in field:
        return ""
    head = ("<thead><tr>" + "".join(f"<th scope='col'>{prose_html(c)}</th>" for c in field["columns"]) + "</tr></thead>"
            if "columns" in field else "")
    rows = "".join("<tr>" + f"<th scope='row'>{prose_html(row[0])}</th>"
                   + "".join(f"<td>{prose_html(c)}</td>" for c in row[1:]) + "</tr>" for row in field["rows"])
    return f"<table class='field-table'>{head}<tbody>{rows}</tbody></table>"


def refs_html(refs, L):
    if not refs:
        return ""
    items = "".join(f"<li><span class='rt'>{esc(r['type'] if given(r.get('type')) else L['source'])}</span> "
                    f"<a href='{esc(r['url'])}'>{esc(r['title'] if given(r.get('title')) else r['url'])}</a></li>"
                    for r in refs)
    return f"<ul class='refs'>{items}</ul>"


def render_document(data, lang, *, console=None, extra_css=""):
    """The printable report (report.html), typeset per docs/design.md; print it with pdf.to_pdf."""
    validate(data)
    L = labels_for(data, lang)
    cm = console if console is not None else console_model(data, lang)
    cx = cm["labels"]
    m, c = data["meta"], counts(data)
    anchors = {id(f): anchor(i) for i, f in enumerate(data["findings"])}
    fs = priority(included(data))
    excluded = [f for f in data["findings"] if f.get("excluded")]

    def value(text):
        return esc(text) if given(text) else esc(L["none"])

    def prose_span(text):
        return f"<span class='prose'>{prose_html(text)}</span>" if given(text) else ""

    def bullets(items, empty):
        return ("<ul>" + "".join(f"<li class='prose'>{prose_html(x)}</li>" for x in items) + "</ul>"
                if items else f"<p class='small'>{esc(L[empty])}</p>")

    meta = "".join(f"<p class='meta-line'><strong>{esc(L[k])}</strong> {esc(m[k])}</p>"
                   for k in META_KEYS[1:] if given(m.get(k)))
    sev_head = "".join(f"<th scope='col' class='{s}'>{s}</th>" for s in SEVERITIES)
    def metric_cell(severity, statuses):
        n = sum(c["by"][(severity, st)] for st in statuses)
        urgent = statuses == ("Open",) and severity in ("High", "Medium") and n
        return f"<td class='metric-urgent'>{n}</td>" if urgent else f"<td>{n}</td>"

    metric_rows = "".join(f"<tr><th scope='row'>{esc(L[label])}</th>"
                          + "".join(metric_cell(s, statuses) for s in SEVERITIES) + "</tr>"
                          for label, statuses in (("open", ("Open",)), ("closed", ("Fixed", "Accepted"))))
    metrics = (f"<table class='metrics'><caption>{esc(L['open_by_severity'])}</caption>"
               f"<thead><tr><th scope='col'></th>{sev_head}</tr></thead><tbody>{metric_rows}</tbody></table>")

    def queue_table(items, lane):
        rows = "".join(
            f"<tr><td><a href='#{anchors[id(f)]}'>{esc(f['id'])}</a><br><span class='badge {f['severity']}'>{f['severity']}</span></td>"
            f"<td><div class='queue-title'>{esc(f['title'])}</div>"
            f"<div class='queue-location'><code>{esc(f.get('location'))}</code></div></td>"
            f"<td class='queue-action'>"
            + (f"<strong>{esc(f['action']['label'])}</strong>{prose_span(f['action'].get('text'))}" if f.get("action") else esc(L["none"]))
            + "</td></tr>" for f in items)
        return (f"<table class='queue' aria-labelledby='priority-queue-{lane}'><caption id='priority-queue-{lane}'>{esc(L['priority_caption'])}</caption>"
                "<colgroup><col class='ref-col'><col class='finding-col'><col class='action-col'></colgroup>"
                f"<thead><tr><th scope='col'>{esc(L['ref'])}</th><th scope='col'>{esc(L['title_col'])}</th>"
                f"<th scope='col'>{esc(L['action'])}</th></tr></thead><tbody>{rows}</tbody></table>")

    def closed_list(items):
        rows = "".join(f"<li><a href='#{f['anchor']}'>{esc(f['id'])}</a>"
                       f"<span>{esc(f['title'])}" +
                       (f"<span class='cx-loc'>{esc(f['location'])}</span>" if f["location"] else "") +
                       f"</span><span class='cx-state'>{esc(' · '.join(filter(None, (f['status_label'], f['verdict']))))}</span></li>"
                       for f in items)
        return f"<ul class='cx-doc-list'>{rows}</ul>"

    source = {f["id"]: f for f in data["findings"]}
    lanes = {}
    for i, lane in enumerate(cm["lanes"], 1):
        key = lane["key"]
        items = [f for f in cm["findings"] if f["lane"] == key]
        body = f"<p class='cx-empty'>{esc(cx['lane_empty'])}</p>"
        if items:
            body = queue_table([source[f["id"]] for f in items], key) if items[0]["open"] else closed_list(items)
        lanes[key] = (f"<section id='lane-{key}' data-lane='{key}' class='cx-doc-lane cx-c-{lane['tone']}'>"
                      f"<h3><span>{i}. {esc(lane['label'])}</span><span class='cx-count'>{len(items)}</span></h3>"
                      f"{body}</section>")

    lists = "".join(f"<section id='{k.replace('_', '-')}'><h2>{esc(L[k])}</h2>{bullets(data.get(k, []), 'not_recorded')}</section>"
                    for k in ("decisions", "next_steps") if data.get(k))

    coverage_rows = "".join(f"<tr><td>{esc(p['name'])}</td><td>{prose_span(p.get('result')) or esc(L['none'])}</td><td>{prose_span(p.get('note')) or esc(L['none'])}</td></tr>"
                            for p in data.get("perspectives", []))
    coverage = (f"<table class='coverage'><caption>{esc(L['coverage_caption'])}</caption>"
                "<colgroup><col class='perspective-col'><col class='result-col'><col class='note-col'></colgroup>"
                f"<thead><tr><th scope='col'>{esc(L['perspective'])}</th><th scope='col'>{esc(L['result'])}</th>"
                f"<th scope='col'>{esc(L['note'])}</th></tr></thead><tbody>{coverage_rows}</tbody></table>"
                if coverage_rows else f"<p class='small'>{esc(L['coverage_missing'])}</p>")

    index_rows = "".join(
        f"<tr role='row'><td role='cell' data-label='{esc(L['title_col'])}'><a class='index-title' href='#{anchors[id(f)]}'>{esc(f['title'])}</a>"
        f"<span class='index-id'>{esc(f['id'])}</span></td>"
        f"<td role='cell' data-label='{esc(L['severity'])}'><span class='badge {f['severity']}'>{f['severity']}</span></td>"
        f"<td role='cell' data-label='{esc(L['status'])}'>{esc(f['status'])}</td>"
        f"<td role='cell' data-label='{esc(L['location'])}'><code>{value(f.get('location'))}</code></td></tr>" for f in fs)
    index = (f"<table class='index' role='table'><caption>{esc(L['register_caption'])}</caption>"
             "<colgroup><col class='finding-col'><col class='severity-col'><col class='status-col'><col class='evidence-col'></colgroup>"
             f"<thead role='rowgroup'><tr role='row'><th scope='col' role='columnheader'>{esc(L['title_col'])}</th>"
             f"<th scope='col' role='columnheader'>{esc(L['severity'])}</th>"
             f"<th scope='col' role='columnheader'>{esc(L['status'])}</th>"
             f"<th scope='col' role='columnheader'>{esc(L['location'])}</th></tr></thead>"
             f"<tbody role='rowgroup'>{index_rows}</tbody></table>" if fs else f"<p class='small'>{esc(L['no_findings'])}</p>")

    def card(f):
        state = "".join(f"<tr><th scope='row'>{esc(L[k])}</th><td>"
                        + (f"<span class='badge {f['severity']}'>{f['severity']}</span>" if k == "severity" else value(f.get(k)))
                        + "</td></tr>" for k in ("severity", "status", "confidence", "verdict", "category", "location"))
        action_text = f.get("action", {}).get("text", "")
        action = (f"<div class='finding-field'><h4>{esc(f['action']['label'])}</h4>"
                  + (f"<p class='prose'>{prose_html(action_text)}</p>" if given(action_text) else "") + "</div>"
                  if f.get("action") and f["status"] == "Open" and not f.get("excluded") else "")
        def field(x, h):
            text = x.get("text", "")
            body = (f"<p class='prose'>{prose_html(text)}</p>" if given(text) else
                    "" if "rows" in x else f"<p class='empty-value'>{esc(L['not_recorded'])}</p>")
            return f"<div class='finding-field'><{h}>{esc(x['label'])}</{h}>{body}{field_table_html(x)}</div>"

        fields = "".join("".join(field(x, "h4") for x in items) if name is None else
                         f"<section class='finding-group'><h4>{esc(name)}</h4>"
                         + "".join(field(x, "h5") for x in items) + "</section>"
                         for name, items in field_groups(f.get("fields", [])))
        snippet = (f"<div class='finding-field'><h4>{esc(L['snippet'])}</h4>{snippet_html(f['snippet'])}</div>"
                   if f.get("snippet") else "")
        refs = (f"<div class='finding-field'><h4>{esc(L['references'])}</h4>{refs_html(f['references'], L)}</div>"
                if f.get("references") else "")
        cls = "finding excluded" if f.get("excluded") else f"finding sev-{f['severity']}"
        return (f"<article class='{cls}' id='{anchors[id(f)]}'><div class='finding-header'>"
                f"<span class='finding-id'>{esc(f['id'])}</span><h3>{esc(f['title'])}</h3>"
                f"<table class='finding-state'><tbody>{state}</tbody></table></div>"
                f"{action}{fields}{snippet}{refs}</article>")

    details = (f"<section id='finding-details'><h2>{esc(L['details'])}</h2>" + "".join(card(f) for f in fs) + "</section>"
               if fs else "")
    excluded_html = (f"<section class='excluded-section' id='excluded'><h2>{esc(L['excluded'])}</h2>"
                     f"<p class='section-note'>{esc(L['excluded_note'])}</p>" + "".join(card(f) for f in excluded) + "</section>"
                     if excluded else "")
    summary = data.get("summary", "")
    return f"""<!doctype html>
<html lang="{esc(lang)}" class="cx-doc"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(L['title'])} - {esc(m['project'])}</title><style>{style.document_css(L['running_footer'])}
{extra_css}
{style.console_css()}</style></head><body>
{console_band_html(cm, L['title'])}
<header class="report-header"><p class="kicker">{esc(L['kind'])}</p>{meta}</header>
{console_tiles_html(cm)}
<main>
<p class="lead prose">{prose_html(summary if given(summary) else L['no_summary'])}</p>
<section class="summary-section" id="summary"><h2>{esc(L['summary'])}</h2><p>{esc(headline(data, L))}</p>{metrics}
<h3 class="limit-heading">{esc(L['limitations'])}</h3><div class="limits">{bullets(data.get('limitations', []), 'limitations_empty')}</div></section>
<div id="triage-lanes">
<section id="priority-queue"><h2>{esc(L['priority'])}</h2><p class="section-note">{esc(cx['priority_note'])}</p>
{'' if c['open'] else f'<p class="small">{esc(L["no_open"])}</p>'}
{lanes['with_fix']}{lanes['without_fix']}</section>
<div id="closed-lanes">{lanes['closed']}{lanes['excluded']}</div>
</div>
{lists}
<section id="recorded-coverage"><h2>{esc(L['coverage'])}</h2><p class="section-note">{esc(L['coverage_note'])}</p>{coverage}
<h3>{esc(L['checked_ok'])}</h3>{bullets(data.get('checked_ok', []), 'not_recorded')}</section>
<section id="finding-register"><h2>{esc(L['register'])}</h2><p class="section-note">{esc(L['register_note'])}</p>{index}</section>
{details}{excluded_html}
</main></body></html>
"""


DASHBOARD = """<!doctype html>
<html lang="__LANG__" class="app-shell">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
__CSS__
</style>
</head>
<body>
<a class="skip" href="#findings" data-l="jump"></a>
<header class="cx-band"><div class="cx-band-in"><div data-cx="ident"></div><div class="cx-side">
<dl class="cx-readout" data-cx="readout"></dl>
<div class="cx-tools"><a class="button" href="report.html">__CX_REPORT__</a><button id="theme" type="button">__CX_THEME__</button></div>
</div></div></header>
<div class="cx" id="console"><div class="cx-grid">
<section class="cx-p cx-sev" data-cx="severity" aria-labelledby="cx-sev-h"></section>
<section class="cx-p cx-ver" data-cx="verdicts" aria-labelledby="cx-ver-h"></section>
<section class="cx-p cx-cov" data-cx="perspectives" aria-labelledby="cx-cov-h"></section>
<section class="cx-triage" id="triage" aria-labelledby="cx-triage-h">
<h2 class="cx-ph" id="cx-triage-h"><b>__TRIAGE__</b><span>__TRIAGE_NOTE__</span></h2>
<div class="cx-triage-in"><div class="cx-board" data-cx="board"></div><aside class="cx-insp" data-cx="inspector"></aside></div>
</section>
</div></div>
<div class="shell">
<nav class="sidebar" id="nav"><h2 class="nav-title" data-l="contents"></h2><ol class="nav-links">
<li><a href="#triage">__TRIAGE__</a></li><li><a href="#findings" data-l="register"></a></li><li><a href="#overview" data-l="summary"></a></li><li><a href="#priority-section" data-l="priority"></a></li><li><a href="#coverage" data-l="coverage"></a></li><li><a href="#lists" data-l="records"></a></li>
</ol><div class="facets"><h2 class="nav-title" data-l="severity"></h2><div id="facets"></div></div>
<dl class="keys"><dt data-l="shortcuts" class="nav-title"></dt><dd><kbd>/</kbd> <span data-l="key_search"></span></dd><dd><kbd>j</kbd> <kbd>k</kbd> <span data-l="key_move"></span></dd><dd><kbd>Enter</kbd> <span data-l="key_toggle"></span></dd></dl></nav>
<main>
<section id="findings" tabindex="-1" aria-labelledby="findings-heading"><div class="section-head"><div><h2 id="findings-heading" data-l="register"></h2><p data-l="register_note"></p></div></div>
<div class="panel filters-panel"><div class="filters">
<label><span data-l="filters_record_set"></span><select id="f-scope"></select></label><label><span data-l="severity"></span><select id="f-sev"></select></label><label><span data-l="status"></span><select id="f-status"></select></label><label><span data-l="category"></span><select id="f-cat"></select></label>
<label class="search"><span data-l="search"></span><input id="f-q" type="search"></label><label><span data-l="sort"></span><select id="f-sort"></select></label>
</div><div class="filter-bottom"><p class="result-count" id="result-count" aria-live="polite"></p><button id="reset" type="button" data-l="reset"></button></div></div>
<div class="tablewrap"><table class="register" role="table"><thead role="rowgroup"><tr role="row"><th scope="col" role="columnheader">ID</th><th scope="col" role="columnheader" data-l="severity"></th><th scope="col" role="columnheader" data-l="confidence"></th><th scope="col" role="columnheader" data-l="status"></th><th scope="col" role="columnheader" data-l="verdict"></th><th scope="col" role="columnheader" data-l="title_col"></th><th scope="col" role="columnheader" data-l="category"></th></tr></thead><tbody id="rows" role="rowgroup"></tbody></table></div></section>
<section id="overview" tabindex="-1" aria-labelledby="overview-heading">
<div class="hero"><div><h2 id="overview-heading" data-l="dashboard_title"></h2><div class="meta" id="meta"></div></div></div>
<div class="summary-banner" id="summary"></div>
<div class="cards" id="cards"></div>
</section>
<section id="priority-section" tabindex="-1" aria-labelledby="priority-heading"><div class="section-head"><div><h2 id="priority-heading" data-l="priority"></h2><p data-l="priority_note"></p></div><a href="#findings" data-l="view_all"></a></div><div class="priority-list" id="priority"></div><p class="report-note" id="queue-note"></p></section>
<details class="panel coverage" id="coverage" tabindex="-1" open><summary><span data-l="coverage"></span><span class="small" id="coverage-count"></span></summary><p data-l="coverage_note"></p><dl class="scope-meta" id="scope-meta"></dl><div class="coverage-columns"><div id="perspectives"></div><div><h3 data-l="limitations"></h3><div id="limitations"></div></div></div></details>
<details class="chart-section"><summary data-l="overview"></summary><p class="section-note" data-l="count_basis"></p><div class="grid"><div class="panel"><h3 data-l="by_severity"></h3><div id="c-sev"></div></div><div class="panel"><h3 data-l="by_category"></h3><div id="c-cat"></div></div><div class="panel"><h3 data-l="by_status"></h3><div id="c-status"></div></div></div></details>
<div class="lists" id="lists" tabindex="-1"></div><footer class="footer" data-l="source_note"></footer>
<noscript><p>__NOSCRIPT__ <a href="report.html">__REPORT__</a></p></noscript>
</main>
</div>
<script id="data" type="application/json">__DATA__</script>
<script>
__JS__
</script>
</body>
</html>
"""


def _finding_payload(finding, index):
    """Copy only the validated contract fields; extensions never enter the page.

    Blank optional strings are left out, so the dashboard treats them as absent
    like the printable report does.
    """
    payload = {k: finding[k] for k in FINDING_KEYS if k in finding
               and (not isinstance(finding[k], str) or given(finding[k]))}
    payload["anchor"] = anchor(index)
    for key, keys in (("action", ("label", "text")), ("snippet", ("start", "hit", "lines"))):
        if key in finding:
            payload[key] = {k: finding[key][k] for k in keys if k in finding[key]}
    if "fields" in finding:
        payload["fields"] = [{k: item[k] for k in ("label", "text", "group", "columns", "rows") if k in item}
                             for item in finding["fields"]]
    if "references" in finding:
        payload["references"] = [{k: item[k] for k in ("type", "title", "url") if k == "url" or given(item.get(k))}
                                 for item in finding["references"]]
    return payload


def render_dashboard(data, lang, *, console=None, extra_css=""):
    """The interactive dashboard (dashboard.html): self-contained, offline, light and dark themes."""
    validate(data)
    L = labels_for(data, lang)
    cm = console if console is not None else console_model(data, lang)
    payload = {
        "meta": {k: data["meta"][k] for k in META_KEYS if given(data["meta"].get(k))},
        "labels": L, "headline": headline(data, L), "summary": data.get("summary", ""),
        "console": cm,
        "findings": [_finding_payload(f, i) for i, f in enumerate(data["findings"])],
        "order": {"severity": SEVERITIES, "status": STATUSES},
        "perspectives": [{k: p[k] for k in ("name", "result", "note") if k in p} for p in data.get("perspectives", [])],
        **{k: data.get(k, []) for k in LIST_KEYS},
    }
    # Escape every less-than sign: <!-- and <script also change HTML parsing.
    blob = json.dumps(payload, ensure_ascii=False, allow_nan=False).replace("<", "\\u003c")
    replacements = {"__LANG__": esc(lang), "__TITLE__": esc(f"{L['dashboard_title']} - {data['meta']['project']}"),
                    "__NOSCRIPT__": esc(L["no_script"]), "__REPORT__": esc(L["report_link"]), "__DATA__": blob,
                    "__TRIAGE__": esc(cm["labels"]["triage"]), "__TRIAGE_NOTE__": esc(cm["labels"]["triage_note"]),
                    "__CX_REPORT__": esc(cm["labels"]["report_link"]), "__CX_THEME__": esc(cm["labels"]["theme"]),
                    "__CSS__": "\n".join((style.dashboard_css(), extra_css, style.console_css())),
                    "__JS__": style.console_js() + "\n" + style.dashboard_js()}
    # Substitute only template tokens, in one pass, never tokens inside report data.
    return re.sub(r"__(?:LANG|TITLE|NOSCRIPT|REPORT|TRIAGE|TRIAGE_NOTE|CX_REPORT|CX_THEME|DATA|CSS|JS)__", lambda mt: replacements[mt.group(0)], DASHBOARD)
