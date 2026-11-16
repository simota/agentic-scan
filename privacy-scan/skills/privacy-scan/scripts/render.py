#!/usr/bin/env python3
"""Render findings.json into dashboard.html and report.md.

    python3 render.py FINDINGS --out DIR [--lang ja|en]

Both outputs are derived from the one record; neither adds facts of its own.
`dashboard.html` is self-contained and works offline. `report.md` holds the
scope, counts, findings, commitments, the personal data map and who receives
each element (when the record has a `data_map`), perspective coverage, sound items,
limitations, decisions and next steps; the chat summary in `reference/report.md`
is written by the agent, not rendered.

Exit codes: 0 written, 1 an output could not be saved, 2 the record does not
match the schema (the field is named on stderr) or the command line is invalid.
"""
import argparse
from base64 import b64encode
from hashlib import sha256
from html import escape
from pathlib import Path
import re
import sys
from urllib.parse import quote, urlsplit

# Importing the local helpers must not write bytecode into the skill tree.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import (CONFIDENCES, PERSPECTIVES, SEVERITIES, VERDICTS,  # noqa: E402
                      SchemaError, prepare_cli, read_json, record_problems, validate)
from findings import commitment_citations, counts as record_counts, excluded as is_excluded  # noqa: E402
from findings import element_citations, recipients  # noqa: E402
from output_io import write_utf8_files  # noqa: E402
from personal_values import LINE_BREAKS  # noqa: E402
from scan_report_kit import style as kit_style  # noqa: E402

LABELS = {
    "en": {
        "title": "Privacy assessment", "scope": "Scope and method",
        "brand": "privacy-scan", "theme": "Theme",
        "findings": "Findings", "commitments": "Privacy commitments", "perspectives": "Perspective coverage",
        "checked_ok": "Checked and sound", "limitations": "What could not be checked",
        "decisions": "Decisions for a human", "next_steps": "Next steps", "excluded": "Excluded",
        "all": "All", "none": "None.",
        "location": "location", "data": "personal data", "subjects": "data subjects",
        "flow": "flow", "contrast": "contrast", "impact": "what happens", "commitment": "commitment",
        "fix": "fix direction", "guard": "guard", "verdict": "recorded verdict",
        "method": "verification", "evidence": "evidence", "analysis": "analysis",
        "verdict_counts": "Verdict counts",
        "references": "references", "status": "status", "review_method": "Review method",
        "inferred": "inferred", "not_checked_reason": "reason",
        "static_note": "Static review; no personal data was read from any data store.",
        "analysed_note": "Static review plus read-only tool analysis (data-flow or schema scan, history); no personal data was read.",
        "project": "System", "scope_row": "Scope", "revision": "Revision", "date": "Date / assessor",
        "axis": "Severity axis", "axis_confirmed": "confirmed by the requester",
        "axis_assumed": "assumed; not confirmed by the requester",
        # Condenses the severity table in SKILL.md and the confidence row in
        # reference/findings-schema.md; change it with them.
        "legend": {
            "title": "How to read the levels", "severity": "Severity", "confidence": "Confidence",
            "High": "Personal data (a sensitive category, or broad personal data of many subjects) "
                    "reaches a party or place the commitments exclude, is processed on a core flow "
                    "without a consent the commitments require, or survives a deletion or "
                    "account-closure path in a primary store",
            "Medium": "A High-class gap lowered one level, personal data kept beyond a stated "
                      "retention period (High for a sensitive category in a primary store), a "
                      "deletion or export path that misses a secondary store, or real personal "
                      "data copied into non-production use",
            "Low": "Collection beyond need with no further exposure, missing pseudonymisation in "
                   "internal analytics, identifiers in URLs inside first-party systems, or "
                   "defence-in-depth gaps in storage protection",
            "Info": "A note with no demonstrated path to a subject's harm or a broken commitment",
            "Confirmed": "The gap follows from the code",
            "Environment-dependent": "The gap needs a named runtime setting, recorded in its conditions",
            "Suspected": "The code suggests the gap but does not show it",
            "separate": "Severity and confidence are graded separately; confidence never raises "
                        "or lowers severity.",
            "assumed": "Severity rests on an assumed list; see decisions.",
        },
        "commitment_columns": ("ID", "Commitment", "Family", "Source", "Status", "Findings"),
        "conditions": "conditions",
        "disclaimer": "Technical review of source code, not legal advice; it does not state "
                      "whether the application complies with any law.",
        "perspective": "perspective",
        "perspective_columns": ("Perspective", "Status", "Note"),
        "filter": "Filter findings by severity",
        "showing": "Showing {shown} of {total}",
        "search": "Search findings", "search_hint": "field, path, ID, commitment…",
        "elements": "data map",
        "data_map": "Personal data map",
        "data_map_summary": "{n} elements, {sensitive} in a sensitive category, {recipients} recipients",
        "data_map_columns": ("ID", "Element", "Category", "Subjects", "Collected at", "Stored in",
                             "Recipients", "Retention and notes", "Findings"),
        "sensitive": "sensitive",
        "recipients": "Who receives personal data",
        "recipient_columns": ("Recipient", "Elements received"),
    },
    "ja": {
        "title": "プライバシー診断", "scope": "対象と方法",
        "brand": "privacy-scan", "theme": "表示切替",
        "findings": "検出事項", "commitments": "プライバシー上の約束", "perspectives": "観点のカバレッジ",
        "checked_ok": "確認して問題なかった項目", "limitations": "確認できなかったこと",
        "decisions": "人が判断すべき事項", "next_steps": "次の作業", "excluded": "除外",
        "all": "すべて", "none": "なし。",
        "location": "場所", "data": "個人データ", "subjects": "データ主体",
        "flow": "データの流れ", "contrast": "対照", "impact": "何が起きるか", "commitment": "約束",
        "fix": "修正方針", "guard": "再発防止チェック", "verdict": "検証判定",
        "method": "検証方法", "evidence": "根拠", "analysis": "解析",
        "verdict_counts": "検証判定別の件数",
        "references": "参考", "status": "ステータス", "review_method": "診断方法",
        "inferred": "推定", "not_checked_reason": "理由",
        "static_note": "静的レビューのみ。データストアから個人データは一切読み取っていない。",
        "analysed_note": "静的レビューに加え、読み取り専用のツール解析（データフロー・スキーマの走査、変更履歴）を実施。個人データは読み取っていない。",
        "project": "システム", "scope_row": "範囲", "revision": "リビジョン", "date": "診断日 / 診断者",
        "axis": "深刻度の軸", "axis_confirmed": "依頼者が確認済み",
        "axis_assumed": "仮定（依頼者は未確認）",
        "legend": {
            "title": "レベルの読み方", "severity": "深刻度", "confidence": "確度",
            "High": "個人データ（要配慮・機微な分類、または多数の主体の広範な個人データ）が、"
                    "約束が除外する相手や場所に届く、約束が求める同意なしに中核フローで処理される、"
                    "または削除・退会の経路を経ても一次ストアに残る",
            "Medium": "High に該当する欠陥を 1 段階下げたもの、定めた保持期間を超えた個人データの保持"
                      "（一次ストアの要配慮・機微な分類なら High）、二次ストア（コピー）を取りこぼす"
                      "削除・エクスポート経路、または本番以外の用途への実在の個人データの複製",
            "Low": "それ以上の露出がない必要以上の収集、社内分析での仮名化の欠如、"
                   "自社システム内での URL 中の識別子、保存時の保護における多層防御の欠如",
            "Info": "主体への害や約束違反に至る経路が示されていない所見",
            "Confirmed": "欠陥がコードから直接わかる",
            "Environment-dependent": "欠陥は名前を挙げた実行時の設定に依存する（前提条件に記録）",
            "Suspected": "コードから欠陥がうかがえるが、示されてはいない",
            "separate": "深刻度と確度は別々に判定する。確度で深刻度を上げ下げしない。",
            "assumed": "深刻度は依頼者が確認していない一覧に基づく。人が判断すべき事項を参照。",
        },
        "commitment_columns": ("ID", "約束", "分類", "出典", "ステータス", "検出事項"),
        "conditions": "前提条件",
        # Enumerations shown in Japanese; perspective names keep the English name
        # used in `category` so findings and coverage can be matched.
        "terms": {
            "Data inventory and minimisation": "データの棚卸しと最小化",
            "Purpose and consent": "目的と同意",
            "Retention and deletion": "保持と削除",
            "Data subject rights": "データ主体の権利",
            "Third-party sharing": "第三者提供",
            "Logs, telemetry and errors": "ログ・テレメトリ・エラー",
            "Exposure to other actors": "他者への露出",
            "Storage protection": "保存時の保護",
            "Client-side tracking": "クライアント側のトラッキング",
            "Identifiers and pseudonymisation": "識別子と仮名化",
            "Non-production and derived copies": "本番以外の環境と派生コピー",
            "Location and transfers": "保存場所と移転",
            "applied": "適用", "partly applied": "一部適用", "N/A": "対象外",
            "not checked": "未確認", "holds": "守られている", "violated": "違反",
            "partly read": "一部のみ確認", "Open": "未対応", "Fixed": "修正済み",
            "Accepted": "受容",
        },
        "disclaimer": "ソースコードの技術的なレビューであり、法的見解ではない。"
                      "アプリケーションが法令に適合しているかどうかは述べていない。",
        "perspective": "観点",
        "perspective_columns": ("観点", "ステータス", "メモ"),
        "filter": "重要度で検出事項を絞り込む",
        "showing": "{total}件中{shown}件を表示",
        "search": "検出事項を検索", "search_hint": "フィールド名・パス・ID・約束…",
        "elements": "データマップ",
        "data_map": "個人データマップ",
        "data_map_summary": "要素 {n} 件（うち要配慮・機微 {sensitive} 件）、受領者 {recipients} 件",
        "data_map_columns": ("ID", "要素", "分類", "データ主体", "収集箇所", "保存先",
                             "受領者", "保持期間・メモ", "検出事項"),
        "sensitive": "機微",
        "recipients": "個人データの受領者",
        "recipient_columns": ("受領者", "受け取る要素"),
    },
}
FIELDS = ("location", "data", "elements", "subjects", "flow", "contrast", "impact", "conditions",
          "commitment", "fix", "guard")


def element_name(record, labels):
    """An element with its sensitive-category mark, as both reports show it."""
    return record["element"] + (f" ({labels['sensitive']})" if record["sensitive"] else "")


def data_map_rows(doc, labels):
    """One row per data map element; the last cell lists the reported findings citing it."""
    citing = element_citations(doc)
    return [(r["id"], element_name(r, labels), r["category"], r["subjects"],
             ", ".join(r.get("collected", [])), "\n".join(r["stores"]), "\n".join(r["recipients"]),
             "\n".join(v for v in (r.get("retention", ""), r.get("note", "")) if shown(v)),
             ", ".join(citing.get(r["id"], [])))
            for r in doc.get("data_map", [])]


def recipient_rows(doc, labels):
    """Recipient -> the elements it receives. Findings cite elements, not
    recipients, so they are listed in the data map table only."""
    names = {r["id"]: f"{r['id']} {element_name(r, labels)}" for r in doc.get("data_map", [])}
    return [(recipient, "\n".join(names[i] for i in ids))
            for recipient, ids in recipients(doc).items()]


def data_map_summary(doc, labels):
    n = record_counts(doc)
    return labels["data_map_summary"].format(n=n["n_elements"], sensitive=n["n_sensitive_elements"],
                                             recipients=n["n_recipients"])


def counts(findings):
    """Reported findings per severity, and the excluded count: `findings.py counts`."""
    recorded = record_counts({"findings": findings})
    return {s: recorded[f"n_{s.lower()}"] for s in SEVERITIES}, recorded["n_excluded"]


def verdict_summary(findings):
    """Show every recorded verdict, including exclusions and zero counts."""
    return " / ".join(f"{v} {sum(f['validation']['verdict'] == v for f in findings)}"
                      for v in VERDICTS)


# The guard lets these separate unrelated numbers, so each must show as a break.
LINE_BREAK = re.compile(rf"\r\n|[{LINE_BREAKS}]")


def as_text(value):
    """Recorded text with every line boundary written as a newline."""
    return LINE_BREAK.sub("\n", ", ".join(value) if isinstance(value, list) else str(value))


def shown(value):
    """Blank optional strings add no row or label to either report."""
    return bool(as_text(value).strip())


def finding_fields(f, labels):
    """The perspective (with its hunt step) leads the recorded fields."""
    step = f.get("step", "")
    category = perspective_name(labels, f["category"])
    perspective = f"{category} ({step.strip()})" if step.strip() else category
    return [("perspective", perspective)] + [(key, f[key]) for key in FIELDS
                                             if key in f and shown(f[key])]


def revision(meta):
    commit = meta.get("commit", "")
    return commit if commit.strip() else "UNKNOWN"


def axis_rows(meta, labels):
    """The severity-axis row, when the record says whether the requester confirmed it."""
    axis = meta.get("axis")
    return [(labels["axis"], labels[f"axis_{axis}"])] if axis in ("confirmed", "assumed") else []


def legend(meta, labels):
    """What each severity and confidence level means here, for both reports:
    (severity rows, confidence rows, closing lines)."""
    text = labels["legend"]
    closing = [text["separate"]] + ([text["assumed"]] if meta.get("axis") == "assumed" else [])
    return ([(s, text[s]) for s in SEVERITIES], [(c, text[c]) for c in CONFIDENCES], closing)


def perspective_rows(doc, labels):
    """List every perspective in the reference order in both reports."""
    recorded = {p["name"]: p for p in doc.get("perspectives", [])}
    return [(perspective_name(labels, name),
             term(labels, recorded.get(name, {}).get("status", "—")),
             recorded.get(name, {}).get("note", ""))
            for name in PERSPECTIVES]


def reference_title(ref):
    """A blank title must not hide the link; fall back to the URL."""
    title = ref.get("title", "")
    return title if title.strip() else ref["url"]


# `$` too: GitHub renders `$…$` as math, as in `$PATH:$HOME`.
MARKDOWN_SPECIALS = "\\`*_[]|~#$"  # each gets a backslash; the backslash stays first


# URLs written in prose. GFM links them automatically but keeps our escape
# backslashes in the target, so they are written as explicit links instead.
# GFM links a scheme in any case after anything but an ASCII letter (also
# directly after Japanese text, digits or '.'), and `www.` only at a word start.
URL_TOKEN = re.compile(r"(?:(?<![A-Za-z])(?i:https?)://|(?<![\w.@/])www\.)"
                       r"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+")
URL_TRAILING = ".,;:!?'\"*_~"
# What GFM would still autolink in text that is not an explicit link: `ftp://`
# and the URLs `_prose_url` declines (a `www.<placeholder>`, a dotless or
# non-ASCII host, `www.` after `_`). An escaped colon or dot keeps them literal
# text, as other unsupported schemes are.
AUTOLINK_START = re.compile(r"(?<![A-Za-z])(?i:ftp|https?)(?=://)|(?<![A-Za-z0-9])www(?=\.)")


def _escape_markdown(text):
    """Backslash-escape MARKDOWN_SPECIALS. str.replace is much faster than a
    translate table on non-ASCII prose; the backslash goes first, so the
    backslashes added for the other characters are not escaped again."""
    for char in MARKDOWN_SPECIALS:
        if char in text:
            text = text.replace(char, "\\" + char)
    return text


def _literal(text, in_link=False):
    text = _escape_markdown(escape(text, quote=False))
    # Link text is never autolinked, so it keeps its spelling. AUTOLINK_START
    # needs a following '://' or 'www.'; without either there is nothing to do.
    if in_link or ("://" not in text and "www." not in text):
        return text
    return AUTOLINK_START.sub(lambda m: m.group() + "\\", text)


AUTHORITY_END = re.compile(r"[/?#]")
DOTTED_HOST = re.compile(r"[A-Za-z0-9]\.[A-Za-z0-9]")


def _prose_url(url):
    """Trim trailing punctuation the way GFM does; return '' when nothing is left."""
    while url and (url[-1] in URL_TRAILING
                   or (url[-1] == ")" and url.count(")") > url.count("("))):
        url = url[:-1]
    # GFM links only a host with a dot; a dotless one stays literal whatever follows.
    authority = AUTHORITY_END.split(url.split("//", 1)[-1], maxsplit=1)[0]
    host = authority.rpartition("@")[2].partition(":")[0]
    return url if DOTTED_HOST.search(host) else ""


def markdown_text(value, links=True):
    """Keep prose literal inside headings, inline text and table cells.

    With `links`, URLs become explicit links whose targets keep their spelling.
    Link labels pass `links=False`, because a link cannot contain another link.
    """
    text = as_text(value)
    parts, pos = [], 0
    # URL_TOKEN needs '://' or 'www.'; skip the scan of prose that has neither.
    scan = links and ("://" in text or "www." in text)
    for match in URL_TOKEN.finditer(text) if scan else ():
        url = _prose_url(match.group())
        if not url:
            continue
        before = _literal(text[pos:match.start()])
        # `!` directly before the link would make it an image.
        parts.append(before[:-1] + "\\!" if before.endswith("!") else before)
        # A bracketed link, not an autolink: CommonMark renderers differ on
        # decoding `&amp;` inside autolinks, but agree inside link destinations.
        target = escape(("http://" if url.startswith("www.") else "") + url, quote=False)
        parts.append(f"[{_literal(url, in_link=True)}](<{target}>)")
        pos = match.start() + len(url)
    parts.append(_literal(text[pos:], in_link=not links))
    # Add our own breaks only after escaping the supplied HTML and Markdown.
    return "".join(parts).replace("\n", "<br>")


def markdown_cell(value):
    """Keep literal text and line breaks inside one Markdown table cell."""
    return markdown_text(value)


def markdown_row(values):
    return "| " + " | ".join(markdown_cell(value) for value in values) + " |"


BULLET_MARKER = re.compile(r"^([ \t]*)([-+])")
ORDERED_MARKER = re.compile(r"^([ \t]*[0-9]{1,9})([.)])(?=\s|$)")
LEADING_BLANKS = re.compile(r"^[ \t]+")


def markdown_item(value):
    """Keep leading whitespace and list markers from starting Markdown blocks."""
    text = markdown_text(value)
    text = BULLET_MARKER.sub(r"\1\\\2", text)
    text = ORDERED_MARKER.sub(r"\1\\\2", text)
    # Character references preserve spaces and tabs without making the list
    # body an indented code block. Add them after escaping supplied markup.
    return LEADING_BLANKS.sub(lambda match: "".join(f"&#{ord(c)};" for c in match[0]), text)


BACKTICK_RUN = re.compile(r"`+")


def markdown_code(value):
    """Keep commands literal, including backticks, padding and line breaks."""
    lines = as_text(value).split("\n")
    spans = []
    for line in lines:
        if not line:
            spans.append("")
            continue
        fence = "`" * (max((len(run) for run in BACKTICK_RUN.findall(line)), default=0) + 1)
        if line.strip(" ") and (line.startswith(("`", " ")) or line.endswith(("`", " "))):
            # CommonMark removes one padding space at each end of a code span.
            line = " " + line + " "
        spans.append(f"{fence}{line}{fence}")
    return "<br>".join(spans)


def reference_destination(url):
    """Encode supported reference URLs before escaping for an output format."""
    try:
        scheme = urlsplit(url).scheme.lower()
    except ValueError:
        return None
    # Unsupported or malformed destinations remain visible as literal text.
    if scheme not in ("", "http", "https"):
        return None
    return quote(url, safe="/:?#[]@!$&'()*+,;=%")


def markdown_reference(ref):
    url = ref["url"]
    title = reference_title(ref)
    destination = reference_destination(url)
    if destination is None:
        # Plain text, not a link label: URLs in it are linked like other prose.
        text = markdown_text(title)
        return text if title == url else f"{text} — {markdown_text(url)}"
    return f"[{markdown_text(title, links=False)}](<{escape(destination, quote=False)}>)"


def html_reference(ref):
    url = ref["url"]
    title = reference_title(ref)
    label = escape(as_text(title))
    destination = reference_destination(url)
    if destination is None:
        return label if title == url else f"{label} — {escape(as_text(url))}"
    return f'<a href="{escape(destination)}">{label}</a>'


def term(labels, value):
    """A recorded enumeration in the report language."""
    return labels.get("terms", {}).get(value, value)


def perspective_name(labels, name):
    translated = term(labels, name)
    return name if translated == name else f"{translated}（{name}）"


def commitment_text(record, labels):
    """Keep recorded qualifications visible in both commitment ledgers."""
    statement, status = record["statement"], term(labels, record["status"])
    if record.get("inferred") is True:
        statement += f" ({labels['inferred']})"
    if record.get("reason", "").strip():
        status += f" — {labels['not_checked_reason']}: {record['reason']}"
    return statement, status


def review_method(meta, findings, labels):
    """Prefer the recorded assessment method, including reviews with no findings."""
    method = meta.get("method", "")
    if method.strip():
        return method
    analysed = any(f["validation"]["method"] == "analysed" for f in findings)
    return labels["analysed_note"] if analysed else labels["static_note"]


def render_markdown(doc, lang):
    t = LABELS[lang]
    meta, findings = doc["meta"], doc.get("findings", [])
    by_sev, excluded = counts(findings)
    method = review_method(meta, findings, t)
    lines = [f"# {t['title']}: {markdown_text(meta.get('project', ''))}", ""]
    lines.append(" / ".join(f"{s} {by_sev[s]}" for s in SEVERITIES)
                 + f" · {t['excluded']} {excluded} · "
                 + markdown_text(method))
    lines += ["", f"**{t['verdict_counts']}:** {verdict_summary(findings)}", "", f"_{t['disclaimer']}_"]
    lines += ["", f"## {t['scope']}", "", "| | |", "|---|---|",
              markdown_row((t['project'], meta.get('project', ''))),
              markdown_row((t['scope_row'], meta.get('scope', ''))),
              markdown_row((t['revision'], revision(meta))),
              *(markdown_row(row) for row in axis_rows(meta, t)),
              markdown_row((t['review_method'], method)),
              markdown_row((t['date'], f"{meta.get('date', '')} / {meta.get('assessor', '')}")), ""]
    severity_rows, confidence_rows, closing = legend(meta, t)
    lines += [f"## {t['legend']['title']}", ""]
    for key, rows in (("severity", severity_rows), ("confidence", confidence_rows)):
        lines += [f"**{t['legend'][key]}**", ""]
        lines += [f"- **{level}:** {markdown_text(text)}" for level, text in rows]
        lines.append("")
    for line in closing:
        lines += [markdown_text(line), ""]
    lines += [f"## {t['findings']}", ""]
    if not findings:
        lines += [t["none"], ""]
    for f in findings:
        v = f["validation"]
        note = f" ({t['excluded']})" if is_excluded(f) else ""
        lines.append(f"### {f['id']} [{f['severity']}][{f['confidence']}] "
                     f"{markdown_text(f['title'])}{note}")
        lines.append("")
        for key, value in finding_fields(f, t):
            lines.append(f"- **{t[key]}:** {markdown_text(value)}")
        lines.append(f"- **{t['verdict']}:** {v['verdict']} · **{t['method']}:** {v['method']}")
        if shown(v.get("evidence", "")):
            lines.append(f"- **{t['evidence']}:** {markdown_text(v['evidence'])}")
        if "analysis" in f:
            a = f["analysis"]
            lines.append(f"- **{t['analysis']}:** {markdown_text(a['result'])} "
                         f"({markdown_text(a['tool'])}: {markdown_code(a['command'])})")
        lines.append(f"- **{t['status']}:** {term(t, f.get('status', 'Open'))}")
        for ref in f.get("references", []):
            lines.append(f"- **{t['references']}:** {markdown_reference(ref)}")
        lines.append("")
    # An empty ledger is shown as such, never left out silently.
    lines += [f"## {t['commitments']}", ""]
    if not doc.get("commitments"):
        lines += [t["none"], ""]
    else:
        lines += [markdown_row(t["commitment_columns"]), "|---|---|---|---|---|---|"]
        citing = commitment_citations(doc)
        for r in doc["commitments"]:
            statement, status = commitment_text(r, t)
            cells = (r["id"], statement, r.get("family", ""), r["source"], status,
                     ", ".join(citing.get(r["id"], [])))
            lines.append(markdown_row(cells))
        lines.append("")
    # Shown only when the record carries a data map; older records render as before.
    if doc.get("data_map"):
        columns = t["data_map_columns"]
        lines += [f"## {t['data_map']}", "", markdown_text(data_map_summary(doc, t)), "",
                  markdown_row(columns), "|" + "---|" * len(columns)]
        lines += [markdown_row(row) for row in data_map_rows(doc, t)]
        lines.append("")
        rows = recipient_rows(doc, t)
        if rows:
            lines += [f"### {t['recipients']}", "", markdown_row(t["recipient_columns"]),
                      "|---|---|"]
            lines += [markdown_row(row) for row in rows]
            lines.append("")
    lines += [f"## {t['perspectives']}", "", markdown_row(t["perspective_columns"]), "|---|---|---|"]
    for row in perspective_rows(doc, t):
        lines.append(markdown_row(row))
    lines.append("")
    for key in ("checked_ok", "limitations", "decisions", "next_steps"):
        lines += [f"## {t[key]}", ""]
        lines += [f"- {markdown_item(item)}" for item in doc.get(key, [])] or [t["none"]]
        lines.append("")
    return "\n".join(lines)


# Rules for privacy-scan record types only, after the shared dashboard
# stylesheet (scan_report_kit/assets/dashboard.css, docs: scan-report-kit).
DASHBOARD_CSS = """
.filter-buttons{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 12px}
button[aria-pressed="true"]{border-color:var(--text);background:var(--soft)}
.register{border-top:1.5px solid var(--text);border-bottom:1.5px solid var(--text)}
.register [data-empty]{color:var(--muted);padding:14px 4px;margin:0}
details[data-sev]{border-top:1px solid var(--line);padding:12px 4px 12px 16px;border-left:.6pt solid var(--line)}
details[data-sev]:first-of-type{border-top:0}
details[data-sev="High"]{border-left:2.4pt solid var(--high)}
details[data-sev="Medium"]{border-left:1.2pt solid var(--medium)}
details[data-sev="Low"]{border-left:.6pt solid var(--low)}
details[data-sev="Info"]{border-left:.6pt solid var(--info)}
details[data-sev="excluded"]{border-left:.6pt dashed var(--muted)}
details[data-sev] summary{font-family:var(--serif)}
details[data-sev] summary .badge{margin-right:8px}
details[data-sev] summary .muted{font-family:var(--sans);font-size:12px;font-weight:400}
details[data-sev] dl{display:grid;grid-template-columns:150px minmax(0,1fr);gap:8px 18px;margin:14px 0 4px}
details[data-sev] dt{font-family:var(--sans);font-size:12px;color:var(--muted)}
dd{margin:0;overflow-wrap:anywhere;white-space:pre-line}
details[data-sev] summary,.hero h1,.hero .meta,.footer{white-space:pre-line}
li{white-space:pre-line}
td{white-space:pre-line}
details[data-sev] .snippet{margin:6px 0 0;white-space:pre-wrap;overflow-wrap:anywhere}
.commitments th:nth-child(1){width:8%}
.commitments th:nth-child(2){width:30%}
.commitments th:nth-child(3){width:10%}
.commitments th:nth-child(4){width:20%}
.commitments th:nth-child(5){width:20%}
.commitments th:nth-child(6){width:12%}
.coverage-table th:nth-child(1){width:42%}
.coverage-table th:nth-child(2){width:14%}
.coverage-table th:nth-child(3){width:44%}
.lists .panel ul{white-space:normal}
@media(max-width:850px){details[data-sev] dl{grid-template-columns:minmax(0,1fr);gap:3px}details[data-sev] dd{margin-bottom:10px}}
/* Narrow screens: each ledger row becomes a labelled card, as the kit does for
   its register, so the status column is never scrolled out of view. Print keeps
   the tables. */
@media screen and (max-width:850px){
table.ledger,table.ledger>tbody,table.ledger>tbody>tr,table.ledger>tbody>tr>td{display:block}
table.ledger>thead{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap}
table.ledger>tbody>tr{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px 14px;padding:12px 4px;border-bottom:1px solid var(--line)}
table.ledger>tbody>tr:last-child{border-bottom:0}
table.ledger>tbody>tr>td{border:0;padding:0;overflow-wrap:anywhere}
table.ledger>tbody>tr>td:before{content:attr(data-label);display:block;font-family:var(--sans);font-size:11px;color:var(--muted);margin-bottom:2px}
table.ledger>tbody>tr>td:empty{display:none}
.commitments td:nth-child(1){grid-area:1/1}
.commitments td:nth-child(5){grid-area:1/2}
.commitments td:nth-child(2){grid-column:1/-1}
.commitments td:nth-child(6){grid-column:1/-1}
table.coverage-table>tbody>tr{grid-template-columns:max-content minmax(0,1fr)}
.coverage-table td:nth-child(1){grid-column:1/-1}}
.filter-buttons .n{font-variant-numeric:tabular-nums;color:var(--muted);margin-left:4px}
.finding-search{font:inherit;font-family:var(--sans);font-size:14px;flex:1 1 14em;max-width:26em;min-width:0;
background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:7px;padding:8px 12px}
.finding-search:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
.register-count{margin:0 0 8px}
/* A ledger status that needs action reads apart from the ones that hold; the
   word itself still carries the meaning. */
.status[data-status="violated"]{color:var(--high);font-weight:700}
.status[data-status="not checked"],.status[data-status="partly read"]{color:var(--medium)}
/* Data map: sensitive elements carry a high-severity rule; the word "sensitive"
   in the element cell still carries the meaning. */
.datamap tr[data-sensitive] td:first-child{box-shadow:inset 2.4pt 0 0 var(--high)}
.datamap th:nth-child(1){width:6%}
.datamap th:nth-child(2){width:14%}
.recipients th:nth-child(1){width:30%}
#data-map h3{margin:24px 0 8px}
@media screen and (max-width:850px){
.datamap td:nth-child(1){grid-area:1/1}
.datamap td:nth-child(2){grid-area:1/2}
.datamap td:nth-child(6),.datamap td:nth-child(7),.datamap td:nth-child(5){grid-column:1/-1}
.recipients td:nth-child(1),.recipients td:nth-child(2){grid-column:1/-1}}
"""
CSS = kit_style.dashboard_css() + DASHBOARD_CSS

# The theme choice is a per-viewer convenience shared with the other *-scan
# dashboards (scan-report-kit's key and behaviour). Storage may be absent or
# throw; the page then follows the system theme.
THEME_KEY = "scan-report-kit.theme"
JS = """
try{const t=localStorage.getItem('%s');if(t==='light'||t==='dark')document.documentElement.dataset.theme=t}catch(e){}
document.getElementById('theme').addEventListener('click',()=>{const root=document.documentElement,
dark=root.dataset.theme?root.dataset.theme==='dark':window.matchMedia('(prefers-color-scheme: dark)').matches;
root.dataset.theme=dark?'light':'dark';try{localStorage.setItem('%s',root.dataset.theme)}catch(e){}});
const count=document.getElementById('register-count'),all=document.querySelectorAll('details[data-sev]'),
search=document.getElementById('finding-search');let sev='all',q='';
const apply=()=>{let shown=0;all.forEach(d=>{d.hidden=(sev!=='all'&&d.dataset.sev!==sev)||
(q!==''&&!d.textContent.toLowerCase().includes(q));shown+=!d.hidden});
const empty=document.querySelector('[data-empty]');if(empty)empty.hidden=shown>0;
if(count)count.textContent=count.dataset.template.replace('{shown}',shown).replace('{total}',all.length);};
document.querySelectorAll('[data-filter]').forEach(b=>b.addEventListener('click',()=>{
sev=b.dataset.filter;document.querySelectorAll('[data-filter]').forEach(x=>x.setAttribute('aria-pressed',x===b));apply();}));
if(search)search.addEventListener('input',()=>{q=search.value.trim().toLowerCase();apply();});
""" % (THEME_KEY, THEME_KEY)


def _csp_source(code):
    return "'sha256-" + b64encode(sha256(code.encode("utf-8")).digest()).decode("ascii") + "'"


# The dashboard needs nothing outside itself: no fetches, images, frames, fonts
# or forms. Hashes pin the page's own style and scripts ('unsafe-inline' is
# ignored where hashes are understood), so markup that ever slipped past the
# escaping could neither run nor send what the page shows anywhere.
CSP = (f"default-src 'none'; style-src {_csp_source(CSS)} 'unsafe-inline'; "
       f"script-src {_csp_source(JS)} 'unsafe-inline'; "
       "base-uri 'none'; form-action 'none'")


def html_head(columns):
    return "<thead><tr>" + "".join(f"<th>{escape(c)}</th>" for c in columns) + "</tr></thead>"


# Short identifiers (C-01) never break at their hyphen.
NOWRAP = " class='nowrap'"


def html_row(columns, cells, nowrap=(), status=None):
    """A ledger row; each cell names its column for the narrow-screen card layout.

    `status` is (column index, recorded status, shown term, text after it): that
    cell marks the term with the recorded value, so states that need action can
    stand out, and keeps the rest of its text.
    """
    html = [escape(as_text(cell)) for cell in cells]
    if status is not None:
        index, value, label, rest = status
        html[index] = (f"<span class='status' data-status='{escape(value)}'>"
                       f"{escape(label)}</span>{escape(as_text(rest))}")
    return "<tr>" + "".join(
        f"<td{NOWRAP if i in nowrap else ''} data-label='{escape(column)}'>{cell}</td>"
        for i, (column, cell) in enumerate(zip(columns, html))) + "</tr>"


def render_html(doc, lang):
    t = LABELS[lang]
    meta, findings = doc["meta"], doc.get("findings", [])
    by_sev, excluded = counts(findings)
    method = review_method(meta, findings, t)
    e = lambda v: escape(as_text(v))  # noqa: E731
    byline = " · ".join(as_text(meta.get(k, "")) for k in ("date", "assessor")
                        if shown(meta.get(k, "")))
    out = [f"<!doctype html><html lang='{lang}'><head><meta charset='utf-8'>",
           f"<meta http-equiv='Content-Security-Policy' content=\"{CSP}\">",
           "<meta name='viewport' content='width=device-width,initial-scale=1'>",
           # A document title cannot show a break, so its lines are joined visibly.
           f"<title>{e(t['title'])}: {e(as_text(meta.get('project', '')).replace(chr(10), ' · '))}</title>"
           f"<style>{CSS}</style></head><body><main>",
           f"<header class='masthead'><span class='brand'>{e(t['brand'])}</span>"
           f"<div class='tools'><button id='theme' type='button'>{e(t['theme'])}</button></div></header>",
           f"<div class='hero'><div><div class='eyebrow'>{e(t['title'])}</div>"
           f"<h1>{e(meta.get('project', ''))}</h1><div class='meta'>{e(byline)}</div></div>"
           f"<div class='hero-aside'>{e(t['disclaimer'])}</div></div>",
           "<div class='cards'>"]
    for s in SEVERITIES:
        out.append(f"<div class='card'><span class='l'><span class='badge {s}'>{s}</span></span>"
                   f"<div class='n'>{by_sev[s]}</div></div>")
    out.append(f"<div class='card'><span class='l'>{e(t['excluded'])}</span>"
               f"<div class='n'>{excluded}</div></div></div>")
    out.append(f"<div class='summary-banner'><p><strong>{e(t['verdict_counts'])}:</strong> "
               f"{e(verdict_summary(findings))}</p></div>")
    scope_rows = [(t['project'], meta.get('project', '')),
                  (t['scope_row'], meta.get('scope', '')),
                  (t['revision'], revision(meta)),
                  *axis_rows(meta, t),
                  (t['review_method'], method),
                  (t['date'], f"{meta.get('date', '')} / {meta.get('assessor', '')}")]
    out.append(f"<section class='panel'><h2>{e(t['scope'])}</h2><dl class='scope-meta'>"
               + "".join(f"<dt>{e(k)}</dt><dd>{e(val)}</dd>" for k, val in scope_rows)
               + "</dl></section>")
    severity_rows, confidence_rows, closing = legend(meta, t)
    out.append(f"<section class='panel' id='levels'><h2>{e(t['legend']['title'])}</h2>"
               f"<h3>{e(t['legend']['severity'])}</h3><dl class='scope-meta'>"
               + "".join(f"<dt><span class='badge {s}'>{s}</span></dt><dd>{e(text)}</dd>"
                         for s, text in severity_rows)
               + f"</dl><h3>{e(t['legend']['confidence'])}</h3><dl class='scope-meta'>"
               + "".join(f"<dt>{e(c)}</dt><dd>{e(text)}</dd>" for c, text in confidence_rows)
               + "</dl>" + "".join(f"<p class='muted'>{e(line)}</p>" for line in closing)
               + "</section>")

    def filter_button(key, label, n, pressed=False):
        # The count tells what a filter will show before it is pressed.
        return (f"<button type='button' data-filter='{key}' aria-pressed='{str(pressed).lower()}'>"
                f"{e(label)} <span class='n'>{n}</span></button>")

    total = len(findings)
    out.append(f"<section id='findings'><div class='section-head'><div><h2>{e(t['findings'])}</h2>"
               f"</div></div><div class='filter-buttons' role='group' aria-label='{e(t['filter'])}'>"
               + filter_button("all", t["all"], total, pressed=True) + " "
               + " ".join(filter_button(s, s, by_sev[s]) for s in SEVERITIES)
               + (" " + filter_button("excluded", t["excluded"], excluded) if excluded else "")
               # Text search narrows the severity filter's result (a field, path, ID or C-01).
               + (f" <input type='search' id='finding-search' class='finding-search' "
                  f"aria-label='{e(t['search'])}' placeholder='{e(t['search_hint'])}' "
                  "autocomplete='off' spellcheck='false'>" if findings else "")
               + "</div>"
               # Announced after each filter change (a status message, WCAG 4.1.3).
               + f"<p class='register-count muted' id='register-count' role='status' "
               f"data-template='{e(t['showing'])}'{'' if findings else ' hidden'}>"
               + e(t["showing"].replace("{shown}", str(total)).replace("{total}", str(total)))
               + "</p><div class='register'>")
    # Shown when there are no findings, and by the filter when none match.
    out.append(f"<p data-empty{'' if not findings else ' hidden'}>{e(t['none'])}</p>")
    for f in findings:
        v = f["validation"]
        rows = [(t[k], value) for k, value in finding_fields(f, t)]
        rows.append((t["verdict"], f"{v['verdict']} ({v['method']})"))
        if shown(v.get("evidence", "")):
            rows.append((t["evidence"], v["evidence"]))
        analysis_html = ""
        if "analysis" in f:
            a = f["analysis"]
            analysis_html = (f"<dt>{e(t['analysis'])}</dt><dd>{e(a['result'])} — {e(a['tool'])}:"
                             f"<pre class='snippet'><code>{e(a['command'])}</code></pre></dd>")
        excluded_finding = is_excluded(f)
        # Excluded findings are not counted under their severity, so they are
        # filtered separately and labelled in the summary as well.
        out.append(f"<details data-sev='{'excluded' if excluded_finding else f['severity']}'>"
                   f"<summary><span class='badge {f['severity']}'>"
                   f"{f['severity']}</span> {e(f['id'])} {e(f['title'])} "
                   f"· {e(v['verdict'])}"
                   + (f" ({e(t['excluded'])})" if excluded_finding else "")
                   + f" <span class='muted'>· {e(f['confidence'])} · "
                   f"{e(perspective_name(t, f['category']))}</span></summary><dl>"
                   + "".join(f"<dt>{e(k)}</dt><dd>{e(val)}</dd>" for k, val in rows)
                   + analysis_html
                   + f"<dt>{e(t['status'])}</dt><dd>{e(term(t, f.get('status', 'Open')))}</dd>"
                   + "".join(f"<dt>{e(t['references'])}</dt><dd>{html_reference(ref)}</dd>"
                             for ref in f.get("references", []))
                   + "</dl></details>")
    out.append("</div></section>")
    if not doc.get("commitments"):
        out.append(f"<section><div class='section-head'><div><h2>{e(t['commitments'])}</h2></div></div>"
                   f"<p class='muted'>{e(t['none'])}</p></section>")
    else:
        out.append(f"<section><div class='section-head'><div><h2>{e(t['commitments'])}</h2></div></div>"
                   f"<div class='tablewrap'><table class='ledger commitments'>"
                   f"{html_head(t['commitment_columns'])}")
        citing = commitment_citations(doc)
        for r in doc["commitments"]:
            statement, status = commitment_text(r, t)
            # The findings that break a commitment, so the ledger leads to them.
            cells = (r["id"], statement, r.get("family", ""), r["source"], status,
                     ", ".join(citing.get(r["id"], [])))
            label = term(t, r["status"])  # commitment_text's status starts with it
            out.append(html_row(t["commitment_columns"], cells, nowrap=(0,),
                                status=(4, r["status"], label, status[len(label):])))
        out.append("</table></div></section>")
    if doc.get("data_map"):
        out.append(f"<section id='data-map'><div class='section-head'><div><h2>{e(t['data_map'])}</h2>"
                   f"<p class='muted'>{e(data_map_summary(doc, t))}</p></div></div>"
                   f"<div class='tablewrap'><table class='ledger datamap'>"
                   f"{html_head(t['data_map_columns'])}")
        for record, row in zip(doc["data_map"], data_map_rows(doc, t)):
            html = html_row(t["data_map_columns"], row, nowrap=(0, 8))
            out.append(html.replace("<tr>", "<tr data-sensitive>", 1) if record["sensitive"] else html)
        out.append("</table></div>")
        rows = recipient_rows(doc, t)
        if rows:
            out.append(f"<h3>{e(t['recipients'])}</h3><div class='tablewrap'>"
                       f"<table class='ledger recipients'>{html_head(t['recipient_columns'])}"
                       + "".join(html_row(t["recipient_columns"], row) for row in rows)
                       + "</table></div>")
        out.append("</section>")
    out.append(f"<section><div class='section-head'><div><h2>{e(t['perspectives'])}</h2></div></div>"
               f"<div class='tablewrap'><table class='ledger coverage-table'>"
               f"{html_head(t['perspective_columns'])}")
    recorded = {p["name"]: p["status"] for p in doc.get("perspectives", [])}
    for name, row in zip(PERSPECTIVES, perspective_rows(doc, t)):
        status = recorded.get(name)
        out.append(html_row(t["perspective_columns"], row,
                            status=(1, status, row[1], "") if status else None))
    out.append("</table></div></section><div class='lists'>")
    for key in ("checked_ok", "limitations", "decisions", "next_steps"):
        items = doc.get(key, [])
        out.append(f"<section class='panel'><h2>{e(t[key])}</h2>"
                   + ("<ul>" + "".join(f"<li>{e(i)}</li>" for i in items) + "</ul>" if items
                      else f"<p class='muted'>{e(t['none'])}</p>")
                   + "</section>")
    out.append(f"</div><footer class='footer'>{e(t['title'])}: {e(meta.get('project', ''))}"
               f" · {e(t['revision'])} {e(revision(meta))}</footer>")
    out.append(f"</main><script>{JS}</script></body></html>")
    return "".join(out)


def main(argv=None):
    prepare_cli()
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("findings")
    parser.add_argument("--out", required=True)
    parser.add_argument("--lang", choices=("ja", "en"))
    args = parser.parse_args(argv)
    if not args.out.strip():
        # A blank --out (an unset shell variable) would write into the working
        # directory, which may be the audited repository.
        parser.error("--out must name the output directory")
    try:
        doc = read_json(args.findings)
        validate(doc, complete=True)
    except SchemaError as exc:
        print(f"schema: {exc}", file=sys.stderr)
        return 2
    lang = args.lang or doc["meta"]["lang"]
    # Finish both renderers before creating or replacing either output.
    markdown = render_markdown(doc, lang)
    html = render_html(doc, lang)
    out = Path(args.out)
    try:
        out.mkdir(parents=True, exist_ok=True)
        write_utf8_files({out / "report.md": markdown, out / "dashboard.html": html},
                         protected_paths=(args.findings,))
    except (OSError, UnicodeError) as exc:
        print(f"write failed: could not save reports ({type(exc).__name__})", file=sys.stderr)
        return 1
    print(f"wrote {out / 'dashboard.html'} and {out / 'report.md'}")
    # Rendering a draft is allowed; say now what `findings.py check` will refuse.
    for problem in record_problems(doc):
        print(f"warning: findings.py check will refuse: {problem}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
