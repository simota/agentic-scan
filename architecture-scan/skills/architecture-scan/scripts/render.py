#!/usr/bin/env python3
"""Render findings.json into dashboard.html and report.md.

    python3 render.py FINDINGS --out DIR [--lang ja|en]

Both outputs are derived from the one record; neither adds facts of its own.
`dashboard.html` is self-contained and works offline. `report.md` follows the
findings-report shape in `reference/report.md`.

Exit codes: 0 written, 1 an output could not be written (render again before
`findings.py check`), 2 the record cannot be read or does not match the schema
(the file or field is named on stderr), or the command line is wrong.
"""
import argparse
import base64
import hashlib
import json
from html import escape
from pathlib import Path
import re
import sys
import unicodedata

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True  # leave no __pycache__ beside the skill
from findings import (CONFIDENCES, EXCLUDED, PERSPECTIVES, SEVERITIES, STATUSES, VERDICTS,  # noqa: E402
                      SchemaError, _atomic_write_all, as_locations, read_json, safe_output, validate)

URL_SCHEME = re.compile(r"https?://", re.IGNORECASE)
SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")


def is_web_url(url):
    return (bool(URL_SCHEME.match(url)) and not re.search(r"[\x00-\x20\x7f]", url)
            and not BIDI_CONTROLS.search(url))


def is_safe_link(url):
    """A web URL or a scheme-less relative path; never javascript:, data: and the like.

    Browsers drop tabs, newlines and leading control characters from a URL, so
    any control character could hide a scheme: such a URL is never a link.
    """
    # A bidi control would reorder the destination wherever it is shown or
    # copied, though its label makes it visible: such a URL is never a link.
    if re.search(r"[\x00-\x1f\x7f]", url) or BIDI_CONTROLS.search(url):
        return False
    stripped = url.lstrip(" ")
    if len(stripped) > 1 and set(stripped[:2]) <= {"/", "\\"}:
        return False  # protocol-relative or UNC: another host, not a relative path
    return is_web_url(url) or not SCHEME.match(stripped)


LABELS = {
    "en": {
        "title": "Architecture assessment", "scope": "Scope and method",
        "findings": "Findings", "rules": "Design rules", "perspectives": "Perspective coverage",
        "checked_ok": "Checked and sound", "limitations": "What could not be checked",
        "decisions": "Decisions for a human", "next_steps": "Next steps", "excluded": "Excluded",
        "all": "All", "none": "None.",
        "location": "location", "scenario": "scenario", "blast_radius": "blast radius",
        "trace": "trace", "contrast": "contrast", "impact": "what happens", "rule": "rule",
        "fix": "fix direction", "guard": "fitness function", "verdict": "recorded verdict",
        "verdicts": "Verdict counts",
        "method": "verification", "evidence": "evidence", "analysis": "analysis",
        "references": "references", "status": "status", "reason": "Reason",
        "category": "perspective", "id": "ID", "statement": "Rule", "source": "Source",
        "rule_status": "Status", "perspective": "Perspective", "note": "Note",
        "not_recorded": "not recorded", "inferred": "inferred, to confirm",
        "baseline": "baseline",
        "static_note": "Static review; no code was changed or executed beyond read-only analysis.",
        "analysed_note": "Static review plus read-only tool analysis (dependency graph, history).",
        "project": "System", "scope_row": "Scope", "revision": "Revision", "date": "Date / assessor",
    },
    "ja": {
        "title": "アーキテクチャ診断", "scope": "対象と方法",
        "findings": "検出事項", "rules": "設計ルール", "perspectives": "観点のカバレッジ",
        "checked_ok": "確認して問題なかった項目", "limitations": "確認できなかったこと",
        "decisions": "人が判断すべき事項", "next_steps": "次の作業", "excluded": "除外",
        "all": "すべて", "none": "なし。",
        "location": "場所", "scenario": "シナリオ", "blast_radius": "影響範囲",
        "trace": "追跡", "contrast": "対照", "impact": "何が起きるか", "rule": "ルール",
        "fix": "修正方針", "guard": "適合性チェック", "verdict": "検証判定",
        "verdicts": "検証判定別件数",
        "method": "検証方法", "evidence": "根拠", "analysis": "解析",
        "references": "参考", "status": "ステータス", "reason": "理由",
        "category": "観点", "id": "ID", "statement": "ルール", "source": "出典",
        "rule_status": "状態", "perspective": "観点", "note": "メモ",
        "not_recorded": "未記録", "inferred": "推定・要確認", "baseline": "ベースライン",
        "static_note": "静的レビューのみ。読み取り専用の解析以外にコードの変更や実行はしていない。",
        "analysed_note": "静的レビューに加え、読み取り専用のツール解析（依存グラフ、変更履歴）を実施。",
        "project": "システム", "scope_row": "範囲", "revision": "リビジョン", "date": "診断日 / 診断者",
    },
}
FIELDS = ("location", "scenario", "blast_radius", "trace", "contrast", "impact", "rule",
          "fix", "guard")


def counts(findings):
    active = [f for f in findings if f["validation"]["verdict"] not in EXCLUDED]
    return {s: sum(f["severity"] == s for f in active) for s in SEVERITIES}, len(findings) - len(active)


def verdict_counts(findings):
    return {v: sum(f["validation"]["verdict"] == v for f in findings) for v in VERDICTS}


# Bidirectional controls (U+202A-202E, U+2066-2069) reorder the text after them,
# so a recorded value could display reversed or hide its own end (Trojan Source).
# They are shown as visible code points instead.
BIDI_CONTROLS = re.compile("[\u202a-\u202e\u2066-\u2069]")


def as_text(value):
    text = ", ".join(value) if isinstance(value, list) else str(value)
    return BIDI_CONTROLS.sub(lambda m: f"[U+{ord(m[0]):04X}]", text)


def review_method(doc, lang):
    """Keep the recorded scope of analysis, including runs with no findings."""
    if doc["meta"].get("method", "").strip():
        return doc["meta"]["method"]
    analysed = any(f["validation"]["method"] == "analysed" or "analysis" in f
                   for f in doc.get("findings", []))
    return LABELS[lang]["analysed_note" if analysed else "static_note"]


# Inside `<code>` GFM still parses inline syntax, so these are encoded; the rest
# of a path or command (`/`, `.`, `:`, `-`) stays readable in the raw file.
CODE_LITERAL = {ord(char): f"&#{ord(char)};" for char in "\\`*_~[]<&|!$\t"}


def markdown_code(value):
    """Keep a literal command or code span intact, even with backticks."""
    value = as_text(value).replace("\r\n", "\n").replace("\r", "\n")
    literal = disarm_autolinks(value.translate(CODE_LITERAL))
    # Runs of spaces and edge spaces would collapse or be trimmed.
    literal = re.sub(r"^ +| {2,}| +$", lambda m: "&#32;" * len(m[0]), literal)
    literal = literal.replace("\n", "<br>")
    return f"<code>{literal}</code>"


# Backslashes are literal (paths such as `docs\\adr`), so the punctuation after
# one loses its escape and is encoded instead; `&<>` are already entities.
AFTER_BACKSLASH = re.compile(r"(?<=\\)[!-%'-/:;=>?@^_{-~]")
# What GFM turns into a link without brackets: a scheme's colon, `www.`, and
# the `@` of an e-mail address. Encoding the last character disarms each.
# No `\b`: GFM also links a scheme or `www.` right after a word character
# (`_https://x`, `参照https://x`).
AUTOLINK = re.compile(r"(?i)(?:https?|ftp|mailto|xmpp):|www\.")


# An `@` is disarmed unless what precedes it cannot end an e-mail local part
# in any renderer: a blank, an opening bracket or quote, `,` or `:` (as in
# `@scope/pkg`, `(@Version`), or punctuation outside ASCII (`。@Transactional`,
# `（@Version`). Everything else is disarmed: letters and digits in any script
# (pandoc reads them all), a combining mark (pandoc composes it into the letter
# before), the `;` that ends an entity this renderer wrote (`a&#95;@x.com`,
# decoded back into the local part before cmark-gfm autolinks), and the rest of
# ASCII punctuation, which other autolinkers accept (`a=@x.com`).
EMAIL_AT = re.compile(r"(?<=(.))@", re.DOTALL)
NOT_LOCAL_PART = set(" \t\r\n([{'\"`,:")


def _disarm_at(match):
    before = match[1]
    if before in NOT_LOCAL_PART or before.isspace() or (
            ord(before) > 127 and unicodedata.category(before)[0] in "PSZ"):
        return "@"
    return "&#64;<!-- -->"


def disarm_autolinks(text):
    """Encode one character of each autolink trigger.

    cmark-gfm finds e-mail addresses after entities are decoded, so an `@` with
    a local part before it (`bob@example.com`) also gets an empty comment,
    which no autolinker reads through. An `@` that starts a word (`@scope/pkg`,
    `@decorator`) has no local part, cannot be an address, and stays readable.
    """
    text = AUTOLINK.sub(lambda m: m[0][:-1] + f"&#{ord(m[0][-1])};", text)
    return EMAIL_AT.sub(_disarm_at, text)
# Outside code spans these stay literal: a backslash, a stray backtick, the
# brackets of a link or image (whose target could be any scheme), a cell pipe.
LITERAL = {ord("\\"): "&#92;", ord("`"): "&#96;", ord("["): "&#91;", ord("]"): "&#93;",
           ord("|"): "&#124;", ord("$"): "&#36;"}  # `$` opens math on GitHub and in pandoc


def markdown_inline(value):
    """Keep recorded text in one GFM block, keeping emphasis and code spans.

    Links and images are shown as literal text, and backslashes as written, so
    no recorded text turns into a link or loses a delimiter it escaped.
    """
    value = as_text(value).replace("\r\n", "\n").replace("\r", "\n")

    def text(part):
        part = re.sub(r"(\\+)`", lambda m: m[1][:-1] + "&#96;" if len(m[1]) % 2 else m[0],
                      # `>` stays readable (`a -> b`): without `<` it opens
                      # no tag, and block_safe stops it quoting a list item.
                      escape(part, quote=False).replace("&gt;", ">"))
        part = AFTER_BACKSLASH.sub(lambda m: f"&#{ord(m[0])};", part)
        return disarm_autolinks(part.translate(LITERAL)).replace("\n", "<br>")

    parts, end = [], 0
    # An odd backslash prefix escapes the opening backtick; delimiter lengths match.
    spans = r"(?<![\\`])((?:\\\\)*)(`+)(?!`)(.+?)(?<!`)\2(?!`)"
    for match in re.finditer(spans, value, re.DOTALL):
        parts.append(text(value[end:match.start()] + match[1]))
        code = match[3].replace("\n", " ")
        if code.startswith(" ") and code.endswith(" ") and code.strip(" "):
            code = code[1:-1]  # CommonMark code spans trim one surrounding space.
        parts.append(markdown_code(code))
        end = match.end()
    parts.append(text(value[end:]))
    return "".join(parts)


# Leading whitespace (indented code) and the markers that open a block when
# they start a line: a heading, a list bullet (`*` or `+` before a blank), a
# rule (three of `*` or `_`), a setext line, a fence, a link definition or task
# box, an ordered item. A leading `-` is always encoded: with the item's own
# `- ` bullet, even `--` makes a rule. `*em*` or `~~struck~~` at the start is inline, not
# a block, so it is left alone.
BLOCK_START = re.compile(
    r"([ \t]*)(#|=|>|\[|-|[*+_](?=[ \t]|$)|([*_])(?=(?:[ \t]*\3){2,}[ \t]*$)|~~~|```"
    r"|[0-9]{1,9}[.)])?")


def block_safe(rendered):
    """Keep recorded text from opening a Markdown block where it starts a line."""
    match = BLOCK_START.match(rendered)
    indent, marker = match[1], match[2] or ""
    if marker[:1].isdigit():
        # `12.` stops being an ordered item once its delimiter is encoded.
        marker = marker[:-1] + f"&#{ord(marker[-1])};"
    elif marker:
        marker = f"&#{ord(marker[0])};" + marker[1:]
    return "".join(f"&#{ord(char)};" for char in indent) + marker + rendered[match.end():]


def heading_text(value):
    """Inline text that cannot lose a trailing `#` to a closing sequence."""
    # The heading drops trailing blanks, which would expose the `#` again.
    rendered = markdown_inline(value).rstrip(" \t")
    return rendered[:-1] + "&#35;" if rendered.endswith("#") else rendered


def markdown_table_cell(value):
    """Keep pipes and line breaks inside a GFM cell, including in code spans."""
    return markdown_inline(value)


def revision(meta):
    commit = meta.get("commit", "")
    return commit if commit.strip() else "UNKNOWN"


def category(f):
    return f"{f['category']} ({f['step']})" if "step" in f else f["category"]


def perspective_rows(doc, lang):
    """Every perspective in reference order, so both outputs show the same gaps."""
    recorded = {p["name"]: p for p in doc.get("perspectives", [])}
    missing = {"status": "—", "note": LABELS[lang]["not_recorded"]}
    return [(name, recorded.get(name, missing)) for name in PERSPECTIVES]


def rule_id(rule):
    """The ledger ID with its family (reference/rules.md §2), e.g. `R-01 · OWN`."""
    return f"{rule['id']} · {rule['family']}" if rule.get("family") else rule["id"]


# `baseline` or `baseline; shared/db.py:12 …`, not a file such as `baselines/x.md`.
BASELINE_SOURCE = re.compile(r"\s*baseline(?![\w./-])", re.IGNORECASE)


def rule_statement(rule, lang):
    """An inferred rule is a question for the requester (reference/rules.md §1).

    A baseline entry is inferred too, but states a general family rule, not
    this codebase's intent, so it is labelled as such and asks nothing.
    """
    if BASELINE_SOURCE.match(rule["source"]):
        return f"{rule['statement']} ({LABELS[lang]['baseline']})"
    if rule.get("inferred") is True:
        return f"{rule['statement']} ({LABELS[lang]['inferred']})"
    return rule["statement"]


def filled(record, key):
    """A recorded value worth a row: present and not blank."""
    return key in record and bool(as_text(record[key]).strip())


def markdown_reference(ref):
    if not is_safe_link(ref["url"]):
        # Web URLs and relative paths become links; any other scheme stays literal.
        title = ref.get("title")
        code = markdown_code(ref["url"])
        return f"{markdown_inline(title)}: {code}" if title and title != ref["url"] else code
    title = markdown_inline(ref.get("title") or ref["url"])
    title = title.replace("[", "&#91;").replace("]", "&#93;")
    # Angle destinations allow parentheses; entities keep input from ending
    # the destination or escaping its closing delimiter.
    url = (escape(ref["url"], quote=False).replace("\\", "&#92;")
           .replace("\r", "&#13;").replace("\n", "&#10;"))
    return f"[{title}](<{url}>)"


def render_markdown(doc, lang):
    t = LABELS[lang]
    cell = markdown_table_cell
    text = markdown_inline
    meta, findings = doc["meta"], doc.get("findings", [])
    by_sev, excluded = counts(findings)
    by_verdict = verdict_counts(findings)
    lines = [f"# {t['title']}: {heading_text(meta.get('project', ''))}", ""]
    lines.append(" / ".join(f"{s} {by_sev[s]}" for s in SEVERITIES)
                 + f" · {t['excluded']} {excluded} · "
                 + text(review_method(doc, lang)))
    lines += ["", f"{t['verdicts']}: "
              + " / ".join(f"{v} {by_verdict[v]}" for v in VERDICTS)]
    lines += ["", f"## {t['scope']}", "", "| | |", "|---|---|",
              f"| {t['project']} | {cell(meta.get('project', ''))} |",
              f"| {t['scope_row']} | {cell(meta.get('scope', ''))} |",
              f"| {t['revision']} | {cell(revision(meta))} |",
              f"| {t['date']} | {cell(meta.get('date', ''))} / {cell(meta.get('assessor', ''))} |", ""]
    lines += [f"## {t['findings']}", ""]
    if not findings:
        lines += [t["none"], ""]
    for f in findings:
        v = f["validation"]
        lines.append(f"### {f['id']} [{f['severity']}][{f['confidence']}][{v['verdict']}] "
                     f"{heading_text(f['title'])}")
        lines.append("")
        lines.append(f"- **{t['category']}:** {text(category(f))}")
        for key in FIELDS:
            if filled(f, key):
                value = f[key]
                if key == "location":
                    paths = as_locations(value)
                    formatted = ", ".join(markdown_code(path) for path in paths)
                else:
                    formatted = text(value)
                lines.append(f"- **{t[key]}:** {formatted}")
        lines.append(f"- **{t['verdict']}:** {v['verdict']} · **{t['method']}:** {v['method']}")
        if filled(v, "evidence"):
            lines.append(f"- **{t['evidence']}:** {text(v['evidence'])}")
        if "analysis" in f:
            a = f["analysis"]
            lines.append(f"- **{t['analysis']}:** {text(a['result'])} "
                         f"({text(a['tool'])}: {markdown_code(a['command'])})")
        lines.append(f"- **{t['status']}:** {f.get('status', 'Open')}")
        for ref in f.get("references", []):
            lines.append(f"- **{t['references']}:** {markdown_reference(ref)}")
        lines.append("")
    if doc.get("rules"):
        lines += [f"## {t['rules']}", "",
                  f"| {t['id']} | {t['statement']} | {t['source']} | {t['rule_status']} |",
                  "|---|---|---|---|"]
        for r in doc["rules"]:
            status = r["status"]
            if filled(r, "reason"):
                status += f"\n{t['reason']}: {r['reason']}"
            lines.append(f"| {cell(rule_id(r))} | {cell(rule_statement(r, lang))} | "
                         f"{cell(r['source'])} | {cell(status)} |")
        lines.append("")
    lines += [f"## {t['perspectives']}", "",
              f"| {t['perspective']} | {t['rule_status']} | {t['note']} |", "|---|---|---|"]
    for name, p in perspective_rows(doc, lang):
        lines.append(f"| {cell(name)} | {cell(p['status'])} | {cell(p['note'])} |")
    lines.append("")
    for key in ("checked_ok", "limitations", "decisions", "next_steps"):
        lines += [f"## {t[key]}", ""]
        lines += [f"- {block_safe(text(item))}" for item in doc.get(key, [])] or [t["none"]]
        lines.append("")
    return "\n".join(lines)


# The dashboard follows security-scan's layout and visual language: masthead,
# summary, counts, a priority queue, coverage, overview charts and a filterable
# register. Unlike security-scan it is rendered here, not by its script, so it
# reads in full without JavaScript and runs under a hash-only CSP.
DASH = {
    "en": {
        "eyebrow": "ARCHITECTURE REVIEW",
        "report_note": "Static review · read-only · offline dashboard",
        "report_link": "Markdown report", "theme": "Toggle color theme",
        "jump_findings": "Jump to findings",
        "risk_summary": "{n} open High / Medium findings need attention.",
        "risk_summary_one": "1 open High / Medium finding needs attention.",
        "open_summary": "{n} open findings are recorded; none are High or Medium.",
        "open_summary_one": "1 open finding is recorded; it is not High or Medium.",
        "no_open": "No open findings are recorded. This does not establish that the design is sound.",
        "no_findings": "No included findings are recorded. Review the scope and limitations before "
                       "drawing conclusions.",
        "unverified_line": "{n} included findings are not yet Valid (Likely or Unverified).",
        "unverified_line_one": "1 included finding is not yet Valid (Likely or Unverified).",
        "none_unverified_line": "Every included finding has a definitive verdict.",
        "open_hm": "Open High/Medium", "open_count": "Open findings",
        "needs_validation": "Open, needs validation", "closed_count": "Fix recorded / accepted",
        "included": "Included findings", "all_records": "All records",
        "counts_note": "Report-wide totals include Open, Fixed and Accepted. Excluded findings do not "
                       "contribute to these totals.",
        "priority": "Start here",
        "priority_note": "Open findings, ordered by severity, then readiness to fix. Confirm the "
                         "scenario before changing code.",
        "view_all": "View all findings",
        "fix_now": "Plan the fix", "verify_first": "Verify first",
        "fix_now_note": "Valid and Confirmed. Use the recorded fix direction and add the fitness "
                        "function so the rule stays enforced.",
        "verify_first_note": "Confirm the scenario, the blast radius and the rule it breaks; record "
                             "evidence before deciding on a fix.",
        "missing_fix": "Fix direction not recorded. Define it after reviewing the evidence.",
        "more_high": "{n} more open High findings are listed in the findings register.",
        "more_high_one": "1 more open High finding is listed in the findings register.",
        "queue_more": "Showing {shown} of {total} open findings.",
        "coverage_heading": "Scope, coverage and limitations",
        "coverage_note": "Coverage is recorded per perspective below. A perspective marked not "
                         "checked, or not recorded, was not reviewed. Zero findings is not a "
                         "guarantee of a sound design.",
        "limitations_count": "Recorded limitations",
        "limitations_empty": "No limitations were recorded. This is not evidence of complete coverage.",
        "perspective_count": "Perspectives applied: {applied} of {total}",
        "rules_note": "The design rules each finding is judged against, with what was checked.",
        "overview": "Results overview",
        "count_basis": "Severity is the cost if the scenario happens; confidence is how certain the "
                       "path is. The verdict records whether the finding applies.",
        "by_sev": "By severity", "by_conf": "By confidence", "by_cat": "By perspective",
        "by_status": "By status", "by_verdict": "By verdict",
        "excluded_note": "Excluded findings are retained with their justification. They are not "
                         "counted in included totals.",
        "findings_register": "Findings register",
        "findings_note": "Open a finding for its scenario, trace, evidence and fix direction. Totals "
                         "above remain report-wide while filtering.",
        "record_set": "Records", "included_set": "Included (excludes ruled-out findings)",
        "excluded_set": "Excluded only", "severity": "Severity", "confidence": "Confidence",
        "category": "Perspective", "status": "Status", "verdict": "Verdict", "sort": "Order",
        "priority_sort": "Open first, then severity", "severity_sort": "Severity",
        "search": "Search", "reset": "Clear filters", "title_col": "Title",
        "showing": "Showing {shown} of {total} records in this view",
        "no_matches": "No findings match these filters. Clear filters to see more.",
        "copy_llm": "Copy for LLM", "copied": "Copied", "copy_failed": "Copy failed",
        "permalink": "Link to finding", "expand": "Show details", "collapse": "Hide details",
        "method_row": "Method",
        "footer": "Rendered from findings.json; every value is shown as recorded. Inspect this "
                  "dashboard before sharing.",
    },
    "ja": {
        "eyebrow": "ARCHITECTURE REVIEW",
        "report_note": "静的レビュー · 読み取り専用 · オフラインダッシュボード",
        "report_link": "Markdown レポート", "theme": "配色を切り替え",
        "jump_findings": "検出事項一覧へ移動",
        "risk_summary": "未対応の High / Medium が {n} 件あります。",
        "open_summary": "未対応の検出事項は {n} 件です。High / Medium は含まれていません。",
        "no_open": "未対応の検出事項は記録されていません。設計の健全性を保証するものではありません。",
        "no_findings": "集計対象の検出事項はありません。対象範囲と制約を確認してから判断してください。",
        "unverified_line": "集計対象のうち {n} 件は判定が確定していません（Likely または Unverified）。",
        "none_unverified_line": "集計対象の検出事項はすべて判定が確定しています。",
        "open_hm": "未対応の高・中", "open_count": "未対応の検出事項",
        "needs_validation": "未対応・要検証", "closed_count": "修正の申告 / 受容",
        "included": "集計対象の検出事項", "all_records": "すべての記録",
        "counts_note": "全体集計には Open・Fixed・Accepted を含みます。除外した検出事項は含みません。",
        "priority": "まず取り組むこと",
        "priority_note": "未対応の検出事項を重大度順、同じ重大度では修正判断の準備ができた順に表示します。"
                         "シナリオを確認してから修正してください。",
        "view_all": "検出事項一覧を見る",
        "fix_now": "修正を計画", "verify_first": "先に検証する",
        "fix_now_note": "Valid・Confirmed です。記録された修正方針で直し、ルールが守られ続けるよう"
                        "適合性チェックを追加してください。",
        "verify_first_note": "シナリオ・影響範囲・違反するルールを確認し、根拠を記録してから修正要否を"
                             "判断してください。",
        "missing_fix": "修正方針が未記録です。根拠を確認し、修正内容を具体化してください。",
        "more_high": "未対応の High がほかに {n} 件あります（検出事項一覧に記載）。",
        "queue_more": "未対応 {total} 件のうち {shown} 件を表示しています。",
        "coverage_heading": "対象範囲・確認状況・制約",
        "coverage_note": "観点ごとの確認状況を下に示します。not checked や未記録の観点は確認していません。"
                         "検出事項がゼロでも設計の健全性の保証にはなりません。",
        "limitations_count": "記録された制約",
        "limitations_empty": "制約事項が記録されていません。すべて確認済みであることを示すものではありません。",
        "perspective_count": "適用した観点: {total} 件中 {applied} 件",
        "rules_note": "各検出事項の判断基準とした設計ルールと、その確認結果です。",
        "overview": "結果概要",
        "count_basis": "重大度はシナリオが起きた場合の損害、確度は経路の確かさ、検証判定はこの対象に"
                       "検出事項が成立するかを表します。",
        "by_sev": "重大度別", "by_conf": "確度別", "by_cat": "観点別",
        "by_status": "対応状況別", "by_verdict": "検証判定別",
        "excluded_note": "除外した検出事項も、その根拠とともに保持します。集計対象の件数には含めません。",
        "findings_register": "検出事項一覧",
        "findings_note": "検出事項を開くとシナリオ・追跡・根拠・修正方針を確認できます。絞り込んでも上部の"
                         "全体集計は変わりません。",
        "record_set": "表示対象", "included_set": "集計対象（誤検知・対象外を除く）",
        "excluded_set": "除外した検出事項のみ", "severity": "重大度", "confidence": "確度",
        "category": "観点", "status": "状況", "verdict": "検証判定", "sort": "表示順",
        "priority_sort": "未対応を先に、重大度順", "severity_sort": "重大度順",
        "search": "検索", "reset": "絞り込みを解除", "title_col": "件名",
        "showing": "この表示対象 {total} 件中 {shown} 件を表示",
        "no_matches": "条件に一致する検出事項はありません。絞り込みを解除すると、ほかの検出事項を確認できます。",
        "copy_llm": "LLM用にコピー", "copied": "コピーしました", "copy_failed": "コピーできませんでした",
        "permalink": "この検出事項へのリンク", "expand": "詳細を開く", "collapse": "詳細を閉じる",
        "method_row": "方法",
        "footer": "findings.json から生成しています。値はすべて記録どおりに表示しています。共有前に内容を"
                  "確認してください。",
    },
}

CSS = """
:root{color-scheme:light;--bg:#f6f5f1;--panel:#fff;--text:#1b1b1b;--muted:#5a5a5a;--line:#dcd9d2;--soft:#ecebe5;--high:#8a1c1c;--medium:#7a4800;--low:#24476e;--info:#5a5a5a;--accent:#1f3f66;--tint:#efede6;--serif:"Hiragino Mincho ProN","Noto Serif CJK JP","Yu Mincho",Georgia,serif;--sans:system-ui,-apple-system,"Hiragino Sans","Noto Sans CJK JP","Noto Sans JP",sans-serif;--mono:ui-monospace,SFMono-Regular,Menlo,monospace}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--bg:#17171a;--panel:#1f1f23;--text:#ece9e2;--muted:#b3aea4;--line:#3a3936;--soft:#2a2a2e;--high:#f2a19a;--medium:#e8bf7a;--low:#a9c3e6;--info:#b3aea4;--accent:#a9c3e6;--tint:#26252a}}
:root[data-theme="dark"]{color-scheme:dark;--bg:#17171a;--panel:#1f1f23;--text:#ece9e2;--muted:#b3aea4;--line:#3a3936;--soft:#2a2a2e;--high:#f2a19a;--medium:#e8bf7a;--low:#a9c3e6;--info:#b3aea4;--accent:#a9c3e6;--tint:#26252a}
*{box-sizing:border-box}[hidden]{display:none!important}html{scroll-behavior:smooth;scroll-padding-top:20px}
body{margin:0;overflow-wrap:anywhere;background:var(--bg);color:var(--text);font:15px/1.7 var(--serif);font-variant-numeric:lining-nums tabular-nums}
main{max-width:1320px;margin:auto;padding:32px 28px 48px}a{color:var(--accent);text-underline-offset:3px}
button,input,select{font:inherit}:focus-visible{outline:3px solid var(--accent);outline-offset:3px}
h1,summary{overflow-wrap:anywhere}h1,h2,h3{font-family:var(--serif);font-weight:700;letter-spacing:0}
h2{font-size:19px;margin:0}h3{font-size:15px;margin:0 0 6px}
button,input,select,label,th,.badge,.brand,.eyebrow,.tools,.filters,.result-count,.card .l,.card .sub,.verdict,.location,.action-label,.reg-head,.reg-meta,dt,.bar,.small,.toggle-label{font-family:var(--sans)}
button,.button{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:2px;padding:8px 12px;text-decoration:none;cursor:pointer}button:hover,.button:hover{background:var(--soft)}
.skip{position:absolute;left:20px;top:-100px}.skip:focus{top:8px;z-index:2}
.masthead{display:flex;justify-content:space-between;align-items:center;gap:12px;border-bottom:1.5px solid var(--text);padding-bottom:18px;margin-bottom:26px}
.brand{font-size:11px;font-weight:750;letter-spacing:.2em;color:var(--muted)}.tools{display:flex;gap:8px;flex-wrap:wrap}
.hero{display:flex;justify-content:space-between;gap:24px;margin-bottom:20px}.hero>div{min-width:0}
.hero h1{font-size:clamp(26px,3.2vw,36px);line-height:1.25;letter-spacing:-.01em;margin:3px 0 9px}
.eyebrow,.meta,.muted{color:var(--muted)}.eyebrow{font-size:13px}.meta{max-width:820px}
.hero-aside{align-self:flex-end;font-size:12px;text-align:right;max-width:280px}
.summary-banner{border-top:1px solid var(--text);border-bottom:1px solid var(--text);padding:14px 4px;margin-bottom:16px}
.summary-banner strong{display:block;font-size:17px}.summary-banner p{margin:5px 0 0}
.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:28px;margin:16px 0}
.card{border-top:1.5px solid var(--text);padding:12px 2px 6px}
.card .l{font-size:11px;letter-spacing:.08em;color:var(--muted);display:block;margin-bottom:8px}
.card .n{font-size:34px;line-height:1.25;font-weight:400}.card .sub{font-size:12px;color:var(--muted);margin-top:6px}
.card.urgent .n{color:var(--high)}.card.review .n{color:var(--medium)}
.card .pair{display:inline-block;white-space:nowrap;margin-right:18px}.card .u{font-family:var(--sans);font-size:11px;letter-spacing:.06em;color:var(--muted);margin-left:6px}
.report-note,.section-note{font-size:12px;color:var(--muted);margin:8px 0 22px}
.section-head{display:flex;justify-content:space-between;gap:16px;align-items:baseline;margin:26px 0 12px}.section-head p{margin:4px 0 0;color:var(--muted)}
.panel{border-top:1px solid var(--line);padding:18px 0;min-width:0}
.priority-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,330px),1fr));gap:12px 28px}
.priority-item{border-top:2px solid var(--line)}.priority-item.sev-High{border-top-color:var(--high)}.priority-item.sev-Medium{border-top-color:var(--medium)}
.priority-top{display:flex;justify-content:space-between;gap:8px;align-items:center;margin-bottom:10px}
.priority-item h3 a{text-decoration:none;color:var(--text)}.priority-item h3 a:hover{text-decoration:underline}
.priority-item p{margin:8px 0}.priority-item .action{padding-top:10px;border-top:1px solid var(--line)}
.action-label{font-size:12px;font-weight:700;color:var(--accent)}
.badge{display:inline-block;font-size:11px;line-height:1.7;font-weight:750;letter-spacing:.1em;white-space:nowrap}
.High{color:var(--high)}.Medium{color:var(--medium)}.Low{color:var(--low)}.Info{color:var(--info)}
.verdict,.location{font-size:12px;color:var(--muted)}.location{display:block;margin-top:4px}
.coverage{border-left:1px solid var(--text);border-top:0;padding:4px 0 4px 18px;margin:20px 0}
.coverage h2 .small{font-size:13px;font-weight:400;color:var(--muted);margin-left:10px}
.scope-meta{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:5px 16px;margin:16px 0}.scope-meta dt{font-size:12px;color:var(--muted)}.scope-meta dd{margin:0}
.coverage ul,.lists ul,#decisions ul{margin:6px 0;padding-left:20px}
table{border-collapse:collapse;width:100%;border-top:1.5px solid var(--text);border-bottom:1.5px solid var(--text)}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
th{font-size:11px;font-weight:700;letter-spacing:.06em;border-bottom:1px solid var(--text);overflow-wrap:normal}
.tablewrap{overflow-x:auto}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px 28px;margin-top:16px}.grid h3{font-size:13px}
.bar{display:grid;grid-template-columns:minmax(85px,46%) 1fr 26px;gap:8px;align-items:center;margin:7px 0;font-size:12px}
.bar .track{display:block;height:5px;background:var(--soft);overflow:hidden}.bar .fill{display:block;height:100%;width:0;background:var(--text)}
.bar .fill.High{background:var(--high)}.bar .fill.Medium{background:var(--medium)}.bar .fill.Low{background:var(--low)}.bar .fill.Info{background:var(--info)}
.bar .v{text-align:right}
.filters{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}
.filters label{display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--muted)}
.filters select,.filters input{width:100%;min-width:0;background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:2px;padding:9px;font-size:13px}
.filters .search{grid-column:span 2}.filter-bottom{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-top:14px}.result-count{font-size:12px;color:var(--muted);margin:0}
.register{border-top:1.5px solid var(--text);border-bottom:1.5px solid var(--text);margin-top:12px}
.reg-head,.finding>details>summary{display:grid;grid-template-columns:9% 9% 14% 9% 10% minmax(0,1fr) 18%;gap:12px;padding:12px}
.reg-head{font-size:11px;font-weight:700;letter-spacing:.06em;border-bottom:1px solid var(--text)}
.finding{border-bottom:1px solid var(--line)}.finding:last-child{border-bottom:0}
.finding>details>summary{list-style:none;cursor:pointer}.finding>details>summary::-webkit-details-marker{display:none}
.finding>details>summary:hover{background:var(--tint)}.reg-title{font-weight:700;min-width:0}
.reg-meta{font-size:13px}.toggle-label{display:block;font-size:11px;font-weight:400;color:var(--accent);margin-top:4px}
.finding .open-label,.finding details[open] .closed-label{display:none}.finding details[open] .open-label{display:inline}
details.excluded .reg-title>span:first-child{text-decoration:line-through}
.detail{background:var(--tint);padding:18px 24px}
.detail-actions{display:flex;justify-content:space-between;gap:12px;align-items:center}.detail-links{display:flex;gap:12px;align-items:center;flex-wrap:wrap;flex-shrink:0}
.detail dl{display:grid;grid-template-columns:150px minmax(0,1fr);gap:8px 18px;margin:12px 0}
.detail dt{font-size:12px;color:var(--muted)}.detail dd{margin:0;overflow-wrap:anywhere}
.action-guidance{border-left:3px solid var(--accent);padding:8px 12px;margin-top:12px}.action-guidance strong{display:block;font-family:var(--sans);font-size:13px}.action-guidance p{margin:4px 0}
.lists{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,280px),1fr));gap:12px 28px;margin-top:24px}.lists h2{font-size:16px}
.empty{color:var(--muted);padding:20px 12px;margin:0}
.footer{font-size:12px;color:var(--muted);border-top:1.5px solid var(--text);margin-top:32px;padding-top:16px}
code{font:12px/1.5 var(--mono);overflow-wrap:anywhere}
@media(max-width:850px){main{padding:22px 18px}.cards{grid-template-columns:repeat(2,minmax(0,1fr))}.hero{display:block}.hero-aside{text-align:left;max-width:none;margin-top:12px}.filters{grid-template-columns:repeat(2,minmax(0,1fr))}.reg-head{display:none}.finding>details>summary{grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;padding:14px}.finding>details>summary>span:before{content:attr(data-label);display:block;color:var(--muted);font-size:10px;font-family:var(--sans)}.reg-title{grid-column:1/-1;grid-row:1}.reg-cat{grid-column:span 2}.detail{padding:16px}.detail dl{grid-template-columns:minmax(0,1fr);gap:3px}.detail dd{margin-bottom:10px}}
@media(max-width:480px){main{padding:16px 12px}.masthead{align-items:flex-start;flex-direction:column}.tools{width:100%}.tools .button{flex:1}.card .n{font-size:28px}.section-head{display:block}.filters{grid-template-columns:1fr 1fr;gap:10px}.filters label:first-child,.filters .search{grid-column:1/-1}.filter-bottom{align-items:flex-start;flex-direction:column}.scope-meta{grid-template-columns:1fr;gap:2px}.scope-meta dd{margin-bottom:8px}.priority-top{flex-wrap:wrap}.detail-actions{flex-direction:column;align-items:flex-start}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
@media print{body{background:white}.tools,.skip,.filters-panel,.copy-finding,.toggle-label{display:none!important}main{padding:0;max-width:none}.card,.priority-item{break-inside:avoid}.finding{display:block!important}}
"""

JS = """
(function(){
'use strict';
var root=document.documentElement,L=JSON.parse(document.getElementById('labels').textContent);
var COPY=JSON.parse(document.getElementById('copy-data').textContent);
function byId(id){return document.getElementById(id);}
function fmt(text,values){return text.replace(/\\{(\\w+)\\}/g,function(_,k){return values[k];});}
document.querySelectorAll('[data-js]').forEach(function(e){e.hidden=false;});
byId('theme').onclick=function(){var dark=root.dataset.theme?root.dataset.theme==='dark':window.matchMedia('(prefers-color-scheme: dark)').matches;root.dataset.theme=dark?'light':'dark';};
document.querySelectorAll('.bar .fill').forEach(function(f){f.style.width=f.dataset.w+'%';});
var list=byId('register-list'),items=list?Array.prototype.slice.call(list.querySelectorAll('.finding')):[];
var m=document.querySelector('[data-empty]'),q=byId('f-q'),searchCache=new Map();
function v(id){return byId(id).value;}
function text(d){if(!searchCache.has(d))searchCache.set(d,d.textContent.toLowerCase());return searchCache.get(d);}
function show(){var scope=v('f-scope'),term=q.value.trim().toLowerCase(),key=v('f-sort')==='severity'?'s':'p',pool=0,n=0;
items.slice().sort(function(a,b){return a.dataset[key]-b.dataset[key];}).forEach(function(d){list.appendChild(d);
var x=d.dataset.x==='1',inPool=scope==='all'||(scope==='excluded')===x;if(inPool)pool++;
d.hidden=!(inPool&&(!v('f-sev')||d.dataset.sev===v('f-sev'))&&(!v('f-conf')||d.dataset.conf===v('f-conf'))&&(!v('f-cat')||d.dataset.cat===v('f-cat'))&&(!v('f-status')||d.dataset.status===v('f-status'))&&(!v('f-verdict')||d.dataset.verdict===v('f-verdict'))&&(!term||text(d).indexOf(term)>=0));if(!d.hidden)n++;});
byId('result-count').textContent=fmt(L.showing,{shown:n,total:pool});if(m)m.hidden=n>0;}
function reset(){['f-sev','f-conf','f-cat','f-status','f-verdict'].forEach(function(id){byId(id).value='';});byId('f-scope').value='included';byId('f-sort').value='priority';q.value='';}
if(list){document.querySelectorAll('.filters select').forEach(function(s){s.onchange=function(){if(s.id==='f-verdict'&&s.dataset.excluded.split(' ').indexOf(s.value)>=0)byId('f-scope').value='all';show();};});
var timer=null;q.oninput=function(){clearTimeout(timer);timer=setTimeout(show,items.length>300?150:0);};
byId('reset').onclick=function(){reset();show();};show();}
function openHash(){var d=byId(decodeURIComponent(location.hash.slice(1)));if(!d||!d.classList.contains('finding'))return;if(d.hidden){reset();if(d.dataset.x==='1')byId('f-scope').value='all';show();}d.querySelector('details').open=true;d.scrollIntoView({block:'start'});d.querySelector('summary').focus({preventScroll:true});}
window.addEventListener('hashchange',openHash);if(location.hash)openHash();
document.addEventListener('click',function(e){var a=e.target.closest('a[href^="#finding-"]');if(a&&a.getAttribute('href')===location.hash){e.preventDefault();openHash();}});
// A denied or unavailable Clipboard API falls back to the selection copy.
function copyFallback(value){return new Promise(function(resolve,reject){var prev=document.activeElement,t=document.createElement('textarea');t.value=value;t.readOnly=true;t.style.position='fixed';t.style.top='0';t.style.left='-9999px';document.body.appendChild(t);t.select();var ok=false;try{ok=document.execCommand('copy');}catch(err){}t.remove();if(prev&&prev.focus)prev.focus({preventScroll:true});if(ok)resolve();else reject(new Error('copy'));});}
function copyText(value){if(navigator.clipboard&&window.isSecureContext)return navigator.clipboard.writeText(value).catch(function(){return copyFallback(value);});return copyFallback(value);}
document.querySelectorAll('.copy-finding').forEach(function(b){var t;b.onclick=function(){var done=function(label){b.textContent=label;clearTimeout(t);t=setTimeout(function(){b.textContent=L.copy_llm;},2000);};copyText(COPY[b.dataset.copy]).then(function(){done(L.copied);},function(){done(L.copy_failed);});};});
// Printing shows and opens every finding, then restores the filtered view.
var shut=[];addEventListener('beforeprint',function(){shut=[];items.forEach(function(f){var d=f.querySelector('details');if(!d.open)shut.push(d);f.hidden=false;d.open=true;});if(m)m.hidden=true;});
addEventListener('afterprint',function(){shut.forEach(function(d){d.open=false;});if(list)show();});
})();
"""


def html_text(value):
    """Keep recorded line breaks visible without interpreting recorded HTML."""
    value = as_text(value).replace("\r\n", "\n").replace("\r", "\n")
    return escape(value).replace("\n", "<br>")


def csp_hash(source):
    return "'sha256-" + base64.b64encode(hashlib.sha256(source.encode("utf-8")).digest()).decode() + "'"


# Nothing is fetched: only the inline style and script below may run.
CSP = (f"default-src 'none'; style-src {csp_hash(CSS)}; script-src {csp_hash(JS)}; "
       "base-uri 'none'; form-action 'none'")


def html_reference(ref):
    """Link only web URLs; any other scheme stays visible as text."""
    title, url = ref.get("title") or ref["url"], ref["url"]
    label = html_text(f"{title}: {url}" if title != url else url)
    if is_web_url(url):
        return f"<a href='{escape(url)}' rel='noopener noreferrer'>{label}</a>"
    return label


def plural(d, key, n, **values):
    text = d[key + "_one"] if n == 1 and key + "_one" in d else d[key]
    return text.format(n=n, **values)


def is_excluded(f):
    return f["validation"]["verdict"] in EXCLUDED


def action(f):
    """Fix now only what is Open, Valid and Confirmed; anything else is verified first."""
    return ("fix_now" if f["validation"]["verdict"] == "Valid" and f["confidence"] == "Confirmed"
            else "verify_first")


def anchor(f):
    return f"finding-{f['id'].lower()}"


def json_data(value):
    # A `<` would let recorded text end the data block or open a comment.
    return json.dumps(value, ensure_ascii=False).replace("<", "\\u003c")


def fenced(value):
    value = as_text(value).replace("\r\n", "\n").replace("\r", "\n")
    fence = "`" * max(3, max((len(run) for run in re.findall(r"`+", value)), default=0) + 1)
    return f"{fence}text\n{value}\n{fence}"


def finding_markdown(f, lang):
    """One finding as plain Markdown for pasting into a model, every value literal."""
    t = LABELS[lang]

    def one(value):
        return re.sub(r"\s*[\r\n]+\s*", " ", as_text(value))

    v = f["validation"]
    out = [f"## {one(f['id'])} · {one(f['title'])}", ""]
    for label, value in (("severity", f["severity"]), ("confidence", f["confidence"]),
                         ("verdict", f"{v['verdict']} ({v['method']})"),
                         ("status", f.get("status", "Open")), ("category", category(f)),
                         ("location", ", ".join(as_locations(f["location"])))):
        out.append(f"- {DASH[lang].get(label, t.get(label))}: {one(value)}")
    if filled(f, "rule"):
        out.append(f"- {t['rule']}: {one(f['rule'])}")
    blocks = [(t[k], f[k]) for k in FIELDS if k not in ("location", "rule") and filled(f, k)]
    if filled(v, "evidence"):
        blocks.append((t["evidence"], v["evidence"]))
    if "analysis" in f:
        a = f["analysis"]
        blocks.append((t["analysis"], f"{a['result']}\n{a['tool']}: {a['command']}"))
    for label, value in blocks:
        out += ["", f"### {label}", "", fenced(value)]
    refs = f.get("references", [])
    if refs:
        out += ["", f"### {t['references']}", ""]
        out += [f"- {one(r['title']) + ' — ' if r.get('title') and r['title'] != r['url'] else ''}"
                f"{one(r['url'])}" for r in refs]
    return "\n".join(out) + "\n"


def bars(order, counter, colored=False):
    top = max([counter.get(k, 0) for k in order] + [1])
    return "".join(
        f"<div class='bar'><span class='t'>{html_text(k)}</span><span class='track'>"
        f"<span class='fill{' ' + k if colored else ''}' data-w='{counter.get(k, 0) * 100 // top}'>"
        f"</span></span><span class='v'>{counter.get(k, 0)}</span></div>" for k in order)


def tally(findings, key):
    out = {}
    for f in findings:
        out[key(f)] = out.get(key(f), 0) + 1
    return out


def options(values, first=None):
    head = f"<option value=''>{html_text(first)}</option>" if first else ""
    return head + "".join(f"<option value='{escape(as_text(value))}'>{html_text(label)}</option>"
                          for value, label in values)


def bullet_list(items, empty):
    if not items:
        return f"<p class='muted'>{html_text(empty)}</p>"
    return "<ul>" + "".join(f"<li>{html_text(i)}</li>" for i in items) + "</ul>"


def render_html(doc, lang):
    t, d = LABELS[lang], DASH[lang]
    e = html_text
    meta, findings = doc["meta"], doc.get("findings", [])
    by_sev, excluded = counts(findings)
    included = [f for f in findings if not is_excluded(f)]
    status = {f["id"]: f.get("status", "Open") for f in findings}
    open_ = [f for f in included if status[f["id"]] == "Open"]
    open_hm = sum(f["severity"] in ("High", "Medium") for f in open_)
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    queue = sorted(open_, key=lambda f: (rank[f["severity"]], action(f) != "fix_now", f["id"]))
    fix_now = sum(action(f) == "fix_now" for f in open_)
    pending = sum(f["validation"]["verdict"] in ("Likely", "Unverified") for f in included)

    out = [f"<!doctype html><html lang='{lang}'><head><meta charset='utf-8'>",
           f"<meta http-equiv='Content-Security-Policy' content=\"{CSP}\">",
           "<meta name='viewport' content='width=device-width,initial-scale=1'>",
           f"<title>{escape(t['title'])}: {escape(' '.join(as_text(meta.get('project', '')).split()))}</title>"
           f"<style>{CSS}</style></head><body>",
           f"<a class='skip' href=\"#findings\">{e(d['jump_findings'])}</a><main>",
           f"<header class='masthead'><span class='brand'>{e(d['eyebrow'])}</span><div class='tools'>"
           f"<a class='button' href=\"report.md\">{e(d['report_link'])}</a>"
           f"<button type='button' id='theme' data-js hidden>{e(d['theme'])}</button></div></header>",
           f"<div class='hero'><div><div class='eyebrow'>{e(t['title'])}</div>"
           f"<h1>{e(meta.get('project', ''))}</h1>"
           f"<div class='meta'>{e(meta.get('scope', ''))} · {e(revision(meta))} · "
           f"{e(meta.get('date', ''))} · {e(meta.get('assessor', ''))}</div></div>"
           f"<div class='hero-aside'>{e(d['report_note'])}</div></div>"]

    if not included:
        headline = d["no_findings"]
    elif open_hm:
        headline = plural(d, "risk_summary", open_hm)
    elif open_:
        headline = plural(d, "open_summary", len(open_))
    else:
        headline = d["no_open"]
    detail = plural(d, "unverified_line", pending) if pending else d["none_unverified_line"]
    out.append(f"<div class='summary-banner'><strong>{e(headline)}</strong>"
               f"<p>{e(detail if included else review_method(doc, lang))}</p></div>")

    closed = "".join(f"<span class='pair'>{sum(status[f['id']] == s for f in included)}"
                     f"<span class='u'>{s}</span></span>" for s in ("Fixed", "Accepted"))
    cards = [(d["open_hm"], open_hm, "urgent", f"{d['open_count']}: {len(open_)}"),
             (d["needs_validation"], len(open_) - fix_now, "review", f"{d['fix_now']}: {fix_now}"),
             (d["closed_count"], closed, "", f"{d['included']}: {len(included)}"),
             (t["excluded"], excluded, "", f"{d['all_records']}: {len(findings)}")]
    out.append("<div class='cards'>" + "".join(
        f"<div class='card {cls}'><span class='l'>{e(label)}</span><div class='n'>{n}</div>"
        f"<div class='sub'>{e(sub)}</div></div>" for label, n, cls, sub in cards) + "</div>")
    out.append(f"<p class='report-note'>{e(d['counts_note'])}</p>")

    # The priority queue: every open High, at least four items, at most twelve.
    highs = sum(f["severity"] == "High" for f in queue)
    top = queue[:max(4, min(highs, 12))]
    out.append(f"<section aria-labelledby='priority-heading'><div class='section-head'><div>"
               f"<h2 id='priority-heading'>{e(d['priority'])}</h2><p>{e(d['priority_note'])}</p></div>"
               f"<a href=\"#findings\">{e(d['view_all'])}</a></div>")
    if any(action(f) == "verify_first" for f in top):
        out.append(f"<p class='section-note'><span class='action-label'>{e(d['verify_first'])}</span> "
                   f"{e(d['verify_first_note'])}</p>")
    if top:
        out.append("<div class='priority-list'>")
        for f in top:
            a = action(f)
            item = [f"<article class='panel priority-item sev-{f['severity']}'><div class='priority-top'>"
                    f"<span class='badge {f['severity']}'>{f['severity']}</span>"
                    f"<span class='action-label'>{e(d[a])}</span></div>"
                    f"<h3><a href=\"#{anchor(f)}\">{e(f['id'])} · {e(f['title'])}</a></h3>"
                    f"<div class='verdict'>{e(f['confidence'])} · {e(f['validation']['verdict'])} · "
                    f"{e(category(f))}</div>",
                    "".join(f"<code class='location'>{e(p)}</code>" for p in as_locations(f["location"])),
                    f"<p>{e(f['impact'])}</p>" if filled(f, "impact") else ""]
            if a == "fix_now":
                item.append(f"<p class='action'>{e(f['fix']) if filled(f, 'fix') else e(d['missing_fix'])}</p>")
            out.append("".join(item) + "</article>")
        out.append("</div>")
    else:
        out.append(f"<p class='panel muted'>{e(d['no_open'] if included else d['no_findings'])}</p>")
    hidden_high = highs - sum(f["severity"] == "High" for f in top)
    if hidden_high > 0:
        out.append(f"<p class='section-note'>{e(plural(d, 'more_high', hidden_high))}</p>")
    if len(top) < len(queue):
        out.append(f"<p class='section-note'>{e(d['queue_more'].format(shown=len(top), total=len(queue)))}</p>")
    out.append("</section>")

    out.append(f"<section class='panel'><h2>{e(t['decisions'])}</h2><div id='decisions'>"
               f"{bullet_list(doc.get('decisions', []), t['none'])}</div></section>")

    rows = perspective_rows(doc, lang)
    applied = sum(p["status"] == "applied" for _, p in rows)
    limitations = doc.get("limitations", [])
    out.append(f"<section class='panel coverage'><h2>{e(d['coverage_heading'])}<span class='small'>"
               f"{e(d['limitations_count'])}: {len(limitations)}</span></h2>"
               f"<p>{e(d['coverage_note'])}</p><dl class='scope-meta'>"
               f"<dt>{e(t['scope_row'])}</dt><dd>{e(meta.get('scope', ''))}</dd>"
               f"<dt>{e(d['method_row'])}</dt><dd>{e(review_method(doc, lang))}</dd>"
               f"<dt>{e(t['revision'])}</dt><dd>{e(revision(meta))}</dd></dl>"
               f"<h3>{e(t['limitations'])}</h3>{bullet_list(limitations, d['limitations_empty'])}"
               f"<h3>{e(t['perspectives'])}</h3><p class='section-note'>"
               f"{e(d['perspective_count'].format(applied=applied, total=len(rows)))}</p>"
               f"<div class='tablewrap'><table class='coverage-table'><thead><tr><th>{e(t['perspective'])}</th>"
               f"<th>{e(t['rule_status'])}</th><th>{e(t['note'])}</th></tr></thead><tbody>")
    for name, p in rows:
        out.append(f"<tr><td>{e(name)}</td><td>{e(p['status'])}</td><td>{e(p['note'])}</td></tr>")
    out.append("</tbody></table></div></section>")

    if doc.get("rules"):
        out.append(f"<section class='panel'><h2>{e(t['rules'])}</h2><p class='section-note'>"
                   f"{e(d['rules_note'])}</p><div class='tablewrap'><table class='rules'><thead><tr>"
                   f"<th>{e(t['id'])}</th><th>{e(t['statement'])}</th><th>{e(t['source'])}</th>"
                   f"<th>{e(t['rule_status'])}</th></tr></thead><tbody>")
        for r in doc["rules"]:
            rule_state = e(r["status"])
            if filled(r, "reason"):
                rule_state += f"<br>{e(t['reason'])}: {e(r['reason'])}"
            out.append(f"<tr><td>{e(rule_id(r))}</td><td>{e(rule_statement(r, lang))}</td>"
                       f"<td>{e(r['source'])}</td><td>{rule_state}</td></tr>")
        out.append("</tbody></table></div></section>")

    cats = sorted(tally(included, lambda f: f["category"]).items(), key=lambda kv: (-kv[1], kv[0]))
    out.append(f"<section class='panel'><h2>{e(d['overview'])}</h2><p class='section-note'>"
               f"{e(d['count_basis'])}</p><div class='grid'>"
               f"<div><h3>{e(d['by_sev'])}</h3>{bars(SEVERITIES, by_sev, colored=True)}</div>"
               f"<div><h3>{e(d['by_conf'])}</h3>{bars(CONFIDENCES, tally(included, lambda f: f['confidence']))}</div>"
               f"<div><h3>{e(d['by_cat'])}</h3>{bars([k for k, _ in cats], dict(cats))}</div>"
               f"<div><h3>{e(d['by_status'])}</h3>{bars(STATUSES, tally(included, lambda f: status[f['id']]))}</div>"
               f"<div><h3>{e(d['by_verdict'])}</h3>{bars(VERDICTS, verdict_counts(findings))}"
               f"<p class='section-note'>{e(d['excluded_note'])}</p></div></div></section>")

    out.append(f"<section id='findings' aria-labelledby='findings-heading'><div class='section-head'><div>"
               f"<h2 id='findings-heading'>{e(d['findings_register'])}</h2><p>{e(d['findings_note'])}</p>"
               f"</div></div>")
    if findings:
        excluded_values = " ".join(EXCLUDED)
        all_cats = sorted({f["category"] for f in findings})
        out.append(
            "<div class='panel filters-panel' data-js hidden><div class='filters'>"
            f"<label><span>{e(d['record_set'])}</span><select id='f-scope'>"
            + options([("included", d["included_set"]), ("excluded", d["excluded_set"]),
                       ("all", d["all_records"])]) + "</select></label>"
            f"<label><span>{e(d['severity'])}</span><select id='f-sev'>"
            + options([(s, s) for s in SEVERITIES], t["all"]) + "</select></label>"
            f"<label><span>{e(d['confidence'])}</span><select id='f-conf'>"
            + options([(c, c) for c in CONFIDENCES], t["all"]) + "</select></label>"
            f"<label><span>{e(d['category'])}</span><select id='f-cat'>"
            + options([(c, c) for c in all_cats], t["all"]) + "</select></label>"
            f"<label><span>{e(d['status'])}</span><select id='f-status'>"
            + options([(s, s) for s in STATUSES], t["all"]) + "</select></label>"
            f"<label><span>{e(d['verdict'])}</span><select id='f-verdict' data-excluded='{excluded_values}'>"
            + options([(v, v) for v in VERDICTS], t["all"]) + "</select></label>"
            f"<label><span>{e(d['sort'])}</span><select id='f-sort'>"
            + options([("priority", d["priority_sort"]), ("severity", d["severity_sort"])]) + "</select></label>"
            f"<label class='search'><span>{e(d['search'])}</span><input id='f-q' type='search' "
            f"placeholder='{escape(d['search'])}'></label></div><div class='filter-bottom'>"
            "<p class='result-count' id='result-count' role='status' aria-live='polite'></p>"
            f"<button type='button' id='reset'>{e(d['reset'])}</button></div></div>")
    heads = ("ID", d["severity"], d["confidence"], d["status"], d["verdict"], d["title_col"], d["category"])
    out.append("<div class='register'><div class='reg-head' aria-hidden='true'>"
               + "".join(f"<span>{e(h)}</span>" for h in heads) + "</div><div id='register-list'>")
    if not findings:
        out.append(f"<p class='empty'>{e(t['none'])}</p>")
    else:
        # Shown by the filter when it leaves no finding visible.
        out.append(f"<p class='empty' data-empty hidden>{e(d['no_matches'])}</p>")

    def priority(f):
        return (status[f["id"]] != "Open", rank[f["severity"]], action(f) != "fix_now", f["id"])

    p_order = {f["id"]: i for i, f in enumerate(sorted(findings, key=priority))}
    s_order = {f["id"]: i for i, f in enumerate(sorted(findings, key=lambda f: (rank[f["severity"]], f["id"])))}
    copy = {}
    for f in findings:
        v = f["validation"]
        x = is_excluded(f)
        copy[f["id"]] = finding_markdown(f, lang)
        fields = [(t["category"], e(category(f)))]
        fields += [(t[k], e(f[k])) for k in FIELDS if filled(f, k)]
        fields.append((t["verdict"], e(f"{v['verdict']} ({v['method']})")))
        if filled(v, "evidence"):
            fields.append((t["evidence"], e(v["evidence"])))
        fields.append((t["status"], e(status[f["id"]])))
        if "analysis" in f:
            a = f["analysis"]
            fields.append((t["analysis"], e(f"{a['result']} — {a['tool']}: {a['command']}")))
        if f.get("references"):
            # Every reference keeps its own row label.
            fields += [(t["references"], html_reference(ref)) for ref in f["references"]]
        guidance = ""
        if status[f["id"]] == "Open" and not x:
            a = action(f)
            guidance = (f"<div class='action-guidance'><strong>{e(d[a])}</strong>"
                        f"<p>{e(d[a + '_note'])}</p></div>")
        elif x:
            guidance = f"<p class='muted'>{e(d['excluded_note'])}</p>"
        # Excluded findings are not in the severity counts, so not in their filters.
        group = "excluded' class='excluded" if x else f["severity"]
        attrs = {"sev": f["severity"], "conf": f["confidence"], "cat": f["category"],
                 "status": status[f["id"]], "verdict": v["verdict"], "x": "1" if x else "0",
                 "p": p_order[f["id"]], "s": s_order[f["id"]]}
        data = "".join(f" data-{k}='{escape(as_text(val))}'" for k, val in attrs.items())
        locations = "".join(f"<code class='location'>{e(p)}</code>" for p in as_locations(f["location"]))
        out.append(
            f"<div class='finding' id='{anchor(f)}'{data}><details data-sev='{group}'><summary>"
            f"<span data-label='ID'>{e(f['id'])}</span>"
            f"<span data-label='{escape(d['severity'])}'><span class='badge {f['severity']}'>{f['severity']}</span></span>"
            f"<span class='reg-meta' data-label='{escape(d['confidence'])}'>{e(f['confidence'])}</span>"
            f"<span class='reg-meta' data-label='{escape(d['status'])}'>{e(status[f['id']])}</span>"
            f"<span class='reg-meta' data-label='{escape(d['verdict'])}'>{e(v['verdict'])}</span>"
            f"<span class='reg-title'><span>{e(f['title'])}</span>{locations}"
            f"<span class='toggle-label' aria-hidden='true'><span class='closed-label'>{e(d['expand'])}</span>"
            f"<span class='open-label'>{e(d['collapse'])}</span></span></span>"
            f"<span class='reg-meta reg-cat' data-label='{escape(d['category'])}'>{e(f['category'])}</span>"
            f"</summary><div class='detail'><div class='detail-actions'><strong>{e(f['id'])} · {e(f['title'])}</strong>"
            f"<span class='detail-links'><button type='button' class='copy-finding' data-js hidden "
            f"data-copy='{escape(f['id'])}' aria-live='polite'>{e(d['copy_llm'])}</button>"
            f"<a href=\"#{anchor(f)}\">{e(d['permalink'])}</a></span></div>{guidance}<dl>"
            + "".join(f"<dt>{e(k)}</dt><dd>{val}</dd>" for k, val in fields) + "</dl></div></details></div>")
    out.append("</div></div></section>")

    out.append("<div class='lists'>" + "".join(
        f"<section class='panel'><h2>{e(t[k])}</h2>{bullet_list(doc.get(k, []), t['none'])}</section>"
        for k in ("next_steps", "checked_ok")) + "</div>")
    out.append(f"<footer class='footer'>{e(d['footer'])}</footer></main>")
    labels = {k: d[k] for k in ("showing", "copy_llm", "copied", "copy_failed")}
    out.append(f"<script type='application/json' id='labels'>{json_data(labels)}</script>"
               f"<script type='application/json' id='copy-data'>{json_data(copy)}</script>"
               f"<script>{JS}</script></body></html>")
    return "".join(out)


def rendered_outputs(doc, lang):
    """The exact bytes render.py writes for doc, keyed by output name."""
    return {"report.md": render_markdown(doc, lang).encode("utf-8"),
            "dashboard.html": render_html(doc, lang).encode("utf-8")}


def main(argv=None):
    safe_output()
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("findings")
    parser.add_argument("--out", required=True)
    parser.add_argument("--lang", choices=("ja", "en"))
    args = parser.parse_args(argv)
    try:
        doc = read_json(args.findings)
        validate(doc, complete=True)
    except SchemaError as exc:
        print(f"schema: {exc}", file=sys.stderr)
        return 2
    lang = args.lang or doc["meta"]["lang"]
    out = Path(args.out)
    try:
        out.mkdir(parents=True, exist_ok=True)
        # Both outputs are staged before either replaces the previous file.
        _atomic_write_all({out / name: data for name, data in rendered_outputs(doc, lang).items()})
    except (OSError, RuntimeError) as exc:
        print(f"write failed: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {out / 'dashboard.html'} and {out / 'report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
