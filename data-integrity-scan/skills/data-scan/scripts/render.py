#!/usr/bin/env python3
"""Render findings.json into dashboard.html and report.md.

    python3 render.py FINDINGS --out DIR [--lang ja|en]

Both outputs are derived from the one record; neither adds facts of its own.
`dashboard.html` is self-contained and works offline. `report.md` is the written
assessment SKILL.md's Outputs table describes (the chat summary, not this
file, takes the shape in `reference/report.md`).

FINDINGS must be a regular file: it is read again under the output directory's
lock. Recorded prose keeps `*emphasis*` and code spans; `_` stays literal, as
identifiers (`__init__`) use it far more often than emphasis does.

Exit codes: 0 written, 1 an output, or the closing line on stdout, could not be
written (render again before `findings.py check`), 2 the record cannot be read
or does not match the schema (the file or field is named on stderr), or the
command line is wrong.
"""
import argparse
import base64
import hashlib
import json
from html import escape
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True  # leave no __pycache__ beside the skill
from findings import (CONFIDENCES, CONTROL, CONVENTION_STATUSES, DEFINITIVE,  # noqa: E402
                      EFFORTS, EXCLUDED, METHODS, NETS, PERSPECTIVE_STATUSES, PERSPECTIVES,
                      REMEDIES, ROLLOUTS, SEVERITIES, STATUSES, VERDICTS, SchemaError,
                      _atomic_write_all, as_locations, locked_dir, nonempty, read_json, run,
                      safe_output, shown_line, validate, visible)
from markdown_safe import (BIDI_CONTROLS, as_text, block_safe, heading_text,  # noqa: E402
                           markdown_code, markdown_inline, markdown_table_cell)
from scan_report_kit import style as kit_style  # noqa: E402

URL_SCHEME = re.compile(r"https?://", re.IGNORECASE)
SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")


def is_web_url(url):
    return (bool(URL_SCHEME.match(url)) and not re.search(r"[\x00-\x20\x7f]", url)
            and not CONTROL.search(url) and not BIDI_CONTROLS.search(url))


def is_safe_link(url):
    """A web URL or a scheme-less relative path; never javascript:, data: and the like.

    Browsers drop tabs, newlines and leading control characters from a URL, so
    any control character could hide a scheme: such a URL is never a link.
    """
    # A bidi control would reorder the destination wherever it is shown or
    # copied, though its label makes it visible: such a URL is never a link.
    if re.search(r"[\x00-\x1f\x7f]", url) or CONTROL.search(url) or BIDI_CONTROLS.search(url):
        return False
    stripped = url.lstrip(" ")
    if len(stripped) > 1 and set(stripped[:2]) <= {"/", "\\"}:
        return False  # protocol-relative or UNC: another host, not a relative path
    return is_web_url(url) or not SCHEME.match(stripped)


LABELS = {
    "en": {
        "title": "Data integrity assessment", "scope": "Scope and method",
        "findings": "Findings", "conventions": "Data rule ledger", "perspectives": "Perspective coverage",
        "plan": "Plan",
        "checked_ok": "Checked and found sound", "limitations": "What could not be checked",
        "decisions": "Decisions for a human", "next_steps": "Next steps", "excluded": "Excluded",
        "all": "All", "none": "None.",
        "location": "location", "hazard": "hazard", "remedy": "remedy",
        "scenario": "scenario", "blast_radius": "blast radius", "trace": "trace",
        "impact": "what can happen to the data", "exposure": "exposure", "enforcement": "enforcement today", "invariants": "invariants",
        "rollout_reason": "rollout reason", "steps": "steps",
        "depends_on": "depends on", "convention": "convention", "fix": "fix direction",
        "verdict": "recorded verdict", "verdicts": "Verdict counts",
        "method": "verification", "evidence": "evidence", "analysis": "analysis",
        "references": "references", "status": "status", "reason": "Reason",
        "category": "perspective", "id": "ID", "idiom": "Rule", "source": "Source",
        "rule_status": "Status", "perspective": "Perspective", "note": "Note",
        "not_recorded": "not recorded", "inferred": "inferred, to confirm",
        "rollout": "rollout", "effort": "effort", "batch": "Batch", "pr_title": "PR title",
        "prerequisite": "prerequisite", "sites": "sites", "gaps": "gaps",
        "window": "History window",
        "axis": "Severity axis", "axis_confirmed": "confirmed by the requester",
        "axis_assumed": "assumed; not confirmed by the requester",
        "static_note": "Static review; no code was changed or executed beyond read-only analysis.",
        "analysed_note": "Static review plus read-only tool analysis (history, a schema dump in the repository).",
        "project": "System", "scope_row": "Scope", "revision": "Revision", "date": "Date",
        "assessor": "Assessor", "analysis_command": "analysis command",
        # The level legend condenses SKILL.md's severity and confidence tables
        # (one `legend_<level>` per SEVERITIES and CONFIDENCES value); change it with them.
        "legend": "How to read the levels", "legend_severity": "Severity",
        "legend_confidence": "Confidence",
        "legend_High": "A core table can be corrupted, lost or locked on a realistic path, and the "
                       "evidence shows it: a fix commit in the window already patched its data, a "
                       "write path traced with no enforcement, or a pending migration that "
                       "rewrites or locks it.",
        "legend_Medium": "Core data without incident evidence, or non-core data with evidence, or "
                         "it blocks a change the requester named.",
        "legend_Low": "A real hazard on data that is neither core nor shown to have gone wrong.",
        "legend_Info": "A note: a hazard with no exposure evidence, a migration already applied in "
                       "production that broke a ledger rule, or a constraint worth adding when the "
                       "table is next changed.",
        "legend_Confirmed": "The hazard is traced in the schema and every write path, and the "
                            "exposure follows from recorded history, the named core tables or the "
                            "repository's own size and deploy records.",
        "legend_Environment-dependent": "The exposure depends on something the repository does not "
                                        "show: table sizes, the engine version in production, the "
                                        "deploy order, constraints in another repository's "
                                        "migrations, history squashed or migrated.",
        "legend_Suspected": "The hazard is traced but the exposure has no evidence.",
        "legend_separate": "Severity and confidence are graded separately.",
        "legend_assumed": "Severity rests on an assumed list; see decisions.",
    },
    "ja": {
        "title": "データ整合性診断", "scope": "対象と方法",
        "findings": "検出事項", "conventions": "データルール台帳", "perspectives": "観点のカバレッジ",
        "plan": "実行計画",
        "checked_ok": "確認して問題がないとした項目", "limitations": "確認できなかったこと",
        "decisions": "人が判断すべき事項", "next_steps": "次の作業", "excluded": "除外",
        "all": "すべて", "none": "なし。",
        "location": "場所", "hazard": "危険", "remedy": "対処",
        "scenario": "シナリオ", "blast_radius": "影響範囲", "trace": "追跡",
        "impact": "データに起こりうること", "exposure": "露出の根拠", "enforcement": "現在の強制", "invariants": "守るべき不変条件",
        "rollout_reason": "適用方法の理由", "steps": "手順",
        "depends_on": "先行する検出事項", "convention": "データルール", "fix": "修正方針",
        "verdict": "検証判定", "verdicts": "検証判定別件数",
        "method": "検証方法", "evidence": "根拠", "analysis": "解析",
        "references": "参考", "status": "状況", "reason": "理由",
        "category": "観点", "id": "ID", "idiom": "ルール", "source": "出典",
        "rule_status": "状態", "perspective": "観点", "note": "メモ",
        "not_recorded": "未記録", "inferred": "推定・要確認",
        "rollout": "適用方法", "effort": "規模", "batch": "バッチ", "pr_title": "PR タイトル",
        "prerequisite": "前提条件", "sites": "強制箇所", "gaps": "不足",
        "window": "履歴の期間",
        "axis": "重大度の軸", "axis_confirmed": "依頼者が確認済み",
        "axis_assumed": "仮定（依頼者は未確認）",
        "static_note": "静的レビューのみ。読み取り専用の解析以外にコードの変更や実行はしていない。",
        "analysed_note": "静的レビューに加え、読み取り専用のツール解析（変更履歴、リポジトリ内のスキーマダンプ）を実施。",
        "project": "システム", "scope_row": "範囲", "revision": "リビジョン", "date": "診断日",
        "assessor": "診断者", "analysis_command": "解析コマンド",
        "legend": "レベルの読み方", "legend_severity": "重大度", "legend_confidence": "確度",
        "legend_High": "中核テーブルが現実的な経路で破損・消失・ロックするおそれがあり、"
                       "かつ証拠がある（期間内の修正コミットがすでにそのデータを直している、"
                       "強制のない書き込み経路を追跡できた、"
                       "またはそのテーブルを書き換えるかロックする未適用のマイグレーションがある）。"
                       "",
        "legend_Medium": "中核データで事故の証拠がない、中核外のデータで証拠がある、"
                         "または依頼者が挙げた変更を妨げている。",
        "legend_Low": "危険は実在するが、中核でもなく問題が起きた実績もないデータにある。",
        "legend_Info": "メモ。露出の証拠がない危険、"
                       "本番に適用済みでデータルールに反したマイグレーション、"
                       "または次にそのテーブルを変更するときに追加する価値のある制約。",
        "legend_Confirmed": "スキーマとすべての書き込み経路で危険を追跡でき、露出が記録された履歴、"
                            "名前を挙げた中核テーブル、"
                            "またはリポジトリ自身のサイズやデプロイの記録から導ける。",
        "legend_Environment-dependent": "露出がリポジトリに現れないものに依存する（テーブルのサイズ、"
                                        "本番のエンジンのバージョン、デプロイの順序、"
                                        "別リポジトリのマイグレーションにある制約、squash "
                                        "や移行された履歴）。",
        "legend_Suspected": "危険は追跡できたが、露出に証拠がない。",
        "legend_separate": "重大度と確度は別々に判定する。",
        "legend_assumed": "重大度は依頼者が確認していないリストに基づく。人が判断すべき事項を参照。",
    },
}
FIELDS = ("location", "hazard", "remedy", "scenario", "blast_radius", "trace", "impact",
          "exposure", "enforcement", "invariants", "rollout_reason", "steps", "depends_on",
          "convention", "fix")
LIST_FIELDS = ("invariants", "steps")


def field_text(f, key, lang):
    """A finding field as one string: lists and the coverage object flattened."""
    value = f[key]
    if key in LIST_FIELDS:
        return "\n".join(value)
    if key == "enforcement":
        t = LABELS[lang]
        sites = ", ".join(value["sites"]) or "—"
        return f"{value['net']} · {t['sites']}: {sites} · {t['gaps']}: {value['gaps']}"
    return value


def counts(findings):
    active = [f for f in findings if f["validation"]["verdict"] not in EXCLUDED]
    return {s: sum(f["severity"] == s for f in active) for s in SEVERITIES}, len(findings) - len(active)


def verdict_counts(findings):
    return {v: sum(f["validation"]["verdict"] == v for f in findings) for v in VERDICTS}




def review_method(doc, lang):
    """Keep the recorded scope of analysis, including runs with no findings."""
    if filled(doc["meta"], "method"):
        return doc["meta"]["method"]
    analysed = any(f["validation"]["method"] == "analysed" or "analysis" in f
                   for f in doc.get("findings", []))
    return LABELS[lang]["analysed_note" if analysed else "static_note"]




def legend(doc, lang):
    """The level legend: (heading, [(level, meaning)]) per scale, then the closing lines."""
    t = LABELS[lang]
    scales = [(t["legend_" + name], [(level, t["legend_" + level]) for level in levels])
              for name, levels in (("severity", SEVERITIES), ("confidence", CONFIDENCES))]
    closing = [t["legend_separate"]]
    if doc["meta"].get("axis") == "assumed":
        closing.append(t["legend_assumed"])
    return scales, closing


def revision(meta):
    commit = meta.get("commit", "")
    return commit if visible(commit) else "UNKNOWN"


def category(f):
    return f"{f['category']} ({f['step']})" if "step" in f else f["category"]


def perspective_rows(doc, lang):
    """Every perspective in reference order, so both outputs show the same gaps."""
    recorded = {p["name"]: p for p in doc.get("perspectives", [])}
    missing = {"status": "—", "note": LABELS[lang]["not_recorded"]}
    return [(name, recorded.get(name, missing)) for name in PERSPECTIVES]


def convention_id(entry):
    """The ledger ID with its concern (reference/conventions.md §2), e.g. `C-01 · ERROR`."""
    return f"{entry['id']} · {entry['concern']}" if entry.get("concern") else entry["id"]


def convention_idiom(entry, lang):
    """An inferred idiom is a question for the requester (reference/conventions.md §1)."""
    if entry.get("inferred") is True:
        return f"{entry['idiom']} ({LABELS[lang]['inferred']})"
    return entry["idiom"]


def batch_findings(batch, findings):
    """A batch's findings as `F-001 title`, in the batch's order."""
    titles = {f["id"]: f["title"] for f in findings}
    return [f"{fid} {titles.get(fid, '')}".rstrip() for fid in batch["findings"]]


def filled(record, key):
    """A recorded value worth a row: present and not blank."""
    return key in record and visible(as_text(record[key]))


def markdown_reference(ref):
    if not is_safe_link(ref["url"]):
        # Web URLs and relative paths become links; any other scheme stays literal.
        title = ref.get("title")
        code = markdown_code(ref["url"])
        return f"{markdown_inline(title)}: {code}" if title and title != ref["url"] else code
    title = markdown_inline(ref.get("title") or ref["url"])  # brackets encoded too
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
              f"| {t['revision']} | {cell(revision(meta))} |"]
    if filled(meta, "window"):
        lines.append(f"| {t['window']} | {cell(meta['window'])} |")
    if meta.get("axis") in ("confirmed", "assumed"):
        lines.append(f"| {t['axis']} | {t['axis_' + meta['axis']]} |")
    # One recorded value per cell or line (coverage and lists below too): emphasis
    # never pairs across two values.
    lines += [f"| {t['date']} | {cell(meta.get('date', ''))} |",
              f"| {t['assessor']} | {cell(meta.get('assessor', ''))} |", ""]
    scales, closing = legend(doc, lang)
    lines += [f"## {t['legend']}", ""]
    for heading, levels in scales:
        lines += [f"**{heading}**", ""] + [f"- **{level}:** {meaning}" for level, meaning in levels] + [""]
    for line in closing:
        lines += [line, ""]
    lines += [f"## {t['findings']}", ""]
    if not findings:
        lines += [t["none"], ""]
    for f in findings:
        v = f["validation"]
        lines.append(f"### {f['id']} [{f['severity']}][{f['rollout']}][{f['effort']}]"
                     f"[{f['confidence']}][{v['verdict']}] {heading_text(f['title'])}")
        lines.append("")
        lines.append(f"- **{t['category']}:** {text(category(f))}")
        for key in FIELDS:
            if key == "enforcement" and filled(f, key):
                s = f["enforcement"]
                sites = ", ".join(markdown_code(site) for site in s["sites"]) or "—"
                lines += [f"- **{t[key]}:** {s['net']}", f"  - **{t['sites']}:** {sites}",
                          f"  - **{t['gaps']}:** {text(s['gaps'])}"]
            elif key in LIST_FIELDS and filled(f, key):
                lines.append(f"- **{t[key]}:**")
                lines += [f"  - {block_safe(text(item))}" for item in f[key]]
            elif filled(f, key):
                value = field_text(f, key, lang)
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
            lines += [f"- **{t['analysis']}:** {text(a['result'])}",
                      f"- **{t['analysis_command']}:** {text(a['tool'])}: "
                      f"{markdown_code(a['command'])}"]
        lines.append(f"- **{t['status']}:** {f.get('status', 'Open')}")
        for ref in f.get("references", []):
            lines.append(f"- **{t['references']}:** {markdown_reference(ref)}")
        lines.append("")
    lines += [f"## {t['plan']}", ""]
    if not doc.get("plan"):
        lines += [t["none"], ""]
    for b in doc.get("plan", []):
        lines += [f"### {t['batch']} {b['batch']}: {heading_text(b['title'])}", "",
                  f"- **{t['pr_title']}:** {text(b['pr_title'])}",
                  f"- **{t['prerequisite']}:** {text(b['prerequisite'])}"]
        lines += [f"- {block_safe(text(item))}" for item in batch_findings(b, findings)]
        lines.append("")
    if doc.get("conventions"):
        lines += [f"## {t['conventions']}", "",
                  f"| {t['id']} | {t['idiom']} | {t['source']} | {t['rule_status']} |",
                  "|---|---|---|---|"]
        for r in doc["conventions"]:
            status = r["status"]
            if filled(r, "reason"):
                status += f"\n{t['reason']}: {r['reason']}"
            lines.append(f"| {cell(convention_id(r))} | {cell(convention_idiom(r, lang))} | "
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
        "eyebrow": "DATA INTEGRITY REVIEW",
        "report_note": "Static review · read-only · offline dashboard",
        "report_link": "Markdown report", "theme": "Toggle color theme",
        "jump_findings": "Jump to findings",
        "contents": "Contents", "nav_summary": "Summary", "nav_lists": "Next steps and checks",
        "shortcuts": "Keyboard", "key_search": "Search", "key_move": "Next / previous finding",
        "key_toggle": "Show or hide details",
        "risk_summary": "{n} open High / Medium findings need attention.",
        "risk_summary_one": "1 open High / Medium finding needs attention.",
        "open_summary": "{n} open findings are recorded; none are High or Medium.",
        "open_summary_one": "1 open finding is recorded; it is not High or Medium.",
        "no_open": "No open findings are recorded. This does not establish that the data cannot be corrupted, lost or locked.",
        "no_findings": "No included findings are recorded. Review the scope and limitations before "
                       "drawing conclusions.",
        "unverified_line": "{n} included findings have no definitive verdict yet "
                           "(Likely, Unverified or Unlikely).",
        "unverified_line_one": "1 included finding has no definitive verdict yet "
                               "(Likely, Unverified or Unlikely).",
        "none_unverified_line": "Every included finding has a definitive verdict.",
        "open_hm": "Open High/Medium", "open_count": "Open findings",
        "needs_validation": "Open, not ready yet", "closed_count": "Fix recorded / accepted",
        "included": "Included findings", "all_records": "All records",
        "counts_note": "Report-wide totals include Open, Fixed and Accepted. Excluded findings do not "
                       "contribute to these totals.",
        "priority": "Start here",
        "priority_note": "Open findings, ordered by exposure, then readiness. The plan below gives "
                         "the order to execute them in.",
        "view_all": "View all findings",
        "fix_now": "Ready to ship", "pin_first": "Stage the rollout", "verify_first": "Verify first",
        "fix_now_note": "Valid, Confirmed and Online: one migration or code change, safe while "
                        "traffic runs. Follow the steps; each ends green.",
        "pin_first_note": "Valid and Confirmed, but the fix needs several deploys or a maintenance "
                          "window. Schedule each step as the steps say.",
        "verify_first_note": "Confirm the hazard, the exposure and what enforces the invariant today; "
                             "record evidence before planning the change.",
        "missing_fix": "Fix direction not recorded. Define it after reviewing the evidence.",
        "more_high": "{n} more open High findings are listed in the findings register.",
        "more_high_one": "1 more open High finding is listed in the findings register.",
        "queue_more": "Showing {shown} of {total} open findings.",
        "coverage_heading": "Scope, coverage and limitations",
        "coverage_note": "Coverage is recorded per perspective below. A perspective marked not "
                         "checked, or not recorded, was not reviewed. Zero findings is not a "
                         "guarantee that the data cannot be corrupted, lost or locked.",
        "limitations_count": "Recorded limitations",
        "limitations_empty": "No limitations were recorded. This is not evidence of complete coverage.",
        "perspective_count": "Perspectives applied: {applied} of {total}",
        "rules_note": "Where this codebase states its data rules; fixes and drift are judged against them.",
        "plan_note": "Batches in execution order; each is one reviewable pull request that leaves the build green.",
        "overview": "Results overview",
        "count_basis": "Severity is what corrupted, lost or locked data here would cost; rollout is "
                       "how the fix reaches production; confidence is how sure the finding is.",
        "by_sev": "By severity", "by_rollout": "By rollout", "by_conf": "By confidence", "by_cat": "By perspective",
        "by_status": "By status", "by_verdict": "By verdict",
        "excluded_note": "Excluded findings are retained with their justification. They are not "
                         "counted in included totals.",
        "findings_register": "Findings register",
        "findings_note": "Open a finding for its hazard, exposure, enforcement today, invariants and steps. Totals "
                         "above remain report-wide while filtering.",
        "record_set": "Records", "included_set": "Included (excludes ruled-out findings)",
        "excluded_set": "Excluded only", "severity": "Severity", "confidence": "Confidence",
        "rollout": "Rollout", "effort": "Effort",
        "category": "Perspective", "status": "Status", "verdict": "Verdict", "sort": "Order",
        "priority_sort": "Open first, then severity", "severity_sort": "Severity",
        "search": "Search", "reset": "Clear filters", "title_col": "Title",
        "showing": "Showing {shown} of {total} records in this view",
        "no_matches": "No findings match these filters. Clear filters to see more.",
        "no_records": "No findings are in this record set. Choose another under Records.",
        "copy_llm": "Copy for LLM", "copied": "Copied", "copy_failed": "Copy failed",
        "permalink": "Link to finding", "expand": "Show details", "collapse": "Hide details",
        "method_row": "Method",
        "footer": "Rendered from findings.json; every value is shown as recorded. Inspect this "
                  "dashboard before sharing.",
    },
    "ja": {
        "eyebrow": "DATA INTEGRITY REVIEW",
        "report_note": "静的レビュー · 読み取り専用 · オフラインダッシュボード",
        "report_link": "Markdown レポート", "theme": "配色を切り替え",
        "jump_findings": "検出事項一覧へ移動",
        "contents": "目次", "nav_summary": "概要", "nav_lists": "次の作業と確認済み事項",
        "shortcuts": "キー操作", "key_search": "検索", "key_move": "次・前の検出事項",
        "key_toggle": "詳細の表示・非表示",
        "risk_summary": "未対応の High / Medium が {n} 件あります。",
        "open_summary": "未対応の検出事項は {n} 件です。High / Medium は含まれていません。",
        "no_open": "未対応の検出事項は記録されていません。データが壊れない・失われない・ロックされないことを保証するものではありません。",
        "no_findings": "集計対象の検出事項はありません。対象範囲と制約を確認してから判断してください。",
        "unverified_line": "集計対象のうち {n} 件は判定が確定していません（Likely・Unverified・Unlikely）。",
        "none_unverified_line": "集計対象の検出事項はすべて判定が確定しています。",
        "open_hm": "未対応の High / Medium", "open_count": "未対応の検出事項",
        "needs_validation": "未対応・準備が必要", "closed_count": "修正の申告 / 受容",
        "included": "集計対象の検出事項", "all_records": "すべての記録",
        "counts_note": "全体集計には Open・Fixed・Accepted を含みます。除外した検出事項は含みません。",
        "priority": "まず取り組むこと",
        "priority_note": "未対応の検出事項を露出の大きい順、同じなら着手の準備ができた順に表示します。"
                         "実行順は下の実行計画に従ってください。",
        "view_all": "検出事項一覧を見る",
        "fix_now": "すぐ適用できる", "pin_first": "段階的に適用する", "verify_first": "先に検証する",
        "fix_now_note": "Valid・Confirmed・Online です。1 回のマイグレーションかコード変更で、"
                        "稼働中のまま適用できます。手順に従い、各手順を green で終えてください。",
        "pin_first_note": "Valid・Confirmed ですが、複数回のデプロイかメンテナンス時間が必要です。"
                          "手順どおりに各段階を計画してください。",
        "verify_first_note": "危険・露出の根拠・現在の強制を確認し、根拠を記録してから変更を"
                             "計画してください。",
        "missing_fix": "修正方針が未記録です。根拠を確認し、修正内容を具体化してください。",
        "more_high": "未対応の High がほかに {n} 件あります（検出事項一覧に記載）。",
        "queue_more": "未対応 {total} 件のうち {shown} 件を表示しています。",
        "coverage_heading": "対象範囲・確認状況・制約",
        "coverage_note": "観点ごとの確認状況を下に示します。not checked や未記録の観点は確認していません。"
                         "検出事項がゼロでも、データが壊れない・失われない・ロックされないことの保証にはなりません。",
        "limitations_count": "記録された制約",
        "limitations_empty": "制約事項が記録されていません。すべて確認済みであることを示すものではありません。",
        "perspective_count": "適用した観点: {total} 件中 {applied} 件",
        "rules_note": "このコードベースがデータのルールを定めている箇所です。修正と逸脱はこれを基準に判断します。",
        "plan_note": "実行順のバッチです。各バッチはビルドを green に保つ、レビュー可能な 1 つの PR です。",
        "overview": "結果概要",
        "count_basis": "重大度はここでデータが壊れる・失われる・ロックされたときの損害、適用方法は"
                       "修正を本番に届ける方法、確度は検出事項の確かさを表します。",
        "by_sev": "重大度別", "by_rollout": "適用方法別", "by_conf": "確度別", "by_cat": "観点別",
        "by_status": "対応状況別", "by_verdict": "検証判定別",
        "excluded_note": "除外した検出事項も、その根拠とともに保持します。集計対象の件数には含めません。",
        "findings_register": "検出事項一覧",
        "findings_note": "検出事項を開くと危険・露出の根拠・現在の強制・守るべき不変条件・手順を確認できます。絞り込んでも上部の"
                         "全体集計は変わりません。",
        "record_set": "表示対象", "included_set": "集計対象（誤検知・対象外を除く）",
        "excluded_set": "除外した検出事項のみ", "severity": "重大度", "confidence": "確度",
        "rollout": "適用方法", "effort": "規模",
        "category": "観点", "status": "状況", "verdict": "検証判定", "sort": "表示順",
        "priority_sort": "未対応を先に、重大度順", "severity_sort": "重大度順",
        "search": "検索", "reset": "絞り込みを解除", "title_col": "件名",
        "showing": "この表示対象 {total} 件中 {shown} 件を表示",
        "no_matches": "条件に一致する検出事項はありません。絞り込みを解除すると、ほかの検出事項を確認できます。",
        "no_records": "この表示対象に検出事項はありません。「表示対象」でほかの対象を選んでください。",
        "copy_llm": "LLM 用にコピー", "copied": "コピーしました", "copy_failed": "コピーできませんでした",
        "permalink": "この検出事項へのリンク", "expand": "詳細を開く", "collapse": "詳細を閉じる",
        "method_row": "方法",
        "footer": "findings.json から生成しています。値はすべて記録どおりに表示しています。共有前に内容を"
                  "確認してください。",
    },
}

# Rules for data-scan record types only, after the shared dashboard
# stylesheet (scan_report_kit/assets/dashboard.css, docs: scan-report-kit).
DASHBOARD_CSS = """
.action-label,.reg-head,.reg-meta,.detail dt,.small,.toggle-label{font-family:var(--sans)}
.action-label{font-size:12px;font-weight:700;color:var(--accent)}
.card .n .pair{display:inline-block;white-space:nowrap;margin-right:18px}
.card .n .u{font-family:var(--sans);font-size:11px;letter-spacing:.06em;color:var(--muted);margin-left:6px}
.coverage h2 .small{font-size:13px;font-weight:400;color:var(--muted);margin-left:10px}
#decisions ul{margin:6px 0;padding-left:20px}
.legend{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:8px 18px;margin:8px 0 14px}
.legend dt{font-family:var(--sans);font-size:13px;font-weight:700}
.legend dd{margin:0}
.bar .fill{display:block;width:0}
.bar .fill.High{background:var(--high)}
.bar .fill.Medium{background:var(--medium)}
.bar .fill.Low{background:var(--low)}
.bar .fill.Info{background:var(--info)}
.register{border-top:1.5px solid var(--text);border-bottom:1.5px solid var(--text);margin-top:12px}
.reg-head,.finding>details>summary{display:grid;grid-template-columns:9% 9% 14% 9% 10% minmax(0,1fr) 18%;gap:12px;padding:12px}
.reg-head{font-size:11px;font-weight:700;letter-spacing:.06em;border-bottom:1px solid var(--text)}
.finding{border-bottom:1px solid var(--line)}
.finding:last-child{border-bottom:0}
.finding>details>summary{list-style:none;cursor:pointer;font-weight:400}
.finding>details>summary::-webkit-details-marker{display:none}
.finding>details>summary:hover{background:var(--tint)}
.reg-title{font-weight:700;min-width:0}
.reg-meta{font-size:13px}
.toggle-label{display:block;font-size:11px;font-weight:400;color:var(--accent);margin-top:4px}
.finding .open-label,.finding details[open] .closed-label{display:none}
.finding details[open] .open-label{display:inline}
details.excluded .reg-title>span:first-child{text-decoration:line-through}
.detail{background:var(--tint);padding:18px 24px}
.detail dl{display:grid;grid-template-columns:150px minmax(0,1fr);gap:8px 18px;margin:12px 0}
.detail dt{font-size:12px;color:var(--muted)}
.detail dd{margin:0;overflow-wrap:anywhere}
.detail dd ul.steps{margin:0;padding-left:0;list-style:none}
.action-guidance{margin-top:12px}
.action-guidance strong{font-family:var(--sans);font-size:13px}
.empty{padding:20px 12px;margin:0}
.plan{margin:6px 0;padding-left:22px}
.plan .batch{margin:10px 0}
.plan .batch ul{margin:4px 0;padding-left:18px}
.vh{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);clip-path:inset(50%);white-space:nowrap}
@media(max-width:850px){.reg-head{display:none}.finding>details>summary{grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;padding:14px}.finding>details>summary .vh{position:static;width:auto;height:auto;overflow:visible;clip:auto;clip-path:none;white-space:normal;display:block;color:var(--muted);font-size:10px;font-family:var(--sans)}.reg-title{grid-column:1/-1;grid-row:1}.reg-cat{grid-column:span 2}.detail{padding:16px}.detail dl{grid-template-columns:minmax(0,1fr);gap:3px}.detail dd{margin-bottom:10px}}
@media(max-width:480px){.detail-actions{flex-direction:column;align-items:flex-start}.legend{grid-template-columns:minmax(0,1fr);gap:3px}.legend dd{margin-bottom:8px}}
@media print{.filters-panel,.copy-finding,.toggle-label{display:none!important}.priority-item{break-inside:avoid}.finding{display:block!important}}
/* Application shell: the register is a <div> grid, not the kit's table, so its
   column heads and the focused finding get the shell's pinning and focus marks here.
   The page script sets --filters-h whenever the filter bar shows; without it there is none. */
.app-shell #decisions-section:focus,.app-shell #levels:focus,.app-shell #plan:focus,.app-shell #rules:focus,.app-shell #charts:focus{outline:0}
.app-shell .finding:focus-within>details>summary{background:var(--tint);box-shadow:inset 2px 0 0 var(--text)}
@media(min-width:1100px){.app-shell .reg-head{position:sticky;z-index:4;top:calc(var(--appbar-h) + var(--filters-h,0px));background:var(--bg)}}
@media print{.app-shell .finding:focus-within>details>summary{background:none;box-shadow:none}.app-shell .reg-head{position:static}}
"""
KIT_CSS = kit_style.dashboard_css()
# The kit's print palette, `html:root` (0,1,1), loses to its own dark rule
# `:root:not([data-theme="light"])` (0,2,0), so a dark system theme would print
# pale text on white. Its light palette is restated here at (0,2,1) until the
# kit fixes it upstream.
PRINT_CSS = ("@media print{html:root:not([data-theme=\"light\"]){"
             + re.search(r"^:root\{([^}]*)\}", KIT_CSS, re.M)[1] + "}}\n")
# The kit's scroll padding leaves a fixed allowance for its pinned filter bar
# and column heads. This register has more filters, which wrap to more rows, so
# a finding reached by its link or by j/k scrolls further by the difference,
# measured by the page script, and its summary row clears both bars.
KIT_PINNED = re.search(r"html\.app-shell\{scroll-padding-top:calc\(var\(--appbar-h\) \+ "
                       r"([0-9]+)px\)\}", KIT_CSS)[1]
PINNED_CSS = ("@media(min-width:1100px){.app-shell .finding,.app-shell .finding>details>summary{"
              "scroll-margin-top:calc("
              f"var(--filters-h,0px) + var(--head-h,44px) + 8px - {KIT_PINNED}px)}}}}\n")
CSS = KIT_CSS + DASHBOARD_CSS + PINNED_CSS + PRINT_CSS

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
// Search the recorded values, not the page's own labels and buttons.
function text(d){if(!searchCache.has(d)){var c=d.cloneNode(true);c.querySelectorAll('.vh,.toggle-label,.detail-actions,.action-guidance,.detail>p,dt').forEach(function(e){e.remove();});searchCache.set(d,c.textContent.toLowerCase());}return searchCache.get(d);}
function show(){var scope=v('f-scope'),term=q.value.trim().toLowerCase(),key=v('f-sort')==='severity'?'s':'p',pool=0,n=0;
items.slice().sort(function(a,b){return a.dataset[key]-b.dataset[key];}).forEach(function(d){list.appendChild(d);
var x=d.dataset.x==='1',inPool=scope==='all'||(scope==='excluded')===x;if(inPool)pool++;
d.hidden=!(inPool&&(!v('f-sev')||d.dataset.sev===v('f-sev'))&&(!v('f-rollout')||d.dataset.rollout===v('f-rollout'))&&(!v('f-effort')||d.dataset.effort===v('f-effort'))&&(!v('f-conf')||d.dataset.conf===v('f-conf'))&&(!v('f-cat')||d.dataset.cat===v('f-cat'))&&(!v('f-status')||d.dataset.status===v('f-status'))&&(!v('f-verdict')||d.dataset.verdict===v('f-verdict'))&&(!term||text(d).indexOf(term)>=0));if(!d.hidden)n++;});
byId('result-count').textContent=fmt(L.showing,{shown:n,total:pool});if(m){m.hidden=n>0;m.textContent=pool?L.no_matches:L.no_records;}syncFacets();}
function reset(){['f-sev','f-rollout','f-effort','f-conf','f-cat','f-status','f-verdict'].forEach(function(id){byId(id).value='';});byId('f-scope').value='included';byId('f-sort').value='priority';q.value='';}
// Sidebar facets: a press filters the included findings by severity, a second press clears it.
var facets=Array.prototype.slice.call(document.querySelectorAll('.facet'));
function syncFacets(){facets.forEach(function(b){b.setAttribute('aria-pressed',String(v('f-scope')==='included'&&v('f-sev')===b.dataset.sev));});}
facets.forEach(function(b){b.onclick=function(){var on=b.getAttribute('aria-pressed')==='true';byId('f-scope').value='included';byId('f-sev').value=on?'':b.dataset.sev;show();byId('findings').scrollIntoView();};});
if(list&&q){document.querySelectorAll('.filters select').forEach(function(s){s.onchange=function(){if(s.id==='f-verdict'&&s.dataset.excluded.split(' ').indexOf(s.value)>=0)byId('f-scope').value='all';show();};});
var timer=null;q.oninput=function(){clearTimeout(timer);timer=setTimeout(show,items.length>300?150:0);};
byId('reset').onclick=function(){reset();show();};show();}
// The register's column heads pin below the filter bar, whose height depends on the language and viewport; a finding scrolled to clears both.
// Measured now too, before a link's finding is scrolled to: the browser's own jump to it while loading would use the defaults.
var panel=document.querySelector('.filters-panel'),head=document.querySelector('.reg-head');
function pin(){var s=byId('findings').style;s.setProperty('--filters-h',panel.offsetHeight+'px');s.setProperty('--head-h',head.offsetHeight+'px');}
if(panel){pin();if(window.ResizeObserver){var pins=new ResizeObserver(pin);pins.observe(panel);pins.observe(head);}}
function hashed(){var h;try{h=decodeURIComponent(location.hash.slice(1));}catch(e){return null;}var d=byId(h)||byId(h.toLowerCase());return d&&d.classList.contains('finding')?d:null;}
function openHash(){var d=hashed();if(!d)return;if(d.hidden){reset();if(d.dataset.x==='1')byId('f-scope').value='all';show();}d.querySelector('details').open=true;d.scrollIntoView({block:'start'});d.querySelector('summary').focus({preventScroll:true});}
window.addEventListener('hashchange',openHash);
// The browser's own jump to the fragment, while the page loads, moves focus to the body: focus the summary again once loaded.
if(location.hash){openHash();if(document.readyState!=='complete')window.addEventListener('load',function(){var d=hashed();if(d)d.querySelector('summary').focus({preventScroll:true});},{once:true});}
document.addEventListener('click',function(e){var a=e.target.closest('a[href^="#finding-"]');if(a&&a.getAttribute('href')===location.hash){e.preventDefault();openHash();}});
// A denied or unavailable Clipboard API falls back to the selection copy.
function copyFallback(value){return new Promise(function(resolve,reject){var prev=document.activeElement,t=document.createElement('textarea');t.value=value;t.readOnly=true;t.style.position='fixed';t.style.top='0';t.style.left='-9999px';document.body.appendChild(t);t.select();var ok=false;try{ok=document.execCommand('copy');}catch(err){}t.remove();if(prev&&prev.focus)prev.focus({preventScroll:true});if(ok)resolve();else reject(new Error('copy'));});}
function copyText(value){if(navigator.clipboard&&window.isSecureContext)return navigator.clipboard.writeText(value).catch(function(){return copyFallback(value);});return copyFallback(value);}
document.querySelectorAll('.copy-finding').forEach(function(b){var t;b.onclick=function(){var done=function(label){b.textContent=label;clearTimeout(t);t=setTimeout(function(){b.textContent=L.copy_llm;},2000);};copyText(COPY[b.dataset.copy]).then(function(){done(L.copied);},function(){done(L.copy_failed);});};});
// Printing shows and opens every finding, then restores the filtered view.
var shut=[];addEventListener('beforeprint',function(){shut=[];items.forEach(function(f){var d=f.querySelector('details');if(!d.open)shut.push(d);f.hidden=false;d.open=true;});if(m)m.hidden=true;});
addEventListener('afterprint',function(){shut.forEach(function(d){d.open=false;});if(list&&q)show();});
// Keyboard: "/" searches, j/k step through the visible findings (Enter on the focused title toggles it), Escape clears the search.
document.addEventListener('keydown',function(e){if(e.altKey||e.ctrlKey||e.metaKey||e.isComposing||!list||!q)return;var t=e.target;if(t&&t.closest&&t.closest('input,select,textarea')){if(e.key==='Escape'&&t===q&&q.value){q.value='';show();}return;}
if(e.key==='/'){e.preventDefault();q.focus();}else if(e.key==='j'||e.key==='k'){var shown=items.filter(function(d){return !d.hidden;}).map(function(d){return d.querySelector('summary');}),current=document.activeElement&&document.activeElement.closest('.finding');if(!shown.length)return;
var at=shown.findIndex(function(s){return s.closest('.finding')===current;}),next=at<0?0:Math.min(shown.length-1,Math.max(0,at+(e.key==='j'?1:-1)));e.preventDefault();shown[next].focus();shown[next].scrollIntoView({block:'nearest'});}});
// Mark the section in view in the sidebar contents.
var navLinks=Array.prototype.slice.call(document.querySelectorAll('#nav a[href^="#"]'));if(window.IntersectionObserver){var visible=new Map(),spy=new IntersectionObserver(function(entries){entries.forEach(function(en){visible.set(en.target.id,en.isIntersecting);});var first=navLinks.find(function(a){return visible.get(a.getAttribute('href').slice(1));});navLinks.forEach(function(a){if(a===first)a.setAttribute('aria-current','location');else a.removeAttribute('aria-current');});},{rootMargin:'-35% 0px -60% 0px'});navLinks.forEach(function(a){var s=byId(a.getAttribute('href').slice(1));if(s)spy.observe(s);});}
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


# Fixed English vocabulary: the values findings.json allows for its enums.
ENGLISH = re.compile("(?<![A-Za-z-])(" + "|".join(sorted(map(re.escape, {
    *SEVERITIES, *ROLLOUTS, *CONFIDENCES, *VERDICTS, *STATUSES, *NETS, *PERSPECTIVES,
    *PERSPECTIVE_STATUSES, *CONVENTION_STATUSES, *REMEDIES, *METHODS}), key=len,
    reverse=True)) + ")(?![A-Za-z-])")


def mark_english(rendered):
    """Mark the fixed English words inside an escaped Japanese UI string."""
    return ENGLISH.sub(lambda m: f"<span lang='en'>{m[0]}</span>", rendered)


def plural(d, key, n, **values):
    text = d[key + "_one"] if n == 1 and key + "_one" in d else d[key]
    return text.format(n=n, **values)


def is_excluded(f):
    return f["validation"]["verdict"] in EXCLUDED


def action(f):
    """Ready only when Valid, Confirmed and Online; Valid and Confirmed otherwise is staged."""
    if f["validation"]["verdict"] != "Valid" or f["confidence"] != "Confirmed":
        return "verify_first"
    return "fix_now" if f["rollout"] == "Online" else "pin_first"


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
    for label, value in (("severity", f["severity"]), ("rollout", f["rollout"]),
                         ("effort", f["effort"]), ("confidence", f["confidence"]),
                         ("verdict", f"{v['verdict']} ({v['method']})"),
                         ("status", f.get("status", "Open")), ("category", category(f)),
                         ("remedy", f"{f['remedy']} ({f['hazard']})"),
                         ("location", ", ".join(as_locations(f["location"])))):
        out.append(f"- {DASH[lang].get(label, t.get(label))}: {one(value)}")
    for key in ("depends_on", "convention"):
        if filled(f, key):
            out.append(f"- {t[key]}: {one(f[key])}")
    blocks = [(t[k], field_text(f, k, lang)) for k in FIELDS
              if k not in ("location", "hazard", "remedy", "depends_on", "convention")
              and filled(f, k)]
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


def bars(order, counter, colored=False, lang_attr=""):
    top = max([counter.get(k, 0) for k in order] + [1])
    return "".join(
        f"<div class='bar'><span class='t'{lang_attr}>{html_text(k)}</span><span class='track'>"
        f"<span class='fill{' ' + k if colored else ''}' data-w='{counter.get(k, 0) * 100 // top}'>"
        f"</span></span><span class='v'>{counter.get(k, 0)}</span></div>" for k in order)


def tally(findings, key):
    out = {}
    for f in findings:
        out[key(f)] = out.get(key(f), 0) + 1
    return out


def options(values, first=None, lang_attr=""):
    head = f"<option value=''>{html_text(first)}</option>" if first else ""
    return head + "".join(f"<option value='{escape(as_text(value))}'{lang_attr}>{html_text(label)}</option>"
                          for value, label in values)


def bullet_list(items, empty):
    if not items:
        return f"<p class='muted'>{html_text(empty)}</p>"
    return "<ul>" + "".join(f"<li>{html_text(i)}</li>" for i in items) + "</ul>"


def render_html(doc, lang):
    t, d = LABELS[lang], DASH[lang]
    e = html_text
    # Severity, rollout, status, verdict and perspective names stay English on the
    # Japanese page; badges, register cells, filters and charts mark them so a
    # screen reader reads them in English (WCAG 3.1.2).
    en = " lang='en'" if lang != "en" else ""

    def ui(text):  # a UI string that may name the English vocabulary
        return mark_english(e(text)) if en else e(text)
    meta, findings = doc["meta"], doc.get("findings", [])
    by_sev, excluded = counts(findings)
    included = [f for f in findings if not is_excluded(f)]
    status = {f["id"]: f.get("status", "Open") for f in findings}
    open_ = [f for f in included if status[f["id"]] == "Open"]
    open_hm = sum(f["severity"] in ("High", "Medium") for f in open_)
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    queue = sorted(open_, key=lambda f: (rank[f["severity"]], action(f) != "fix_now", f["id"]))
    fix_now = sum(action(f) == "fix_now" for f in open_)
    pending = sum(f["validation"]["verdict"] not in DEFINITIVE for f in included)

    nav = [("overview", d["nav_summary"]), ("priority-section", d["priority"]),
           ("decisions-section", t["decisions"]), ("coverage", d["coverage_heading"]),
           ("levels", t["legend"]), ("plan", t["plan"])]
    nav += [("rules", t["conventions"])] if doc.get("conventions") else []
    nav += [("charts", d["overview"]), ("findings", d["findings_register"]), ("lists", d["nav_lists"])]
    # Facets and keys drive the register's filters, so they appear only with it, like the filters.
    tools = ""
    if findings:
        tools = (f"<div class='facets' data-js hidden><h2 class='nav-title'>{e(d['severity'])}</h2>"
                 + "".join(f"<button type='button' class='facet' data-sev='{s}' aria-controls='register-list' "
                           f"aria-pressed='false'><span class='facet-name {s}'{en}>{s}</span>"
                           f"<span class='facet-n'>{by_sev[s]}</span></button>" for s in SEVERITIES)
                 + f"</div><dl class='keys' data-js hidden><dt class='nav-title'>{e(d['shortcuts'])}</dt>"
                 f"<dd><kbd>/</kbd> {e(d['key_search'])}</dd>"
                 f"<dd><kbd>j</kbd> <kbd>k</kbd> {e(d['key_move'])}</dd>"
                 f"<dd><kbd>Enter</kbd> {e(d['key_toggle'])}</dd></dl>")
    out = [f"<!doctype html><html lang='{lang}' class='app-shell'><head><meta charset='utf-8'>",
           f"<meta http-equiv='Content-Security-Policy' content=\"{CSP}\">",
           "<meta name='viewport' content='width=device-width,initial-scale=1'>",
           f"<title>{escape(t['title'])}: {escape(' '.join(as_text(meta.get('project', '')).split()))}</title>"
           f"<style>{CSS}</style></head><body>",
           f"<a class='skip' href=\"#findings\">{e(d['jump_findings'])}</a>",
           f"<header class='appbar'><div class='appbar-in'><span class='brand'><span{en}>{e(d['eyebrow'])}</span>"
           f"<span class='appbar-project'>{e(meta.get('project', ''))}</span></span><div class='tools'>"
           f"<a class='button' href=\"report.md\">{e(d['report_link'])}</a>"
           f"<button type='button' id='theme' data-js hidden>{e(d['theme'])}</button></div></div></header>",
           f"<div class='shell'><nav class='sidebar' id='nav' aria-label='{e(d['contents'])}'>"
           f"<h2 class='nav-title'>{e(d['contents'])}</h2><ol class='nav-links'>"
           + "".join(f"<li><a href=\"#{i}\">{e(label)}</a></li>" for i, label in nav) + f"</ol>{tools}</nav>",
           "<main><section id='overview' tabindex='-1' aria-labelledby='h'>",
           f"<div class='hero'><div><div class='eyebrow'>{e(t['title'])}</div>"
           f"<h1 id='h'>{e(meta.get('project', ''))}</h1>"
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
    out.append(f"<div class='summary-banner'><strong>{ui(headline)}</strong>"
               f"<p>{ui(detail) if included else e(review_method(doc, lang))}</p></div>")

    closed = "".join(f"<span class='pair'>{sum(status[f['id']] == s for f in included)}"
                     f"<span class='u'{en}>{s}</span></span>" for s in ("Fixed", "Accepted"))
    cards = [(d["open_hm"], open_hm, "urgent", f"{d['open_count']}: {len(open_)}"),
             (d["needs_validation"], len(open_) - fix_now, "review", f"{d['fix_now']}: {fix_now}"),
             (d["closed_count"], closed, "", f"{d['included']}: {len(included)}"),
             (t["excluded"], excluded, "", f"{d['all_records']}: {len(findings)}")]
    out.append("<div class='cards'>" + "".join(
        f"<div class='card {cls}'><span class='l'>{ui(label)}</span><div class='n'>{n}</div>"
        f"<div class='sub'>{e(sub)}</div></div>" for label, n, cls, sub in cards) + "</div>")
    out.append(f"<p class='report-note'>{ui(d['counts_note'])}</p></section>")

    # The priority queue: every open High, at least four items, at most twelve.
    highs = sum(f["severity"] == "High" for f in queue)
    top = queue[:max(4, min(highs, 12))]
    out.append(f"<section id='priority-section' tabindex='-1' aria-labelledby='priority-heading'>"
               f"<div class='section-head'><div>"
               f"<h2 id='priority-heading'>{e(d['priority'])}</h2><p>{e(d['priority_note'])}</p></div>"
               f"<a href=\"#findings\">{e(d['view_all'])}</a></div>")
    for a in ("pin_first", "verify_first"):
        if any(action(f) == a for f in top):
            out.append(f"<p class='section-note'><span class='action-label'>{e(d[a])}</span> "
                       f"{ui(d[a + '_note'])}</p>")
    if top:
        out.append("<div class='priority-list'>")
        for f in top:
            a = action(f)
            item = [f"<article class='panel priority-item sev-{f['severity']}'><div class='priority-top'>"
                    f"<span class='badge {f['severity']}'{en}>{f['severity']}</span>"
                    f"<span class='action-label'>{e(d[a])}</span></div>"
                    f"<h3><a href=\"#{anchor(f)}\">{e(f['id'])} · {e(f['title'])}</a></h3>"
                    f"<div class='verdict'{en}>{e(f['rollout'])} · {e(f['effort'])} · {e(f['confidence'])} · "
                    f"{e(f['validation']['verdict'])} · {e(f['remedy'])}</div>",
                    "".join(f"<code class='location'>{e(p)}</code>" for p in as_locations(f["location"])),
                    f"<p>{e(f['impact'])}</p>" if filled(f, "impact") else ""]
            if a == "fix_now":
                item.append(f"<p class='action'>{e(f['fix']) if filled(f, 'fix') else e(d['missing_fix'])}</p>")
            out.append("".join(item) + "</article>")
        out.append("</div>")
    else:
        out.append(f"<p class='panel muted'>{ui(d['no_open'] if included else d['no_findings'])}</p>")
    hidden_high = highs - sum(f["severity"] == "High" for f in top)
    if hidden_high > 0:
        out.append(f"<p class='section-note'>{ui(plural(d, 'more_high', hidden_high))}</p>")
    if len(top) < len(queue):
        out.append(f"<p class='section-note'>{e(d['queue_more'].format(shown=len(top), total=len(queue)))}</p>")
    out.append("</section>")

    out.append(f"<section class='panel' id='decisions-section' tabindex='-1'><h2>{e(t['decisions'])}</h2>"
               f"<div id='decisions'>"
               f"{bullet_list(doc.get('decisions', []), t['none'])}</div></section>")

    rows = perspective_rows(doc, lang)
    applied = sum(p["status"] == "applied" for _, p in rows)
    limitations = doc.get("limitations", [])
    window = (f"<dt>{e(t['window'])}</dt><dd>{e(meta['window'])}</dd>"
              if filled(meta, "window") else "")
    if meta.get("axis") in ("confirmed", "assumed"):
        window += f"<dt>{e(t['axis'])}</dt><dd>{e(t['axis_' + meta['axis']])}</dd>"
    out.append(f"<section class='panel coverage' id='coverage' tabindex='-1'><h2>{e(d['coverage_heading'])}<span class='small'>"
               f"{e(d['limitations_count'])}: {len(limitations)}</span></h2>"
               f"<p>{ui(d['coverage_note'])}</p><dl class='scope-meta'>"
               f"<dt>{e(t['scope_row'])}</dt><dd>{e(meta.get('scope', ''))}</dd>"
               f"<dt>{e(d['method_row'])}</dt><dd>{e(review_method(doc, lang))}</dd>"
               f"<dt>{e(t['revision'])}</dt><dd>{e(revision(meta))}</dd>{window}</dl>"
               f"<h3>{e(t['limitations'])}</h3>{bullet_list(limitations, d['limitations_empty'])}"
               f"<h3 id='perspectives-heading'>{e(t['perspectives'])}</h3><p class='section-note'>"
               f"{e(d['perspective_count'].format(applied=applied, total=len(rows)))}</p>"
               f"<div class='tablewrap' tabindex='0' role='region' aria-labelledby='perspectives-heading'>"
               f"<table class='coverage-table'><thead><tr><th>{e(t['perspective'])}</th>"
               f"<th>{e(t['rule_status'])}</th><th>{e(t['note'])}</th></tr></thead><tbody>")
    for name, p in rows:
        out.append(f"<tr><td{en}>{e(name)}</td><td{en}>{e(p['status'])}</td><td>{e(p['note'])}</td></tr>")
    out.append("</tbody></table></div></section>")

    scales, closing = legend(doc, lang)
    out.append(f"<section class='panel' id='levels' tabindex='-1'><h2>{e(t['legend'])}</h2>")
    for heading, levels in scales:
        out.append(f"<h3>{e(heading)}</h3><dl class='legend'>" + "".join(
            f"<dt><span class='badge {level}'{en}>{level}</span></dt><dd>{ui(meaning)}</dd>"
            if level in SEVERITIES else f"<dt{en}>{e(level)}</dt><dd>{ui(meaning)}</dd>"
            for level, meaning in levels) + "</dl>")
    out.append("".join(f"<p class='section-note'>{ui(line)}</p>" for line in closing) + "</section>")

    out.append(f"<section class='panel' id='plan' tabindex='-1'><h2>{e(t['plan'])}</h2><p class='section-note'>"
               f"{e(d['plan_note'])}</p>")
    if doc.get("plan"):
        out.append("<ol class='plan'>")
        for b in doc["plan"]:
            links = "".join(f"<li><a href=\"#finding-{escape(fid.lower())}\">{e(item)}</a></li>"
                            for fid, item in zip(b["findings"], batch_findings(b, findings)))
            out.append(f"<li class='batch'><strong>{e(t['batch'])} {b['batch']}: {e(b['title'])}</strong>"
                       f"<div class='small'>{e(t['pr_title'])}: {e(b['pr_title'])} · "
                       f"{e(t['prerequisite'])}: {e(b['prerequisite'])}</div><ul>{links}</ul></li>")
        out.append("</ol>")
    else:
        out.append(f"<p class='muted'>{e(t['none'])}</p>")
    out.append("</section>")

    if doc.get("conventions"):
        out.append(f"<section class='panel' id='rules' tabindex='-1'><h2 id='rules-heading'>{e(t['conventions'])}</h2>"
                   f"<p class='section-note'>{e(d['rules_note'])}</p><div class='tablewrap' tabindex='0' "
                   "role='region' aria-labelledby='rules-heading'><table class='rules'><thead><tr>"
                   f"<th>{e(t['id'])}</th><th>{e(t['idiom'])}</th><th>{e(t['source'])}</th>"
                   f"<th>{e(t['rule_status'])}</th></tr></thead><tbody>")
        for r in doc["conventions"]:
            state = f"<span{en}>{e(r['status'])}</span>" if en else e(r["status"])
            if filled(r, "reason"):
                state += f"<br>{e(t['reason'])}: {e(r['reason'])}"
            out.append(f"<tr><td class='nowrap'>{e(convention_id(r))}</td><td>{e(convention_idiom(r, lang))}</td>"
                       f"<td>{e(r['source'])}</td><td>{state}</td></tr>")
        out.append("</tbody></table></div></section>")

    cats = sorted(tally(included, lambda f: f["category"]).items(), key=lambda kv: (-kv[1], kv[0]))
    out.append(f"<section class='panel' id='charts' tabindex='-1'><h2>{e(d['overview'])}</h2><p class='section-note'>"
               f"{e(d['count_basis'])}</p><div class='grid'>"
               f"<div><h3>{e(d['by_sev'])}</h3>{bars(SEVERITIES, by_sev, True, en)}</div>"
               f"<div><h3>{e(d['by_rollout'])}</h3>{bars(ROLLOUTS, tally(included, lambda f: f['rollout']), lang_attr=en)}</div>"
               f"<div><h3>{e(d['by_conf'])}</h3>{bars(CONFIDENCES, tally(included, lambda f: f['confidence']), lang_attr=en)}</div>"
               f"<div><h3>{e(d['by_cat'])}</h3>{bars([k for k, _ in cats], dict(cats), lang_attr=en)}</div>"
               f"<div><h3>{e(d['by_status'])}</h3>{bars(STATUSES, tally(included, lambda f: status[f['id']]), lang_attr=en)}</div>"
               f"<div><h3>{e(d['by_verdict'])}</h3>{bars(VERDICTS, verdict_counts(findings), lang_attr=en)}"
               f"<p class='section-note'>{ui(d['excluded_note'])}</p></div></div></section>")

    out.append(f"<section id='findings' tabindex='-1' aria-labelledby='findings-heading'><div class='section-head'><div>"
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
            + options([(s, s) for s in SEVERITIES], t["all"], en) + "</select></label>"
            f"<label><span>{e(d['rollout'])}</span><select id='f-rollout'>"
            + options([(r, r) for r in ROLLOUTS], t["all"], en) + "</select></label>"
            f"<label><span>{e(d['effort'])}</span><select id='f-effort'>"
            + options([(x, x) for x in EFFORTS], t["all"], en) + "</select></label>"
            f"<label><span>{e(d['confidence'])}</span><select id='f-conf'>"
            + options([(c, c) for c in CONFIDENCES], t["all"], en) + "</select></label>"
            f"<label><span>{e(d['category'])}</span><select id='f-cat'>"
            + options([(c, c) for c in all_cats], t["all"], en) + "</select></label>"
            f"<label><span>{e(d['status'])}</span><select id='f-status'>"
            + options([(s, s) for s in STATUSES], t["all"], en) + "</select></label>"
            f"<label><span>{e(d['verdict'])}</span><select id='f-verdict' data-excluded='{excluded_values}'>"
            + options([(v, v) for v in VERDICTS], t["all"], en) + "</select></label>"
            f"<label><span>{e(d['sort'])}</span><select id='f-sort'>"
            + options([("priority", d["priority_sort"]), ("severity", d["severity_sort"])]) + "</select></label>"
            f"<label class='search'><span>{e(d['search'])}</span><input id='f-q' type='search' "
            f"placeholder='{escape(d['search'])}'></label></div><div class='filter-bottom'>"
            "<p class='result-count' id='result-count' role='status' aria-live='polite'></p>"
            f"<button type='button' id='reset'>{e(d['reset'])}</button></div></div>")
    heads = ("ID", d["severity"], d["rollout"], d["status"], d["verdict"], d["title_col"], d["category"])
    out.append("<div class='register'><div class='reg-head' aria-hidden='true'>"
               + "".join(f"<span>{e(h)}</span>" for h in heads) + "</div><div id='register-list'>")
    if not findings:
        out.append(f"<p class='empty'>{e(t['none'])}</p>")
    else:
        # Shown by the filter when it leaves no finding visible.
        out.append(f"<p class='empty' data-empty hidden>{e(d['no_matches'])}</p>")

    def priority(f):
        return (status[f["id"]] != "Open", rank[f["severity"]], action(f) != "fix_now", f["id"])

    def column(label):
        # The header row is hidden from screen readers, so each cell names its
        # column; the narrow layout shows the same label.
        return f"<span class='vh'>{e(label)} </span>"

    p_order = {f["id"]: i for i, f in enumerate(sorted(findings, key=priority))}
    s_order = {f["id"]: i for i, f in enumerate(sorted(findings, key=lambda f: (rank[f["severity"]], f["id"])))}
    copy = {}
    for f in findings:
        v = f["validation"]
        x = is_excluded(f)
        copy[f["id"]] = finding_markdown(f, lang)
        def word(text):  # fixed English vocabulary
            return f"<span{en}>{e(text)}</span>" if en else e(text)

        fields = [(t["category"], word(category(f))),
                  (d["rollout"], f"{word(f['rollout'])} · {e(d['effort'])} {word(f['effort'])} · "
                              f"{word(f['confidence'])}")]
        def value(k):
            if k == "remedy":
                return word(f[k])
            if k == "enforcement":  # net and a `none` gap are vocabulary; the rest is text
                s = f[k]
                gaps = word(s["gaps"]) if s["gaps"].strip() == "none" else e(s["gaps"])
                return (f"{word(s['net'])} · {e(t['sites'])}: {e(', '.join(s['sites']) or '—')}"
                        f" · {e(t['gaps'])}: {gaps}")
            if k in LIST_FIELDS:  # one item per entry, so an entry's own line break is not a new one
                return "<ul class='steps'>" + "".join(f"<li>{e(i)}</li>" for i in f[k]) + "</ul>"
            return e(field_text(f, k, lang))

        fields += [(t[k], value(k)) for k in FIELDS if filled(f, k)]
        fields.append((t["verdict"], word(f"{v['verdict']} ({v['method']})")))
        if filled(v, "evidence"):
            fields.append((t["evidence"], e(v["evidence"])))
        fields.append((t["status"], word(status[f["id"]])))
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
                        f"<p>{ui(d[a + '_note'])}</p></div>")
        elif x:
            guidance = f"<p class='muted'>{ui(d['excluded_note'])}</p>"
        # Excluded findings are not in the severity counts, so not in their filters.
        group = "excluded' class='excluded" if x else f["severity"]
        attrs = {"sev": f["severity"], "rollout": f["rollout"], "effort": f["effort"],
                 "conf": f["confidence"], "cat": f["category"],
                 "status": status[f["id"]], "verdict": v["verdict"], "x": "1" if x else "0",
                 "p": p_order[f["id"]], "s": s_order[f["id"]]}
        data = "".join(f" data-{k}='{escape(as_text(val))}'" for k, val in attrs.items())
        locations = "".join(f"<code class='location'>{e(p)}</code>" for p in as_locations(f["location"]))
        out.append(
            f"<div class='finding' id='{anchor(f)}'{data}><details data-sev='{group}'><summary>"
            f"<span>{column('ID')}{e(f['id'])}</span>"
            f"<span>{column(d['severity'])}<span class='badge {f['severity']}'{en}>{f['severity']}</span></span>"
            f"<span class='reg-meta'>{column(d['rollout'])}<span{en}>{e(f['rollout'])} · {e(f['effort'])}</span></span>"
            f"<span class='reg-meta'>{column(d['status'])}<span{en}>{e(status[f['id']])}</span></span>"
            f"<span class='reg-meta'>{column(d['verdict'])}<span{en}>{e(v['verdict'])}</span></span>"
            f"<span class='reg-title'><span>{e(f['title'])}</span>{locations}"
            f"<span class='toggle-label' aria-hidden='true'><span class='closed-label'>{e(d['expand'])}</span>"
            f"<span class='open-label'>{e(d['collapse'])}</span></span></span>"
            f"<span class='reg-meta reg-cat'>{column(d['category'])}<span{en}>{e(f['category'])}</span></span>"
            f"</summary><div class='detail'><div class='detail-actions'><strong>{e(f['id'])} · {e(f['title'])}</strong>"
            f"<span class='detail-links'><button type='button' class='copy-finding' data-js hidden "
            f"data-copy='{escape(f['id'])}' aria-live='polite'>{e(d['copy_llm'])}</button>"
            f"<a href=\"#{anchor(f)}\">{e(d['permalink'])}</a></span></div>{guidance}<dl>"
            + "".join(f"<dt>{e(k)}</dt><dd>{val}</dd>" for k, val in fields) + "</dl></div></details></div>")
    out.append("</div></div></section>")

    out.append("<div class='lists' id='lists' tabindex='-1'>" + "".join(
        f"<section class='panel'><h2>{e(t[k])}</h2>{bullet_list(doc.get(k, []), t['none'])}</section>"
        for k in ("next_steps", "checked_ok")) + "</div>")
    out.append(f"<footer class='footer'>{e(d['footer'])}</footer></main></div>")
    labels = {k: d[k] for k in ("showing", "no_matches", "no_records", "copy_llm", "copied",
                                "copy_failed")}
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
    parser.add_argument("findings", type=nonempty)
    parser.add_argument("--out", required=True, type=nonempty)
    parser.add_argument("--lang", choices=("ja", "en"))
    args = parser.parse_args(argv)
    out = Path(args.out)
    try:
        # The record is read twice, here and under the lock: a pipe or other
        # one-shot stream would be empty the second time.
        record = Path(args.findings)
        if record.exists() and not record.is_file():
            raise SchemaError(f"{args.findings}: not a regular file; save the record to a file")
        # A bad record is refused before anything is created.
        validate(read_json(args.findings), complete=True)
        # A write follows a link: a planted one would send the outputs outside
        # the run, so neither the directory nor an output may be one.
        if out.is_symlink():
            raise OSError(f"{out} is a symlink; render into a plain, new directory")
        out.mkdir(parents=True, exist_ok=True)
        # Read again, render and write under the lock merge and check take on
        # the output directory (where the record usually is): a merge that
        # lands while render waits is what render writes. Both outputs are
        # staged before either replaces the previous file.
        with locked_dir(out):
            doc = read_json(args.findings)
            validate(doc, complete=True)
            for name in ("dashboard.html", "report.md"):
                if (out / name).is_symlink():
                    raise OSError(f"{out / name} is a symlink; remove it, then render again")
            outputs = rendered_outputs(doc, args.lang or doc["meta"]["lang"])
            _atomic_write_all({out / name: data for name, data in outputs.items()})
    except SchemaError as exc:
        print(f"schema: {shown_line(exc)}", file=sys.stderr)
        return 2
    except (OSError, RuntimeError) as exc:
        print(f"write failed: {shown_line(exc)}", file=sys.stderr)
        return 1
    print(f"wrote {out / 'dashboard.html'} and {out / 'report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(run(main))
