#!/usr/bin/env python3
"""Render findings.json into dashboard.html, report.html and report.pdf.

    python3 render.py FINDINGS --out DIR [--lang ja|en] [--repo REPO] [--no-pdf]

With --repo, each finding's `location` excerpt is embedded, read and redacted as excerpt.py describes
(the commit's blob for a scan of a clean tree, else the working tree; credential-shaped values masked;
credential files never quoted). The record is checked against record.py's schema first.
--lang defaults to `meta.lang`, else ja. Styles, PDF printing and safe writes come from
report_style.py, report_pdf.py and report_output.py: the PDF is printed by headless
Chrome/Chromium (CHROME overrides the path), else WeasyPrint, each within
PROMPT_SCAN_PDF_TIMEOUT seconds (default: 120 plus 0.05 per finding, at most 900).

Exit codes: 0 written, 2 unreadable input or schema error, 3 HTML written but
no PDF (no engine, or the engine failed; the message says which).
"""
import argparse
from collections import Counter
import hashlib
import html
import json
from pathlib import Path
import re
import sys

# The report modules sit next to this script; -I and PYTHONSAFEPATH leave the script's directory off sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import report_pdf, report_style  # noqa: E402
from report_output import unsafe_target, write_output  # noqa: E402
# The record's vocabulary and schema, and the excerpt rules, are shared with the other tools.
from record import (CONFIDENCES, EXCLUDED, KINDS, SEVERITIES, STATUSES, STRING_LISTS,  # noqa: E402
                    VERDICTS, SchemaError, id_key, load)
from excerpt import attach_sources, mask  # noqa: E402

STAMP = '<meta name="prompt-scan-source" content="sha256:{}">'

PERSPECTIVE_NAMES_JA = {
    "Task and intent": "タスクと意図",
    "Instruction consistency": "指示の一貫性",
    "Structure and placement": "構成と配置",
    "Variables and assembly": "変数と組み立て",
    "Output contract": "出力契約",
    "Examples": "入出力例",
    "Tools and agents": "ツールとエージェント",
    "Untrusted input": "信頼できない入力",
    "Safety and refusal": "安全性と拒否応答",
    "Context budget": "コンテキスト予算",
    "Model and parameters": "モデルとパラメータ",
    "Language and tone": "言語と文体",
    "Evaluation": "評価とテスト",
    "Maintainability": "保守性",
}


def perspective_label(name, L):
    """Display name for a perspective or finding category; English passes through unchanged."""
    names = L.get("perspective_names")
    return names.get(name, name) if names else name


LABELS = {
    "en": {
        "title": "Prompt review report", "dashboard": "Prompt review dashboard",
        "target": "Target", "commit": "Revision", "dirty": "uncommitted changes present",
        "dirty_unknown": "uncommitted changes not determined", "date": "Date",
        "assessor": "Assessor", "scope": "Scope", "abstract": "Summary",
        "axis": "Severity axis", "axis_confirmed": "confirmed by the requester",
        "axis_assumed": "assumed; not confirmed by the requester",
        "summary_line": "{total} findings ({defects} defects, {improvements} improvements); "
                        "{high} High, {medium} Medium. {excluded} excluded with evidence.",
        "table_counts": "Findings by severity and kind",
        "running_footer": "PROMPT REVIEW", "cap_inventory": "Prompts in scope",
        "cap_perspectives": "Coverage by perspective", "cap_evals": "Eval runs against findings",
        "severity": "Severity", "kind": "Kind", "total": "Total",
        "defect": "Defect", "improvement": "Improvement",
        "s_inventory": "Prompt inventory", "s_perspectives": "Perspectives", "s_findings": "Findings",
        "s_sound": "Checked and sound", "s_evals": "Eval runs", "s_decisions": "Decisions for a human",
        "s_limitations": "Limitations", "s_next": "Next steps",
        "id": "ID", "name": "Name", "location": "Location", "consumer": "Consumer", "model": "Model",
        "inputs": "Inputs", "output": "Output", "result": "Result", "note": "Note", "perspective": "Perspective",
        "prompt": "Prompt", "confidence": "Confidence", "verdict": "Verdict", "status": "Status",
        "symptom": "Symptom", "cause": "Cause", "impact": "Impact", "fix": "Fix direction",
        "proposal": "Proposal", "before": "Before", "after": "After", "test": "Eval / test assertion",
        "evidence": "Verdict evidence", "references": "References", "excerpt": "Excerpt",
        "previous": "Earlier review (before rescan)", "source": "Source",
        "cases": "Cases", "passed": "Passed", "failed": "Failed", "finding": "Finding",
        "none": "None recorded.", "all": "All", "search": "Search", "excluded": "Excluded",
        "no_match": "No finding matches the filters.",
        "kinds": {"defect": "Defect", "improvement": "Improvement"},
        "results": {"applied": "applied", "N/A": "N/A", "not checked": "not checked"},
    },
    "ja": {
        "title": "プロンプト診断レポート", "dashboard": "プロンプト診断ダッシュボード",
        "target": "対象", "commit": "リビジョン", "dirty": "未コミットの変更あり",
        "dirty_unknown": "未コミットの変更は未確認", "date": "診断日",
        "assessor": "診断者", "scope": "範囲", "abstract": "要旨",
        "axis": "深刻度の軸", "axis_confirmed": "依頼者が確認済み", "axis_assumed": "仮定（依頼者は未確認）",
        "summary_line": "指摘 {total} 件（不具合 {defects} 件、改善提案 {improvements} 件）。"
                        "High {high} 件、Medium {medium} 件。根拠付きで除外 {excluded} 件。",
        "table_counts": "深刻度と種別ごとの指摘数",
        "running_footer": "プロンプト診断", "cap_inventory": "対象プロンプト",
        "cap_perspectives": "観点ごとの確認結果", "cap_evals": "指摘ごとの評価実行",
        "severity": "深刻度", "kind": "種別", "total": "合計",
        "defect": "不具合", "improvement": "改善提案",
        "s_inventory": "プロンプト一覧", "s_perspectives": "観点", "s_findings": "指摘",
        "s_sound": "確認して問題がなかった項目", "s_evals": "評価の実行記録", "s_decisions": "判断が必要な事項",
        "s_limitations": "制約事項", "s_next": "次のステップ",
        "id": "ID", "name": "名前", "location": "場所", "consumer": "利用箇所", "model": "モデル",
        "inputs": "入力", "output": "出力先", "result": "結果", "note": "備考", "perspective": "観点",
        "prompt": "プロンプト", "confidence": "確度", "verdict": "検証判定", "status": "状態",
        "symptom": "症状", "cause": "原因", "impact": "影響", "fix": "修正方針",
        "proposal": "改善案", "before": "現在", "after": "提案", "test": "評価・テストの確認内容",
        "evidence": "判定の根拠", "references": "参考資料", "excerpt": "抜粋",
        "previous": "再スキャン前のレビュー", "source": "出所",
        "cases": "ケース数", "passed": "成功", "failed": "失敗", "finding": "指摘",
        "none": "記録なし。", "all": "すべて", "search": "検索", "excluded": "除外",
        "no_match": "条件に合う指摘はありません。",
        "kinds": {"defect": "不具合", "improvement": "改善提案"},
        "results": {"applied": "実施", "N/A": "対象外", "not checked": "未確認"},
        "perspective_names": PERSPECTIVE_NAMES_JA,
    },
}

# console-triage layer (report_assets/console.css, console.js) and the report's
# vertical lane list. Lane names follow dashboard_model()'s action(); CLOSED and
# EXCLUDED hold the records the queue leaves out.
LABELS["en"].update(
    s_queue="Priority queue",
    queue_note="Every record sits in one of four lanes, top to bottom: FIX NOW and VERIFY FIRST hold the open, "
               "non-excluded findings (each ordered by severity, kind and ID); CLOSED and EXCLUDED list the rest "
               "for reference. Planning a fix requires Valid and Confirmed; other open findings need verification first.",
    cap_queue="Open findings in order of severity, kind and ID; the full entry for each follows in the findings section.",
    next_action="Next action",
    excluded_short="Excluded",
    excluded_note="Excluded findings are retained with their justification. They are not counted in included totals.",
    previous_validation="Previous validation (historical; not the current verdict)",
    fix_now_note="Valid, Confirmed finding. Apply the recorded fix direction or proposal and check it with the recorded eval or test.",
    verify_first_note="Re-read the prompt as sent and the code around it, or run the recorded eval case, before deciding on a change.",
    copied="Copied", copy_failed="Copy failed",
    missing_fix="Fix direction not recorded. Define the change after reviewing the evidence.",
    missing_evidence="No validation evidence recorded.", not_recorded="Not recorded",
    cx_report_link="Printable report",
    cx_readout="Record status", cx_readout_open="open", cx_readout_closed="closed", cx_readout_excluded="excluded",
    cx_severity_h="Severity", cx_severity_note="{n} included records; {x} excluded are not counted",
    cx_tile_sub="open {open} · closed {closed}", cx_legend_cell="1 cell = 1 record.",
    cx_legend_open="open", cx_legend_closed="fixed or accepted",
    cx_verdict_h="Verdict", cx_verdict_note="all {n} records; excluded verdicts kept as their own block",
    cx_perspective_h="Perspectives", cx_perspective_note="{n} perspectives",
    cx_perspectives_empty="No perspectives recorded.",
    cx_board_h="Triage", cx_board_note="every record in one lane; pick a card to inspect it",
    cx_lane_empty="None", cx_inspector_h="Inspector", cx_inspector_empty="No records to inspect.",
    cx_copy="Copy for Issue / LLM", cx_open_record="Open in register",
    cx_where_h="Where", cx_evidence_h="Evidence", cx_evidence_method="method: {method}", cx_fix_h="Fix direction",
    cx_empty_records="No records.", cx_read_only="read-only",
    cx_lane_fix_now="FIX NOW", cx_lane_verify_first="VERIFY FIRST", cx_lane_closed="CLOSED", cx_lane_excluded="EXCLUDED",
    cx_lane_note_fix_now="Open; Valid and Confirmed.",
    cx_lane_note_verify_first="Open; verdict or confidence still to confirm.",
    cx_lane_note_closed="Fix recorded or risk accepted.",
    cx_lane_note_excluded="False positive or not applicable; kept with the justification.",
)
LABELS["ja"].update(
    s_queue="優先対応一覧",
    queue_note="全件を 4 つのレーンに上から順に置いています。FIX NOW と VERIFY FIRST は未対応かつ除外されていない指摘で、"
               "それぞれ深刻度、種別、ID の順です。CLOSED と EXCLUDED は残りの記録を参照用に並べています。"
               "修正に進む対象は Valid・Confirmed の指摘で、それ以外の未対応の指摘は先に検証が必要です。",
    cap_queue="深刻度・種別・ID 順に並べた未対応の指摘。各指摘の全文は指摘の節に続きます。",
    next_action="次の対応",
    excluded_short="除外",
    excluded_note="除外した指摘も、その根拠とともに保持します。集計対象の件数には含めません。",
    previous_validation="以前の判定（履歴。現在の判定ではありません）",
    fix_now_note="Valid・Confirmed の指摘です。記録された修正方針または改善案を適用し、記録された評価・テストで確認してください。",
    verify_first_note="送信されるプロンプト全体と周辺コードを読み直すか、記録された評価ケースを実行してから変更要否を判断してください。",
    copied="コピーしました", copy_failed="コピーできませんでした",
    missing_fix="修正方針が未記録です。根拠を確認し、変更内容を具体化してください。",
    missing_evidence="判定の根拠が記録されていません。", not_recorded="未記録",
    cx_report_link="印刷用レポート",
    cx_readout="対応状況", cx_readout_open="open", cx_readout_closed="closed", cx_readout_excluded="excluded",
    cx_severity_h="Severity", cx_severity_note="集計対象 {n} 件（除外 {x} 件は数えない）",
    cx_tile_sub="未解決 {open} · 対応済 {closed}", cx_legend_cell="1 マス = 1 件。",
    cx_legend_open="未解決", cx_legend_closed="対応済み（Fixed / Accepted）",
    cx_verdict_h="Verdict", cx_verdict_note="記録 {n} 件の判定。除外の判定は独立した区画",
    cx_perspective_h="Perspectives", cx_perspective_note="観点 {n}",
    cx_perspectives_empty="観点の記録がありません。",
    cx_board_h="Triage", cx_board_note="全件をいずれかのレーンに置いています。カードを選ぶと詳細を表示します",
    cx_lane_empty="該当なし", cx_inspector_h="Inspector", cx_inspector_empty="表示できる記録がありません。",
    cx_copy="Issue / LLM 用にコピー", cx_open_record="一覧で開く",
    cx_where_h="該当箇所", cx_evidence_h="根拠", cx_evidence_method="method: {method}", cx_fix_h="修正方針",
    cx_empty_records="記録がありません。", cx_read_only="read-only",
    cx_lane_fix_now="FIX NOW / 修正計画", cx_lane_verify_first="VERIFY FIRST / 先に検証",
    cx_lane_closed="CLOSED / 対応済・受容", cx_lane_excluded="EXCLUDED / 誤検知・除外",
    cx_lane_note_fix_now="未対応で、Valid・Confirmed の指摘",
    cx_lane_note_verify_first="未対応で、判定や確度の確認が残る指摘",
    cx_lane_note_closed="修正の申告（Fixed）または受容（Accepted）",
    cx_lane_note_excluded="誤検知・対象外として根拠つきで保持",
)

LANES = ("fix_now", "verify_first", "closed", "excluded")
LANE_TONES = {"fix_now": "high", "verify_first": "medium", "closed": "low", "excluded": "accent"}
VERDICT_TONES = {"Valid": "strong", "Likely": "mid", "Unverified": "hatch", "Unlikely": "weak"}
SEVERITY_TONES = {"High": "high", "Medium": "medium", "Low": "low", "Info": "info"}


def console_lane(finding, actions):
    """The lane of one record: excluded verdicts, then closed statuses, then dashboard_model()'s action."""
    if finding["validation"]["verdict"] in EXCLUDED:
        return "excluded"
    if finding.get("status", "Open") != "Open":
        return "closed"
    return actions[str(finding["id"])]


def console_model(data, model, L):
    """The normalized console model (artifacts/report-style/console/INTEGRATION.md) for both outputs."""
    actions = {str(item["id"]): item["action"] for item in model["queue"]}
    meta = data.get("meta", {})
    findings = []
    for f in ordered(data.get("findings", [])):
        lane = console_lane(f, actions)
        excluded = lane == "excluded"
        status = f.get("status", "Open")
        v = f["validation"]
        prompt = f.get("prompt")
        prompt_text = ", ".join(prompt) if isinstance(prompt, list) else (prompt or "")
        notes = [L["excluded_note"]] if excluded else []
        pv = f.get("previous_validation")
        if isinstance(pv, dict) and isinstance(pv.get("verdict"), str):
            notes.append(L["previous_validation"] + ": " + pv["verdict"])
        guidance = L[lane + "_note"] if lane in ("fix_now", "verify_first") else ""
        findings.append({
            "id": str(f["id"]), "severity": f["severity"], "status": status,
            "status_label": L["excluded_short"] if excluded else status,
            "verdict": v["verdict"], "title": f["title"], "location": f["location"], "lane": lane,
            "open": lane in ("fix_now", "verify_first"), "excluded": excluded,
            "anchor": "finding-" + f["id"].lower(),
            "tags": [L["kinds"][f["kind"]], f["confidence"]],
            "where": [
                {"label": L["location"], "value": f.get("location") or "", "mono": True},
                {"label": L["prompt"], "value": prompt_text, "mono": True},
                {"label": L["perspective"], "value": perspective_label(f.get("category") or "", L)},
                {"label": L["symptom"], "value": f.get("symptom") or ""},
                {"label": L["cause"], "value": f.get("cause") or ""},
                {"label": L["impact"], "value": f.get("impact") or ""},
            ],
            "evidence": {"text": v.get("evidence") or "", "method": v.get("method") or "", "notes": notes},
            "fix": f.get("fix") or "",
            "guidance": guidance,
        })
    perspectives = [
        {"name": perspective_label(p["name"], L),
         **({"note": p["note"]} if "note" in p else {}),
         "result": L["results"].get(p["result"], p["result"]),
         "tone": "muted", "on": False}
        for p in data.get("perspectives", [])
    ]
    labels = {key[3:]: value for key, value in L.items() if key.startswith("cx_")}
    labels.update(copied=L["copied"], copy_failed=L["copy_failed"], fix_missing=L["missing_fix"],
                  evidence_missing=L["missing_evidence"], not_recorded=L["not_recorded"], location=L["location"])
    return {
        "meta": {"skill": "prompt-scan", "title": meta.get("target") or "—", "title_id": "cx-title",
                 "context": [meta.get("date") or "", revision(meta, L) or "", meta.get("scope") or "",
                             L["cx_read_only"]],
                 "headline": summary_line(data, L)},
        "counts": {"open": model["open_count"], "closed": model["fixed"] + model["accepted"],
                   "excluded": model["excluded"], "total": len(data.get("findings", []))},
        "severities": list(SEVERITIES),
        "verdicts": [{"key": v, "label": v, "excluded": v in EXCLUDED,
                      **({"tone": VERDICT_TONES[v]} if v in VERDICT_TONES else {})}
                     for v in VERDICTS],
        "lanes": [{"key": key, "label": L["cx_lane_" + key], "note": L["cx_lane_note_" + key],
                   "tone": LANE_TONES[key]} for key in LANES],
        "perspectives": perspectives,
        "findings": findings,
        "labels": labels,
    }


def console_band_html(cm, kind=""):
    """Static band header (report.html / PDF): wordmark, skill, title, context and open / closed / excluded readout."""
    meta, cnts, L = cm["meta"], cm["counts"], cm["labels"]
    context = "".join(f"<span>{esc(part)}</span>" for part in meta["context"] if part)
    readout = "".join(f"<div><dt>{esc(L['readout_' + key])}</dt><dd>{cnts[key]}</dd></div>"
                      for key in ("open", "closed", "excluded"))
    return (f"<header class='cx-band'><div class='cx-band-in'><div>"
            f"<p class='cx-wm'><span><span class='cx-perm' aria-hidden='true'>r--</span> agentic-scan</span>"
            f"<span class='cx-skill'>{esc(meta['skill'])}</span></p>"
            + (f"<p class='cx-kind'>{esc(kind)}</p>" if kind else "") +
            f"<h1>{esc(meta['title'])}</h1>" + (f"<p class='cx-ctx'>{context}</p>" if context else "") +
            f"</div><dl class='cx-readout' aria-label='{esc(L['readout'])}' data-cx-readout>{readout}</dl></div></header>")


def console_tiles_html(cm):
    """Static severity tiles: one cell per included record, filled while it is open."""
    L, included = cm["labels"], [f for f in cm["findings"] if not f["excluded"]]
    tiles = []
    for sev in cm["severities"]:
        items = [f for f in included if f["severity"] == sev]
        opened = [f for f in items if f["open"]]
        cells = ("".join("<i class='cx-on'></i>" for _ in opened[:120])
                 + "<i></i>" * max(0, min(len(items), 120) - len(opened)))
        if len(items) > 120:
            cells += f"<span class='cx-more'>+{len(items) - 120}</span>"
        ids = " ".join(f["id"] for f in opened[:6]) + (" …" if len(opened) > 6 else "")
        sub = L["tile_sub"].format(open=len(opened), closed=len(items) - len(opened)) + (f" · {ids}" if ids else "")
        tiles.append(f"<div class='cx-tile cx-c-{SEVERITY_TONES[sev]}' data-severity='{esc(sev)}'>"
                     f"<span class='cx-l'>{esc(sev)}</span><span class='cx-n'>{len(items)}</span>"
                     f"<span class='cx-cells' aria-hidden='true'>{cells}</span><span class='cx-s'>{esc(sub)}</span></div>")
    note = L["severity_note"].format(n=len(included), x=len(cm["findings"]) - len(included))
    return (f"<section class='cx-sev' aria-labelledby='cx-sev-h'><h2 class='cx-ph' id='cx-sev-h'><b>{esc(L['severity_h'])}</b>"
            f"<span>{esc(note)}</span></h2><div class='cx-tiles'>{''.join(tiles)}</div>"
            f"<p class='cx-legend'>{esc(L['legend_cell'])}<i class='cx-on'></i>{esc(L['legend_open'])} "
            f"<i></i>{esc(L['legend_closed'])}</p></section>")

# How to read the levels: the one source for both pages. The severity lines condense SKILL.md's severity
# table and the paragraph under it, the confidence lines reference/validation.md's confidence table;
# change these with them.
LEGEND = {
    "en": {
        "heading": "How to read the levels",
        "severity": {
            "High": "On ordinary inputs the feature produces wrong output or output its consumer cannot use; or "
                    "untrusted input can override the instructions while the model holds tools, other users' data "
                    "or side-effecting actions; or a secret or another user's personal data is placed in a prompt "
                    "that reaches a lower-trust reader.",
            "Medium": "A High-class impact that needs one condition the prompt author does not control; or a "
                      "contradiction that makes behaviour depend on which instruction the model weights.",
            "Low": "Clarity, structure or example gaps with a limited, plausible effect on quality; avoidable token "
                   "cost; a defense-in-depth gap at a trust boundary that holds today; or a High-class impact that "
                   "needs two or more conditions the prompt author does not control.",
            "Info": "A maintainability or style note with no behavioural effect.",
        },
        "confidence": {
            "Confirmed": "Certain from the text and code alone.",
            "Model-dependent": "The cause is real, but whether it changes the output depends on how the model "
                               "weighs it; the recorded eval case would settle it.",
            "Suspected": "A signal not yet traced end to end.",
        },
        "kinds": "Severity is about impact and applies to both kinds: defects and improvements are graded on "
                 "this one scale.",
        "graded": "Severity and confidence are graded separately; confidence never raises or lowers severity.",
        "assumed": "Severity rests on an assumed list; see decisions.",
    },
    "ja": {
        "heading": "レベルの読み方",
        "severity": {
            "High": "通常の入力で、誤った出力や利用側が使えない出力になる。または、モデルがツール・他ユーザーのデータ・"
                    "副作用のある操作を持つ状態で、信頼できない入力が指示を上書きできる。または、秘密情報や他ユーザーの"
                    "個人データが、より信頼度の低い読み手に届くプロンプトに入る。",
            "Medium": "High 相当の影響だが、プロンプト作成者が制御できない条件が 1 つ必要。または、指示の矛盾により、"
                      "モデルがどちらの指示を重視するかで挙動が変わる。",
            "Low": "明確さ・構成・例の不足による、品質への限定的で起こりうる影響。避けられるトークンコスト。"
                   "現時点では保たれている信頼境界での多層防御の欠如。または、作成者が制御できない条件が 2 つ以上"
                   "必要な High 相当の影響。",
            "Info": "挙動に影響しない、保守性や書き方についての注記。",
        },
        "confidence": {
            "Confirmed": "テキストとコードだけで確定できる。",
            "Model-dependent": "原因は実在するが、出力が変わるかはモデルの重み付け次第。記録した評価ケースで確かめる。",
            "Suspected": "端から端まではまだ追跡していない兆候。",
        },
        "kinds": "深刻度は影響で決まり、不具合と改善提案の両方を同じ尺度で判定します。",
        "graded": "深刻度と確度は別々に判定します。確度によって深刻度を上げ下げしません。",
        "assumed": "深刻度は依頼者が確認していない仮定の一覧に基づきます。「判断が必要な事項」を参照してください。",
    },
}


def legend(meta, lang):
    """The level legend for one page: a line per severity and confidence, then the closing notes.
    The assumed-axis note appears only when meta.axis is `assumed`."""
    G = LEGEND[lang]
    notes = [G["kinds"], G["graded"]] + ([G["assumed"]] if meta.get("axis") == "assumed" else [])
    return {"heading": G["heading"],
            "severity": [[s, G["severity"][s]] for s in SEVERITIES],
            "confidence": [[c, G["confidence"][c]] for c in CONFIDENCES],
            "notes": notes}


def ordered(findings):
    """Active findings by severity, then kind and id; excluded ones last."""
    return sorted(findings, key=lambda f: (f["validation"]["verdict"] in EXCLUDED, SEVERITIES.index(f["severity"]),
                                           KINDS.index(f["kind"]), id_key(f["id"])))


def counts(data):
    active = [f for f in data.get("findings", []) if f["validation"]["verdict"] not in EXCLUDED]
    by = Counter((f["severity"], f["kind"]) for f in active)
    return active, by


# ---------------------------------------------------------------- HTML helpers

def esc(value):
    return html.escape(str(value), quote=True)


def para(value):
    if isinstance(value, list):
        return "<ul>" + "".join(f"<li>{esc(v)}</li>" for v in value) + "</ul>"
    return f'<p class="prose">{esc(value)}</p>'


def snippet_html(excerpt):
    """A source excerpt as the kit's captioned listing: numbered lines, the cited range highlighted."""
    first, lines, (start, end) = excerpt
    rows = "".join(f'<span class="{"hit" if start <= first + i <= end else ""}"><b>{first + i:>4}</b>  {esc(line)}</span>'
                   for i, line in enumerate(lines))
    return f'<pre class="snippet">{rows}</pre>'


def revision(meta, L):
    """The short commit with the tree state at scan time, or None outside Git."""
    commit = meta.get("commit")
    if not commit:
        return None
    state = {True: L["dirty"], None: L["dirty_unknown"]}.get(meta.get("dirty"))
    return commit[:12] + (f" ({state})" if state else "")


def axis(meta, L):
    """Whether the requester confirmed the trust boundary severity is judged against, or None if unrecorded."""
    return L["axis_" + meta["axis"]] if meta.get("axis") else None


def meta_lines(data, L):
    meta = data.get("meta", {})
    revision_text = revision(meta, L) or "—"
    rows = [(L["commit"], revision_text), (L["date"], meta.get("date") or "—"),
            (L["assessor"], meta.get("assessor") or "—"), (L["scope"], meta.get("scope") or "—"),
            (L["axis"], axis(meta, L) or "—")]
    return "".join(f'<p class="meta-line"><strong>{esc(k)}</strong><span>{esc(v)}</span></p>' for k, v in rows)


def counts_table(data, L):
    active, by = counts(data)
    head = "".join(f'<th scope="col" class="num">{esc(L[k])}</th>' for k in KINDS) + \
        f'<th scope="col" class="num">{esc(L["total"])}</th>'
    rows = []
    for s in SEVERITIES:
        cells = "".join(f'<td class="num">{by[(s, k)]}</td>' for k in KINDS)
        rows.append(f'<tr><th scope="row"><span class="badge {s}">{s}</span></th>{cells}'
                    f'<td class="num">{sum(by[(s, k)] for k in KINDS)}</td></tr>')
    totals = "".join(f'<td class="num">{sum(by[(s, k)] for s in SEVERITIES)}</td>' for k in KINDS)
    rows.append(f'<tr class="total"><th scope="row">{esc(L["total"])}</th>{totals}<td class="num">{len(active)}</td></tr>')
    return (f'<table class="counts"><caption>{esc(L["table_counts"])}</caption>'
            f'<thead><tr><th scope="col">{esc(L["severity"])}</th>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table>')


def summary_line(data, L):
    active, by = counts(data)
    return L["summary_line"].format(
        total=len(active), defects=sum(1 for f in active if f["kind"] == "defect"),
        improvements=sum(1 for f in active if f["kind"] == "improvement"),
        high=sum(1 for f in active if f["severity"] == "High"),
        medium=sum(1 for f in active if f["severity"] == "Medium"),
        excluded=len(data.get("findings", [])) - len(active))


def finding_html(f, L, excerpts):
    """One finding entry in the kit's document vocabulary; its section number comes from CSS counters."""
    prompt = f.get("prompt")
    prompt = ", ".join(prompt) if isinstance(prompt, list) else prompt
    v = f["validation"]
    rows = [(L["severity"], f'<span class="badge {f["severity"]}">{f["severity"]}</span>'),
            (L["kind"], f'<span class="kind kind-{f["kind"]}">{esc(L["kinds"][f["kind"]])}</span>'),
            (L["location"], f'<code>{esc(f["location"])}</code>'),
            (L["prompt"], esc(prompt) if prompt else None),
            (L["perspective"], esc(perspective_label(f["category"], L))),
            (L["confidence"], esc(f["confidence"])),
            (L["verdict"], esc(v["verdict"]) + (f' <span class="muted">({esc(v["method"])})</span>'
                                                 if v.get("method") else "")),
            (L["status"], esc(f.get("status", "Open"))),
            (L["source"], esc(f["source"]) if f.get("source") else None)]
    state = "".join(f'<tr><th scope="row">{esc(k)}</th><td>{val}</td></tr>' for k, val in rows if val)
    fields = []
    for key in ("symptom", "cause", "impact", "fix"):
        if f.get(key):
            fields.append((L[key], para(f[key])))
    proposal = f.get("proposal")
    if proposal:
        fields.append((L["proposal"], '<div class="proposal">'
                       f'<figure><figcaption>{esc(L["before"])}</figcaption><pre>{esc(proposal.get("before", ""))}</pre></figure>'
                       f'<figure><figcaption>{esc(L["after"])}</figcaption><pre>{esc(proposal.get("after", ""))}</pre></figure>'
                       "</div>"))
    if f.get("test"):
        fields.append((L["test"], para(f["test"])))
    if v.get("evidence"):
        fields.append((L["evidence"], para(v["evidence"])))
    if f.get("previous_validation"):
        pv = f["previous_validation"]
        fields.append((L["previous"], para(pv["verdict"] + ": " + (pv.get("evidence") or ""))))
    if f["id"] in excerpts:
        fields.append((L["excerpt"], snippet_html(excerpts[f["id"]])))
    if f.get("references"):
        items = "".join(f'<li><a href="{esc(r["url"])}" rel="noopener noreferrer">{esc(r.get("title") or r["url"])}</a></li>'
                        for r in f["references"])
        fields.append((L["references"], f'<ul class="refs">{items}</ul>'))
    body = "".join(f'<div class="finding-field"><h4>{esc(k)}</h4>{content}</div>' for k, content in fields)
    cls = "finding excluded" if v["verdict"] in EXCLUDED else f'finding sev-{f["severity"]}'
    return (f'<article class="{cls}" id="{esc(f["id"])}"><div class="finding-header">'
            f'<span class="finding-id">{esc(f["id"])}</span><h3>{esc(f["title"])}</h3>'
            f'<table class="finding-state"><tbody>{state}</tbody></table></div>{body}</article>')


def legend_html(G, L):
    """The level legend as two definition lists, severity then confidence, and the closing notes."""
    sev = "".join(f'<dt><span class="badge {s}">{s}</span></dt><dd>{esc(text)}</dd>' for s, text in G["severity"])
    conf = "".join(f'<dt>{esc(c)}</dt><dd>{esc(text)}</dd>' for c, text in G["confidence"])
    return (f'<h3>{esc(L["severity"])}</h3><dl class="legend">{sev}</dl>'
            f'<h3>{esc(L["confidence"])}</h3><dl class="legend">{conf}</dl>'
            + "".join(f'<p class="small">{esc(n)}</p>' for n in G["notes"]))


def list_section(items, L):
    return "<ul>" + "".join(f"<li>{esc(x)}</li>" for x in items) + "</ul>" if items else f'<p class="small">{esc(L["none"])}</p>'


# The shared stylesheet (report_assets/document.css, the bundled report kit)
# comes first; these add only the rules for prompt-scan record types: the
# severity-by-kind counts table, the level legend, the prompt inventory and
# eval-run tables, the kind label and before/after proposals.
REPORT_CSS = """
.num{text-align:right}
.counts .badge{margin:0}
.counts tbody th{border-bottom:0;font-weight:400}
.counts tbody tr+tr th{border-top:.3pt solid var(--hair)}
.counts tr.total th,.counts tr.total td{font-weight:700;border-top:.6pt solid var(--rule)}
.inv .id-col{width:8%}.evals .id-col{width:9%}
.inv .name-col{width:20%}.inv .kind-col{width:11%}.inv .loc-col{width:20%}.inv .consumer-col{width:17%}.inv .model-col{width:24%}
.evals .finding-col{width:10%}.evals .model-col{width:18%}.evals .date-col{width:13%}.evals .num-col{width:8%}.evals .note-col{width:26%}
.fid{font:7.8pt/1.5 var(--mono);white-space:nowrap}
.inv code{font-size:7.6pt}
.kind{font:7.2pt/1.5 var(--sans);letter-spacing:.06em;color:var(--muted);border:.5pt solid var(--hair);padding:0 1.5mm;border-radius:.6mm;white-space:nowrap}
.muted{color:var(--muted)}
.finding.excluded h3{color:var(--muted);text-decoration:line-through}
.proposal{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:4mm}
.proposal figure{margin:0;min-width:0}
.proposal figcaption{font:700 7.4pt/1.4 var(--sans);letter-spacing:.06em;color:var(--muted);margin-bottom:1mm}
.proposal pre{margin:0;padding:1.5mm 0 1.5mm 3mm;border-left:.6pt solid var(--rule);font:7.6pt/1.55 var(--mono);white-space:pre-wrap;overflow-wrap:anywhere;word-wrap:break-word;word-break:break-all}
.legend{display:grid;grid-template-columns:22mm minmax(0,1fr);gap:1mm 4mm;margin:1.5mm 0 3mm;font-size:9pt}
.legend dt{font:7.6pt/1.9 var(--sans);color:var(--muted)}.legend dt .badge{margin:0}
.legend dd{margin:0}
@media screen and (max-width:600px){.legend{grid-template-columns:minmax(0,1fr);gap:0}.legend dd{margin-bottom:2mm}.proposal{grid-template-columns:minmax(0,1fr)}.index td.num{text-align:left}}
"""


def stacked_row(L, columns, cells):
    """A row of a table that stacks into labelled cards on narrow screens (the kit's `.index` pattern):
    each cell carries its column label, and explicit roles keep the table semantics once CSS sets
    display:block on it."""
    return "<tr role='row'>" + "".join(
        f'<td role="cell" data-label="{esc(L[col])}"' + (f' class="{cls}"' if cls else "") + f'>{value}</td>'
        for col, (value, cls) in zip(columns, cells)) + "</tr>"  # noqa: B905 - strict= needs 3.10; CI runs 3.9


def stacked_table(name, caption, L, columns, col_classes, rows, numeric=()):
    cols = "".join(f'<col class="{c}">' for c in col_classes)
    head = "".join('<th scope="col" role="columnheader"' + (' class="num"' if col in numeric else "") +
                   f'>{esc(L[col])}</th>' for col in columns)
    return (f'<table class="{name} index" role="table"><caption>{esc(caption)}</caption><colgroup>{cols}</colgroup>'
            f'<thead role="rowgroup"><tr role="row">{head}</tr></thead><tbody role="rowgroup">{rows}</tbody></table>')


def table_or_none(rows, html_table, L):
    return html_table if rows else f'<p class="small">{esc(L["none"])}</p>'


def render_report_html(data, L, lang, excerpts):
    findings = ordered(data.get("findings", []))
    G = legend(data.get("meta", {}), lang)
    model = dashboard_model(data)
    full_L = {**L, **DASH_LABELS[lang]}
    cm = console_model(data, model, full_L)
    by_id = {f["id"]: f for f in data.get("findings", [])}
    lane_meta = {lane["key"]: lane for lane in cm["lanes"]}

    def badge(f):
        return f'<span class="badge {esc(f["severity"])}">{esc(f["severity"])}</span>'

    def queue_table(items):
        rows = []
        for item in items:
            f, action = by_id[item["id"]], item["action"]
            action_text = (f.get("fix") or full_L["missing_fix"]) if action == "fix_now" else ""
            preview = action_text if len(action_text) <= 220 else action_text[:217].rstrip() + "..."
            rows.append(
                f'<tr><td><a href="#{esc(f["id"])}">{esc(f["id"])}</a><br>{badge(f)}</td>'
                f'<td><div class="queue-title">{esc(f["title"])}</div>'
                f'<div class="queue-location"><code>{esc(f["location"])}</code></div></td>'
                f'<td class="queue-action"><strong>{esc(full_L[action])}</strong>{esc(preview)}</td></tr>'
            )
        return (f'<table class="queue"><caption>{esc(L["cap_queue"])}</caption>'
                '<colgroup><col class="ref-col"><col class="finding-col"><col class="action-col"></colgroup>'
                f'<thead><tr><th scope="col">ID / {esc(L["severity"])}</th><th scope="col">{esc(L["finding"])}</th>'
                f'<th scope="col">{esc(L["next_action"])}</th></tr></thead><tbody>{"".join(rows)}</tbody></table>')

    def lane_box(n, key, body):
        lane = lane_meta[key]
        return (f'<div class="cx-doc-lane cx-c-{lane["tone"]}" id="lane-{key}" data-lane="{key}">'
                f'<h3><span>{n}. {esc(lane["label"])}</span><span class="cx-count">{body[0]}</span></h3>'
                f'<p class="cx-lane-note small">{esc(lane["note"])}</p>{body[1]}</div>')

    def queue_lane(n, action):
        items = [item for item in model["queue"] if item["action"] == action]
        parts = "".join(
            f'<h4 id="priority-queue-{action}-{kind}">{esc(full_L["part_" + kind])}</h4>' + queue_table(part_items)
            for kind in KINDS for part_items in [[item for item in items if item["kind"] == kind]] if part_items
        )
        return lane_box(n, action, (len(items), parts or f'<p class="small">{esc(L["cx_lane_empty"])}</p>'))

    def record_lane(n, key):
        records = [(by_id[c["id"]], c) for c in cm["findings"] if c["lane"] == key]
        rows = "".join(
            f'<li><span><a href="#{esc(c["id"])}">{esc(c["id"])}</a><br>{badge(f)}</span>'
            f'<span>{esc(f["title"])}<span class="cx-loc">{esc(f["location"])}</span></span>'
            f'<span class="cx-state">{esc(c["status_label"])} · {esc(c["verdict"])}</span></li>'
            for f, c in records
        )
        return lane_box(n, key, (len(records), f'<ul class="cx-doc-list">{rows}</ul>' if rows
                                 else f'<p class="small">{esc(L["cx_lane_empty"])}</p>'))

    verify_legend = (
        f'<p class="queue-legend"><strong>{esc(full_L["verify_first"])}</strong> {esc(full_L["verify_first_note"])}</p>'
        if any(item["action"] != "fix_now" for item in model["queue"]) else ""
    )
    queue_html = (queue_lane(1, "fix_now") + queue_lane(2, "verify_first")
                  if model["queue"] else f'<p>{esc(full_L["no_open"])}</p>')
    closed_lanes_html = f'<div id="closed-lanes">{record_lane(3, "closed")}{record_lane(4, "excluded")}</div>'
    triage_html = (f'<p class="section-note">{esc(L["queue_note"])}</p>{verify_legend}'
                   f'<div id="priority-queue">{queue_html}</div>{closed_lanes_html}')

    prompts = data.get("prompts", [])
    inv_cols = ("id", "name", "kind", "location", "consumer", "model")
    prompt_rows = "".join(stacked_row(L, inv_cols, (
        (esc(p["id"]), "fid"), (esc(p["name"]), ""), (esc(p.get("kind", "")), ""),
        (f'<code>{esc(p["location"])}</code>', ""), (f'<code>{esc(p.get("consumer", ""))}</code>', ""),
        (esc(p.get("model", "")), ""))) for p in prompts)
    prompt_table = table_or_none(prompts, stacked_table(
        "inv", L["cap_inventory"], L, inv_cols,
        ("id-col", "name-col", "kind-col", "loc-col", "consumer-col", "model-col"), prompt_rows), L)
    persp_rows = "".join(
        f'<tr><td>{esc(perspective_label(p["name"], L))}</td><td>{esc(L["results"][p["result"]])}</td><td>{esc(p.get("note", ""))}</td></tr>'
        for p in data.get("perspectives", []))
    persp_table = (f'<table class="coverage"><caption>{esc(L["cap_perspectives"])}</caption>'
                   '<colgroup><col class="perspective-col"><col class="result-col"><col class="note-col"></colgroup>'
                   f'<thead><tr><th scope="col">{L["perspective"]}</th><th scope="col">{L["result"]}</th>'
                   f'<th scope="col">{L["note"]}</th></tr></thead><tbody>{persp_rows}</tbody></table>')
    finding_parts = "".join(finding_html(f, L, excerpts) for f in findings) \
        or f'<p class="small">{esc(L["none"])}</p>'
    runs = data.get("eval_runs", [])
    eval_cols = ("id", "finding", "model", "date", "cases", "passed", "failed", "note")
    eval_rows = "".join(stacked_row(L, eval_cols, (
        (esc(r["id"]), "fid"), (esc(r["finding"]), "fid"), (esc(r["model"]), ""), (esc(r["date"]), ""),
        (r["cases"], "num"), (r["passed"], "num"), (r["failed"], "num"), (esc(r.get("note", "")), ""))) for r in runs)
    eval_part = table_or_none(runs, stacked_table(
        "evals", L["cap_evals"], L, eval_cols,
        ("id-col", "finding-col", "model-col", "date-col", "num-col", "num-col", "num-col", "note-col"), eval_rows,
        numeric={"cases", "passed", "failed"}), L)
    sections = [
        ("summary", L["abstract"], f'<p class="lead">{esc(summary_line(data, L))}</p>{counts_table(data, L)}'),
        ("levels", G["heading"], legend_html(G, L)),
        ("triage-lanes", full_L["cx_board_h"], triage_html),
        ("inventory", L["s_inventory"], prompt_table), ("perspectives", L["s_perspectives"], persp_table),
        ("checked-ok", L["s_sound"], list_section(data.get("checked_ok", []), L)),
        ("finding-details", L["s_findings"], finding_parts), ("eval-runs", L["s_evals"], eval_part),
        ("decisions", L["s_decisions"], list_section(data.get("decisions", []), L)),
        ("limitations", L["s_limitations"], list_section(data.get("limitations", []), L)),
        ("next-steps", L["s_next"], list_section(data.get("next_steps", []), L)),
    ]
    body = "".join(f'<section id="{sid}"' + (' class="summary-section"' if sid == "summary" else "") +
                   f'><h2>{esc(title)}</h2>{content}</section>' for sid, title, content in sections)
    target = data.get("meta", {}).get("target", "")
    title = f'{L["title"]} — {target}'.rstrip(" —")
    css = report_style.document_css(L["running_footer"]) + REPORT_CSS + report_style.console_css()
    return (f'<!doctype html><html lang="{lang}" class="cx-doc"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)}</title>'
            f'<style>{css}</style></head><body>'
            f'{console_band_html(cm, L["title"])}'
            f'<header class="report-header"><p class="kicker">{esc(L["running_footer"])}</p>{meta_lines(data, L)}</header>'
            f'{console_tiles_html(cm)}'
            f'<main>{body}</main></body></html>')


# The shared stylesheet (report_assets/dashboard.css, the bundled report kit)
# comes first; these add only the rules for prompt-scan's dashboard pieces: the
# decisions panel, the verify-first legend, paired counts on the closed card,
# the earlier-validation history box, proposal text, which wraps as in the
# report where the kit's code listing scrolls sideways, and the level legend.
DASH_CSS = """
#decisions-section h2{margin-bottom:8px}#decisions-section ul{margin:0;padding-left:20px}
.verify-legend{margin:0 0 14px;color:var(--muted)}
.verify-legend .action-label{font-family:var(--sans);font-size:12px;font-weight:700;color:var(--accent)}
.card .n .pair{display:inline-block;white-space:nowrap;margin-right:18px}
.card .n .u{font-family:var(--sans);font-size:11px;letter-spacing:.06em;color:var(--muted);margin-left:6px}
.history{border:1px dashed var(--line);padding:12px;margin-top:16px}
.history p{margin:5px 0;white-space:pre-wrap}
.snippet.proposal-text{white-space:pre-wrap;overflow-wrap:anywhere}
#levels-section h2{margin-bottom:8px}#levels h3{margin:14px 0 6px}
.legend{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:6px 16px;margin:0 0 8px}
.legend dt{font-family:var(--sans);font-size:12px;color:var(--muted)}.legend dt .badge{margin:0}.legend dd{margin:0}
@media(max-width:600px){.legend{grid-template-columns:minmax(0,1fr);gap:2px}.legend dd{margin-bottom:8px}}
"""

DASHBOARD = r"""<!doctype html>
<html lang="__LANG__">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
__CSS__
</style>
</head>
<body>
<a class="skip" href="#findings" data-l="jump_findings"></a>
<header class="cx-band"><div class="cx-band-in"><div data-cx="ident"></div><div class="cx-side"><dl class="cx-readout" data-cx="readout"></dl><div class="cx-tools"><a class="button" href="report.html" data-l="cx_report_link"></a><button id="theme" type="button" data-l="theme"></button></div></div></div></header>
<div class="cx" id="console"><div class="cx-grid">
<section class="cx-p cx-sev" data-cx="severity" aria-labelledby="cx-sev-h"></section>
<section class="cx-p cx-ver" data-cx="verdicts" aria-labelledby="cx-ver-h"></section>
<section class="cx-p cx-cov" data-cx="perspectives" aria-labelledby="cx-cov-h"></section>
<section class="cx-triage" id="triage" tabindex="-1" aria-labelledby="cx-triage-h"><h2 class="cx-ph" id="cx-triage-h"><b data-l="cx_board_h"></b><span data-l="cx_board_note"></span></h2><div class="cx-triage-in"><div class="cx-board" data-cx="board"></div><aside class="cx-insp" data-cx="inspector" aria-live="polite"></aside></div></section>
</div></div>
<main>
<section id="findings" aria-labelledby="findings-heading"><div class="section-head"><div><h2 id="findings-heading" data-l="findings_register"></h2><p data-l="findings_note"></p></div></div>
<div class="panel filters-panel"><div class="filters">
<label><span data-l="record_set"></span><select id="f-scope"></select></label><label><span data-l="part"></span><select id="f-part"></select></label><label><span data-l="severity"></span><select id="f-sev"></select></label><label><span data-l="confidence"></span><select id="f-conf"></select></label><label><span data-l="category"></span><select id="f-cat"></select></label><label><span data-l="prompt"></span><select id="f-prompt"></select></label><label><span data-l="status"></span><select id="f-status"></select></label><label><span data-l="verdict"></span><select id="f-verdict"></select></label><label><span data-l="sort"></span><select id="f-sort"></select></label><label class="search"><span data-l="search"></span><input id="f-q" type="search"></label></div><div class="filter-bottom"><p class="result-count" id="result-count" role="status" aria-live="polite"></p><button type="button" id="reset" data-l="reset"></button></div></div>
<div class="tablewrap"><table class="register"><thead><tr><th scope="col">ID</th><th scope="col" data-l="severity"></th><th scope="col" data-l="part"></th><th scope="col" data-l="confidence"></th><th scope="col" data-l="verdict"></th><th scope="col" data-l="title_col"></th><th scope="col" data-l="category"></th></tr></thead><tbody id="rows"></tbody></table></div></section>
<div class="hero"><div><div class="eyebrow" data-l="dash_title"></div><h2 id="h" data-l="abstract"></h2><div class="meta" id="meta"></div></div><div class="hero-aside" data-l="report_note"></div></div>
<div class="summary-banner" id="summary"></div>
<div class="cards" id="cards"></div><p class="report-note" data-l="counts_note"></p>
<div class="cards part-cards" id="part-cards"></div><p class="report-note" data-l="part_note"></p>
<section aria-labelledby="priority-heading"><div class="section-head"><div><h2 id="priority-heading" data-l="priority"></h2><p data-l="priority_note"></p></div><a href="#findings" data-l="view_all"></a></div><p class="verify-legend" id="verify-legend" hidden></p><div id="priority"></div><p class="section-note" id="queue-note"></p></section>
<section class="panel" id="levels-section" aria-labelledby="levels-heading"><h2 id="levels-heading"></h2><div id="levels"></div></section>
<section class="panel" id="decisions-section" aria-labelledby="decisions-heading"><h2 id="decisions-heading" data-l="decisions"></h2><div id="decisions"></div></section>
<details class="panel coverage" id="coverage" open><summary><span data-l="coverage_heading"></span><span class="small" id="coverage-count"></span></summary><p data-l="coverage_note"></p><dl class="scope-meta" id="scope-meta"></dl><div class="coverage-columns"><section><h3 data-l="limitations"></h3><div id="limitations"></div></section><section><h3 data-l="perspectives"></h3><div id="perspectives"></div></section></div></details>
<details class="chart-section"><summary data-l="overview"></summary><p class="section-note" data-l="count_basis"></p><div class="grid"><div class="panel"><h3 data-l="by_sev"></h3><div id="c-sev"></div></div><div class="panel"><h3 data-l="by_kind"></h3><div id="c-kind"></div></div><div class="panel"><h3 data-l="by_conf"></h3><div id="c-conf"></div></div><div class="panel"><h3 data-l="by_cat"></h3><div id="c-cat"></div></div><div class="panel"><h3 data-l="by_status"></h3><div id="c-status"></div></div><div class="panel"><h3 data-l="by_verdict"></h3><div id="c-verdict"></div><p class="section-note" data-l="excluded_note"></p></div></div></details>
<div class="lists" id="lists"></div><footer class="footer" data-l="source_note"></footer>
<noscript><p>__NOSCRIPT__ <a href="report.html">__REPORT__</a></p></noscript>
</main>
<script id="data" type="application/json">__DATA__</script>
<script>
__CONSOLE_JS__
(function(){
'use strict';
var D=JSON.parse(document.getElementById('data').textContent),L=D.labels,ALL=D.findings,R=D.report;
var F=ALL.filter(function(f){return D.excluded_verdicts.indexOf(f.verdict)<0;}),SEV=D.order.severity,CONF=D.order.confidence,ST=D.order.status;
var expanded=new Set();
function el(t,a,txt){var e=document.createElement(t);if(a)Object.keys(a).forEach(function(k){e.setAttribute(k,a[k]);});if(txt!=null)e.textContent=txt;return e;}
function byId(id){return document.getElementById(id);}
function fmt(text,values){return text.replace(/\{(\w+)\}/g,function(_,key){return values[key];});}
function pl(key,n,values){return fmt(n===1&&L[key+'_one']?L[key+'_one']:L[key],values||{n:n});}
function excluded(f){return D.excluded_verdicts.indexOf(f.verdict)>=0;}
function statusText(f){return excluded(f)?L.excluded_short:f.status;}
function badge(f){return el('span',{'class':'badge '+f.severity},f.severity);}
function kindText(f){return L['part_short_'+f.kind];}
function catText(c){return (L.perspective_names&&L.perspective_names[c])||c;}
function action(f){return f.status==='Open'&&f.verdict==='Valid'&&f.confidence==='Confirmed'?'fix_now':'verify_first';}
function count(fs,key,label){var c=Object.create(null);fs.forEach(function(f){var k=label?label(f):f[key];c[k]=(c[k]||0)+1;});return c;}
function listInto(box,items,empty){if(!items.length){box.appendChild(el('p',{'class':'muted'},empty));return;}var ul=el('ul');items.forEach(function(x){ul.appendChild(el('li',null,x));});box.appendChild(ul);}
document.title=L.dash_title+' - '+D.meta.target;
byId('meta').textContent=[D.meta.date,D.meta.assessor].filter(Boolean).join(' · ');
document.querySelectorAll('[data-l]').forEach(function(e){e.textContent=L[e.getAttribute('data-l')];});
// The theme choice is remembered under the bundled report kit's key. Storage may be
// absent or throw (private windows, blocked site data); the page then follows the system theme.
var THEME_KEY='scan-report-kit.theme';try{var saved=window.localStorage.getItem(THEME_KEY);if(saved==='light'||saved==='dark')document.documentElement.dataset.theme=saved;}catch(e){}
byId('theme').onclick=function(){var root=document.documentElement,dark=root.dataset.theme?root.dataset.theme==='dark':window.matchMedia('(prefers-color-scheme: dark)').matches;root.dataset.theme=dark?'light':'dark';try{window.localStorage.setItem(THEME_KEY,root.dataset.theme);}catch(e){}};
var summary=byId('summary');
summary.appendChild(el('strong',null,D.headline));
summary.appendChild(el('p',null,F.length?(R.open_hm?pl('risk_summary',R.open_hm):(R.open_count?pl('open_summary',R.open_count):L.no_open)):L.no_findings));
[[L.open_hm,R.open_hm,'urgent',L.open_count+': '+R.open_count],[L.needs_validation,R.verify_first,'review',L.fix_now+': '+R.fix_now],[L.closed_count,[[R.fixed,'Fixed'],[R.accepted,'Accepted']],'',L.included+': '+F.length],[L.excluded_short,R.excluded,'',L.all_records+': '+ALL.length]].forEach(function(c){var d=el('div',{'class':'card '+c[2]});d.appendChild(el('span',{'class':'l'},c[0]));var n=el('div',{'class':'n'});if(Array.isArray(c[1]))c[1].forEach(function(x){var pair=el('span',{'class':'pair'},x[0]);pair.appendChild(el('span',{'class':'u'},x[1]));n.appendChild(pair);});else n.textContent=c[1];d.appendChild(n);d.appendChild(el('div',{'class':'sub'},c[3]));byId('cards').appendChild(d);});
D.parts.forEach(function(part){var c=R.parts[part],d=el('div',{'class':'card','data-part':part});d.appendChild(el('span',{'class':'l'},L['part_'+part]+' · '+L.open_count));d.appendChild(el('div',{'class':'n'},c.open_count));d.appendChild(el('div',{'class':'sub'},fmt(L.part_card_sub,c)));byId('part-cards').appendChild(d);});
var shownTop=0;D.parts.forEach(function(part){var items=R.queue.filter(function(item){return item.kind===part;}).map(function(item){return {finding:ALL.find(function(f){return f.id===item.id;}),action:item.action,anchor:D.anchors[item.id]};}),high=items.filter(function(item){return item.finding.severity==='High';}).length,top=items.slice(0,Math.max(4,Math.min(high,12))),hiddenHigh=high-top.filter(function(item){return item.finding.severity==='High';}).length;shownTop+=top.length;if(!R.queue.length)return;byId('priority').appendChild(el('h3',{'class':'part-heading',id:'priority-'+part},L['part_'+part]));var list=el('div',{'class':'priority-list'});byId('priority').appendChild(list);if(!top.length)list.appendChild(el('div',{'class':'panel muted'},L.part_none_open));top.forEach(function(item){var f=item.finding,p=el('article',{'class':'panel priority-item sev-'+f.severity}),head=el('div',{'class':'priority-top'});head.appendChild(badge(f));head.appendChild(el('span',{'class':'action-label'},L[item.action]));p.appendChild(head);var h=el('h3');h.appendChild(el('a',{href:'#'+item.anchor},f.id+' · '+f.title));p.appendChild(h);p.appendChild(el('div',{'class':'verdict'},f.confidence+' · '+f.verdict));p.appendChild(el('code',{'class':'location'},f.location));if(f.impact)p.appendChild(el('p',{'class':'impact'},f.impact));if(item.action==='fix_now')p.appendChild(el('p',{'class':'action'},f.fix||L.missing_fix));list.appendChild(p);});if(hiddenHigh>0)byId('priority').appendChild(el('p',{'class':'section-note more-high','data-part':part},pl('more_high',hiddenHigh)));});
if(R.queue.some(function(item){return item.action==='verify_first';})){var legend=byId('verify-legend');legend.appendChild(el('span',{'class':'action-label'},L.verify_first));legend.appendChild(document.createTextNode(' '+L.verify_first_note));legend.hidden=false;}
if(!R.queue.length)byId('priority').appendChild(el('div',{'class':'panel muted'},L.no_open));byId('queue-note').textContent=shownTop<R.open_count?fmt(L.queue_more,{shown:shownTop,total:R.open_count}):'';
[['scope','scope_l'],['commit','commit'],['axis','axis'],['prompts','prompts_l']].forEach(function(k){byId('scope-meta').appendChild(el('dt',null,L[k[1]]));byId('scope-meta').appendChild(el('dd',null,D.meta[k[0]]||L.not_recorded));});
byId('coverage-count').textContent=L.limitations_count+': '+D.limitations.length;listInto(byId('limitations'),D.limitations,L.limitations_empty);
if(!D.perspectives.length)byId('perspectives').appendChild(el('p',{'class':'muted'},L.coverage_missing));
D.perspectives.forEach(function(p){var box=el('div',{'class':'perspective'});box.appendChild(el('strong',null,p.name));box.appendChild(el('p',null,L.results[p.result]||p.result||L.not_recorded));if(p.note)box.appendChild(el('p',{'class':'muted'},p.note));byId('perspectives').appendChild(box);});
function bars(id,key,order,colored,fs,label){var c=count(fs||F,key,label),keys=order||Object.keys(c).sort(function(a,b){return c[b]-c[a]||a.localeCompare(b);});var max=Math.max.apply(null,keys.map(function(k){return c[k]||0;}).concat([1]));keys.forEach(function(k){var r=el('div',{'class':'bar'});r.appendChild(el('span',{'class':'t'},k));var t=el('div',{'class':'track'}),fill=el('div',{'class':'fill'});fill.style.width=((c[k]||0)/max*100)+'%';if(colored)fill.style.background='var(--'+k.toLowerCase()+')';t.appendChild(fill);r.appendChild(t);r.appendChild(el('span',{'class':'v'},c[k]||0));byId(id).appendChild(r);});}
bars('c-sev','severity',SEV,true);bars('c-kind','kind',D.parts.map(function(p){return L['part_short_'+p];}),false,F,kindText);bars('c-conf','confidence',CONF);bars('c-cat','category',null,false,F,function(f){return catText(f.category);});bars('c-status','status',ST);bars('c-verdict','verdict',D.order.verdict,false,ALL);
function opts(id,vals,first){var s=byId(id);if(first)s.appendChild(el('option',{value:''},first));vals.forEach(function(v){var pair=Array.isArray(v)?v:[v,v];s.appendChild(el('option',{value:pair[0]},pair[1]));});s.onchange=function(){if(id==='f-verdict'&&D.excluded_verdicts.indexOf(s.value)>=0)byId('f-scope').value='all';draw();};}
opts('f-scope',[['included',L.included_set],['excluded',L.excluded_set],['all',L.all_records]]);opts('f-part',D.parts.map(function(part){return [part,L['part_short_'+part]];}),L.part_all);opts('f-sort',[['priority',L.priority_sort],['severity',L.severity_sort]]);
opts('f-sev',SEV,L.all);opts('f-conf',CONF,L.all);opts('f-cat',Object.keys(count(ALL,'category')).sort().map(function(c){return [c,catText(c)];}),L.all);opts('f-prompt',D.prompt_ids,L.all);opts('f-status',ST,L.all);opts('f-verdict',D.order.verdict,L.all_verdicts);
// Large registers redraw once typing pauses instead of on every keystroke.
var q=byId('f-q'),searchTimer=null;q.placeholder=L.search;q.oninput=function(){clearTimeout(searchTimer);if(ALL.length>300)searchTimer=setTimeout(draw,150);else draw();};
function v(id){return byId(id).value;}
function reset(){['f-part','f-sev','f-conf','f-cat','f-prompt','f-status','f-verdict'].forEach(function(id){byId(id).value='';});byId('f-scope').value='included';byId('f-sort').value='priority';q.value='';}
byId('reset').onclick=function(){reset();draw();};
function fence(text){var runs=String(text).match(/`+/g)||[],n=Math.max.apply(null,runs.map(function(r){return r.length;}).concat([2]))+1;return Array(n+1).join('`');}
function oneLine(v){return String(v).replace(/\s*[\r\n]+\s*/g,' ');}
function fenced(v){var fc=fence(v);return fc+'text\n'+v+'\n'+fc;}
function asText(v){return Array.isArray(v)?v.map(function(x){return '- '+x;}).join('\n'):v;}
function findingMarkdown(f){var out=['## '+oneLine(f.id)+' · '+oneLine(f.title),''],p=function(label,value){if(value)out.push('- '+label+': '+oneLine(value));},block=function(label,value,raw){if(value)out.push('','### '+label,'',raw?value:fenced(value));};
p(L.severity,f.severity);p(L.part,kindText(f));p(L.confidence,f.confidence);p(L.status,statusText(f));p(L.verdict,f.verdict);p(L.category,catText(f.category));p(L.prompt,f.prompts.join(', '));p(L.location,f.location);
if(f.status==='Open'&&!excluded(f)){var a=action(f);block(L[a],L[a+'_note'],true);}['symptom','cause','impact','fix'].forEach(function(k){block(L[k],f[k]);});
if(f.proposal){block(L.proposal_before,f.proposal.before);block(L.proposal_after,f.proposal.after);}block(L.test,asText(f.test));block(L.evidence,f.validation.evidence);block(L.validation_method,f.validation.method);
if(f.snippet){var lines=f.snippet.lines.map(function(text,i){var n=f.snippet.start+i;return (n>=f.snippet.hit[0]&&n<=f.snippet.hit[1]?'>':' ')+String(n).padStart(5,' ')+' '+text;}).join('\n'),fc=fence(lines);block(L.snippet,fc+'\n'+lines+'\n'+fc,true);}
var refs=f.references||[];if(refs.length)block(L.references,refs.map(function(r){return '- '+(r.title&&r.title!==r.url?oneLine(r.title)+' — ':'')+oneLine(r.url);}).join('\n'),true);
return out.join('\n')+'\n';}
// A denied or unavailable Clipboard API falls back to the selection copy.
function copyText(text){if(navigator.clipboard&&window.isSecureContext)return navigator.clipboard.writeText(text).catch(function(){return copyFallback(text);});return copyFallback(text);}
function copyFallback(text){return new Promise(function(resolve,reject){var prev=document.activeElement,t=el('textarea',{readonly:'','aria-hidden':'true',style:'position:fixed;top:0;left:-9999px'});t.value=text;document.body.appendChild(t);t.select();var ok=false;try{ok=document.execCommand('copy');}catch(e){}t.remove();if(prev&&prev.focus)prev.focus({preventScroll:true});if(ok)resolve();else reject(new Error('copy'));});}
function copyButton(f){var b=el('button',{type:'button','class':'copy-finding','aria-live':'polite'},L.copy_llm),timer;b.onclick=function(e){e.stopPropagation();var done=function(label){b.textContent=label;clearTimeout(timer);timer=setTimeout(function(){b.textContent=L.copy_llm;},2000);};copyText(findingMarkdown(f)).then(function(){done(L.copied);},function(){done(L.copy_failed);});};return b;}
// Detail content is built on first expansion: a large register would
// otherwise build every record's full detail tree on each redraw.
function details(f,anchor){var dt=el('tr',{'class':'detail',id:anchor+'-detail'});dt.hidden=!expanded.has(anchor);if(!dt.hidden)fillDetails(dt,f,anchor);return dt;}
function snippetNode(start,lines,hit){var pre=el('pre',{'class':'snippet'});lines.forEach(function(text,i){var n=start+i,ln=el('span',{'class':hit&&n>=hit[0]&&n<=hit[1]?'hit':''});ln.appendChild(el('b',null,String(n).padStart(5,' ')+' '));ln.appendChild(document.createTextNode(text));pre.appendChild(ln);});return pre;}
function textNode(text){var pre=el('pre',{'class':'snippet proposal-text'});pre.textContent=text;return pre;}
function fillDetails(dt,f,anchor){if(dt.firstChild)return;var td=el('td',{colspan:7}),dl=el('dl');
var head=el('div',{'class':'detail-actions'});head.appendChild(el('strong',null,f.id+' · '+f.title));var links=el('span',{'class':'detail-links'});links.appendChild(copyButton(f));links.appendChild(el('a',{href:'#'+anchor},L.permalink));head.appendChild(links);td.appendChild(head);
if(f.status==='Open'&&!excluded(f)){var a=action(f),guidance=el('div',{'class':'action-guidance'});guidance.appendChild(el('strong',null,L[a]));guidance.appendChild(el('p',null,L[a+'_note']));td.appendChild(guidance);}else if(excluded(f)){td.appendChild(el('p',{'class':'muted'},L.excluded_note));}
function field(label,value){dl.appendChild(el('dt',null,label));var dd=el('dd');if(value instanceof Node)dd.appendChild(value);else dd.textContent=value;dl.appendChild(dd);}
field(L.location,f.location);if(f.prompts.length)field(L.prompt,f.prompts.join(', '));field(L.status,statusText(f));['symptom','cause','impact'].forEach(function(k){if(f[k])field(L[k],f[k]);});field(L.fix,f.fix||(f.status==='Open'&&!excluded(f)?L.missing_fix:L.not_recorded));
if(f.proposal){if(f.proposal.before)field(L.proposal_before,textNode(f.proposal.before));if(f.proposal.after)field(L.proposal_after,textNode(f.proposal.after));}
if(f.test)field(L.test,asText(f.test));field(L.evidence,f.validation.evidence||L.missing_evidence);if(f.validation.method)field(L.validation_method,f.validation.method);
if(f.snippet)field(L.snippet,snippetNode(f.snippet.start,f.snippet.lines,f.snippet.hit));
var refs=f.references||[];if(refs.length){var ul=el('ul',{'class':'refs'});refs.forEach(function(r){var li=el('li');li.appendChild(el('a',{href:r.url,target:'_blank',rel:'noopener noreferrer'},r.title||r.url));ul.appendChild(li);});field(L.references,ul);}td.appendChild(dl);
if(f.previous_validation&&typeof f.previous_validation==='object'){var history=el('aside',{'class':'history'});history.appendChild(el('strong',null,L.previous_validation));history.appendChild(el('p',null,L.history_note));['verdict','evidence','method'].forEach(function(k){if(typeof f.previous_validation[k]==='string')history.appendChild(el('p',null,f.previous_validation[k]));});td.appendChild(history);}dt.appendChild(td);}
var searchCache=new Map();
function searchText(f){if(searchCache.has(f))return searchCache.get(f);var val=f.validation||{},pr=f.proposal||{},text=[f.id,f.title,f.location,f.category,catText(f.category),f.prompts.join(' '),f.symptom,f.cause,f.impact,f.fix,pr.before,pr.after,asText(f.test),f.status,f.severity,f.kind,kindText(f),f.confidence,f.verdict,val.evidence,val.method].filter(Boolean).join('\n').toLowerCase();searchCache.set(f,text);return text;}
function draw(){clearTimeout(searchTimer);var tb=byId('rows');tb.textContent='';var term=q.value.trim().toLowerCase(),scope=v('f-scope');var pool=scope==='all'?ALL:ALL.filter(function(f){return scope==='excluded'?excluded(f):!excluded(f);});var shown=pool.filter(function(f){return (!v('f-part')||f.kind===v('f-part'))&&(!v('f-sev')||f.severity===v('f-sev'))&&(!v('f-conf')||f.confidence===v('f-conf'))&&(!v('f-cat')||f.category===v('f-cat'))&&(!v('f-prompt')||f.prompts.indexOf(v('f-prompt'))>=0)&&(!v('f-status')||f.status===v('f-status'))&&(!v('f-verdict')||f.verdict===v('f-verdict'))&&(!term||searchText(f).indexOf(term)>=0);});
shown.sort(function(a,b){var status=v('f-sort')==='priority'?Number(a.status!=='Open')-Number(b.status!=='Open'):0;return status||SEV.indexOf(a.severity)-SEV.indexOf(b.severity)||(v('f-sort')==='priority'?Number(action(a)!=='fix_now')-Number(action(b)!=='fix_now'):0)||D.parts.indexOf(a.kind)-D.parts.indexOf(b.kind)||String(a.id).localeCompare(String(b.id),'en',{numeric:true});});
byId('result-count').textContent=fmt(L.showing,{shown:shown.length,total:pool.length});
if(!shown.length){var empty=el('tr'),td=el('td',{colspan:7,'class':'empty'},pool.length?L.no_matches:L.no_records);empty.appendChild(td);tb.appendChild(empty);return;}
shown.forEach(function(f){var anchor=D.anchors[f.id],tr=el('tr',{'class':'row',id:anchor}),dt=details(f,anchor);var labels=['ID',L.severity,L.part,L.confidence,L.verdict,L.title_col,L.category];var values=[f.id,null,kindText(f),f.confidence,f.verdict,null,catText(f.category)],button;
values.forEach(function(value,i){var cell=el('td',{'data-label':labels[i]},value);if(i===1)cell.appendChild(badge(f));if(i===5){button=el('button',{type:'button','class':'finding-toggle','aria-expanded':String(!dt.hidden),'aria-controls':dt.id},f.title);button.appendChild(el('span',{'class':'toggle-label'},dt.hidden?L.expand:L.collapse));cell.appendChild(button);cell.appendChild(el('code',{'class':'location'},f.location));}tr.appendChild(cell);});
function toggle(){if(dt.hidden)fillDetails(dt,f,anchor);dt.hidden=!dt.hidden;if(dt.hidden)expanded.delete(anchor);else expanded.add(anchor);button.setAttribute('aria-expanded',String(!dt.hidden));button.querySelector('.toggle-label').textContent=dt.hidden?L.expand:L.collapse;}
button.onclick=function(e){e.stopPropagation();toggle();};tr.onclick=function(e){if(!e.target.closest('a,button'))toggle();};tb.appendChild(tr);tb.appendChild(dt);});}
function openHash(){var anchor=window.location.hash.slice(1),f=ALL.find(function(x){return D.anchors[x.id]===anchor;});if(!f)return;expanded.add(anchor);draw();if(!byId(anchor)){reset();if(excluded(f))byId('f-scope').value='all';expanded.add(anchor);draw();}var row=byId(anchor);row.scrollIntoView({block:'start'});row.querySelector('button').focus({preventScroll:true});}
document.addEventListener('click',function(e){var a=e.target.closest('a[href^="#finding-"]');if(a&&a.getAttribute('href')===window.location.hash){e.preventDefault();openHash();}});
window.addEventListener('hashchange',openHash);draw();if(window.location.hash)openHash();
listInto(byId('decisions'),D.decisions,L.not_recorded);
// The level legend: every line comes from render.py's LEGEND, already narrowed to this record.
byId('levels-heading').textContent=D.legend.heading;[['severity',L.severity],['confidence',L.confidence]].forEach(function(k){byId('levels').appendChild(el('h3',null,k[1]));var dl=el('dl',{'class':'legend'});D.legend[k[0]].forEach(function(row){var dt=el('dt');if(k[0]==='severity')dt.appendChild(el('span',{'class':'badge '+row[0]},row[0]));else dt.textContent=row[0];dl.appendChild(dt);dl.appendChild(el('dd',null,row[1]));});byId('levels').appendChild(dl);});
D.legend.notes.forEach(function(n){byId('levels').appendChild(el('p',{'class':'muted'},n));});
['next_steps','checked_ok'].forEach(function(k){var p=el('section',{'class':'panel'});p.appendChild(el('h2',null,L[k]));listInto(p,D[k],L.not_recorded);byId('lists').appendChild(p);});
// Console layer: band, panels, triage board and inspector; its copy reuses the register's Markdown.
window.AgenticConsole.mount(D.console,{root:document,copy:function(card){var f=ALL.find(function(x){return String(x.id)===card.id;});return copyText(findingMarkdown(f));}});
})();
</script>
</body>
</html>
"""

# Dashboard wording; the record's kinds (defect, improvement) are its parts.
DASH_LABELS = {
    "en": {
        "eyebrow": "PROMPT REVIEW", "dash_title": "Prompt Findings",
        "report_note": "Static review · read-only · offline report",
        "report_link": "Print / report", "theme": "Toggle color theme",
        "priority": "Start here",
        "priority_note": "Open findings, ordered by severity, then readiness to fix. Check the cited prompt "
                         "and call site before changing the text.",
        "fix_now": "Plan the fix", "verify_first": "Verify first",
        "fix_now_note": "Valid, Confirmed finding. Apply the recorded fix direction or proposal and check it "
                        "with the recorded eval or test.",
        "verify_first_note": "Re-read the prompt as sent and the code around it, or run the recorded eval "
                             "case, before deciding on a change.",
        "more_high": "{n} more open High findings of this kind are listed in the findings register.",
        "more_high_one": "1 more open High finding of this kind is listed in the findings register.",
        "missing_fix": "Fix direction not recorded. Define the change after reviewing the evidence.",
        "no_open": "No open findings are recorded. This does not establish that the prompts behave as intended.",
        "no_findings": "No included findings are recorded. Review the scope and limitations before drawing "
                       "conclusions.",
        "included": "Included findings", "excluded_short": "Excluded", "open_count": "Open findings",
        "open_hm": "Open High/Medium", "needs_validation": "Open, needs validation",
        "closed_count": "Fix recorded / accepted", "all_records": "All records",
        "open_summary": "{n} open findings are recorded; none are High or Medium.",
        "open_summary_one": "1 open finding is recorded; it is not High or Medium.",
        "risk_summary": "{n} open High / Medium findings need attention.",
        "risk_summary_one": "1 open High / Medium finding needs attention.",
        "counts_note": "Report-wide totals include Open, Fixed and Accepted. Excluded findings do not "
                       "contribute to these totals.",
        "part": "Kind", "part_all": "All kinds",
        "part_defect": "Defects", "part_improvement": "Improvements",
        "part_short_defect": "Defect", "part_short_improvement": "Improvement",
        "part_note": "Defects are prompts or prompt assembly that is broken: unfilled variables, contradictions, "
                     "output-contract mismatches, injection boundaries, truncation. Improvements are prompts that "
                     "work but would work better; each carries a before/after proposal. L-* findings come from "
                     "inventory.py lint.",
        "part_card_sub": "Open High/Medium: {open_hm} · Total: {total}",
        "part_none_open": "No open findings of this kind.",
        "view_all": "View all findings", "queue_more": "Showing {shown} of {total} open findings.",
        "decisions": "Decisions required",
        "coverage_heading": "Scope, coverage and limitations",
        "coverage_note": "Coverage is recorded per perspective below. Missing perspectives or empty notes do "
                         "not mean they were checked. Zero findings does not mean the prompts behave as intended.",
        "scope_l": "Scope", "commit": "Revision", "prompts_l": "Prompts reviewed",
        "limitations": "Limitations", "limitations_count": "Recorded limitations",
        "limitations_empty": "No limitations were recorded. This is not evidence of complete coverage.",
        "perspectives": "Coverage by perspective", "coverage_missing": "No perspective coverage was recorded.",
        "not_recorded": "Not recorded",
        "overview": "Results overview",
        "count_basis": "Severity is potential impact; confidence is certainty. The verdict records whether the "
                       "finding applies.",
        "by_sev": "By severity", "by_kind": "By kind", "by_conf": "By confidence", "by_cat": "By perspective",
        "by_status": "By status", "by_verdict": "By verdict",
        "excluded_note": "Excluded findings are retained with their justification. They are not counted in "
                         "included totals.",
        "findings_register": "Findings register",
        "findings_note": "Open a finding for its cause, proposal and how to check the fix. Totals above remain "
                         "report-wide while filtering.",
        "record_set": "Records", "included_set": "Included (excludes ruled-out findings)",
        "excluded_set": "Excluded only", "severity": "Severity", "confidence": "Confidence",
        "category": "Perspective", "prompt": "Prompt", "status": "Status", "verdict": "Verdict",
        "all_verdicts": "All verdicts", "sort": "Order", "priority_sort": "Open first, then severity",
        "severity_sort": "Severity", "search": "Search", "all": "All", "reset": "Clear filters",
        "showing": "Showing {shown} of {total} records in this view",
        "no_matches": "No findings match these filters. Clear filters to see more.",
        "no_records": "No records in this view.", "title_col": "Title",
        "expand": "Show details", "collapse": "Hide details", "permalink": "Link to finding",
        "copy_llm": "Copy for LLM", "copied": "Copied", "copy_failed": "Copy failed",
        "location": "Location", "symptom": "Symptom", "cause": "Cause", "impact": "Impact",
        "fix": "Fix direction", "proposal_before": "Current text", "proposal_after": "Proposed text",
        "test": "How to check", "evidence": "Verdict evidence", "validation_method": "Validation method",
        "snippet": "Source", "references": "References",
        "previous_validation": "Previous validation (historical; not the current verdict)",
        "history_note": "Revalidate this evidence against the current prompts and code.",
        "missing_evidence": "No validation evidence recorded.",
        "next_steps": "Recommended next steps", "checked_ok": "Checked and sound",
        "source_note": "Source excerpts are best-effort redacted. Inspect this report before sharing.",
        "no_script": "Enable JavaScript to use the interactive dashboard, or open the report for the complete "
                     "record.",
        "jump_findings": "Jump to findings",
    },
    "ja": {
        "eyebrow": "PROMPT REVIEW", "dash_title": "プロンプト診断結果",
        "report_note": "静的レビュー · 読み取り専用 · オフラインレポート",
        "report_link": "印刷用のレポート", "theme": "配色を切り替え",
        "priority": "まず取り組むこと",
        "priority_note": "未対応の指摘を深刻度順、同じ深刻度では修正判断の準備ができた順に表示します。"
                         "文面を変える前に、該当プロンプトと呼び出し箇所を確認してください。",
        "fix_now": "修正を計画", "verify_first": "先に検証する",
        "fix_now_note": "Valid・Confirmed の指摘です。記録された修正方針または改善案を適用し、記録された評価・テストで確認してください。",
        "verify_first_note": "送信されるプロンプト全体と周辺コードを読み直すか、記録された評価ケースを実行してから変更要否を判断してください。",
        "more_high": "この種別には未対応の High がほかに {n} 件あります（指摘一覧に記載）。",
        "missing_fix": "修正方針が未記録です。根拠を確認し、変更内容を具体化してください。",
        "no_open": "未対応の指摘は記録されていません。プロンプトが意図どおりに動くことを保証するものではありません。",
        "no_findings": "集計対象の指摘はありません。診断範囲と制約を確認してから判断してください。",
        "included": "集計対象の指摘", "excluded_short": "除外", "open_count": "未対応の指摘",
        "open_hm": "未対応の高・中", "needs_validation": "未対応・要検証",
        "closed_count": "修正の申告 / 受容", "all_records": "すべての記録",
        "open_summary": "未対応の指摘は {n} 件です。High / Medium は含まれていません。",
        "risk_summary": "未対応の High / Medium が {n} 件あります。",
        "counts_note": "全体集計には Open・Fixed・Accepted を含みます。除外した指摘は含みません。",
        "part": "種別", "part_all": "すべての種別",
        "part_defect": "不具合", "part_improvement": "改善提案",
        "part_short_defect": "不具合", "part_short_improvement": "改善提案",
        "part_note": "不具合は、プロンプトやその組み立てが壊れているものです（埋まらない変数、指示の矛盾、出力形式とパーサーの不一致、"
                     "インジェクション境界、切り詰め）。改善提案は、動作はするがより良くできるもので、現在の文面と提案文を併記しています。"
                     "L-* は inventory.py の機械チェックによる指摘です。",
        "part_card_sub": "未対応の高・中: {open_hm} 件 · 計 {total} 件",
        "part_none_open": "この種別に未対応の指摘はありません。",
        "view_all": "指摘一覧を見る", "queue_more": "未対応 {total} 件のうち {shown} 件を表示しています。",
        "decisions": "判断が必要な事項",
        "coverage_heading": "診断範囲・確認状況・制約",
        "coverage_note": "観点ごとの確認状況を下に示します。観点や備考の記載がない場合、確認済みとは見なしません。"
                         "指摘がゼロでも、プロンプトが意図どおりに動く保証にはなりません。",
        "scope_l": "範囲", "commit": "リビジョン", "prompts_l": "対象プロンプト",
        "limitations": "制約事項", "limitations_count": "記録された制約",
        "limitations_empty": "制約事項が記録されていません。すべて確認済みであることを示すものではありません。",
        "perspectives": "観点別の診断結果", "coverage_missing": "観点ごとの確認状況が記録されていません。",
        "not_recorded": "未記録",
        "overview": "結果概要",
        "count_basis": "深刻度は想定される影響、確度は確かさ、検証判定はこの対象に指摘が成立するかを表します。",
        "by_sev": "深刻度別", "by_kind": "種別別", "by_conf": "確度別", "by_cat": "観点別",
        "by_status": "状態別", "by_verdict": "検証判定別",
        "excluded_note": "除外した指摘も、その根拠とともに保持します。集計対象の件数には含めません。",
        "findings_register": "指摘一覧",
        "findings_note": "指摘を開くと原因・改善案・修正の確認方法を確認できます。絞り込んでも上部の全体集計は変わりません。",
        "record_set": "表示対象", "included_set": "集計対象（誤検知・対象外を除く）",
        "excluded_set": "除外した指摘のみ", "severity": "深刻度", "confidence": "確度",
        "category": "観点", "prompt": "プロンプト", "status": "状態", "verdict": "検証判定",
        "all_verdicts": "すべての検証判定", "sort": "表示順", "priority_sort": "未対応を先に、深刻度順",
        "severity_sort": "深刻度順", "search": "検索", "all": "すべて", "reset": "絞り込みを解除",
        "showing": "この表示対象 {total} 件中 {shown} 件を表示",
        "no_matches": "条件に一致する指摘はありません。絞り込みを解除すると、ほかの指摘を確認できます。",
        "no_records": "この表示対象に該当する記録はありません。", "title_col": "件名",
        "expand": "詳細を開く", "collapse": "詳細を閉じる", "permalink": "この指摘へのリンク",
        "copy_llm": "LLM用にコピー", "copied": "コピーしました", "copy_failed": "コピーできませんでした",
        "location": "場所", "symptom": "症状", "cause": "原因", "impact": "影響",
        "fix": "修正方針", "proposal_before": "現在の文面", "proposal_after": "提案する文面",
        "test": "確認方法", "evidence": "判定の根拠", "validation_method": "検証方法",
        "snippet": "該当ソース", "references": "参照",
        "previous_validation": "以前の判定（履歴。現在の判定ではありません）",
        "history_note": "現在のプロンプト・コードに照らして再検証してください。",
        "missing_evidence": "判定の根拠が記録されていません。",
        "next_steps": "推奨する対応順", "checked_ok": "問題がなかった確認項目",
        "source_note": "ソース抜粋の伏せ字は完全ではありません。共有前に内容を確認してください。",
        "no_script": "対話型ダッシュボードには JavaScript が必要です。レポートではすべての記録を確認できます。",
        "jump_findings": "指摘一覧へ移動",
    },
}


def dashboard_model(data):
    """Counts and the open queue, as the dashboard shows them."""
    findings = data.get("findings", [])
    included = [f for f in findings if f["validation"]["verdict"] not in EXCLUDED]
    open_ = [f for f in included if f.get("status", "Open") == "Open"]

    def action(f):
        return "fix_now" if f["validation"]["verdict"] == "Valid" and f["confidence"] == "Confirmed" else "verify_first"

    queue = sorted(open_, key=lambda f: (SEVERITIES.index(f["severity"]), action(f) != "fix_now",
                                         KINDS.index(f["kind"]), id_key(f["id"])))
    return {
        "queue": [{"id": f["id"], "kind": f["kind"], "action": action(f)} for f in queue],
        "open_count": len(open_), "open_hm": sum(f["severity"] in ("High", "Medium") for f in open_),
        "fix_now": sum(action(f) == "fix_now" for f in open_),
        "verify_first": sum(action(f) == "verify_first" for f in open_),
        "fixed": sum(f.get("status") == "Fixed" for f in included),
        "accepted": sum(f.get("status") == "Accepted" for f in included),
        "excluded": len(findings) - len(included),
        "parts": {kind: {"open_count": sum(f["kind"] == kind for f in open_),
                         "open_hm": sum(f["kind"] == kind and f["severity"] in ("High", "Medium") for f in open_),
                         "total": sum(f["kind"] == kind for f in included)} for kind in KINDS},
    }


def render_dashboard(data, L, lang, excerpts):
    meta = data.get("meta", {})
    labels = {**L, **DASH_LABELS[lang]}
    items = []
    for f in data.get("findings", []):
        prompt = f.get("prompt")
        x = excerpts.get(f["id"])
        item = {k: f[k] for k in ("id", "kind", "severity", "confidence", "category", "title", "location",
                                  "symptom", "cause", "impact", "fix", "proposal", "test", "references",
                                  "previous_validation") if k in f}
        item.update(status=f.get("status", "Open"), verdict=f["validation"]["verdict"], validation=f["validation"],
                    prompts=[prompt] if isinstance(prompt, str) else (prompt or []),
                    snippet={"start": x[0], "lines": x[1], "hit": list(x[2])} if x else None)
        items.append(item)
    model = dashboard_model(data)
    prompts = data.get("prompts", [])
    payload = {
        "meta": {"target": meta.get("target", ""), "date": meta.get("date"), "assessor": meta.get("assessor"),
                 "scope": meta.get("scope"),
                 "commit": revision(meta, L), "axis": axis(meta, L),
                 "prompts": ", ".join(f'{p["id"]} {p["name"]}' for p in prompts) or None},
        "labels": labels, "legend": legend(meta, lang), "headline": summary_line(data, L),
        "report": model, "console": console_model(data, model, labels), "findings": items,
        "anchors": {f["id"]: "finding-" + f["id"].lower() for f in data.get("findings", [])},
        "parts": KINDS, "prompt_ids": [p["id"] for p in prompts],
        "order": {"severity": SEVERITIES, "confidence": CONFIDENCES, "status": STATUSES, "verdict": VERDICTS},
        "excluded_verdicts": sorted(EXCLUDED),
        **{k: data.get(k, []) for k in STRING_LISTS},
        "perspectives": [{"name": perspective_label(p["name"], L),
                          **{k: p[k] for k in ("result", "note") if k in p}}
                         for p in data.get("perspectives", [])],
    }
    # Escape every less-than sign: <!-- and <script also change HTML parsing.
    blob = json.dumps(payload, ensure_ascii=False).replace("<", "\\u003c") \
        .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    replacements = {"__CSS__": report_style.dashboard_css() + DASH_CSS + report_style.console_css(),
                    "__CONSOLE_JS__": report_style.console_js(),
                    "__LANG__": lang, "__TITLE__": esc(f'{labels["dash_title"]} - {meta.get("target", "")}'),
                    "__NOSCRIPT__": esc(labels["no_script"]), "__REPORT__": esc(labels["report_link"]),
                    "__DATA__": blob}
    # Substitute only template tokens, not token-like strings inside report data.
    return re.sub(r"__(?:CSS|CONSOLE_JS|LANG|TITLE|NOSCRIPT|REPORT|DATA)__", lambda m: replacements[m.group(0)], DASHBOARD)


# ---------------------------------------------------------------- PDF

TIMEOUT_ENV = "PROMPT_SCAN_PDF_TIMEOUT"
OUTPUTS = ("dashboard.html", "report.html", "report.pdf")


def to_pdf(html_path, pdf_path, failures, timeout=None):
    """Print html_path with report_pdf (Chrome, else WeasyPrint). Returns the engine name or None.

    Each engine that was found but did not produce a PDF is appended to failures
    as one readable string; engine stderr is masked (mask) before it is recorded.
    """
    found = []
    timeout = report_pdf.pdf_timeout(env=TIMEOUT_ENV) if timeout is None else timeout
    engine = report_pdf.to_pdf(html_path, pdf_path, found, timeout, redact=mask)
    failures.extend(f"{name} {reason}" + (f": {detail}" if detail else "") for name, reason, detail in found)
    return engine


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("findings")
    p.add_argument("--out", required=True)
    p.add_argument("--lang", choices=sorted(LABELS), help="report language (default: meta.lang, else ja)")
    p.add_argument("--repo", help="reviewed repository, for embedded excerpts")
    p.add_argument("--no-pdf", action="store_true")
    a = p.parse_args(argv)
    try:
        source = Path(a.findings).read_bytes()
        data = load(a.findings, source)
        excerpts = attach_sources(data, a.repo)
        lang = a.lang or data.get("meta", {}).get("lang") or "ja"
        L = LABELS[lang]
        stamp = STAMP.format(hashlib.sha256(source).hexdigest())
        pages = {"dashboard.html": render_dashboard(data, L, lang, excerpts),
                 "report.html": render_report_html(data, L, lang, excerpts)}
    except (SchemaError, OSError) as e:
        print(f"render.py: {e}", file=sys.stderr)
        return 2
    out = Path(a.out)
    try:
        out.mkdir(parents=True, exist_ok=True)
        unsafe = unsafe_target(out, OUTPUTS)
        if unsafe:
            raise OSError(f"refusing to write {unsafe}: it exists as a symlink or non-regular file")
        # A previous run's PDF must never survive next to newer HTML.
        (out / "report.pdf").unlink(missing_ok=True)
        for name, page in pages.items():
            write_output(out / name, page.replace("<head>", "<head>" + stamp, 1))
            print(f"wrote {out / name}")
        if a.no_pdf:
            return 0
    except OSError as e:
        print(f"render.py: cannot write outputs to {out}: {e}", file=sys.stderr)
        return 2
    failures = []
    timeout = report_pdf.pdf_timeout(len(data.get("findings", [])), env=TIMEOUT_ENV)
    engine = to_pdf(out / "report.html", out / "report.pdf", failures, timeout)
    if not engine:
        reason = "; ".join(failures) if failures else "no PDF engine found (Chrome/Chromium or weasyprint)"
        print(f"render.py: {reason}. report.html is ready to print. Without an engine anywhere: merge the "
              "limitation 'report.pdf not produced: no PDF engine', re-run with --no-pdf, then "
              "contract_check.py <out> --no-pdf", file=sys.stderr)
        return 3
    print(f"wrote {out / 'report.pdf'} ({engine})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
