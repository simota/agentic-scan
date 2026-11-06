#!/usr/bin/env python3
"""Compare two findings.json records: what is new, resolved, still open or changed.

    python3 compare.py BASELINE CURRENT [--format markdown|json] [--lang ja|en]
                       [--fail-on High|Medium|Low|Info]

BASELINE is an earlier run's record and CURRENT a later run's record of the same
application (for example before and after a round of fixes). IDs are renumbered
on every run, so findings are matched by root cause instead: the same
`category`, then shared location files, the hunt `step` and title similarity;
line numbers are ignored because they move between revisions.

A finding is *active* while it is included (not `FalsePositive` or
`NotApplicable`) and not `Fixed`. Each active finding lands in one bucket:

- new: active now, not active in the baseline (absent, Fixed or excluded there)
- resolved: active in the baseline, and now Fixed, excluded, or absent while
  the current run applied its perspective
- not re-checked: active in the baseline and absent now, but the current run
  did not apply its perspective, so its absence proves nothing
- persisting: active in both runs; severity, confidence, verdict, status and
  location-file changes are listed

Budgets are matched by statement (then by ID) and perspectives by name; their
status changes are listed. The comparison is printed to stdout as Markdown (the
record's strings are escaped as in report.md) or as JSON.

`--fail-on SEVERITY` turns the comparison into a gate: exit 1 when a new or
escalated finding that is `Open` has at least that severity. Use it in CI
against an accepted baseline so that only regressions fail the build.

Exit codes: 0 compared (and the gate, if any, passed), 1 the gate failed,
2 an input could not be read or does not match the schema, or a usage error.
"""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import (EXCLUDED, LOCATION, SEVERITIES, SchemaError,  # noqa: E402
                      escape_unencodable_console, finding_locations, finding_status,
                      read_json, validate)
from render import markdown_cell, markdown_text  # noqa: E402

# Two findings of one category are the same root cause when they share a file
# or, failing that, when their titles are this similar.
TITLE_MATCH = 0.8

LABELS = {
    "en": {
        "title": "Changes since baseline", "baseline": "Baseline", "current": "Current",
        "open_counts": "Active findings by severity", "summary": "Summary",
        "new": "New", "resolved": "Resolved", "unchecked": "Not re-checked",
        "persisting": "Persisting", "changed": "changed", "unchanged": "unchanged",
        "budgets": "Budget changes", "perspectives": "Perspective changes",
        "notes": "Notes", "none": "None.",
        "change_col": "Change", "current_id": "Current ID", "baseline_id": "Baseline ID",
        "severity": "Severity", "title_col": "Title", "location": "Location",
        "id": "ID", "statement": "Budget", "from": "Baseline", "to": "Current",
        "perspective": "Perspective",
        "reason_absent": "no longer reported", "reason_fixed": "marked Fixed",
        "reason_excluded": "now {verdict}", "reason_reappeared": "was Fixed in the baseline",
        "reason_was_excluded": "was {verdict} in the baseline",
        "reason_unchecked": "{category} is {status} in the current run",
        "reason_first": "first reported",
        "added": "added", "dropped": "not in the current run",
        "scope_differs": "The scopes differ (baseline: {old}; current: {new}); a finding "
                         "missing from the current run may lie outside its scope.",
        "same_commit": "Both records name the same revision ({commit}); differences come "
                       "from the review, not from code changes.",
        "gate_ok": "gate passed: no new or escalated Open finding at {severity} or above",
        "gate_failed": "gate failed: {count} new or escalated Open finding(s) at {severity} "
                       "or above: {ids}",
    },
    "ja": {
        "title": "ベースラインからの変化", "baseline": "ベースライン", "current": "今回",
        "open_counts": "深刻度別の未解決の検出事項", "summary": "概要",
        "new": "新規", "resolved": "解消", "unchecked": "未再確認",
        "persisting": "継続", "changed": "変化あり", "unchanged": "変化なし",
        "budgets": "バジェットの変化", "perspectives": "観点の変化",
        "notes": "注記", "none": "なし。",
        "change_col": "変化", "current_id": "今回の ID", "baseline_id": "前回の ID",
        "severity": "深刻度", "title_col": "タイトル", "location": "場所",
        "id": "ID", "statement": "バジェット", "from": "前回", "to": "今回",
        "perspective": "観点",
        "reason_absent": "今回は報告されていない", "reason_fixed": "Fixed に更新",
        "reason_excluded": "今回は {verdict}", "reason_reappeared": "前回は Fixed",
        "reason_was_excluded": "前回は {verdict}",
        "reason_unchecked": "今回の {category} は {status}",
        "reason_first": "初めて報告",
        "added": "追加", "dropped": "今回の記録にない",
        "scope_differs": "対象範囲が異なる（前回: {old}、今回: {new}）。今回報告されていない"
                         "検出事項は、今回の範囲外にある可能性がある。",
        "same_commit": "両方の記録が同じリビジョン（{commit}）を指している。差分はコードの"
                       "変更ではなくレビューの違いによる。",
        "gate_ok": "ゲート通過: {severity} 以上の新規・深刻化した Open の検出事項はない",
        "gate_failed": "ゲート失敗: {severity} 以上の新規・深刻化した Open の検出事項が "
                       "{count} 件: {ids}",
    },
}
CHANGE_FIELDS = ("severity", "confidence", "verdict", "status")


def is_active(finding):
    return (finding["validation"]["verdict"] not in EXCLUDED
            and finding_status(finding) != "Fixed")


def location_files(finding):
    return frozenset(LOCATION.fullmatch(loc)["path"].strip() for loc in finding_locations(finding))


def normalized_title(finding):
    return " ".join(finding["title"].casefold().split())


def bigrams(text):
    """Character bigrams: they compare titles in any script, with or without spaces."""
    return frozenset(text[k:k + 2] for k in range(len(text) - 1)) or frozenset((text,))


def similarity(a, b):
    """Dice coefficient of two bigram sets, 0..1."""
    return 2 * len(a & b) / (len(a) + len(b))


def _step(finding):
    return finding.get("step", "").strip()


def _greedy(candidates, pairs, used_new):
    """Assign (-score, i, j) candidates best first, one-to-one, into pairs."""
    for _, i, j in sorted(candidates):
        if i not in pairs and j not in used_new:
            pairs[i] = j
            used_new.add(j)


def match_findings(baseline, current):
    """One-to-one pairs {baseline index: current index} of findings with one root cause.

    Only findings of the same category can match. First pass: findings sharing
    a location file, scored by file overlap, title similarity and the hunt step.
    Then, for what is left, an identical title, and finally a title at least
    TITLE_MATCH similar by character bigrams (a file renamed or moved). Indexing by file and title
    keeps the usual case linear; only the leftovers are compared pairwise.
    """
    files = [location_files(f) for f in baseline], [location_files(f) for f in current]
    titles = [normalized_title(f) for f in baseline], [normalized_title(f) for f in current]
    grams = [bigrams(t) for t in titles[0]], [bigrams(t) for t in titles[1]]
    by_file = {}
    for j, new in enumerate(current):
        for path in files[1][j]:
            by_file.setdefault((new["category"], path), set()).add(j)
    candidates = []
    for i, old in enumerate(baseline):
        for j in set().union(*(by_file.get((old["category"], path), set())
                               for path in files[0][i])):
            new = current[j]
            overlap = len(files[0][i] & files[1][j]) / len(files[0][i] | files[1][j])
            title = similarity(grams[0][i], grams[1][j])
            same_step = 0.5 if _step(old) and _step(old) == _step(new) else 0.0
            candidates.append((-(2 * overlap + title + same_step), i, j))
    pairs, used_new = {}, set()
    _greedy(candidates, pairs, used_new)
    by_title = {}
    for j, new in enumerate(current):
        if j not in used_new:
            by_title.setdefault((new["category"], titles[1][j]), []).append(j)
    for i, old in enumerate(baseline):
        if i in pairs:
            continue
        free = [j for j in by_title.get((old["category"], titles[0][i]), ()) if j not in used_new]
        if free:
            pairs[i] = free[0]
            used_new.add(free[0])
    candidates = []
    for j, new in enumerate(current):
        if j in used_new:
            continue
        size = len(grams[1][j])
        for i, old in enumerate(baseline):
            if i in pairs or old["category"] != new["category"]:
                continue
            other = len(grams[0][i])
            # The Dice coefficient cannot exceed 2 min / sum: skip without intersecting.
            if 2 * min(size, other) < TITLE_MATCH * (size + other):
                continue
            score = similarity(grams[0][i], grams[1][j])
            if score >= TITLE_MATCH:
                candidates.append((-score, i, j))
    _greedy(candidates, pairs, used_new)
    return pairs


def finding_fields(f):
    return {"severity": f["severity"], "confidence": f["confidence"],
            "verdict": f["validation"]["verdict"], "status": finding_status(f)}


def summary_entry(change, old, new, reason=None):
    shown = new or old
    entry = {"change": change, "current_id": new["id"] if new else None,
             "baseline_id": old["id"] if old else None, "severity": shown["severity"],
             "category": shown["category"], "title": shown["title"],
             "location": finding_locations(shown)[0]}
    if reason:
        entry["reason"] = reason
    return entry


def compare_findings(baseline, current, perspectives):
    """Bucket every active finding; perspectives maps a category to its current status."""
    pairs = match_findings(baseline, current)
    matched_new = set(pairs.values())
    result = {"new": [], "resolved": [], "unchecked": [], "persisting": []}
    for i, old in enumerate(baseline):
        new = current[pairs[i]] if i in pairs else None
        if new is None:
            if not is_active(old):
                continue
            status = perspectives.get(old["category"], "not checked")
            if status == "applied":
                result["resolved"].append(summary_entry("resolved", old, None,
                                                        {"kind": "absent"}))
            else:
                result["unchecked"].append(summary_entry(
                    "unchecked", old, None,
                    {"kind": "unchecked", "category": old["category"], "status": status}))
        elif is_active(old) and is_active(new):
            before, after = finding_fields(old), finding_fields(new)
            changes = {key: {"from": before[key], "to": after[key]}
                       for key in CHANGE_FIELDS if before[key] != after[key]}
            old_files, new_files = location_files(old), location_files(new)
            if old_files != new_files:
                changes["files"] = {"from": sorted(old_files), "to": sorted(new_files)}
            entry = summary_entry("persisting", old, new)
            entry["changes"] = changes
            entry["escalated"] = (SEVERITIES.index(new["severity"])
                                  < SEVERITIES.index(old["severity"]))
            entry["status"] = finding_status(new)
            result["persisting"].append(entry)
        elif is_active(old):
            reason = ({"kind": "fixed"} if finding_status(new) == "Fixed"
                      else {"kind": "excluded", "verdict": new["validation"]["verdict"]})
            result["resolved"].append(summary_entry("resolved", old, new, reason))
        elif is_active(new):
            reason = ({"kind": "reappeared"} if finding_status(old) == "Fixed"
                      else {"kind": "was_excluded", "verdict": old["validation"]["verdict"]})
            entry = summary_entry("new", old, new, reason)
            entry["status"] = finding_status(new)
            result["new"].append(entry)
    for j, new in enumerate(current):
        if j not in matched_new and is_active(new):
            entry = summary_entry("new", None, new, {"kind": "first"})
            entry["status"] = finding_status(new)
            result["new"].append(entry)
    order = {s: n for n, s in enumerate(SEVERITIES)}
    for bucket in result.values():
        bucket.sort(key=lambda e: (order[e["severity"]], e["current_id"] or "",
                                   e["baseline_id"] or ""))
    return result


def normalized_statement(budget):
    return " ".join(budget["statement"].casefold().split())


def compare_budgets(baseline, current):
    """Status changes of budgets matched by statement, then by ID; added and dropped ones."""
    remaining = list(current)
    changes = []
    unmatched_old = []
    for old in baseline:
        found = next((b for b in remaining
                      if normalized_statement(b) == normalized_statement(old)), None)
        if found is None:
            unmatched_old.append(old)
        else:
            remaining.remove(found)
            changes.append((old, found))
    for old in list(unmatched_old):
        found = next((b for b in remaining if b["id"] == old["id"]), None)
        if found is not None:
            remaining.remove(found)
            unmatched_old.remove(old)
            changes.append((old, found))
    rows = [{"baseline_id": old["id"], "current_id": new["id"], "statement": new["statement"],
             "from": old["status"], "to": new["status"]}
            for old, new in changes if old["status"] != new["status"]]
    rows += [{"baseline_id": old["id"], "current_id": None, "statement": old["statement"],
              "from": old["status"], "to": None} for old in unmatched_old]
    rows += [{"baseline_id": None, "current_id": new["id"], "statement": new["statement"],
              "from": None, "to": new["status"]} for new in remaining]
    return rows


def compare_perspectives(baseline, current):
    old = {p["name"]: p["status"] for p in baseline}
    new = {p["name"]: p["status"] for p in current}
    return [{"name": name, "from": old.get(name), "to": new.get(name)}
            for name in [*old, *(n for n in new if n not in old)]
            if old.get(name) != new.get(name)]


def active_counts(findings):
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        if is_active(f):
            counts[f["severity"]] += 1
    return counts


def compare(baseline, current):
    """The whole comparison as plain data (what --format json prints)."""
    perspectives = {p["name"]: p["status"] for p in current.get("perspectives", [])}
    run = lambda doc: {key: doc["meta"].get(key, "") for key in  # noqa: E731
                       ("project", "scope", "commit", "date", "assessor")}
    result = {
        "baseline": run(baseline), "current": run(current),
        "counts": {"baseline": active_counts(baseline.get("findings", [])),
                   "current": active_counts(current.get("findings", []))},
        "findings": compare_findings(baseline.get("findings", []),
                                     current.get("findings", []), perspectives),
        "budgets": compare_budgets(baseline.get("budgets", []), current.get("budgets", [])),
        "perspectives": compare_perspectives(baseline.get("perspectives", []),
                                             current.get("perspectives", [])),
    }
    notes = []
    old_scope, new_scope = baseline["meta"]["scope"].strip(), current["meta"]["scope"].strip()
    if old_scope != new_scope:
        notes.append({"kind": "scope_differs", "old": old_scope, "new": new_scope})
    old_commit = baseline["meta"].get("commit", "").strip()
    if old_commit and old_commit == current["meta"].get("commit", "").strip():
        notes.append({"kind": "same_commit", "commit": old_commit})
    result["notes"] = notes
    return result


def gate(result, threshold):
    """IDs of new or escalated Open findings at threshold severity or above."""
    limit = SEVERITIES.index(threshold)
    tripped = [e for e in result["findings"]["new"]
               if e["status"] == "Open" and SEVERITIES.index(e["severity"]) <= limit]
    tripped += [e for e in result["findings"]["persisting"]
                if e["escalated"] and e["status"] == "Open"
                and SEVERITIES.index(e["severity"]) <= limit]
    return sorted(e["current_id"] for e in tripped)


def reason_text(reason, t):
    if not reason:
        return ""
    template = t[f"reason_{reason['kind']}"]
    return template.format(**{k: v for k, v in reason.items() if k != "kind"})


def change_text(entry, t):
    if entry["change"] != "persisting":
        return reason_text(entry.get("reason"), t)
    parts = []
    for key, change in entry["changes"].items():
        if key == "files":
            parts.append(f"files {', '.join(change['from'])} → {', '.join(change['to'])}")
        else:
            parts.append(f"{key} {change['from']} → {change['to']}")
    return "; ".join(parts) or t["unchanged"]


def run_line(run):
    commit = run["commit"].strip() or "UNKNOWN"
    return f"{run['project']} · {commit} · {run['date']} · {run['assessor']}"


def finding_rows(entries, t):
    headers = (t["change_col"], t["current_id"], t["baseline_id"], t["severity"],
               t["title_col"], t["location"])
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    for e in entries:
        cells = (markdown_cell(change_text(e, t)), e["current_id"] or "—",
                 e["baseline_id"] or "—", e["severity"], markdown_cell(e["title"]),
                 markdown_cell(e["location"]))
        lines.append("| " + " | ".join(cells) + " |")
    return lines


def render_markdown(result, lang):
    t = LABELS[lang]
    f = result["findings"]
    changed = [e for e in f["persisting"] if e["changes"]]
    lines = [f"# {t['title']}: {markdown_text(result['current']['project'])}", "",
             f"- **{t['baseline']}:** {markdown_text(run_line(result['baseline']))}",
             f"- **{t['current']}:** {markdown_text(run_line(result['current']))}", ""]
    old, new = result["counts"]["baseline"], result["counts"]["current"]

    def delta(severity):
        diff = new[severity] - old[severity]
        return f"{severity} {old[severity]} → {new[severity]}" + (
            f" ({diff:+d})" if diff else "")

    lines += [f"**{t['open_counts']}:** " + " / ".join(delta(s) for s in SEVERITIES), ""]
    lines += [f"**{t['summary']}:** {t['new']} {len(f['new'])} · {t['resolved']} "
              f"{len(f['resolved'])} · {t['unchecked']} {len(f['unchecked'])} · "
              f"{t['persisting']} {len(f['persisting'])} ({t['changed']} {len(changed)})", ""]
    for key, entries in (("new", f["new"]), ("resolved", f["resolved"]),
                         ("unchecked", f["unchecked"]), ("persisting", f["persisting"])):
        lines += [f"## {t[key]} ({len(entries)})", ""]
        lines += (finding_rows(entries, t) if entries else [t["none"]]) + [""]
    lines += [f"## {t['budgets']}", ""]
    if result["budgets"]:
        lines += [f"| {t['id']} | {t['statement']} | {t['from']} | {t['to']} |", "|---|---|---|---|"]
        for b in result["budgets"]:
            ids = " → ".join(i for i in (b["baseline_id"], b["current_id"]) if i)
            if b["baseline_id"] and b["current_id"] and b["baseline_id"] == b["current_id"]:
                ids = b["current_id"]
            lines.append(f"| {markdown_cell(ids)} | {markdown_cell(b['statement'])} | "
                         f"{markdown_cell(b['from'] or t['added'])} | "
                         f"{markdown_cell(b['to'] or t['dropped'])} |")
    else:
        lines.append(t["none"])
    lines += ["", f"## {t['perspectives']}", ""]
    if result["perspectives"]:
        lines += [f"| {t['perspective']} | {t['from']} | {t['to']} |", "|---|---|---|"]
        for p in result["perspectives"]:
            lines.append(f"| {p['name']} | {p['from'] or '—'} | {p['to'] or '—'} |")
    else:
        lines.append(t["none"])
    if result["notes"]:
        lines += ["", f"## {t['notes']}", ""]
        for note in result["notes"]:
            text = t[note["kind"]].format(**{k: v for k, v in note.items() if k != "kind"})
            lines.append(f"- {markdown_text(text)}")
    return "\n".join(lines) + "\n"


def load(path):
    doc = read_json(path)
    try:
        validate(doc, complete=True)
    except SchemaError as exc:
        raise SchemaError(f"{path}: {exc}") from exc
    return doc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("baseline")
    parser.add_argument("current")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--lang", choices=("ja", "en"),
                        help="labels of the Markdown output (default: the current record's)")
    parser.add_argument("--fail-on", choices=SEVERITIES, metavar="SEVERITY",
                        help="exit 1 when a new or escalated Open finding has at least "
                             "this severity (High, Medium, Low or Info)")
    args = parser.parse_args(argv)
    escape_unencodable_console()
    try:
        baseline, current = load(args.baseline), load(args.current)
    except SchemaError as exc:
        print(f"schema: {exc}", file=sys.stderr)
        return 2
    result = compare(baseline, current)
    lang = args.lang or current["meta"]["lang"]
    if args.fail_on:
        result["gate"] = {"fail_on": args.fail_on, "tripped": gate(result, args.fail_on)}
    if args.format == "json":
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        sys.stdout.write(render_markdown(result, lang))
    if args.fail_on:
        t = LABELS[lang]
        tripped = result["gate"]["tripped"]
        if tripped:
            print(t["gate_failed"].format(count=len(tripped), severity=args.fail_on,
                                          ids=", ".join(tripped)), file=sys.stderr)
            return 1
        print(t["gate_ok"].format(severity=args.fail_on), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
