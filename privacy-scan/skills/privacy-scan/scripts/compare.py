"""Compare two assessments of the same application: what is new, resolved, reopened or persisting.

Used by `findings.py diff OLD NEW`. IDs are renumbered on every run, so findings
are matched by what they are about, not by ID, in three passes, each one-to-one:

1. the same perspective, hunt step and path of the first `location`
2. the same perspective and any shared location path
3. the same perspective and the same title (a file moved or was renamed)

Within a pass, closer first-location lines and more similar titles win. The
match is a heuristic: the output says which pass matched each pair, so a person
can confirm it. A finding is *active* when it is reported (not `FalsePositive`
or `NotApplicable`) and its status is not `Fixed`.

| OLD     | NEW      | Class      |
|---------|----------|------------|
| active  | active   | persisting |
| active  | inactive | resolved   |
| active  | (none)   | resolved   |
| inactive| active   | reopened   |
| (none)  | active   | new        |

Both records pass the schema check first. Only IDs, titles, severities and
paths from those records are printed, which the personal-value guard has
already accepted.
"""
from difflib import SequenceMatcher
import re

SEVERITIES = ("High", "Medium", "Low", "Info")
EXCLUDED = ("FalsePositive", "NotApplicable")
PASSES = ("location", "path", "title")
TRACKED = (("severity", lambda f: f["severity"]),
           ("confidence", lambda f: f["confidence"]),
           ("verdict", lambda f: f["validation"]["verdict"]),
           ("status", lambda f: f.get("status", "Open")))

LABELS = {
    "en": {
        "title": "Assessment comparison", "old": "Earlier", "new": "Current",
        "revision": "revision", "date": "date",
        "summary": "{new} new, {reopened} reopened, {resolved} resolved, {persisting} persisting",
        "classes": {"new": "New", "reopened": "Reopened", "resolved": "Resolved",
                    "persisting": "Persisting"},
        "reasons": {"gone": "no longer reported", "Fixed": "marked Fixed",
                    "FalsePositive": "excluded as FalsePositive",
                    "NotApplicable": "excluded as NotApplicable"},
        "matched": {"location": "same location", "path": "shared path", "title": "same title"},
        "counts": "Active findings by severity", "commitments": "Commitments",
        "added": "added", "removed": "no longer in the ledger", "none": "None.",
        "note": "Findings are matched by perspective, location and title, not by ID; "
                "confirm each pair before relying on it.",
        "unchanged": "unchanged",
    },
    "ja": {
        "title": "診断結果の比較", "old": "前回", "new": "今回",
        "revision": "リビジョン", "date": "診断日",
        "summary": "新規 {new} 件、再発 {reopened} 件、解消 {resolved} 件、継続 {persisting} 件",
        "classes": {"new": "新規", "reopened": "再発", "resolved": "解消", "persisting": "継続"},
        "reasons": {"gone": "報告されなくなった", "Fixed": "Fixed に更新された",
                    "FalsePositive": "FalsePositive として除外された",
                    "NotApplicable": "NotApplicable として除外された"},
        "matched": {"location": "同じ場所", "path": "共通のパス", "title": "同じタイトル"},
        "counts": "対応が必要な検出事項（深刻度別）", "commitments": "プライバシー上の約束",
        "added": "追加", "removed": "台帳から外れた", "none": "なし。",
        "note": "検出事項は ID ではなく観点・場所・タイトルで対応づけている。"
                "各組を確認してから利用すること。",
        "unchanged": "変化なし",
    },
}


def _locations(f):
    return f["location"] if isinstance(f["location"], list) else [f["location"]]


def _path_line(location):
    path, _, lines = location.rpartition(":")
    return path, int(lines.split("-")[0])


def reported(f):
    return f["validation"]["verdict"] not in EXCLUDED


def active(f):
    return reported(f) and f.get("status", "Open") != "Fixed"


def _normal(text):
    return re.sub(r"\s+", " ", text).strip().casefold()


def _eligible(kind, a, b):
    if a["category"] != b["category"]:
        return False
    if kind == "location":
        return (_path_line(_locations(a)[0])[0] == _path_line(_locations(b)[0])[0]
                and a.get("step", "").strip() == b.get("step", "").strip())
    if kind == "path":
        return bool({_path_line(x)[0] for x in _locations(a)}
                    & {_path_line(x)[0] for x in _locations(b)})
    return _normal(a["title"]) == _normal(b["title"])


def _distance(a, b):
    (path_a, line_a), (path_b, line_b) = _path_line(_locations(a)[0]), _path_line(_locations(b)[0])
    lines = abs(line_a - line_b) if path_a == path_b else 10 ** 9
    return (lines, -SequenceMatcher(None, _normal(a["title"]), _normal(b["title"])).ratio())


def match(old, new):
    """Pair old and new findings one-to-one; return [(old_index, new_index, pass)]."""
    pairs, used_old, used_new = [], set(), set()
    for kind in PASSES:
        candidates = sorted(
            (_distance(a, b), i, j)
            for i, a in enumerate(old) if i not in used_old
            for j, b in enumerate(new) if j not in used_new and _eligible(kind, a, b))
        for _, i, j in candidates:
            if i not in used_old and j not in used_new:
                used_old.add(i)
                used_new.add(j)
                pairs.append((i, j, kind))
    return pairs


def _summary(f):
    return {"id": f["id"], "severity": f["severity"], "title": f["title"],
            "category": f["category"], "location": _locations(f)[0]}


def _commitment_changes(old, new):
    """Match ledger entries by statement first, then by ID; report status changes."""
    old_rows, new_rows = old.get("commitments", []), new.get("commitments", [])
    pairs, used_old, used_new = [], set(), set()
    for key in (lambda r: _normal(r["statement"]), lambda r: r["id"]):
        index = {}
        for i, r in enumerate(old_rows):
            if i not in used_old:
                index.setdefault(key(r), i)
        for j, r in enumerate(new_rows):
            i = index.get(key(r))
            if j not in used_new and i is not None and i not in used_old:
                used_old.add(i)
                used_new.add(j)
                pairs.append((i, j))
    changed = [{"old_id": old_rows[i]["id"], "id": new_rows[j]["id"],
                "statement": new_rows[j]["statement"],
                "from": old_rows[i]["status"], "to": new_rows[j]["status"]}
               for i, j in sorted(pairs, key=lambda p: p[1])
               if old_rows[i]["status"] != new_rows[j]["status"]]
    added = [{"id": r["id"], "statement": r["statement"], "status": r["status"]}
             for j, r in enumerate(new_rows) if j not in used_new]
    removed = [{"id": r["id"], "statement": r["statement"], "status": r["status"]}
               for i, r in enumerate(old_rows) if i not in used_old]
    return {"changed": changed, "added": added, "removed": removed}


def _severity_counts(doc):
    rows = [f for f in doc.get("findings", []) if active(f)]
    return {s: sum(f["severity"] == s for f in rows) for s in SEVERITIES}


def compare(old, new):
    """The comparison as plain data (the `--json` output)."""
    old_findings, new_findings = old.get("findings", []), new.get("findings", [])
    pairs = match(old_findings, new_findings)
    result = {"old": {k: old["meta"].get(k, "") for k in ("project", "commit", "date")},
              "new": {k: new["meta"].get(k, "") for k in ("project", "commit", "date")},
              "new_findings": [], "reopened": [], "resolved": [], "persisting": []}
    paired_old, paired_new = {i for i, _, _ in pairs}, {j for _, j, _ in pairs}
    for i, j, kind in sorted(pairs, key=lambda p: (p[1], p[0])):
        a, b = old_findings[i], new_findings[j]
        if active(a) and active(b):
            changes = {name: {"from": get(a), "to": get(b)}
                       for name, get in TRACKED if get(a) != get(b)}
            result["persisting"].append({**_summary(b), "old_id": a["id"], "matched_by": kind,
                                         "changes": changes})
        elif active(a):
            reason = b["validation"]["verdict"] if not reported(b) else "Fixed"
            result["resolved"].append({**_summary(a), "new_id": b["id"], "matched_by": kind,
                                       "reason": reason})
        elif active(b):
            result["reopened"].append({**_summary(b), "old_id": a["id"], "matched_by": kind})
    for j, b in enumerate(new_findings):
        if j not in paired_new and active(b):
            result["new_findings"].append(_summary(b))
    for i, a in enumerate(old_findings):
        if i not in paired_old and active(a):
            result["resolved"].append({**_summary(a), "new_id": "", "matched_by": "",
                                       "reason": "gone"})
    order = {s: n for n, s in enumerate(SEVERITIES)}
    for key in ("new_findings", "reopened", "resolved", "persisting"):
        result[key].sort(key=lambda r: (order[r["severity"]], r["location"]))
    result["counts"] = {"old": _severity_counts(old), "new": _severity_counts(new)}
    result["commitments"] = _commitment_changes(old, new)
    return result


def render_markdown(result, lang, text, code):
    """Markdown for a chat summary, a PR description or the owner report.

    `text` escapes recorded prose and `code` writes a code span
    (render.markdown_text and render.markdown_code).
    """
    t = LABELS[lang]
    c = result
    lines = [f"## {t['title']}", ""]
    for side in ("old", "new"):
        meta = c[side]
        lines.append(f"- **{t[side]}:** {text(meta['project'])} · {t['revision']} "
                     f"{text(meta['commit'] or 'UNKNOWN')} · {t['date']} {text(meta['date'])}")
    lines += ["", t["summary"].format(new=len(c["new_findings"]), reopened=len(c["reopened"]),
                                      resolved=len(c["resolved"]), persisting=len(c["persisting"])),
              "", f"_{t['note']}_", ""]

    def head(f):
        return f"{f['id']} [{f['severity']}] {text(f['title'])} ({code(f['location'])})"

    sections = (("new", c["new_findings"], lambda f: ""),
                ("reopened", c["reopened"],
                 lambda f: f" — {f['old_id']}, {t['matched'][f['matched_by']]}"),
                ("resolved", c["resolved"],
                 lambda f: f" — {t['reasons'][f['reason']]}"
                 + (f" ({f['new_id']}, {t['matched'][f['matched_by']]})" if f["new_id"] else "")),
                ("persisting", c["persisting"],
                 lambda f: f" — {f['old_id']}, {t['matched'][f['matched_by']]}"
                 + "".join(f"; {name} {change['from']} → {change['to']}"
                           for name, change in f["changes"].items())))
    for key, rows, tail in sections:
        lines += [f"### {t['classes'][key]} ({len(rows)})", ""]
        lines += [f"- {head(f)}{tail(f)}" for f in rows] or [t["none"]]
        lines.append("")
    lines += [f"### {t['counts']}", "", f"| | {' | '.join(SEVERITIES)} |",
              "|---|" + "---|" * len(SEVERITIES)]
    for side in ("old", "new"):
        lines.append(f"| {t[side]} | " + " | ".join(str(c["counts"][side][s]) for s in SEVERITIES)
                     + " |")
    lines += ["", f"### {t['commitments']}", ""]
    ledger = c["commitments"]
    rows = ([f"- {r['id']} {text(r['statement'])}: {r['from']} → {r['to']}"
             + (f" ({r['old_id']})" if r["old_id"] != r["id"] else "") for r in ledger["changed"]]
            + [f"- {r['id']} {text(r['statement'])}: {t['added']} ({r['status']})"
               for r in ledger["added"]]
            + [f"- {r['id']} {text(r['statement'])}: {t['removed']} ({r['status']})"
               for r in ledger["removed"]])
    lines += rows or [t["unchanged"]]
    return "\n".join(lines) + "\n"
