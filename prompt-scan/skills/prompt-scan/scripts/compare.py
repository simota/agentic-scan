#!/usr/bin/env python3
"""Compare an earlier review's findings.json with a new one: what is new, what persists, what was resolved.

    python3 compare.py BASELINE CURRENT [--json] [--out FILE] [--lang ja|en] [--fail-on SEVERITY]

Both files are read and validated with record.py; neither is changed. IDs cannot be compared directly
(F-* ids are renumbered in severity order, L-* ids are reassigned on every rescan), so findings are
matched by what they are about:

- an L-* finding matches an L-* with the same lint rule, file and title
- an F-* finding matches an F-* in the same file under the same perspective; among several candidates
  the closest title wins, then the closest line. A candidate whose title shares little with the finding
  (a reworded title, a review in the other language) is accepted only at the same location, or when it is
  the one finding of that perspective in that file on both sides

A finding is *active* unless its verdict is FalsePositive or NotApplicable. Each pair or leftover is one of:

| Class | Baseline | Current |
|---|---|---|
| new | absent | active |
| reopened | excluded | active |
| persisting | active | active (severity, kind, verdict or status changes are listed) |
| resolved | active | absent |
| dismissed | active | excluded |

A resolved finding was not reported again; only a recorded eval run or test shows that the behaviour
changed. A moved or renamed file reads as one finding resolved and one new.

--accepted-fragment FILE writes a findings.py merge fragment that sets `status: Accepted` on each
persisting F-* finding the baseline had accepted and the current review left `Open`, so an accepted risk
is not re-triaged on every review. Merge it into CURRENT with findings.py merge after renumbering. L-*
findings carry no status (a fragment gives them only a validation), so none is carried onto them.

--fail-on SEVERITY exits 1 when a new or reopened finding is at SEVERITY or above, so CI can refuse a
regression without failing on findings already known.

Exit codes: 0 compared, 1 --fail-on threshold reached, 2 unreadable input or schema error.
"""
import argparse
import difflib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import record  # noqa: E402
from record import EXCLUDED, LOC_RE, SEVERITIES, SchemaError  # noqa: E402
from excerpt import mask  # noqa: E402
from scan_report_kit.output import unsafe_target, write_output  # noqa: E402

CLASSES = ("new", "reopened", "persisting", "resolved", "dismissed")
TRACKED = ("severity", "kind", "confidence", "verdict", "status")
# Below this title similarity, an F-* pair needs to be the only candidate on both sides.
TITLE_MATCH = 0.5

LABELS = {
    "en": {
        "title": "Review comparison", "baseline": "Baseline", "current": "Current",
        "summary": "{new} new, {reopened} reopened, {persisting} persisting, {resolved} resolved, "
                   "{dismissed} dismissed.",
        "new": "New", "reopened": "Reopened", "persisting": "Persisting", "resolved": "Resolved",
        "dismissed": "Dismissed", "none": "None.", "changed": "changed",
        "resolved_note": "Resolved means not reported by the current review; only an eval run or a test shows "
                         "that the behaviour changed.",
    },
    "ja": {
        "title": "診断結果の比較", "baseline": "前回", "current": "今回",
        "summary": "新規 {new} 件、再発 {reopened} 件、継続 {persisting} 件、解消 {resolved} 件、除外 {dismissed} 件。",
        "new": "新規", "reopened": "再発", "persisting": "継続", "resolved": "解消",
        "dismissed": "除外", "none": "なし。", "changed": "変更",
        "resolved_note": "解消は今回の診断で再び報告されなかったことを示すだけで、挙動の改善は評価の実行かテストでのみ示せる。",
    },
}


def path_line(location):
    m = LOC_RE.match(location)
    return (m["path"], int(m["start"])) if m else (location, 0)


def bucket(f):
    """What a finding must share with its counterpart: its origin, file and perspective (L-*: its rule)."""
    path, _ = path_line(f["location"])
    if f["id"].startswith("L-"):
        return "L", path, f.get("rule") or f["category"]
    return "F", path, f["category"]


def norm(text):
    return re.sub(r"\s+", " ", text).strip().lower()


def similarity(a, b):
    return difflib.SequenceMatcher(None, norm(a["title"]), norm(b["title"])).ratio()


def pair(baseline, current):
    """Matched (baseline, current) pairs, then unmatched baseline and current findings, each in input order."""
    groups = {}
    for side, findings in ((0, baseline), (1, current)):
        for f in findings:
            groups.setdefault(bucket(f), ([], []))[side].append(f)
    pairs, used = [], set()
    for key, (old, new) in groups.items():
        if not old or not new:
            continue
        lone = len(old) == 1 and len(new) == 1
        candidates = []
        for i, a in enumerate(old):
            for j, b in enumerate(new):
                title = similarity(a, b)
                if key[0] == "L":
                    if norm(a["title"]) != norm(b["title"]):
                        continue
                elif title < TITLE_MATCH and not lone and a["location"] != b["location"]:
                    continue
                distance = abs(path_line(a["location"])[1] - path_line(b["location"])[1])
                candidates.append((-title, distance, i, j))
        taken_old, taken_new = set(), set()
        for _, _, i, j in sorted(candidates):
            if i in taken_old or j in taken_new:
                continue
            taken_old.add(i)
            taken_new.add(j)
            pairs.append((old[i], new[j]))
            used.update((id(old[i]), id(new[j])))
    return (pairs, [f for f in baseline if id(f) not in used], [f for f in current if id(f) not in used])


def active(f):
    return f["validation"]["verdict"] not in EXCLUDED


def tracked(f):
    return {"severity": f["severity"], "kind": f["kind"], "confidence": f["confidence"],
            "verdict": f["validation"]["verdict"], "status": f.get("status", "Open")}


def entry(f, other=None, baseline_side=False):
    """One line of the comparison: the finding as recorded on its newest side, and what changed."""
    item = {"id": None if baseline_side else f["id"], "baseline_id": f["id"] if baseline_side else None,
            "title": f["title"], "location": f["location"], "category": f["category"], **tracked(f)}
    if other is not None:
        item["baseline_id"] = other["id"]
        before, after = tracked(other), tracked(f)
        item["changes"] = {k: [before[k], after[k]] for k in TRACKED if before[k] != after[k]}
    return item


def compare(baseline, current):
    """The comparison of two validated records, as a JSON-ready object."""
    pairs, gone, added = pair(baseline.get("findings", []), current.get("findings", []))
    result = {c: [] for c in CLASSES}
    for old, new in pairs:
        if active(old) and active(new):
            result["persisting"].append(entry(new, old))
        elif active(new):
            result["reopened"].append(entry(new, old))
        elif active(old):
            result["dismissed"].append(entry(new, old))
    result["resolved"] = [entry(f, baseline_side=True) for f in gone if active(f)]
    result["new"] = [entry(f) for f in added if active(f)]
    for c in CLASSES:
        result[c].sort(key=lambda e: (SEVERITIES.index(e["severity"]), *path_line(e["location"])))

    def side(data):
        meta = data.get("meta", {})
        return {k: meta.get(k) for k in ("target", "date", "assessor", "commit", "dirty")}
    return {"tool": "compare.py", "baseline": side(baseline), "current": side(current),
            "summary": {c: len(result[c]) for c in CLASSES}, **result}


def regressions(result, threshold):
    """New and reopened findings at threshold severity or above."""
    limit = SEVERITIES.index(threshold)
    return [e for c in ("new", "reopened") for e in result[c] if SEVERITIES.index(e["severity"]) <= limit]


def accepted(result):
    """Updates carrying the baseline's Accepted status onto persisting F-* findings still Open."""
    return [{"id": e["id"], "status": "Accepted"} for e in result["persisting"]
            if e["id"].startswith("F-") and (e.get("changes") or {}).get("status") == ["Accepted", "Open"]]


def markdown(result, L):
    def side(meta):
        commit = (meta.get("commit") or "")[:12]
        return " · ".join(x for x in (meta.get("target"), meta.get("date"), commit) if x) or "—"

    def line(e):
        ident = e["id"] or e["baseline_id"]
        if e["id"] and e["baseline_id"] and e["baseline_id"] != e["id"]:
            ident = f'{e["id"]} (← {e["baseline_id"]})'
        text = f'- [{e["severity"]}][{e["kind"]}] {ident} {e["title"]} — `{e["location"]}`'
        changes = e.get("changes") or {}
        if changes:
            text += f' — {L["changed"]}: ' + ", ".join(f"{k} {a} → {b}" for k, (a, b) in changes.items())
        return mask(text)
    lines = [f'# {L["title"]}', "", f'- {L["baseline"]}: {side(result["baseline"])}',
             f'- {L["current"]}: {side(result["current"])}', "", L["summary"].format(**result["summary"]), ""]
    for c in CLASSES:
        lines += [f'## {L[c]} ({len(result[c])})', ""]
        lines += [line(e) for e in result[c]] or [L["none"]]
        if c == "resolved" and result[c]:
            lines += ["", L["resolved_note"]]
        lines.append("")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("baseline", type=Path, help="the earlier review's findings.json")
    p.add_argument("current", type=Path, help="the new review's findings.json")
    p.add_argument("--json", action="store_true", help="write the comparison as JSON instead of Markdown")
    p.add_argument("--out", type=Path, help="write here instead of stdout")
    p.add_argument("--lang", choices=sorted(LABELS), help="Markdown language (default: the current meta.lang, else ja)")
    p.add_argument("--accepted-fragment", type=Path, metavar="FILE",
                   help="write a merge fragment carrying the baseline's Accepted status onto persisting findings")
    p.add_argument("--fail-on", choices=SEVERITIES, metavar="SEVERITY",
                   help="exit 1 when a new or reopened finding is at this severity or above")
    a = p.parse_args(argv)
    try:
        baseline = record.load(a.baseline, record.read_regular(a.baseline))
        current = record.load(a.current, record.read_regular(a.current))
    except (SchemaError, OSError) as e:
        print(f"compare.py: {e}", file=sys.stderr)
        return 2
    result = compare(baseline, current)
    lang = a.lang or current.get("meta", {}).get("lang") or "ja"
    text = json.dumps(result, ensure_ascii=False, indent=2) + "\n" if a.json else markdown(result, LABELS[lang])
    if a.out:
        try:
            if a.out.resolve() in (a.baseline.resolve(), a.current.resolve()):
                raise OSError("it is one of the compared files")
            unsafe = unsafe_target(a.out.parent, [a.out.name])
            if unsafe:
                raise OSError(f"{unsafe} exists as a symlink or non-regular file")
            write_output(a.out, text)
        except OSError as e:
            print(f"compare.py: cannot write {a.out}: {e}", file=sys.stderr)
            return 2
        print(f"wrote {a.out}: " + ", ".join(f"{n} {c}" for c, n in result["summary"].items()))
    else:
        sys.stdout.write(text)
    if a.accepted_fragment:
        updates = accepted(result)
        try:
            unsafe = unsafe_target(a.accepted_fragment.parent, [a.accepted_fragment.name])
            if unsafe or a.accepted_fragment.resolve() in (a.baseline.resolve(), a.current.resolve()):
                raise OSError("it is a compared file, a symlink or a non-regular file")
            write_output(a.accepted_fragment, json.dumps({"findings": updates}, indent=2) + "\n")
        except OSError as e:
            print(f"compare.py: cannot write {a.accepted_fragment}: {e}", file=sys.stderr)
            return 2
        print(f"wrote {a.accepted_fragment}: Accepted carried onto {len(updates)} finding(s)", file=sys.stderr)
    if a.fail_on:
        found = regressions(result, a.fail_on)
        if found:
            print(f"compare.py: {len(found)} new or reopened finding(s) at {a.fail_on} or above: "
                  + ", ".join(e["id"] for e in found), file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
