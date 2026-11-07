#!/usr/bin/env python3
"""Compare a later ux-scan review with an earlier one (reference/follow-up.md).

    python3 compare.py BASELINE CURRENT --out FILE|- [--format markdown|json] [--lang ja|en]
                       [--fail-on High|Medium|Low|Info] [--carry-forward FRAGMENT]

BASELINE and CURRENT are two findings.json records of the same app, each passing
findings.py check. Ids are renumbered per review and lines move, so findings are matched
by content: the same hunt step, file and title first; then the same hunt step and file,
by title likeness or a nearby line; then a near-identical title anywhere (a moved file).
Each match or leftover is one change:

  new        reported now, not before (or ruled out before)
  resolved   reported before, no longer reported: confirm it with `after` evidence
  fixed      marked Fixed now
  regressed  marked Fixed before, reported again now
  ruled_out  reported before, judged FalsePositive or NotApplicable now
  persisting reported both times; severity, status, verdict, id or line changes are noted

--fail-on SEVERITY exits 1 when a new or regressed Open finding, or a persisting one raised
to it, is at or above SEVERITY: a gate for CI or a release checklist. The output never
replaces a review output. --carry-forward FRAGMENT also writes a findings.py merge fragment for
CURRENT: each persisting finding Accepted in the baseline and Open now goes back to Accepted, and a
decisions line names every regression and carried acceptance; read it, edit what no longer holds,
then merge it. Standard library only.
Exit status: 0 written, 1 the --fail-on gate tripped (still written), 2 invalid input.
"""

import argparse
import json
import re
import sys
from difflib import SequenceMatcher
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import SEVERITIES, RecordError  # noqa: E402
from record_files import SEVERITY_RANK, allow_note, at_least, code, counted, load_record, split_location, write_derived  # noqa: E402

CHANGES = ("new", "regressed", "resolved", "fixed", "ruled_out", "persisting")
# A pair on the same hunt step and file needs a title this alike, or a start line this near.
SAME_FILE_LIKENESS = 0.6
NEAR_LINES = 3
# A pair anywhere else (the file moved, or the finding was filed under another step) needs this.
MOVED_LIKENESS = 0.85
LABELS = {
    "en": {"title": "UX review comparison", "baseline": "Baseline", "current": "Current", "review": "Review",
           "date": "Date", "commit": "Commit", "open": "Open findings", "severity": "Severity",
           "change": "Change", "count": "Count", "none": "No changes between the two reviews.",
           "gate": "Gate", "tripped": "tripped: {n} finding(s) at or above {s}", "passed": "passed (at or above {s})",
           "new": "New", "regressed": "Regressed", "resolved": "Resolved (confirm with after evidence)",
           "fixed": "Fixed", "ruled_out": "Ruled out", "persisting": "Persisting",
           "unchanged": "{n} persisting finding(s) unchanged apart from their ids or lines are counted, not listed."},
    "ja": {"title": "UX診断の比較", "baseline": "前回", "current": "今回", "review": "診断", "date": "日付",
           "commit": "コミット", "open": "未対応の指摘", "severity": "重大度", "change": "変化", "count": "件数",
           "none": "2回の診断の間に変化はありません。", "gate": "ゲート",
           "tripped": "不合格: {s} 以上が {n} 件", "passed": "合格（{s} 以上なし）",
           "new": "新規", "regressed": "再発", "resolved": "解消（after の証跡で確認）", "fixed": "修正済み",
           "ruled_out": "除外", "persisting": "継続",
           "unchanged": "id や行の移動以外に変化のない継続中の指摘 {n} 件は件数のみ示します。"},
}


def normalized_title(finding):
    return " ".join(re.sub(r"\W+", " ", finding["title"].casefold()).split())


def likeness(a, b):
    return SequenceMatcher(None, normalized_title(a), normalized_title(b)).ratio()


def match(baseline, current):
    """[(baseline finding or None, current finding or None)]: every finding of both, each in one pair."""
    left = {f["id"]: f for f in baseline}
    right = {f["id"]: f for f in current}
    pairs = []

    def take(candidates):
        # Best pairs first, so one close match is not stolen by a looser one.
        for _, b, c in sorted(candidates, key=lambda item: (item[0], item[1]["id"], item[2]["id"])):
            if b["id"] in left and c["id"] in right:
                del left[b["id"]], right[c["id"]]
                pairs.append((b, c))

    def place(f):
        path, start, _ = split_location(f["location"])
        return (f["perspective"], path), start

    def same_place():
        groups = {}
        for c in right.values():
            groups.setdefault(place(c)[0], []).append(c)
        return [(b, c) for b in left.values() for c in groups.get(place(b)[0], [])]

    take([((0, abs(place(b)[1] - place(c)[1])), b, c) for b, c in same_place()
          if normalized_title(b) == normalized_title(c)])
    candidates = []
    for b, c in same_place():
        ratio, distance = likeness(b, c), abs(place(b)[1] - place(c)[1])
        if ratio >= SAME_FILE_LIKENESS or distance <= NEAR_LINES:
            candidates.append(((1, -ratio, distance), b, c))
    take(candidates)
    take([((2, -ratio), b, c) for b in left.values() for c in right.values()
          if (ratio := likeness(b, c)) >= MOVED_LIKENESS])
    pairs += [(b, None) for b in left.values()] + [(None, c) for c in right.values()]
    return pairs


def summary(f):
    return {"id": f["id"], "title": f["title"], "severity": f["severity"], "status": f["status"],
            "verdict": f["validation"]["verdict"], "location": f["location"], "perspective": f["perspective"]}


def classify(b, c):
    """(change, notes) for a pair, or None when nothing a reader needs to see changed."""
    if c is None:
        return ("resolved", []) if counted(b) and b["status"] != "Fixed" else None
    if b is None:
        if not counted(c):
            return None
        return ("fixed", ["not in the baseline"]) if c["status"] == "Fixed" else ("new", [])
    if not counted(b):
        return ("new", [f"ruled out ({b['validation']['verdict']}) in the baseline"]) \
            if counted(c) and c["status"] != "Fixed" else None
    if not counted(c):
        return ("ruled_out", [f"verdict {b['validation']['verdict']} -> {c['validation']['verdict']}"])
    if b["status"] == "Fixed":
        return ("regressed", []) if c["status"] != "Fixed" else None
    if c["status"] == "Fixed":
        return "fixed", []
    notes = []
    if b["severity"] != c["severity"]:
        direction = "raised" if SEVERITY_RANK[c["severity"]] < SEVERITY_RANK[b["severity"]] else "lowered"
        notes.append(f"severity {direction}: {b['severity']} -> {c['severity']}")
    if b["status"] != c["status"]:
        notes.append(f"status {b['status']} -> {c['status']}")
        if b["status"] == "Accepted":
            notes.append("accepted in the baseline: carry the acceptance forward or record why not")
    if b["validation"]["verdict"] != c["validation"]["verdict"]:
        notes.append(f"verdict {b['validation']['verdict']} -> {c['validation']['verdict']}")
    if b["perspective"] != c["perspective"]:
        notes.append(f"perspective {b['perspective']} -> {c['perspective']}")
    if split_location(b["location"])[0] != split_location(c["location"])[0]:
        notes.append(f"moved {b['location']} -> {c['location']}")
    return "persisting", notes


def compare(base, cur, fail_on=None):
    items, unchanged = [], 0
    for b, c in match(base["findings"], cur["findings"]):
        result = classify(b, c)
        if result is None:
            continue
        change, notes = result
        if change == "persisting" and not notes:
            unchanged += 1
        items.append({"change": change, "baseline": summary(b) if b else None,
                      "current": summary(c) if c else None, "notes": notes})
    order = {name: i for i, name in enumerate(CHANGES)}

    def rank(item):
        f = item["current"] or item["baseline"]
        return order[item["change"]], SEVERITY_RANK[f["severity"]], f["id"]
    items.sort(key=rank)

    def open_counts(data):
        counts = dict.fromkeys(SEVERITIES, 0)
        for f in data["findings"]:
            if counted(f) and f["status"] == "Open":
                counts[f["severity"]] += 1
        return counts

    def review(data):
        return {k: data["meta"][k] for k in ("project", "date", "commit") if data["meta"].get(k)}

    result = {"format": "ux-scan-compare/1", "baseline": review(base), "current": review(cur),
              "open": {"baseline": open_counts(base), "current": open_counts(cur)},
              "counts": {name: sum(item["change"] == name for item in items) for name in CHANGES},
              "unchanged": unchanged, "changes": items}
    if fail_on:
        blocking = [item["current"]["id"] for item in items if item["current"]
                    and item["current"]["status"] == "Open" and at_least(item["current"], fail_on)
                    and (item["change"] in ("new", "regressed")
                         or any(note.startswith("severity raised") for note in item["notes"]))]
        result["gate"] = {"fail_on": fail_on, "blocking": blocking}
    return result


def carry_forward(result, base):
    """A findings.py merge fragment recording the comparison's outcome in the current review."""
    when = " ".join(x for x in (base["meta"].get("date"), base["meta"].get("commit")) if x)
    findings, decisions = [], []
    for item in result["changes"]:
        b, c = item["baseline"], item["current"]
        if item["change"] == "regressed":
            decisions.append(f"{c['id']} regressed: Fixed in the {when} review (as {b['id']}), reported again; "
                             "find what undid the fix.")
        elif item["change"] == "persisting" and b["status"] == "Accepted" and c["status"] == "Open":
            findings.append({"id": c["id"], "status": "Accepted"})
            decisions.append(f"{c['id']} carried forward as Accepted from the {when} review (as {b['id']}); "
                             "confirm the reason still holds.")
    fragment = {}
    if findings:
        fragment["findings"] = findings
    if decisions:
        fragment["decisions"] = decisions
    return fragment


def markdown(result, lang):
    L = LABELS[lang]
    b, c = result["baseline"], result["current"]
    lines = [f"# {c.get('project') or b.get('project')}: {L['title']}", "",
             f"| {L['review']} | {L['date']} | {L['commit']} |", "|---|---|---|",
             f"| {L['baseline']} | {b.get('date', '')} | {b.get('commit', '')} |",
             f"| {L['current']} | {c.get('date', '')} | {c.get('commit', '')} |", "",
             f"| {L['open']} | {L['baseline']} | {L['current']} | Δ |", "|---|---:|---:|---:|"]
    for severity in SEVERITIES:
        before, after = result["open"]["baseline"][severity], result["open"]["current"][severity]
        lines.append(f"| {severity} | {before} | {after} | {after - before:+d} |")
    lines += ["", f"| {L['change']} | {L['count']} |", "|---|---:|"]
    lines += [f"| {L[name]} | {result['counts'][name]} |" for name in CHANGES]
    if "gate" in result:
        gate = result["gate"]
        verdict = (L["tripped"].format(n=len(gate["blocking"]), s=gate["fail_on"]) + ": " + ", ".join(gate["blocking"])
                   if gate["blocking"] else L["passed"].format(s=gate["fail_on"]))
        lines += ["", f"**{L['gate']}:** {verdict}"]
    listed = [item for item in result["changes"] if item["change"] != "persisting" or item["notes"]]
    if not listed:
        lines += ["", L["none"] if not result["unchanged"] else L["unchanged"].format(n=result["unchanged"])]
        return "\n".join(lines) + "\n"
    for name in CHANGES:
        group = [item for item in listed if item["change"] == name]
        if not group:
            continue
        lines += ["", f"## {L[name]} ({len(group)})", ""]
        for item in group:
            f, before = item["current"] or item["baseline"], item["baseline"]
            ids = f"{before['id']} → {item['current']['id']}" if before and item["current"] \
                and before["id"] != item["current"]["id"] else f["id"]
            title = " ".join(f["title"].split()).replace("&", "&amp;").replace("<", "&lt;")
            text = f"- **{ids}** {f['severity']}: {title} ({code(f['location'])})"
            if item["notes"]:
                text += "; " + "; ".join(item["notes"])
            lines.append(text)
    if result["unchanged"]:
        lines += ["", L["unchanged"].format(n=result["unchanged"])]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("baseline")
    parser.add_argument("current")
    parser.add_argument("--out", required=True, help="output file, or - for stdout")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--lang", choices=("ja", "en"), default="en", help="markdown labels")
    parser.add_argument("--fail-on", choices=SEVERITIES)
    parser.add_argument("--carry-forward", metavar="FRAGMENT",
                        help="also write a findings.py merge fragment carrying acceptances and regressions forward")
    args = parser.parse_args(argv)
    carried = None
    try:
        base, _ = load_record(args.baseline)
        cur, _ = load_record(args.current)
        result = compare(base, cur, args.fail_on)
        text = (json.dumps(result, ensure_ascii=False, indent=2) + "\n" if args.format == "json"
                else markdown(result, args.lang))
        if args.carry_forward:
            if args.carry_forward == "-" or (args.out != "-" and Path(args.carry_forward).resolve()
                                             == Path(args.out).resolve()):
                raise RecordError("--carry-forward: name a file other than --out")
            carried = carry_forward(result, base)
        target = write_derived(args.out, text, [args.baseline, args.current])
        if carried is not None:
            fragment = write_derived(args.carry_forward, json.dumps(carried, ensure_ascii=False, indent=2) + "\n",
                                     [args.baseline, args.current])
    except (RecordError, OSError, ValueError, RecursionError) as e:
        print(f"compare.py: {e}", file=sys.stderr)
        return 2
    counts = ", ".join(f"{n} {name}" for name, n in result["counts"].items() if n) or "no changes"
    tripped = bool(result.get("gate", {}).get("blocking"))
    if target is not None:
        print(f"wrote {target} ({counts}){allow_note(target, [args.baseline, args.current])}")
    if carried is not None:
        carried_n = len(carried.get("findings", []))
        print(f"wrote {fragment} ({carried_n} acceptance(s) carried, {len(carried.get('decisions', []))} decision line(s)); "
              f"review it, then findings.py merge {args.current} {fragment}"
              if carried else f"wrote {fragment} (nothing to carry forward)")
    if tripped:
        print(f"compare.py: gate tripped at {args.fail_on}: {', '.join(result['gate']['blocking'])}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    from file_io import tolerant_console
    tolerant_console()
    sys.exit(main())
