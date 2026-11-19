#!/usr/bin/env python3
"""Compare an earlier assessment with a later one of the same codebase.

    python3 compare.py OLD_FINDINGS NEW_FINDINGS [--lang ja|en] [--format md|json] [--out FILE]
                       [--carry FRAGMENT] [--fail-on High|Medium|Low|Info]

IDs are renumbered on every run, so findings are paired by what they are, not
by ID: the same title, or a shared file with the same perspective or the same
cited ledger idiom (convention IDs are renumbered too). Each pair is matched once,
best first. The comparison then says, of the later record:

- new: reported now, with no counterpart in the earlier record
- resolved: reported earlier, not found again (which is not proof of a fix:
  compare the scopes and limitations it prints)
- persisting: in both, with each change of severity, confidence, verdict,
  status, perspective or location; a finding the earlier record marked `Fixed`
  that is found again is flagged as reappeared
- now excluded / now reported: moved out of or into the excluded verdicts
  (`FalsePositive`, `NotApplicable`)

plus the counts per severity (excluded verdicts apart, as report.md counts
them), every data rule ledger entry whose status changed, appeared or went
(matched by idiom), and every perspective whose coverage changed.

The comparison reads both records and writes nothing beside them; with `--out`
it writes FILE (outside the run's output directory, or add it with `check
--allow`). Neither record is changed.

`--carry FRAGMENT` writes the triage people already did on the earlier record
as a fragment for the later one, so an independent re-run does not lose it:
for each persisting finding still `Open` now, an earlier `Accepted` status
(unless the severity rose since, which reopens the decision), together with
each earlier `decisions` item that names it, its finding IDs rewritten to the
later ones, since `check` wants every `Accepted` finding named in `decisions`
with who decided and why. An item that also names an earlier finding with no
counterpart now is not carried; the summary says so, and that decision is
written again by hand. A finding marked `Fixed` that is found again is not
carried: it is flagged as reappeared instead. Verdicts, severities and every
other judgment are never carried. Merge it with `findings.py merge`
before the later record is renumbered again, then render.

`--fail-on SEVERITY` makes the comparison a regression gate: exit 3 when the
later record has, at or above SEVERITY, a new finding, a finding that
reappeared after `Fixed`, a finding reported again after being excluded, or a
persisting finding whose severity rose to it. Each reason goes to stderr.

Exit codes: 0 compared, 1 a record cannot be read, does not match the schema
or FILE could not be written, 2 the command line is wrong, 3 `--fail-on` found
a regression (the outputs are still written).
"""
import argparse
import json
from pathlib import Path
import re
import sys
import unicodedata

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True  # leave no __pycache__ beside the skill
from findings import (EXCLUDED, PERSPECTIVES, SEVERITIES, SchemaError,  # noqa: E402
                      _atomic_write_all, _rewrite_ids, as_locations, cited_conventions,
                      read_json, safe_output, split_location, validate)
from markdown_safe import as_text, markdown_code, markdown_inline  # noqa: E402
from render import perspective_name, perspective_status, revision  # noqa: E402

# How close two locations in the same file must be to count as the same place.
NEAR_LINES = 30
WORDS = {
    "en": {
        "title": "Assessment comparison", "earlier": "Earlier", "later": "Later",
        "project": "System", "scope": "Scope", "revision": "Revision", "date": "Date / assessor",
        "counts": "Counts (excluded verdicts apart)", "severity": "Severity",
        "change": "Change", "open_hm": "Open High / Medium",
        "summary": "{new} new, {resolved} resolved, {persisting} persisting "
                   "({changed} changed, {reappeared} reappeared after Fixed), "
                   "{now_excluded} now excluded, {now_reported} now reported.",
        "new": "New findings", "resolved": "Resolved: not found again",
        "resolved_note": "Not finding a problem again is not proof that it was fixed: "
                         "compare the scopes above and the later record's limitations.",
        "scope_differs": "The scopes differ, so a finding outside the later scope may be "
                         "listed as resolved.",
        "persisting": "Persisting findings", "reappeared": "reappeared: the earlier record "
        "marks it Fixed", "unchanged": "unchanged",
        "now_excluded": "Now excluded", "now_reported": "Now reported (earlier excluded)",
        "rules": "Data rule ledger", "rule_added": "new entry", "rule_dropped": "no longer in the ledger",
        "perspectives": "Perspective coverage", "none": "None.",
        "severity_f": "severity", "confidence": "confidence", "verdict": "verdict",
        "status": "status", "category": "perspective", "location": "location",
    },
    "ja": {
        "title": "診断の比較", "earlier": "前回", "later": "今回",
        "project": "システム", "scope": "範囲", "revision": "リビジョン", "date": "診断日 / 診断者",
        "counts": "件数（除外した判定を除く）", "severity": "重大度",
        "change": "増減", "open_hm": "未対応の High / Medium",
        "summary": "新規 {new} 件、解消 {resolved} 件、継続 {persisting} 件"
                   "（うち変化あり {changed} 件、Fixed 後の再発 {reappeared} 件）、"
                   "新たに除外 {now_excluded} 件、新たに報告 {now_reported} 件。",
        "new": "新規の検出事項", "resolved": "解消: 今回は検出されなかった",
        "resolved_note": "再び検出されなかったことは修正の証明ではない。"
                         "上の範囲と、今回の記録の「確認できなかったこと」を照らし合わせること。",
        "scope_differs": "範囲が異なるため、今回の範囲外の検出事項も解消として並ぶことがある。",
        "persisting": "継続している検出事項", "reappeared": "再発: 前回の記録では Fixed",
        "unchanged": "変化なし",
        "now_excluded": "新たに除外", "now_reported": "新たに報告（前回は除外）",
        "rules": "データルール台帳", "rule_added": "新しい項目", "rule_dropped": "台帳から消えた項目",
        "perspectives": "観点のカバレッジ", "none": "なし。",
        "severity_f": "重大度", "confidence": "確度", "verdict": "検証判定",
        "status": "ステータス", "category": "観点", "location": "場所",
    },
}


def norm(text):
    """Text compared loosely: case, width and blanks do not matter."""
    return " ".join(unicodedata.normalize("NFKC", as_text(text)).casefold().split())


def places(f):
    """Each location as (path, start, end); a path compared by its spelling."""
    out = []
    for loc in as_locations(f["location"]):
        parts = split_location(loc)
        if parts:
            path, start, end = parts
            path = path.replace("\\", "/")
            while path.startswith("./"):
                path = path[2:]
            out.append((path, start, end))
    return out


def features(doc):
    """What pairing compares, per finding, computed once: title, places, files, ledger idioms."""
    ledger = {c["id"]: norm(c["idiom"]) for c in doc.get("conventions", [])}
    out = []
    for f in doc.get("findings", []):
        spots = places(f)
        out.append({"title": norm(f["title"]), "places": spots, "files": {p for p, _, _ in spots},
                    "category": f["category"], "step": f.get("step"),
                    "rules": {ledger[cid] for cid in cited_conventions(f) if cid in ledger}})
    return out


def score(old, new):
    """How alike two findings' features are, or 0 when they are not the same root cause."""
    same_title = old["title"] == new["title"]
    shared = bool(old["files"] & new["files"])
    same_category = old["category"] == new["category"]
    shared_rule = bool(old["rules"] & new["rules"])
    if not same_title and not (shared and (same_category or shared_rule)):
        return 0
    points = 100 * same_title + 40 * shared + 20 * same_category + 15 * shared_rule
    points += 15 * (old["step"] is not None and old["step"] == new["step"])
    if any(p == q and s <= qe + NEAR_LINES and qs <= e + NEAR_LINES
           for p, s, e in old["places"] for q, qs, qe in new["places"]):
        points += 10
    return points


def pair_findings(old_doc, new_doc):
    """One-to-one pairs (old, new), best match first; then the unpaired of each side."""
    olds, news = old_doc.get("findings", []), new_doc.get("findings", [])
    old_features, new_features = features(old_doc), features(new_doc)
    # Only a finding with the same title or a shared file can pair, so only those are scored.
    by_title, by_file = {}, {}
    for j, feature in enumerate(new_features):
        by_title.setdefault(feature["title"], []).append(j)
        for path in feature["files"]:
            by_file.setdefault(path, []).append(j)
    candidates = []
    for i, feature in enumerate(old_features):
        near = set(by_title.get(feature["title"], ()))
        for path in feature["files"]:
            near.update(by_file.get(path, ()))
        for j in near:
            points = score(feature, new_features[j])
            if points:
                candidates.append((-points, i, j))
    candidates.sort()
    used_old, used_new, paired = set(), set(), []
    for _, i, j in candidates:
        if i in used_old or j in used_new:
            continue
        used_old.add(i)
        used_new.add(j)
        paired.append((j, i))
    pairs = [(olds[i], news[j]) for j, i in sorted(paired)]
    return (pairs, [o for i, o in enumerate(olds) if i not in used_old],
            [n for j, n in enumerate(news) if j not in used_new])


def excluded(f):
    return f["validation"]["verdict"] in EXCLUDED


def changes(old, new):
    """Each field that differs between the two, as (field, before, after)."""
    out = []
    for key, get in (("severity_f", lambda f: f["severity"]),
                     ("confidence", lambda f: f["confidence"]),
                     ("verdict", lambda f: f["validation"]["verdict"]),
                     ("status", lambda f: f.get("status", "Open")),
                     ("category", lambda f: f["category"])):
        if get(old) != get(new):
            out.append((key, get(old), get(new)))
    if {p for p, _, _ in places(old)} != {p for p, _, _ in places(new)}:
        out.append(("location", ", ".join(as_locations(old["location"])),
                    ", ".join(as_locations(new["location"]))))
    return out


def tally(doc):
    active = [f for f in doc.get("findings", []) if not excluded(f)]
    counts = {s: sum(f["severity"] == s for f in active) for s in SEVERITIES}
    counts["open_hm"] = sum(f["severity"] in SEVERITIES[:2] and f.get("status", "Open") == "Open"
                            for f in active)
    return counts


def rule_changes(old_doc, new_doc):
    """(old entry or None, new entry or None) for each ledger entry that changed."""
    old = {norm(c["idiom"]): c for c in old_doc.get("conventions", [])}
    new = {norm(c["idiom"]): c for c in new_doc.get("conventions", [])}
    out = []
    for key, r in new.items():
        if key not in old:
            out.append((None, r))
        elif old[key]["status"] != r["status"]:
            out.append((old[key], r))
    out += [(r, None) for key, r in old.items() if key not in new]
    return out


def perspective_changes(old_doc, new_doc):
    status = [{p["name"]: p["status"] for p in d.get("perspectives", [])}
              for d in (old_doc, new_doc)]
    return [(name, status[0].get(name, "—"), status[1].get(name, "—")) for name in PERSPECTIVES
            if status[0].get(name, "—") != status[1].get(name, "—")]


def compare(old_doc, new_doc):
    """The comparison as plain data; both outputs are written from it."""
    pairs, unpaired_old, unpaired_new = pair_findings(old_doc, new_doc)
    result = {"new": [], "resolved": [], "persisting": [], "now_excluded": [],
              "now_reported": [], "ids": {o["id"]: n["id"] for o, n in pairs}}
    for o, n in pairs:
        if excluded(o) and excluded(n):
            continue
        if excluded(n):
            result["now_excluded"].append((o, n))
        elif excluded(o):
            result["now_reported"].append((o, n))
        else:
            result["persisting"].append((o, n, changes(o, n), o.get("status") == "Fixed"))
    result["new"] = [n for n in unpaired_new if not excluded(n)]
    result["resolved"] = [o for o in unpaired_old if not excluded(o)]
    result["counts"] = (tally(old_doc), tally(new_doc))
    result["rules"] = rule_changes(old_doc, new_doc)
    result["perspectives"] = perspective_changes(old_doc, new_doc)
    return result


def summary_counts(result):
    return {"new": len(result["new"]), "resolved": len(result["resolved"]),
            "persisting": len(result["persisting"]),
            "changed": sum(bool(p[2]) for p in result["persisting"]),
            "reappeared": sum(p[3] for p in result["persisting"]),
            "now_excluded": len(result["now_excluded"]),
            "now_reported": len(result["now_reported"])}


def brief(f):
    return {"id": f["id"], "title": f["title"], "severity": f["severity"],
            "verdict": f["validation"]["verdict"], "status": f.get("status", "Open"),
            "location": as_locations(f["location"])}


def as_json(result, old_doc, new_doc):
    return {
        "earlier": {k: old_doc["meta"].get(k) for k in ("project", "scope", "commit", "date")},
        "later": {k: new_doc["meta"].get(k) for k in ("project", "scope", "commit", "date")},
        "summary": summary_counts(result),
        "counts": {"earlier": result["counts"][0], "later": result["counts"][1]},
        "new": [brief(n) for n in result["new"]],
        "resolved": [brief(o) for o in result["resolved"]],
        "persisting": [{"earlier": brief(o), "later": brief(n), "reappeared": reappeared,
                        "changes": [{"field": "severity" if k == "severity_f" else k,
                                     "earlier": a, "later": b} for k, a, b in diff]}
                       for o, n, diff, reappeared in result["persisting"]],
        "now_excluded": [{"earlier": brief(o), "later": brief(n)}
                         for o, n in result["now_excluded"]],
        "now_reported": [{"earlier": brief(o), "later": brief(n)}
                         for o, n in result["now_reported"]],
        "conventions": [{"idiom": (n or o)["idiom"],
                   "earlier": o and {"id": o["id"], "status": o["status"]},
                   "later": n and {"id": n["id"], "status": n["status"]}}
                  for o, n in result["rules"]],
        "perspectives": [{"name": name, "earlier": a, "later": b}
                         for name, a, b in result["perspectives"]],
    }


def line_of(f):
    locs = ", ".join(markdown_code(loc) for loc in as_locations(f["location"]))
    return (f"**{f['id']}** [{f['severity']}][{f['validation']['verdict']}] "
            f"{markdown_inline(f['title'])} — {locs}")


def as_markdown(result, old_doc, new_doc, lang):
    w, text = WORDS[lang], markdown_inline
    old_meta, new_meta = old_doc["meta"], new_doc["meta"]
    lines = [f"# {w['title']}: {text(new_meta['project'])}", "",
             w["summary"].format(**summary_counts(result)), "",
             f"| | {w['earlier']} | {w['later']} |", "|---|---|---|"]
    for key, get in (("project", lambda m: m["project"]), ("scope", lambda m: m["scope"]),
                     ("revision", revision),
                     ("date", lambda m: f"{m['date']} / {m['assessor']}")):
        lines.append(f"| {w[key]} | {text(get(old_meta))} | {text(get(new_meta))} |")
    lines += ["", f"## {w['counts']}", "",
              f"| {w['severity']} | {w['earlier']} | {w['later']} | {w['change']} |",
              "|---|---|---|---|"]
    before, after = result["counts"]
    for key in (*SEVERITIES, "open_hm"):
        label = w["open_hm"] if key == "open_hm" else key
        lines.append(f"| {label} | {before[key]} | {after[key]} | {after[key] - before[key]:+d} |")
    lines += ["", f"## {w['new']}", ""]
    lines += [f"- {line_of(n)}" for n in result["new"]] or [w["none"]]
    lines += ["", f"## {w['resolved']}", ""]
    lines += [f"- {line_of(o)}" for o in result["resolved"]] or [w["none"]]
    if result["resolved"]:
        lines += ["", w["resolved_note"]]
        if norm(old_meta["scope"]) != norm(new_meta["scope"]):
            lines += ["", w["scope_differs"]]
    lines += ["", f"## {w['persisting']}", ""]
    for o, n, diff, reappeared in result["persisting"]:
        lines.append(f"- {line_of(n)} ← {o['id']}")
        if reappeared:
            lines.append(f"  - **{w['reappeared']}**")
        for key, a, b in diff:
            if key == "category":
                a, b = perspective_name(a, lang), perspective_name(b, lang)
            lines.append(f"  - {w[key]}: {text(a)} → {text(b)}")
        if not diff and not reappeared:
            lines.append(f"  - {w['unchanged']}")
    if not result["persisting"]:
        lines.append(w["none"])
    for key in ("now_excluded", "now_reported"):
        if result[key]:
            lines += ["", f"## {w[key]}", ""]
            lines += [f"- {line_of(n)} ← {o['id']} ({o['validation']['verdict']} → "
                      f"{n['validation']['verdict']})" for o, n in result[key]]
    lines += ["", f"## {w['rules']}", ""]
    for o, n in result["rules"]:
        rule = n or o
        if o is None:
            state = f"{w['rule_added']}: {n['status']}"
        elif n is None:
            state = f"{w['rule_dropped']} ({o['status']})"
        else:
            state = f"{o['status']} → {n['status']}"
        ids = " → ".join(dict.fromkeys(r["id"] for r in (o, n) if r))
        lines.append(f"- **{text(ids)}** {text(rule['idiom'])}: {state}")
    if not result["rules"]:
        lines.append(w["none"])
    lines += ["", f"## {w['perspectives']}", ""]
    lines += [f"- {text(perspective_name(name, lang))}: "
              f"{perspective_status(a, lang)} → {perspective_status(b, lang)}"
              for name, a, b in result["perspectives"]] or [w["none"]]
    return "\n".join(lines) + "\n"


class _Renaming(dict):
    """An old-to-new ID mapping that records each mentioned ID it cannot rename."""

    def __init__(self, mapping):
        super().__init__(mapping)
        self.missing = set()

    def get(self, key, default=None):
        if key not in self:
            self.missing.add(key)
        return super().get(key, default)


def carried_decision(item, ids):
    """The decision with its finding IDs renamed, or None when it names one gone now."""
    renaming = _Renaming(ids)
    text = _rewrite_ids(item, renaming)
    return None if renaming.missing else text


def carry(result, old_doc):
    """(fragment, lines): the earlier triage to carry into the later record, and what was done."""
    updates, decisions, lines = [], [], []
    for o, n, _, _ in result["persisting"]:
        if o.get("status") != "Accepted" or n.get("status", "Open") != "Open":
            continue
        if SEVERITIES.index(n["severity"]) < SEVERITIES.index(o["severity"]):
            lines.append(f"not carried {o['id']} → {n['id']}: Accepted as {o['severity']}, "
                         f"now {n['severity']}; decide again")
            continue
        updates.append({"id": n["id"], "status": "Accepted"})
        lines.append(f"carried {o['id']} → {n['id']}: Accepted")
        # Mentions as check reads them: ASCII boundaries, so "F-003は" names F-003.
        naming = [item for item in old_doc.get("decisions", [])
                  if re.search(rf"(?<!\w){o['id']}(?!\w)", item, re.ASCII)]
        kept = [text for text in (carried_decision(item, result["ids"]) for item in naming) if text]
        decisions += [text for text in kept if text not in decisions]
        if not kept:
            lines.append(f"  no decision carried for {n['id']}: name who accepted it and why in "
                         "decisions before check")
    fragment = {"findings": updates}
    if decisions:
        fragment["decisions"] = decisions
    return fragment, lines


def regressions(result, threshold):
    """Each reason the later record is worse at or above threshold, as one line."""
    limit = SEVERITIES.index(threshold)

    def at(f):
        return SEVERITIES.index(f["severity"]) <= limit

    out = [f"new {n['id']} [{n['severity']}] {n['title']}" for n in result["new"] if at(n)]
    for o, n, _, reappeared in result["persisting"]:
        if not at(n):
            continue
        if reappeared:
            out.append(f"reappeared {n['id']} [{n['severity']}] {n['title']} (earlier {o['id']} "
                       "was Fixed)")
        elif not at(o):
            out.append(f"severity rose {n['id']} {o['severity']} → {n['severity']} {n['title']}")
    out += [f"reported again {n['id']} [{n['severity']}] {n['title']} (earlier "
            f"{o['validation']['verdict']})" for o, n in result["now_reported"] if at(n)]
    return out


def load(path):
    doc = read_json(path)
    validate(doc, complete=True)
    return doc


def main(argv=None):
    safe_output()
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("old", metavar="OLD_FINDINGS")
    parser.add_argument("new", metavar="NEW_FINDINGS")
    parser.add_argument("--lang", choices=("ja", "en"))
    parser.add_argument("--format", choices=("md", "json"), default="md")
    parser.add_argument("--out", metavar="FILE", help="write here instead of standard output")
    parser.add_argument("--carry", metavar="FRAGMENT",
                        help="also write the earlier Accepted statuses as a fragment "
                             "for the later record")
    parser.add_argument("--fail-on", choices=SEVERITIES, metavar="SEVERITY",
                        help="exit 3 on a regression at or above SEVERITY (High, Medium, Low, Info)")
    args = parser.parse_args(argv)
    docs = []
    for path in (args.old, args.new):
        try:
            docs.append(load(path))
        except SchemaError as exc:
            print(f"schema: {exc}", file=sys.stderr)
            return 1
    old_doc, new_doc = docs
    result = compare(old_doc, new_doc)
    if args.format == "json":
        output = json.dumps(as_json(result, old_doc, new_doc), ensure_ascii=False, indent=2) + "\n"
    else:
        output = as_markdown(result, old_doc, new_doc, args.lang or new_doc["meta"]["lang"])
    files = {}
    if args.out is not None:
        files[Path(args.out)] = output.encode("utf-8")
    if args.carry is not None:
        fragment, carried = carry(result, old_doc)
        files[Path(args.carry)] = (json.dumps(fragment, ensure_ascii=False, indent=2)
                                   + "\n").encode("utf-8")
    if files:
        try:
            _atomic_write_all(files)
        except (OSError, RuntimeError) as exc:
            print(f"write failed: {exc}", file=sys.stderr)
            return 1
    # With the comparison on stdout, every other message goes to stderr.
    note = sys.stdout if args.out is not None else sys.stderr
    if args.out is None:
        sys.stdout.write(output)
    else:
        print(f"wrote {args.out}", file=note)
    if args.carry is not None:
        for line in carried:
            print(line, file=note)
        print(f"wrote {args.carry}: {len(fragment['findings'])} finding(s) to update; merge it "
              f"with findings.py merge {args.new} {args.carry}", file=note)
    if args.fail_on is not None:
        found = regressions(result, args.fail_on)
        for line in found:
            print(f"regression: {line}", file=sys.stderr)
        if found:
            return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
