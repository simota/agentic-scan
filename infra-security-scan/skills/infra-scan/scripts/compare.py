#!/usr/bin/env python3
"""Compare two assessments of the same estate: what was fixed, what is new.

    python3 compare.py PREVIOUS CURRENT [--format text|markdown|json] [--lang en|ja]
                       [--fail-on High|Medium|Low|Info]

PREVIOUS and CURRENT are each a findings.json or an output directory holding
one (its iac.json, when present, tells which files the run read). Nothing is
written; the comparison is printed. `render.py --previous PREVIOUS` puts the
same comparison into the dashboard and the assessment.

IDs are not stable between assessments (`renumber` orders F-* by severity), so
findings are matched by content: an I-* by its rule and then its resources and
file, an F-* by provider and perspective and then its resources, title and file.
Attack paths are matched by entry actor and target. Findings counted by the
reports take part: excluded findings (FalsePositive / NotApplicable) only as
the state a match moved from or to, and I-* covered by a review finding not at
all, since that finding carries their root cause.

| Change | Meaning |
|---|---|
| new | in CURRENT only |
| resolved | in PREVIOUS only, and its file is still among CURRENT's inputs |
| out_of_inputs | in PREVIOUS only, and CURRENT's iac.json no longer reads its file (removed, or out of scope) |
| reopened | excluded in PREVIOUS, counted in CURRENT |
| excluded | counted in PREVIOUS, excluded in CURRENT (closed by triage, not by a fix) |
| persisting | counted in both; `changes` lists severity, confidence, verdict and location moves |

A resolved finding means the configuration no longer shows it, not that the
deployed estate is fixed: say so, and confirm with a plan or snapshot.

`--fail-on SEVERITY` exits 1 when a new or reopened finding, or a persisting one
whose severity rose, is at SEVERITY or above, or when an attack path is newly
open: a gate for a retest.

Exit codes: 0 compared, 1 a --fail-on gate tripped, 2 unreadable input or schema error.
"""
import argparse
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also under python -I
import render  # noqa: E402
from common import LOCATION, SEV_RANK, SEVERITIES  # noqa: E402
from redaction import CREDENTIAL  # noqa: E402

CHANGES = ("new", "resolved", "out_of_inputs", "reopened", "excluded", "persisting")
TRACKED = ("severity", "confidence", "verdict", "location")
SPACE = re.compile(r"\s+")

LABELS = {
    "en": {
        "heading": "Changes since the previous assessment",
        "previous": "Previous", "current": "Current", "change": "Change",
        "counts": "Counted findings by severity", "open_paths": "Open attack paths",
        "new": "New", "resolved": "Resolved", "out_of_inputs": "No longer in the inputs",
        "reopened": "Reopened", "excluded": "Excluded by triage", "persisting": "Persisting",
        "changed": "Persisting, changed", "ap_new": "New attack paths", "ap_removed": "Attack paths no longer recorded",
        "ap_changed": "Attack path status changes", "none": "none",
        "resolved_note": "Resolved means the configuration no longer shows the finding; confirm the deployed "
                         "state with a plan or snapshot.",
        "verdict": "verdict", "severity": "severity", "confidence": "confidence", "location": "location",
        "note_project": "the records name different projects ({0} / {1})",
        "note_order": "PREVIOUS is dated after CURRENT ({0} > {1}); were they swapped?",
        "note_files": "CURRENT has no iac.json beside it: a finding whose file left the inputs reads as resolved",
    },
    "ja": {
        "heading": "前回診断からの変化",
        "previous": "前回", "current": "今回", "change": "変化",
        "counts": "深刻度別の件数", "open_paths": "開いている攻撃経路",
        "new": "新規", "resolved": "解消", "out_of_inputs": "入力に含まれなくなった",
        "reopened": "再発", "excluded": "精査で除外", "persisting": "継続",
        "changed": "継続（変化あり）", "ap_new": "新しい攻撃経路", "ap_removed": "記録されなくなった攻撃経路",
        "ap_changed": "攻撃経路の状態の変化", "none": "なし",
        "resolved_note": "解消は設定上その検出事項が見えなくなったことを示します。稼働環境はプランまたはスナップショットで確認してください。",
        "verdict": "判定", "severity": "深刻度", "confidence": "確度", "location": "場所",
        "note_project": "2 つの記録は別の対象を指しています（{0} / {1}）",
        "note_order": "前回の記録の日付が今回より後です（{0} > {1}）。順序が逆ではありませんか",
        "note_files": "今回の記録の隣に iac.json がないため、入力から外れたファイルの検出事項も解消と表示されます",
    },
}


class CompareError(Exception):
    pass


def load_side(path):
    """(record, files or None, digest) from a findings.json or an output directory."""
    path = Path(path)
    record_path = path / "findings.json" if path.is_dir() else path
    if not record_path.is_file():
        raise CompareError(f"{path}: no findings.json")
    data = render.load_record(record_path)
    render.validate(data, partial=True)
    files = None
    iac = record_path.parent / "iac.json"
    if iac.is_file():
        try:
            doc = json.loads(iac.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError, RecursionError) as e:
            raise CompareError(f"{iac}: unreadable ({e})") from None
        if isinstance(doc, dict) and isinstance(doc.get("files"), list):
            files = {f.get("path") for f in doc["files"] if isinstance(f, dict) and isinstance(f.get("path"), str)}
    return data, files, render.record_digest(data)


def norm(text):
    return SPACE.sub(" ", str(text or "")).strip().strip(".").casefold()


def location_file(location):
    m = LOCATION.match(location) if isinstance(location, str) else None
    return m.group(1) if m else str(location or "")


def state(f, covered):
    if render.is_excluded(f):
        return "excluded"
    return "covered" if f.get("id") in covered else "counted"


def score(old, new):
    """How alike two findings are; None when they cannot be the same root cause."""
    kind = str(old.get("id", ""))[:2]
    if kind != str(new.get("id", ""))[:2]:
        return None
    a, b = set(old.get("resources", [])), set(new.get("resources", []))
    same_file = location_file(old.get("location")) == location_file(new.get("location"))
    points = 4 if a and a == b else 2 if a & b else 0
    points += 1 if same_file else 0
    if kind == "I-":
        if old.get("rule") != new.get("rule") or not (a & b or same_file):
            return None
        points += (old.get("detail") == new.get("detail")) + (old.get("location") == new.get("location"))
        return points
    if old.get("provider") != new.get("provider") or old.get("category") != new.get("category"):
        return None
    same_title = norm(old.get("title")) == norm(new.get("title"))
    if not (a & b or same_title):
        return None
    return points + (3 if same_title else 0)


def candidates(old, new):
    """For each old finding, the ascending indexes of the new findings score() can pair
    it with: the same kind and rule (I-) or provider and category, and a shared
    resource or the same file (I-) or title. A superset: score() still decides.
    Raises TypeError for unhashable values, which only an unvalidated record holds."""
    def group(f):
        kind = str(f.get("id", ""))[:2]
        return (kind, f.get("rule")) if kind == "I-" else (kind, f.get("provider"), f.get("category"))

    def alike(f, kind):
        return location_file(f.get("location")) if kind == "I-" else norm(f.get("title"))

    index = {}
    for j, n in enumerate(new):
        key = group(n)
        by_resource, by_alike = index.setdefault(key, ({}, {}))
        for r in set(n.get("resources", [])):
            by_resource.setdefault(r, []).append(j)
        by_alike.setdefault(alike(n, key[0]), []).append(j)
    out = []
    for o in old:
        key = group(o)
        found = set()
        if key in index:
            by_resource, by_alike = index[key]
            for r in set(o.get("resources", [])):
                found.update(by_resource.get(r, ()))
            found.update(by_alike.get(alike(o, key[0]), ()))
        out.append(sorted(found))
    return out


def match(old, new):
    """Greedy one-to-one pairs, best score first; ties in ID order so the result is stable."""
    try:
        # Scoring every pair is quadratic: 6,000 findings a side took a minute.
        within = candidates(old, new)
    except TypeError:
        within = None  # every pair, as score() alone would decide
    pairs, new_keys = [], {}
    for i, o in enumerate(old):
        o_key = None
        for j in range(len(new)) if within is None else within[i]:
            n = new[j]
            s = score(o, n)
            if s is not None:
                if o_key is None:
                    o_key = render.id_key(o["id"])
                if j not in new_keys:
                    new_keys[j] = render.id_key(n["id"])
                pairs.append((-s, o_key, new_keys[j], o, n))
    pairs.sort(key=lambda p: p[:3])
    taken_o, taken_n, out = set(), set(), []
    for _, _, _, o, n in pairs:
        if o["id"] in taken_o or n["id"] in taken_n:
            continue
        taken_o.add(o["id"])
        taken_n.add(n["id"])
        out.append((o, n))
    return out


def clean(text):
    """Either record may not have passed this run's merge gate: never repeat a credential shape."""
    return CREDENTIAL.sub("[redacted]", text) if isinstance(text, str) else text


def brief(f):
    return {"id": f["id"], "title": clean(f.get("title", "")), "severity": f.get("severity"),
            "confidence": f.get("confidence"), "verdict": (f.get("validation") or {}).get("verdict"),
            "location": clean(f.get("location")), "resources": [clean(r) for r in f.get("resources", [])],
            **({"rule": f["rule"]} if f.get("rule") else {})}


def side_meta(data, digest):
    meta = data.get("meta", {})
    return {"project": clean(meta.get("project", "")), "date": meta.get("date", ""), "commit": meta.get("commit", ""),
            "digest": digest}


def compare(previous, current, previous_files=None, current_files=None, digests=("", "")):
    """The comparison as a JSON-ready dict; see the module docstring for the change kinds."""
    pc, cc = render.covered_by(previous), render.covered_by(current)
    old = [f for f in previous.get("findings", []) if state(f, pc) != "covered"]
    new = [f for f in current.get("findings", []) if state(f, cc) != "covered"]
    result = {k: [] for k in CHANGES}
    pairs = match(old, new)
    matched_o = {o["id"] for o, _ in pairs}
    matched_n = {n["id"] for _, n in pairs}
    for o, n in pairs:
        so, sn = state(o, pc), state(n, cc)
        if so == "excluded" and sn == "excluded":
            continue
        kind = "reopened" if so == "excluded" else "excluded" if sn == "excluded" else "persisting"
        bo, bn = brief(o), brief(n)
        changes = [{"field": k, "from": bo[k], "to": bn[k]} for k in TRACKED if bo[k] != bn[k]]
        result[kind].append({"previous": bo, "current": bn, "changes": changes})
    for n in new:
        if n["id"] not in matched_n and state(n, cc) == "counted":
            result["new"].append({"current": brief(n)})
    for o in old:
        if o["id"] not in matched_o and state(o, pc) == "counted":
            gone = current_files is not None and location_file(o.get("location")) not in current_files
            result["out_of_inputs" if gone else "resolved"].append({"previous": brief(o)})
    for items in result.values():
        items.sort(key=lambda item: (SEV_RANK.get((item.get("current") or item["previous"])["severity"], 9),
                                     render.id_key((item.get("current") or item["previous"])["id"])))

    def ap_key(a):
        return norm(a.get("entry")), norm(a.get("target"))
    old_ap = {ap_key(a): a for a in previous.get("attack_paths", [])}
    new_ap = {ap_key(a): a for a in current.get("attack_paths", [])}

    def ap_brief(a):
        return {"id": a["id"], "entry": clean(a.get("entry", "")), "target": clean(a.get("target", "")),
                "status": a.get("status")}
    paths = {"new": [ap_brief(a) for k, a in new_ap.items() if k not in old_ap],
             "removed": [ap_brief(a) for k, a in old_ap.items() if k not in new_ap],
             "changed": [], "unchanged": 0}
    for k, a in new_ap.items():
        if k in old_ap:
            if old_ap[k].get("status") != a.get("status"):
                paths["changed"].append({"previous": ap_brief(old_ap[k]), "current": ap_brief(a)})
            else:
                paths["unchanged"] += 1

    def open_paths(data):
        return sum(1 for a in data.get("attack_paths", []) if a.get("status") == "open")
    keep = lambda c: {s: c[s] for s in (*SEVERITIES, "excluded", "covered", "unverified")}
    notes = []
    pm, cm = previous.get("meta", {}), current.get("meta", {})
    if pm.get("project") and cm.get("project") and norm(pm["project"]) != norm(cm["project"]):
        notes.append(["note_project", pm["project"], cm["project"]])
    if pm.get("date") and cm.get("date") and pm["date"] > cm["date"]:
        notes.append(["note_order", pm["date"], cm["date"]])
    if current_files is None:
        notes.append(["note_files"])
    return {
        "previous": side_meta(previous, digests[0]), "current": side_meta(current, digests[1]),
        "counts": {"previous": keep(render.counts(previous)), "current": keep(render.counts(current))},
        "open_attack_paths": {"previous": open_paths(previous), "current": open_paths(current)},
        "findings": result, "attack_paths": paths, "notes": notes,
    }


def regressions(result, threshold):
    """Lines naming what trips --fail-on THRESHOLD."""
    limit = SEV_RANK[threshold]
    out = []
    for kind in ("new", "reopened"):
        for item in result["findings"][kind]:
            f = item["current"]
            if SEV_RANK.get(f["severity"], 9) <= limit:
                out.append(f"{kind} {f['id']} [{f['severity']}] {f['title']}")
    for item in result["findings"]["persisting"]:
        o, n = item["previous"], item["current"]
        if SEV_RANK.get(n["severity"], 9) < SEV_RANK.get(o["severity"], 9) and SEV_RANK.get(n["severity"], 9) <= limit:
            out.append(f"raised {n['id']} {o['severity']} -> {n['severity']} {n['title']}")
    for a in result["attack_paths"]["new"]:
        if a["status"] == "open":
            out.append(f"newly open {a['id']} {a['entry']} -> {a['target']}")
    for item in result["attack_paths"]["changed"]:
        if item["current"]["status"] == "open":
            out.append(f"newly open {item['current']['id']} {item['current']['entry']} -> {item['current']['target']}")
    return out


def note_text(note, L):
    """A note is [label key, *arguments], so every output can word it in its language."""
    return L[note[0]].format(*note[1:])


def change_text(item, L):
    return ", ".join(f"{L[c['field']]} {c['from']} → {c['to']}" for c in item["changes"])


def item_line(item, L):
    o, n = item.get("previous"), item.get("current")
    if o and n:
        ident = o["id"] if o["id"] == n["id"] else f"{o['id']} → {n['id']}"
        f = n
    else:
        f = n or o
        ident = f["id"]
    line = f"{ident} [{f['severity']}] {f['title']} ({f['location']})"
    return line + (f" — {change_text(item, L)}" if item.get("changes") else "")


def sections(result, L):
    """[(label, [line])] in reading order; persisting findings without a change are counted, not listed."""
    fs = result["findings"]
    out = [(L[k], [item_line(i, L) for i in fs[k]]) for k in ("new", "reopened", "resolved", "out_of_inputs",
                                                               "excluded")]
    out.append((L["changed"], [item_line(i, L) for i in fs["persisting"] if i["changes"]]))
    aps = result["attack_paths"]
    out.append((L["ap_new"], [f"{a['id']} [{a['status']}] {a['entry']} → {a['target']}" for a in aps["new"]]))
    out.append((L["ap_changed"], [f"{c['current']['id']} {c['previous']['status']} → {c['current']['status']}: "
                                  f"{c['current']['entry']} → {c['current']['target']}" for c in aps["changed"]]))
    out.append((L["ap_removed"], [f"{a['id']} [{a['status']}] {a['entry']} → {a['target']}" for a in aps["removed"]]))
    return out


def headline(result, L):
    cp, cc = result["counts"]["previous"], result["counts"]["current"]
    sev = " · ".join(f"{s} {cp[s]} → {cc[s]}" for s in SEVERITIES)
    op = result["open_attack_paths"]
    fs = result["findings"]
    return (f"{sev}; {L['open_paths']} {op['previous']} → {op['current']}; "
            f"{L['new']} {len(fs['new'])}, {L['resolved']} {len(fs['resolved'])}, "
            f"{L['reopened']} {len(fs['reopened'])}, {L['persisting']} {len(fs['persisting'])}")


def as_text(result, L):
    p, c = result["previous"], result["current"]
    side = lambda m: " ".join(x for x in (m["date"], m["commit"][:12]) if x) or "-"
    project = f" {p['project']}" if p["project"] else ""
    lines = [f"{L['heading']}:{project} {side(p)} → {side(c)}", headline(result, L)]
    for label, items in sections(result, L):
        if items:
            lines += ["", f"{label} ({len(items)})"] + [f"  {x}" for x in items]
    lines += ["", L["resolved_note"]] + [f"note: {note_text(n, L)}" for n in result["notes"]]
    return "\n".join(lines) + "\n"


def as_markdown(result, L):
    p, c = result["previous"], result["current"]
    cp, cc = result["counts"]["previous"], result["counts"]["current"]
    op = result["open_attack_paths"]
    lines = [f"## {L['heading']}", "",
             f"{L['previous']}: {p['date']} `{p['commit'][:12] or '-'}` · {L['current']}: {c['date']} `{c['commit'][:12] or '-'}`",
             "", f"| | {' | '.join(SEVERITIES)} | {L['open_paths']} |", "|---|" + "---|" * (len(SEVERITIES) + 1),
             f"| {L['previous']} | {' | '.join(str(cp[s]) for s in SEVERITIES)} | {op['previous']} |",
             f"| {L['current']} | {' | '.join(str(cc[s]) for s in SEVERITIES)} | {op['current']} |"]
    for label, items in sections(result, L):
        lines += ["", f"### {label} ({len(items)})", ""] + ([f"- {x}" for x in items] or [f"- {L['none']}"])
    lines += ["", L["resolved_note"]] + [f"- note: {note_text(n, L)}" for n in result["notes"]]
    return "\n".join(lines) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("previous")
    p.add_argument("current")
    p.add_argument("--format", choices=("text", "markdown", "json"), default="text")
    p.add_argument("--lang", choices=sorted(LABELS), default="en")
    p.add_argument("--fail-on", choices=SEVERITIES, metavar="SEVERITY",
                   help="exit 1 on a new, reopened or raised finding at SEVERITY or above, or a newly open path")
    a = p.parse_args(argv)
    try:
        prev, prev_files, prev_digest = load_side(a.previous)
        cur, cur_files, cur_digest = load_side(a.current)
    except CompareError as e:
        print(f"compare: {e}", file=sys.stderr)
        return 2
    except render.SchemaError as e:
        for problem in e.problems:
            print(f"schema: {problem}", file=sys.stderr)
        return 2
    result = compare(prev, cur, prev_files, cur_files, (prev_digest, cur_digest))
    L = LABELS[a.lang]
    if a.format == "json":
        shown = {**result, "notes": [note_text(n, L) for n in result["notes"]]}
        sys.stdout.write(json.dumps(shown, ensure_ascii=False, indent=2) + "\n")
    else:
        sys.stdout.write(as_markdown(result, L) if a.format == "markdown" else as_text(result, L))
    if a.fail_on:
        tripped = regressions(result, a.fail_on)
        if tripped:
            print(f"compare: --fail-on {a.fail_on}: " + "; ".join(tripped), file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
