#!/usr/bin/env python3
"""Turn a settled prune-scan record into an ordered removal plan (reference/plan.md).

    python3 plan.py FINDINGS [--unit UNIT]... [--out PLAN.md] [--json PLAN.json] [--lang en|ja]

FINDINGS is a review's findings.json (units.json beside it names the units).
The plan is the hand-off to the later removal request: one checkbox step per
open Valid finding, remove-now steps before reduce or consolidate, each with
what to subtract, what remains, what is lost, the risk and every file it
touches. Ordering prose in a finding's risk or subtraction ("after P-010",
"P-010 の後") puts it after the finding it names; a step that waits for a
finding still to be decided, or for one kept, moves to "waits for a
decision". Coupling prose ("goes with P-003", "P-003 と併せて") is shown
beside the step without reordering it. Every other open, counted finding is
listed with the question a human must settle (its decisions lines, else its
risk). Files several steps touch are listed, so removals that share a file can
land together. --unit limits the steps to those units; prerequisites outside
them are still named. Markdown goes to --out or stdout; --json writes the same
plan for an agent. The plan names the record's SHA-256: regenerate it after
any merge. Nothing is deleted. Standard library only.
Exit status: 0 planned, 2 invalid input or unwritable output (reasons on stderr).
"""

import argparse
import hashlib
import heapq
import os
import re
import sys
from contextlib import ExitStack
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import (EXCLUDED, RecordError, check_findings, dump, load_json, record_sources,  # noqa: E402
                      rewrite_prose, units_beside)
from safe_output import SAFE_OUTPUT, tolerant_stdout, write_output_at  # noqa: E402
from safe_paths import open_directory  # noqa: E402
from report_output import write_output  # noqa: E402

MARK = "\x00"
# Prose that orders one subtraction after another, read around a marked reference.
AFTER_BEFORE = re.compile(r"(?i)\b(?:after|once|until|following)\s+(?:the\s+)?(?:\S+\s+){0,1}\Z")
AFTER_AFTER = re.compile(r"\A\s*(?:の後|のあと|より後|より前には行わない|が済んで|の完了後|を先に)")
WITH_BEFORE = re.compile(r"(?i)\b(?:with|alongside|together with)\s+\Z")
WITH_AFTER = re.compile(r"\A\s*(?:と併せて|と一緒に|と同時に|の[^。、\n\x00]{0,10}?で併せて)")

TEXT = {
    "en": {
        "title": "Removal plan: {project}", "commit": " (commit {commit})",
        "record": "From the review of {date}{commit}; findings.json SHA-256 `{sha}`. Regenerate the plan after "
                  "any merge into the record.",
        "scope": "Units: {units}.",
        "intro": "Each step is one open `Valid` finding. Work top to bottom; a step that names a prerequisite "
                 "comes after it. Nothing here was deleted by the review.",
        "now": "Remove now", "reduce": "Reduce or consolidate", "blocked": "Waits for a decision",
        "decide": "Decide with a human first", "shared": "Files several steps touch",
        "after_title": "After the removals", "none": "Nothing in this group.",
        "verb": {"remove": "Remove", "reduce": "Reduce", "consolidate": "Consolidate"},
        "remains": "Remains", "loses": "Loses", "risk": "Risk", "touches": "Touches", "unit": "Unit",
        "after": "After", "with": "Coordinate with", "related": "See also", "waits": "Waits for",
        "question": "To settle", "confidence": "Confidence", "undecided": "still to decide",
        "why_decide": "{id} is still to decide ({confidence}, {verdict})",
        "why_kept": "{id} is kept ({status}, {verdict}); the order it required no longer holds: re-check this step",
        "why_cycle": "an ordering cycle with {ids}; order these steps by hand",
        "outside": "{id} first (outside the selected units)",
        "kept": "Not in this plan: {parts}.",
        "kept_part": {"Unlikely": "{n} kept as Unlikely (evidence of use)", "Accepted": "{n} Accepted",
                      "Fixed": "{n} already Fixed", "Excluded": "{n} ruled out (FalsePositive / NotApplicable)"},
        "follow": [
            "Commit the removals step by step, so each can be reverted alone.",
            "Run the app's own tests and build after each group.",
            "Re-run `inventory.py <repo> --units <units.json> --out <new-out>/inventory.json`: removals orphan "
            "the next wave of candidates.",
            "Run a follow-up prune-scan into a new output directory, then "
            "`compare.py <this-out> <new-out> --repo <repo> --fragment <scratch>/carry.json` to record what is "
            "gone as Fixed (reference/follow-up.md).",
        ],
    },
    "ja": {
        "title": "削除計画:{project}", "commit": "(コミット {commit})",
        "record": "{date}のレビュー{commit}から作成。findings.json の SHA-256 は `{sha}`。記録へマージしたら計画を作り直す。",
        "scope": "対象ユニット:{units}。",
        "intro": "各ステップは未対応の `Valid` 指摘1件。上から順に進める。前提を挙げたステップはその後に置いている。"
                 "レビューは何も削除していない。",
        "now": "今すぐ削除", "reduce": "縮小・統合", "blocked": "判断待ち",
        "decide": "先に人が判断する", "shared": "複数のステップが触れるファイル",
        "after_title": "削除の後で", "none": "該当なし。",
        "verb": {"remove": "削除", "reduce": "縮小", "consolidate": "統合"},
        "remains": "残るもの", "loses": "失うもの", "risk": "リスク", "touches": "触れるファイル", "unit": "ユニット",
        "after": "前提", "with": "併せて調整", "related": "関連", "waits": "待ち",
        "question": "判断すること", "confidence": "確信度", "undecided": "未判断",
        "why_decide": "{id} が未判断({confidence}、{verdict})",
        "why_kept": "{id} は残す判断({status}、{verdict})。求めていた順序が成り立たないため、このステップを見直す",
        "why_cycle": "{ids} と順序が循環している。手で順序を決める",
        "outside": "先に {id}(選択外のユニット)",
        "kept": "この計画に含めないもの:{parts}。",
        "kept_part": {"Unlikely": "Unlikely として残す {n} 件(利用の証拠あり)", "Accepted": "Accepted {n} 件",
                      "Fixed": "対応済み(Fixed){n} 件", "Excluded": "除外(FalsePositive / NotApplicable){n} 件"},
        "follow": [
            "削除はステップごとにコミットし、個別に戻せるようにする。",
            "各グループの後にアプリ自身のテストとビルドを実行する。",
            "`inventory.py <repo> --units <units.json> --out <new-out>/inventory.json` を再実行する。"
            "削除によって次の候補が孤立する。",
            "新しい出力ディレクトリへ再レビューを行い、"
            "`compare.py <this-out> <new-out> --repo <repo> --fragment <scratch>/carry.json` で"
            "消えたものを Fixed として記録する(reference/follow-up.md)。",
        ],
    },
}


def location_file(location):
    return re.sub(r":[1-9][0-9]*(?:-[1-9][0-9]*)?\Z", "", location)


def code(text):
    """A Markdown code span that survives backticks in the text."""
    fence = "`" * (max((len(m) for m in re.findall(r"`+", text)), default=0) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def one_line(text):
    return " ".join(str(text).split())


def references(data, finding):
    """(after, with, related) finding ids named in a finding's risk and subtraction prose."""
    ids = {f["id"] for f in data["findings"]}
    marks = {i: f"{MARK}{i}{MARK}" for i in ids}
    sources = record_sources(data)
    after, together, related = [], [], []
    texts = [finding["risk"], *(finding["subtraction"][k] for k in ("what", "remains", "loses"))]
    for text in texts:
        marked = rewrite_prose(text, marks, sources)
        for m in re.finditer(f"{MARK}(P-[0-9]{{3}}){MARK}", marked):
            ref = m.group(1)
            if ref == finding["id"]:
                continue
            before = marked[max(0, m.start() - 40):m.start()].split(MARK)[-1]
            rest = marked[m.end():m.end() + 30]
            if AFTER_BEFORE.search(before) or AFTER_AFTER.match(rest):
                after.append(ref)
            elif WITH_BEFORE.search(before) or WITH_AFTER.match(rest):
                together.append(ref)
            else:
                related.append(ref)
    after = list(dict.fromkeys(after))
    together = [i for i in dict.fromkeys(together) if i not in after]
    related = [i for i in dict.fromkeys(related) if i not in after and i not in together]
    return after, together, related


def group(f):
    """now, reduce, decide, or the reason it is not planned."""
    verdict = f["validation"]["verdict"]
    if verdict in EXCLUDED:
        return "Excluded"
    if f["status"] != "Open":
        return f["status"]
    if verdict == "Unlikely":
        return "Unlikely"
    if verdict == "Valid":
        return "now" if f["subtraction"]["action"] == "remove" else "reduce"
    return "decide"


def build_plan(data, units, selected, lang):
    T = TEXT[lang]
    by_id = {f["id"]: f for f in data["findings"]}
    kind = {f["id"]: group(f) for f in data["findings"]}
    refs = {f["id"]: references(data, f) for f in data["findings"]}
    unit_names = {u["id"]: u["name"] for u in (units or {}).get("units", [])}
    in_scope = (lambda f: True) if not selected else (lambda f: f["unit_ref"] in selected)
    order = {f["id"]: n for n, f in enumerate(data["findings"])}
    actionable = [f["id"] for f in data["findings"] if kind[f["id"]] in ("now", "reduce")]

    # A step waits when a prerequisite, directly or through another step, is not itself a step.
    waits, wave = {}, {}

    def resolve(fid, trail=()):
        if fid in wave or fid in waits or fid in trail:  # A cycle is left to the ordering below.
            return
        reasons, level = [], 0 if kind[fid] == "now" else 1
        for pre in refs[fid][0]:
            k = kind.get(pre)
            g = by_id[pre]
            if k in ("now", "reduce"):
                resolve(pre, trail + (fid,))
                if pre in waits:  # The prerequisite's own reason is this step's too.
                    reasons.extend(waits[pre])
                else:
                    level = max(level, wave.get(pre, 0))
            elif k == "decide":
                reasons.append(T["why_decide"].format(id=pre, confidence=g["confidence"],
                                                      verdict=g["validation"]["verdict"]))
            elif k != "Fixed":
                reasons.append(T["why_kept"].format(id=pre, status=g["status"], verdict=g["validation"]["verdict"]))
        if reasons:
            waits[fid] = list(dict.fromkeys(reasons))
        else:
            wave[fid] = level

    for fid in actionable:
        resolve(fid)
    # Kahn's algorithm over ready steps, keeping wave and then record (severity) order.
    ready_ids = [i for i in actionable if i in wave]
    pending = {i: {p for p in refs[i][0] if p in wave} for i in ready_ids}
    users = {i: [j for j in ready_ids if i in pending[j]] for i in ready_ids}
    heap = [(wave[i], order[i], i) for i in ready_ids if not pending[i]]
    heapq.heapify(heap)
    ordered = []
    while heap:
        _, _, i = heapq.heappop(heap)
        ordered.append(i)
        for j in users[i]:
            pending[j].discard(i)
            if not pending[j]:
                heapq.heappush(heap, (wave[j], order[j], j))
    cyclic = [i for i in ready_ids if i not in ordered]
    for i in cyclic:
        waits[i] = [T["why_cycle"].format(ids=", ".join(x for x in cyclic if x != i))]

    def entry(fid):
        f = by_id[fid]
        after, together, related = refs[fid]
        files = list(dict.fromkeys(location_file(x) for x in [f["location"], *f.get("occurrences", [])]))
        row = {"id": fid, "severity": f["severity"], "action": f["subtraction"]["action"],
               "element": f["element"], "location": f["location"], "files": files,
               "unit_ref": f["unit_ref"], "unit_name": unit_names.get(f["unit_ref"], ""),
               "what": f["subtraction"]["what"], "remains": f["subtraction"]["remains"],
               "loses": f["subtraction"]["loses"], "risk": f["risk"],
               "after": after, "with": together, "related": related}
        outside = [p for p in after if p in wave and not in_scope(by_id[p])]
        if outside:
            row["first_outside"] = outside
        return row

    steps = []
    for fid in ordered:
        if in_scope(by_id[fid]):
            steps.append({**entry(fid), "wave": "now" if wave[fid] == 0 else "reduce"})
    blocked = [{**entry(fid), "waits_for": waits[fid]} for fid in actionable
               if fid in waits and in_scope(by_id[fid])]
    decide = []
    for f in data["findings"]:
        if kind[f["id"]] != "decide" or not in_scope(f):
            continue
        marks = {f["id"]: f"{MARK}{f['id']}{MARK}"}
        sources = record_sources(data)
        lines = [line for line in data.get("decisions", [])
                 if f"{MARK}{f['id']}{MARK}" in rewrite_prose(line, marks, sources)]
        decide.append({"id": f["id"], "severity": f["severity"], "confidence": f["confidence"],
                       "verdict": f["validation"]["verdict"], "element": f["element"], "location": f["location"],
                       "unit_ref": f["unit_ref"], "question": lines or [f["risk"]],
                       "unblocks": [b["id"] for b in blocked if any(f["id"] in w for w in b["waits_for"])]})
    touched = {}
    for row in steps + blocked:
        for path in row["files"]:
            touched.setdefault(path, []).append(row["id"])
    shared = {path: ids for path, ids in sorted(touched.items()) if len(ids) > 1}
    kept = {}
    for f in data["findings"]:
        if kind[f["id"]] in ("Unlikely", "Accepted", "Fixed", "Excluded") and in_scope(f):
            kept[kind[f["id"]]] = kept.get(kind[f["id"]], 0) + 1
    return {"steps": steps, "blocked": blocked, "decide": decide, "shared_files": shared, "kept": kept}


def markdown(plan, lang):
    T = TEXT[lang]
    rec = plan["record"]
    commit = T["commit"].format(commit=rec["commit"][:12]) if rec.get("commit") else ""
    out = [f"# {T['title'].format(project=rec['project'])}", "",
           T["record"].format(date=rec["date"], commit=commit, sha=rec["sha256"][:16]), ""]
    if plan["units"]:
        out += [T["scope"].format(units=", ".join(plan["units"])), ""]
    out += [T["intro"], ""]

    undecided = {row["id"] for row in plan["decide"]}

    def refs_line(label, ids):
        named = [f"{i} ({T['undecided']})" if i in undecided else i for i in ids]
        return [f"  - {label}: {', '.join(named)}"] if ids else []

    def step(n, row, extra=()):
        head = (f"- [ ] {n}. **{row['id']}** · {row['severity']} · {one_line(row['element'])} — "
                f"{code(row['location'])}")
        lines = [head, f"  - {T['verb'][row['action']]}: {one_line(row['what'])}",
                 f"  - {T['remains']}: {one_line(row['remains'])}",
                 f"  - {T['loses']}: {one_line(row['loses'])}",
                 f"  - {T['risk']}: {one_line(row['risk'])}",
                 f"  - {T['touches']}: " + ", ".join(code(p) for p in row["files"])]
        if row.get("unit_name"):
            lines.append(f"  - {T['unit']}: {row['unit_ref']} {one_line(row['unit_name'])}")
        lines += refs_line(T["after"], row["after"])
        lines += [f"  - {T['outside'].format(id=i)}" for i in row.get("first_outside", [])]
        lines += refs_line(T["with"], row["with"]) + refs_line(T["related"], row["related"])
        lines += [f"  - {T['waits']}: {one_line(w)}" for w in extra]
        return lines

    n = 0
    for wave in ("now", "reduce"):
        rows = [r for r in plan["steps"] if r["wave"] == wave]
        out += [f"## {T[wave]} ({len(rows)})", ""]
        if not rows:
            out += [T["none"], ""]
        for row in rows:
            n += 1
            out += step(n, row) + [""]
    out += [f"## {T['blocked']} ({len(plan['blocked'])})", ""]
    if not plan["blocked"]:
        out += [T["none"], ""]
    for row in plan["blocked"]:
        n += 1
        out += step(n, row, row["waits_for"]) + [""]
    out += [f"## {T['decide']} ({len(plan['decide'])})", ""]
    if not plan["decide"]:
        out += [T["none"], ""]
    for row in plan["decide"]:
        out.append(f"- [ ] **{row['id']}** · {row['severity']} · {one_line(row['element'])} — "
                   f"{code(row['location'])} ({T['confidence']}: {row['confidence']}, {row['verdict']})")
        out += [f"  - {T['question']}: {one_line(q)}" for q in row["question"]]
        if row["unblocks"]:
            out.append(f"  - {T['waits']}: {', '.join(row['unblocks'])}")
        out.append("")
    if plan["shared_files"]:
        out += [f"## {T['shared']}", ""]
        out += [f"- {code(path)}: {', '.join(ids)}" for path, ids in plan["shared_files"].items()] + [""]
    if plan["kept"]:
        parts = [T["kept_part"][k].format(n=v) for k, v in plan["kept"].items()]
        out += [T["kept"].format(parts=", ".join(parts) if lang == "en" else "、".join(parts)), ""]
    out += [f"## {T['after_title']}", ""]
    out += [f"{i}. {line}" for i, line in enumerate(T["follow"], 1)]
    return "\n".join(out) + "\n"


def write_text(target, text, protected):
    output = Path(target)
    with ExitStack() as resources:
        if SAFE_OUTPUT:
            selected = output.parent.stat()
            directory = open_directory(output.parent.resolve(strict=True), readable=False, expected_stat=selected)
            resources.callback(os.close, directory)
            write_output_at(directory, output.name, text, protected=tuple(protected))
        else:
            if output.exists() and any(os.path.samestat(os.stat(output), s) for s in protected):
                raise OSError("output would overwrite an input")
            write_output(output, text)


def main(argv=None):
    tolerant_stdout()
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("findings", help="the review's findings.json (units.json beside it is read too)")
    p.add_argument("--unit", action="append", default=[], metavar="UNIT",
                   help="only plan steps in this unit (a units.json id such as UN-01); repeatable")
    p.add_argument("--out", help="write the Markdown plan to this file instead of stdout (not the reviewed repository)")
    p.add_argument("--json", help="also write the plan as JSON to this file")
    p.add_argument("--lang", choices=("en", "ja"), default="en", help="language of the plan's labels (default: en)")
    a = p.parse_args(argv)
    target = Path(a.findings)
    if target.is_dir():
        target = target / "findings.json"
    try:
        raw = target.read_bytes()
        units = units_beside(target)
        data = check_findings(load_json(target), units, ordered=False)
        known = {u["id"] for u in (units or {}).get("units", [])} | {f["unit_ref"] for f in data["findings"]}
        unknown = [u for u in a.unit if u not in known]
        if unknown:
            raise RecordError(f"--unit {unknown[0]}: no such unit in the record")
        plan = {"tool": "plan.py", "version": 1,
                "record": {"project": data["meta"]["project"], "date": data["meta"]["date"],
                           "commit": data["meta"].get("commit", ""), "sha256": hashlib.sha256(raw).hexdigest()},
                "units": a.unit, **build_plan(data, units, set(a.unit), a.lang)}
    except (RecordError, OSError) as e:
        print(f"plan.py: {e}", file=sys.stderr)
        return 2
    text = markdown(plan, a.lang)
    targets = [(t, payload) for t, payload in ((a.out, text), (a.json, None)) if t]
    if len(targets) == 2 and Path(a.out).absolute() == Path(a.json).absolute():
        print("plan.py: --out and --json name the same file", file=sys.stderr)
        return 2
    protected = []
    for path in (target, target.with_name("units.json")):
        try:
            protected.append(os.stat(path))
        except OSError:
            pass
    for out, payload in targets:
        try:
            write_text(out, text if payload is not None else dump(plan), protected)
        except (OSError, ValueError, RecordError) as e:
            print(f"plan.py: cannot write {out}: {e}", file=sys.stderr)
            return 2
    if a.out:
        print(f"wrote {a.out}: {len(plan['steps'])} steps, {len(plan['blocked'])} waiting, "
              f"{len(plan['decide'])} to decide" + (f"; {a.json}" if a.json else ""))
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
