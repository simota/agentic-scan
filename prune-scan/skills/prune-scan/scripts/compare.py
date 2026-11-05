#!/usr/bin/env python3
"""Compare a follow-up prune-scan review with an earlier one (reference/follow-up.md).

    python3 compare.py EARLIER LATER [--repo REPO] [--json OUT] [--fragment OUT] [--lang en|ja]

EARLIER and LATER are review output directories (or a record in each); what
both hold is compared: findings.json, inventory.json or both.
Findings are matched across the two records by what they name, not by id,
because renumber assigns ids afresh in every review: first by perspective and
element, then by perspective and location file, then by element alone; only
one-to-one matches count. Each earlier open finding is resolved (the later
record marks it Fixed), accepted, ruled out (the later review found it
FalsePositive or NotApplicable), persisting (with its severity, confidence,
verdict and action changes) or missing (the later review did not find it);
later findings with no earlier match are new; earlier closed findings open
again are reopened. With inventory.json in both directories, inventory
candidates are compared too: appeared rows are the next wave of orphans.

--repo checks whether each missing finding's files still exist. --fragment
writes a findings.py merge fragment that carries every missing finding into the
later record as Fixed, with fresh ids after the later record's last id and
units, entry points and purpose items mapped onto the later units.json; confirm
each one is really gone before merging it. Nothing is written inside --repo.
Standard library only.
Exit status: 0 compared, 2 invalid input or unwritable output (reasons on stderr).
"""

import argparse
import json
import os
import re
import sys
from contextlib import ExitStack
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import (EXCLUDED, PURPOSE_FAMILIES, RecordError, SEVERITIES, check_findings, check_units,  # noqa: E402
                      dump, load_json, merge, record_exists, renumber)
from safe_output import SAFE_OUTPUT, tolerant_stdout, write_output_at  # noqa: E402
from safe_paths import descriptor_within, open_directory, within  # noqa: E402
from scan_report_kit.output import write_output  # noqa: E402

TRACKED = ("severity", "confidence", "verdict", "action", "status")
EXAMPLES = 5

# Inventory sections compared, with the fields that identify a candidate. A
# location's line moves with every edit above it, so only its file counts.
INVENTORY_KEYS = {
    "unreferenced_symbols": ("name", "kind", "@location"),
    "orphan_files": ("path",),
    "unimported_dependencies": ("manifest", "name"),
    "duplicate_purpose": ("manifest", "group"),
    "platform_replaceable": ("manifest", "name"),
    "env_declared_not_read": ("name",),
    "env_read_not_declared": ("name",),
    "feature_flags": ("name",),
    "i18n_unreferenced": ("bundle", "key"),
    "assets_unreferenced": ("path",),
    "css_unreferenced": ("class", "@location"),
    "unreferenced_routes": ("method", "route", "@location"),
    "uninvoked_scripts": ("source", "name"),
    "unreferenced_files": ("path",),
    "skipped_tests": ("@location", "text"),
    "commented_code": ("@location", "lines"),
    "markers": ("@location", "marker", "text"),
    "sql_tables_unreferenced": ("table",),
    "sql_columns_unreferenced": ("table", "column"),
}

NOTES = {
    "en": {
        "gone": "{path} no longer exists in the repository.",
        "present": "{path} still exists; the follow-up review did not find the element in it.",
        "unchecked": "The repository was not checked.",
        "carried": "Follow-up review {date}: not found again; carried from the {earlier} review{commit}. {where}",
    },
    "ja": {
        "gone": "{path}はリポジトリに存在しない。",
        "present": "{path}は残っているが、再レビューではその中に要素が見つからなかった。",
        "unchecked": "リポジトリは確認していない。",
        "carried": "{date}の再レビューで再検出されず、{earlier}のレビュー{commit}から引き継いだ。{where}",
    },
}


def norm(text):
    return " ".join(str(text).split()).casefold()


def location_path(location):
    return location.rpartition(":")[0] if re.search(r":[1-9][0-9]*(?:-[1-9][0-9]*)?\Z", location) else location


def counted(finding):
    return finding["validation"]["verdict"] not in EXCLUDED


def tracked(finding):
    return {"severity": finding["severity"], "confidence": finding["confidence"],
            "verdict": finding["validation"]["verdict"], "action": finding["subtraction"]["action"],
            "status": finding["status"]}


def match_findings(earlier, later):
    """Earlier id -> (later id, basis), one-to-one, decided in three passes of falling strictness."""
    passes = (
        ("perspective and element", lambda f: (f["perspective"], norm(f["element"]))),
        ("perspective and location file", lambda f: (f["perspective"], location_path(f["location"]))),
        ("element", lambda f: norm(f["element"])),
    )
    matched, used = {}, set()
    for basis, key in passes:
        left, right = {}, {}
        for f in earlier:
            if f["id"] not in matched:
                left.setdefault(key(f), []).append(f["id"])
        for f in later:
            if f["id"] not in used:
                right.setdefault(key(f), []).append(f["id"])
        for k, ids in left.items():
            if len(ids) == 1 and len(right.get(k, ())) == 1:
                matched[ids[0]] = (right[k][0], basis)
                used.add(right[k][0])
    return matched


def summary_row(finding, **extra):
    return {"id": finding["id"], "severity": finding["severity"], "perspective": finding["perspective"],
            "element": finding["element"], "location": finding["location"], **extra}


def exists_in(repo, relative):
    """Whether a repository-relative path names an entry, without following a final symlink."""
    try:
        os.lstat(os.path.join(repo, relative))
        return True
    except (OSError, ValueError):
        return False


def compare_findings(earlier, later, repo=None):
    old, new = earlier["findings"], later["findings"]
    by_new = {f["id"]: f for f in new}
    matched = match_findings(old, new)
    out = {"resolved": [], "accepted": [], "ruled_out": [], "persisting": [], "missing": [], "reopened": [],
           "new": []}
    for f in old:
        hit = matched.get(f["id"])
        g = by_new.get(hit[0]) if hit else None
        if f["status"] == "Open" and counted(f):
            if g is None:
                row = summary_row(f, action=f["subtraction"]["action"])
                if repo is not None:
                    paths = list(dict.fromkeys(location_path(x) for x in [f["location"], *f.get("occurrences", [])]))
                    row["paths_gone"] = [p for p in paths if not exists_in(repo, p)]
                    row["paths_present"] = [p for p in paths if p not in row["paths_gone"]]
                out["missing"].append(row)
                continue
            row = summary_row(f, later_id=g["id"], matched_by=hit[1])
            if not counted(g):
                out["ruled_out"].append({**row, "later_verdict": g["validation"]["verdict"]})
            elif g["status"] == "Fixed":
                out["resolved"].append(row)
            elif g["status"] == "Accepted":
                out["accepted"].append(row)
            else:
                before, after = tracked(f), tracked(g)
                changes = {k: [before[k], after[k]] for k in TRACKED if before[k] != after[k]}
                out["persisting"].append({**row, "changes": changes})
        elif g is not None and f["status"] != "Open" and g["status"] == "Open" and counted(g):
            out["reopened"].append(summary_row(g, earlier_id=f["id"], earlier_status=f["status"],
                                               matched_by=hit[1]))
    seen = {hit[0] for hit in matched.values()}
    out["new"] = [summary_row(g) for g in new if g["id"] not in seen and counted(g) and g["status"] == "Open"]
    return out, matched


def open_by_severity(record):
    counts = dict.fromkeys(SEVERITIES, 0)
    for f in record["findings"]:
        if f["status"] == "Open" and counted(f):
            counts[f["severity"]] += 1
    return counts


def inventory_key(section, row):
    fields = INVENTORY_KEYS[section]
    key = []
    for field in fields:
        if field == "@location":
            value = row.get("location", row.get("path", ""))
            key.append(location_path(value) if isinstance(value, str) else json.dumps(value, sort_keys=True))
        else:
            value = row.get(field, "")
            key.append(value if isinstance(value, str) else json.dumps(value, sort_keys=True))
    return tuple(key)


def compare_inventory(earlier, later):
    sections = {}
    for section in INVENTORY_KEYS:
        old, new = earlier.get(section), later.get(section)
        if not isinstance(old, list) or not isinstance(new, list):
            continue
        old_keys = {inventory_key(section, r) for r in old if isinstance(r, dict)}
        new_keys = {inventory_key(section, r) for r in new if isinstance(r, dict)}
        appeared = [r for r in new if isinstance(r, dict) and inventory_key(section, r) not in old_keys]
        gone = [r for r in old if isinstance(r, dict) and inventory_key(section, r) not in new_keys]
        sections[section] = {"earlier": len(old), "later": len(new), "appeared": appeared, "gone": gone}
    truncated = sorted(set(earlier.get("truncated") or {}) | set(later.get("truncated") or {}))
    return {"sections": sections, "truncated": truncated}


def load_inventory(path):
    data = load_json(path)
    if not isinstance(data, dict) or data.get("tool") != "inventory.py":
        raise RecordError(f"{path}: not an inventory.py output")
    return data


def map_units(finding, old_units, new_units):
    """Rewrite unit_ref, entry_ref and purpose_ref onto the later units.json, or say why not."""
    if new_units is None:
        return finding, None
    f = dict(finding)
    old_unit = {u["id"]: u for u in (old_units or {}).get("units", [])}
    new_unit = {u["id"]: u for u in new_units["units"]}

    def same_or_named(ref, olds, news, name):
        if ref in news and (ref not in olds or norm(olds[ref][name]) == norm(news[ref][name])):
            return ref
        if ref in olds:
            hits = [k for k, v in news.items() if norm(v[name]) == norm(olds[ref][name])]
            if len(hits) == 1:
                return hits[0]
        return None

    unit = same_or_named(f["unit_ref"], old_unit, new_unit, "name")
    if unit is None:  # The most specific path prefix owns a file (reference/units.md).
        path = location_path(f["location"])
        owners = [(len(p), u["id"]) for u in new_units["units"] for p in u.get("paths", [])
                  if path == p.rstrip("/") or path.startswith(p if p.endswith("/") else p + "/")]
        unit = max(owners)[1] if owners else None
    if unit is None:
        return None, f"no unit in the later units.json matches {f['unit_ref']} or covers {f['location']}"
    f["unit_ref"] = unit
    if f.get("entry_ref"):
        olds = {e["id"]: e for e in (old_units or {}).get("entry_points", [])}
        news = {e["id"]: e for e in new_units["entry_points"]}
        f["entry_ref"] = (same_or_named(f["entry_ref"], olds, news, "name")
                          or same_or_named(f["entry_ref"], olds, news, "location") or "")
    if f.get("purpose_ref"):
        olds = {p["id"]: p for p in (old_units or {}).get("purpose", [])}
        news = {p["id"]: p for p in new_units["purpose"]}
        ref = same_or_named(f["purpose_ref"], olds, news, "text")
        needed = f["perspective"][:2] in PURPOSE_FAMILIES or f["confidence"] == "Purpose-dependent"
        if ref is None and needed:
            return None, f"no purpose item in the later units.json matches {f['purpose_ref']}"
        if ref is None:
            del f["purpose_ref"]
        else:
            f["purpose_ref"] = ref
    return f, None


def carry_fragment(earlier, later, missing, matched, old_units, new_units, lang):
    """A merge fragment that records each missing earlier finding as Fixed in the later record."""
    used = [int(f["id"][2:]) for f in later["findings"]]
    next_id = max(used, default=0) + 1
    by_old = {f["id"]: f for f in earlier["findings"]}
    notes = NOTES[lang]
    meta, later_meta = earlier.get("meta", {}), later.get("meta", {})
    commit = f" (commit {meta['commit'][:12]})" if meta.get("commit") else ""
    carried, skipped = [], []
    for row in missing:
        if by_old[row["id"]]["validation"]["verdict"] == "Unlikely":
            skipped.append({"id": row["id"], "reason": "Unlikely in the earlier review (evidence of use, kept); "
                                                       "record a removal only after confirming it"})
            continue
        f, reason = map_units(by_old[row["id"]], old_units, new_units)
        if f is None:
            skipped.append({"id": row["id"], "reason": reason})
            continue
        if next_id > 999:
            skipped.append({"id": row["id"], "reason": "no free id: at most 999 findings fit one record"})
            continue
        if "paths_gone" not in row:
            where = notes["unchecked"]
        elif location_path(f["location"]) in row["paths_gone"]:
            where = notes["gone"].format(path=location_path(f["location"]))
        else:
            where = notes["present"].format(path=location_path(f["location"]))
        validation = dict(f["validation"])
        note = notes["carried"].format(date=later_meta.get("date", ""), earlier=meta.get("date", ""),
                                       commit=commit, where=where)
        validation["evidence"] = f"{validation.get('evidence', '').rstrip()} {note}".strip()
        candidate = {**f, "id": f"P-{next_id:03d}", "status": "Fixed", "validation": validation}
        try:  # One finding the later baseline cannot hold must not block the others.
            check_findings({"schema_version": 1, "meta": later_meta, "findings": [candidate]}, new_units,
                           ordered=False)
        except RecordError as e:
            skipped.append({"id": row["id"], "reason": str(e)})
            continue
        carried.append({**f, "status": "Fixed", "validation": validation, "_earlier": row["id"],
                        "_new": f"P-{next_id:03d}"})
        next_id += 1
    # Earlier prose names earlier ids: point them at the same findings in the later record.
    mapping = {old: hit[0] for old, hit in matched.items()}
    mapping.update({f["_earlier"]: f["_new"] for f in carried})
    pseudo = {"meta": {}, "findings": [{k: v for k, v in f.items() if k not in ("_earlier", "_new")} for f in carried]}
    rewritten = renumber(pseudo, mapping)["findings"] if carried else []
    return {"findings": rewritten}, [(f["_earlier"], f["_new"]) for f in carried], skipped


def review_directory(path):
    """The output directory a command-line argument names: itself, or the directory of a record in it."""
    target = Path(path)
    if target.is_dir():
        return target
    if target.name in ("findings.json", "inventory.json") and target.is_file():
        return target.parent
    raise RecordError(f"{path}: expected a review output directory, its findings.json or its inventory.json")


def checked_record(directory):
    """(findings, units) checked from a review directory, or (None, None) when it holds no findings.json."""
    target = directory / "findings.json"
    if not record_exists(target):
        return None, None
    units = (check_units(load_json(directory / "units.json"))
             if record_exists(directory / "units.json") else None)
    return check_findings(load_json(target), units, ordered=False), units


def text_report(result):
    lines = []
    if "findings" in result:
        findings_lines(result, lines)
    inventory_lines(result, lines)
    carry = result.get("carried")
    if carry is not None:
        lines.append(f"fragment: {len(carry['ids'])} carried as Fixed"
                     + (" (" + ", ".join(f"{a}->{b}" for a, b in carry["ids"]) + ")" if carry["ids"] else ""))
        for s in carry["skipped"]:
            lines.append(f"  not carried {s['id']}: {s['reason']}")
    return "\n".join(lines)


def findings_lines(result, lines):
    f = result["findings"]
    lines += [
        "prune-scan follow-up: {e} -> {l} open; resolved {r}, accepted {a}, ruled out {x}, missing {m}, "
        "persisting {p}, new {n}, reopened {o}".format(
            e=sum(result["open_by_severity"]["earlier"].values()), l=sum(result["open_by_severity"]["later"].values()),
            r=len(f["resolved"]), a=len(f["accepted"]), x=len(f["ruled_out"]), m=len(f["missing"]),
            p=len(f["persisting"]), n=len(f["new"]), o=len(f["reopened"])),
        "open by severity: " + ", ".join(
            f"{s} {result['open_by_severity']['earlier'][s]}->{result['open_by_severity']['later'][s]}"
            for s in SEVERITIES),
    ]

    def section(title, rows, describe):
        if rows:
            lines.append(f"{title}:")
            lines.extend(f"  {describe(r)}" for r in rows)

    def gone(r):
        if "paths_gone" not in r:
            return ""
        return "  [gone: " + ", ".join(r["paths_gone"]) + "]" if r["paths_gone"] else "  [still present: confirm]"

    section("missing (not found again; confirm each, then carry as Fixed)", f["missing"],
            lambda r: f"{r['id']} {r['severity']} {r['location']}  {r['element']}{gone(r)}")
    section("persisting with changes", [r for r in f["persisting"] if r["changes"]],
            lambda r: f"{r['id']} -> {r['later_id']} {r['element']}: "
                      + ", ".join(f"{k} {a}->{b}" for k, (a, b) in r["changes"].items()))
    section("ruled out by the later review", f["ruled_out"],
            lambda r: f"{r['id']} -> {r['later_id']} {r['later_verdict']}  {r['element']}")
    section("new", f["new"], lambda r: f"{r['id']} {r['severity']} {r['location']}  {r['element']}")
    section("reopened", f["reopened"],
            lambda r: f"{r['earlier_id']} ({r['earlier_status']}) -> {r['id']} {r['element']}")


def inventory_lines(result, lines):
    inventory = result.get("inventory")
    if inventory:
        moved = [(k, v) for k, v in inventory["sections"].items() if v["appeared"] or v["gone"]]
        lines.append("inventory: " + (", ".join(f"{k} +{len(v['appeared'])}/-{len(v['gone'])}" for k, v in moved)
                                      or "no candidate appeared or disappeared"))
        for k, v in moved:
            for row in v["appeared"][:EXAMPLES]:
                label = row.get("location") or row.get("path") or row.get("name") or ""
                name = row.get("name") or row.get("key") or row.get("class") or row.get("route") or ""
                lines.append(f"  new candidate {k}: {label} {name}".rstrip())
            if len(v["appeared"]) > EXAMPLES:
                lines.append(f"  ... {len(v['appeared']) - EXAMPLES} more in {k}")
        if inventory["truncated"]:
            lines.append("  truncated sections (counts are partial): " + ", ".join(inventory["truncated"]))


def main(argv=None):
    tolerant_stdout()
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("earlier", help="output directory of the earlier review (or its findings.json or inventory.json)")
    p.add_argument("later", help="output directory of the follow-up review (or its findings.json or inventory.json)")
    p.add_argument("--repo", help="reviewed repository: check whether missing findings' files still exist (read only)")
    p.add_argument("--json", help="write the full comparison as JSON to this file (outside --repo)")
    p.add_argument("--fragment", help="write a findings.py merge fragment carrying missing findings as Fixed "
                                      "(outside --repo)")
    p.add_argument("--lang", choices=("en", "ja"), default="en",
                   help="language of the notes the fragment adds to validation.evidence (default: en)")
    a = p.parse_args(argv)
    if a.repo is not None and not Path(a.repo).is_dir():
        print(f"compare.py: {a.repo} is not a directory", file=sys.stderr)
        return 2
    try:
        old_dir, new_dir = review_directory(a.earlier), review_directory(a.later)
        if os.path.samefile(old_dir, new_dir):
            raise RecordError("the earlier and the later review are the same directory")
        earlier, old_units = checked_record(old_dir)
        later, new_units = checked_record(new_dir)
        names = [n for n in ("findings.json", "inventory.json")
                 if record_exists(old_dir / n) and record_exists(new_dir / n)]
        if not names:
            raise RecordError("nothing to compare: both directories need findings.json, or both inventory.json")
        if a.fragment and "findings.json" not in names:
            raise RecordError("--fragment needs findings.json in both directories")
        inputs = [d / n for d in (old_dir, new_dir) for n in (*names, "units.json")]
        result = {"tool": "compare.py", "version": 1}
        if "findings.json" in names:
            result["earlier"] = {"date": earlier["meta"]["date"], "commit": earlier["meta"].get("commit", "")}
            result["later"] = {"date": later["meta"]["date"], "commit": later["meta"].get("commit", "")}
            result["open_by_severity"] = {"earlier": open_by_severity(earlier), "later": open_by_severity(later)}
            result["findings"], matched = compare_findings(earlier, later, a.repo)
        if "inventory.json" in names:
            result["inventory"] = compare_inventory(load_inventory(old_dir / "inventory.json"),
                                                    load_inventory(new_dir / "inventory.json"))
        fragment = None
        if a.fragment:
            fragment, ids, skipped = carry_fragment(earlier, later, result["findings"]["missing"], matched,
                                                    old_units, new_units, a.lang)
            # Merge into a copy only: the fragment must apply cleanly to the later record as it stands.
            check_findings(merge(later, fragment), new_units, ordered=False)
            result["carried"] = {"ids": ids, "skipped": skipped}
    except (RecordError, OSError) as e:
        print(f"compare.py: {e}", file=sys.stderr)
        return 2
    protected = []
    for path in inputs:
        try:
            protected.append(os.stat(path))
        except OSError:
            pass
    targets = [(t, payload) for t, payload in ((a.json, result), (a.fragment, fragment)) if t]
    if len(targets) == 2 and Path(a.json).absolute() == Path(a.fragment).absolute():
        print("compare.py: --json and --fragment name the same file", file=sys.stderr)
        return 2
    for target, _ in targets:  # Refuse every unsafe target before writing any.
        if a.repo is not None and within(Path(target).parent, a.repo):
            print(f"compare.py: {target} must be outside the reviewed repository", file=sys.stderr)
            return 2
    for target, payload in targets:
        output = Path(target)
        try:
            text = dump(payload)
            with ExitStack() as resources:
                if SAFE_OUTPUT:
                    selected = output.parent.stat()
                    directory = open_directory(output.parent.resolve(strict=True), readable=False,
                                               expected_stat=selected)
                    resources.callback(os.close, directory)
                    if a.repo is not None and descriptor_within(directory, a.repo):
                        raise OSError("output must be outside the reviewed repository")
                    write_output_at(directory, output.name, text, protected=tuple(protected))
                else:
                    if any(os.path.samestat(os.stat(output), s) for s in protected if output.exists()):
                        raise OSError("output would overwrite an input")
                    write_output(output, text)
        except (OSError, ValueError, RecordError) as e:
            print(f"compare.py: cannot write {target}: {e}", file=sys.stderr)
            return 2
    print(text_report(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
