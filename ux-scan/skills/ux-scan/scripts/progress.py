#!/usr/bin/env python3
"""What is left of a ux-scan review in progress (reference/progress.md).

    python3 progress.py OUT [--out FILE|-] [--format markdown|json] [--lang ja|en] [--strict]

Reads OUT/flows.json, OUT/inventory.json and OUT/findings.json as far as they exist (none is
required, and the findings may still be unordered or Unverified) and lists, per review unit in
task order (primary flows, the shared unit, secondary flows), what the run contract and *Done
when* still ask for:

  records      flows.json or inventory.json missing, or the inventory older than the flows
  candidates   inventory candidates no finding, checked_ok, limitations or decisions line decides
  units        flows with no finding and no trace in perspectives, checked_ok or limitations
  perspectives families with no perspectives entry
  findings     Unverified verdicts, missing or uncited evidence, Fixed without after evidence,
               Valid or Likely High and Medium findings without a mockup or a limitations line,
               mockups without tiers, and numbering not yet in severity order

A candidate is decided when a finding's location or occurrences covers its path:line (whatever
the verdict), or when a finding's validation or prose (observed, expected, impact, fix), or a
checked_ok, limitations, decisions or next_steps line names that path:line (a trailing part of the path is enough: app.css:12). It
writes nothing beside the record; the default output is standard output. Standard library only.
Exit status: 0 listed, 1 items remain with --strict, 2 invalid input.
"""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence  # noqa: E402
from findings import (EXCLUDED, FAMILIES, FAMILY_NAME, RecordError, canonical_digest, check_findings,  # noqa: E402
                      check_flows, flow_ids, load_json)
from record_files import code, split_location, write_derived  # noqa: E402

KINDS = ("records", "units", "candidates", "perspectives", "findings")
PRIORITY_ORDER = {"primary": 0, "shared": 1, "secondary": 2}
# A path:line or path:line-line mention in prose; the path needs an extension.
MENTION = re.compile(r"(?<![\w./@-])((?:[\w@()\[\]+.-]+/)*[\w@()\[\]+-][\w@()\[\]+.-]*\.[A-Za-z0-9]+):(\d+)(?:-(\d+))?")
ID_RANGE = re.compile(r"U-(\d{3})\s*(?:to|through|から|〜|～|~|\.\.|[-‐‑–—])\s*U-(\d{3})")
ID = re.compile(r"(?<![\w-])U-(\d{3})(?!\d)")
# The hunt steps each inventory key feeds (reference/inventory.md), so a candidate names where to look.
PERSPECTIVES = {"orphan_routes": "IA1, IA2", "off_scale.spacing": "LG2, VH2", "off_scale.font_sizes": "VH2, CC2",
                "off_scale.breakpoints": "RS1", "off_scale.z_index": "LG3", "fixed_widths": "RS2",
                "tap_targets": "RS3", "focus_outline": "ST2", "viewport_meta": "RS4", "click_handlers": "AX2",
                "images": "AX4, PP2", "inputs": "FM1, FM4", "icon_buttons": "AX4", "positive_tabindex": "AX3",
                "state_branches": "FB1, PP1, ST3", "destructive_actions": "FB4", "motion": "MO1, MO2",
                "truncation": "IN1, IN2", "physical_properties": "IN3", "locale_expansion": "IN1"}
# A row about a whole file (a component that fetches but never shows a loading state) is decided by a
# finding anywhere in that file under one of these perspective families.
FILE_FAMILIES = {"state_branches": ("FB", "PP", "ST")}
LABELS = {
    "en": {"title": "UX review progress", "done": "Nothing left: render, then run contract_check.py.",
           "left": "{n} item(s) left", "records": "Records", "units": "Review units",
           "candidates": "Undecided inventory candidates", "perspectives": "Perspectives", "findings": "Findings",
           "unit": "Unit", "findings_n": "Findings", "open": "Undecided", "next": "Next",
           "no_flow": "no flow (write flows.json first)", "confirm": "To confirm"},
    "ja": {"title": "UX診断の進捗", "done": "残りはありません。描画してから contract_check.py を実行してください。",
           "left": "残り {n} 件", "records": "記録", "units": "レビュー単位",
           "candidates": "未判定のインベントリ候補", "perspectives": "観点", "findings": "指摘",
           "unit": "単位", "findings_n": "指摘", "open": "未判定", "next": "次に",
           "no_flow": "フローなし（先に flows.json を書く）", "confirm": "要確認"},
}


def _load(path, check):
    """The checked contents of path, None when absent."""
    if not path.exists() and not path.is_symlink():
        return None
    return check(load_json(path, record=True))


def _inventory(data):
    if not isinstance(data, dict) or data.get("tool") != "inventory.py":
        raise RecordError("inventory.json: not written by inventory.py")
    return data


def candidates(inventory):
    """(category, path:line or path, what, key) for every inventory row that may be a defect."""
    out = []

    def add(category, location, what, key=None):
        if isinstance(location, str) and location:
            out.append({"category": category, "perspective": PERSPECTIVES[category], "location": location,
                        "what": what, "key": key})

    for row in inventory.get("orphan_routes", []):
        route = row.get("route")
        add("orphan_routes", row.get("location"), f"route {route} is linked from nowhere",
            route if isinstance(route, str) and len(route) > 1 else None)
    for scale, rows in (inventory.get("off_scale") or {}).items():
        for row in rows:
            for loc in row.get("locations", []):
                add(f"off_scale.{scale}", loc, f"{row.get('value')} is off the {scale} scale")
    for row in inventory.get("fixed_widths", []):
        if row.get("wider_than_smallest_viewport", True):
            for loc in row.get("locations", []):
                add("fixed_widths", loc, f"fixed width {row.get('value')}")
    for row in inventory.get("tap_targets", []):
        size = ", ".join(f"{k} {v}" for k, v in (row.get("sizes") or {}).items())
        add("tap_targets", row.get("location"), f"{row.get('selector')} {size}".strip())
    for row in inventory.get("focus_outline", []):
        if not row.get("replacement_in_rule"):
            add("focus_outline", row.get("location"), f"{row.get('selector')} removes the outline")
    for row in inventory.get("viewport_meta", []):
        if row.get("blocks_zoom"):
            add("viewport_meta", row.get("location"), "viewport blocks zoom")
    simple = {"click_handlers": lambda r: f"<{r.get('element')}> click without {', '.join(r.get('missing', []))}",
              "images": lambda r: f"<img> without {', '.join(r.get('missing', []))}",
              "inputs": lambda r: f"{r.get('element')} {r.get('name') or ''} without "
                                  f"{', '.join(r.get('missing', []))}".replace("  ", " "),
              "icon_buttons": lambda r: f"<{r.get('element')}> with no accessible name",
              "positive_tabindex": lambda r: "tabindex above 0",
              "state_branches": lambda r: f"no {', '.join(r.get('missing', []))} state",
              "destructive_actions": lambda r: f"{r.get('call')} without confirm or undo"}
    for category, what in simple.items():
        for row in inventory.get(category, []):
            add(category, row.get("location"), what(row))
    motion = inventory.get("motion") or {}
    if not motion.get("reduced_motion"):
        for loc in motion.get("locations", []):
            add("motion", loc, "motion with no reduced-motion path")
    for name in ("truncation", "physical_properties"):
        for row in inventory.get(name) or []:
            for loc in row.get("locations", []):
                add(name, loc, str(row.get("pattern") or row.get("property")))
    for bundle in inventory.get("locale_expansion", []):
        for key in bundle.get("keys", []):
            add("locale_expansion", bundle.get("file"),
                f"{bundle.get('lang')} {key.get('key')} is {key.get('ratio')}x the {bundle.get('base')} width",
                key.get("key"))
    return out


def _spans(text):
    """(path, start, end) for every path:line mention in text."""
    spans = []
    for m in MENTION.finditer(text or ""):
        path = m[1]
        # "(app.css:12)": an opening bracket the path never closes belongs to the prose.
        while path[:1] in "([" and (")" if path[0] == "(" else "]") not in path:
            path = path[1:]
        spans.append((path, int(m[2]), int(m[3] or m[2])))
    return spans


def _same_file(candidate, mention):
    return candidate == mention or candidate.endswith("/" + mention)


def _prose(data):
    """Every line that can decide a candidate or trace a unit."""
    lines = []
    for key in ("checked_ok", "limitations", "decisions", "next_steps"):
        lines += data.get(key, [])
    for f in data["findings"]:
        v = f["validation"]
        lines += [v.get("evidence", ""), v.get("intent_checked", ""),
                  *(f.get(k, "") for k in ("observed", "expected", "impact", "fix"))]
    return lines


def decided(candidate, data):
    """Whether a finding or a record line decides this candidate."""
    path, _, line = candidate["location"].rpartition(":")
    if not line.isdigit():  # A locale file: decided by a finding in it or a mention of its key.
        path, line = candidate["location"], None
    else:
        line = int(line)
    families = FILE_FAMILIES.get(candidate["category"])
    for f in data["findings"]:
        for loc in [f["location"], *f.get("occurrences", [])]:
            fpath, start, end = split_location(loc)
            if fpath == path and (line is None or start <= line <= end
                                  or (families and f["perspective"].rstrip("0123456789") in families)):
                return True
    for text in _prose(data):
        for mpath, start, end in _spans(text):
            if _same_file(path, mpath) and (line is None or start <= line <= end):
                return True
        if candidate["key"] and re.search(r"(?<![\w.])" + re.escape(candidate["key"]) + r"(?![\w])", text):
            return True
    return False


def unit_of(location, flows):
    """The flow whose screens are in the candidate's file (task order), else the shared unit."""
    path = location.rpartition(":")[0] if location.rpartition(":")[2].isdigit() else location
    ordered = sorted(flows["flows"], key=lambda fl: PRIORITY_ORDER[fl["priority"]])
    for fl in ordered:
        if any(s["location"].rpartition(":")[0] == path for s in fl["screens"]):
            return fl["id"]
    return next((fl["id"] for fl in ordered if fl["priority"] == "shared"), None)


def named_ids(lines):
    """The finding ids a set of prose lines names, ranges expanded."""
    ids = set()
    for text in lines:
        for a, b in ID_RANGE.findall(text):
            lo, hi = sorted((int(a), int(b)))
            ids.update(f"U-{n:03d}" for n in range(lo, hi + 1))
        ids.update(f"U-{n}" for n in ID.findall(text))
    return ids


def _item(kind, text, do, unit=None, ids=None, location=None, confirm=False):
    item = {"kind": kind, "text": text, "do": do, "level": "confirm" if confirm else "todo"}
    if unit:
        item["unit"] = unit
    if ids:
        item["ids"] = ids
    if location:
        item["location"] = location
    return item


def progress(out):
    out = Path(out)
    if not out.is_dir():
        raise RecordError(f"{out}: not a directory")
    flows = _load(out / "flows.json", check_flows)
    ids = flow_ids(flows) if flows else None
    inventory = _load(out / "inventory.json", _inventory)
    data = _load(out / "findings.json", lambda d: check_findings(d, ids, ordered=False))
    record = data or {"findings": []}
    items = []
    inv_cmd = (f"inventory.py <repo> --flows {out / 'flows.json'} --out {out / 'inventory.json'}")
    if flows is None:
        items.append(_item("records", "flows.json is missing",
                           "write the flows (reference/flows.md), then findings.py flows"))
    if inventory is None:
        items.append(_item("records", "inventory.json is missing", f"run {inv_cmd}"))
    elif flows is not None and inventory.get("flows_sha256") != canonical_digest(flows):
        items.append(_item("records", "inventory.json predates the current flows", f"rerun {inv_cmd}"))
    if data is None:
        items.append(_item("records", "findings.json is missing: no finding merged yet",
                           "merge fragments with findings.py merge (reference/findings-schema.md)"))

    units = []
    if flows is not None:
        traced = " ".join([*record.get("checked_ok", []), *record.get("limitations", []),
                           *(f"{p['name']} {p.get('result', '')} {p.get('note', '')}"
                             for p in record.get("perspectives", []))])
        for fl in sorted(flows["flows"], key=lambda fl: PRIORITY_ORDER[fl["priority"]]):
            n = sum(f["flow_ref"] == fl["id"] for f in record["findings"])
            units.append({"id": fl["id"], "name": fl["name"], "priority": fl["priority"], "findings": n,
                          "undecided": 0})
            if not n and not re.search(r"(?<![\w-])" + re.escape(fl["id"]) + r"(?![\w-])", traced):
                items.append(_item("units", f"{fl['id']} {fl['name']} ({fl['priority']}) has no finding and no trace",
                                   "review it, then record what held up in checked_ok or a perspectives note, "
                                   "or name it in limitations", unit=fl["id"]))
    by_unit = {u["id"]: u for u in units}
    if inventory is not None:
        for c in candidates(inventory):
            if decided(c, record):
                continue
            unit = unit_of(c["location"], flows) if flows else None
            if unit in by_unit:
                by_unit[unit]["undecided"] += 1
            items.append(_item("candidates", f"{c['category']} ({c['perspective']}): {c['what']}",
                               "read it in context: merge a finding, or a checked_ok, limitations or decisions "
                               "line naming its path:line", unit=unit, location=c["location"]))

    recorded = {FAMILY_NAME.match(p["name"].strip())[1] for p in record.get("perspectives", [])
                if FAMILY_NAME.match(p["name"].strip()) and p.get("result", "").strip()}
    missing = [f for f in FAMILIES if f not in recorded]
    if missing:
        items.append(_item("perspectives", f"no entry for {', '.join(missing)}",
                           "record each family as applied, N/A with the reason, or not checked"))

    findings = record["findings"]
    included = [f for f in findings if f["validation"]["verdict"] not in EXCLUDED]

    def ids_of(pred, pool=findings):
        return [f["id"] for f in pool if pred(f)]

    def add(text, do, found):
        if found:
            items.append(_item("findings", f"{text}: {', '.join(found)}", do, ids=found))

    add("still Unverified", "settle the verdict in VERIFY (reference/validation.md)",
        ids_of(lambda f: f["validation"]["verdict"] == "Unverified"))
    add("no evidence of the defect (stage before)", "capture it into evidence/ and cite it (reference/evidence.md)",
        ids_of(lambda f: not any(evidence.stage(i) == "before" for i in evidence.items(f)), included))
    add("Fixed without evidence of the fix (stage after)", "capture the fixed view as stage after",
        ids_of(lambda f: f["status"] == "Fixed" and not any(evidence.stage(i) == "after"
                                                            for i in evidence.items(f))))
    directory = out / evidence.DIRECTORY
    on_disk = {p.name for p in directory.iterdir()} if directory.is_dir() else set()
    cited = {i["file"] for f in findings for i in evidence.items(f)}
    absent = sorted(cited - on_disk)
    if absent:
        items.append(_item("findings", f"cited evidence not in {evidence.DIRECTORY}/: {', '.join(absent)}",
                           "capture the files or correct the citations"))
    uncited = sorted(on_disk - cited)
    if uncited:
        items.append(_item("findings", f"{evidence.DIRECTORY}/ files no finding cites: {', '.join(uncited)}",
                           "cite them or remove them"))
    limited = named_ids(record.get("limitations", []))
    found = ids_of(lambda f: f["validation"]["verdict"] in ("Valid", "Likely") and f["severity"] in ("High", "Medium")
                   and not f.get("mockup") and f["id"] not in limited)
    if found:  # Only a finding a user can see needs one, and that is a judgement: confirm, not a to-do.
        items.append(_item("findings", f"Valid or Likely High/Medium without a mockup: {', '.join(found)}",
                           "if a user can see it, draw one (reference/mockups.md) or name it in limitations",
                           ids=found, confirm=True))

    def untiered(f):
        mocks = f.get("mockup")
        mocks = mocks if isinstance(mocks, list) else [mocks] if mocks else []
        return any(not m.get("tier") and not m.get("note") for m in mocks) and f["id"] not in limited
    add("mockups without the three tiers (松竹梅)", "add the tiers, or say why not in the mockup note or limitations",
        ids_of(untiered, included))
    if data is not None:
        try:
            check_findings(data, ids)
        except RecordError as e:
            items.append(_item("findings", f"numbering: {e}", f"run findings.py renumber {out / 'findings.json'}"))

    todo = [i for i in items if i["level"] == "todo"]
    return {"out": str(out), "done": not todo, "units": units,
            "counts": {k: sum(i["kind"] == k for i in todo) for k in KINDS},
            "confirm": sum(i["level"] == "confirm" for i in items), "items": items}


def _next(result):
    """The one step to take next, in phase order."""
    first = {i["kind"]: i for i in reversed(result["items"]) if i["level"] == "todo"}
    for kind in KINDS:
        if kind in first:
            return first[kind]["do"]
    return None


def _text(text):
    """Prose safe for a Markdown renderer that passes raw HTML through."""
    return " ".join(str(text).split()).replace("&", "&amp;").replace("<", "&lt;")


def markdown(result, lang):
    L = LABELS[lang]
    todo = [i for i in result["items"] if i["level"] == "todo"]
    confirm = [i for i in result["items"] if i["level"] == "confirm"]
    lines = [f"# {L['title']}", "", code(result["out"]), ""]
    lines.append(L["done"] if result["done"] else
                 f"**{L['left'].format(n=len(todo))}** — {L['next']}: {_text(_next(result))}")
    if result["units"]:
        lines += ["", f"| {L['unit']} | {L['findings_n']} | {L['open']} |", "|---|---:|---:|"]
        for u in result["units"]:
            name = _text(u["name"]).replace("|", "\\|")
            lines.append(f"| {u['id']} {name} ({u['priority']}) | {u['findings']} | {u['undecided']} |")
    for kind in KINDS:
        group = [i for i in todo if i["kind"] == kind]
        if not group:
            continue
        lines += ["", f"## {L[kind]} ({len(group)})", ""]
        if kind == "candidates":
            for unit in dict.fromkeys(i.get("unit") for i in group):
                lines.append(f"- **{unit or L['no_flow']}**")
                lines += [f"  - [ ] {code(i['location'])} {_text(i['text'])}" for i in group if i.get("unit") == unit]
            lines += ["", f"→ {_text(group[0]['do'])}"]
            continue
        lines += [f"- [ ] {_text(i['text'])} → {_text(i['do'])}" for i in group]
    if confirm:
        lines += ["", f"## {L['confirm']} ({len(confirm)})", ""]
        lines += [f"- [ ] {_text(i['text'])} → {_text(i['do'])}" for i in confirm]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("out_dir", metavar="OUT")
    parser.add_argument("--out", default="-", help="output file, or - for stdout (the default)")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--lang", choices=("ja", "en"), default="en", help="markdown labels")
    parser.add_argument("--strict", action="store_true", help="exit 1 while items remain")
    args = parser.parse_args(argv)
    try:
        result = progress(args.out_dir)
        text = (json.dumps(result, ensure_ascii=False, indent=2) + "\n" if args.format == "json"
                else markdown(result, args.lang))
        inputs = [Path(args.out_dir) / name for name in ("findings.json", "flows.json", "inventory.json")]
        target = write_derived(args.out, text, inputs)
    except (RecordError, OSError, ValueError, RecursionError) as e:
        print(f"progress.py: {e}", file=sys.stderr)
        return 2
    if target is not None:
        left = sum(i["level"] == "todo" for i in result["items"])
        print(f"wrote {target} ({left} items left, {result['confirm']} to confirm)")
    return 1 if args.strict and not result["done"] else 0


if __name__ == "__main__":
    from file_io import tolerant_console
    tolerant_console()
    sys.exit(main())
