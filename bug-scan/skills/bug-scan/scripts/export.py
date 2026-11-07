#!/usr/bin/env python3
"""Export a finished bug-scan record for the places work happens next: issue drafts, code scanning, a spreadsheet.

    export.py issues <out>/findings.json --out <dir> [--lang ja|en] [--min-severity Low]
    export.py sarif  <out>/findings.json --out <file.sarif> [--min-severity Info]
    export.py csv    <out>/findings.json --out <file.csv>

Everything is derived from findings.json (and surfaces.json beside it when present), so an export never says
more than the record. Exports are written outside the run directory, whose files the contract fixes.

- `issues`: one Markdown draft per unresolved record, plus index.md. Filing stays the requester's step; after
  filing, `ledger.py set <ledger> <key> --ref <url>` links the issue so later runs carry it.
- `sarif`: SARIF 2.1.0 for code scanning and editors. `partialFingerprints` holds the tracking key, so a defect
  keeps its identity across runs even when lines move.
- `csv`: the whole register, excluded and closed records included, one row each.

Standard library only.
"""
import argparse
import csv
import io
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (LOCATION, PATTERNS, SEVERITIES, RecordError, as_list, clean, closed, excluded, load_json,  # noqa: E402
                    pattern_name, unresolved, write_text)
from findings import reference_errors, shape_errors  # noqa: E402
from render import TEXT  # noqa: E402

SARIF_LEVEL = dict(High="error", Medium="warning", Low="note", Info="note")
LIVE_SIBLING = ("affected", "unknown")
MENTION = re.compile(r"(?<![\w`@./-])@[A-Za-z0-9][A-Za-z0-9-]*(?:/[A-Za-z0-9._-]+)?")
FORMULA_START = ("=", "+", "-", "@", "\t", "\r")
CSV_COLUMNS = ("id", "key", "title", "status", "severity", "confidence", "verdict", "risk", "likelihood", "impact", "pattern",
               "module", "location", "surfaces", "first_seen", "last_seen", "owner", "fix", "external_refs")
EXPORT_TEXT = {
    "ja": dict(index="下書き一覧", drafted="bug-scan の findings.json から下書きしました。起票は依頼者が行います。", summary="概要",
               where="場所", fix="修正方針", checklist="修正後の確認", relations="関連する記録", data="データ修復", labels="ラベル案",
               after_filing="起票後に台帳へ結びつける", none="なし", severity="重大度", risk="リスク", verdict="判定",
               sibling_todo="横展開先を確認する", guard_todo="再発防止", regression_todo="回帰テストを足す", data_todo="既存データを修復する",
               count="件", drafts="件の下書き", skipped="下書きにしなかった記録", reason_closed="修正済み", reason_excluded="誤検知・対象外",
               reason_below="重大度が基準未満", surfaces="対象", title="タイトル"),
    "en": dict(index="Issue drafts", drafted="Drafted by bug-scan from findings.json. Filing is the requester's step.", summary="Summary",
               where="Where", fix="Fix direction", checklist="After the fix", relations="Related records", data="Data remediation",
               labels="Suggested labels", after_filing="Link it to the ledger after filing", none="none", severity="Severity", risk="Risk",
               verdict="Verdict", sibling_todo="Check the sibling site", guard_todo="Guard", regression_todo="Add the regression test",
               data_todo="Repair data already written", count="", drafts="drafts", skipped="Records not drafted", reason_closed="closed",
               reason_excluded="judged false or out of scope", reason_below="below the severity threshold", surfaces="Surfaces", title="Title"),
}


def load_record(path):
    record = load_json(path)
    if not isinstance(record, dict):
        raise RecordError(f"{path}: must be a JSON object")
    errors = shape_errors(record) or reference_errors(record)
    if errors:
        raise RecordError("; ".join(errors[:8]))
    surfaces_path = Path(path).parent / "surfaces.json"
    surfaces = load_json(surfaces_path) if surfaces_path.exists() else {}
    catalog = {s["id"]: s for s in surfaces.get("surfaces", []) if isinstance(s, dict) and "id" in s}
    return record, catalog


def refuse_run_directory(record_path, target):
    """The run directory holds exactly the contract's files; an export there would fail contract_check."""
    run = Path(record_path).resolve().parent
    target = Path(target).resolve()
    if target == run or run in target.parents:
        raise RecordError(f"{target} is inside the run directory {run}; write exports elsewhere so the contract still holds")


def at_least(finding, minimum):
    severity = finding.get("severity") or "Info"
    return SEVERITIES.index(severity) <= SEVERITIES.index(minimum)


def safe(text):
    """Recorded text leaving the review: no secrets or addresses, and no @mention that would notify someone on filing."""
    return MENTION.sub(lambda m: f"`{m.group(0)}`", clean(text))


def surface_label(surface, catalog):
    item = catalog.get(surface["id"], {})
    parts = [surface["id"], item.get("name"), f"[{surface['op']}]" if surface.get("op") else None, item.get("note")]
    return " ".join(str(p) for p in parts if p)


def issue_markdown(finding, record, catalog, lang):
    t, x = TEXT[lang], EXPORT_TEXT[lang]
    risk = finding.get("risk") or {}
    severity = finding.get("severity") or "Info"
    lines = [f"# [{finding['id']}] {safe(finding['title'])}", ""]
    rows = [(x["severity"], severity), (x["risk"], t["level"].get(risk.get("level"), risk.get("level"))), (t["status"], finding["status"]),
            (x["verdict"], (finding.get("validation") or {}).get("verdict")),
            (t["pattern"], f"{finding['pattern']} {pattern_name(finding['pattern'], lang)}" if finding.get("pattern") else None),
            (t["module"], finding.get("module")), (t["key"], finding.get("key")), (t["first_seen"], finding.get("first_seen")),
            (t["owner"], finding.get("owner"))]
    lines += ["| | |", "|---|---|"] + [f"| {a} | {safe(b).replace('|', '/')} |" for a, b in rows if b] + [""]
    locations = as_list(finding.get("location"))
    if locations:
        lines += [f"## {x['where']}", ""] + [f"- `{loc}`" for loc in locations] + [""]
    if finding.get("surfaces"):
        lines += [f"## {x['surfaces']}", ""] + [f"- {safe(surface_label(s, catalog))}" for s in finding["surfaces"]] + [""]
    repro = finding.get("repro")
    if repro:
        lines += [f"## {t['g_repro']} ({t['repro_state'][repro['state']]})", ""]
        if repro.get("preconditions"):
            lines += [f"**{t['preconditions']}**", ""] + [f"- {safe(p)}" for p in repro["preconditions"]] + [""]
        for name in ("fixture", "environment"):
            if repro.get(name):
                lines += [f"**{t[name]}**: {safe(repro[name])}", ""]
        lines += [f"{n}. {safe(step)}" for n, step in enumerate(repro.get("steps", []), 1)] + [""]
        lines += [f"- **{t['expected']}**: {safe(repro.get('expected', ''))}", f"- **{t['actual']}**: {safe(repro.get('actual', t['none_recorded']))}"]
        if repro.get("last_run"):
            lines.append(f"- **{t['last_run']}**: {safe(repro['last_run'])}")
        lines.append("")
    hazard = finding.get("hazard")
    if risk or hazard:
        lines += [f"## {t['g_risk']}", ""]
        if risk:
            lines.append(f"- **{t['risk']}**: {t['level'][risk['level']]} ({t['likelihood']} {t['level'][risk['likelihood']]} × "
                         f"{t['impact']} {t['level'][risk['impact']]})")
            for name in ("detectability", "basis"):
                if risk.get(name):
                    lines.append(f"- **{t[name]}**: {safe(risk[name])}")
        if hazard:
            separator = "、" if lang == "ja" else ", "
            lines.append(f"- **{t['classes']}**: {safe(separator.join(hazard['classes']))}")
            lines.append(f"- **{t['irreversible']}** {t['yn'][hazard['irreversible']]} / **{t['silent']}** {t['yn'][hazard['silent']]}")
            for name in ("reach", "recovery"):
                if hazard.get(name):
                    lines.append(f"- **{t[name]}**: {safe(hazard[name])}")
        lines.append("")
    if finding.get("fix"):
        lines += [f"## {x['fix']}", "", safe(finding["fix"]), ""]
    checklist = []
    for site in finding.get("sibling_sites", []):
        if site["state"] in LIVE_SIBLING:
            checklist.append(f"- [ ] {x['sibling_todo']}: `{site['location']}` ({t['sib_state'][site['state']]}: {safe(site['evidence'])})")
    if finding.get("regression_test"):
        checklist.append(f"- [ ] {x['regression_todo']}: {safe(finding['regression_test'])}")
    if finding.get("guard") and finding.get("guard") != finding.get("regression_test"):
        checklist.append(f"- [ ] {x['guard_todo']}: {safe(finding['guard'])}")
    data = finding.get("data_remediation") or {}
    if data.get("needed") in ("yes", "unknown"):
        detail = "; ".join(safe(data[k]) for k in ("locate", "method") if data.get(k))
        checklist.append(f"- [ ] {x['data_todo']} ({t['needed']}: {t['yn'][data['needed']]}){': ' + detail if detail else ''}")
    if checklist:
        lines += [f"## {x['checklist']}", ""] + checklist + [""]
    relations = finding.get("relations", [])
    if relations:
        titles = {f["id"]: f["title"] for f in record.get("findings", [])}
        lines += [f"## {x['relations']}", ""]
        lines += [f"- {r['type']} → {r['to']} {safe(titles.get(r['to'], ''))} ({r['strength']}: {safe(r['evidence'])})" for r in relations]
        lines.append("")
    if finding.get("external_refs"):
        lines += [f"## {t['refs']}", ""] + [f"- {safe(ref)}" for ref in finding["external_refs"]] + [""]
    labels = ["bug-scan", f"severity:{severity}"] + ([finding["pattern"]] if finding.get("pattern") else [])
    lines += [f"**{x['labels']}**: " + ", ".join(f"`{label}`" for label in labels), ""]
    if finding.get("key"):
        lines += ["---", "", f"<sub>{x['drafted']} {x['after_filing']}: `ledger.py set <ledger.json> {finding['key']} --ref <issue-url> --reason filed`</sub>", ""]
    return "\n".join(lines)


def export_issues(record_path, out, lang=None, minimum="Low"):
    refuse_run_directory(record_path, out)
    record, catalog = load_record(record_path)
    lang = lang or record.get("meta", {}).get("lang") or "ja"
    t, x = TEXT[lang], EXPORT_TEXT[lang]
    drafted, skipped = [], []
    for finding in record.get("findings", []):
        if excluded(finding):
            skipped.append((finding, x["reason_excluded"]))
        elif closed(finding):
            skipped.append((finding, x["reason_closed"]))
        elif not at_least(finding, minimum):
            skipped.append((finding, x["reason_below"]))
        else:
            drafted.append(finding)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for finding in drafted:
        write_text(out / f"{finding['id']}.md", issue_markdown(finding, record, catalog, lang))
    meta = record.get("meta", {})
    index = [f"# {x['index']}: {safe(meta.get('project', ''))} ({meta.get('date', '')})", "", x["drafted"], ""]
    index += [f"| ID | {x['severity']} | {x['risk']} | {t['status']} | {x['title']} |", "|---|---|---|---|---|"]
    for finding in drafted:
        level = (finding.get("risk") or {}).get("level")
        index.append(f"| [{finding['id']}]({finding['id']}.md) | {finding.get('severity') or 'Info'} | {t['level'].get(level, '-')} | "
                     f"{finding['status']} | {safe(finding['title']).replace('|', '/')} |")
    if not drafted:
        index.append(f"| - | - | - | - | {x['none']} |")
    if skipped:
        index += ["", f"## {x['skipped']}", ""] + [f"- {f['id']} {safe(f['title'])}: {why}" for f, why in skipped]
    write_text(out / "index.md", "\n".join(index) + "\n")
    return drafted, skipped


def region(location):
    match = LOCATION.match(location)
    if not match:
        return None
    start = int(match.group("line"))
    area = dict(startLine=start)
    if match.group("end") and int(match.group("end")) >= start:
        area["endLine"] = int(match.group("end"))
    return dict(physicalLocation=dict(artifactLocation=dict(uri=match.group("path"), uriBaseId="%SRCROOT%"), region=area))


def to_sarif(record, catalog, minimum="Info"):
    lang = record.get("meta", {}).get("lang") or "ja"
    used, results, skipped = set(), [], []
    for finding in record.get("findings", []):
        if not unresolved(finding) or not at_least(finding, minimum):
            continue
        places = [r for r in (region(loc) for loc in as_list(finding.get("location"))) if r]
        if not places:
            skipped.append(finding["id"])
            continue
        rule = finding.get("pattern") or "Unclassified"
        used.add(rule)
        severity = finding.get("severity") or "Info"
        message = f"{finding['id']} {clean(finding['title'])}"
        if finding.get("fix"):
            message += f" / {TEXT[lang]['fix_action']}: {clean(finding['fix'])}"
        related = []
        for index, site in enumerate(s for s in finding.get("sibling_sites", []) if s["state"] in LIVE_SIBLING):
            place = region(site["location"])
            if place:
                place.update(id=index + 1, message=dict(text=f"{site['state']}: {clean(site['evidence'])}"))
                related.append(place)
        result = dict(ruleId=rule, level=SARIF_LEVEL[severity], message=dict(text=message), locations=places[:1],
                      properties=dict(bugScanId=finding["id"], severity=severity, status=finding["status"],
                                      verdict=(finding.get("validation") or {}).get("verdict"), risk=(finding.get("risk") or {}).get("level"),
                                      module=finding.get("module"), surfaces=[surface_label(s, catalog) for s in finding.get("surfaces", [])]))
        if len(places) > 1:
            offset = len(related)
            for index, place in enumerate(places[1:], 1):
                place.update(id=offset + index, message=dict(text=f"{finding['id']} {clean(finding['title'])}"))
                related.append(place)
        if related:
            result["relatedLocations"] = related
        if finding.get("key"):
            result["partialFingerprints"] = {"bugScanKey/v1": finding["key"]}
        result["properties"] = {k: v for k, v in result["properties"].items() if v not in (None, [])}
        results.append(result)
    rules = [dict(id=rule, name=re.sub(r"[^A-Za-z0-9]+", "", pattern_name(rule, "en").title()) or rule,
                  shortDescription=dict(text=pattern_name(rule, "en")), fullDescription=dict(text=f"{pattern_name(rule, 'en')} / {pattern_name(rule, 'ja')}"),
                  properties=dict(tags=["bug-scan", "defect-pattern"]))
             for rule in PATTERNS if rule in used]
    meta = record.get("meta", {})
    run = dict(tool=dict(driver=dict(name="bug-scan", rules=rules)), results=results, columnKind="unicodeCodePoints",
               properties={k: meta[k] for k in ("project", "commit", "date", "scope") if meta.get(k)})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [run]}, skipped


def cell(value):
    """A spreadsheet cell that cannot be read as a formula, so a recorded title cannot execute on open."""
    text = clean(value)
    return "'" + text if text.startswith(FORMULA_START) else text


def to_csv(record, catalog):
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for finding in record.get("findings", []):
        risk = finding.get("risk") or {}
        row = dict(id=finding["id"], key=finding.get("key"), title=finding.get("title"), status=finding.get("status"),
                   severity=finding.get("severity"), confidence=finding.get("confidence"), verdict=(finding.get("validation") or {}).get("verdict"),
                   risk=risk.get("level"), likelihood=risk.get("likelihood"), impact=risk.get("impact"), pattern=finding.get("pattern"),
                   module=finding.get("module"), location="; ".join(as_list(finding.get("location"))),
                   surfaces="; ".join(surface_label(s, catalog) for s in finding.get("surfaces", [])), first_seen=finding.get("first_seen"),
                   last_seen=finding.get("last_seen"), owner=finding.get("owner"), fix=finding.get("fix"),
                   external_refs="; ".join(finding.get("external_refs", [])))
        writer.writerow([cell(row[c]) if row[c] is not None else "" for c in CSV_COLUMNS])
    return "﻿" + buffer.getvalue()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("issues", "sarif", "csv"):
        one = sub.add_parser(name)
        one.add_argument("record", help="<out>/findings.json")
        one.add_argument("--out", required=True)
        if name != "csv":
            one.add_argument("--min-severity", choices=SEVERITIES, default="Low" if name == "issues" else "Info")
        if name == "issues":
            one.add_argument("--lang", choices=("ja", "en"))
    args = parser.parse_args(argv)
    try:
        if args.command == "issues":
            drafted, skipped = export_issues(args.record, args.out, args.lang, args.min_severity)
            print(f"wrote {len(drafted)} draft(s) and index.md to {args.out}; {len(skipped)} record(s) not drafted")
            return 0
        refuse_run_directory(args.record, args.out)
        record, catalog = load_record(args.record)
        if args.command == "sarif":
            data, skipped = to_sarif(record, catalog, args.min_severity)
            write_text(args.out, json.dumps(data, ensure_ascii=False, indent=2) + "\n")
            note = f"; {len(skipped)} without a path:line left out ({', '.join(skipped)})" if skipped else ""
            print(f"wrote {args.out}: {len(data['runs'][0]['results'])} result(s){note}")
        else:
            write_text(args.out, to_csv(record, catalog))
            print(f"wrote {args.out}: {len(record.get('findings', []))} row(s)")
    except (RecordError, OSError) as error:
        print(f"export.py: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
