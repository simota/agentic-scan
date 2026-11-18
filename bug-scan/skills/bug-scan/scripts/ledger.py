#!/usr/bin/env python3
"""Track defects across runs in a ledger kept outside the reviewed repository.

    ledger.py reconcile <ledger.json> <out>/findings.json --repo <repo> --fragment <scratch>/ledger-fragment.json
    ledger.py set <ledger.json> <key> [--status Accepted|Open] [--owner TEAM] [--ref URL] --reason TEXT
    ledger.py list <ledger.json> [--status NotSeen] [--format markdown|json]

Run reconcile after the run's own findings are final: the ledger is read only then, so an earlier
verdict cannot steer this one. A record that stops being found becomes NotSeen, never Fixed.
The fragment carries first_seen, reopened statuses, the owner and external references back into
findings.json. `set --status Open` withdraws an acceptance, so the next run's own status counts again.
`set --ref` links a filed issue or PR to the entry. Standard library only.
"""
import argparse
import datetime
import json
import sys
from pathlib import Path

from common import (CLOSED, SECRET, STATUSES, RecordError, as_list, excluded, load_json, location_path,
                    personal_email, write_json)

HUMAN_STATUSES = ("Accepted",)
SETTABLE = ("Accepted", "Open")
LEDGER_STATUSES = (*STATUSES, "NotSeen")
ENTRY_KEYS = ("key", "title", "status", "status_log", "first_seen", "last_seen")


def read_ledger(path):
    if not Path(path).exists():
        return dict(version=1, entries=[])
    data = load_json(path)
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        raise RecordError(f"{path}: not a ledger")
    for index, entry in enumerate(data["entries"]):
        missing = [k for k in ENTRY_KEYS if not isinstance(entry, dict) or k not in entry]
        if missing:
            raise RecordError(f"{path}: entries[{index}] needs {', '.join(missing)}")
    return data


def place_of(finding):
    locations = as_list(finding.get("location"))
    return location_path(locations[0]) if locations else None


def reconcile(ledger, record, today):
    """Update ledger entries and return (fragment, change lines)."""
    entries = {e["key"]: e for e in ledger["entries"]}
    fragment_findings, decisions, changes = [], [], dict(new=[], continuing=[], reopened=[], not_seen=[], fixed=[])
    seen = set()
    for finding in record.get("findings", []):
        if excluded(finding):
            continue
        if "key" not in finding:
            raise RecordError(f"{finding.get('id')}: has no tracking key; merge it with a pattern first")
        key = finding["key"]
        seen.add(key)
        status = finding["status"]
        entry = entries.get(key)
        if entry is None:
            near = [e for e in entries.values() if e["key"] not in seen and e.get("pattern") == finding.get("pattern")
                    and e.get("place") and e.get("place") == place_of(finding)]
            for candidate in near:
                decisions.append(f"{finding['id']} may be the same defect as ledger entry {candidate['key']} "
                                 f"({candidate['title']}): the surfaces differ, so they were not linked automatically")
            entry = dict(key=key, title=finding["title"], pattern=finding.get("pattern"), place=place_of(finding),
                         first_seen=finding.get("first_seen") or today, last_seen=today, status=status,
                         status_log=[dict(date=today, status=status, reason="first recorded")])
            entries[key] = entry
            changes["new"].append(key)
        else:
            previous = entry["status"]
            entry.update(title=finding["title"], last_seen=today, place=place_of(finding))
            if previous in CLOSED and status not in CLOSED:
                status = "Reopened"
                changes["reopened"].append(key)
                entry["status"] = status
                entry["status_log"].append(dict(date=today, status=status, reason=f"found again after {previous}"))
            elif previous in HUMAN_STATUSES and status not in CLOSED:
                status = previous
            elif previous != status:
                if status in CLOSED:
                    changes["fixed"].append(key)
                entry["status"] = status
                entry["status_log"].append(dict(date=today, status=status, reason=f"was {previous}"))
                changes["continuing"].append(key)
            else:
                changes["continuing"].append(key)
        update = dict(id=finding["id"], first_seen=entry["first_seen"], last_seen=entry["last_seen"],
                      status=status, status_log=entry["status_log"])
        if entry.get("owner"):
            update["owner"] = entry["owner"]
        if entry.get("external_refs"):
            refs = list(finding.get("external_refs") or [])
            update["external_refs"] = refs + [r for r in entry["external_refs"] if r not in refs]
        fragment_findings.append(update)
    for key, entry in entries.items():
        if key in seen or entry["status"] in CLOSED or entry["status"] in HUMAN_STATUSES:
            continue
        if entry["status"] != "NotSeen":
            entry["status_log"].append(dict(date=today, status="NotSeen", reason="not found in this run; not proof of a fix"))
            entry["status"] = "NotSeen"
        changes["not_seen"].append(key)
        decisions.append(f"Not found in this run, which does not prove a fix (the scope may differ): ledger entry {key}, {entry['title']}")
    ledger["entries"] = [entries[k] for k in sorted(entries)]
    fragment = dict(findings=fragment_findings)
    if decisions:
        fragment["decisions"] = decisions
    return fragment, changes


def set_entry(entry, today, reason, status=None, owner=None, ref=None):
    """A person's decision on one entry. Every change is logged with its reason."""
    for name, value in (("reason", reason), ("owner", owner), ("ref", ref)):
        if value and (SECRET.search(value) or personal_email(value)):
            raise RecordError(f"--{name} holds a personal e-mail address or something shaped like a secret")
    if status:
        if status == "Open" and entry["status"] not in HUMAN_STATUSES:
            raise RecordError(f"{entry['key']} is {entry['status']}; --status Open only withdraws an acceptance")
        entry["status"] = status
        entry["status_log"].append(dict(date=today, status=status, reason=reason))
    if owner:
        entry["owner"] = owner
    if ref:
        refs = entry.setdefault("external_refs", [])
        if ref not in refs:
            refs.append(ref)
            if not status:
                entry["status_log"].append(dict(date=today, status=entry["status"], reason=f"linked {ref}: {reason}"))


def listing(ledger, status=None):
    rows = [e for e in ledger["entries"] if status is None or e["status"] == status]
    order = {name: index for index, name in enumerate(("Reopened", "Open", "Triaged", "Unverified", "NotSeen", "Accepted", "Fixed", "Verified"))}
    return sorted(rows, key=lambda e: (order.get(e["status"], 99), e["last_seen"], e["key"]))


def listing_markdown(rows):
    lines = ["| key | status | first seen | last seen | owner | refs | title |", "|---|---|---|---|---|---|---|"]
    for e in rows:
        refs = " ".join(e.get("external_refs", [])) or "-"
        lines.append(f"| {e['key']} | {e['status']} | {e['first_seen']} | {e['last_seen']} | {e.get('owner') or '-'} | {refs} | "
                     f"{str(e['title']).replace('|', '/')} |")
    counts = {}
    for e in rows:
        counts[e["status"]] = counts.get(e["status"], 0) + 1
    lines += ["", ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())) or "no entries"]
    if counts.get("NotSeen"):
        lines.append("NotSeen means not found by a later run, which does not prove a fix.")
    return "\n".join(lines) + "\n"


def inside(path, repo):
    try:
        Path(path).resolve().relative_to(Path(repo).resolve())
        return True
    except ValueError:
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("reconcile")
    one.add_argument("ledger")
    one.add_argument("findings")
    one.add_argument("--repo", required=True, help="the reviewed repository; the ledger may not live inside it")
    one.add_argument("--fragment", required=True, help="where to write the fragment to merge into findings.json")
    two = sub.add_parser("set")
    two.add_argument("ledger")
    two.add_argument("key")
    two.add_argument("--status", choices=SETTABLE, help="Accepted, or Open to withdraw an acceptance")
    two.add_argument("--owner", help="a team or role, never a person's name from commit history")
    two.add_argument("--ref", help="a filed issue, PR or incident URL to link to the entry")
    two.add_argument("--reason", required=True)
    three = sub.add_parser("list")
    three.add_argument("ledger")
    three.add_argument("--status", choices=LEDGER_STATUSES)
    three.add_argument("--format", choices=("markdown", "json"), default="markdown")
    args = parser.parse_args(argv)
    try:
        ledger = read_ledger(args.ledger)
        if args.command == "reconcile":
            if inside(args.ledger, args.repo):
                raise RecordError("the ledger must live outside the reviewed repository")
            record = load_json(args.findings)
            if not isinstance(record, dict):
                raise RecordError(f"{args.findings}: must be a JSON object")
            today = record.get("meta", {}).get("date")
            if not today:
                raise RecordError("findings.json has no meta.date")
            fragment, changes = reconcile(ledger, record, today)
            write_json(args.fragment, fragment)
            write_json(args.ledger, ledger)
            print({k: len(v) for k, v in changes.items()})
        elif args.command == "list":
            if not Path(args.ledger).exists():
                raise RecordError(f"{args.ledger} does not exist")
            rows = listing(ledger, args.status)
            print(json.dumps(rows, ensure_ascii=False, indent=2) if args.format == "json" else listing_markdown(rows), end="")
            if args.format == "json":
                print()
        else:
            if not (args.status or args.owner or args.ref):
                raise RecordError("set needs --status, --owner or --ref")
            match = [e for e in ledger["entries"] if e["key"] == args.key]
            if not match:
                raise RecordError(f"{args.key} is not in the ledger")
            set_entry(match[0], datetime.date.today().isoformat(), args.reason, args.status, args.owner, args.ref)
            write_json(args.ledger, ledger)
    except RecordError as error:
        print(f"ledger.py: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
