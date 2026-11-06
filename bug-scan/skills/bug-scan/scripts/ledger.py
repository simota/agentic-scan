#!/usr/bin/env python3
"""Track defects across runs in a ledger kept outside the reviewed repository.

    ledger.py reconcile <ledger.json> <out>/findings.json --repo <repo> --fragment <scratch>/ledger-fragment.json
    ledger.py set <ledger.json> <key> [--status Accepted] [--owner TEAM] --reason TEXT

Run reconcile after the run's own findings are final: the ledger is read only then, so an earlier
verdict cannot steer this one. A record that stops being found becomes NotSeen, never Fixed.
The fragment carries first_seen and reopened statuses back into findings.json. Standard library only.
"""
import argparse
import datetime
import sys
from pathlib import Path

from common import RecordError, as_list, load_json, location_path, write_json

HUMAN_STATUSES = ("Accepted",)
CLOSED = ("Fixed", "Verified")


def is_excluded(finding):
    return finding.get("validation", {}).get("verdict") in ("FalsePositive", "NotApplicable")


def read_ledger(path):
    if not Path(path).exists():
        return dict(version=1, entries=[])
    data = load_json(path)
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        raise RecordError(f"{path}: not a ledger")
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
        if is_excluded(finding):
            continue
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
    two.add_argument("--status", choices=HUMAN_STATUSES)
    two.add_argument("--owner", help="a team or role, never a person's name from commit history")
    two.add_argument("--reason", required=True)
    args = parser.parse_args(argv)
    try:
        ledger = read_ledger(args.ledger)
        if args.command == "reconcile":
            if inside(args.ledger, args.repo):
                raise RecordError("the ledger must live outside the reviewed repository")
            record = load_json(args.findings)
            today = record.get("meta", {}).get("date")
            if not today:
                raise RecordError("findings.json has no meta.date")
            fragment, changes = reconcile(ledger, record, today)
            write_json(args.fragment, fragment)
            write_json(args.ledger, ledger)
            print({k: len(v) for k, v in changes.items()})
        else:
            match = [e for e in ledger["entries"] if e["key"] == args.key]
            if not match:
                raise RecordError(f"{args.key} is not in the ledger")
            today = datetime.date.today().isoformat()
            if args.status:
                match[0]["status"] = args.status
                match[0]["status_log"].append(dict(date=today, status=args.status, reason=args.reason))
            if args.owner:
                match[0]["owner"] = args.owner
            write_json(args.ledger, ledger)
    except RecordError as error:
        print(f"ledger.py: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
