#!/usr/bin/env python3
"""Mine fix candidates, blame edges and churn from a repository's git history, read-only.

    history.py <repo> --out <out>/history.json [--since "12 months ago"] [--max-fixes 200]
    history.py <repo> --releases <sha> [<sha>...]    # tags containing each commit, as JSON

The output holds candidates, never findings: a blame edge says who last touched a line, not who
caused a defect. Author names and diff bodies are not stored. Standard library only.
"""
import argparse
import json
import re
import sys
from collections import Counter

from common import RecordError, clean, git, redact, write_json

STRICT_FIX = re.compile(r"^(fix|bugfix|hotfix)(\([^)]*\))?!?:", re.I)
LOOSE_FIX = re.compile(r"\b(fix(es|ed)?|bug|regression|hotfix)\b|修正|不具合|バグ", re.I)
REVERT = re.compile(r"^revert\b", re.I)
KIND = re.compile(r"^([a-z]+)(\([^)]*\))?!?:", re.I)
KNOWN_KINDS = {"feat": "feature", "feature": "feature", "fix": "fix", "bugfix": "fix", "hotfix": "fix", "refactor": "refactor",
               "docs": "docs", "test": "test", "tests": "test", "chore": "chore", "ci": "ci", "build": "build",
               "perf": "perf", "style": "style", "revert": "revert", "deps": "dependency"}
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|specs)(/|$)|(_test|\.test|\.spec)\.[^/]+$|(^|/)test_[^/]+$")
DOC_PATH = re.compile(r"\.(md|mdx|rst|txt|adoc)$", re.I)
GENERATED = re.compile(r"(^|/)(node_modules|vendor|dist|build|\.git)/|(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Cargo\.lock|go\.sum)$")
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+")
FIELD = "\x1f"
RECORD = "\x1e"


def kind_of(subject):
    match = KIND.match(subject)
    if match:
        return KNOWN_KINDS.get(match.group(1).lower(), "other")
    if REVERT.search(subject):
        return "revert"
    return "fix" if LOOSE_FIX.search(subject) else "other"


def module_of(path, depth):
    parts = path.split("/")[:-1]
    return "/".join(parts[:depth]) or "."


def source_files(files):
    return [f for f in files if not TEST_PATH.search(f) and not DOC_PATH.search(f) and not GENERATED.search(f)]


def read_log(repo, since, max_commits):
    fmt = RECORD + FIELD.join(("%H", "%cs", "%P", "%s"))
    args = ["log", "--no-merges", "--no-ext-diff", f"--format={fmt}", "--name-only", "-z", f"--max-count={max_commits}"]
    if since:
        args.append(f"--since={since}")
    commits = []
    for chunk in git(repo, *args, check=False).split(RECORD)[1:]:
        header, *names = chunk.split("\x00")
        sha, day, parents, subject = header.split(FIELD, 3)
        commits.append(dict(sha=sha, date=day, parents=parents.split(), subject=subject.strip(),
                            files=[n.strip("\n") for n in names if n.strip("\n")]))
    return commits


def blame_origins(repo, commit):
    """Commits that last touched the lines this fix changed or removed, per the parent revision."""
    parent = commit["parents"][0] if commit["parents"] else None
    origins, changed_lines = Counter(), 0
    if not parent:
        return origins, changed_lines
    for path in source_files(commit["files"]):
        diff = git(repo, "show", "--no-ext-diff", "--no-textconv", "--unified=0", "--format=", commit["sha"], "--", path, check=False)
        ranges = []
        for line in diff.splitlines():
            match = HUNK.match(line)
            if not match or match.group(2) == "0":
                continue
            start, count = int(match.group(1)), int(match.group(2) or 1)
            changed_lines += count
            ranges.append((start, count))
        if ranges:
            origins.update(blame_ranges(repo, parent, path, ranges))
    return origins, changed_lines


def _blame_rows(repo, parent, path, ranges):
    spans = [f"-L{start},{start + count - 1}" for start, count in ranges]
    blame = git(repo, "blame", "--no-textconv", "-w", "-s", "-l", *spans, parent, "--", path, check=False)
    return [row.split()[0] for row in blame.splitlines() if row.strip()]


def blame_ranges(repo, parent, path, ranges):
    """Last-touching commit per changed line, one blame for all of a file's hunks.

    Blame refuses the whole call when any one range is out of bounds, so a short answer
    falls back to one call per hunk and keeps every range that does resolve.
    """
    rows = _blame_rows(repo, parent, path, ranges)
    if len(ranges) > 1 and len(rows) != sum(count for _, count in ranges):
        rows = [ref for one in ranges for ref in _blame_rows(repo, parent, path, [one])]
    return Counter(rows)


FULL_HASH = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


def full_sha(repo, ref, cache, hash_len=None):
    """Blame marks a boundary commit with ^ and a shortened hash, so resolve what it printed.

    `blame -l` prints every other commit in full; one already as long as HEAD's hash is
    returned as is, since rev-parse would only echo it back.
    """
    bare = ref.lstrip("^")
    if bare not in cache:
        if hash_len and bare == ref and len(bare) == hash_len and FULL_HASH.match(bare):
            cache[bare] = bare
        else:
            cache[bare] = git(repo, "rev-parse", "--verify", "--quiet", f"{bare}^{{commit}}", check=False).strip() or bare
    return cache[bare]


def describe(repo, sha):
    """Date and subject of a commit outside the mined window, so an old origin can still be cited."""
    day, _, subject = git(repo, "show", "-s", f"--format=%cs{FIELD}%s", sha, check=False).strip().partition(FIELD)
    return dict(date=day or None, subject=subject)


DESCRIBE_BATCH = 100  # commits per git call: keeps the command line far below Windows' 32K limit


def describe_all(repo, shas):
    """describe() for many commits in a few git calls, falling back to one call each if a batch is off."""
    shas = list(dict.fromkeys(shas))
    out = {}
    for at in range(0, len(shas), DESCRIBE_BATCH):
        batch = shas[at:at + DESCRIBE_BATCH]
        text = git(repo, "log", "--no-walk=unsorted", f"--format={RECORD}%H{FIELD}%cs{FIELD}%s", *batch, "--", check=False)
        rows = [chunk.rstrip("\n").split(FIELD, 2) for chunk in text.split(RECORD)[1:]]
        if len(rows) == len(batch) and all(len(row) == 3 and row[0] == sha for row, sha in zip(rows, batch)):
            out.update((sha, dict(date=day or None, subject=subject.rstrip())) for (_, day, subject), sha in zip(rows, batch))
        else:
            out.update((sha, describe(repo, sha)) for sha in batch)
    return out


def mine(repo, since, max_fixes, depth, max_commits):
    if git(repo, "rev-parse", "--is-inside-work-tree", check=False).strip() != "true":
        raise RecordError(f"{repo} is not a git work tree")
    commits = read_log(repo, since, max_commits)
    by_sha = {c["sha"]: c for c in commits}
    kinds, churn, fixes_per_module = Counter(), Counter(), Counter()
    candidates = []
    for commit in commits:
        kinds[kind_of(commit["subject"])] += 1
        touched = {module_of(f, depth) for f in source_files(commit["files"])}
        for module in touched:
            churn[module] += 1
        strict = bool(STRICT_FIX.search(commit["subject"]))
        if strict or (LOOSE_FIX.search(commit["subject"]) and not KIND.match(commit["subject"])):
            for module in touched:
                fixes_per_module[module] += 1
            candidates.append((commit, "prefix" if strict else "word"))
    head = git(repo, "rev-parse", "HEAD", check=False).strip()
    hash_len = len(head) if FULL_HASH.match(head) else None
    records, resolved, top = [], {}, []
    for index, (commit, match) in enumerate(candidates):
        record = dict(commit=commit["sha"], date=commit["date"], subject=clean(commit["subject"]), match=match,
                      files=source_files(commit["files"])[:40], test_changed=any(TEST_PATH.search(f) for f in commit["files"]))
        if index < max_fixes:
            origins, changed = blame_origins(repo, commit)
            merged = Counter()
            for ref, lines in origins.items():
                merged[full_sha(repo, ref, resolved, hash_len)] += lines
            record["changed_lines"] = changed
            record["pure_addition"] = changed == 0
            top.append((record, merged.most_common(12)))
        else:
            record["origins_skipped"] = True
        records.append(record)
    # Origins outside the mined window, in first-cited order, described in one batch.
    extra = describe_all(repo, [sha for _, rows in top for sha, _ in rows if sha not in by_sha])
    for record, rows in top:
        record["origins"] = []
        for sha, lines in rows:
            info = by_sha.get(sha) or extra[sha]
            record["origins"].append(dict(commit=sha, lines=lines, date=info.get("date"), kind=kind_of(info.get("subject", ""))))
    tree = [f for f in git(repo, "ls-files", "-z", check=False).split("\x00") if f]
    tests = [f for f in tree if TEST_PATH.search(f)]
    modules = []
    for module in sorted(set(churn) | set(fixes_per_module)):
        leaf = module.rsplit("/", 1)[-1]
        pattern = re.compile(rf"(^|[/_.-]){re.escape(leaf)}([/_.-]|$)") if leaf != "." else None
        tested = sum(1 for t in tests if t.startswith(module + "/") or (pattern and pattern.search(t)))
        modules.append(dict(module=module, commits=churn[module], fix_candidates=fixes_per_module[module], test_files=tested))
    index_refs = {}
    for commit in commits:
        index_refs[commit["sha"]] = dict(date=commit["date"], kind=kind_of(commit["subject"]), subject=clean(commit["subject"]))
    for sha, info in extra.items():
        index_refs[sha] = dict(date=info.get("date"), kind=kind_of(info.get("subject", "")), subject=clean(info.get("subject", "")))
    tags = [line.split(FIELD) for line in git(repo, "for-each-ref", "--sort=creatordate", f"--format=%(refname:short){FIELD}%(creatordate:short)", "refs/tags", check=False).splitlines() if FIELD in line]
    merges = git(repo, "rev-list", "--count", "--merges", "HEAD", *([f"--since={since}"] if since else []), check=False).strip()
    prefixed = sum(1 for c in commits if KIND.match(c["subject"]))
    return dict(
        meta=dict(head=head, since=since, module_depth=depth,
                  blame_limit=max_fixes),
        quality=dict(shallow=git(repo, "rev-parse", "--is-shallow-repository", check=False).strip() == "true",
                     commits=len(commits), reached_max_commits=len(commits) >= max_commits, merges=int(merges or 0), prefix_share=round(prefixed / len(commits), 3) if commits else 0,
                     tags=len(tags), fix_by_prefix=sum(1 for _, m in candidates if m == "prefix"), fix_by_word=sum(1 for _, m in candidates if m == "word")),
        kinds=dict(kinds.most_common()),
        commits=index_refs,
        modules=modules,
        fix_candidates=records,
        tags=[dict(name=redact(t[0]), date=t[1]) for t in tags],
    )


def releases(repo, shas):
    out = {}
    for sha in shas:
        names = git(repo, "tag", "--contains", sha, "--sort=creatordate", check=False).split()
        out[sha] = dict(first=names[0] if names else None, last=names[-1] if names else None, basis="tag" if names else "UNKNOWN")
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("repo")
    parser.add_argument("--out", help="history.json to write; outside the reviewed repository")
    parser.add_argument("--since", default="12 months ago", help="git --since window; empty means all history")
    parser.add_argument("--max-fixes", type=int, default=200, help="blame only this many of the newest candidates")
    parser.add_argument("--max-commits", type=int, default=5000)
    parser.add_argument("--module-depth", type=int, default=2)
    parser.add_argument("--releases", nargs="+", metavar="SHA", help="print the tags containing each commit and stop")
    args = parser.parse_args(argv)
    try:
        if args.releases:
            print(json.dumps(releases(args.repo, args.releases), ensure_ascii=False, indent=2))
            return 0
        if not args.out:
            parser.error("--out is required unless --releases is given")
        data = mine(args.repo, args.since, args.max_fixes, args.module_depth, args.max_commits)
        write_json(args.out, data)
    except RecordError as error:
        print(f"history.py: {error}", file=sys.stderr)
        return 2
    q = data["quality"]
    print(f"wrote {args.out}: {q['commits']} commits, {len(data['fix_candidates'])} fix candidates "
          f"({q['fix_by_prefix']} by prefix, {q['fix_by_word']} by word), shallow={q['shallow']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
