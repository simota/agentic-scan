#!/usr/bin/env python3
"""Fail when a document cites a repository file that does not exist.

    python3 scripts/ci/check_doc_refs.py

Checks backticked `reference/...` and `scripts/...` paths
(resolved against the skill), backticked repository paths such as
`skills/prune-scan/...`, `docs/...`, `examples/...` and `tests/...`, and
relative Markdown links, in every tracked Markdown document. A backticked
command such as `scripts/render.py --lang ja` cites the path it starts with.
"""
from pathlib import Path
import re
import sys

REPO = Path(__file__).resolve().parents[2]
# The path alone, or the first word of a command whose arguments follow it.
ARGS = r"(?:\s[^`]*)?`"
SKILL_REF = re.compile(r"`((?:reference|scripts)/[A-Za-z][A-Za-z0-9._/-]*)" + ARGS)
REPO_REF = re.compile(r"`((?:skills/prune-scan|docs|examples|tests|scripts/ci)/[A-Za-z0-9._/-]*[A-Za-z0-9_-])" + ARGS)
LINK = re.compile(r"\]\(([^)\s#]+)(?:#[^)]*)?\)")


def problems(repo=REPO):
    skill = repo / "skills" / "prune-scan"
    docs = sorted({*repo.glob("*.md"), *repo.glob("docs/*.md"), *skill.glob("*.md"),
                   *skill.glob("reference/*.md")})
    for doc in docs:
        text = doc.read_text(encoding="utf-8")
        rel = doc.relative_to(repo)
        for ref in sorted(set(SKILL_REF.findall(text))):
            # A bare scripts/ci/... path is a repository path, not a skill path.
            base = repo if ref.startswith("scripts/ci/") else skill
            if not (base / ref.rstrip("/")).exists():
                yield f"{rel} cites {ref}, which does not exist"
        for ref in sorted(set(REPO_REF.findall(text))):
            if "*" not in ref and not (repo / ref).exists():
                yield f"{rel} cites {ref}, which does not exist"
        for target in sorted(set(LINK.findall(text))):
            if re.match(r"[a-z][a-z0-9+.-]*:", target) or "{{" in target:
                continue  # External URL or a template placeholder.
            if not (doc.parent / target).exists():
                yield f"{rel} links to {target}, which does not exist"


def main():
    found = list(problems())
    for line in found:
        print("MISS " + line, file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
