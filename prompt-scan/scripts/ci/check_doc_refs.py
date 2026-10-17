#!/usr/bin/env python3
"""Fail when a document cites a repository file that does not exist.

    python3 scripts/ci/check_doc_refs.py

Checks backticked `reference/...`, `scripts/...` and `templates/...` paths
(resolved against the skill), including a script or document named inside a
backticked command, backticked repository paths such as `skills/prompt-scan/...`,
`docs/...`, `examples/...` and `tests/...`, and relative Markdown links, in every
Markdown document the repository tracks.
"""
from pathlib import Path
import re
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
SKILL = REPO / "skills" / "prompt-scan"
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "build", "dist", ".tox", "site-packages"}


def documents():
    """The repository's own Markdown: Git's tracked files, else a walk that skips environments and builds."""
    try:
        listed = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z", "--", "*.md"],
                                capture_output=True, check=True, timeout=20).stdout
        return sorted(REPO / name for name in listed.decode("utf-8").split("\0") if name)
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return sorted(p for p in REPO.rglob("*.md") if not SKIP_DIRS & set(p.relative_to(REPO).parts))


DOCS = documents()
SKILL_REF = re.compile(r"`((?:reference|scripts|templates)/[A-Za-z][A-Za-z0-9._/-]*)`")
CODE_SPAN = re.compile(r"`([^`\n]+)`")
# A skill file named as one word of a command, e.g. `scripts/findings.py renumber <out>/findings.json`.
COMMAND_REF = re.compile(r"(?<![\w./<>-])((?:reference|scripts|templates)/[A-Za-z][A-Za-z0-9._/-]*\.(?:py|md))(?=\s)")
REPO_REF = re.compile(r"`((?:skills/prompt-scan|docs|examples|tests|scripts/ci)/[A-Za-z0-9._/-]*[A-Za-z0-9_/-])`")
LINK = re.compile(r"\]\(([^)\s#]+)(?:#[^)\s]*)?(?:\s+\"[^\"]*\")?\)")


def problems():
    for doc in DOCS:
        text = doc.read_text(encoding="utf-8")
        rel = doc.relative_to(REPO)
        commands = {ref for span in CODE_SPAN.findall(text) for ref in COMMAND_REF.findall(span)}
        for ref in sorted(set(SKILL_REF.findall(text)) | commands):
            # A bare scripts/ci/... path is a repository path, not a skill path.
            base = REPO if ref.startswith("scripts/ci/") else SKILL
            if not (base / ref.rstrip("/")).exists():
                yield f"{rel} cites {ref}, which does not exist"
        for ref in sorted(set(REPO_REF.findall(text))):
            if not (REPO / ref).exists():
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
