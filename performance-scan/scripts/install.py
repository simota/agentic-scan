#!/usr/bin/env python3
"""Install helpers used by Makefile; keep filesystem paths as single values."""
import argparse
import os
from pathlib import Path
import sys


def targets(args):
    if args.skills_dir:
        directory = Path(args.skills_dir)
        return [(directory, directory)]
    if args.project:
        project = Path(args.project)
        return [(project, project / ".claude" / "skills")]

    roots = {
        "claude": Path(args.claude_home),
        "codex": Path(args.codex_home),
        "agy": Path(args.agy_home),
    }
    agents = args.agents.split()
    unknown = sorted(set(agents) - roots.keys())
    if unknown:
        raise ValueError(
            f"unknown AGENT '{' '.join(unknown)}' - use claude, codex or agy, or set SKILLS_DIR"
        )
    return sorted({(roots[a], roots[a] / "skills") for a in agents}, key=lambda t: str(t[0]))


def link(skill, destinations, agents):
    if not skill.is_dir():
        raise ValueError(f"refusing {skill} - skill directory does not exist")
    linked = 0
    for guard, directory in destinations:
        destination = directory / skill.name
        if not guard.is_dir():
            print(f"skip     {destination} - {guard} does not exist")
            continue
        if destination.is_symlink():
            current = os.readlink(destination)
            if current != str(skill):
                raise ValueError(
                    f"refusing {destination} is a symlink to {current} - resolve it, then re-run"
                )
            print(f"ok       {destination} already linked")
        elif destination.exists():
            raise ValueError(
                f"refusing {destination} exists and is not a symlink - move it aside first"
            )
        else:
            directory.mkdir(parents=True, exist_ok=True)
            destination.symlink_to(skill, target_is_directory=True)
            print(f"linked   {destination} -> {skill}")
        linked += 1
    if not linked:
        raise ValueError(f"nothing linked - no skills directory found for: {agents}")
    print(f"invoke it with:  {skill.name}   (or /{skill.name} in a slash-command harness)")


def unlink(skill, destinations):
    for _, directory in destinations:
        destination = directory / skill.name
        if destination.is_symlink():
            current = os.readlink(destination)
            if current == str(skill):
                destination.unlink()
                print(f"unlinked {destination}")
            else:
                print(f"left     {destination} - points at {current}, not this repo")
        elif destination.exists():
            print(f"left     {destination} - not a symlink")
        else:
            print(f"absent   {destination}")


def status(skill, destinations):
    for guard, directory in destinations:
        destination = directory / skill.name
        if not guard.is_dir():
            print(f"skip     {destination} - host not installed")
        elif destination.is_symlink():
            print(f"symlink  {destination} -> {os.readlink(destination)}")
        elif destination.is_dir():
            print(f"dir      {destination} - not a symlink")
        elif destination.exists():
            print(f"file     {destination} - not a skill directory")
        else:
            print(f"absent   {destination}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("link", "unlink", "status"))
    parser.add_argument("--skill", required=True, type=Path)
    parser.add_argument("--agents", default="claude codex agy")
    parser.add_argument("--project", default="")
    parser.add_argument("--skills-dir", default="")
    parser.add_argument("--claude-home", default=str(Path.home() / ".claude"))
    parser.add_argument("--codex-home", default=os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))
    parser.add_argument("--agy-home", default=os.environ.get("AGY_HOME", str(Path.home() / ".gemini" / "antigravity-cli")))
    args = parser.parse_args(argv)
    try:
        skill = args.skill.resolve()
        destinations = targets(args)
        if args.action == "link":
            link(skill, destinations, args.agents)
        elif args.action == "unlink":
            unlink(skill, destinations)
        else:
            status(skill, destinations)
    except (OSError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
