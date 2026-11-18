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

    homes = {"claude": args.claude_home, "codex": args.codex_home, "agy": args.agy_home}
    agents = args.agents.split()
    if not agents:
        raise ValueError("AGENT is empty - use claude, codex or agy, or set SKILLS_DIR")
    unknown = sorted(set(agents) - homes.keys())
    if unknown:
        raise ValueError(
            f"unknown AGENT '{' '.join(unknown)}' - use claude, codex or agy, or set SKILLS_DIR"
        )
    # Path("") is ".", which always exists: an empty home would link into the
    # current directory.
    empty = sorted(a for a in agents if not homes[a])
    if empty:
        raise ValueError(f"the home directory for '{' '.join(empty)}' is empty"
                         " - set CLAUDE_HOME, CODEX_HOME or AGY_HOME, or set SKILLS_DIR")
    roots = {a: Path(homes[a]) for a in agents}
    return sorted({(roots[a], roots[a] / "skills") for a in agents}, key=lambda t: str(t[0]))


def points_at(destination, skill):
    """True when a symlink reaches this skill, even through another path alias."""
    try:
        return destination.resolve() == skill
    except (OSError, RuntimeError):
        return False


def made_by_link(destination, skill):
    """True for a link that link() (or an older Makefile) could have created.

    That is a symlink whose own target is this skill, written absolute, relative
    or through a checkout alias. A chain whose target is another symlink (e.g. a
    dotfiles link) is someone else's and is left alone.
    """
    target = destination.parent / os.readlink(destination)
    return target.is_dir() and not target.is_symlink() and points_at(destination, skill)


def link(skill, destinations, agents):
    if not skill.is_dir():
        raise ValueError(f"refusing {skill} - skill directory does not exist")
    # Check every destination before creating any link, so a conflict on one
    # host does not leave the others half-installed.
    plan = []
    for guard, directory in destinations:
        destination = directory / skill.name
        if not guard.is_dir():
            print(f"skip     {destination} - {guard} does not exist")
            continue
        try:
            resolved = directory.resolve()
        except RuntimeError as exc:
            raise ValueError(f"refusing {directory} - {exc}") from exc
        # Python 3.13+ returns a looping link instead of raising; a file cannot hold links.
        if resolved.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise ValueError(f"refusing {directory} - not a usable directory")
        if resolved / skill.name == skill:
            raise ValueError(f"refusing {destination} - the skill itself already lives there")
        if resolved == skill or skill in resolved.parents:
            raise ValueError(f"refusing {directory} - it is inside the skill itself")
        # mkdir runs after earlier hosts are linked, so find a blocked path now:
        # a dangling symlink or a file where a missing directory would go.
        ancestor = directory
        while not ancestor.exists():
            if ancestor.is_symlink():
                raise ValueError(f"refusing {directory} - {ancestor} is a dangling symlink")
            ancestor = ancestor.parent
        if not ancestor.is_dir():
            raise ValueError(f"refusing {directory} - {ancestor} is not a directory")
        if destination.is_symlink():
            if not points_at(destination, skill):
                raise ValueError(
                    f"refusing {destination} is a symlink to {os.readlink(destination)}"
                    " - resolve it, then re-run"
                )
        elif destination.exists():
            raise ValueError(
                f"refusing {destination} exists and is not a symlink - move it aside first"
            )
        plan.append((directory, destination))
    for directory, destination in plan:
        if destination.is_symlink():
            print(f"ok       {destination} already linked")
        else:
            directory.mkdir(parents=True, exist_ok=True)
            destination.symlink_to(skill, target_is_directory=True)
            print(f"linked   {destination} -> {skill}")
    linked = len(plan)
    if not linked:
        raise ValueError(f"nothing linked - no skills directory found for: {agents}")
    print(f"invoke it with:  {skill.name}   (or /{skill.name} in a slash-command harness)")


def unlink(skill, destinations):
    for _, directory in destinations:
        destination = directory / skill.name
        if destination.is_symlink():
            if made_by_link(destination, skill):
                destination.unlink()
                print(f"unlinked {destination}")
            elif points_at(destination, skill):
                print(f"left     {destination} - reaches this skill through another symlink"
                      f" ({os.readlink(destination)}); remove it where it was made")
            else:
                print(f"left     {destination} - points at {os.readlink(destination)}, not this repo")
        elif destination.exists():
            print(f"left     {destination} - not a symlink")
        else:
            print(f"absent   {destination}")


def status(skill, destinations):
    for guard, directory in destinations:
        destination = directory / skill.name
        if not guard.is_dir():
            print(f"skip     {destination} - {guard} does not exist")
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
            # Name what was searched: AGENT is unused with SKILLS_DIR or PROJECT.
            searched = args.skills_dir or args.project or args.agents
            link(skill, destinations, searched)
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
