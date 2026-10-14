"""Shared, conservative checks for optional source text in review outputs."""

import re

SECRET_NAME = re.compile(r"(?:secret(?:[_-]?(?:access[_-]?)?key)?|token|passw(?:or)?d|"
                         r"api[_-]?key|private[_-]?key|client[_-]?(?:secret|key)|key[_-]data)", re.I)
PRIVATE_KEY = re.compile(r"(?i)-----BEGIN (?:[A-Z0-9]+ )*(?:PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----")


def physical_lines(text):
    """Lines numbered as editors and grep -n count them: split on newlines only.

    str.splitlines also breaks on form feeds, NEL and U+2028, which would shift
    every later line away from the path:line a finding cites.
    """
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    return [line[:-1] if line.endswith("\r") else line for line in lines]


def sensitive_source(text):
    """Suppress optional excerpts from sources with secret names or key blocks.

    Values may continue across lines, operators and comments in different
    languages. Inspect the whole bounded source instead of guessing where a
    sensitive expression ends; candidate names and locations remain useful.
    """
    return bool(PRIVATE_KEY.search(text) or SECRET_NAME.search(text))
