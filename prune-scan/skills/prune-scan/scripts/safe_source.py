"""Shared, conservative checks for optional source text in review outputs."""

import re

SECRET_NAME = re.compile(r"(?:secret(?:[_-]?(?:access[_-]?)?key)?|token|passw(?:or)?d|"
                         r"api[_-]?key|private[_-]?key|client[_-]?secret)", re.I)
PRIVATE_KEY = re.compile(r"(?i)-----BEGIN (?:[A-Z0-9]+ )*(?:PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----")


def sensitive_source(text):
    """Suppress optional excerpts from sources with secret names or key blocks.

    Values may continue across lines, operators and comments in different
    languages. Inspect the whole bounded source instead of guessing where a
    sensitive expression ends; candidate names and locations remain useful.
    """
    return bool(PRIVATE_KEY.search(text) or SECRET_NAME.search(text))
