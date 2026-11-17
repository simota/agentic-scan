"""Make recorded text safe to place in GitHub-flavoured Markdown.

Shared by render.py (report.md) and drafts.py, so both escape recorded text
the same way. Standard library and findings.py only: no scan_report_kit.
"""

from html import escape
from pathlib import Path
import re
import sys
import unicodedata

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True  # leave no __pycache__ beside the skill
from findings import shown  # noqa: E402

# Bidirectional controls (Unicode's Bidi_Control: U+061C, U+200E-200F,
# U+202A-202E, U+2066-2069) reorder the text after them, so a recorded value
# could display reversed or hide its own end (Trojan Source). They are shown as
# visible code points instead.
BIDI_CONTROLS = re.compile("[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def as_text(value):
    text = ", ".join(value) if isinstance(value, list) else str(value)
    # Terminal controls too: report.md is also read with cat and less.
    return shown(BIDI_CONTROLS.sub(lambda m: f"[U+{ord(m[0]):04X}]", text))


# Inside `<code>` GFM still parses inline syntax, so these are encoded; the rest
# of a path or command (`/`, `.`, `:`, `-`) stays readable in the raw file.
CODE_LITERAL = {ord(char): f"&#{ord(char)};" for char in "\\`*_~[]<&|!$\t"}


def markdown_code(value):
    """Keep a literal command or code span intact, even with backticks."""
    value = as_text(value).replace("\r\n", "\n").replace("\r", "\n")
    literal = disarm_autolinks(value.translate(CODE_LITERAL))
    # Runs of spaces and edge spaces would collapse or be trimmed.
    literal = re.sub(r"^ +| {2,}| +$", lambda m: "&#32;" * len(m[0]), literal)
    literal = literal.replace("\n", "<br>")
    return f"<code>{literal}</code>"


# Backslashes are literal (paths such as `docs\\adr`), so the punctuation after
# one loses its escape and is encoded instead; `&<>` are already entities.
AFTER_BACKSLASH = re.compile(r"(?<=\\)[!-%'-/:;=>?@^_{-~]")
# What GFM turns into a link without brackets: a scheme's colon, `www.`, and
# the `@` of an e-mail address. Encoding the last character disarms each.
# No `\b`: GFM also links a scheme or `www.` right after a word character
# (`_https://x`, `参照https://x`).
AUTOLINK = re.compile(r"(?i)(?:https?|ftp|mailto|xmpp):|www\.")


# An `@` is disarmed unless what precedes it cannot end an e-mail local part
# in any renderer: a blank, an opening bracket or quote, `,` or `:` (as in
# `@scope/pkg`, `(@Version`), or punctuation outside ASCII (`。@Transactional`,
# `（@Version`). Everything else is disarmed: letters and digits in any script
# (pandoc reads them all), a combining mark (pandoc composes it into the letter
# before), the `;` that ends an entity this renderer wrote (`a&#95;@x.com`,
# decoded back into the local part before cmark-gfm autolinks), and the rest of
# ASCII punctuation, which other autolinkers accept (`a=@x.com`).
EMAIL_AT = re.compile(r"(?<=(.))@", re.DOTALL)
NOT_LOCAL_PART = set(" \t\r\n([{'\"`,:")


def _disarm_at(match):
    before = match[1]
    if before in NOT_LOCAL_PART or before.isspace() or (
            ord(before) > 127 and unicodedata.category(before)[0] in "PSZ"):
        return "@"
    return "&#64;<!-- -->"


def disarm_autolinks(text):
    """Encode one character of each autolink trigger.

    cmark-gfm finds e-mail addresses after entities are decoded, so an `@` with
    a local part before it (`bob@example.com`) also gets an empty comment,
    which no autolinker reads through. An `@` that starts a word (`@scope/pkg`,
    `@decorator`) has no local part, cannot be an address, and stays readable.
    """
    text = AUTOLINK.sub(lambda m: m[0][:-1] + f"&#{ord(m[0][-1])};", text)
    return EMAIL_AT.sub(_disarm_at, text)
# Outside code spans these stay literal: a backslash, a stray backtick, the
# brackets of a link or image (whose target could be any scheme), a cell pipe,
# `_`, which recorded prose uses in identifiers far more than for emphasis
# (`__getattr__` would turn bold), and `~`, which GFM strikes through with even
# one on each side (`1~3 and 5~7`); `*em*` stays emphasis.
LITERAL = {ord("\\"): "&#92;", ord("`"): "&#96;", ord("["): "&#91;", ord("]"): "&#93;",
           ord("|"): "&#124;", ord("$"): "&#36;",  # `$` opens math on GitHub and in pandoc
           ord("_"): "&#95;", ord("~"): "&#126;"}


def markdown_inline(value):
    """Keep recorded text in one GFM block, keeping `*` emphasis and code spans.

    Links and images are shown as literal text, and backslashes as written, so
    no recorded text turns into a link or loses a delimiter it escaped.
    """
    value = as_text(value).replace("\r\n", "\n").replace("\r", "\n")

    def text(part):
        # `>` stays readable (`a -> b`): without `<` it opens no tag, and
        # block_safe stops it quoting a list item. A backslash before a stray
        # backtick is kept like any other: LITERAL encodes both.
        part = escape(part, quote=False).replace("&gt;", ">")
        part = AFTER_BACKSLASH.sub(lambda m: f"&#{ord(m[0])};", part)
        return disarm_autolinks(part.translate(LITERAL)).replace("\n", "<br>")

    parts, end = [], 0
    # An odd backslash prefix escapes the opening backtick; delimiter lengths match.
    spans = r"(?<![\\`])((?:\\\\)*)(`+)(?!`)(.+?)(?<!`)\2(?!`)"
    for match in re.finditer(spans, value, re.DOTALL):
        parts.append(text(value[end:match.start()] + match[1]))
        code = match[3].replace("\n", " ")
        if code.startswith(" ") and code.endswith(" ") and code.strip(" "):
            code = code[1:-1]  # CommonMark code spans trim one surrounding space.
        parts.append(markdown_code(code))
        end = match.end()
    parts.append(text(value[end:]))
    return "".join(parts)


# Leading whitespace (indented code) and the markers that open a block when
# they start a line: a heading, a list bullet (`*` or `+` before a blank), a
# rule (three of `*` or `_`), a setext line, a fence, a link definition or task
# box, an ordered item. A leading `-` is always encoded: with the item's own
# `- ` bullet, even `--` makes a rule. `*em*` at the start is inline, not a block, so it
# is left alone.
BLOCK_START = re.compile(
    r"([ \t]*)(#|=|>|\[|-|[*+_](?=[ \t]|$)|([*_])(?=(?:[ \t]*\3){2,}[ \t]*$)|~~~|```"
    r"|[0-9]{1,9}[.)])?")


def block_safe(rendered):
    """Keep recorded text from opening a Markdown block where it starts a line."""
    match = BLOCK_START.match(rendered)
    indent, marker = match[1], match[2] or ""
    if marker[:1].isdigit():
        # `12.` stops being an ordered item once its delimiter is encoded.
        marker = marker[:-1] + f"&#{ord(marker[-1])};"
    elif marker:
        marker = f"&#{ord(marker[0])};" + marker[1:]
    return "".join(f"&#{ord(char)};" for char in indent) + marker + rendered[match.end():]


def heading_text(value):
    """Inline text that cannot lose a trailing `#` to a closing sequence."""
    # The heading drops trailing blanks, which would expose the `#` again.
    rendered = markdown_inline(value).rstrip(" \t")
    return rendered[:-1] + "&#35;" if rendered.endswith("#") else rendered


def markdown_table_cell(value):
    """Keep pipes and line breaks inside a GFM cell, including in code spans."""
    return markdown_inline(value)
