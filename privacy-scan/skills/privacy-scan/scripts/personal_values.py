"""The personal-value guard: text that must never be saved in a record.

Findings describe where personal data goes, never the data itself. `find`
returns why a text is shaped like a personal value (an e-mail address or a
long personal number), or None; `find_in_url` does the same for a reference
URL. findings.py turns a reason into a SchemaError naming the field. This
module only reads its input and depends on the standard library alone.

The rules, in full:

Report prose, including analysis results, commitments, perspective notes and the
top-level text lists, is checked for e-mail addresses (other than
`example.com`, `example.org`, `example.net` or the `.example`, `.test`,
`.invalid` domains; prose may run straight on after one, as in
`user@example.comに`) and runs of 12 or more digits. The guard recognises quoted
and Unicode e-mail forms, including complete internationalised domain labels
and bracketed address literals (IPv4 and IPv6). Bracketed literal domains are
not exempted as reserved example domains. The guard also recognises repeated
spaces, tabs, non-breaking spaces, hyphens, Unicode dashes, the minus sign or
the katakana prolonged sound mark (`ー`) between digits, and card-style groups
(4-4-4-4 or 4-6-5) joined by `.`, `/`, `_` or `+`. ISO dates (`2026-10-09`) and
UUIDs are not counted as digit runs, so date ranges and identifiers stay
allowed. In a `location` path only, a path segment that starts with a compact
date-time (`20261009123045_create_users.py`, as timestamped migrations are
named; also after Flyway's `V`) is not counted either. Line numbers in `location` have at most nine digits and ledger IDs at
most six (`C-01`…`C-999999`); longer values are refused rather than exempted.
Mail-header comments and folding whitespace around the local part, `@` and
domain are also inspected without changing the saved text.
Line breaks keep unrelated numbers separate. Only a temporary copy is normalised
for inspection; accepted text retains its original spelling. Name fields and
use placeholders.

All checked prose is also inspected after percent-decoding and HTML-entity
decoding (`%40`, `&#64;`), repeated up to three times so double-encoded values
are caught, and with invisible characters removed: format characters
(zero-width spaces, word joiners, soft hyphens) and the other default-ignorable
code points (variation selectors, the combining grapheme joiner, Hangul
fillers). Hex digests and dashless UUIDs (whole tokens of
32 or more hex digits containing a letter) are not counted as digit runs.

Reference URLs are checked both as supplied and after percent-decoding their
parsed components. Query names and values also receive form decoding (`+`
means a space). A URL that cannot be parsed is checked after decoding the whole
string. These checks use temporary copies; accepted URLs retain their original
spelling.
"""
import bisect
from html import unescape
import re
import unicodedata
from urllib.parse import parse_qsl, unquote, unquote_plus, urlsplit

EMAIL = "contains an e-mail address; name the field, not the value"
LONG_NUMBER_VALUE = "contains a long number shaped like personal data; use a placeholder"

# Values that look like real personal data. Field names and placeholders such
# as `<email>` or `user@example.com` are fine; the value itself never is.
EMAIL_MARKERS = re.compile(r'["@]')
EMAIL_LOCAL_CHAR = re.compile(r'[^\s"(),:;<>@\[\]\\]')
EMAIL_LITERAL_DOMAIN = re.compile(r"\[(?:[^\[\]\r\n]|(?:\r\n|\n)[ \t])+\]")
EMAIL_FWS = re.compile(r"[ \t]+|(?:\r\n|\n)[ \t]+")
EMAIL_COMMENT_MARKERS = re.compile(r"[()\\\r\n]")
# Ideographic and full/half-width full stops, read as '.' in domains.
IDNA_DOT_CHARS = "\u3002\uff0e\uff61"
# Default-ignorable code points (Unicode DerivedCoreProperties) display as
# nothing, like format characters, but are combining marks, fillers or
# unassigned: the grapheme joiner, Khmer inherent vowels, Mongolian and other
# variation selectors, Hangul fillers and reserved ranges.
INVISIBLE = re.compile("[\u034f\u115f\u1160\u17b4\u17b5\u180b-\u180f\u2065\u3164\ufe00-\ufe0f"
                       "\uffa0\ufff0-\ufff8\U000e0000-\U000e0fff]")
# IDNA exceptions and join controls (RFC 5892, sections 2.6 and 2.8) can
# occur in labels too. Candidate detection need not validate their context.
IDNA_LABEL_EXTRAS = frozenset("\u00b7\u0375\u05f3\u05f4\u06fd\u06fe\u0f0b\u200c\u200d\u30fb")
EXAMPLE_DOMAINS = re.compile(r"(?:^|\.)example\.(?:com|org|net)$|\.(?:example|test|invalid)$",
                             re.IGNORECASE)
# An ASCII label that runs straight on into other letters, as Japanese prose
# does after an address ("user@example.comに送る").
ASCII_RUN_ON_LABEL = re.compile(r"([A-Za-z0-9-]*[A-Za-z])[^\x00-\x7f]")
# Line boundaries (a regex class body). They separate unrelated numbers in
# prose, so render.py shows every one of them as a line break.
LINE_BREAKS = r"\r\n\v\f\x1c-\x1e\x85\u2028\u2029"
# Horizontal Unicode whitespace and hyphens, including Unicode dashes, the minus
# sign and the katakana prolonged sound mark, may separate the digits; line
# boundaries still separate unrelated numbers in prose.
LONG_NUMBER = re.compile(
    rf"\d(?:(?:[^\S{LINE_BREAKS}]|[-\u2010-\u2015\u2212\u30fc])*\d){{11}}")
# Card-style groups joined by one repeated '.', '/', '_' or '+' (4-4-4-2..4 or
# 4-6-5). Groups of at most three digits, as in IP addresses, never match.
# Three groups (4-4-4) are not refused: date-partitioned paths and port lists
# (`logs/2026/1016/0930.log`, `8080/8443/9443`) share that shape.
GROUPED_NUMBER = re.compile(r"(?<!\d)\d{4}([./_+])\d{4}\1\d{4}\1\d{2,4}(?!\d)"
                            r"|(?<!\d)\d{4}([./_+])\d{6}\2\d{5}(?!\d)")
# ISO dates, UUIDs and hex digests (a whole token of 32 or more hex digits with
# at least one letter: SHA-1/256 values, dashless UUIDs) are technical values;
# they are masked before counting digits so they are not mistaken for personal
# numbers. Dates are judged per run of digits joined by the separators
# LONG_NUMBER accepts, outside UUIDs and hex digests: a run is masked only when
# it consists entirely of ISO dates (a range) and six-digit times of day after a
# date; any other digit in the run keeps the whole run counted, so masking
# cannot split a longer number.
# A UUID or hex digest is masked, but where a free-standing number sits next to
# it across those separators, its digits on that edge are kept so they still
# count; digits attached to a letter belong to a word (`sha256`), and a masked
# date or another UUID or digest beside it is not a free-standing number.
# The hour of a clock time after a date (`2024-03-15 10:22`) and the seconds
# before a date that follows (`10:22:33 - 2024-03-15`) belong to the date-time.
SEPARATOR_CLASS = rf"(?:[^\S{LINE_BREAKS}]|[-\u2010-\u2015\u2212\u30fc])"
DIGIT_SEPARATOR = re.compile(SEPARATOR_CLASS)
DIGIT_RUN = re.compile(rf"\d(?:{SEPARATOR_CLASS}*\d)*")
DATE_TOKEN = re.compile(r"(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])(?!\d)")
TIME_TOKEN = re.compile(r"(?:[01]\d|2[0-3])[0-5]\d[0-5]\d(?!\d)")
# Unicode-aware boundaries: a token never starts or ends inside a digit run.
UUID = re.compile(r"(?<![\dA-Fa-f])[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}(?![\dA-Fa-f])")
HEX_DIGEST = re.compile(r"(?<![\dA-Za-z])(?=[0-9]*[A-Fa-f])[0-9A-Fa-f]{32,128}(?![\dA-Za-z])")
EDGE_DIGITS_START = re.compile(rf"\d(?:{SEPARATOR_CLASS}*\d)*")
EDGE_DIGITS_END = re.compile(rf"\d(?:{SEPARATOR_CLASS}*\d)*\Z")
CLOCK_EDGE = re.compile(r"\d{1,2}")


def _past_separators(value, pos, step):
    """Index after skipping digit separators from pos (backwards when step < 0)."""
    if step < 0:
        while pos > 0 and DIGIT_SEPARATOR.fullmatch(value[pos - 1]):
            pos -= 1
    else:
        while pos < len(value) and DIGIT_SEPARATOR.fullmatch(value[pos]):
            pos += 1
    return pos


def _only_dates_and_times(run, after_colon=False, before_colon=False):
    """True when a digit run is nothing but dates, each optionally followed by a time.

    With `after_colon`, the run may open with the 1-2 digits that end a clock
    time; with `before_colon`, it may close with the 1-2 digit hour of one.
    """
    pos, after_date = 0, False
    if after_colon:
        opening = CLOCK_EDGE.match(run)
        if opening and opening.end() < len(run) and DIGIT_SEPARATOR.fullmatch(run[opening.end()]):
            pos = _past_separators(run, opening.end(), 1)
    while pos < len(run):
        if before_colon and after_date and CLOCK_EDGE.fullmatch(run, pos):
            return True
        token = DATE_TOKEN.match(run, pos) or (after_date and TIME_TOKEN.match(run, pos))
        if not token:
            return False
        after_date = token.re is DATE_TOKEN
        pos = _past_separators(run, token.end(), 1)
    return True


def _mask_technical_numbers(value):
    spans = []
    tokens = sorted((m for pattern in (UUID, HEX_DIGEST) for m in pattern.finditer(value)),
                    key=lambda m: m.start())
    # Digit runs are judged with the tokens blanked out, so a UUID's digits never
    # join the date or number beside it. Tokens never touch a digit directly.
    outside = list(value)
    for m in tokens:
        outside[m.start():m.end()] = "\0" * (m.end() - m.start())
    outside = "".join(outside)
    runs = list(DIGIT_RUN.finditer(outside))
    run_starts = [m.start() for m in runs]
    dates = set()

    def free_digit_at(pos, outward):
        """Whether the digit at pos belongs to a free-standing number.

        Digits of a masked date run or of another token are technical too.
        Digits attached to a letter on the outward side belong to a word
        (`sha256`, `utf8`). Runs are found once and looked up by bisection, so
        chains stay linear.
        """
        index = bisect.bisect_right(run_starts, pos) - 1
        run = runs[index] if index >= 0 else None
        if run is None or run.end() <= pos or index in dates:
            return False
        if outward < 0:
            return not (run.start() > 0 and value[run.start() - 1].isalpha())
        return not (run.end() < len(value) and value[run.end()].isalpha())

    for index, m in enumerate(runs):
        after_colon = m.start() > 0 and value[m.start() - 1] == ":"
        before_colon = value[m.end():m.end() + 1] == ":"
        if _only_dates_and_times(m.group(), after_colon, before_colon) and DATE_TOKEN.search(m.group()):
            spans.append((m.start(), m.end(), "#"))
            dates.add(index)
    for m in tokens:
        token = m.group()
        left = _past_separators(value, m.start(), -1)
        right = _past_separators(value, m.end(), 1)
        lead = EDGE_DIGITS_START.match(token)
        tail = EDGE_DIGITS_END.search(token)
        keep_left = (lead.group() if lead and left > 0 and value[left - 1].isdecimal()
                     and free_digit_at(left - 1, -1) else "")
        keep_right = (tail.group() if tail and right < len(value) and value[right].isdecimal()
                      and free_digit_at(right, 1) else "")
        spans.append((m.start(), m.end(), keep_left + "#" + keep_right))
    masked, pos = [], 0
    for start, end, replacement in sorted(spans):
        if start >= pos:
            masked.append(value[pos:start] + replacement)
            pos = end
    return "".join(masked) + value[pos:]


# Compact date-times (YYYYMMDDhhmmss) that begin a path segment, as in
# timestamped migration files. Only `location` paths are exempted this way;
# in prose such a number could be an account identifier.
PATH_TIMESTAMP = re.compile(r"(?:^|(?<=[/\\]))[Vv]?(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])"
                            r"(?:[01]\d|2[0-3])[0-5]\d[0-5]\d(?=[_.-])")
# A semantic version with a prerelease or build suffix (`1.2.3-beta.1`, `2.0.0+build`).
PACKAGE_VERSION = re.compile(
    r"\d+\.\d+\.\d+[-+](?:alpha|beta|rc|canary|next|pre|preview|dev|snapshot|nightly|build"
    # One character per repetition: `(?:[.-]?[0-9A-Za-z]+)*` accepts the same
    # strings, but splits a long alphanumeric run in exponentially many ways
    # before a failed fullmatch (a domain that runs on into Japanese prose).
    r"|experimental|insiders)(?:[.-]?[0-9A-Za-z])*", re.IGNORECASE)
# Percent and entity decoding passes over prose (covers double encoding).
DECODE_ROUNDS = 3


def _email_fold(value, pos):
    """A header line continues only when the next line begins with space/tab."""
    if value[pos:pos + 2] == "\r\n":
        pos += 1
    return value[pos:pos + 1] == "\n" and value[pos + 1:pos + 2] in (" ", "\t")


def _email_cfws(value):
    """Index complete comments and folding whitespace in linear passes.

    Only email-candidate boundaries use these jumps. Comments stay in the
    original text, so mailboxes inside them are still inspected, and unrelated
    prose and digit runs are never joined. The stack handles nested comments
    without recursion; cached boundary jumps avoid rescanning comment chains.
    """
    spans = {m.start(): m.end() for m in EMAIL_FWS.finditer(value)}
    stack = []
    escaped_until = 0
    for marker in EMAIL_COMMENT_MARKERS.finditer(value):
        pos = marker.start()
        if pos < escaped_until:
            continue
        char = value[pos]
        if char == "(":
            stack.append(pos)
        elif char == ")":
            if stack:
                spans[stack.pop()] = pos + 1
        elif char == "\\":
            if stack:
                if value[pos + 1:pos + 2] in ("\r", "\n"):
                    stack.clear()
                else:
                    escaped_until = pos + 2
        elif not _email_fold(value, pos):
            # An ordinary line boundary cannot extend a comment or address.
            stack.clear()
    starts = {end: start for start, end in spans.items()}
    before, after = {}, {}
    # Visit only the span boundaries, in the order a scan of every position
    # would reach them (forwards for `before`, backwards for `after`).
    for pos in sorted(starts):
        start = starts[pos]
        before[pos] = before.get(start, start)
    for pos in sorted(spans, reverse=True):
        end = spans[pos]
        after[pos] = after.get(end, end)
    return before, after


def _email_starts(value, before, after):
    """Yield domain starts without rescanning local parts or adjacent CFWS."""
    quoted = {}
    if '"' in value:
        # Work backwards so every quote's closing quote is found once, even
        # when many escaped quotes could start overlapping candidates. The
        # two suffix results let a backslash skip exactly one character.
        next_end = after_next_end = None
        for pos in range(len(value) - 1, -1, -1):
            char = value[pos]
            if char == '"':
                if next_end is not None:
                    at = after.get(next_end + 1, next_end + 1)
                    if value[at:at + 1] == "@":
                        quoted[pos] = (next_end + 1, at)
                end = pos
            elif char in "\r\n":
                end = next_end if _email_fold(value, pos) else None
            elif char == "\\":
                end = after_next_end if value[pos + 1:pos + 2] not in ("\r", "\n") else None
            else:
                end = next_end
            next_end, after_next_end = end, next_end
    consumed = 0
    quoted_ats = set()
    for marker in EMAIL_MARKERS.finditer(value):
        pos = marker.start()
        if pos < consumed:
            continue
        # Suppress only @ signs inside a complete quoted local part, never
        # those in its trailing comments. Handle the outer @ just once.
        if pos in quoted:
            consumed, at = quoted[pos]
            quoted_ats.add(at)
        # For an unquoted local part, its last character suffices to establish
        # a candidate; rescanning the earlier characters adds no information.
        elif value[pos] == "@" and pos not in quoted_ats:
            local_end = before.get(pos, pos)
            # Earlier @ signs may belong to trailing comments, so their
            # positions must not invalidate the local part before that CFWS.
            if not local_end or not EMAIL_LOCAL_CHAR.fullmatch(value[local_end - 1]):
                continue
            at = pos
        else:
            continue
        yield after.get(at + 1, at + 1)


def _email_domains(value):
    """Read bracketed literals or complete Unicode domain labels."""
    if "@" not in value:
        return
    before, after = _email_cfws(value)
    for start in _email_starts(value, before, after):
        end = start
        literal = EMAIL_LITERAL_DOMAIN.match(value, end)
        if literal:
            # Keep brackets so literal addresses cannot match example domains.
            # This is candidate detection, not IP or SMTP syntax validation.
            yield literal.group()
            continue
        while end < len(value):
            char = value[end]
            # Unlike \w, Unicode marks remain part of the current label. Do
            # not exempt an example-domain prefix followed by such a mark.
            if (char not in ".-_" and char not in IDNA_LABEL_EXTRAS
                    and unicodedata.category(char)[0] not in "LMN"):
                break
            end += 1
        domain = value[start:end].rstrip(".")
        # Malformed trailing labels must not hide a preceding address in prose.
        if "." in domain:
            yield domain


def _example_domain(domain):
    """A reserved example domain, also when prose runs straight on after it.

    Top-level labels never mix ASCII with other scripts, so a last label that
    starts in ASCII and continues into other letters ends where its ASCII part
    ends. Only the last label is cut: `example.comé.рф` and `example.comん.jp`
    are judged whole, so prose after a later sentence break stays refused.
    """
    if EXAMPLE_DOMAINS.search(domain):
        return True
    head, dot, last = domain.rpartition(".")
    run_on = ASCII_RUN_ON_LABEL.match(last)
    return bool(dot and run_on and EXAMPLE_DOMAINS.search(f"{head}.{run_on.group(1)}"))


def find(value):
    """Why `value` must be refused (shaped like an e-mail address or a long
    personal number), or None when it may be saved. Pure: `value` is never
    changed, and any value is accepted (None passes; others are read as str)."""
    if value is None:
        return None
    # Keep this guard safe for callers that have not checked the shape yet.
    value = str(value)
    reason = _scan(value)
    if reason:
        return reason
    # Quoted request lines and markup carry values percent- or entity-encoded
    # (`%40`, `&#64;`), sometimes twice. Inspect a few decoded copies as well.
    for _ in range(DECODE_ROUNDS):
        if "%" not in value and "&" not in value:
            break
        decoded = unescape(unquote(value))
        if decoded == value:
            break
        value = decoded
        reason = _scan(value)
        if reason:
            return reason
    return None


def _scan(value):
    # Inspect a normalised copy: non-breaking spaces and width variants must
    # not evade the guard, and accepted text must keep its original spelling.
    # Invisible characters (format characters such as zero-width spaces, word
    # joiners and soft hyphens, and the other default-ignorable code points)
    # are dropped so they cannot split an address or a number.
    value = unicodedata.normalize("NFKC", value)
    # Per-character work in Python dominated long prose: look up each distinct
    # character once, and use str.replace (fast on any script) instead of a
    # translate table. The result is the same as translating and filtering.
    for dot in IDNA_DOT_CHARS:
        if dot in value:
            value = value.replace(dot, ".")
    for char in {c for c in set(value) if unicodedata.category(c) == "Cf"}:
        value = value.replace(char, "")
    value = INVISIBLE.sub("", value)
    for domain in _email_domains(value):
        # `react@18.2.0` and `sdk@1.2.3-beta` name package versions, not mail
        # domains. Bracketed literals and four-part numeric hosts still count.
        if PACKAGE_VERSION.fullmatch(domain) or (
                not domain.startswith("[") and domain.count(".") != 3
                and not any(c.isalpha() for c in domain.rsplit(".", 1)[-1])):
            continue
        if not _example_domain(domain):
            return EMAIL
    # Masking only replaces spans with '#' and keeps original digits beside
    # it, so every digit run it leaves is part of one in the input: without a
    # long run in the input there is none to find after masking. Skip the
    # costly masking then; the outcome is unchanged.
    if GROUPED_NUMBER.search(value) or (LONG_NUMBER.search(value)
                                        and LONG_NUMBER.search(_mask_technical_numbers(value))):
        return LONG_NUMBER_VALUE
    return None



def find_in_url(value):
    """`find` for a reference URL: raw and decoded values, spelling unchanged."""
    try:
        parts = urlsplit(value)
    except ValueError:
        # Malformed references are still displayed as text by the renderer.
        candidates = [value, unquote(value), unquote_plus(value)]
    else:
        candidates = [value, *(unquote(part) for part in parts)]
        # Query values also use '+' for spaces. Decode the original query once;
        # keep its names and values separate so unrelated numbers are not joined.
        for name, item in parse_qsl(parts.query, keep_blank_values=True):
            candidates += [name, item]
    return next(filter(None, map(find, candidates)), None)

