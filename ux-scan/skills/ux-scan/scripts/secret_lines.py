"""Decide which source lines an excerpt must not publish. Standard library only.

Two independent tests, both linear in the line length:

- Known credential formats are always masked: provider token prefixes, JWTs,
  private-key blocks, credentials in URLs and command lines, and bearer or
  basic authorization values.
- A secret-like name (password, secret, token, api key, credentials…) is
  masked only when the value assigned to it looks like a credential: a literal
  of six or more characters without whitespace that is not a label. Labels
  (a capitalised word such as "Password", or non-ASCII text such as
  "パスワード"), types, expressions, references (process.env.X) and booleans
  stay visible, because forms and locale files are exactly what a UX review
  cites.

These are conservative heuristics, not a credential audit.
"""

import re

SHOWN_CHARACTERS = 240
# Text after the shown part that is still searched, so a credential whose
# identifying end lies just past the cut is found.
LOOKAHEAD = 512

KNOWN_SECRET = re.compile(
    r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]*"                  # JWT
    r"|\bAIza[\w-]{30}"                                    # Google API key
    r"|\b(?:sk|rk|pk)_(?:live|test)_\w"                    # Stripe
    r"|\bwhsec_\w|\bsk-(?:proj-|ant-)?[\w-]{16}"          # webhook secrets, OpenAI, Anthropic
    r"|\bgh[pousr]_\w{20}|\bgithub_pat_\w|\bglpat-[\w-]{10}"  # GitHub, GitLab
    r"|\bxox[abpr]-\w|hooks\.slack\.com/services/"         # Slack
    r"|\bSG\.[\w-]{16,}\.|\bAKIA[0-9A-Z]{16}\b"            # SendGrid, AWS
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|://[^/\s:@\"'`]+:[^/\s@\"'`]+@"                     # scheme://user:password@host
    r"|(?i:\bbearer\s+(?=[\w.~+/-]*\d)[\w.~+/-]{16,})"
    r"|(?i:\bauthorization\W+basic\s+[A-Za-z0-9+/]{8,})"
    r"|(?i:\bcurl\b[^\n]*?\s-u\s*[^\s:]+:\S)|(?i:\bmysql\b[^\n]*?\s-p\S)")
# The start of a known format at the very end of the shown text.
CUT_SECRET = re.compile(r"(?i)(?:\bbearer\s+[\w.~+/-]*|://[^/\s:@\"'`]+:[^/\s@\"'`]*|\b(?:sk|rk|pk)_(?:live|test)_?"
                        r"|\bgh[pousr]_\w*|\bgithub_pat_\w*|\bxox[abpr]-?|\bAKIA[0-9A-Z]*|\beyJ[\w.-]*"
                        r"|\bAIza[\w-]*|-----BEGIN[A-Z ]*)\Z")

_NAMES = (r"secret|passw(?:or)?d|\bpwd|passphrase|\bpass\b|api[_-]?keys?|private[_-]?key"
          r"|access[_-]?key|credentials?|token|client[_-]?id")
SECRET_NAME = re.compile(r"(?i)" + _NAMES)
# The rest of the name (bounded), closing quotes or brackets, an optional type
# (Go "Password string = …"), then an assignment: = : := ?= =>, XML >value< or value="…".
ASSIGNMENT = re.compile(r"[\w.-]{0,64}(?:[\"'\]]|\s+[A-Za-z_][\w.]*(?=\s*:?=))?\s*(?::=|\?=|=>|[:=])\s*"
                        r"|[\w.-]{0,64}\"?\s+value=|[\w.-]{0,64}\"?>(?=[^<\s])")
# A quoted secret name as a call's first argument: define('DB_PASSWORD', 'v'), setdefault("SECRET_KEY", "v").
CALL_ARGUMENT = re.compile(r"(?i)\(\s*[\"'`][\w.-]{0,64}?(?:" + _NAMES + r")[\w.-]{0,64}[\"'`]\s*,\s*")
QUOTED_VALUE = re.compile(r"[\[(]?\s*[\"'`]([^\"'`\s]{6,})[\"'`]")
BARE_VALUE = re.compile(r"([^\s\"'`,;(){}\[\]<]{6,})")
REFERENCE = re.compile(r"[A-Za-z_$][\w$]*(?:\.[\w$]+|\[[^\]]*\]|\(.*)+|[A-Za-z_$][\w$]*\(.*")
NOT_SECRET = re.compile(r"(?i)(?:true|false|null|none|undefined|nil|string|number|boolean|bool|int|str|any)\W*")


LABEL = re.compile(r"[A-Z][a-z]+(?:[-'][A-Za-z]+)*[.:?!…]*")


def _credential_like(value):
    """A literal that reads as a credential rather than a UI label."""
    return value.isascii() and not LABEL.fullmatch(value)


def _value_starts(text):
    """Offsets where a value assigned to a secret-like name begins."""
    for name in SECRET_NAME.finditer(text):
        assignment = ASSIGNMENT.match(text, name.end())
        if assignment:
            yield assignment.end()
    for call in CALL_ARGUMENT.finditer(text):
        yield call.end()


def _assigned_secret(text):
    for rest in _value_starts(text):
        quoted = QUOTED_VALUE.match(text, rest)
        if quoted:
            if _credential_like(quoted.group(1)):
                return True
            continue
        if rest < len(text) and text[rest] in "{([":
            continue  # An expression, such as password={password}.
        bare = BARE_VALUE.match(text, rest)
        if (bare and not text.startswith("(", bare.end())  # A call such as useState(…).
                and not REFERENCE.fullmatch(bare.group(1)) and not NOT_SECRET.fullmatch(bare.group(1))
                and _credential_like(bare.group(1))):
            return True
    return False


def secret_line(line):
    """Whether the shown part of line must be masked."""
    searched = line[:SHOWN_CHARACTERS + LOOKAHEAD]
    if KNOWN_SECRET.search(searched) or _assigned_secret(searched):
        return True
    return len(line) > SHOWN_CHARACTERS and bool(CUT_SECRET.search(line[:SHOWN_CHARACTERS]))


BASE64_LINE = re.compile(r"\s*[A-Za-z0-9+/]{40,}={0,2}\s*")


def _base64_only(line):
    """A line of key material: 40+ base64 characters mixing digits and both letter cases."""
    return (BASE64_LINE.fullmatch(line) is not None and any(c.isdigit() for c in line)
            and any(c.isupper() for c in line) and any(c.islower() for c in line))


def private_key_lines(lines):
    """Indexes of lines inside -----BEGIN … PRIVATE KEY----- blocks, or base64-only lines."""
    hidden, inside = set(), False
    for index, line in enumerate(lines):
        if "PRIVATE KEY-----" in line and "-----BEGIN" in line:
            inside = True
        if inside or _base64_only(line):
            hidden.add(index)
        if inside and "-----END" in line:
            inside = False
    return hidden
