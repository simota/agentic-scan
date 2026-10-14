"""Decide which source lines an excerpt must not publish. Standard library only.

Two independent tests, both linear in the line length:

- Known credential formats are always masked: provider token prefixes, JWTs,
  private-key blocks, credentials in URLs and command lines, and bearer or
  basic authorization values.
- A secret-like name (password, secret, token, api key, credentials…) is
  masked when the value assigned to it is a literal that is not a label.
  Labels (a capitalised word or a phrase repeating the name's keyword, such
  as "Password" or "Enter your password", or non-ASCII text such as "パスワード"), types, expressions, references
  (process.env.X), booleans, colours and lengths stay visible, because forms and locale files are exactly what a UX review
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
    r"|(?i:\bauthorization\W+basic\s+[A-Za-z0-9+/]{8,})|(?i:\bauthorization\W+bearer\s+[\w.~+/-]{16,})"
    r"|(?i:\bcurl\b[^\n]*?\s-u\s*[^\s:]+:\S)|(?i:\bmysql\b[^\n]*?\s-p\S)")
# The start of a known format at the very end of the shown text.
CUT_SECRET = re.compile(r"(?i)(?:\bbearer\s+[\w.~+/-]*|://[^/\s:@\"'`]+:[^/\s@\"'`]*|\b(?:sk|rk|pk)_(?:live|test)_?"
                        r"|\bgh[pousr]_\w*|\bgithub_pat_\w*|\bxox[abpr]-?|\bAKIA[0-9A-Z]*|\beyJ[\w.-]*"
                        r"|\bAIza[\w-]*|-----BEGIN[A-Z ]*)\Z")

_KEYWORD = (r"secret|passw(?:or)?d|pwd|passphrase|pass|api[_-]?keys?|private[_-]?key"
            r"|access[_-]?key|credentials?|token|client[_-]?id")
# A name part may follow the keyword only when it is key-like or an environment
# or version tag (SECRET_KEY, AWS_SECRET_ACCESS_KEY, DB_PASSWORD_PROD, AUTH_TOKEN_V2),
# so passwordLabel, tokenColor or password_reset_url are UI names, not secrets.
_SUFFIX = (r"(?:[_.-]?(?:access[_-]?)?(?:keys?|token|hash|salt|pem|value|secret))?"
           r"(?:[_-](?:prod|production|dev|development|staging|test|live|local|v?\d+))*\d*")
# The keyword starts a name part: after a non-letter, or as a capitalised word
# after any letter (camelCase passwordHash, acronym prefixes DBPassword, APISecret).
NAME_START = r"(?:(?<![A-Za-z])|(?<=[A-Za-z])(?=[A-Z][a-z]))"
SECRET_NAME = re.compile(NAME_START + r"(?i:(?:" + _KEYWORD + r")" + _SUFFIX + r")(?![A-Za-z])")
# Closing quotes or brackets, an optional type (Go "Password string = …"), then an
# assignment: = : := ?= =>, XML >value< or value="…"; == compares.
ASSIGNMENT = re.compile(r"(?:[\"'\]]|\s+[A-Za-z_][\w.]*(?=\s*:?=))?\s*(?::=|\?=|=>|[:=](?!=))\s*"
                        r"|\"?\s+value=|\"?>(?=[^<\s])")
# A type annotation, then the assignment: password: string = "…", password?: str | None = "…".
ANNOTATED = re.compile(r"[\"']?\??\s*:\s*[A-Za-z_][\w.]*(?:<[^<>=\n]{0,64}>|\[[^\]=\n]{0,64}\])?"
                       r"(?:\s*\|\s*[A-Za-z_][\w.]*)*\s*=(?![=>])\s*")
# A quoted secret name as a call's first argument: define('DB_PASSWORD', 'v'), setdefault("SECRET_KEY", "v").
CALL_ARGUMENT = re.compile(r"\(\s*[\"'`][\w.-]{0,64}?" + NAME_START + r"(?i:(?:" + _KEYWORD + r")" + _SUFFIX + r")[\"'`]\s*,\s*")
# Any non-empty quoted literal, spaces included ("correct horse battery staple").
QUOTED_VALUE = re.compile(r"[\[({]?\s*([\"'`])((?:(?!\1)[^\\\n]|\\.)+)\1")
BARE_VALUE = re.compile(r"([^\s\"'`,;(){}\[\]<]+)")
REFERENCE = re.compile(r"[A-Za-z_$][\w$]*(?:\.[\w$]+|\[[^\]]*\])+")
NOT_SECRET = re.compile(r"(?i)(?:true|false|null|none|undefined|nil|string|number|boolean|bool|int|str|any|"
                        r"include|same-origin|omit|strong|weak|medium)\W*")
COLOR_OR_LENGTH = re.compile(r"#[0-9a-fA-F]{3,8}|-?\d+(?:\.\d+)?(?:px|rem|em|%|vh|vw|ms|s)")
# CSS custom properties; Sass and Less variables hold colours and lengths, exempt as values.
VARIABLE_PREFIX = re.compile(r"--[\w-]*\Z")


LABEL_WORD = re.compile(r"[A-Z][a-z]+(?:[-'][A-Za-z]+)*[.:?!…]*")
# Two or more words of letters, without digits or underscores ("Enter your password").
LABEL_PHRASE = re.compile(r"[^\W\d_]+(?:[-'][^\W\d_]+)*(?:[,.:;?!…]*\s+[^\W\d_]+(?:[-'][^\W\d_]+)*)+[.:?!…]*")


def _is_label(value, name):
    """A UI label for this name: a capitalised word that repeats the name's keyword
    ("Password", "Passwort"), words without digits that include it ("Enter your
    password"), or text with no ASCII word at all ("パスワード").

    A value with digits, underscores or lower-case letters only ("password123",
    "token_abc"), or a phrase without the keyword ("correct horse battery
    staple"), is a credential.
    """
    keyword = SECRET_NAME.match(name)
    stem = re.sub(r"[^a-z]", "", keyword.group(0).lower())[:5] if keyword else ""
    return ((bool(stem) and stem in value.lower()
             and (LABEL_WORD.fullmatch(value) is not None or LABEL_PHRASE.fullmatch(value) is not None))
            or (not re.search(r"[A-Za-z0-9]{2}", value) and re.search(r"[^\x00-\x7f]", value) is not None))


def _value_starts(text):
    """(offset where an assigned value begins, the secret-like name) pairs."""
    for name in SECRET_NAME.finditer(text):
        if VARIABLE_PREFIX.search(text, max(0, name.start() - 64), name.start()):
            continue  # A CSS custom property such as --token-color.
        if name.start() and text[name.start() - 1] in "/\\":
            continue  # A path such as /etc/passwd.
        assignment = ANNOTATED.match(text, name.end()) or ASSIGNMENT.match(text, name.end())
        if assignment:
            yield assignment.end(), name.group(0)
    for call in CALL_ARGUMENT.finditer(text):
        yield call.end(), SECRET_NAME.search(call.group(0)).group(0)


def _secret_literal(quoted, name):
    """Whether a matched QUOTED_VALUE is a credential rather than a label, keyword, colour or length."""
    value = quoted.group(2)
    return not (_is_label(value, name) or NOT_SECRET.fullmatch(value) or COLOR_OR_LENGTH.fullmatch(value))


def _assigned_secret(text):
    for rest, name in _value_starts(text):
        quoted = QUOTED_VALUE.match(text, rest)
        if quoted:
            if _secret_literal(quoted, name):
                return True
            continue
        if rest < len(text) and text[rest] in "{([":
            continue  # An expression, such as password={password}.
        bare = BARE_VALUE.match(text, rest)
        if bare and text.startswith("(", bare.end()):
            # A call such as useState(…) or String("…"): a literal first argument is the value.
            quoted = QUOTED_VALUE.match(text, bare.end())
            if quoted and _secret_literal(quoted, name):
                return True
            continue
        if (bare and not REFERENCE.fullmatch(bare.group(1)) and not NOT_SECRET.fullmatch(bare.group(1))
                and not COLOR_OR_LENGTH.fullmatch(bare.group(1))):
            return True  # A bare env or properties value is never a UI label.
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
    """Indexes of lines inside complete -----BEGIN … PRIVATE KEY----- … -----END blocks, or base64-only lines.

    A BEGIN with no END after it hides nothing more than its own line, which
    secret_line already masks.
    """
    hidden, begin = set(), None
    for index, line in enumerate(lines):
        if "PRIVATE KEY-----" in line and "-----BEGIN" in line:
            begin = index
        if begin is not None and "-----END" in line:
            hidden.update(range(begin, index + 1))
            begin = None
        if _base64_only(line):
            hidden.add(index)
    return hidden
