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
    r"|-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----"     # PEM and PGP armour
    r"|://[^/\s:@\"'`]*:[^/\s@\"'`]+@"                     # scheme://user:password@host, also redis://:password@host
    r"|(?i:(?<!\S)--(?:password|passwd|pass|token|secret|api-?key)(?:=|\s+)[\"']?(?![-$<{%\\])[^\s\"'])"  # --password value
    r"|(?i:\bbearer\s+(?=[\w.~+/-]*\d)[\w.~+/-]{16,})"
    r"|(?i:\bauthorization\W+basic\s+[A-Za-z0-9+/]{8,})|(?i:\bauthorization\W+bearer\s+[\w.~+/-]{16,})"
    r"|(?i:\bcurl\b[^\n]*?\s(?:-u\s*|--user(?:=|\s+))[^\s:]+:\S)|(?i:\bmysql\b[^\n]*?\s-p\S)")
# The start of a known format at the very end of the shown text.
CUT_SECRET = re.compile(r"(?i)(?:\bbearer\s+[\w.~+/-]*|://[^/\s:@\"'`]*:[^/\s@\"'`]*|\b(?:sk|rk|pk)_(?:live|test)_?"
                        r"|\bgh[pousr]_\w*|\bgithub_pat_\w*|\bxox[abpr]-?|\bAKIA[0-9A-Z]*|\beyJ[\w.-]*"
                        r"|\bAIza[\w-]*|-----BEGIN[A-Z ]*)\Z")

_KEYWORD = (r"secret|passw(?:or)?d|pwd|passphrase|pass|api[_-]?keys?|private[_-]?key"
            r"|access[_-]?key|credentials?|token|client[_-]?id")
# A name part may follow the keyword only when it is key-like or an environment
# or version tag (SECRET_KEY, SECRET_KEY_BASE, AWS_SECRET_ACCESS_KEY, PASSWORD_ADMIN,
# DB_PASSWORD_PROD, AUTH_TOKEN_V2),
# so passwordLabel, tokenColor or password_reset_url are UI names, not secrets.
_SUFFIX = (r"(?:[_.-]?(?:access[_-]?)?(?:keys?|token|hash|salt|pem|value|secret))?"
           r"(?:[_-](?:base|confirm(?:ation)?|admin|root|master))?"
           r"(?:[_-](?:prod|production|dev|development|staging|test|live|local|v?\d+))*\d*")
# The keyword starts a name part: after a non-letter, as a capitalised word after
# any letter (camelCase passwordHash, acronym prefixes DBPassword, APISecret), or
# inside an upper-case name (DBPASSWORD, APITOKEN, MYSECRET); a long lower-case
# keyword may also end a lower-case name (mypassword, csrftoken), but a bare
# "pass" may not (bypass, compass).
NAME_START = (r"(?:(?<![A-Za-z])|(?<=[A-Za-z])(?=[A-Z][a-z])|(?<=[A-Za-z])(?=[A-Z]{2}(?![a-z]))"
              r"|(?<=[a-z])(?=passw|secret|token|api_?key|passphrase))")
SECRET_NAME = re.compile(NAME_START + r"(?i:(?:" + _KEYWORD + r")" + _SUFFIX + r")(?![A-Za-z])")
# Closing quotes or brackets (also a subscript, ["password"]), an optional type (Go "Password string = …"), then an
# assignment: = : := ?= ||= &&= ??= =>, XML >value< or value="…"; == compares.
ASSIGNMENT = re.compile(r"(?:[\"'`](?:\s*\])?|\]|\s+[A-Za-z_][\w.]*(?=\s*:?=))?\s*(?::=|\|\|=|&&=|\?\?=|\?=|=>|[:=](?!=))\s*"
                        r"|\"?\s+value=|\"?>(?=[^<\s])")
# A form field named by the secret-like name (name="password"): its value or defaultValue may follow other
# attributes. A label, id or type="password" names no value, so only the name attribute reaches this far.
FIELD_NAME = re.compile(r"(?i)(?<![\w:-])name\s*=\s*[\"']?[\w.\[\]-]{0,64}\Z")
ATTRIBUTE_NAME = re.compile(r"[^\s\"'=<>/{}`]+")
EQUALS = re.compile(r"\s*=\s*")
UNQUOTED_VALUE = re.compile(r"[^\s\"'=<>`{}]+")
FIELD_VALUE_NAMES = ("value", "defaultvalue")
# A type annotation, then the assignment: password: string = "…", password?: str | None = "…".
ANNOTATED = re.compile(r"[\"']?\??\s*:\s*[A-Za-z_][\w.]*(?:<[^<>=\n]{0,64}>|\[[^\]=\n]{0,64}\])?"
                       r"(?:\s*\|\s*[A-Za-z_][\w.]*)*\s*=(?![=>])\s*")
# The end of a line whose assigned value continues on the next one.
OPEN_END = re.compile(r"(?:\|\||\?\?|&&|\bor|\band|[-+*/(\[{,?:=])\s*\Z")
# A secret flag whose value follows a shell line continuation: --password \\
FLAG_CONTINUES = re.compile(r"(?i)(?<!\S)(--(?:password|passwd|pass|token|secret|api-?key))(?:=|\s+)\\\Z")
BLOCK_COMMENT = re.compile(r"/\*.*?\*/")
LEADING_COMMENTS = re.compile(r"\A(?:/\*.*?\*/\s*)+")
COMMENT_LINE = re.compile(r"(?://|#|/\*|\*|<!--)")
# A quoted secret name as a call's first argument: define('DB_PASSWORD', 'v'), setdefault("SECRET_KEY", "v").
CALL_ARGUMENT = re.compile(r"\(\s*[\"'`][\w.-]{0,64}?" + NAME_START + r"(?i:(?:" + _KEYWORD + r")" + _SUFFIX + r")[\"'`]\s*,\s*")
# Any non-empty quoted literal, spaces included ("correct horse battery staple").
QUOTED_VALUE = re.compile(r"[\[({]?\s*([\"'`])((?:(?!\1)[^\\\n]|\\.)+)\1")
# A quoted literal with no closing quote before the end of the searched text.
UNCLOSED_VALUE = re.compile(r"[\[({]?\s*([\"'`])((?:(?!\1)[^\\\n]|\\.)*)\Z")
# Up to eight opening delimiters of an expression: {, ((, [{ ….
EXPRESSION_START = re.compile(r"(?:[{(\[]\s*){1,8}")
BARE_VALUE = re.compile(r"([^\s\"'`,;(){}\[\]<]+)")
REFERENCE = re.compile(r"[A-Za-z_$][\w$]*(?:\.[\w$]+|\[[^\]]*\])+")
# A NAME=value line with no space before "=": .env files, Java properties, export lines.
# A plain $VAR or ${VAR}; ${VAR:-default} and its kin carry a default that is judged as a value.
# (${VAR:?message} carries an error message, not a value.)
# It must be the whole value: ${VALUE}hunter2 or $VALUE-hunter2 carries a literal.
ENV_REFERENCE = re.compile(r"\$(?:\{[A-Za-z_]\w*(?::?\?[^}]*)?\}|[A-Za-z_]\w*)"
                           # ${VALUE} hunter2 carries a literal too; # and // start a comment only after a space.
                           # A quote ends it only directly, and only as a closing quote (see _code_reference):
                           # ${VALUE} "hunter2" and ${VALUE}"hunter2" carry a literal.
                           r"(?=[\"'`]|\s*(?:[,;)}\]]|\Z)|\s+(?:#|//))")
# In configuration files only the end of the line or a spaced # comment ends a reference.
CONFIG_REFERENCE_END = re.compile(r"[ \t]*(?:\Z|\r?$)|[ \t]+#", re.MULTILINE)
ENV_DEFAULT = re.compile(r"\$\{[A-Za-z_]\w*:?[-=+]([^}\s]*)\}")
# Files whose values are configuration, judged with config=True.
CONFIG_FILE = re.compile(r"(?i)(?:^|/)(?:\.env[\w.-]*|[^/]*\.(?:properties|env|ini|cfg|conf|toml|ya?ml))$")
ENV_LINE = re.compile(r"\s*(?:export\s+)?[A-Za-z_][\w.-]*=(?![=>])")
IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*")
# A literal that a reference or expression falls back to: process.env.X || "…", x ?? "…", x or "…".
# Ternary branches are not read: they mostly choose between UI values (isMobile ? "sm" : "md").
FALLBACK = re.compile(r"(?:\|\||\?\?|\bor\b)\s*(?:[({\[]\s*){0,8}(?=[\"'`])")  # also || ("…")
STATEMENT_END = re.compile(r"[,;}\n]")
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


def _braces_end(text, i):
    """The offset after the {…} expression opening at i, nested braces and quoted strings included, or None."""
    depth = 0
    while i < len(text):
        c = text[i]
        if c in "\"'`":
            close = text.find(c, i + 1)
            if close < 0:
                return None
            i = close
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if not depth:
                return i + 1
        i += 1
    return None


def _field_value(text, i):
    """Where the value or defaultValue of the tag continuing at i begins, past any attributes in between, or None.

    i is just after the field's name, before its closing quote. One pass to the end of the tag; the end
    of the text when the tag goes on past it (attributes on the following lines).
    """
    if i < len(text) and text[i] in "\"'":
        i += 1
    while True:
        start = i
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            return len(text)  # The tag continues on the next line.
        if i == start:
            return None  # Attributes are separated by whitespace.
        if text[i] == "{":  # A JSX spread.
            i = _braces_end(text, i)
            if i is None:
                return None
            continue
        attribute = ATTRIBUTE_NAME.match(text, i)
        if not attribute:
            return None  # > or /> ends the tag.
        equals = EQUALS.match(text, attribute.end())
        if not equals:  # A boolean attribute: disabled, readonly.
            i = attribute.end()
            continue
        if attribute.group(0).lower() in FIELD_VALUE_NAMES:
            return equals.end()
        i = equals.end()
        if i >= len(text):
            return None
        if text[i] in "\"'":
            close = text.find(text[i], i + 1)
            if close < 0:
                return None
            i = close + 1
        elif text[i] == "{":
            i = _braces_end(text, i)
            if i is None:
                return None
        else:
            unquoted = UNQUOTED_VALUE.match(text, i)
            if not unquoted:
                return None
            i = unquoted.end()


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
        # Also judged apart: name=password class=x value="…" reads as a typed declaration above.
        if FIELD_NAME.search(text, max(0, name.start() - 80), name.start()):
            field = _field_value(text, name.end())
            if field is not None:
                yield field, name.group(0)
    for call in CALL_ARGUMENT.finditer(text):
        yield call.end(), SECRET_NAME.search(call.group(0)).group(0)


def _secret_literal(quoted, name):
    """Whether a matched QUOTED_VALUE is a credential rather than a label, keyword, colour or length."""
    value = quoted.group(2)
    if ENV_REFERENCE.fullmatch(value):
        return False  # "${DB_PASSWORD}" or "$PW": a variable, quoted.
    default = ENV_DEFAULT.fullmatch(value)
    if default and (not default.group(1) or default.group(1).startswith("$")):
        return False
    return not (_is_label(value, name) or NOT_SECRET.fullmatch(value) or COLOR_OR_LENGTH.fullmatch(value))


def _code_reference(text, bare, config=False):
    """Whether a bare value is code: a digit-free identifier or reference (currentPassword,
    auth.currentPassword). In configuration files and on NAME=value lines (.env, .properties)
    a bare value is always a literal, and a digit in the root (Pa55.word) marks a value too."""
    value = bare.group(1)
    default = ENV_DEFAULT.match(text, bare.start())
    if default:  # ${VAR:-default}: the default is the value.
        return not default.group(1) or default.group(1).startswith("$") or bool(
            NOT_SECRET.fullmatch(default.group(1).strip("\"'")))
    if reference := ENV_REFERENCE.match(text, bare.start()):
        after = text[reference.end():reference.end() + 1]
        # A quote ends the reference only when it closes a quote opened just before it ("${PW}");
        # elsewhere it starts a word the shell concatenates: ${VALUE}"hunter2" carries a literal.
        if after in "\"'`" and after and text[bare.start() - 1:bare.start()] != after:
            return False
        if config and not CONFIG_REFERENCE_END.match(text, reference.end() + (after in "\"'`" and bool(after))):
            return False  # In configuration , ; ) ] } do not end a value: ${VALUE} , hunter2 is one.
        return True  # $VAR or ${VAR}: an environment or shell variable, not its value.
    if text.startswith("${", bare.start()):
        return False  # ${VALUE} followed by more text: not a whole reference, so a literal.
    dotted = REFERENCE.fullmatch(value) is not None
    if config or not (dotted or IDENTIFIER.fullmatch(value)) or ENV_LINE.match(text):
        return False  # Configuration files hold values, never code.
    if re.search(r"\d", IDENTIFIER.match(value).group(0)):
        return False  # hunter2.secret reads as a value, not an object.
    return True  # In code a string literal is quoted, so a bare identifier is a reference.


def _fallback_secret(text, start, name):
    """Whether the statement from start on falls back to a credential literal (x || "…", x ?? "…")."""
    stop = STATEMENT_END.search(text, start)
    for operator in FALLBACK.finditer(text, start, stop.start() if stop else min(len(text), start + 200)):
        quoted = QUOTED_VALUE.match(text, operator.end())  # The delimiters before it are consumed already.
        if quoted and _secret_literal(quoted, name):
            return True
    return False


def _assigned_secret(text, config=False):
    for rest, name in _value_starts(text):
        quoted = QUOTED_VALUE.match(text, rest)
        if quoted:
            if _secret_literal(quoted, name):
                return True
            continue
        unclosed = UNCLOSED_VALUE.match(text, rest)
        if unclosed and unclosed.group(2) and _secret_literal(unclosed, name):
            return True  # A literal cut off by the line limit, or left open.
        expression = EXPRESSION_START.match(text, rest)
        if expression:
            quoted = QUOTED_VALUE.match(text, expression.end())
            if quoted and _secret_literal(quoted, name):
                return True  # A literal inside nested delimiters: (("…")), {("…")}.
        if _fallback_secret(text, rest, name):
            return True
        bare = BARE_VALUE.match(text, expression.end() if expression else rest)
        if bare and text.startswith("(", bare.end()):
            # A call such as useState(…) or String("…"), also inside {…}: a literal first argument is the value.
            quoted = QUOTED_VALUE.match(text, bare.end())
            if quoted and _secret_literal(quoted, name):
                return True
            continue
        if expression:
            continue  # An expression, such as password={password}.
        if (bare and not _code_reference(text, bare, config) and not NOT_SECRET.fullmatch(bare.group(1))
                and not COLOR_OR_LENGTH.fullmatch(bare.group(1))):
            return True  # A bare env or properties value is never a UI label.
    return False


CONTINUATION_LINES = 5  # Lines after a name that a wrapped value may sit on.


REGEX_KEYWORDS = {"return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void", "throw", "yield",
                  "await", "instanceof"}
REGEX_LITERAL = re.compile(r"/(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n\[])+/[a-z]*")


def _unclosed(text):
    """Whether text leaves a ( [ or { open, outside quoted literals and comments: password = (\n x\n || "…"."""
    bare = re.sub(r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`", "", text)
    bare = re.sub(r"/\*.*?(?:\*/|\Z)|//.*|(?<!\S)#.*", "", bare)  # Comments are not syntax: x // ).
    # Nor are regular-expression literals: /[)]/.test(x). A "/" after an operand divides.
    def literal(match):
        before = re.search(r"([\w$]+|[)\]])\s*\Z", bare[:match.start()])
        return match[0] if before and before[1] not in REGEX_KEYWORDS else " "
    bare = REGEX_LITERAL.sub(literal, bare)
    return sum(bare.count(c) for c in "([{") > sum(bare.count(c) for c in ")]}")


def _opens_comment(text):
    """Whether text ends inside a /* block comment it opened."""
    return text.rfind("/*") > text.rfind("*/")


def _open_names(text):
    """Start offsets of secret-like names whose assigned value continues on the next line: nothing
    follows the assignment (password =), or the line ends in an operator or opening delimiter
    (password = process.env.PW ||)."""
    starts = []
    if _opens_comment(text):
        text = text[:text.rfind("/*")].rstrip()  # password = x || /* dev … continues after the comment.
    for name in SECRET_NAME.finditer(text):
        tail = text[name.start():]
        if any(rest >= len(tail) or OPEN_END.search(tail, rest) for rest, _ in _value_starts(tail)):
            starts.append(name.start())
        elif field := _open_field(text, name):
            starts.append(field)  # From name=, so the joined text still names the field.
    return starts


def _open_field(text, name):
    """Where name="…" starts when the field's tag goes on past the end of text, or None."""
    field = FIELD_NAME.search(text, max(0, name.start() - 80), name.start())
    return field.start() if field and _field_value(text, name.end()) == len(text) else None


def _open_tag(text):
    """Whether text ends inside the tag of a secret-named field, before its value."""
    return any(_open_field(text, name) is not None for name in SECRET_NAME.finditer(text))


def continued_secret_lines(lines, start, stop, config=False):
    """Indexes in lines[start:stop] of a value wrapped onto a later line than its secret-like name
    (export const clientToken =\n  "…";) or flag (--password \\\n  "…"), with the name's line.

    A line whose assignment continues is judged from the name on, joined with the
    following lines that are neither blank nor comments for as long as the joined
    expression still ends in an operator (at most five lines on); start may lie one
    line before the excerpt.
    """
    hidden = set()
    for index in range(max(0, start), min(len(lines), stop)):
        text = lines[index][:SHOWN_CHARACTERS + LOOKAHEAD].rstrip()
        flag = FLAG_CONTINUES.search(text)
        names = _open_names(text)
        if not (names or flag):
            continue
        # From the name on, so a long line before it cannot push the value past the limit.
        joined, used = flag.group(1) if flag else text[names[-1]:], [index]
        in_comment = _opens_comment(joined)
        if in_comment:
            joined = joined[:joined.rfind("/*")].rstrip()
        for following in range(index + 1, min(len(lines), index + 1 + CONTINUATION_LINES)):
            value = lines[following].strip()
            if in_comment:  # Inside a block comment that opened after the operator: skip to its end.
                close = value.find("*/")
                if close < 0:
                    continue
                value, in_comment = value[close + 2:].strip(), False
            value = LEADING_COMMENTS.sub("", value)  # /* dev */ "…": the value follows the comment.
            if not value or COMMENT_LINE.match(value):
                in_comment = _opens_comment(value)
                continue  # A blank line or a comment between the name and its value.
            joined = joined + " " + value[:SHOWN_CHARACTERS + LOOKAHEAD]
            used.append(following)
            if secret_line(joined, config):
                hidden.update(used)
                break
            if _opens_comment(joined):  # A comment opened on this line: its value follows the comment.
                joined, in_comment = joined[:joined.rfind("/*")].rstrip(), True
                continue
            if not OPEN_END.search(joined) and not _unclosed(joined) and not _open_tag(joined):
                break  # The expression or the field's tag ended without a credential.
            # Still open (process.env.PW ||, or an unclosed "("): the value continues on the next line.
    return hidden


def secret_line(line, config=False):
    """Whether the shown part of line must be masked.

    config is true for configuration files (.env, .properties, YAML…), where a
    bare value such as Sommer.x is a literal, never a code reference.
    """
    searched = line[:SHOWN_CHARACTERS + LOOKAHEAD]
    # Assignments are judged with block comments blanked, so a comment can neither hide a value
    # (password = x || /* dev */ "…") nor pose as one (password = /* note */ auth.pw); each
    # comment's own text is judged too, for a secret written inside it.
    comments = BLOCK_COMMENT.findall(searched) if "/*" in searched else []
    uncommented = BLOCK_COMMENT.sub(lambda m: " " * len(m.group(0)), searched) if comments else searched
    if (KNOWN_SECRET.search(searched) or _assigned_secret(uncommented, config)
            or any(_assigned_secret(comment[2:-2], config) for comment in comments)):
        return True
    return len(line) > SHOWN_CHARACTERS and bool(CUT_SECRET.search(line[:SHOWN_CHARACTERS]))


BASE64_LINE = re.compile(r"\s*[A-Za-z0-9+/]{40,}={0,2}\s*")


def _base64_only(line):
    """A line of key material: 40+ base64 characters mixing digits and both letter cases."""
    return (BASE64_LINE.fullmatch(line) is not None and any(c.isdigit() for c in line)
            and any(c.isupper() for c in line) and any(c.islower() for c in line))


PRIVATE_KEY_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----")


def private_key_lines(lines):
    """Indexes of lines inside complete -----BEGIN … PRIVATE KEY [BLOCK]----- … -----END blocks
    (PEM and PGP armour), or base64-only lines.

    A BEGIN with no END after it hides nothing more than its own line, which
    secret_line already masks.
    """
    hidden, begin = set(), None
    for index, line in enumerate(lines):
        if PRIVATE_KEY_BEGIN.search(line):
            begin = index
        if begin is not None and "-----END" in line:
            hidden.update(range(begin, index + 1))
            begin = None
        if _base64_only(line):
            hidden.add(index)
    return hidden
