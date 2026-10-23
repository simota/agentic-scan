"""Conservative redaction for values copied into scan outputs (stdlib only)."""
import bisect
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote_plus, urlsplit, urlunsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import unique_object  # noqa: E402


# The second alternative takes the short spellings (DB_PASS, admin_pw, pwd)
# only as whole words, so bypass_mode or upwards are not keys of a secret.
SECRET_FIELD = re.compile(
    r"(?i)(?<![\w/?&.-])(?:[\w/.-]*(password|passwd|secret|token|private[-_]?key|access[-_]?key|api[-_]?key|"
    r"client[-_]?key|tls\.key|ssh[-_]?key|client[-_]?secret|connection[-_]?string|credentials?|"
    r"(?:signing|hmac|jwt|session|app)[-_]?key)[\w/.-]*|"
    r"(?:[\w/.-]*[^a-zA-Z\s\"'=:])?(pass(?:phrase)?|pwd|pw|authorization|bearer)"
    r"(?:[^a-zA-Z\s\"'=:][\w/.-]*)?)[\"']?\s*[:=]")
# Known credential formats, labelled for the scanner's SEC-001 detail. The
# scanner, redaction and the merge gate all build their patterns from these.
CREDENTIAL_SHAPES = (
    ("AWS access key ID", r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    ("access token", r"gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20}|"
                     r"xox[abeoprs]-[0-9]+-[A-Za-z0-9-]+|xapp-[0-9]-[A-Za-z0-9-]+|AIza[0-9A-Za-z_-]{35}"),
)
SECRET_SHAPE = re.compile("|".join(pattern for _, pattern in CREDENTIAL_SHAPES))
# PEM and OpenSSH use five dashes; RFC 4716 (SSH2) uses four and spaces.
KEY_MARKER = re.compile(r"-{4,5} ?(BEGIN|END) (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)? ?-{4,5}")
# Anything credential-shaped in text saved to the record. Token prefixes are
# case-sensitive: "asiaPacific..." is a name, not a key.
# A PuTTY key file opens with its format header (PuTTY-User-Key-File-3: ssh-ed25519).
PUTTY_HEADER = r"PuTTY-User-Key-File-[0-9]+:"
CREDENTIAL = re.compile(
    "|".join((SECRET_SHAPE.pattern, KEY_MARKER.pattern, PUTTY_HEADER, r'(?i:"private_key"\s*:)',
              r"xox[abeoprs]-")))
KEY_BEGIN = re.compile(KEY_MARKER.pattern.replace("(BEGIN|END)", "BEGIN"))
# A key block from its opening marker through its closing one, or to the end
# of the text when it has none: the body is the secret, not the marker.
KEY_BLOCK = re.compile(rf"(?:{KEY_BEGIN.pattern}|{PUTTY_HEADER})(?:.*?{KEY_MARKER.pattern}|.*)", re.DOTALL)


def hide_credentials(text):
    """text with every credential shape, and any private key's body, replaced."""
    return CREDENTIAL.sub("[REDACTED]", KEY_BLOCK.sub("[REDACTED]", text))
SAFE_VALUE = re.compile(
    r'(?:(?:(?:var|local|data|module)\.|(?:aws_|google_))[\w.\[\]-]+|null|true|false|'
    r'"?(?:none|NONE|AWS_IAM|IAM|CUSTOM|JWT|COGNITO_USER_POOLS)"?)'
    r"\s*[,}]?\s*$")
SAFE_SCALAR = re.compile(
    r'(?:null|true|false|"?(?:none|NONE|AWS_IAM|IAM|CUSTOM|JWT|COGNITO_USER_POOLS)"?)\s*[,}]?\s*$')
# A count or duration about a secret is policy evidence (minimum_password_length
# = 14, RefreshTokenValidity: 30); only a bare integer under such a key is kept.
SETTING_KEY = re.compile(r"(?i)(?:length|age|prevention|validity|days|hours|minutes|seconds|ttl|period)[\"']?\s*[:=]")
SETTING_VALUE = re.compile(r'"?[0-9]+"?\s*,?\s*$')
HEREDOC = re.compile(r"<<-?\s*([A-Za-z_][A-Za-z0-9_-]*)\s*$")
# Apostrophes are valid in URL userinfo. Keep it through the last @ so a
# surrounding string's quote cannot cut off credentials before module_source.
URL = re.compile(r"(?<![A-Za-z0-9+.-])(?:[A-Za-z][A-Za-z0-9+.-]*::)?"
                 r"[A-Za-z][A-Za-z0-9+.-]*://(?:[^/\s\"<>]*@)?[^\s\"'<>]+")
# A Secrets Manager ARN names a secret, not its value: its ":secret:" segment
# is no key. Only that prefix is exempt; anything after it is read as usual.
SECRET_ARN = re.compile(r"\barn:aws[\w-]*:secretsmanager:[\w-]*:[0-9]*:secret:")
QUOTED_KEY = re.compile(r'("(?:\\.|[^"\\])*")\s*:')
JSON_STRING = re.compile(r'"(?:\\.|[^"\\])*"')
# These getter options identify a revision or limit its history. Other query
# values can be credentials (including signed storage URLs), so omit them.
PUBLIC_QUERY = {"ref", "depth", "version"}
SENSITIVITY_MASKS = {"sensitive_values", "before_sensitive", "after_sensitive"}


def split_lines(text, keepends=False):
    """Split on LF (and CRLF) only, as the HCL and JSON line counters do.

    str.splitlines() also breaks on form feeds, vertical tabs and Unicode
    separators, which would shift every later line number in a report.
    """
    lines = text.split("\n")
    if keepends:
        lines = [line + "\n" for line in lines[:-1]] + ([lines[-1]] if lines[-1] else [])
        return lines
    if lines and lines[-1] == "":
        lines.pop()
    return [line[:-1] if line.endswith("\r") else line for line in lines]


def _secret_fields(line):
    # Qualified YAML/JSON keys can contain slashes. A URL path or query is
    # handled by module_source instead of being mistaken for such a key.
    urls = [match.span() for pattern in (URL, SECRET_ARN) for match in pattern.finditer(line)]
    return (match for match in SECRET_FIELD.finditer(line)
            if not any(start <= match.start() < end for start, end in urls)
            # http_tokens = "optional" is IMDS evidence, not a token.
            and not PUBLIC_WORDS.fullmatch(match.group().rstrip(":= \t\"'").lstrip("\"'")))


def _secret_field(line):
    return next(_secret_fields(line), None)


def is_secret_name(name):
    """A key or variable name that conventionally holds a secret (DB_PASS, admin_pw too)."""
    probe = PUBLIC_WORDS.sub("_", name)  # http_tokens, authorization_type
    return _secret_field(probe + ":") is not None or CREDENTIAL_WORD.search(probe) is not None


def _secret_refs(value, secret=False):
    """CloudFormation parameters referenced (Ref, Fn::Sub) under secret-named keys."""
    refs = set()
    if isinstance(value, dict):
        for key, item in value.items():
            inner = secret or (isinstance(key, str) and is_secret_name(key))
            if inner and key == "Ref" and isinstance(item, str):
                refs.add(item)
            elif inner and key == "Fn::Sub" and isinstance(item, (str, list)):
                text = item if isinstance(item, str) else item[0] if item and isinstance(item[0], str) else ""
                refs.update(re.findall(r"\$\{([A-Za-z0-9]+)\}", text))
            refs |= _secret_refs(item, inner)
    elif isinstance(value, list):
        for item in value:
            refs |= _secret_refs(item, secret)
    return refs


def has_escaped_secret_keys(text, docs):
    """Omit parsed JSON/YAML whose escaped keys defeat raw-line redaction.

    Use decoded document keys as the source of sensitivity. Raw key candidates
    only identify escaped spellings; comments and YAML plain scalars must not
    change which keys are examined. Ordinary/public keys keep their excerpts.
    """
    names, pending = set(), [docs]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            names.update(key for key in value if isinstance(key, str) and _secret_field(key + ":"))
            pending.extend(item for key, item in value.items() if key not in SENSITIVITY_MASKS)
        elif isinstance(value, list):
            pending.extend(value)
    if not names:
        return False
    for match in QUOTED_KEY.finditer(text):
        raw = match.group(1)
        if "\\" not in raw:
            continue
        try:
            key = json.loads(raw)
        except ValueError:
            continue  # The caller already omits unsupported JSON/YAML syntax.
        if key in names:
            return True
    return False


def _sensitive_mask(value):
    """Terraform masks may nest objects/lists; only explicit false is safe."""
    if isinstance(value, dict):
        return any(_sensitive_mask(item) for item in value.values())
    if isinstance(value, list):
        return any(_sensitive_mask(item) for item in value)
    return value is not False


def has_structured_secrets(value):
    """Detect secrets whose meaning is not confined to one source line.

    A renderer cannot safely reuse the original text of these documents:
    sensitivity masks and name/value pairs may be far apart or in any order.
    Omit their excerpts instead of inventing new line numbers by reserializing.
    """
    if isinstance(value, list):
        return any(has_structured_secrets(item) for item in value)
    if isinstance(value, str):
        # JSON held in a string: kubectl's last-applied-configuration
        # annotation, an embedded policy or task definition.
        text = value.strip()
        if text[:1] in ("{", "[") and len(text) > 1:
            try:
                return has_structured_secrets(json.loads(text, object_pairs_hook=unique_object))
            except (ValueError, RecursionError):
                return False
        return False
    if not isinstance(value, dict):
        return False
    if "sensitive" in value and value["sensitive"] is not False:
        return True
    if any(_sensitive_mask(value[key]) for key in SENSITIVITY_MASKS if key in value):
        return True
    # CloudFormation parameter defaults can be secret without a secret-looking
    # parameter name. Only explicit false is safe; YAML block strings may be
    # opaque, and NoEcho also permits string booleans in templates.
    no_echo = value.get("NoEcho", False)
    if no_echo is not False and not (isinstance(no_echo, str) and no_echo.lower() == "false"):
        return True
    # A CloudFormation parameter default is secret when a secret-named
    # property can Ref it; the parameter's own name need not say so.
    params = value.get("Parameters")
    if isinstance(params, dict):
        refs = _secret_refs({k: v for k, v in value.items() if k != "Parameters"})
        if any(isinstance(params.get(name), dict) and "Default" in params[name] for name in refs):
            return True
    # Container flags: args: ["--password", "x"], command: ["sh", "-c", "mysql -p..."].
    for key in ("args", "command", "Command", "EntryPoint", "entryPoint"):
        items = value.get(key)
        if not isinstance(items, list):
            continue
        texts = [item for item in items if isinstance(item, str)]
        # A secret-named flag (--db-password, --token=...), or a database
        # client given its password inline (mysql -pX).
        if any(re.match(r"-{1,2}\S", item) and is_secret_name(item.split("=")[0]) for item in texts):
            return True
        if any(re.search(r"\b(?:mysql|mysqldump|mariadb|psql|mongo|mongosh|redis-cli)\b", item) for item in texts) \
                and any(re.search(r"(?:^|\s)-p\S", item) for item in texts):
            return True
        if any("redis-cli" in item for item in texts) and any(re.search(r"(?:^|\s)-a(?:\s|$)", item) for item in texts):
            return True
    # Plan JSON variables, configuration defaults and output changes put the
    # name one level above the value: "admin_pw": {"value": "..."}.
    for key, item in value.items():
        if isinstance(key, str) and isinstance(item, dict) and is_secret_name(key) and \
                {"value", "default", "constant_value", "Default", "after", "before"} & item.keys():
            return True
    if value.get("kind") == "SecretList":
        return True  # Typed list items may omit their own kind: Secret.
    if value.get("kind") == "Secret" and any(key in value for key in ("data", "stringData")):
        return True
    # Covers Kubernetes env entries, CloudFormation Name/Value and Key/Value
    # pairs and other literal collections, including a value that precedes its
    # name in the source. CloudFormation capitalizes these keys.
    keys = {key.lower(): key for key in value if isinstance(key, str)}
    for val_key, label_keys in (("value", ("name", "key")), ("parametervalue", ("parameterkey",))):
        if val_key in keys:
            for label in label_keys:
                if label in keys:
                    name = value[keys[label]]
                    if not isinstance(name, str) or is_secret_name(name):
                        return True
    if "env" in value and value["env"] is not None:
        entries = value["env"]
        if not isinstance(entries, (dict, list)):
            return True  # Opaque block strings and unknown env expressions.
        # Check decoded keys too; a JSON/YAML escape can hide a secret name
        # from line redaction. Env strings such as "var.password" are literal
        # values, so Terraform's SAFE_VALUE reference exception does not apply.
        if isinstance(entries, dict) and any(
                not isinstance(name, str) or is_secret_name(name) for name in entries):
            return True
        if isinstance(entries, list) and any(
                not isinstance(entry, dict) or ("value" in entry and "name" not in entry)
                for entry in entries):
            return True
    # Masks describe booleans, not configuration name/value objects themselves.
    return any(has_structured_secrets(item) for key, item in value.items()
               if key not in SENSITIVITY_MASKS)


def redact_json_values(text, lines):
    """Mask complete secret values in validated JSON, retaining source line numbers.

    A string token followed by a colon is a real key, unlike a key-like spelling
    inside a string value. Decode each secret value to find its exact endpoint:
    a closing value and the next secret key may share the same source line.
    """
    starts, offset = [], 0
    for line in split_lines(text, keepends=True):
        starts.append(offset)
        offset += len(line)
    decoder = json.JSONDecoder()
    result = list(lines)
    hidden_until = 0
    for match in JSON_STRING.finditer(text):
        if match.start() < hidden_until:
            continue  # An enclosing secret value already covers these tokens.
        after = match.end()
        while after < len(text) and text[after].isspace():
            after += 1
        if after >= len(text) or text[after] != ":":
            continue
        if not _secret_field(json.loads(match.group()) + ":"):
            continue
        start = after + 1
        while start < len(text) and text[start].isspace():
            start += 1
        value, end = decoder.raw_decode(text, start)
        if value is None or isinstance(value, bool):
            continue
        hidden_until = end
        first = bisect.bisect_right(starts, start) - 1
        last = bisect.bisect_right(starts, end - 1) - 1
        if bisect.bisect_right(starts, match.start()) - 1 == first:
            # redact_lines already hides the key's trailing value. Preserve
            # public fields before that key in compact, single-line documents.
            first += 1
        for index in range(first, last + 1):
            result[index] = "[redacted]"
    return result


def module_source(source):
    """Keep a module's address and pin, without URL credentials or signatures."""
    prefix = re.match(r"^[A-Za-z][A-Za-z0-9+.-]*::", source)
    getter = prefix.group(0) if prefix else ""
    raw = source[len(getter):]
    # urlsplit ends the authority at the first "/", "?" or "#", so a password
    # holding one (postgres://app:a#b@db) would land in the path or fragment.
    # Userinfo is everything to the last "@" when a ":" comes before any of
    # them and is not a port (host:5432/path@x keeps its host).
    userinfo = re.match(r"([A-Za-z][A-Za-z0-9+.-]*://)([^\s\"'<>]*)@", raw)
    if userinfo and re.match(r"[^/?#:\[]*:(?!\d*(?:[/?#]|$))", userinfo.group(2)):  # not [::1]:8080
        # The authority branch below replaces this placeholder with [redacted].
        raw = userinfo.group(1) + "redacted@" + raw[userinfo.end():]
    try:
        url = urlsplit(raw)
    except ValueError:
        # Malformed authorities must not fall back to printing their contents.
        return getter + "[redacted source]"
    authority = url.netloc
    if "@" in authority:
        authority = "[redacted]@" + authority.rsplit("@", 1)[1]
    path = url.path
    if not authority:
        # SCP-style Git sources, including a token used as the SSH username.
        path = re.sub(r"^[^/]*@(?=[^/]+:)", "[redacted]@", path)
        if url.scheme and "@" in path:
            return getter + "[redacted source]"
    query = []
    for item in url.query.split("&") if url.query else []:
        key, sep, value = item.partition("=")
        if not sep:
            query.append("[redacted]")
        elif unquote_plus(key).lower() in PUBLIC_QUERY:
            query.append(key + "=" + ("[redacted]" if SECRET_SHAPE.search(unquote_plus(value)) else value))
        else:
            query.append(SECRET_SHAPE.sub("[redacted]", key) + "=[redacted]")
    safe = urlunsplit((url.scheme, authority, path, "&".join(query),
                       "[redacted]" if url.fragment else ""))
    return getter + SECRET_SHAPE.sub("[redacted]", safe)


def redact(line, *, syntax="hcl"):
    """Redact a line; only HCL may treat reference-shaped values as public."""
    matches = list(_secret_fields(line))
    safe = SAFE_VALUE if syntax == "hcl" else SAFE_SCALAR
    for i, match in enumerate(matches):
        rest_to_end = line[match.end():].strip()
        if not rest_to_end or safe.fullmatch(rest_to_end):
            continue
        if SETTING_KEY.search(match.group()) and SETTING_VALUE.fullmatch(rest_to_end):
            continue
        if i + 1 < len(matches):
            rest_to_next = line[match.end():matches[i + 1].start()].strip()
            if safe.fullmatch(rest_to_next):
                continue
        # Only complete references/booleans are safe, not expressions that
        # happen to start with a reference and then contain a literal value.
        line = line[:match.end()] + " [redacted]"
        break
    if KEY_MARKER.search(line):
        return "[redacted]"
    line = URL.sub(lambda m: module_source(m.group(0)), line)
    return SECRET_SHAPE.sub("[redacted]", line)


def _open_quote(text):
    """The quote still open at the end of text, or None.

    A key-like match inside a string ("secretsmanager:GetSecretValue") is
    followed by that string's closing quote; read as an opening quote, it
    carried the value on to every following line.
    """
    quote, escaped = None, False
    for char in text:
        if escaped:
            escaped = False
        elif quote and char == "\\":
            escaped = True
        elif quote:
            quote = None if char == quote else quote
        elif char in "\"'":
            quote = char
        elif char == "#":
            break
    return quote


class _Value:
    """Track quoted/composite values that continue after a sensitive key."""
    def __init__(self, quote=None):
        self.stack = []
        self.quote = quote
        self.escaped = False
        self.started = False
        self.trailing_op = False

    def feed(self, text):
        for n, char in enumerate(text):
            if self.quote:
                self.trailing_op = False
                if self.escaped:
                    self.escaped = False
                elif char == "\\":
                    self.escaped = True
                elif self.quote == '"' and char == "{" and n > 0 and text[n - 1] in "$%":
                    sig = text[n - 1]
                    k = n - 1
                    while k >= 0 and text[k] == sig:
                        k -= 1
                    if (n - 1 - k) % 2 == 1:
                        self.stack.append("${")
                        self.quote = None
                elif char == self.quote:
                    self.quote = None
            elif char == '"' or (char == "'" and "${" not in self.stack):
                self.quote = char
                self.trailing_op = False
            elif char == "#" or text[n:n + 2] == "//":
                break
            elif char.isspace():
                continue
            elif char in "([{":
                self.stack.append(char)
                self.trailing_op = False
            elif char in ")]}":
                if char == "}" and self.stack and self.stack[-1] == "${":
                    self.stack.pop()
                    self.quote = '"'
                elif self.stack and self.stack[-1] == {")": "(", "]": "[", "}": "{"}[char]:
                    self.stack.pop()
                self.trailing_op = False
            else:
                self.trailing_op = char in "?:+"
            self.started = True
        # Whitespace/comments before the first token do not complete a value.
        return not self.started or bool(self.stack or self.quote or self.trailing_op)


def redact_lines(lines, *, syntax="hcl"):
    """Redact before slicing excerpts, preserving the original line numbers.

    A finding can point into the middle of a PEM or heredoc. Processing the
    whole file first keeps a start marker outside the excerpt effective.
    """
    result = []
    pem = False
    heredoc = None
    block_indent = None
    indentless = False
    value = None
    for line in lines:
        # A line hidden by an earlier composite value can also start another
        # secret heredoc. Find every key before line hiding skips that boundary.
        start_heredoc = None
        if syntax == "hcl" and not pem and heredoc is None and not (value and value.quote):
            for match in _secret_fields(line):
                start = HEREDOC.fullmatch(line[match.end():].strip())
                if start:
                    start_heredoc = start.group(1)
                    break
        private = pem
        for marker in KEY_MARKER.finditer(line):
            private = True
            pem = marker.group(1) == "BEGIN"
        hidden = private
        if heredoc is not None:
            hidden = True
            if line.strip() == heredoc:
                heredoc = None
        elif value is not None:
            hidden = True
            if not value.feed(line):
                value = None
        if block_indent is not None:
            indent = len(line) - len(line.lstrip())
            same_level_item = (indentless and indent == block_indent and
                               re.match(r"-(?:\s|$)", line.lstrip()))
            content = line.strip() and not (syntax == "yaml" and line.lstrip().startswith("#"))
            if content and indent <= block_indent and not same_level_item:
                block_indent = None
            else:
                hidden = True
        if heredoc is None and value is None and block_indent is None and not private:
            for match in reversed(list(_secret_fields(line))):
                rest = line[match.end():].strip()
                start = HEREDOC.fullmatch(rest)
                if start:
                    heredoc = start.group(1)
                    break
                if not rest or rest.startswith("#") or re.fullmatch(r"[|>][1-9+-]*(?:\s+#.*)?", rest):
                    block_indent = len(line) - len(line.lstrip())
                    empty = not rest or rest.startswith("#")
                    indentless = syntax == "yaml" and empty
                    if empty and syntax != "yaml":
                        # JSON permits a value on the next line at any indent.
                        # YAML instead follows its mapping/list indentation.
                        value = _Value()
                    break
                # Inside a string closed later on this line with text after the
                # key ("secretsmanager:GetSecretValue"]), the value ends with that
                # string. Otherwise ("export DB_PASSWORD=", then the value as the
                # next list item; an apostrophe in a comment) keep the tracker as
                # it was: hiding the following lines is the safe reading.
                quote = _open_quote(line[:match.end()])
                inside = rest.split(quote, 1)[0] if quote and quote in rest else ""
                pending = _Value(quote if re.search(r"[A-Za-z0-9]", inside) else None)
                if pending.feed(rest):
                    value = pending
                    break
        if start_heredoc is not None:
            heredoc = start_heredoc
        result.append("[redacted]" if hidden else redact(line, syntax=syntax))
    return result


# ---------------------------------------------------------------- excerpt scrub
#
# Key-based redaction above recognises secrets by the field that holds them.
# Excerpts also carry free text: comments, script bodies, flags, connection
# strings and names in neighbouring lines. This last pass is deliberately
# broad: an excerpt that loses a value is acceptable, a leaked value is not.

# Secret words bounded by non-letters: db_pass, DB_PASS, admin_pw, STRIPE_SK,
# client-key-data, Authorization; not bypass, disk, authorized_networks or
# aws_secretsmanager (the trailing letters continue the word).
SECRET_WORD = re.compile(
    r"(?i)(?<![a-z])((?:pg|db|my|admin|root|user|app|master)?pass(?:word|wd|phrase)?|pwd|pw|"
    r"secrets?|tokens?|auth(?:orization)?|user[-_]?data(?:[-_]base64)?|startup[-_]?script|custom[-_]?data|"
    r"credentials?|private[-_]?key|api[-_]?key|access[-_]?key|client[-_]?key|bearer|sk|"
    r"tls\.key|ssh[-_]?key|(?:signing|hmac|jwt|session|app)[-_]?key)(?![a-z])")
# Public spellings that contain a secret word but name no secret.
PUBLIC_WORDS = re.compile(r"(?i)token\.actions\.githubusercontent\.com|kms[-_]?key|http[-_]?tokens|secretsmanager|"
                          r"block[-_]project[-_]ssh[-_]keys|authori[sz]ation[-_]scopes|"
                          r"authori[sz]ation[-_]type|auth[-_]?type|authorizer[\w-]{0,64}|"
                          r"token[-_](?:endpoint|url|uri|ttl|lifetime|expiry)|"
                          r"(?:secret|token|auth)[\w-]{0,64}\.(?:arn|id|name)\b")
# The subset that names a credential value, used to judge a whole document
# (name/value pairs, plan variables). "auth-service" or "user_data" in a
# name says nothing about its value, so those words only scrub single lines.
CREDENTIAL_WORD = re.compile(
    r"(?i)(?<![a-z])((?:pg|db|my|admin|root|user|app|master)?pass(?:word|wd|phrase)?|pwd|pw|"
    r"secrets?|tokens?|credentials?|private[-_]?key|api[-_]?key|access[-_]?key|client[-_]?key|"
    r"bearer|sk|tls\.key|ssh[-_]?key|(?:signing|hmac|jwt|session|app)[-_]?key)(?![a-z])")
MAX_SCRUB = 2000  # longer lines (minified JSON) are hidden whole: linear time, nothing to read
STRUCTURE = re.compile(r'^\s*(?:resource|data|module|variable|output|provider|dynamic)\b[^=]*\{\s*$|'
                       r'^\s*(?:kind|type|Type)\s*:\s*"?[\w:.-]+"?\s*,?\s*$')
SAFE_TAIL = re.compile(r'\s*(?:[:=]\s*)?"?(?:true|false|null|none|NONE|AWS_IAM|IAM|CUSTOM|JWT|'
                       r'COGNITO_USER_POOLS|[0-9]+)"?\s*,?\s*$')
ENTROPY = re.compile(r"[A-Za-z0-9+_-]{16,}")
# A base64 key is one token: ENTROPY alone splits it at "/" and "=" into
# pieces too short or too plain to judge, leaving long runs of the key.
BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])")
# Cloud resource IDs and ARNs are long and mixed but name no secret.
RESOURCE_ID = re.compile(r"(?:ami|sg|subnet|vpc|i|vol|snap|eni|igw|nat|rtb|acl|pcx|tgw|lt|eipalloc|"
                         r"vpce|fs|db|cluster|key|sgr)-[0-9a-f]{8,17}|[a-z0-9-]+_[a-z0-9_]+", re.IGNORECASE)
# Linear alternatives: userinfo without a slash, possibly with an escaped
# quote or a space inside (postgres://app:a\"b@db, postgres://app:a b@db).
URL_USERINFO = re.compile(r"://[^/\s\"'@]*(?:\\\"[^/\s\"'@]*)*@|://[^/\"'@]*\s[^/\"'@]*@")
# Go's DSN names its transport after the @: app:pw@tcp(db:3306)/name.
BARE_USERINFO = re.compile(r'(?<=["\'\s=])([\w.%+-]+):([^"\'\s@/]+)@(?=[\w.-]+[:/"\'\s(]|[\w.-]+$)')
# Oracle EZConnect and JDBC thin: scott/pw@db:1521/ORCL. Not an image digest
# (library/nginx@sha256:...).
SLASH_USERINFO = re.compile(r'(?<=["\'\s:=])([\w.$-]+)/([^"\'\s@/]+)@(?!sha\d+:)(?=[\w.-]+[:/])')
SHELL_PASSWORD = re.compile(r"(?<!\S)(--password[= ]|--pass[= ]|--token[= ])(?=\S)(\S+)")
DB_CLIENT = re.compile(r"\b(?:mysql|mysqldump|mariadb|psql|mongo|mongosh|redis-cli)\b")
CLIENT_PASSWORD = re.compile(r"(?<!\S)(-p|-P|-a)(?=\S)(\S+)")
# redis-cli -a takes the password as the next argument, also in a JSON or
# YAML flow list: ["redis-cli", "-a", "x"].
REDIS_AUTH = re.compile(r"""(?<![\w-])(-a|--pass|--askpass)(["']?\s*,?\s*["']?)([^"'\s,\]]+)""")
SCP_USER = re.compile(r'((?:^|["\s=(])(?:[A-Za-z][A-Za-z0-9+.-]*::)?)([^\s"\'@/:]+)@(?!sha\d+:)(?=[\w.-]+:)')
WEBHOOK = re.compile(r"hooks\.slack\.com/services/\S+|discord(?:app)?\.com/api/webhooks/\S+", re.IGNORECASE)
UNICODE_ESCAPE = re.compile(r"(?<!\\)\\u([0-9A-Fa-f]{4})")
# curl -u user:password, --user user:password, wget --http-user ... style pairs.
# Option and value may be attached (-uadmin:pw), spaced, or separate exec-form
# list elements ("-u", "admin:pw"). A numeric uid:gid (docker -u 1000:1000) is no password.
OPTION_GAP = r"""(?:\s+|=|["']\s*,\s*)?\\?["']?"""
USER_PASSWORD = re.compile(rf"""((?<![\w-])["']?(?:-u|--user|--proxy-user){OPTION_GAP})([^\s:"'@,\\]+:)"""
                           r"""("[^"\s,][^"]*"?|'[^'\s,][^']*'?|(?=[^\s"'\\])[^\s"',\]\\]+)""")
# Tools that take a password as an option's value; docker/podman only for login
# (their -p elsewhere maps ports).
TOOL_LOGIN = re.compile(r"\b(?:sshpass|ldap(?:search|add|modify|delete|passwd)|smbclient|mysqladmin|"
                        r"(?:docker|podman|nerdctl|buildah|skopeo|oras|helm|az|crane)\b[^|;&]*\blogin)\b|"
                        r"\bopenssl\b")
TOOL_PASSWORD = re.compile(r"""((?<![\w-])["']?(?:-passin|-passout|-pass|--password|--pass|-p|-w|-k|-P)"""
                           r"""(?:\s+|=|["']\s*,\s*)\\?["']?)(?=[^\s"'\\])([^\s"',\]\\]+)""")
PROCESS_USER = re.compile(r"\b(?:docker|podman|nerdctl|kubectl|crictl|ctr|sudo|runuser|chroot|buildah)\b|"
                          r"\b(?:user|runAsUser|runAsGroup)\s*[:=]")
HTTP_CLIENT = re.compile(r"\b(?:curl|wget|http|httpie|xh|ftp|lftp|svn|git)\b|://")
SSHPASS_ATTACHED = re.compile(r"(\bsshpass\s+(?:-[a-zA-Z]\s+)*-p)(?=\S)([^\s\"']+)")
# A secret piped into a command that reads it from stdin precedes the keyword
# (echo X | docker login --password-stdin), so the keyword check misses it.
STDIN_SINK = re.compile(r"--password-stdin|--with-token\b|\bchpasswd\b|\bpasswd\b|--stdin\b|"
                        r"\bsudo\s+(?:-[a-zA-Z]+\s+)*-[a-zA-Z]*S|\blogin\s+-(?![\w-])")
# htpasswd -b FILE USER PASSWORD (or -nb USER PASSWORD) takes the password as an argument.
HTPASSWD_ARG = re.compile(r"(\bhtpasswd\s+(?:-[a-zA-Z]+\s+)*-[a-zA-Z]*b[a-zA-Z]*\s+(?:\S+\s+)+?)"
                          r"(\S+)(?=\s*(?:[\"';|&)]|$))")
PIPED_VALUE = re.compile(r"\b((?:echo|printf)\s+(?:-[a-zA-Z]+\s+)*)([^|\s][^|]*?)(\s*\|)")
# crypt(3), htpasswd and bcrypt hashes: crackable offline, and their "." and
# "/" split them into runs too short for the entropy check.
CRYPT_HASH = re.compile(r"\$(?:1|2[abxy]?|5|6|y|apr1|argon2(?:id|i|d))\$[^\s:'\"]+")
PUTTY = re.compile(r"PuTTY-User-Key-File-\d|^\s*Private-Lines:", re.IGNORECASE)


def _base64_key(token):
    """Base64 rather than a path: "+" or padding, or slashes as rare as in
    random data (about 1 in 64; a path has one every few characters)."""
    if len(token) < 24:  # a 16-byte key is 22 characters and "=="
        return False
    shaped = "+" in token or token.endswith("=") or (
        "/" in token and len(token) >= 40 and token.count("/") <= len(token) // 16)
    letters = re.sub(r"[+/=]", "", token)
    # Random characters switch between upper, lower and digit about 63% of
    # the time; CamelCase names (AmazonAPIGatewayPushToCloudWatchLogs) 20-30%.
    # 32 random bytes carry no digit about once in a thousand keys.
    kinds = ["u" if c.isupper() else "l" if c.islower() else "d" for c in letters]
    switches = sum(a != b for a, b in zip(kinds, kinds[1:]))
    return shaped and switches >= len(letters) * 0.45 and (_high_entropy(letters) or (
        len(token) >= 40 and letters != letters.lower() and letters != letters.upper()))


def _high_entropy(token):
    """Random-looking: mixed case with digits, long hex, or long letter-digit runs.

    Names such as my-bucket-2024-prod or k8s-node-group-v2 stay readable.
    """
    if RESOURCE_ID.fullmatch(token):
        return False
    upper = any(c.isupper() for c in token)
    lower = any(c.islower() for c in token)
    digits = sum(c.isdigit() for c in token)
    letters = sum(c.isalpha() for c in token)
    return (upper and lower and digits >= 1) or re.fullmatch(r"[0-9a-fA-F]{32,}", token) is not None or (
        len(token) >= 24 and digits >= 4 and letters >= 4 and "-" not in token and "_" not in token)


DATED_NAME = re.compile(r"[A-Za-z]*-?[0-9]{4}-[0-9]{2}-[0-9]{2}")


def _value_quote(line, start):
    """The quote that encloses the argument holding line[start], or None.

    The argument is the token around start: "admin:a b" or "-uadmin:a b" or an
    escaped \\"admin:a b\\" inside an HCL string; -p"a b" quotes the value itself.
    """
    if line[start:start + 1] in ("\"", "'"):
        return line[start], start + 1
    token = start
    while token > 0 and line[token - 1] not in " \t[,(=":
        token -= 1
    if line[token:token + 1] in ("\"", "'"):
        return line[token], start
    if line[token:token + 2] in ("\\\"", "\\'"):
        return line[token:token + 2], start
    return None, start


def _closing_quote(line, quote, start):
    """Index of the quote that closes an argument opened by quote, or -1.

    In a shell, a backslash escapes a double quote (an odd run before it) and
    nothing escapes a single quote. Inside an HCL string the argument opens with
    an escaped quote, so exactly one backslash marks its close.
    """
    char = quote[-1]
    for i in range(start, len(line)):
        if line[i] != char:
            continue
        j = i
        while j > 0 and line[j - 1] == "\\":
            j -= 1
        run = i - j
        if char == "'" or (run == 1 if len(quote) == 2 else run % 2 == 0):
            return i - len(quote) + 1
    return -1


def _shell_word_end(line, start, end):
    """End of the unquoted shell word holding line[start:end]. A backslash escapes
    the next character (admin:pfx\\ secret is one argument), and a quoted part
    joined to the word continues it (admin:pfx"a secret"). A quote that is never
    closed on the line ends the word: it closes a string the word sits in."""
    i, n = start, len(line)
    while i < n and (i < end or line[i] not in " \t,]"):
        c = line[i]
        if c == "\\" and i + 1 < n:
            i += 2
        elif c in "\"'" and i >= end:
            close = _closing_quote(line, c, i + 1)
            if close == -1:
                break
            i = close + 1
        else:
            i += 1
    return max(end, i)


def _redact_values(pattern, line, group, keep=lambda m: False):
    """Replace each match's value group with [redacted], through its closing quote.

    A quoted value may hold spaces ("admin:pfx secret"), so redacting only the
    pattern's unspaced run would leave the rest of the credential in the excerpt.
    """
    out, pos = [], 0
    for m in pattern.finditer(line):
        if m.start() < pos or keep(m):
            continue
        start, end = m.start(group), m.end(group)
        quote, search = _value_quote(line, start)
        if quote:
            close = _closing_quote(line, quote, search)
            end = max(end, len(line) if close == -1 else close)
        else:
            end = _shell_word_end(line, start, end)
        out.append(line[pos:start] + "[redacted]")
        pos = end
    out.append(line[pos:])
    return "".join(out)


def _entropy(match):
    # A commit pinned with ?ref= is evidence (PS-001), not a secret.
    if match.string[max(0, match.start() - 4):match.start()] == "ref=":
        return match.group()
    # Date-versioned names are public (AWS::Serverless-2016-10-31, 2012-10-17).
    if DATED_NAME.fullmatch(match.group()):
        return match.group()
    return "[redacted]" if _high_entropy(match.group()) else match.group()


# IAM member prefixes name an identity, not credentials (user:alice@example.com).
MEMBER_PREFIX = {"user", "group", "serviceaccount", "domain", "principal", "principalset", "deleted"}


def scrub_line(line, syntax="hcl"):
    if line == "[redacted]" or not line.strip():
        return line
    if len(line) > MAX_SCRUB:
        return "[redacted]"
    line = WEBHOOK.sub("[redacted]", line)
    line = URL_USERINFO.sub("://[redacted]@", line)
    line = BARE_USERINFO.sub(lambda m: m.group() if m.group(1).lower() in MEMBER_PREFIX
                             else m.group(1) + ":[redacted]@", line)
    line = SLASH_USERINFO.sub(lambda m: m.group(1) + "/[redacted]@", line)
    line = _redact_values(SHELL_PASSWORD, line, 2)
    # A numeric uid:gid only where -u/--user selects a process user (docker run -u 1000:1000);
    # curl -u 123:456 is a password all the same.
    process_user = PROCESS_USER.search(line) is not None and not HTTP_CLIENT.search(line)
    line = _redact_values(USER_PASSWORD, line, 3,
                          lambda m: process_user and (m.group(2)[:-1] + m.group(3)).isdigit())
    line = _redact_values(SSHPASS_ATTACHED, line, 2)
    if TOOL_LOGIN.search(line):
        line = _redact_values(TOOL_PASSWORD, line, 2)
    line = CRYPT_HASH.sub("[redacted]", line)
    line = HTPASSWD_ARG.sub(lambda m: m.group(1) + "[redacted]", line)
    if STDIN_SINK.search(line):
        line = PIPED_VALUE.sub(lambda m: m.group(1) + "[redacted]" + m.group(3), line)
    if DB_CLIENT.search(line):  # mysql -pX; not -port=8080 elsewhere
        line = _redact_values(CLIENT_PASSWORD, line, 2)
        if "redis-cli" in line:
            line = _redact_values(REDIS_AUTH, line, 3)
    line = SCP_USER.sub(lambda m: m.group(1) + ("git" if m.group(2) == "git" else "[redacted]") + "@", line)
    line = BASE64_TOKEN.sub(lambda m: "[redacted]" if _base64_key(m.group()) else m.group(), line)
    line = ENTROPY.sub(_entropy, line)
    decoded = UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), line)
    probe = PUBLIC_WORDS.sub(lambda m: "_" * len(m.group()), SECRET_ARN.sub(lambda m: "_" * len(m.group()), decoded))
    match = SECRET_WORD.search(probe)
    if match and not STRUCTURE.match(line):
        if decoded != line:
            return line[:len(line) - len(line.lstrip())] + "[redacted]"
        # Keep the whole key (authorization_type) and judge only its value.
        end = match.end() + len(re.match(r"[\w.-]*[\"']?", line[match.end():]).group())
        rest = line[end:]
        value = re.sub(r"^\s*[:=]\s*", "", rest)
        # Complete Terraform references name no value; "[redacted]" is ours.
        public = SAFE_TAIL.fullmatch(rest) or value.strip() == "[redacted]" or (
            syntax == "hcl" and SAFE_VALUE.fullmatch(value))
        if re.search(r"[A-Za-z0-9]", rest) and not public:
            line = line[:end] + " [redacted]"
    return line


def _is_safe_json_block(body_lines):
    body = "\n".join(body_lines).strip()
    if not body.startswith(("{", "[")):
        return False
    try:
        doc = json.loads(body, object_pairs_hook=unique_object)
    except (ValueError, RecursionError):
        return False
    raw_lines = list(body_lines)
    return (not has_escaped_secret_keys(body, [doc]) and not has_structured_secrets(doc)
            and redact_json_values("\n".join(raw_lines), raw_lines) == raw_lines)


def scrub_lines(lines, syntax="hcl", original=None):
    """Hide script and text bodies, comments, secret-word lines and opaque tokens.

    Heredoc and YAML block-scalar bodies are hidden unless they hold JSON (an
    inline policy document), whose lines are scrubbed one by one.
    """
    out = []
    heredoc = block = None
    putty = continued = False
    lines = list(lines)
    original = lines if original is None else list(original)
    for idx, (line, source) in enumerate(zip(lines, original)):
        if continued:
            # A backslash continuation of a line whose value was hidden.
            out.append("[redacted]")
            continued = source.rstrip().endswith("\\")
            continue
        if putty:
            out.append("[redacted]")
            putty = not re.match(r"\s*Private-MAC:", line)
            continue
        if PUTTY.search(line):
            out.append("[redacted]")
            putty = True
            continue
        # Structure (terminators, indentation) comes from the source line; an
        # earlier pass may already have replaced the text with "[redacted]".
        if heredoc is not None:
            term, opaque = heredoc
            if source.strip() == term:
                heredoc = None
                out.append(line)
            else:
                out.append("[redacted]" if opaque else scrub_line(line, "json") if line.strip() else line)
            continue
        if block is not None:
            indent, opaque = block
            current = len(source) - len(source.lstrip())
            if not source.strip():
                out.append(line)
                continue
            if current > indent:
                out.append("[redacted]" if opaque else scrub_line(line, "json"))
                continue
            block = None
        out.append(scrub_line(line, syntax))
        continued = source.rstrip().endswith("\\") and (
            "[redacted]" in out[-1] or SECRET_WORD.search(PUBLIC_WORDS.sub("_", source)) is not None)
        # Openers come from the source: an earlier pass may have replaced
        # "password = trimspace(<<EOF" with "password = [redacted]".
        line = source
        if line.lstrip().startswith(("#", "//")):
            continue  # an opener inside a comment opens nothing
        start = re.search(r"<<-?\s*([A-Za-z_][A-Za-z0-9_-]*)\s*$", line)
        if syntax == "hcl" and start:
            term = start.group(1)
            end_idx = next((j for j in range(idx + 1, len(original)) if original[j].strip() == term), len(original))
            heredoc = (term, not _is_safe_json_block(original[idx + 1:end_idx]))
        elif syntax == "yaml" and re.search(r"(?:^|:\s|-\s)\s*[|>][1-9+-]*\s*(?:#.*)?$", line):
            indent = len(line) - len(line.lstrip())
            body_lines = []
            for next_line in original[idx + 1:]:
                if next_line.strip() and (len(next_line) - len(next_line.lstrip())) <= indent:
                    break
                body_lines.append(next_line)
            block = (indent, not _is_safe_json_block(body_lines))
    return out
