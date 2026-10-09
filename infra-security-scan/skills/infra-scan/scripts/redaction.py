"""Conservative redaction for values copied into scan outputs (stdlib only)."""
import bisect
import json
import re
from urllib.parse import unquote_plus, urlsplit, urlunsplit


SECRET_FIELD = re.compile(
    r"(?i)(?<![\w/?&.-])[\w/.-]*(password|passwd|secret|token|private[-_]?key|access[-_]?key|api[-_]?key|"
    r"client[-_]?secret|connection[-_]?string|credentials?)[\w/.-]*[\"']?\s*[:=]")
SECRET_SHAPE = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|"
                          r"github_pat_[A-Za-z0-9_]{20,}|xox[abeoprs]-[A-Za-z0-9-]+|"
                          r"xapp-[0-9]-[A-Za-z0-9-]+|AIza[0-9A-Za-z_-]{35}|"
                          r"glpat-[A-Za-z0-9_-]{20}")
# PEM and OpenSSH use five dashes; RFC 4716 (SSH2) uses four and spaces.
KEY_MARKER = re.compile(r"-{4,5} ?(BEGIN|END) (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)? ?-{4,5}")
SAFE_VALUE = re.compile(
    r"(?:(?:(?:var|local|data|module)\.|(?:aws_|google_))[\w.\[\]-]+|null|true|false)"
    r"\s*[,}]?\s*$")
SAFE_SCALAR = re.compile(r"(?:null|true|false)\s*[,}]?\s*$")
HEREDOC = re.compile(r"<<-?\s*([A-Za-z_][A-Za-z0-9_-]*)\s*$")
# Apostrophes are valid in URL userinfo. Keep it through the last @ so a
# surrounding string's quote cannot cut off credentials before module_source.
URL = re.compile(r"(?<![A-Za-z0-9+.-])(?:[A-Za-z][A-Za-z0-9+.-]*::)?"
                 r"[A-Za-z][A-Za-z0-9+.-]*://(?:[^/\s\"<>]*@)?[^\s\"'<>]+")
QUOTED_KEY = re.compile(r'("(?:\\.|[^"\\])*")\s*:')
JSON_STRING = re.compile(r'"(?:\\.|[^"\\])*"')
# These getter options identify a revision or limit its history. Other query
# values can be credentials (including signed storage URLs), so omit them.
PUBLIC_QUERY = {"ref", "depth", "version"}
SENSITIVITY_MASKS = {"sensitive_values", "before_sensitive", "after_sensitive"}


def _secret_fields(line):
    # Qualified YAML/JSON keys can contain slashes. A URL path or query is
    # handled by module_source instead of being mistaken for such a key.
    urls = [match.span() for match in URL.finditer(line)]
    return (match for match in SECRET_FIELD.finditer(line)
            if not any(start <= match.start() < end for start, end in urls))


def _secret_field(line):
    return next(_secret_fields(line), None)


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
    if value.get("kind") == "SecretList":
        return True  # Typed list items may omit their own kind: Secret.
    if value.get("kind") == "Secret" and any(key in value for key in ("data", "stringData")):
        return True
    # Covers Kubernetes env entries, CloudFormation Name/Value and Key/Value
    # pairs and other literal collections, including a value that precedes its
    # name in the source. CloudFormation capitalizes these keys.
    keys = {key.lower(): key for key in value if isinstance(key, str)}
    if "value" in keys:
        for label in ("name", "key"):
            if label in keys:
                name = value[keys[label]]
                if not isinstance(name, str) or _secret_field(name + ":"):
                    return True
    if "env" in value and value["env"] is not None:
        entries = value["env"]
        if not isinstance(entries, (dict, list)):
            return True  # Opaque block strings and unknown env expressions.
        # Check decoded keys too; a JSON/YAML escape can hide a secret name
        # from line redaction. Env strings such as "var.password" are literal
        # values, so Terraform's SAFE_VALUE reference exception does not apply.
        if isinstance(entries, dict) and any(
                not isinstance(name, str) or _secret_field(name + ":") for name in entries):
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
    for line in text.splitlines(keepends=True):
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
    match = _secret_field(line)
    if match:
        rest = line[match.end():].strip()
        # Only complete references/booleans are safe, not expressions that
        # happen to start with a reference and then contain a literal value.
        safe = SAFE_VALUE if syntax == "hcl" else SAFE_SCALAR
        if rest and not safe.fullmatch(rest):
            line = line[:match.end()] + " [redacted]"
    if KEY_MARKER.search(line):
        return "[redacted]"
    line = URL.sub(lambda m: module_source(m.group(0)), line)
    return SECRET_SHAPE.sub("[redacted]", line)


class _Value:
    """Track quoted/composite values that continue after a sensitive key."""
    def __init__(self):
        self.stack = []
        self.quote = None
        self.escaped = False
        self.started = False

    def feed(self, text):
        for n, char in enumerate(text):
            if self.quote:
                if self.escaped:
                    self.escaped = False
                elif char == "\\":
                    self.escaped = True
                elif char == self.quote:
                    self.quote = None
            elif char in "\"'":
                self.quote = char
            elif char == "#" or text[n:n + 2] == "//":
                break
            elif char.isspace():
                continue
            elif char in "([{":
                self.stack.append(char)
            elif char in ")]}":
                if self.stack and self.stack[-1] == {")": "(", "]": "[", "}": "{"}[char]:
                    self.stack.pop()
            self.started = True
        # Whitespace/comments before the first token do not complete a value.
        return not self.started or bool(self.stack or self.quote)


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
        if not hidden:
            match = _secret_field(line)
            if match:
                rest = line[match.end():].strip()
                start = HEREDOC.fullmatch(rest)
                if start:
                    heredoc = start.group(1)
                elif not rest or rest.startswith("#") or re.fullmatch(r"[|>][1-9+-]*(?:\s+#.*)?", rest):
                    block_indent = len(line) - len(line.lstrip())
                    empty = not rest or rest.startswith("#")
                    indentless = syntax == "yaml" and empty
                    if empty and syntax != "yaml":
                        # JSON permits a value on the next line at any indent.
                        # YAML instead follows its mapping/list indentation.
                        value = _Value()
                else:
                    pending = _Value()
                    if pending.feed(rest):
                        value = pending
        if start_heredoc is not None:
            heredoc = start_heredoc
        result.append("[redacted]" if hidden else redact(line, syntax=syntax))
    return result
