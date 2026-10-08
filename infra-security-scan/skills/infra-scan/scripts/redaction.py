"""Conservative redaction for values copied into scan outputs (stdlib only)."""
import re
from urllib.parse import unquote_plus, urlsplit, urlunsplit


SECRET_FIELD = re.compile(
    r"(?i)(?<![\w/?&.-])[\w/.-]*(password|passwd|secret|token|private[-_]?key|access[-_]?key|api[-_]?key|"
    r"client[-_]?secret|connection[-_]?string|credentials?)[\w/.-]*[\"']?\s*[:=]")
SECRET_SHAPE = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|"
                          r"github_pat_[A-Za-z0-9_]+|xox[baprs]-[A-Za-z0-9-]+")
KEY_MARKER = re.compile(r"-----(BEGIN|END) (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")
SAFE_VALUE = re.compile(
    r"(?:(?:(?:var|local|data|module)\.|(?:aws_|google_))[\w.\[\]-]+|null|true|false)"
    r"\s*[,}]?\s*$")
HEREDOC = re.compile(r"<<-?\s*([A-Za-z_][A-Za-z0-9_-]*)\s*$")
URL = re.compile(r"(?<![A-Za-z0-9+.-])(?:[A-Za-z][A-Za-z0-9+.-]*::)?"
                 r"[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>]+")
# These getter options identify a revision or limit its history. Other query
# values can be credentials (including signed storage URLs), so omit them.
PUBLIC_QUERY = {"ref", "depth", "version"}
SENSITIVITY_MASKS = {"sensitive_values", "before_sensitive", "after_sensitive"}


def _secret_field(line):
    # Qualified YAML/JSON keys can contain slashes. A URL path or query is
    # handled by module_source instead of being mistaken for such a key.
    urls = [match.span() for match in URL.finditer(line)]
    return next((match for match in SECRET_FIELD.finditer(line)
                 if not any(start <= match.start() < end for start, end in urls)), None)


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
    if value.get("kind") == "SecretList":
        return True  # Typed list items may omit their own kind: Secret.
    if value.get("kind") == "Secret" and any(key in value for key in ("data", "stringData")):
        return True
    # Covers Kubernetes env entries and other literal name/value collections,
    # including a value that precedes its name in the source.
    if "name" in value and "value" in value:
        name = value["name"]
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


def redact(line):
    """Redact a single line; use redact_lines for a source file's excerpts."""
    match = _secret_field(line)
    if match:
        rest = line[match.end():].strip()
        # Only complete references/booleans are safe, not expressions that
        # happen to start with a reference and then contain a literal value.
        if rest and not SAFE_VALUE.fullmatch(rest):
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


def redact_lines(lines):
    """Redact before slicing excerpts, preserving the original line numbers.

    A finding can point into the middle of a PEM or heredoc. Processing the
    whole file first keeps a start marker outside the excerpt effective.
    """
    result = []
    pem = False
    heredoc = None
    block_indent = None
    value = None
    for line in lines:
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
            if line.strip() and indent <= block_indent:
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
                    if not rest or rest.startswith("#"):
                        # JSON permits a value on the next line at any indent.
                        value = _Value()
                else:
                    pending = _Value()
                    if pending.feed(rest):
                        value = pending
        result.append("[redacted]" if hidden else redact(line))
    return result
