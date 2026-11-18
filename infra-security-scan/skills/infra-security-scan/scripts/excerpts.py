"""Source excerpts for the reports: which cited lines are safe to show, redacted.

attach_sources() opens each finding's `path:line` under the assessed
repository and returns the lines around it, or nothing when the file, its
module or its document could carry a secret: state, variable and key files,
sensitive Terraform declarations and the values they reach, structured
secrets in JSON/YAML, and exports. What it returns is redacted line by line
(redaction.py). render.py imports this module only when --repo is given, so
the record tools (findings.py, contract_check.py) never load the scanner's
parsers.
"""
import json
from pathlib import Path
import posixpath
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also under python -I
from common import LOCATION, STATE_FILE, split_yaml_documents, unique_object  # noqa: E402
from iac_scan import (Block, HEREDOC, IDENT, LineIndex, MAX_BYTES, MAX_HCL_DEPTH, SKIP_DIRS, UNKNOWN,  # noqa: E402
                      _Lit, _YamlSubset, heredoc_span, is_export, literal, parse_body, parse_hcl,
                      skip_balanced, skip_space, skip_string, unquote)
from redaction import (SAFE_VALUE, SETTING_NAME, contextual_secret_fields, has_contextual_secrets,  # noqa: E402
                       has_escaped_secret_keys, has_structured_secrets, is_secret_name,
                       redact_json_values, redact_lines, scrub_lines, split_lines)


# Terraform names state backups terraform.tfstate.<timestamp>.backup; dotenv
# files carry an environment suffix (.env.production).
SENSITIVE_NAME = re.compile(r"(\.tfvars(\.json)?|\.pem|\.key|\.p12|\.pfx|\.ppk|\.jks|\.keystore|\.env)$|"
                            + STATE_FILE.pattern + r"|\.env\.[^/]*$|\.envrc$|secret|credential|"
                            r"id_(rsa|dsa|ecdsa|ed25519)|netrc|\.npmrc|\.pypirc|\.pgpass|kubeconfig|"
                            r"\.dockercfg|(^|/)\.docker/config\.json$|htpasswd|(^|/)g?shadow-?$", re.IGNORECASE)


def hcl_declares_sensitive(text):
    """Only a known false variable/output declaration permits its source."""
    for block in parse_hcl(text):
        if block.type in ("variable", "output") and "sensitive" in block.attrs:
            raw, _ = block.attrs["sensitive"]
            if literal(raw) is not False:
                return True
    return False


HCL_MARKED_SECRET = re.compile(
    r'(?<![\w.])sensitive\s*\(|\bephemeral\s*=\s*true\b|"SecureString"|'
    r'resource\s+"(?:kubernetes_secret(?:_v1)?|aws_secretsmanager_secret_version|'
    r'google_secret_manager_secret_version)"')
HCL_NAME = re.compile(r'(?i)(?<![\w.-])"?(?:name|key|parameter_?key)"?\s*[=:]\s*"([^"\n]*)"')
HCL_VALUE = re.compile(r'(?i)(?<![\w.-])"?(?:value|parameter_?value)"?\s*[=:]')
# A name computed by an expression (var.db_password_env_name): it may name a secret.
HCL_EXPR_NAME = re.compile(r'(?i)(?<![\w.-])"?(?:name|key|parameter_?key)"?\s*[=:]\s*[^"\s]')


class _HclExpression:
    """An unresolved leaf, retaining its expression rather than losing its refs."""
    def __init__(self, raw):
        self.raw = raw


class _HclSet:
    """Retain set iteration semantics even when its elements are unresolved."""
    def __init__(self, value):
        self.value = value


_HCL_TEMPLATE = re.compile(r"(?<!\$)\$\{|(?<!%)%\{")


class _HclLiteral(_Lit):
    def primary(self, multiline=False, depth=0):
        start = self.i
        value = super().primary(multiline, depth)
        if self.s.startswith("toset(", start):
            return _HclSet(value)
        if self.s.startswith("tolist(", start) and isinstance(value, _HclSet):
            return value.value
        if HEREDOC.match(self.s, start) and isinstance(value, str) and _HCL_TEMPLATE.search(value):
            return _HclExpression(self.s[start:self.i])
        return value

    def value(self, multiline=False, depth=0):
        start = self.i
        value = super().value(multiline, depth)
        return _HclExpression(self.s[start:self.i]) if value is UNKNOWN else value

    def parse(self):
        value = super().parse()
        return _HclExpression(self.s) if value is UNKNOWN else value


def hcl_source_blocks(text):
    """The normal HCL blocks plus top-level attributes, as used by Terragrunt."""
    attrs, blocks = parse_body(text, 0, len(text), LineIndex(text))
    if attrs:
        root = Block("", [], 1, len(split_lines(text)))
        root.attrs = attrs
        blocks.append(root)
    return blocks


def hcl_blocks_with_context(blocks):
    """Carry the generated block type and lexically scoped iterator inputs."""
    pending = [(block, "", {}) for block in blocks]
    while pending:
        block, parent, inherited = pending.pop()
        context = (unquote(block.labels[0]) if block.type == "dynamic" and block.labels else
                   parent if block.type == "content" and parent else block.type)
        bindings = inherited
        if "for_each" in block.attrs and block.type in ("dynamic", "resource", "data", "module"):
            iterator = block.attrs.get("iterator", (context, 0))[0] if block.type == "dynamic" else "each"
            if isinstance(iterator, str):
                parts, end = _hcl_reference_at(iterator)
                if len(parts) == 1 and end == len(iterator):
                    bindings = {**inherited, parts[0]: (block.attrs["for_each"][0], inherited)}
        yield block, context, bindings
        pending.extend((child, context if block.type == "dynamic" else "", bindings) for child in block.blocks)


_HCL_VALUES, _HCL_KEYS = object(), object()


def _hcl_reference_at(raw, start=0):
    """Read a traversal with HCL whitespace/comments, Unicode names and indexes."""
    i, n = skip_space(raw, start, len(raw)), len(raw)
    match = IDENT.match(raw, i)
    if not match:
        return (), i
    parts, i = [match.group()], match.end()
    while True:
        i = skip_space(raw, i, n)
        if i < n and raw[i] == ".":
            match = IDENT.match(raw, skip_space(raw, i + 1, n))
            if not match:
                break
            parts.append(match.group())
            i = match.end()
        elif i < n and raw[i] == "[":
            end = skip_balanced(raw, i)
            index = literal(raw[i + 1:end - 1])
            parts.append(index if isinstance(index, (str, int)) else _HCL_VALUES)
            i = end
        else:
            break
    return tuple(parts), i


def _hcl_template_parts(text, depth):
    for match in _HCL_TEMPLATE.finditer(text):
        opening = match.end() - 1
        close = skip_balanced(text, opening)
        yield from _hcl_expression_parts(text[opening + 1:close - 1], depth + 1)


def _hcl_expression_parts(raw, depth=0, object_body=False):
    """Recover objects and actual refs within opaque functions/conditionals.

    The scanner owns strings, comments and balanced delimiters. Do not search
    raw prose for `var.x`, or treat a public sibling of a key as its dependency.
    """
    if depth > MAX_HCL_DEPTH:
        raise RecursionError("HCL expression inspection exceeds maximum depth")
    i, n = 0, len(raw)
    while i < n:
        i = skip_space(raw, i, n)
        if i >= n:
            break
        heredoc = HEREDOC.match(raw, i)
        if heredoc:
            start, end, i = heredoc_span(raw, heredoc)
            body = raw[start:end]
            if _HCL_TEMPLATE.search(body):
                yield from _hcl_template_parts(body, depth)
            else:
                yield body
        elif object_body and raw[i] == "(":
            end = skip_balanced(raw, i)
            key_start, key_end = i + 1, end - 1
            for _ in range(MAX_HCL_DEPTH):
                key_start = skip_space(raw, key_start, key_end)
                if key_start >= key_end or raw[key_start] != "(":
                    break
                close = skip_balanced(raw, key_start)
                if skip_space(raw, close, key_end) != key_end:
                    break
                key_start, key_end = key_start + 1, close - 1
            else:
                raise RecursionError("HCL object key exceeds maximum depth")
            key = literal(raw[key_start:key_end])
            separator = skip_space(raw, end, n)
            if isinstance(key, str) and separator < n and raw[separator] in "=:" and \
                    not raw.startswith("=>", separator):
                # The scanner intentionally treats computed keys as unknown.
                # A parenthesized literal still identifies this key's schema.
                parser = _HclLiteral(raw)
                parser.i = separator + 1
                yield {key: parser.value(depth=depth + 1)}
                i = parser.i
            else:
                yield from _hcl_expression_parts(raw[i + 1:end - 1], depth + 1)
                i = end
        elif raw[i] in '"[{':
            end = skip_string(raw, i) if raw[i] == '"' else skip_balanced(raw, i)
            value = _HclLiteral(raw[i:end]).parse()
            if isinstance(value, _HclExpression):
                if raw[i] == '"':
                    # Only template expressions are code inside a string.
                    yield from _hcl_template_parts(raw[i:end], depth)
                else:
                    yield from _hcl_expression_parts(raw[i + 1:end - 1], depth + 1, raw[i] == "{")
            else:
                yield value
            i = end
        else:
            parts, end = _hcl_reference_at(raw, i)
            if parts:
                if len(parts) > 1:
                    yield _HclExpression(raw[i:end])
                i = end
            else:
                i += 1


def hcl_contextual_secrets(blocks, indirect=False):
    """Find contextual key literals, or only their module-local dependencies.

    This does not evaluate HCL: known objects select only their secret children;
    unresolved expressions are conservative, and external refs remain readable.
    `indirect` prevents a literal key in one file from hiding unrelated defaults
    in another file merely because the key's text resembles a variable name.
    """
    parsed, declarations = {}, {}

    def value(raw):
        if raw not in parsed:
            parsed[raw] = _HclLiteral(raw).parse()
        return parsed[raw]

    contexts = list(hcl_blocks_with_context(blocks))
    # Repeated aliases can expand exponentially without increasing source size.
    # Bound work by the input rather than attempting to expand the HCL value.
    work_remaining = max(MAX_HCL_DEPTH, sum(len(raw) for block, _, _ in contexts
                                            for raw, _ in block.attrs.values()))
    for block, _, _ in contexts:
        if block.type == "variable" and block.labels and "default" in block.attrs:
            name = unquote(block.labels[0])
            if isinstance(name, str):
                declarations.setdefault(("var", name), []).append(value(block.attrs["default"][0]))
        if block.type == "locals":
            for name, (raw, _) in block.attrs.items():
                declarations.setdefault(("local", name), []).append(value(raw))

    def carries(node, container, bindings, path=(), followed=False, seen=frozenset(), depth=0):
        nonlocal work_remaining
        work_remaining -= 1
        if work_remaining < 0:
            raise RecursionError("HCL key reference inspection exceeds source work budget")
        if depth > MAX_HCL_DEPTH:
            raise RecursionError("HCL key reference inspection exceeds maximum depth")
        if isinstance(node, _HclSet):
            if path and path[0] is _HCL_KEYS:
                path = (_HCL_VALUES,) + path[1:]  # A set iterator's key is its value.
            return carries(node.value, container, bindings, path, followed, seen, depth + 1)
        if isinstance(node, _HclExpression):
            parts, end = _hcl_reference_at(node.raw)
            if parts and end == len(node.raw):
                if container is not None and not contextual_secret_fields(container):
                    return False  # Its declaration is checked once, with its own structure.
                if len(parts) >= 2 and parts[0] in bindings and parts[1] in ("key", "value"):
                    raw, outer = bindings[parts[0]]
                    select = _HCL_VALUES if parts[1] == "value" else _HCL_KEYS
                    return carries(value(raw), container, outer, (select,) + parts[2:] + path,
                                   followed, seen, depth + 1)
                name = parts[:2]
                if len(name) == 2 and name[0] in ("var", "local"):
                    if name in seen:
                        return False
                    return any(carries(item, container, {}, parts[2:] + path, True, seen | {name}, depth + 1)
                               for item in declarations.get(name, ()))
                return False
            if container is None and (followed or not indirect):
                return True  # An opaque key expression may itself contain a literal.
            # An unevaluated transformation can change shape: the output's
            # selectors cannot safely be applied to its input collection.
            return any(carries(item, container, bindings, (), followed, seen, depth + 1)
                       for item in _hcl_expression_parts(node.raw))
        if path:
            field, *remaining = path
            if field is _HCL_VALUES:
                selected = node.values() if isinstance(node, dict) else node if isinstance(node, list) else ()
            elif field is _HCL_KEYS:
                selected = node.keys() if isinstance(node, dict) else range(len(node)) if isinstance(node, list) else ()
            elif isinstance(node, dict):
                selected = [node[field]] if field in node else ()
            elif isinstance(node, list) and isinstance(field, int) and 0 <= field < len(node):
                selected = [node[field]]
            else:
                selected = ()
            return any(carries(item, container, bindings, tuple(remaining), followed, seen, depth + 1)
                       for item in selected)
        if container is None:
            if indirect and not followed and isinstance(node, (dict, list)):
                # jsonencode retains its literal object/list in this parser.
                # Its embedded references still contribute to the key string.
                items = node.values() if isinstance(node, dict) else node
                return any(carries(item, None, bindings, (), False, seen, depth + 1) for item in items)
            return (followed or not indirect) and node not in (None, "", [], {})
        fields = contextual_secret_fields(container)
        if isinstance(node, dict):
            return any(carries(item, None if name.replace("_", "").lower() in fields else name,
                               bindings, (), followed, seen, depth + 1) for name, item in node.items())
        if isinstance(node, list):
            return any(carries(item, container, bindings, (), followed, seen, depth + 1) for item in node)
        return (followed or not indirect) and has_contextual_secrets(node, container)

    for block, context, bindings in contexts:
        fields = contextual_secret_fields(context)
        for name, (raw, _) in block.attrs.items():
            container = None if name.replace("_", "").lower() in fields else name
            if carries(value(raw), container, bindings):
                return True
    return False


def hcl_has_paired_secret(text):
    """Name/value pairs (env blocks, jsonencode lists) and secret-named variables.

    Line redaction sees `value = "..."`, not that its sibling `name` is
    DB_PASSWORD. Treat a secret-shaped name with a value nearby as a secret.
    """
    # Values Terraform itself treats as secret, wherever their names point.
    if HCL_MARKED_SECRET.search(text):
        return True
    lines = text.split("\n")
    for n, line in enumerate(lines):
        for match in HCL_NAME.finditer(line):
            if is_secret_name(match.group(1)) and any(
                    HCL_VALUE.search(near) for near in lines[max(0, n - 15):n + 16]):
                return True
        # As for blocks below: an object literal (jsonencode environment lists)
        # whose name is an expression and whose value beside it is not a reference.
        name = HCL_EXPR_NAME.search(line)
        if name:
            for k in range(max(0, n - 3), min(len(lines), n + 4)):
                value = HCL_VALUE.search(lines[k])
                # Only a literal can leak: a string, heredoc or number, not an
                # iterator (for k, v in ...: { name = k, value = v }) or each.value.
                if not value or not re.match(r'\s*(?:"|<<|[0-9])', lines[k][value.end():]):
                    continue
                # The same object only: no brace between them (a resource's
                # name and a nested setting { value = ... } are not a pair).
                if k < n or (k == n and value.start() < name.start()):
                    between = "\n".join(lines[k:n + 1])[value.end():len("\n".join(lines[k:n])) + name.start()
                                                           + (1 if k < n else 0)]
                else:
                    between = "\n".join(lines[n:k + 1])[name.end():len("\n".join(lines[n:k])) + value.start()
                                                           + (1 if k > n else 0)]
                if "{" not in between and "}" not in between:
                    return True
    top = hcl_source_blocks(text)
    if hcl_secret_indirection(top) or hcl_contextual_secrets(top):
        return True
    for block, _, _ in hcl_blocks_with_context(top):
        # A secret-named parameter or env block with its value anywhere in the block.
        names = [literal(block.attrs[k][0]) for k in ("name", "key", "parameter_key") if k in block.attrs]
        if ("value" in block.attrs or "parameter_value" in block.attrs) and any(
                not isinstance(x, str) or is_secret_name(x) for x in names):
            return True
    for block in top:
        if block.type == "variable" and block.labels and "default" in block.attrs and \
                is_secret_name(block.labels[0]):
            default = literal(block.attrs["default"][0])
            # A number (secret_recovery_window_in_days = 7) or an empty string is no secret.
            if not isinstance(default, (int, float, bool)) and default not in (None, ""):
                return True
        if block.type == "output" and block.labels and "value" in block.attrs and \
                is_secret_name(block.labels[0]):
            raw_val = block.attrs["value"][0].strip()
            val = literal(raw_val)
            if not SAFE_VALUE.fullmatch(raw_val) and isinstance(val, str) and val != "":
                return True
        if block.type == "locals":
            for attr_name, (raw_val, _) in block.attrs.items():
                if is_secret_name(attr_name):
                    val = literal(raw_val.strip())
                    if not SAFE_VALUE.fullmatch(raw_val.strip()) and isinstance(val, str) and val != "":
                        return True
    return False


HCL_INDIRECT = re.compile(r"(?<![\w.])(var|local)\.([A-Za-z_][\w-]*)")
# What such an attribute reads through a file function is a path, and a
# *_id, *_name or *_arn names a secret held elsewhere (secret_id = "prod/db").
HCL_FILE_CALL = re.compile(r"\b(?:file|filebase64|templatefile|pathexpand|abspath|dirname|basename)\s*\([^()]*\)")
HCL_NAMES_A_SECRET = re.compile(r"(?i)(?:_id|_ids|_name|_names|_arn|_arns|_file|_path)$")


def _holds_value(value):
    """A literal that could be the secret: text, a number or a non-empty collection."""
    return value not in (None, "", [], {}) and value is not UNKNOWN and not isinstance(value, bool)


def hcl_secret_indirection(blocks):
    """A secret-named attribute that reads a variable or local holding a literal.

    `password = var.db_admin` is safe to show; `variable "db_admin" { default
    = "..." }` is then the password, though its own name says nothing. So is
    `password = local.creds.admin` over a literal object, or a number."""
    literals, wanted = set(), set()
    for block, _, _ in hcl_blocks_with_context(blocks):
        if block.type == "variable" and block.labels and "default" in block.attrs:
            if _holds_value(literal(block.attrs["default"][0])):
                literals.add(("var", block.labels[0]))
        for name, (raw, _) in block.attrs.items():
            if block.type == "locals" and _holds_value(literal(raw.strip())) and \
                    not SAFE_VALUE.fullmatch(raw.strip()):
                literals.add(("local", name))
            # password_length = var.n reads a setting, not a secret.
            if is_secret_name(name) and not HCL_NAMES_A_SECRET.search(name) and not SETTING_NAME.search(name):
                wanted.update(HCL_INDIRECT.findall(HCL_FILE_CALL.sub("", raw)))
    return bool(literals & wanted) or hcl_contextual_secrets(blocks, indirect=True)


def hcl_module_sensitive(directory):
    """Conservatively include declarations inherited through override files.

    Do not evaluate override order or read symlink targets. Unknown sibling
    context makes the module's excerpts unsafe, even when this file looks public.
    """
    blocks = []
    try:
        for sibling in directory.iterdir():
            if sibling.name.lower().endswith((".tf.json", ".tofu.json")):
                return True  # Unsupported Terraform JSON can also override sensitivity.
            if sibling.suffix.lower() not in (".tf", ".tofu", ".hcl"):
                continue
            if sibling.is_symlink():
                return True
            # A file the scanner skipped as too large is unknown context too.
            if sibling.is_file() and (sibling.stat().st_size > MAX_BYTES or
                                      hcl_declares_sensitive(sibling.read_text(encoding="utf-8-sig"))):
                return True
            if sibling.is_file():
                blocks.extend(hcl_source_blocks(sibling.read_text(encoding="utf-8-sig")))
    except (OSError, ValueError, TypeError, RecursionError):
        return True
    # The secret may be read in one file and written in another.
    return hcl_secret_indirection(blocks)


def source_lines(path):
    """Preserve source line numbers, or return None if an excerpt is unsafe.

    Reuse the scanner's conservative YAML subset. A tag, alias or other
    unsupported construct must not fall back to raw text near another finding.
    JSON sensitivity and env name/value relationships require the whole document;
    line-oriented redaction alone cannot enforce them.
    """
    if path.stat().st_size > MAX_BYTES:
        return None  # the scanner did not read it either
    # Match the scanner's BOM handling before checking sensitivity or line numbers.
    text = path.read_text(encoding="utf-8-sig")
    lines = split_lines(text)
    suffix = path.suffix.lower()
    syntax = "text"
    try:
        if suffix == ".json" or (suffix == ".template" and text.lstrip().startswith("{")):
            syntax = "json"
            docs = [json.loads(text, object_pairs_hook=unique_object)]
        elif suffix in (".yaml", ".yml", ".template"):
            syntax = "yaml"
            cfn_hint = suffix == ".template" or "AWSTemplateFormatVersion" in text or "Resources:" in text
            # The scanner's document split and YAML subset, so both read the same documents.
            docs = []
            for rows in split_yaml_documents(lines):
                try:
                    docs.append(_YamlSubset(rows).parse())
                except ValueError:
                    if not cfn_hint:
                        raise
                    docs.append(_YamlSubset(rows, cfn=True).parse())
        else:
            docs = []
            if suffix in (".tf", ".tofu", ".hcl"):
                syntax = "hcl"
                # Sensitivity belongs to the block, not to the default/value
                # line. Only a known false declaration permits an excerpt.
                if hcl_declares_sensitive(text) or hcl_has_paired_secret(text):
                    return None
        if has_escaped_secret_keys(text, docs) or any(has_structured_secrets(doc) for doc in docs):
            return None
        # Exports committed into the repository are snapshots wherever they sit:
        # deployed values (emails, IPs, environment) never become excerpts.
        if any(is_export(doc) for doc in docs):
            return None
        lines = redact_lines(lines, syntax=syntax)
        if syntax == "json":
            lines = redact_json_values(text, lines)
        # Last, broad pass over free text: comments, script bodies, flags,
        # connection strings and opaque tokens (redaction.scrub_lines).
        lines = scrub_lines(lines, syntax="hcl" if syntax == "text" else syntax, original=split_lines(text))
    except (ValueError, TypeError, RecursionError):
        return None
    return lines


def attach_sources(data, repo, context=3):
    """Return {finding id: [(lineno, text, hit)]} for readable, non-sensitive locations."""
    root = Path(repo).resolve()
    out = {}
    hcl_modules = {}
    # Kubernetes Secret values can have arbitrary keys and remain secret even
    # when base64-encoded. Do not expose them through a neighboring finding.
    secret_manifests = set()
    for f in data.get("findings", []):
        # A state file is secret whatever its name (SEC-002 also reads content).
        if f.get("rule") in ("K8S-003", "SEC-002"):
            match = LOCATION.match(f.get("location", ""))
            if match:
                secret_manifests.add(posixpath.normpath(match.group(1)))
    for f in data.get("findings", []):
        if f.get("rule") in ("SEC-001", "SEC-002", "K8S-003"):
            continue
        m = LOCATION.match(f.get("location", ""))
        if not m:
            continue
        rel, start = posixpath.normpath(m.group(1)), int(m.group(2))
        end = int(m.group(3) or start)
        # Judge the file that will be opened, not the spelling of the path:
        # "terraform.tfstate/." names the state file too.
        if rel in secret_manifests or SENSITIVE_NAME.search(rel) or rel.startswith(("../", "/")) or rel == "..":
            continue
        if any(part in SKIP_DIRS for part in Path(rel).parts):
            continue
        cand = root / rel
        try:
            if any(p.is_symlink() for p in (cand, *cand.parents) if p != root and root in p.parents) or not cand.is_file():
                continue
            real = cand.resolve().relative_to(root).as_posix()
            if real in secret_manifests or SENSITIVE_NAME.search(real) or any(part in SKIP_DIRS for part in Path(real).parts):
                continue
            if cand.suffix.lower() in (".tf", ".tofu", ".hcl") or cand.name.lower().endswith((".tf.json", ".tofu.json")):
                directory = cand.parent.resolve()
                directory.relative_to(root)
                if directory not in hcl_modules:
                    hcl_modules[directory] = hcl_module_sensitive(directory)
                if hcl_modules[directory]:
                    continue
            lines = source_lines(cand)
        except (OSError, ValueError, RecursionError):
            continue
        if lines is None:
            continue
        end = min(end, start + 40)
        lo, hi = max(1, start - context), min(len(lines), end + context)
        if start <= len(lines):  # a line past the end of the file (an edited file) has nothing to show
            out[f["id"]] = [(i, lines[i - 1], start <= i <= end) for i in range(lo, hi + 1)]
    return out

