"""Where code loads each prompt file, what it fills the template with, and which model call sends it.

inventory.py calls trace() once per scan. For every quoted path in code that names a prompt file
(`"answer.prompt"`, `PROMPTS / "support_system.md"`, `f"{DIR}/system.md"`), the expression holding it is
followed through loader calls (`open`, `read_text`, `readFileSync`, `get_template`, `Template`,
`path.join`...) and method chains to:

- a render call: `.format`, `.format_map`, `.render`, `.substitute`, `.safe_substitute`, `.invoke`,
  `.format_messages`, `.format_prompt`, or `.replace`/`.replaceAll` with a literal placeholder, whose
  keyword arguments or dict/object keys are the names it fills;
- a model API call that sends it as is (no render): the template's placeholders reach the model literally;
- an assignment, whose target is then followed the same way through the rest of the file.

Each render site is *complete* when every name it fills is spelled out: a `**kwargs`/`...spread`, a
positional dict variable or a computed key makes it open. A binding is *traced* when every use of the
loaded text was one of the three above; anything else (passed to another function, stored in a
collection, returned, used in another file, a quoted path matching several prompt files) leaves it
untraced, and the lint rules built on it (inventory.py `unfilled-variable`, `unused-render-key`) only
judge complete sites of traced bindings.

It reads text only and runs nothing. It is a heuristic over masked source (comments and string contents
blanked), not a parser: a binding it cannot follow is reported as untraced, never guessed.
"""
import bisect
from pathlib import PurePosixPath
import re

HASH_COMMENT = {".py", ".rb", ".ex", ".exs"}
SLASH_COMMENT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt", ".cs", ".php", ".rs",
                 ".swift"}
PAIR = {"(": ")", "[": "]", "{": "}"}
CLOSER = {v: k for k, v in PAIR.items()}

# Calls whose result is the loaded text (or a path or template object holding it), so the expression
# continues after their closing parenthesis. The last dotted segment is compared.
LOADERS = {"open", "read", "read_text", "readFile", "readFileSync", "readFileAsync", "get_template",
           "from_file", "from_template", "Path", "PurePath", "PurePosixPath", "join", "joinpath", "resolve",
           "files", "resource_string", "read_resource", "get_data", "Template", "dedent", "cleandoc", "str",
           "String", "decode", "strip", "trim", "await"}
# Render methods and the placeholder syntax each fills.
RENDER_STYLE = {"format": "brace", "format_map": "brace", "invoke": "brace", "ainvoke": "brace",
                "format_messages": "brace", "format_prompt": "brace", "render": "jinja", "render_async": "jinja",
                "substitute": "dollar", "safe_substitute": "dollar", "replace": "any", "replaceAll": "any"}
# Statements that only test a value: a use there neither renders nor hands the text on.
TESTS = re.compile(r"\s*(?:if|elif|while|assert|unless)\b")
ASSIGN = re.compile(r"\s*(?:(?:export\s+)?(?:const|let|var|final|val)\s+)?"
                    r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*(?::\s*[^=\n]{1,60}?)?\s*:?=(?![=>])")
IDENT = re.compile(r"[A-Za-z_$][\w$]*")
KEYWORD_ARG = re.compile(r"\s*([A-Za-z_]\w*)\s*=(?!=)")
OBJECT_KEY = re.compile(r"\s*([A-Za-z_$][\w$]*)\s*:(?!:)")
SHORTHAND = re.compile(r"\s*([A-Za-z_$][\w$]*)\s*$")
NUMBER = re.compile(r"\s*(-?[0-9]+(?:\.[0-9]+)?)\s*$")
CONSTANT = {"True": True, "False": False, "true": True, "false": False}
# Call parameters whose literal value is worth recording at a call site; any other is listed by name only.
PARAMS = {"model", "max_tokens", "max_completion_tokens", "max_output_tokens", "maxTokens", "maxOutputTokens",
          "temperature", "top_p", "topP", "top_k", "topK", "stream", "n", "seed", "reasoning_effort"}
MAX_TRACE = 4  # How many assignments deep one binding is followed.


class Source:
    """One code file: its text, the text with comments and string contents blanked, and its brackets."""

    def __init__(self, text, suffix):
        self.text = text
        self.masked, self.strings = mask_code(text, suffix)
        self.block_braces = suffix not in HASH_COMMENT  # In C-like languages a { may open a block.
        self.lines = [0] + [m.end() for m in re.finditer("\n", text)]
        self.match, self.parent, stack = {}, {}, []
        for m in BRACKET.finditer(self.masked):
            i, c = m.start(), m.group()
            if c in PAIR:
                self.parent[i] = stack[-1] if stack else None
                stack.append(i)
            elif c in CLOSER:
                # A stray closer (a regex literal, say) is skipped; an unmatched opener stays unmatched.
                while stack and self.masked[stack[-1]] != CLOSER[c]:
                    stack.pop()
                if stack:
                    self.match[stack.pop()] = i
        self.opens = sorted(self.match)

    def line(self, pos):
        return bisect.bisect_right(self.lines, pos)

    def enclosing(self, pos):
        """The brackets around pos, innermost first, up to the statement: a block brace ends the walk.

        Brackets nest, so every bracket around pos also holds the last one opened before it: the walk goes up
        that one's parents, never over its siblings."""
        result = []
        i = bisect.bisect_left(self.opens, pos) - 1
        start = self.opens[i] if i >= 0 else None
        while start is not None:
            if start in self.match and self.match[start] > pos:
                if self.is_block(start):
                    break
                result.append(start)
            start = self.parent.get(start)
        return result

    def is_block(self, start):
        if self.masked[start] != "{" or not self.block_braces:
            return False
        before = self.masked[max(0, start - 16):start].rstrip()
        return not before or before[-1] not in "=(,:[?!&|+" and not re.search(r"\b(?:return|await|yield)$", before)

    def callee(self, start):
        """The dotted name before an opening bracket, '' for a bare group."""
        m = re.search(r"([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*$", self.masked[max(0, start - 120):start])
        return re.sub(r"\s+", "", m.group(1)) if m else ""

    def statement(self, pos, outer):
        """Where the statement holding pos starts; outer is its outermost enclosing bracket, or None."""
        anchor = outer if outer is not None else pos
        line = self.masked.rfind("\n", 0, anchor) + 1
        i = anchor - 1
        while i >= line:
            c = self.masked[i]
            if c == ";" or self.block_braces and (c == "}" or c == "{" and self.is_block(i)):
                return i + 1
            i -= 1
        return line


_STRINGS = (r'"""[\s\S]*?(?:"""|\Z)|' r"'''[\s\S]*?(?:'''|\Z)|"
            r'"(?:[^"\\\n]|\\[\s\S])*"?|' r"'(?:[^'\\\n]|\\[\s\S])*'?")
# Comments and string literals, leftmost first: a # or // inside a string belongs to the string.
HASH_TOKENS = re.compile(r"#[^\n]*|" + _STRINGS)
SLASH_TOKENS = re.compile(r"//[^\n]*|/\*[\s\S]*?(?:\*/|\Z)|`(?:[^`\\]|\\[\s\S])*`?|" + _STRINGS)
NOT_NEWLINE = re.compile(r"[^\n]")
BRACKET = re.compile(r"[()\[\]{}]")


def mask_code(text, suffix):
    """(masked, strings): comments and string contents replaced by spaces (newlines kept, same length), and
    the (start, end, quote length) of every string literal, quotes included. Python and the other # languages
    take # comments and triple quotes; the rest take // and /* */ comments and backtick strings."""
    out, strings, last = [], [], 0
    for m in (HASH_TOKENS if suffix in HASH_COMMENT else SLASH_TOKENS).finditer(text):
        start, end = m.span()
        token = m.group()
        out.append(text[last:start])
        if token[0] in "#/":
            out.append(NOT_NEWLINE.sub(" ", token))
        else:
            q = 3 if token[:3] in ('"""', "'''") else 1
            close = q if len(token) >= 2 * q and token.endswith(token[:q]) else 0
            out.append(token[:q] + NOT_NEWLINE.sub(" ", token[q:len(token) - close]) + token[len(token) - close:])
            strings.append((start, end, q))
        last = end
    out.append(text[last:])
    return "".join(out), strings


def literal(src, start, end):
    """The content of the one string literal spanning masked[start:end] (spaces aside), or None."""
    while start < end and src.masked[start].isspace():
        start += 1
    while end > start and src.masked[end - 1].isspace():
        end -= 1
    k = bisect.bisect_left(src.strings, (start, -1, 0))
    if k < len(src.strings) and src.strings[k][0] == start and src.strings[k][1] == end:
        q = src.strings[k][2]
        # A prefix such as f, r or b sits before the quote and is not part of the span.
        return src.text[start + q:end - q]
    if start > 0 and k < len(src.strings) and src.strings[k][1] == end and re.fullmatch(
            r"[A-Za-z]{1,2}", src.masked[start:src.strings[k][0]]):
        q = src.strings[k][2]
        return src.text[src.strings[k][0] + q:end - q]
    return None


def split_args(src, start, end):
    """Top-level comma-separated spans of masked[start:end]."""
    spans, depth, s = [], 0, start
    i = start
    while i < end:
        c = src.masked[i]
        if c in PAIR and i in src.match:
            i = src.match[i] + 1
            continue
        if c == ",":
            spans.append((s, i))
            s = i + 1
        i += 1
    spans.append((s, end))
    return [(a, b) for a, b in spans if src.masked[a:b].strip()]


def object_keys(src, start, end):
    """(keys, complete) of the dict or object literal between the braces at start and end."""
    keys, complete = [], True
    for a, b in split_args(src, start + 1, end):
        text = src.masked[a:b]
        if text.lstrip().startswith(("**", "...", "[")):
            complete = False
            continue
        colon = text.find(":")
        quoted = literal(src, a, a + colon) if colon > 0 else None
        m = OBJECT_KEY.match(text) or SHORTHAND.match(text)
        if quoted is not None and IDENT.fullmatch(quoted):
            keys.append(quoted)
        elif m:
            keys.append(m.group(1))
        else:
            complete = False
    return keys, complete


def call_keys(src, method, start, end):
    """(keys, complete, is_render) for the arguments of a render call between its parentheses."""
    args = split_args(src, start + 1, end)
    if method in ("replace", "replaceAll"):
        if not args:
            return [], True, False
        first = literal(src, *args[0])
        if first is None:
            return [], False, True  # A regex or a computed placeholder: some names, unknown which.
        names = placeholder_names(first)
        return names, True, bool(names)
    keys, complete = [], True
    for a, b in args:
        text = src.masked[a:b]
        stripped = text.strip()
        kw = KEYWORD_ARG.match(text)
        if stripped.startswith(("**", "...")):
            complete = False
        elif kw:
            keys.append(kw.group(1))
        elif stripped.startswith("{"):
            brace = a + text.index("{")
            if brace in src.match:
                more, ok = object_keys(src, brace, src.match[brace])
                keys += more
                complete = complete and ok
            else:
                complete = False
        elif re.match(r"dict\s*\(", stripped):
            paren = a + text.index("(")
            if paren in src.match:
                more, ok, _ = call_keys(src, "format", paren, src.match[paren])
                keys += more
                complete = complete and ok
            else:
                complete = False
        else:
            complete = False  # A positional value: a dict variable, a context object, positional fields.
    return keys, complete, True


PLACEHOLDER = re.compile(r"\{\{[-~]?\s*([A-Za-z_]\w*)|\{([A-Za-z_]\w*)\}|\$\{?([A-Za-z_]\w*)")


def placeholder_names(text):
    return list(dict.fromkeys(n for groups in PLACEHOLDER.findall(text) for n in groups if n))


def chain(src, pos):
    """[(method, open, close)] of the method calls chained directly after pos, and where the chain ends."""
    calls, n = [], len(src.masked)
    while pos < n:
        m = re.compile(r"\s*(\??\.)\s*([A-Za-z_$][\w$]*)\s*").match(src.masked, pos)
        if m and m.end() < n and src.masked[m.end()] == "(" and m.end() in src.match:
            calls.append((m.group(2), m.end(), src.match[m.end()]))
            pos = src.match[m.end()] + 1
        elif m:
            pos = m.end()
        else:
            m = re.compile(r"[ \t]*([\[!])").match(src.masked, pos)
            if m and m.group(1) == "[" and m.end() - 1 in src.match:
                pos = src.match[m.end() - 1] + 1
            elif m and m.group(1) == "!" and not src.masked.startswith("!=", m.end() - 1):
                pos = m.end()
            else:
                break
    return calls, pos


class Tracer:
    def __init__(self, src, rel, senders):
        self.src, self.rel, self.senders = src, rel, senders

    def sender(self, start):
        """Whether the bracket at start opens a model API call that sends a prompt."""
        if self.src.masked[start] != "(":
            return False
        window = self.src.masked[max(0, start - 80):start + 1]
        return any(m.end() == len(window) for p in self.senders for m in p.finditer(window))

    def loader(self, start):
        """Whether the bracket at start opens a loader call or a bare group, whose value is what it holds."""
        if self.src.masked[start] != "(":
            return False
        name = self.src.callee(start)
        return not name or name.rpartition(".")[2] in LOADERS

    def follow(self, pos, end, depth, seen, result):
        """Follow the value at masked[pos:end] (a quoted path or a name holding it) to its uses."""
        src = self.src
        rings = src.enclosing(pos)
        stmt_start = src.statement(pos, rings[-1] if rings else None)
        calls = []
        while True:
            more, after = chain(src, end)
            calls += more
            if rings and self.loader(rings[0]):
                end = src.match[rings[0]] + 1  # Through a loader call or a group: its value is the text.
                rings = rings[1:]
                continue
            break
        site = None
        for method, start, close in calls:
            if method not in RENDER_STYLE:
                continue
            keys, complete, render = call_keys(src, method, start, close)
            if not render:
                continue
            if site is None:
                site = {"location": f"{self.rel}:{src.line(start)}", "via": method, "keys": [],
                        "complete": True, "style": RENDER_STYLE[method]}
            site["keys"] += [k for k in keys if k not in site["keys"]]
            site["complete"] = site["complete"] and complete
            if site["style"] != RENDER_STYLE[method]:
                site["style"] = "any"
        sent = next((r for r in rings if self.sender(r)), None)
        if site is None and sent is not None:
            site = {"location": f"{self.rel}:{src.line(sent)}", "via": "sent", "keys": [], "complete": True,
                    "style": "any"}
        target = ASSIGN.match(src.masked, stmt_start)
        if target and target.end() > pos:
            target = None
        if site is not None:
            result["sites"].append(site)
            if target and not rings:
                result["targets"].add(target.group(1))
            if sent is not None:
                result["sent_at"].add(src.line(sent))
            return
        if rings:
            result["traced"] = False  # Handed to a call, list or dict this trace does not follow.
            return
        if target is None:
            if not TESTS.match(src.masked, stmt_start):
                result["traced"] = False  # Returned, yielded or used as a bare expression.
            return
        if re.compile(r"[ \t]*(.?)").match(src.masked, after).group(1) not in ("", "\n", "\r", ";", "+"):
            result["traced"] = False  # Part of a larger expression (a conditional, an operator).
            return
        name = target.group(1)
        result["targets"].add(name)
        if name in seen:
            return
        if depth >= MAX_TRACE:
            result["traced"] = False
            return
        followed = False
        for m in re.compile(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])").finditer(src.masked, target.end()):
            inner = src.enclosing(m.start())
            # A keyword argument or an object key of that name is not a use of the variable.
            if inner and (src.masked[inner[0]] == "(" and re.match(r"\s*=(?![=>])", src.masked[m.end():])
                          or src.masked[inner[0]] == "{" and re.match(r"\s*:(?!:)", src.masked[m.end():])):
                continue
            # A later assignment to the same name starts a different value.
            own = ASSIGN.match(src.masked, src.statement(m.start(), inner[-1] if inner else None))
            if own and own.start(1) == m.start():
                break
            followed = True
            self.follow(m.start(), m.end(), depth + 1, seen | {name}, result)
        if not followed:
            result["traced"] = False  # Used in another file, or not at all.


def path_matches(value, by_parts):
    """The prompt paths a quoted string names: its trailing segments without template syntax."""
    if not value or any(c.isspace() for c in value):
        return []
    parts = [p for p in value.replace("\\", "/").split("/")]
    clean = []
    for p in reversed(parts):
        if not p or any(c in p for c in "{}$%*<>") or p in (".", ".."):
            break
        clean.insert(0, p)
    if not clean:
        return []
    return [path for path, segs in by_parts.get(clean[-1], []) if segs[-len(clean):] == clean]


def trace(code_files, prompt_paths, senders):
    """Bindings of prompt files in code.

    code_files: [(rel, text, suffix)]; prompt_paths: prompt file paths as reported; senders: compiled
    patterns of model API calls that send a prompt. Returns (bindings, sources) where sources maps a code
    path to its Source, for call_details().
    """
    by_parts = {}
    for path in prompt_paths:
        segs = PurePosixPath(path).parts
        by_parts.setdefault(segs[-1], []).append((path, list(segs)))
    names = sorted(by_parts)
    bindings, sources = [], {}
    for rel, text, suffix in code_files:
        if not any(name in text for name in names):
            continue
        src = sources.get(rel) or Source(text, suffix)
        sources[rel] = src
        for start, end, q in src.strings:
            value = src.text[start + q:end - q]
            if not any(value.endswith(name) for name in names):
                continue
            matches = path_matches(value, by_parts)
            if not matches:
                continue
            result = {"sites": [], "targets": set(), "sent_at": set(), "traced": len(matches) == 1}
            Tracer(src, rel, senders).follow(start, end, 0, frozenset(), result)
            for path in matches:
                binding = {
                    "prompt": path, "loaded_at": f"{rel}:{src.line(start)}",
                    "traced": result["traced"], "renders": [dict(s) for s in result["sites"]],
                    "targets": sorted(result["targets"]), "sent_at": sorted(f"{rel}:{n}" for n in result["sent_at"]),
                }
                if len(matches) > 1:
                    binding["ambiguous"] = True  # The quoted path names several prompt files.
                bindings.append(binding)
    return bindings, sources


def call_details(src, pos):
    """(args, params, words) of the call whose name ends just before masked[pos] == '(': argument names
    (keyword or object keys; '**' for a spread), literal values of PARAMS, and every identifier in the
    arguments (to link the variables holding prompts)."""
    if pos not in src.match:
        return None
    close = src.match[pos]
    spans = split_args(src, pos + 1, close)
    if len(spans) == 1 and src.masked[spans[0][0]:spans[0][1]].strip().startswith("{"):
        brace = spans[0][0] + src.masked[spans[0][0]:spans[0][1]].index("{")
        if brace in src.match:
            spans = split_args(src, brace + 1, src.match[brace])
    args, params = [], {}
    for a, b in spans:
        text = src.masked[a:b]
        if text.lstrip().startswith(("**", "...")):
            args.append("**")
            continue
        m = KEYWORD_ARG.match(text) or OBJECT_KEY.match(text)
        if not m:
            short = SHORTHAND.match(text)
            if short:
                args.append(short.group(1))
            continue
        name = m.group(1)
        args.append(name)
        if name in PARAMS:
            value_start = a + m.end()
            raw = src.masked[value_start:b]
            quoted = literal(src, value_start, b)
            if quoted is not None:
                params[name] = quoted
            elif NUMBER.match(raw):
                number = NUMBER.match(raw).group(1)
                params[name] = float(number) if "." in number else int(number)
            elif raw.strip() in CONSTANT:
                params[name] = CONSTANT[raw.strip()]
    words = set(IDENT.findall(src.masked[pos + 1:close]))
    return args, params, words


# Parsing a reply as JSON; a schema-validating parser (pydantic, zod) carries its own contract and is not one.
PARSE_CALL = re.compile(r"\b(?:json\.loads|JSON\.parse|orjson\.loads|ujson\.loads|json5\.loads|yaml\.safe_load)\s*\(")
# Arguments that give the call a schema of its own: the keys then come from code, not from the prompt.
SCHEMA_ARGS = {"response_format", "tools", "functions", "tool_choice", "output_format", "text_format", "text",
               "response_schema", "responseSchema", "schema", "output", "experimental_output", "response_model",
               "generation_config", "generationConfig", "config"}
MAX_ALIASES = 3


def reply_reads(src, pos):
    """[(line, key, parse line, literal start)] of the keys code reads from the JSON parsed out of the reply of the call
    whose opening parenthesis is at pos, or None when the call is not assigned, or its reply is not parsed
    as JSON in this file. Followed: the call's assignment target, assignments of expressions holding it
    (`text = message.content[0].text`), a JSON parse of one of them, and subscripts and .get() of the
    parsed value, chained or through its own assignment target."""
    if pos not in src.match:
        return None
    rings = src.enclosing(pos)
    stmt = src.statement(pos, rings[-1] if rings else None)
    target = ASSIGN.match(src.masked, stmt)
    if not target or rings or target.end() > pos:
        return None
    holders, frontier, after = {target.group(1)}, [target.group(1)], src.match[pos]
    reads, parsed = [], False
    for _ in range(MAX_ALIASES):
        found = []
        for name in frontier:
            for m in re.compile(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])").finditer(src.masked, after):
                inner = src.enclosing(m.start())
                start = src.statement(m.start(), inner[-1] if inner else None)
                own = ASSIGN.match(src.masked, start)
                if own and own.start(1) == m.start():
                    continue
                parse = next((o for o in inner if PARSE_CALL.search(src.masked, max(0, o - 40), o + 1)
                              and PARSE_CALL.search(src.masked, max(0, o - 40), o + 1).end() == o + 1), None)
                if parse is not None:
                    parsed = True
                    reads += subscripts(src, src.match[parse] + 1, src.line(parse))
                    outer = src.enclosing(parse)
                    alias = ASSIGN.match(src.masked, src.statement(parse, outer[-1] if outer else None))
                    if alias and not outer and alias.end() <= parse:
                        reads += value_reads(src, alias, src.line(parse))
                elif own and not inner and own.group(1) not in holders and own.end() <= m.start():
                    holders.add(own.group(1))
                    found.append(own.group(1))
        frontier = found
        if not frontier:
            break
    return reads if parsed else None


def key_at(src, pos):
    """(key, where its literal starts) of a subscript `["key"]` or `.get("key"` starting at pos, or (None, None)."""
    m = re.compile(r"\s*(?:\[|\??\.\s*get\s*\()").match(src.masked, pos)
    if not m or m.end() - 1 not in src.match:
        return None, None
    opening = m.end() - 1
    args = split_args(src, opening + 1, src.match[opening])
    key = literal(src, *args[0]) if args else None
    if not key or not IDENT.fullmatch(key):
        return None, None
    return key, src.masked.find(src.masked[args[0][0]:args[0][1]].strip()[:1], args[0][0])


def subscripts(src, pos, parse_line):
    key, at = key_at(src, pos)
    return [(src.line(pos), key, parse_line, at)] if key else []


def value_reads(src, alias, parse_line):
    """The first-level keys read from the variable alias names, after its assignment."""
    name, reads = alias.group(1), []
    for m in re.compile(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])").finditer(src.masked, alias.end()):
        inner = src.enclosing(m.start())
        own = ASSIGN.match(src.masked, src.statement(m.start(), inner[-1] if inner else None))
        if own and own.start(1) == m.start():
            break  # Reassigned: later reads are of another value.
        key, at = key_at(src, m.end())
        if key:
            reads.append((src.line(m.start()), key, parse_line, at))
    return reads


def string_words(src, skip=()):
    """Every word in the file's string literals, as an inline prompt or a schema might hold it, but those of
    the literals starting at skip (the keys read)."""
    skip = set(skip)
    return {w for start, end, q in src.strings if start not in skip for w in IDENT.findall(src.text[start + q:end - q])}


# Inline prompts: string literals in code assigned to, or passed as, a prompt-named name.
PROMPT_NAME = re.compile(r"(?i)prompt|instruction|persona|^system(?:_?(?:message|msg|text|content))?$|^preamble$")
# The name before a literal: `NAME = `, `NAME: str = `, `name=` (keyword), `name: ` (object key, quoted or
# not), optionally through a dedent call, a group or a string prefix (f, r, b, rb).
NAMED = re.compile(r"""["']?([A-Za-z_$][\w$]*)["']?\s*(?::\s*[\w\[\], .|]{1,40}?\s*=|:(?!:)|=(?![=>])|:=)\s*"""
                   r"""(?:(?:[\w.]*dedent|[\w.]*cleandoc|[\w.]*strip|String\.raw)?\s*\(\s*)*[A-Za-z]{0,2}$""")
SYSTEM_ROLE = re.compile(r"""["']?role["']?\s*[:=]\s*["']system["']""")
# On the raw text, before any masking: where a literal may follow a prompt-named name (the match ends on its
# opening quote), and where a message's content may be a system prompt. A file with neither is not masked.
# Each word is found with str.find on a lowercased copy and the rest matched at that offset: a
# case-insensitive alternation would test every character of every code file.
PROMPT_WORDS = ("prompt", "instruction", "persona", "system", "preamble")
AFTER_WORD = re.compile(r"""[\w$]*["']?\s*(?::[^=\n]{0,40}=|:=|[:=])\s*(?:[\w.]*\(\s*)*[A-Za-z]{0,2}["'`]""")
ROLE_BEFORE = re.compile(r"""role["']?\s*[:=]\s*["']$""")
CONTENT = re.compile(r"""["']?content["']?\s*[:=]\s*(?:[\w.]*\(\s*)*[A-Za-z]{0,2}["'`]""")
ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def inline_candidates(text):
    """The offsets at which an inline prompt's literal may open, from the raw text; empty for most files."""
    low = text.lower()
    if len(low) != len(text):  # A character whose lower case is longer (U+0130): keep offsets aligned.
        low = text.translate(ASCII_LOWER)
    starts, role = set(), False
    for word in PROMPT_WORDS:
        i = low.find(word)
        while i >= 0:
            m = AFTER_WORD.match(text, i + len(word))
            if m:
                starts.add(m.end() - 1)
            if word == "system" and i and text[i - 1] in "\"'" and ROLE_BEFORE.search(text, max(0, i - 32), i):
                role = True
            i = low.find(word, i + len(word))
    if role:
        starts |= {m.end() - 1 for m in CONTENT.finditer(text)}
    return starts


JOIN = re.compile(r"\s*(?:\+|\\)?\s*")
MIN_INLINE = 20


def inline_prompts(src, candidates=None):
    """[(name, start, pieces)] for each prompt-named string literal: pieces are (content, first line) of the
    literal and of each literal joined to it (implicit concatenation, +, a line continuation). A literal
    without whitespace (a path, an identifier) or shorter than MIN_INLINE characters in all is not one.
    candidates (inline_candidates()) limits the literals looked at."""
    found, used = [], set()
    for k, (start, end, q) in enumerate(src.strings):
        if k in used or candidates is not None and start not in candidates:
            continue
        m = NAMED.search(src.text, max(0, start - 160), start)
        if not m or m.end() != start:
            continue
        name = m.group(1)
        if not PROMPT_NAME.search(name):
            inner = src.enclosing(start)
            if name != "content" or not inner or not SYSTEM_ROLE.search(src.text, inner[0], src.match[inner[0]]):
                continue
            name = "system"
        pieces, j = [(src.text[start + q:end - q], src.line(start))], k
        while j + 1 < len(src.strings):
            gap = src.masked[src.strings[j][1]:src.strings[j + 1][0]]
            nxt = src.strings[j + 1]
            # A prefix letter (f, r, b) may sit before the next quote.
            if not JOIN.fullmatch(re.sub(r"[A-Za-z]{1,2}$", "", gap)):
                break
            j += 1
            used.add(j)
            pieces.append((src.text[nxt[0] + nxt[2]:nxt[1] - nxt[2]], src.line(nxt[0])))
        text = "".join(p for p, _ in pieces)
        if len(text) >= MIN_INLINE and any(c.isspace() for c in text.strip()):
            found.append((name, start, pieces))
    return found
