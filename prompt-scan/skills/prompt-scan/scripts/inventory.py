#!/usr/bin/env python3
"""Inventory the LLM prompts in a repository and lint them mechanically.

    python3 inventory.py REPO [--out inventory.json] [--into findings.json]
    python3 inventory.py REPO [--baseline findings.json] [--sarif FILE] [--fail-on SEVERITY]

Lists prompt files (prompt directories, prompt and template suffixes, agent and
skill definitions), call sites of model APIs in code, template variables per
prompt file, quoted model IDs and lint hits, and (bindings.py) where code loads
each prompt file, the keys each render call fills it with and the model call
that sends it. It reads files only: nothing is executed and nothing leaves the
machine.

With --into, the lint hits replace every `L-*` finding in an existing
findings.json (scanner text stays in English), and `meta.commit` / `meta.dirty`
are set from the repository's Git state. A reviewer's latest verdict on the
same rule and location is kept as `previous_validation`, across rescans until a
new review replaces it; the new hit starts `Unverified`.

--out replaces only an earlier inventory.json: an existing file of any other
kind (findings.json, with --out and --into swapped) is refused.

The lint runs on its own in CI, without a review: --sarif writes the hits as
SARIF 2.1.0 (as export.py sarif does for a review), --fail-on SEVERITY prints
each hit at that severity or above as `path:line: severity rule: detail` and
exits 1 when there is one, and --baseline names an earlier review's
findings.json whose L-* verdicts FalsePositive or NotApplicable suppress the
same hit (same rule, file and named variables, keys or tag; line numbers aside,
so an edit above it does not bring it back). With --sarif or --fail-on and no
--out, the inventory is not written to stdout.

Exit codes: 0 written, 1 --fail-on threshold reached, 2 unreadable input,
unwritable output or schema error.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bindings as binding_tool  # noqa: E402
import record  # noqa: E402
from excerpt import SECRET_RE, has_secret_needle, sensitive, source_lines  # noqa: E402
from scan_report_kit.output import unsafe_target, write_output  # noqa: E402

VCS_DIRS = {".git", ".hg", ".svn"}
SKIP_DIRS = VCS_DIRS | {"node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build",
             ".next", ".nuxt", "vendor", "target", "coverage", ".tox", ".mypy_cache", ".pytest_cache",
             "site-packages", ".idea", ".vscode"}
MAX_FILE_BYTES = 1024 * 1024
TEXT_SUFFIXES = {".md", ".mdx", ".mdc", ".txt", ".prompt", ".prompty", ".j2", ".jinja", ".jinja2", ".tmpl",
                 ".tpl", ".mustache", ".hbs", ".yaml", ".yml", ".json", ".xml", ".toml"}
CODE_SUFFIXES = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java", ".kt", ".cs",
                 ".php", ".rs", ".swift", ".ex", ".exs"}
CONFIG_SUFFIXES = {".yaml", ".yml", ".json", ".toml"}
# Files a template engine renders by definition, whether or not they open a {{ yet.
ENGINE_SUFFIXES = {".j2", ".jinja", ".jinja2", ".mustache", ".hbs", ".tmpl", ".tpl"}
AGENT_NAMES = {"AGENTS.md", "CLAUDE.md", "GEMINI.md", ".cursorrules", ".windsurfrules",
               "copilot-instructions.md"}
PROMPT_DIRS = {"prompts", "prompt", "system_prompts", "system-prompts", "instructions"}
AGENT_DIRS = (".claude/agents", ".claude/commands", ".cursor/rules", ".github/prompts", ".codex/agents")

# (api, pattern, needles): every match of the pattern contains one of its needles, so a file holding none
# is skipped without the pattern's word-boundary tests at each character. Keep the two in step;
# tests/test_inventory.py checks that the needles cover each pattern.
CALL_PATTERNS = [
    ("anthropic.messages", re.compile(r"\.messages\.(?:create|stream|count_tokens)\s*\("), (".messages.",)),
    ("openai.chat.completions", re.compile(r"\.chat\.completions\.(?:create|parse)\s*\("), (".chat.completions.",)),
    ("openai.responses", re.compile(r"\.responses\.(?:create|parse)\s*\("), (".responses.",)),
    ("gemini.generate_content", re.compile(r"\b(?:generate_content|generateContent)\s*\("),
     ("generate_content", "generateContent")),
    ("ai-sdk", re.compile(r"\b(?:generateText|streamText|generateObject|streamObject)\s*\("),
     ("generateText", "streamText", "generateObject", "streamObject")),
    ("langchain", re.compile(r"\b(?:ChatPromptTemplate|PromptTemplate|SystemMessagePromptTemplate|"
                             r"SystemMessage|HumanMessage)\b"), ("PromptTemplate", "SystemMessage", "HumanMessage")),
    ("role:system", re.compile(r"""["']?role["']?\s*[:=]\s*["']system["']"""), ("role",)),
    ("prompt-variable", re.compile(r"\b(?:SYSTEM_PROMPT|system_prompt|systemPrompt|PROMPT_TEMPLATE|"
                                   r"prompt_template|promptTemplate)\b\s*[:=]"),
     ("SYSTEM_PROMPT", "system_prompt", "systemPrompt", "PROMPT_TEMPLATE", "prompt_template", "promptTemplate")),
]
# Call sites that send a prompt to a model; their arguments are recorded and their prompts linked.
SENDING_APIS = {"anthropic.messages", "openai.chat.completions", "openai.responses", "gemini.generate_content",
                "ai-sdk"}
SENDERS = [pattern for api, pattern, _ in CALL_PATTERNS if api in SENDING_APIS]
SCHEMA_ARGS = binding_tool.SCHEMA_ARGS
# Bare IDs plus the forms clouds use: Bedrock `us.anthropic.claude-…-v1:0`, Vertex `claude-…@20240620`,
# Gemini `models/gemini-…`.
_TAIL = r"(?:[a-z0-9.-]*[a-z0-9])?"
MODEL_RE = re.compile(r"""["'`]((?:(?:[a-z]{2,6}\.)?anthropic\.)?claude-[a-z0-9]""" + _TAIL + r"""(?:@[0-9]{8})?"""
                      r"""(?::[0-9]+)?|(?:chat)?gpt-[0-9a-z]""" + _TAIL + r"""|"""
                      r"""o[134](?:-mini|-pro|-preview)?(?:-[0-9]{4}-[0-9]{2}-[0-9]{2})?|"""
                      r"""(?:models/)?gemini-(?:[0-9]|pro|flash|ultra|nano|exp)""" + _TAIL + r"""|"""
                      r"""mistral-[a-z0-9]""" + _TAIL + r"""|llama-?[0-9]""" + _TAIL + r""")["'`]""")
VARIABLE_RES = [
    re.compile(r"\{\{[-~]?\s*([A-Za-z_][\w.]*)"),       # Jinja ({{- x }}), Mustache, Handlebars ({{~ x}})
    # str.format and f-string style, with an optional conversion and format spec: {amount:.2f}, {name!r}
    re.compile(r"(?<![{$])\{([A-Za-z_]\w*)(?:![rsa])?(?::[^{}\s]*)?\}(?!\})"),
    re.compile(r"\$\{([A-Za-z_]\w*)\}"),                # JS template literal, string.Template
]
# The placeholder syntax each kind of render call fills (bindings.RENDER_STYLE): str.format and f-string
# templates single braces, Jinja and Mustache double braces, string.Template ${name} and $name; "any" (a
# literal .replace, or a template sent without rendering) every syntax above but the bare $name.
STYLE_RES = {"brace": [VARIABLE_RES[1]], "jinja": [VARIABLE_RES[0]],
             "dollar": [VARIABLE_RES[2], re.compile(r"(?<![\w$\\])\$([A-Za-z_]\w*)")], "any": VARIABLE_RES}
# A template that pulls in another file may fill or use names this scan cannot see.
INCLUDES = re.compile(r"\{%-?\s*(?:include|extends|import|from)\b|\{\{>")
# Names the template tests before using (an if, a default filter, a Mustache section): optional by design.
OPTIONAL = re.compile(r"\{%-?\s*(?:if|elif|unless)\b([^%]*)%\}|\{\{[#^]\s*(?:if\s+|unless\s+|with\s+)?([\w.]+)|"
                      r"([A-Za-z_]\w*)\s*\|\s*default\b|([A-Za-z_]\w*)\s+is\s+(?:not\s+)?defined")
# Every template construct; a word in none of them is not a name the template uses.
CONSTRUCT = re.compile(r"\{\{.*?\}\}|\{%.*?%\}|\$\{[^}\n]*\}|\{[^{}\n]*\}|\$[A-Za-z_]\w*")
# File references in agent and skill prompts: Markdown links, CLAUDE.md-style @imports, and paths in code
# spans. A path in a code span is judged only when its directory exists (a renamed or moved file); one
# under a directory that does not exist may name a file to create, or one in another repository.
MD_LINK = re.compile(r"\]\(([^)\s#<>]+)(?:#[^)\s]*)?(?:\s+\"[^\"]*\")?\)")
AT_IMPORT = re.compile(r"(?<![\w@`])@((?:\.{1,2}/)*[A-Za-z0-9_][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_.-]+)*)")
PATH_TOKEN = re.compile(r"(?:\.{1,2}/)*\.?[A-Za-z0-9_][A-Za-z0-9_.-]*(?:/\.?[A-Za-z0-9_][A-Za-z0-9_.-]*)+/?")
REF_SUFFIXES = {".md", ".mdc", ".mdx", ".txt", ".py", ".sh", ".js", ".mjs", ".cjs", ".ts", ".json", ".yaml",
                ".yml", ".toml", ".prompt", ".prompty", ".j2", ".jinja", ".jinja2", ".tmpl", ".csv", ".html",
                ".sql", ".xml"}
TEMPLATE_TOKEN = re.compile(r"\{\{|\}\}|\{%|%\}")
PAIRS = {"{{": "}}", "{%": "%}"}
OPEN_TAG = re.compile(r"<([a-z][\w-]*)((?:\s+[\w:-]+\s*=\s*(?:\"[^\"]*\"|'[^']*'))*)\s*(/?)>")
CLOSE_TAG = re.compile(r"</([a-z][\w-]*)\s*>")
HTML_TAGS = set("""a abbr article aside audio b blockquote body br button caption center cite code col dd del
details div dl dt em figcaption figure font footer form g h1 h2 h3 h4 h5 h6 head header hr html i iframe img
input ins kbd label li link main mark meta nav ol option p path picture pre q s samp script section select
small source span strong style sub summary sup svg table tbody td textarea th thead time title tr u ul var
video""".split())
INLINE_CODE = re.compile(r"(`+)(?!`).+?(?<!`)\1(?!`)")  # Markdown code span: an example, not markup
# XXX inside a hyphenated run is a format mask (XXX-XXX-XXXX), not a placeholder.
PLACEHOLDER_RE = re.compile(r"\b(?:TODO|FIXME|TBD)\b|(?<![\w-])XXX(?![\w-])|(?i:lorem ipsum)|(?i:\[(?:insert|placeholder)\b[^\]]*\])")
# Names a template defines or the engine provides, which no caller has to fill.
TEMPLATE_BUILTINS = {"loop", "self", "super", "caller", "varargs", "kwargs", "range", "else", "this", "true",
                     "false", "none", "null"}
TEMPLATE_DEFINES = re.compile(r"\{%-?\s*(?:set|for|with)\s+([A-Za-z_][\w, ]*?)\s*(?:=|\bin\b|%\})|"
                              r"\{%-?\s*macro\s+\w+\s*\(([^)]*)\)|\{\{#each\s+[\w.]+\s+as\s+\|([\w ]+)\|")
CODE_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
LARGE_PROMPT_TOKENS = 8000
DUPLICATE_MIN_CHARS = 40

NOT_COVERED = [
    "prompts built at runtime from string pieces in code (only call sites, prompt variables and string "
    "literals assigned to prompt-named names are listed)",
    "prompts loaded from databases, prompt registries, feature flags or environment variables",
    "provider-side or framework-added system text",
]
# Added to not_covered when a directory was pruned: by name (a skill or prompt directory called build,
# coverage, env or vendor is skipped too) or because it is a symlink the walk does not follow, so each
# pruned path is listed in skipped_dirs.
SKIPPED_NOTE = ("files under directories skipped by name (dependencies, environments, build output) "
                "or because they are symlinks (see skipped_dirs)")
# Added when a file that would be a prompt file could not be read as text; each is listed in skipped_files.
UNREAD_NOTE = "prompt files not read: symlinked, binary, unreadable or over 1 MiB (see skipped_files)"

# Text for each lint rule's L-* finding. Scanner-written text stays in English.
RULES = {
    "unbalanced-template": dict(
        kind="defect", severity="Medium", confidence="Suspected", category="Variables and assembly",
        title="Unbalanced template delimiters",
        symptom="The template engine may fail to render, or render a delimiter literally into the prompt.",
        impact="The call fails, or the model receives broken markup in place of the intended variable.",
        fix="Balance the delimiter, or escape it when a literal brace is intended.",
        test="Render the template with representative values and assert no template delimiter remains."),
    "unclosed-tag": dict(
        kind="defect", severity="Low", confidence="Suspected", category="Structure and placement",
        title="Prompt section tag opened but not closed",
        symptom="The model cannot tell where the tagged section ends; following text may be read as part of it.",
        impact="Instructions or data after the tag may be treated as the wrong kind of content.",
        fix="Close the tag, or rename the closing tag to match the opening one.",
        test="Assert every section tag in the rendered prompt has a matching closing tag."),
    "placeholder": dict(
        kind="defect", severity="Low", confidence="Suspected", category="Maintainability",
        title="Placeholder text in a prompt",
        symptom="The model receives unfinished text (TODO, TBD, lorem ipsum, [INSERT ...]).",
        impact="The model may follow or echo the placeholder, or the intended instruction is missing.",
        fix="Replace the placeholder with the intended text, or move the note into a template comment.",
        test="Assert the rendered prompt contains no placeholder markers."),
    "unreferenced-variable": dict(
        kind="defect", severity="Medium", confidence="Suspected", category="Variables and assembly",
        title="Template variable named nowhere in the code",
        symptom="The variable may reach the model empty, as a literal placeholder, or fail the render.",
        impact="The prompt is sent without the content the variable was meant to carry.",
        fix="Fill the variable at the call site that renders this template, or remove it from the template.",
        test="Render the template from its call site with strict undefined-variable handling and assert it succeeds."),
    "unfilled-variable": dict(
        kind="defect", severity="High", confidence="Suspected", category="Variables and assembly",
        title="Template variable the rendering code does not fill",
        symptom="The variable reaches the model empty or as a literal placeholder, or the render fails "
                "(str.format raises KeyError).",
        impact="Every call through that render sends the prompt without the content the variable was meant to "
               "carry, or fails.",
        fix="Pass the variable at the render call named in the cause, or remove it from the template; render "
            "with strict undefined-variable handling.",
        test="Render the template from the named call site with strict undefined-variable handling and assert "
             "it succeeds and contains the variable's content."),
    "unused-render-key": dict(
        kind="defect", severity="Medium", confidence="Suspected", category="Variables and assembly",
        title="Value passed to a template that never uses it",
        symptom="The code passes a value when rendering the template, but the template has no placeholder of "
                "that name, so the value is dropped.",
        impact="Content the caller prepared for the model (often under a renamed variable) never reaches it.",
        fix="Add the placeholder where the template needs the value, rename the key to the placeholder it was "
            "meant for, or stop passing it.",
        test="Render the template from the named call site and assert the rendered prompt contains the passed "
             "value."),
    "unrequested-output-key": dict(
        kind="defect", severity="High", confidence="Suspected", category="Output contract",
        title="Code reads a reply key the prompt never asks for",
        symptom="The code reads a key from the model's JSON reply that no prompt sent on that call names, so "
                "the model has no reason to produce it.",
        impact="The read fails (KeyError) or yields nothing on ordinary replies; the feature returns wrong or "
               "empty output.",
        fix="Ask for the key in the prompt's output format, or read the key the prompt asks for; better, use "
            "structured output with one schema shared by the prompt and the parser.",
        test="For a representative input, parse the reply as the code does and assert every key it reads is "
             "present."),
    "missing-file-reference": dict(
        kind="defect", severity="Medium", confidence="Suspected", category="Instruction consistency",
        title="Prompt points to a file that does not exist",
        symptom="The prompt tells the model to read or use a file that is not in the repository.",
        impact="The model cannot follow that instruction: it searches, guesses the file's content or goes on "
               "without it.",
        fix="Point the reference at the file's current path, restore the file, or remove the instruction.",
        test="Assert every file the prompt cites resolves in the repository, relative to the prompt file or the "
             "repository root."),
    "duplicate-line": dict(
        kind="improvement", severity="Info", confidence="Confirmed", category="Context budget",
        title="Repeated line in a prompt",
        symptom="The same long line appears more than once in one prompt file.",
        impact="Tokens are spent twice; if one copy is later edited, the two diverge.",
        fix="Keep one copy where it applies, or state why the repetition is deliberate.",
        test="Assert the rendered prompt contains each long instruction line once."),
    "secret-literal": dict(
        kind="defect", severity="High", confidence="Suspected", category="Untrusted input",
        title="Secret-looking value in a prompt file",
        symptom="A value with the format of a credential is part of prompt text.",
        impact="Anything that can make the model repeat its prompt can disclose the value.",
        fix="Remove the value from the prompt and rotate it; pass credentials to code, never to the model.",
        test="Assert the rendered prompt matches no credential pattern."),
    "large-prompt": dict(
        kind="improvement", severity="Info", confidence="Confirmed", category="Context budget",
        title="Large prompt file",
        symptom=f"The file alone is estimated at more than {LARGE_PROMPT_TOKENS} tokens.",
        impact="Cost and latency on every call; less room for inputs and output.",
        fix="Move rarely needed material to on-demand context, or cache the static prefix.",
        test="Assert the rendered prompt's estimated token count stays under the agreed budget."),
}
SEVERITY_RANK = {s: i for i, s in enumerate(record.SEVERITIES)}


def walk(root, skipped=None, unread=None):
    """Files under root, sorted; each directory pruned by name (VCS metadata aside) or not followed because it
    is a symlink is added to skipped, and each symlink that would be a prompt file to unread."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        # Once per directory: the relative path of each entry is this one's plus its name.
        prefix = here.relative_to(root).as_posix() + "/"
        prefix = "" if prefix == "./" else prefix
        if skipped is not None:
            skipped += [prefix + d for d in sorted(dirnames)
                        if d in SKIP_DIRS - VCS_DIRS or d not in SKIP_DIRS and (here / d).is_symlink()]
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = here / name
            # One lstat answers both is_symlink() and is_file(): a path that is not a link stats as itself.
            try:
                mode = os.lstat(path).st_mode
            except OSError:
                mode = 0  # As is_symlink() and is_file() answer for a path that cannot be stat'ed.
            link = stat.S_ISLNK(mode)
            if link or not stat.S_ISREG(mode) or sensitive(name):
                rel = prefix + name
                if unread is not None and link and not sensitive(name) and prompt_kind(shown(rel)):
                    unread.append({"path": shown(rel), "reason": "symlink"})
                continue
            yield path, prefix + name


def shown(rel):
    """A path as reported: a name that is not UTF-8 gets its bytes escaped (\\xff), which JSON can hold."""
    return os.fsencode(rel).decode("utf-8", "backslashreplace")


def read_text(path):
    """(text, None), or (None, why the file was not read)."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None, "over 1 MiB"
        raw = path.read_bytes()
    except OSError:
        return None, "unreadable"
    if b"\x00" in raw:
        return None, "binary"
    return raw.decode("utf-8", errors="replace"), None


def prompt_kind(rel):
    """The prompt kind for a path, or None when the path is not a prompt file."""
    path = Path(rel)
    name, suffix = path.name, path.suffix.lower()
    if name == "SKILL.md":
        return "skill"
    if name in AGENT_NAMES or any(rel.startswith(d + "/") or f"/{d}/" in rel for d in AGENT_DIRS):
        return "agent"
    if suffix in {".prompt", ".prompty"} or name.endswith(".prompt.md"):
        return "template"
    parts = {p.lower() for p in path.parts[:-1]}
    if parts & PROMPT_DIRS and suffix in TEXT_SUFFIXES:
        return "template"
    return None


def estimate_tokens(text):
    """A rough estimate: about four ASCII characters per token, one per other character."""
    # Encoding to ASCII and dropping the rest keeps exactly the characters below 128, counted in C; a slice
    # at a time, so no copy of a whole large file is made.
    ascii_chars = len(text) if text.isascii() else sum(
        len(text[i:i + 1024].encode("ascii", "ignore")) for i in range(0, len(text), 1024))
    return ascii_chars // 4 + (len(text) - ascii_chars)


def match_lines(pattern, text):
    """Indices (0-based) of the lines, as source_lines() splits text, on which some match of pattern starts.

    One search of the whole text replaces a search of every line. Each line pattern.search(line) matches is
    among them: that match is also one of the whole text, since the line breaks around it (\\n, and a \\r
    source_lines strips) satisfy every boundary the patterns test as the ends of the line do. A match running
    over a line break may add a line no per-line search matches, so callers still test each line returned.
    """
    found, pos, line = [], 0, 0
    while True:
        m = pattern.search(text, pos)
        if m is None:
            return found
        line += text.count("\n", pos, m.start())
        found.append(line)
        end = text.find("\n", m.start())
        if end < 0:
            return found
        pos, line = end + 1, line + 1


def without_code_spans(line):
    """The line with its Markdown code spans removed; a line without a backtick has none to remove."""
    return INLINE_CODE.sub("", line) if "`" in line else line


def variables(text, patterns=VARIABLE_RES):
    found = []
    for pattern in patterns:
        for name in pattern.findall(text):
            if name not in found:
                found.append(name)
    return found


FENCE = re.compile(r"^([ \t]*)(`{3,}|~{3,})")
LIST_ITEM = re.compile(r"^[ \t]*(?:[-*+]|[0-9]{1,9}[.)])[ \t]+")


def width(indent):
    return len(indent.expandtabs(4))


def fenced_lines(lines):
    """Line numbers (1-based) inside Markdown code fences, which hold examples rather than prompt markup.

    As in CommonMark, a fence opens with at most three spaces of indentation (more inside a list item,
    relative to the item's text), so a line indented four spaces outside a list is an indented code
    block; it closes only on a bare run of its own character at least as long as the opener and
    indented at most three spaces more than it, so a ``` line inside a ```` fence, or an indented ```
    in the fenced code, stays inside; and a backtick run followed by another backtick on its line
    (```json``` is ...) is inline code, not an opener.
    """
    fence, indent, item, result = None, 0, None, set()
    for number, line in enumerate(lines, 1):
        m = FENCE.match(line)
        if fence is None:
            listed = LIST_ITEM.match(line)
            if listed:
                item = width(listed.group(0))
            elif line.strip() and item is not None and width(line[:len(line) - len(line.lstrip())]) < item:
                item = None  # A line left of the item's text ends the list.
            if m and width(m.group(1)) <= (item or 0) + 3 \
                    and not (m.group(2)[0] == "`" and "`" in line[m.end():]):
                fence, indent = m.group(2), width(m.group(1))
                result.add(number)
        else:
            result.add(number)
            if m and m.group(2)[0] == fence[0] and len(m.group(2)) >= len(fence) \
                    and not line[m.end():].strip() and width(m.group(1)) <= indent + 3:
                fence = None
    return result


def lint_template(lines, fenced, engine=False, data=False):
    stack, hits = [], []
    prose = [(number, line) for number, line in enumerate(lines, 1) if number not in fenced]
    # Outside an engine template file, a file that never opens {{ or {% is not a template: a }} there is
    # JSON or literal text. In a JSON, YAML or TOML file it closes nested objects even when a value holds
    # a {{variable}}, so only an opener left open counts there.
    templated = engine or not data and any(token in PAIRS for _, line in prose for token in TEMPLATE_TOKEN.findall(line))
    for number, line in prose:
        for token in TEMPLATE_TOKEN.findall(line):
            if token in PAIRS:
                stack.append((token, number))
            elif stack and PAIRS[stack[-1][0]] == token:
                stack.pop()
            elif templated:
                hits.append((number, f"closing {token} with no matching opener"))
    hits += [(number, f"{token} opened and never closed") for token, number in stack]
    return [min(hits)] if hits else []


def lint_tags(lines, fenced):
    opened = {}
    for number, line in enumerate(lines, 1):
        if number in fenced:
            continue
        for name, _attrs, selfclosing in OPEN_TAG.findall(line):
            if name not in HTML_TAGS and not selfclosing:
                opened.setdefault(name, []).append(number)
        for name in CLOSE_TAG.findall(line):
            if opened.get(name):
                opened[name].pop()
    return [(numbers[0], f"<{name}> opened {len(numbers)} more time(s) than closed")
            for name, numbers in sorted(opened.items(), key=lambda kv: kv[1][0] if kv[1] else 0) if numbers]


def template_uses(text, *, lines=None, fenced=None, patterns=VARIABLE_RES):
    """(line, names) for each line outside code fences that uses a template variable the template itself
    does not define: what a caller has to fill. lines and fenced, when given, are source_lines(text) and
    fenced_lines() of them, which scan() has already worked out; patterns narrows the placeholder syntax
    (STYLE_RES)."""
    lines = source_lines(text) if lines is None else lines
    fenced = fenced_lines(lines) if fenced is None else fenced
    defined = set(TEMPLATE_BUILTINS)
    for groups in TEMPLATE_DEFINES.findall(text):
        defined |= set(CODE_WORD.findall(" ".join(groups)))
    uses = []
    for number, line in enumerate(lines, 1):
        # Every VARIABLE_RES pattern opens a brace, so a line without one uses no variable.
        if number in fenced or "{" not in line and (patterns is VARIABLE_RES or "$" not in line):
            continue
        names = [n.split(".")[0] for n in variables(without_code_spans(line), patterns)]
        names = [n for n in dict.fromkeys(names) if n.lower() not in defined and n not in defined]
        if names:
            uses.append((number, names))
    return uses


def lint_unreferenced(templates, code_words, settled=None):
    """One unreferenced-variable hit per template file whose variables some name no code file contains;
    a name lint_bindings() settled for that file (settled[rel]) is left out."""
    hits = []
    for rel, uses in templates:
        done = (settled or {}).get(rel, set())
        missing = [(number, name) for number, names in uses for name in names
                   if name not in code_words and name not in done]
        if missing:
            names = list(dict.fromkeys(name for _, name in missing))
            hits.append(dict(rule="unreferenced-variable", location=f"{rel}:{missing[0][0]}",
                             detail=f"{len(names)} variable(s) no code file names: {', '.join(names)}", **{
                                 k: RULES["unreferenced-variable"][k] for k in ("kind", "severity", "confidence", "category")}))
    return hits


def optional_names(text):
    return {word for groups in OPTIONAL.findall(text) for group in groups for word in CODE_WORD.findall(group)}


def lint_bindings(templates, bindings):
    """unfilled-variable and unused-render-key hits from the render sites bindings.trace() found.

    templates maps a template path to (text, lines, fenced). A template that includes or extends another is
    skipped: that file may fill or use the names. unfilled-variable needs a complete site of a traced
    binding; unused-render-key needs only a site of a binding naming this one file. A site that both leaves
    a variable unfilled and passes a key the template never uses (a renamed variable, usually) is one
    unfilled-variable hit naming both.

    Returns (hits, settled): settled maps a template to the names unreferenced-variable must not report
    again, those unfilled-variable reported and, when every binding is traced and every site complete in
    one placeholder syntax, the brace text that syntax does not fill (a {example} in a Jinja template)."""
    hits, settled = [], {}
    for rel, (text, lines, fenced) in templates.items():
        mine = [b for b in bindings if b["prompt"] == rel and not b.get("ambiguous")]
        if not mine or INCLUDES.search(text):
            continue
        optional = optional_names(text)
        used = {word for chunk in CONSTRUCT.findall(text) for word in CODE_WORD.findall(chunk)}
        uses = {style: template_uses(text, lines=lines, fenced=fenced, patterns=patterns)
                for style, patterns in STYLE_RES.items()}
        missing, sites, renamed, extra, lost_at = {}, [], [], [], set()
        for b in mine:
            for site in b["renders"]:
                unused = [k for k in site["keys"] if k not in used]
                lost = []
                if b["traced"] and site["complete"]:
                    for number, names in uses[site["style"]]:
                        for name in names:
                            if name not in site["keys"] and name not in optional:
                                lost.append(name)
                                missing.setdefault(name, number)
                if lost:
                    verb = "sends it without rendering" if site["via"] == "sent" else "renders it"
                    sites.append(f"{site['location']} {verb}")
                    lost_at.add(site["location"])
                    renamed += [k for k in unused if k not in renamed]
                elif unused:
                    extra.append((site["location"], unused))
        styles = {s["style"] for b in mine for s in b["renders"]}
        if all(b["traced"] and b["renders"] and all(s["complete"] for s in b["renders"]) for b in mine) \
                and len(styles) == 1 and styles != {"any"}:
            filled = {n for _, names in uses[styles.pop()] for n in names}
            settled[rel] = {n for _, names in template_uses(text, lines=lines, fenced=fenced) for n in names} - filled
        if missing:
            names = sorted(missing, key=lambda n: (missing[n], n))
            detail = f"{len(names)} variable(s) not filled where {', '.join(dict.fromkeys(sites))}: {', '.join(names)}"
            if renamed:
                detail += f"; that call passes {', '.join(renamed)}, which the template never uses"
            hits.append(dict(rule="unfilled-variable", location=f"{rel}:{min(missing.values())}", detail=detail,
                             **{k: RULES["unfilled-variable"][k] for k in ("kind", "severity", "confidence", "category")}))
            settled[rel] = settled.get(rel, set()) | set(names)
        for location, keys in dict(extra).items():
            if location in lost_at:
                continue
            hits.append(dict(rule="unused-render-key", location=location,
                             detail=f"renders {rel} with {len(keys)} key(s) the template never uses: {', '.join(keys)}",
                             **{k: RULES["unused-render-key"][k] for k in ("kind", "severity", "confidence", "category")}))
    return hits, settled


def resolves(root, base, ref):
    """True, False, or None when ref leaves the repository or is not a repository path."""
    ref = ref.split("#")[0].split("?")[0]
    if not ref or ref.startswith(("/", "~")) or re.match(r"[a-z][a-z0-9+.-]*:", ref):
        return None
    for start in (base, ""):
        target = os.path.normpath(os.path.join(start, ref))
        if target == ".." or target.startswith("../") or os.path.isabs(target):
            continue
        if os.path.lexists(os.path.join(root, target)):
            return True
    return False


def lint_references(root, rel, lines, fenced):
    """missing-file-reference: the paths an agent or skill prompt cites that exist neither next to it nor
    from the repository root. Markdown links and @imports always count; a code-span path counts when it
    names a file with a known suffix (or a directory, with a trailing /) and its own directory exists."""
    base = os.path.dirname(os.fsdecode(os.fsencode(rel)))
    missing = []
    for number, line in enumerate(lines, 1):
        if number in fenced:
            continue
        refs = [(ref, False) for ref in MD_LINK.findall(line) if "{{" not in ref]
        prose = without_code_spans(line)
        refs += [(ref, False) for ref in AT_IMPORT.findall(prose)
                 if "/" in ref or Path(ref).suffix.lower() in REF_SUFFIXES]
        for span in INLINE_CODE.finditer(line):
            for token in span.group(0).strip("`").split():
                token = token.rstrip(".,;:)")
                if PATH_TOKEN.fullmatch(token) and "." not in token.split("/")[0].lstrip(".") and (
                        token.endswith("/") or Path(token).suffix.lower() in REF_SUFFIXES):
                    refs.append((token, True))
        for ref, guarded in refs:
            if guarded:
                parent = os.path.dirname(ref.rstrip("/")) or "."
                if not resolves(root, base, parent):
                    continue
            if resolves(root, base, ref.rstrip("/") or ".") is False and ref not in (r for _, r in missing):
                missing.append((number, ref))
    if not missing:
        return []
    names = [ref for _, ref in missing]
    return [dict(rule="missing-file-reference", location=f"{rel}:{missing[0][0]}",
                 detail=f"{len(names)} reference(s) to files that do not exist: {', '.join(names)}",
                 **{k: RULES["missing-file-reference"][k] for k in ("kind", "severity", "confidence", "category")})]


def lint_file(rel, text, tokens, *, lines=None, fenced=None, line_map=None):
    """Lint hits for one prompt file; lines and fenced as template_uses() takes them. With line_map (the
    file line of each of lines), text is an inline prompt in code: its braces belong to the code's string
    syntax (an f-string's {{ is a literal brace), so unbalanced-template is not applied."""
    lines = source_lines(text) if lines is None else lines
    fenced = fenced_lines(lines) if fenced is None else fenced
    # Markup rules skip code fences and inline code spans: both hold examples such as `<out>`.
    prose = [without_code_spans(line) for line in lines]
    hits = []
    suffix = Path(rel).suffix.lower()
    for number, detail in [] if line_map else lint_template(prose, fenced, suffix in ENGINE_SUFFIXES,
                                                            suffix in CONFIG_SUFFIXES):
        hits.append(("unbalanced-template", number, detail))
    for number, detail in lint_tags(prose, fenced):
        hits.append(("unclosed-tag", number, detail))
    marks = [n for n, line in enumerate(prose, 1) if n not in fenced and PLACEHOLDER_RE.search(line)]
    if marks:
        hits.append(("placeholder", marks[0], f"{len(marks)} line(s) with placeholder markers"))
    seen, repeats = {}, []
    for number, line in enumerate(lines, 1):
        key = " ".join(line.split())
        if len(key) >= DUPLICATE_MIN_CHARS and not key.startswith("|"):
            if key in seen:
                repeats.append(number)
            else:
                seen[key] = number
    if repeats:
        hits.append(("duplicate-line", repeats[0], f"{len(repeats)} repeated line(s)"))
    secrets = [n for n, line in enumerate(lines, 1) if SECRET_RE.search(line)] if has_secret_needle(text) else []
    if secrets:
        # Location and kind only; the value is never copied.
        hits.append(("secret-literal", secrets[0], f"{len(secrets)} line(s) with a credential-shaped value"))
    if tokens > LARGE_PROMPT_TOKENS:
        hits.append(("large-prompt", 1, f"about {tokens} tokens"))
    if line_map:
        hits = [(rule, line_map[min(number, len(line_map)) - 1], detail) for rule, number, detail in hits]
    return [dict(rule=rule, location=f"{rel}:{number}", detail=detail, **{
        k: RULES[rule][k] for k in ("kind", "severity", "confidence", "category")}) for rule, number, detail in hits]


def git_state(root, read=()):
    """HEAD, and whether what the scan read under root differs from it (None when Git cannot tell).

    Untracked files count, and so do ignored ones and files inside submodules among `read` (the paths
    the inventory reports, as on disk): the scan read them, but HEAD does not hold them. A file read
    under skip-worktree or assume-unchanged leaves the answer None: git status does not compare it. So does
    an unstaged edit that only a filter driver's clean command could confirm (an LFS pointer, say).
    """
    def git(*args, ok=(0,), stdin=None, where=root, strip=True):
        try:
            # A repository's core.fsmonitor names a command that `git status` would run.
            # --no-optional-locks: status must not refresh .git/index, a write inside the reviewed repository.
            r = subprocess.run(["git", "--no-optional-locks", "-C", str(where), "-c", "core.fsmonitor=false", *args],
                               capture_output=True, text=True, timeout=20, input=stdin, errors="surrogateescape")
        except (OSError, subprocess.TimeoutExpired):
            return None
        return (r.stdout.strip() if strip else r.stdout) if r.returncode in ok else None

    commit = git("rev-parse", "HEAD")
    if not commit:
        return None, None
    # git status hashes stat-dirty files through each filter driver's clean or process command, which the
    # repository configures; blank them all so no command from the reviewed repository runs.
    # -z --name-only: a driver name may contain spaces (filter."my x".clean).
    drivers = git("config", "-z", "--name-only", "--get-regexp", r"^filter\..*\.(clean|process)$", ok=(0, 1))
    if drivers is None:
        return commit, None
    keys = [key for key in drivers.split("\0") if key]
    # -c takes the first "=" for the end of the key, so a driver named "a=b" cannot be blanked; without
    # running status, Git cannot say whether the tree changed.
    if any("=" in key for key in keys):
        return commit, None
    no_filters = [arg for key in keys for arg in ("-c", f"{key}=")]
    # "." limits the answer to the scanned tree when root is a subdirectory of the work tree.
    # --untracked-files=normal overrides a repository's status.showUntrackedFiles=no.
    # --ignore-submodules=all keeps status out of submodules, whose own config may name filter commands too.
    # -z keeps each entry's leading status column; porcelain paths are relative to the top of the work tree.
    status = git(*no_filters, "status", "--porcelain", "-z", "--untracked-files=normal", "--ignore-submodules=all",
                 "--", ".", strip=False)
    if status is None:
        return commit, None
    changed, tokens = [], iter(status.split("\0"))
    for entry in tokens:
        if entry:
            changed.append((entry[:2], entry[3:]))
            if entry[0] in "RC":
                next(tokens, None)  # A rename or copy also names its source.
    # With its clean command blanked, a filtered file that is only stat-dirty compares its working-tree
    # content with what that command stored in HEAD (an LFS pointer, a stripped notebook): changed or not,
    # Git cannot tell without running the command. Any other entry is a change.
    unsure = [path for xy, path in changed if xy == " M"]
    unknown = False  # Set when only such files differ; a later check may still prove a change.
    if unsure and len(unsure) == len(changed) and keys:
        top = git("rev-parse", "--show-toplevel")
        attrs = git("check-attr", "-z", "--stdin", "filter", stdin="\0".join(unsure) + "\0", where=top,
                    strip=False) if top else None
        if attrs is None:
            return commit, None
        names = {key[len("filter."):].rpartition(".")[0] for key in keys}
        fields = attrs.split("\0")
        if {path for path, value in zip(fields[0::3], fields[2::3]) if value in names} >= set(unsure):  # noqa: B905 - the trailing NUL leaves a short last triple; 3.9 has no strict=
            unknown, changed = True, []
    if changed:
        return commit, True
    if not read:
        return commit, None if unknown else False
    # A submodule is a gitlink (mode 160000) in HEAD's tree, not its files. -v tags each entry: S marks
    # skip-worktree and a lowercase tag assume-unchanged, flags under which git status hides edits.
    stage = git("ls-files", "-z", "-v", "--stage", "--", ".")
    if stage is None:
        return commit, None
    entries = [(entry.split(" ", 2), entry.split("\t", 1)[1]) for entry in stage.split("\0") if "\t" in entry]
    modules = [path for (_tag, mode, _rest), path in entries if mode == "160000"]
    if any(path.startswith(module + "/") for path in read for module in modules):
        return commit, True
    read_set = set(read)
    if any(path in read_set and (tag == "S" or tag.islower()) for (tag, _mode, _rest), path in entries):
        return commit, None
    # check-ignore exits 0 when some path is ignored and 1 when none is.
    ignored = git("check-ignore", "--stdin", "-z", ok=(0, 1), stdin="\0".join(read) + "\0")
    return commit, True if ignored else None if ignored is None or unknown else False


def location_key(location):
    path, _, line = location.rpartition(":")
    return path, int(line) if line.isdigit() else 0


def link_call_sites(call_sites, found, sources, code, prompt_words=None):
    """Give each call site that sends a prompt its argument names, the literal values of the parameters that
    matter (model, max_tokens, temperature...) and the prompt files whose text it sends; return the
    unrequested-output-key hits of those calls (prompt_words maps a prompt file to the words in it)."""
    hits = []
    for site in call_sites:
        opening = site.pop("_open")
        if site["api"] not in SENDING_APIS or opening is None:
            continue
        rel = site["path"]
        src = sources.get(rel)
        if src is None:
            src = sources[rel] = binding_tool.Source(*code[rel])
        site["_at"] = opening
        details = binding_tool.call_details(src, src.lines[site["line"] - 1] + opening)
        if details is None:
            continue
        args, params, words = details
        here = f"{rel}:{site['line']}"
        site["args"], site["params"] = args, params
        sent = [b for b in found if b["loaded_at"].rpartition(":")[0] == rel and (
            set(b["targets"]) & words or here in b["sent_at"])]
        site["prompts"] = sorted({b["prompt"] for b in sent})
        if prompt_words is not None and sent:
            hits += lint_reply(site, sent, src, prompt_words)
    return hits


def lint_reply(site, sent, src, prompt_words):
    """An unrequested-output-key hit when code reads keys from the call's parsed JSON reply that neither
    the prompt files it sends, nor any other prompt file (one may be sent through a helper the trace does
    not follow), nor any string literal in its file names. A call with a schema argument (response_format,
    tools...), a spread argument or a prompt file whose path is ambiguous is not judged."""
    if SCHEMA_ARGS & set(site["args"]) or "**" in site["args"] or any(b.get("ambiguous") for b in sent):
        return []
    rel = site["path"]
    reads = binding_tool.reply_reads(src, src.lines[site["line"] - 1] + site.get("_at", 0))
    if not reads:
        return []
    asked = set().union(*prompt_words.values())
    asked |= binding_tool.string_words(src, skip=[at for *_, at in reads])
    missing = {}
    for line, key, _parse, _at in reads:
        if key not in asked:
            missing.setdefault(key, line)
    if not missing:
        return []
    keys = sorted(missing, key=lambda k: (missing[k], k))
    prompts = ", ".join(sorted({b["prompt"] for b in sent}))
    return [dict(rule="unrequested-output-key", location=f"{rel}:{min(missing.values())}",
                 detail=f"{len(keys)} key(s) read from the reply of the call at {rel}:{site['line']} that no prompt "
                        f"it sends names ({prompts}): {', '.join(keys)}",
                 **{k: RULES["unrequested-output-key"][k] for k in ("kind", "severity", "confidence", "category")})]


def scan_inline(rel, src, candidates=None):
    """(entries, hits) for the inline prompts of one code file (bindings.inline_prompts)."""
    entries, hits = [], []
    for name, start, pieces in binding_tool.inline_prompts(src, candidates):
        lines, numbers = [], []
        for content, first in pieces:
            for i, line in enumerate(content.split("\n")):
                lines.append(line.rstrip("\r"))
                numbers.append(first + i)
        text = "\n".join(lines)
        tokens = estimate_tokens(text)
        entries.append({"path": rel, "line": src.line(start), "name": name, "lines": len(lines), "chars": len(text),
                        "est_tokens": tokens, "variables": variables(text)})
        hits += lint_file(rel, text, tokens, lines=lines, fenced=fenced_lines(lines), line_map=numbers)
    return entries, hits


def scan(root):
    root = Path(root).resolve()
    prompt_files, call_sites, models, lint, read, skipped, unread = [], [], {}, [], set(), [], []
    templates, code_words, code_files, template_texts, prompt_words, inline = [], set(), [], {}, {}, []
    disk = {}  # The on-disk path of each code file, for the Git state of what was read.
    for path, on_disk in walk(root, skipped, unread):
        rel = shown(on_disk)
        suffix = path.suffix.lower()
        kind = prompt_kind(rel)
        is_code = suffix in CODE_SUFFIXES
        if kind is None and not is_code and suffix not in CONFIG_SUFFIXES:
            continue
        text, why = read_text(path)
        if text is None:
            if kind is not None:
                unread.append({"path": rel, "reason": why})
            continue
        lines = source_lines(text)
        if kind is not None:
            tokens = estimate_tokens(text)
            prompt_files.append({"path": rel, "kind": kind, "lines": len(lines), "chars": len(text),
                                 "est_tokens": tokens, "variables": variables(text)})
            fenced = fenced_lines(lines)
            prompt_words[rel] = set(CODE_WORD.findall(text))
            lint += lint_file(rel, text, tokens, lines=lines, fenced=fenced)
            if kind in ("skill", "agent"):
                lint += lint_references(root, on_disk, lines, fenced)
            if kind == "template":
                templates.append((rel, template_uses(text, lines=lines, fenced=fenced)))
                template_texts[rel] = (text, lines, fenced)
            read.add(on_disk)
        if is_code:
            code_words.update(CODE_WORD.findall(text))
            code_files.append((rel, text, suffix))
            disk[rel] = on_disk
        if is_code or suffix in CONFIG_SUFFIXES:
            # Only lines on which some pattern's match starts can match it; most code lines match none.
            patterns = [pattern for _, pattern, needles in CALL_PATTERNS
                        if any(needle in text for needle in needles)] if is_code else []
            candidates = sorted({i for pattern in [*patterns, MODEL_RE] for i in match_lines(pattern, text)
                                 if i < len(lines)})
            for number, line in ((i + 1, lines[i]) for i in candidates):
                if is_code:
                    for api, pattern, _needles in CALL_PATTERNS:
                        m = pattern.search(line)
                        if m:
                            call_sites.append({"path": rel, "line": number, "api": api,
                                               "_open": m.end() - 1 if line[m.end() - 1:m.end()] == "(" else None})
                            read.add(on_disk)
                for model in MODEL_RE.findall(line):
                    models.setdefault(model, []).append(f"{rel}:{number}")
                    read.add(on_disk)
    found, sources = binding_tool.trace(code_files, [f["path"] for f in prompt_files], SENDERS)
    for rel, text, suffix in code_files:
        candidates = binding_tool.inline_candidates(text)
        if candidates:
            src = sources.get(rel) or binding_tool.Source(text, suffix)
            entries, hits = scan_inline(rel, src, candidates)
            if entries:
                sources[rel] = src
                read.add(disk[rel])
                inline += entries
                lint += hits
    for f in prompt_files:
        f["loaded_by"] = sorted({b["loaded_at"] for b in found if b["prompt"] == f["path"]}, key=location_key)
    lint += link_call_sites(call_sites, found, sources, dict((rel, (text, suffix)) for rel, text, suffix in code_files),
                            prompt_words)
    for site in call_sites:
        site.pop("_at", None)
    hits, settled = lint_bindings(template_texts, found)
    lint += hits
    # Without any code there is no caller to check against: a prompt-only repository is filled elsewhere.
    if code_words:
        lint += lint_unreferenced(templates, code_words, settled)
    commit, dirty = git_state(root, sorted(read))
    lint.sort(key=lambda h: (SEVERITY_RANK[h["severity"]], h["location"].rpartition(":")[0],
                             int(h["location"].rpartition(":")[2]), h["rule"]))
    return {
        "tool": "inventory.py", "version": 1, "root": shown(root.name), "commit": commit, "dirty": dirty,
        "prompt_files": prompt_files, "inline_prompts": inline, "call_sites": call_sites, "bindings": found,
        "models": [{"id": m, "locations": locs} for m, locs in sorted(models.items())],
        "lint": lint, "skipped_dirs": [shown(d) for d in sorted(skipped)],
        "skipped_files": sorted(unread, key=lambda f: f["path"]),
        "not_covered": NOT_COVERED + ([SKIPPED_NOTE] if skipped else []) + ([UNREAD_NOTE] if unread else []),
    }


def lint_findings(lint):
    result = []
    for number, hit in enumerate(lint, 1):
        rule = RULES[hit["rule"]]
        result.append({
            "id": f"L-{number:03d}", "source": "inventory.py", "rule": hit["rule"],
            "kind": rule["kind"], "severity": rule["severity"], "confidence": rule["confidence"],
            "category": rule["category"], "title": rule["title"], "location": hit["location"],
            "symptom": rule["symptom"], "cause": f"inventory.py {hit['rule']}: {hit['detail']}.",
            "impact": rule["impact"], "fix": rule["fix"], "test": rule["test"],
            "validation": {"verdict": "Unverified", "evidence": "", "method": "inventory.py lint"},
            "status": "Open",
        })
    return result


def hit_key(rule, location, text):
    """What identifies one hit across rescans: unclosed-tag reports one hit per tag, possibly on one line."""
    if rule == "unused-render-key":
        # One call site may render several templates, each its own hit.
        tag = re.search(r"renders (\S+) with", text or "")
    else:
        tag = re.search(r"<([a-z][\w-]*)>", text or "") if rule == "unclosed-tag" else None
    return rule, location, tag.group(1) if tag else None


def suppression_key(rule, location, text):
    """What identifies a reviewed hit for --baseline: its rule, file, tag and detail with every number
    blanked, so the verdict still applies after lines move. text is a hit's detail or an L-* cause."""
    _rule, _location, tag = hit_key(rule, location, text)
    detail = re.sub(r"^inventory\.py [\w-]+: |\.$", "", text or "")
    return rule, location.rpartition(":")[0], tag, re.sub(r"[0-9]+", "#", detail)


def suppressed_by(baseline):
    """The suppression keys of the L-* findings a review judged FalsePositive or NotApplicable (a rescan
    since keeps that review as previous_validation)."""
    data = record.load(baseline, record.read_regular(baseline))
    keys = set()
    for f in data.get("findings", []):
        if not f["id"].startswith("L-") or not f.get("rule"):
            continue
        review = f["validation"]
        if review.get("verdict") == "Unverified" and isinstance(f.get("previous_validation"), dict):
            review = f["previous_validation"]
        if review.get("verdict") in record.EXCLUDED:
            keys.add(suppression_key(f["rule"], f["location"], f.get("cause")))
    return keys


def lint_report(inventory, a):
    """--baseline, --sarif and --fail-on: the exit code, after writing the SARIF file."""
    hits = inventory["lint"]
    if a.baseline:
        keys = suppressed_by(a.baseline)
        kept = [h for h in hits if suppression_key(h["rule"], h["location"], h["detail"]) not in keys]
        if len(kept) < len(hits):
            print(f"inventory.py: {len(hits) - len(kept)} hit(s) suppressed by reviewed verdicts in {a.baseline}",
                  file=sys.stderr)
        hits = kept
    if a.sarif:
        import export  # noqa: E402 - only this mode needs it
        meta = {"target": inventory["root"], "scope": "inventory.py lint", "commit": inventory["commit"]}
        a.sarif.parent.mkdir(parents=True, exist_ok=True)
        export.write(a.sarif, export.sarif({"meta": meta}, lint_findings(hits)))
        print(f"wrote {a.sarif}: {len(hits)} lint hit(s)", file=sys.stderr)
    if a.fail_on:
        limit = record.SEVERITIES.index(a.fail_on)
        failing = [h for h in hits if record.SEVERITIES.index(h["severity"]) <= limit]
        for h in failing:
            print(f"{h['location']}: {h['severity']} {h['rule']}: {h['detail']}", file=sys.stderr)
        if failing:
            print(f"inventory.py: {len(failing)} lint hit(s) at {a.fail_on} or above", file=sys.stderr)
            return 1
    return 0


def merge_into(findings_path, inventory):
    original = record.read_regular(findings_path)
    data = record.read_json(findings_path, original)
    try:
        record.validate_data(data)
    except record.SchemaError as e:
        raise record.SchemaError(f"{findings_path}: {e}") from None
    old = {hit_key(f.get("rule"), f.get("location"), f.get("cause")): f for f in data.get("findings", [])
           if isinstance(f, dict) and str(f.get("id", "")).startswith("L-")}
    new = lint_findings(inventory["lint"])
    for finding in new:
        hit = old.get(hit_key(finding["rule"], finding["location"], finding["cause"]), {})
        review = hit.get("validation")
        # The latest review wins; a hit nobody re-reviewed since the last rescan keeps the older one.
        if isinstance(review, dict) and review.get("verdict") != "Unverified":
            finding["previous_validation"] = review
        elif isinstance(hit.get("previous_validation"), dict):
            finding["previous_validation"] = hit["previous_validation"]
    data["findings"] = [f for f in data.get("findings", [])
                        if not (isinstance(f, dict) and str(f.get("id", "")).startswith("L-"))] + new
    meta = data.setdefault("meta", {})
    meta["commit"], meta["dirty"] = inventory["commit"], inventory["dirty"]
    record.validate_data(copy.deepcopy(data))
    record.write_report(Path(findings_path), data, original)
    return len(new)


def is_inventory(path):
    try:
        value = json.loads(record.read_regular(path).decode("utf-8"))
    except (OSError, UnicodeError, ValueError, RecursionError):
        return False
    return isinstance(value, dict) and value.get("tool") == "inventory.py"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("repo", type=Path)
    p.add_argument("--out", type=Path, help="write inventory.json here (default: stdout)")
    p.add_argument("--into", type=Path, help="replace the L-* findings of this findings.json")
    p.add_argument("--baseline", type=Path, help="a reviewed findings.json: its FalsePositive and NotApplicable "
                                                 "L-* verdicts suppress the same hits for --sarif and --fail-on")
    p.add_argument("--sarif", type=Path, help="write the lint hits as SARIF 2.1.0 here")
    p.add_argument("--fail-on", choices=record.SEVERITIES, metavar="SEVERITY",
                   help="print the lint hits at this severity or above and exit 1 when there is one")
    a = p.parse_args(argv)
    if not a.repo.is_dir():
        print(f"inventory.py: {a.repo}: not a directory", file=sys.stderr)
        return 2
    inventory = scan(a.repo)
    text = json.dumps(inventory, ensure_ascii=False, indent=2) + "\n"
    if a.out:
        try:
            a.out.parent.mkdir(parents=True, exist_ok=True)
            # As render.py does: a planted link must not redirect the write, e.g. into the reviewed repository.
            unsafe = unsafe_target(a.out.parent, [a.out.name])
            if unsafe:
                raise OSError(f"refusing to write {unsafe}: it exists as a symlink or non-regular file")
            if a.out.exists() and not is_inventory(a.out):
                # A swapped --out/--into would otherwise replace findings.json, the record of the whole review.
                raise OSError("it exists and is not an inventory.json (check --out against --into)")
            write_output(a.out, text)
        except OSError as e:
            print(f"inventory.py: cannot write {a.out}: {e}", file=sys.stderr)
            return 2
        print(f"wrote {a.out}: {len(inventory['prompt_files'])} prompt file(s), "
              f"{len(inventory['call_sites'])} call site(s), {len(inventory['lint'])} lint hit(s)")
    elif not (a.sarif or a.fail_on):
        sys.stdout.write(text)
    if a.into:
        try:
            count = merge_into(a.into, inventory)
        except (record.SchemaError, record.MergeConflict, OSError) as e:
            print(f"inventory.py: {e}", file=sys.stderr)
            return 2
        print(f"merged {count} L-* finding(s) into {a.into}", file=sys.stderr if not a.out else sys.stdout)
    if a.baseline or a.sarif or a.fail_on:
        try:
            if a.sarif and a.sarif.resolve() in {x.resolve() for x in (a.out, a.into, a.baseline) if x}:
                raise OSError(f"--sarif {a.sarif} is also another input or output")
            return lint_report(inventory, a)
        except (record.SchemaError, OSError) as e:
            print(f"inventory.py: {e}", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
