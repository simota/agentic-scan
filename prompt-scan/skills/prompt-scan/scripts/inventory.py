#!/usr/bin/env python3
"""Inventory the LLM prompts in a repository and lint them mechanically.

    python3 inventory.py REPO [--out inventory.json] [--into findings.json]

Lists prompt files (prompt directories, prompt and template suffixes, agent and
skill definitions), call sites of model APIs in code, template variables per
prompt file, quoted model IDs and lint hits. It reads files only: nothing is
executed and nothing leaves the machine.

With --into, the lint hits replace every `L-*` finding in an existing
findings.json (scanner text stays in English), and `meta.commit` / `meta.dirty`
are set from the repository's Git state. A reviewer's earlier verdict on the
same rule and location is kept as `previous_validation`; the new hit starts
`Unverified`.

Exit codes: 0 written, 2 unreadable input or schema error.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import findings as merge_tool  # noqa: E402
import render  # noqa: E402

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build",
             ".next", ".nuxt", "vendor", "target", "coverage", ".tox", ".mypy_cache", ".pytest_cache",
             "site-packages", ".idea", ".vscode"}
MAX_FILE_BYTES = 1024 * 1024
TEXT_SUFFIXES = {".md", ".mdx", ".mdc", ".txt", ".prompt", ".prompty", ".j2", ".jinja", ".jinja2", ".tmpl",
                 ".tpl", ".mustache", ".hbs", ".yaml", ".yml", ".json", ".xml", ".toml"}
CODE_SUFFIXES = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java", ".kt", ".cs",
                 ".php", ".rs", ".swift", ".ex", ".exs"}
CONFIG_SUFFIXES = {".yaml", ".yml", ".json", ".toml"}
AGENT_NAMES = {"AGENTS.md", "CLAUDE.md", "GEMINI.md", ".cursorrules", ".windsurfrules",
               "copilot-instructions.md"}
PROMPT_DIRS = {"prompts", "prompt", "system_prompts", "system-prompts", "instructions"}
AGENT_DIRS = (".claude/agents", ".claude/commands", ".cursor/rules", ".github/prompts", ".codex/agents")
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx"}

CALL_PATTERNS = [
    ("anthropic.messages", re.compile(r"\.messages\.(?:create|stream|count_tokens)\s*\(")),
    ("openai.chat.completions", re.compile(r"\.chat\.completions\.(?:create|parse)\s*\(")),
    ("openai.responses", re.compile(r"\.responses\.(?:create|parse)\s*\(")),
    ("gemini.generate_content", re.compile(r"\b(?:generate_content|generateContent)\s*\(")),
    ("ai-sdk", re.compile(r"\b(?:generateText|streamText|generateObject|streamObject)\s*\(")),
    ("langchain", re.compile(r"\b(?:ChatPromptTemplate|PromptTemplate|SystemMessagePromptTemplate|"
                             r"SystemMessage|HumanMessage)\b")),
    ("role:system", re.compile(r"""["']?role["']?\s*[:=]\s*["']system["']""")),
    ("prompt-variable", re.compile(r"\b(?:SYSTEM_PROMPT|system_prompt|systemPrompt|PROMPT_TEMPLATE|"
                                   r"prompt_template|promptTemplate)\b\s*[:=]")),
]
MODEL_RE = re.compile(r"""["'`]((?:claude-[a-z0-9][a-z0-9.-]*[a-z0-9])|(?:gpt-[0-9a-z][a-z0-9.-]*[a-z0-9])|"""
                      r"""(?:o[134](?:-mini|-pro)?)|(?:gemini-[0-9][a-z0-9.-]*[a-z0-9])|"""
                      r"""(?:mistral-[a-z0-9.-]*[a-z0-9])|(?:llama-?[0-9][a-z0-9.-]*[a-z0-9]))["'`]""")
VARIABLE_RES = [
    re.compile(r"\{\{\s*([A-Za-z_][\w.]*)"),            # Jinja, Mustache, Handlebars
    re.compile(r"(?<![{$])\{([A-Za-z_]\w*)\}(?!\})"),   # str.format, f-string style
    re.compile(r"\$\{([A-Za-z_]\w*)\}"),                # JS template literal, string.Template
]
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
PLACEHOLDER_RE = re.compile(r"\b(?:TODO|FIXME|TBD|XXX)\b|(?i:lorem ipsum)|(?i:\[(?:insert|placeholder)\b[^\]]*\])")
SECRET_RE = render.SECRET_RE
LARGE_PROMPT_TOKENS = 8000
DUPLICATE_MIN_CHARS = 40

NOT_COVERED = [
    "prompts built at runtime from string pieces in code (only call sites and prompt variables are listed)",
    "prompts loaded from databases, prompt registries, feature flags or environment variables",
    "provider-side or framework-added system text",
]

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
SEVERITY_RANK = {s: i for i, s in enumerate(render.SEVERITIES)}


def walk(root):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if path.is_symlink() or not path.is_file() or name.startswith(".env") \
                    or path.suffix.lower() in SENSITIVE_SUFFIXES:
                continue
            yield path, rel


def read_text(path):
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw:
        return None
    return raw.decode("utf-8", errors="replace")


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
    ascii_chars = sum(1 for c in text if ord(c) < 128)
    return ascii_chars // 4 + (len(text) - ascii_chars)


def variables(text):
    found = []
    for pattern in VARIABLE_RES:
        for name in pattern.findall(text):
            if name not in found:
                found.append(name)
    return found


def fenced_lines(lines):
    """Line numbers (1-based) inside Markdown code fences, which hold examples rather than prompt markup."""
    inside, result = False, set()
    for number, line in enumerate(lines, 1):
        if line.lstrip().startswith(("```", "~~~")):
            inside = not inside
            result.add(number)
        elif inside:
            result.add(number)
    return result


def lint_template(lines, fenced):
    stack, hits = [], []
    for number, line in enumerate(lines, 1):
        if number in fenced:
            continue
        for token in TEMPLATE_TOKEN.findall(line):
            if token in PAIRS:
                stack.append((token, number))
            elif stack and PAIRS[stack[-1][0]] == token:
                stack.pop()
            else:
                hits.append((number, f"closing {token} with no matching opener"))
    hits += [(number, f"{token} opened and never closed") for token, number in stack]
    return hits[:1]


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


def lint_file(rel, text, tokens):
    lines = text.splitlines()
    fenced = fenced_lines(lines)
    # Markup rules skip code fences and inline code spans: both hold examples such as `<out>`.
    prose = [INLINE_CODE.sub("", line) for line in lines]
    hits = []
    for number, detail in lint_template(prose, fenced):
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
    secrets = [n for n, line in enumerate(lines, 1) if SECRET_RE.search(line)]
    if secrets:
        # Location and kind only; the value is never copied.
        hits.append(("secret-literal", secrets[0], f"{len(secrets)} line(s) with a credential-shaped value"))
    if tokens > LARGE_PROMPT_TOKENS:
        hits.append(("large-prompt", 1, f"about {tokens} tokens"))
    return [dict(rule=rule, location=f"{rel}:{number}", detail=detail, **{
        k: RULES[rule][k] for k in ("kind", "severity", "confidence", "category")}) for rule, number, detail in hits]


def git_state(root):
    def git(*args):
        try:
            r = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return r.stdout.strip() if r.returncode == 0 else None

    commit = git("rev-parse", "HEAD")
    if not commit:
        return None, None
    status = git("status", "--porcelain", "--untracked-files=no")
    return commit, bool(status)


def scan(root):
    root = Path(root).resolve()
    prompt_files, call_sites, models, lint = [], [], {}, []
    for path, rel in walk(root):
        suffix = path.suffix.lower()
        kind = prompt_kind(rel)
        is_code = suffix in CODE_SUFFIXES
        if kind is None and not is_code and suffix not in CONFIG_SUFFIXES:
            continue
        text = read_text(path)
        if text is None:
            continue
        lines = text.splitlines()
        if kind is not None:
            tokens = estimate_tokens(text)
            prompt_files.append({"path": rel, "kind": kind, "lines": len(lines), "chars": len(text),
                                 "est_tokens": tokens, "variables": variables(text)})
            lint += lint_file(rel, text, tokens)
        if is_code or suffix in CONFIG_SUFFIXES:
            for number, line in enumerate(lines, 1):
                if is_code:
                    for api, pattern in CALL_PATTERNS:
                        if pattern.search(line):
                            call_sites.append({"path": rel, "line": number, "api": api})
                for model in MODEL_RE.findall(line):
                    models.setdefault(model, []).append(f"{rel}:{number}")
    commit, dirty = git_state(root)
    lint.sort(key=lambda h: (SEVERITY_RANK[h["severity"]], h["location"]))
    return {
        "tool": "inventory.py", "version": 1, "root": root.name, "commit": commit, "dirty": dirty,
        "prompt_files": prompt_files, "call_sites": call_sites,
        "models": [{"id": m, "locations": locs} for m, locs in sorted(models.items())],
        "lint": lint, "not_covered": NOT_COVERED,
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


def merge_into(findings_path, inventory):
    original = merge_tool.read_regular(findings_path)
    data = merge_tool.read_json(findings_path, original)
    if not isinstance(data, dict):
        raise render.SchemaError(f"{findings_path}: report must be an object")
    old = {(f.get("rule"), f.get("location")): f.get("validation") for f in data.get("findings", [])
           if isinstance(f, dict) and str(f.get("id", "")).startswith("L-")}
    new = lint_findings(inventory["lint"])
    for finding in new:
        previous = old.get((finding["rule"], finding["location"]))
        if isinstance(previous, dict) and previous.get("verdict") != "Unverified":
            finding["previous_validation"] = previous
    data["findings"] = [f for f in data.get("findings", [])
                        if not (isinstance(f, dict) and str(f.get("id", "")).startswith("L-"))] + new
    meta = data.setdefault("meta", {})
    meta["commit"], meta["dirty"] = inventory["commit"], inventory["dirty"]
    render.validate_data(copy.deepcopy(data))
    merge_tool.write_report(Path(findings_path), data, original)
    return len(new)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("repo", type=Path)
    p.add_argument("--out", type=Path, help="write inventory.json here (default: stdout)")
    p.add_argument("--into", type=Path, help="replace the L-* findings of this findings.json")
    a = p.parse_args(argv)
    if not a.repo.is_dir():
        print(f"inventory.py: {a.repo}: not a directory", file=sys.stderr)
        return 2
    inventory = scan(a.repo)
    text = json.dumps(inventory, ensure_ascii=False, indent=2) + "\n"
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(text, encoding="utf-8")
        print(f"wrote {a.out}: {len(inventory['prompt_files'])} prompt file(s), "
              f"{len(inventory['call_sites'])} call site(s), {len(inventory['lint'])} lint hit(s)")
    else:
        sys.stdout.write(text)
    if a.into:
        try:
            count = merge_into(a.into, inventory)
        except (render.SchemaError, merge_tool.MergeConflict, OSError) as e:
            print(f"inventory.py: {e}", file=sys.stderr)
            return 2
        print(f"merged {count} L-* finding(s) into {a.into}", file=sys.stderr if not a.out else sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
