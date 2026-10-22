# Inventory — what `inventory.py` finds and what it misses

**Read when:** RECON, to run the inventory and read its output; end of REVIEW,
before `--into`; whenever an `L-*` finding is reviewed.

```
python3 scripts/inventory.py <repo> --out <out>/inventory.json
python3 scripts/inventory.py <repo> --out <out>/inventory.json --into <out>/findings.json
```

It reads files only. It never executes code from the repository and sends
nothing over the network; the Git state it records comes from `git status`
and `git check-ignore`, with the repository's fsmonitor and filter-driver
commands switched off, without entering submodules and without refreshing the
index. A file whose name is not UTF-8 is listed with the bytes escaped
(`\xff`); Git still sees its real name, but `render.py` cannot reopen the
escaped one, so its findings carry no excerpt. Directories such as `.git`, `node_modules`, virtual
environments and build output are skipped, as are `.env*` files, key files,
symlinks, binary files and files over 1 MiB.

## What it lists

| Section | Contents |
|---|---|
| `prompt_files` | Files under a `prompts/`, `prompt/`, `system_prompts/`, `system-prompts/` or `instructions/` directory; `.prompt`, `.prompty`, `*.prompt.md`; `SKILL.md` (not the files it tells the model to read: `reference/recon.md` §2); `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, `copilot-instructions.md`; files under `.claude/agents`, `.claude/commands`, `.cursor/rules`, `.github/prompts`, `.codex/agents`. Each with kind, size, an estimated token count and the template variables found (`{{name}}`, `{name}`, `${name}`) |
| `call_sites` | Lines in code that call a model API or build a prompt object: Anthropic `messages.create`, OpenAI `chat.completions.create` / `responses.create`, Gemini `generate_content`, the AI SDK `generateText` family, LangChain prompt and message classes, `role: "system"` literals and `SYSTEM_PROMPT`-style assignments |
| `models` | Quoted model IDs (`claude-…`, `gpt-…`, `o1`/`o3`/`o4`, `gemini-…`, `mistral-…`, `llama…`) in code and config, with each location, including the cloud forms `us.anthropic.claude-…-v1:0` (Bedrock), `claude-…@YYYYMMDD` (Vertex) and `models/gemini-…`. Whether an ID is current is not decided here (`SKILL.md`, *Decide first*) |
| `lint` | Mechanical hits in prompt files, below |
| `not_covered` | What the scan cannot see; copy each line that applies into `limitations` |

`est_tokens` is a rough estimate (about four ASCII characters per token, one
per other character). Use it to rank prompts by size, not as a provider count.

## Lint rules

| Rule | Kind / severity / confidence | Hit when |
|---|---|---|
| `secret-literal` | defect / High / Suspected | A line in a prompt file matches a credential format (provider key prefixes, AWS access key, GitHub and Slack tokens, private-key block). Location and kind only; the value is never copied |
| `unbalanced-template` | defect / Medium / Suspected | `{{`/`}}` or `{%`/`%}` do not pair up, outside code. A closer counts only in an engine template file (`.j2`, `.jinja`, `.jinja2`, `.mustache`, `.hbs`, `.tmpl`, `.tpl`) or a file that opens `{{` or `{%` somewhere: elsewhere `}}` is JSON or literal text |
| `unclosed-tag` | defect / Low / Suspected | A non-HTML tag such as `<instructions>` is opened more often than closed, outside code |
| `placeholder` | defect / Low / Suspected | `TODO`, `FIXME`, `TBD`, `XXX` (not inside a format mask such as `XXX-XXX-XXXX`), lorem ipsum or `[INSERT …]` outside code |
| `duplicate-line` | improvement / Info / Confirmed | A line of 40 or more characters (not a table row) appears again in the same file |
| `large-prompt` | improvement / Info / Confirmed | The file alone is estimated at more than 8000 tokens |

"Outside code" excludes both code fences and inline code spans, which hold
examples such as `<out>`. Each hit is one `L-*` finding per rule per file, at
the first line that hits; `unclosed-tag` gives one per tag name.

## Reviewing `L-*` findings

`--into` replaces every `L-*` in `findings.json`, so review them only after the
last `--into`. Write `inventory.json` in that same run (`--out` with `--into`):
`contract_check.py` fails when its lint hits or Git state differ from the
`L-*` findings and `meta`. For each one, read the location and merge a `validation` with a
verdict and evidence — for example `FalsePositive` for a literal brace that the
template engine never sees, or `Valid` for a `TODO` that reaches the model.
A fragment may change nothing else on an `L-*`. When a hit is a symptom of a
larger defect the agent found, keep the `L-*` and cite it from the `F-*`
finding's `cause` by rule and location (`unclosed-tag at prompts/a.md:3`), not by
its ID: `L-*` IDs are reassigned on every `--into`.

A rescan keeps the latest reviewed verdict on the same rule and location as
`previous_validation` (a later rescan before a new review keeps it too); the
new hit starts `Unverified` and needs a fresh look.
