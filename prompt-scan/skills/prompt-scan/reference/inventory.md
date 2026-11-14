# Inventory: what `inventory.py` finds and what it misses

**Read when:** RECON, to run the inventory and read its output; end of REVIEW,
before `--into`; whenever an `L-*` finding is reviewed.

```
python3 scripts/inventory.py <repo> --out <out>/inventory.json
python3 scripts/inventory.py <repo> --out <out>/inventory.json --into <out>/findings.json
```

It reads files only: it never executes code from the repository and sends
nothing over the network. The Git state it records comes from `git status`,
`git ls-files` and `git check-ignore`, with the repository's fsmonitor and
filter-driver commands switched off; it does not enter submodules or refresh
the index.

It skips directories such as `.git`, `node_modules`, virtual environments and
build output, and symlinked directories, which the walk does not follow; all
are listed in `skipped_dirs`, VCS metadata aside. It also skips `.env*` and
`*.env` files, key files, login files such as `.npmrc`, `.netrc` and `id_rsa`
(`render.py` quotes none of these either), symlinks, binary files and files
over 1 MiB; a prompt file among these is listed in `skipped_files`. A file
whose name is not UTF-8 is listed with the bytes escaped (`\xff`); Git still
sees its real name, but `render.py` cannot reopen the escaped one, so its
findings carry no excerpt.

## What it lists

| Section | Contents |
|---|---|
| `prompt_files` | Files under a `prompts/`, `prompt/`, `system_prompts/`, `system-prompts/` or `instructions/` directory; `.prompt`, `.prompty`, `*.prompt.md`; `SKILL.md` (not the files it tells the model to read: `reference/recon.md` §2); `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, `copilot-instructions.md`; files under `.claude/agents`, `.claude/commands`, `.cursor/rules`, `.github/prompts`, `.codex/agents`. Each with kind, size, an estimated token count, the template variables found (`{{name}}`, `{name}`, `${name}`) and `loaded_by`: each code line that names the file in a quoted path (from `bindings`) |
| `inline_prompts` | String literals in code assigned to, or passed as, a name containing `prompt`, `instruction` or `persona`, or named `system` (`system_message`…) or `preamble`, and the `content` of a message whose role is `system`; through `dedent`/`cleandoc`, implicit concatenation, `+` and line continuations. Each with its line, name, size, estimated tokens and variables. A literal without whitespace (a path) or under 20 characters is not listed. The prompt-text lint rules apply to each at its own code lines, except `unbalanced-template`: an f-string's `{{` is a literal brace. A prompt assembled from variables, a call or a loop is not listed |
| `call_sites` | Lines in code that call a model API or build a prompt object: Anthropic `messages.create`, OpenAI `chat.completions.create` / `responses.create`, Gemini `generate_content`, the AI SDK `generateText` family, LangChain prompt and message classes, `role: "system"` literals and `SYSTEM_PROMPT`-style assignments. A call that sends a prompt (the first four APIs) also gets `args` (its keyword or object-key argument names, `**` for a spread), `params` (the literal values of `model`, `max_tokens`, `temperature`, `top_p`, `stream`, `seed`, `reasoning_effort` and their camelCase forms; a value held in a variable is left out), `prompts` (the prompt files whose loaded or rendered text the call passes, from `bindings`) and `inline_prompts` (the `path:line` of each inline prompt written in the call or passed by its name) |
| `bindings` | Where code loads each prompt file and what it does with the text, below |
| `models` | Quoted model IDs (`claude-…`, `gpt-…`, `o1`/`o3`/`o4`, `gemini-…`, `mistral-…`, `llama…`) in code and config, with each location, including the cloud forms `us.anthropic.claude-…-v1:0` (Bedrock), `claude-…@YYYYMMDD` (Vertex) and `models/gemini-…`. Whether an ID is current is not decided here (`SKILL.md`, *Decide first*) |
| `lint` | Mechanical hits in prompt files, below |
| `skipped_dirs` | Each directory pruned by name at any depth, and each symlinked directory: a skill or prompt directory named `build`, `coverage`, `env`, `vendor`… is pruned too, and so is a `prompts/` that is a symlink. Read the prompt files in any that hold some, or name them in `limitations` |
| `skipped_files` | Each file that would be a prompt file but was not read, with the reason: `symlink`, `binary`, `unreadable` or `over 1 MiB`. Read them by hand or name them in `limitations` |
| `not_covered` | What the scan cannot see; copy each line that applies into `limitations` |

## Bindings

`scripts/bindings.py` follows each quoted path in code that names a prompt file
(`"answer.prompt"`, `PROMPTS / "support_system.md"`, `f"{DIR}/system.md"`) through
loader calls (`open`, `read_text`, `readFileSync`, `get_template`, `Template`,
`path.join`…), method chains and assignments in the same file, to where the text
is rendered or sent. Each binding records:

| Field | Meaning |
|---|---|
| `prompt`, `loaded_at` | The prompt file and the code line naming it |
| `renders` | Each render site: `location`, `via` (`format`, `format_map`, `render`, `substitute`, `safe_substitute`, `invoke`, `format_messages`, `format_prompt`, `replace`/`replaceAll` with a literal placeholder, or `sent` for a model API call that passes the text unrendered), `keys` (the names it fills: keyword arguments, dict or object keys), `complete` (`false` when a `**kwargs`, `...spread`, positional dict variable, computed key or regex replace may fill names the scan cannot see) and `style` (the placeholder syntax that call fills) |
| `targets` | The variables that hold the text, loaded or rendered; `call_sites[].prompts` links through them |
| `sent_at` | Model API calls that take the text directly |
| `traced` | `true` when every use of the text was a render, a send, an assignment followed further, or a test (`if path.exists()`); `false` when it was handed to another function, stored in a list or dict, returned, used only in another file, or the quoted path names several prompt files (`ambiguous: true`) |

It reads masked source (comments and string contents blanked), not a parse
tree: a binding it cannot follow is `traced: false`, never guessed. A prompt
file with no `loaded_by` is loaded by a computed path, from another file through
a helper, from outside the repository, or not at all: find its loader by hand
(`reference/recon.md` §2). Use `bindings` and `call_sites[].args`/`params`/`prompts`
to fill the prompt map's `consumer`, `model` and `inputs` (`reference/recon.md`
§3), then read each site: a trace is where to look, not what the code does.

`est_tokens` is a rough estimate (about four ASCII characters per token, one
per other character). Use it to rank prompts by size, not as a provider count.

## Lint rules

| Rule | Kind / severity / confidence | Hit when |
|---|---|---|
| `secret-literal` | defect / High / Suspected | A line in a prompt file matches a credential format (provider key prefixes, AWS access keys, GitHub, GitLab, Hugging Face, Stripe and Slack tokens, private-key block). Location and kind only; the value is never copied |
| `unreferenced-variable` | defect / Medium / Suspected | A template variable in a `template` prompt file (prompt directory, `.prompt`, `.prompty`), outside code fences and inline code, whose name (the part before any `.`) appears as a word in no code file of the repository. Names the template defines (`{% set %}`, `{% for %}`, macro parameters) and engine names (`loop`, `this`…) are skipped; nothing is reported when the repository holds no code. One hit per file, at the first such line, naming every such variable. A hit means no caller can be seen filling it: confirm at the call site, which may pass a dictionary built elsewhere or a framework's input variables. A name `unfilled-variable` reports is left out, and so is brace text that is not a variable in the syntax every traced, complete render of the file fills (`{example}` in a template only ever rendered by Jinja) |
| `unfilled-variable` | defect / High / Suspected | In a `template` prompt file, a traced binding has a complete render site that does not fill a variable the template uses in the syntax that call fills (`{name}` for `.format` and LangChain, `{{ name }}` for `.render`, `$name`/`${name}` for `string.Template`, any for a literal `.replace` or an unrendered send), outside code fences. A name the template tests first (`{% if name %}`, `name \| default(…)`, `name is defined`, a Mustache `{{#name}}` section) is optional and skipped, and so is every template that includes, extends or imports another. One hit per file, at the first such line, naming the sites and the variables; when the same call passes a key the template never uses (a renamed variable, usually) the hit names that key too. Its names are left out of `unreferenced-variable` |
| `unused-render-key` | defect / Medium / Suspected | A render site of a binding naming this one file passes a key (keyword argument, dict or object key) that appears in no template construct of the file (`{…}`, `{{…}}`, `{%…%}`, `${…}`, `$name`), code fences included, at the render site's line. One hit per template and site; a site already named by an `unfilled-variable` hit is not repeated |
| `unrequested-output-key` | defect / High / Suspected | A model call that sends traced prompt files is assigned, and its reply is parsed in the same file (`json.loads`, `JSON.parse`, directly or through assignments such as `text = r.content[0].text`), and the code reads a first-level key of the parsed value (`["key"]`, `.get("key")`) that no prompt file of the repository and no other string literal in that code file names as a word. A call with a schema argument (`response_format`, `tools`, `output_format`, `text_format`, `response_schema`, `config`…) or a spread, or one sending a prompt file through an ambiguous path, is not judged. One hit per call, at the first such read, naming the call, its prompt files and the keys |
| `missing-file-reference` | defect / Medium / Suspected | An agent or skill prompt file (`SKILL.md`, `AGENTS.md`, `CLAUDE.md`, `.claude/agents`…), outside code fences, cites a path that exists neither relative to the file nor from the repository root: a Markdown link, an `@path` import (with a `/` or a known suffix, so `@name` mentions and e-mail addresses are not), or a path in a code span with a known suffix (`.md`, `.py`, `.json`, `.yaml`, `.prompt`…) or a trailing `/` whose own directory does exist, so a file to be created, or one in another repository, is not reported. URLs, absolute and home paths, globs, placeholders (`<out>/…`) and paths leaving the repository are skipped. One hit per file, at the first such line, naming every missing path |
| `unbalanced-template` | defect / Medium / Suspected | `{{`/`}}` or `{%`/`%}` do not pair up, outside code. A closer counts only in an engine template file (`.j2`, `.jinja`, `.jinja2`, `.mustache`, `.hbs`, `.tmpl`, `.tpl`) or a file that opens `{{` or `{%` somewhere, never in a JSON, YAML or TOML file: elsewhere `}}` is JSON or literal text |
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
`L-*` findings and `meta`, or when an `L-*` differs from what `--into` wrote
in anything but its review. `--out` replaces only an earlier `inventory.json`,
so swapping it with `--into` is refused rather than overwriting
`findings.json`.

A rescan keeps the latest reviewed verdict on the same rule and location as
`previous_validation` (a later rescan before a new review keeps it too); the
new hit starts `Unverified` and needs a fresh look.

Read the location of each hit and merge a `validation` with a verdict and
evidence: for example `FalsePositive` for a literal brace that the template
engine never sees, or `Valid` for a `TODO` that reaches the model. A fragment
may change nothing else on an `L-*`.

For `unrequested-output-key`, reconstruct the message as sent (`reference/recon.md`
§4): `Valid` when nothing sent on that call (history, a prompt from a helper or
a database, a provider default) asks for the key; `FalsePositive` with the
text that does. For `unfilled-variable` and `unused-render-key`, read the binding's
`loaded_at` and each named site: `Valid` when that call is the one that renders
this template on the path the feature takes and nothing between (a
`.partial()`, a framework's default inputs, a wrapper that adds keys) fills the
name; `FalsePositive` with that evidence otherwise.

The same root cause found by the agent is one `F-*` finding citing the hit by
rule and location. When a hit is a symptom of a larger defect the agent found,
keep the `L-*` and cite it from the `F-*` finding's `cause` by rule and location
(`unclosed-tag at prompts/a.md:3`), not by its ID: `L-*` IDs are reassigned on
every `--into`.

## Lint in CI

In CI, the lint runs alone, without a review:

```
python3 scripts/inventory.py <repo> --sarif <file>.sarif --fail-on High [--baseline <review>/findings.json]
```

`--fail-on` prints each hit at that severity or above as `path:line: severity
rule: detail` and exits 1 when there is one; `--sarif` writes the hits as SARIF
2.1.0; `--baseline` suppresses each hit an earlier review judged
`FalsePositive` or `NotApplicable` (in `validation`, or kept as
`previous_validation` across a rescan), matched by rule, file, tag and detail
with line numbers aside. None of them writes inside the repository or changes
the review's outputs.
