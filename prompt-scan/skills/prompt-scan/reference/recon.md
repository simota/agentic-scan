# Recon — mapping the prompts and the code around them

**Read when:** RECON, before any finding is written.

The goal is a map in which every prompt is a row with a known sender, known
variables and a known consumer. A prompt reviewed without that map is a piece
of prose; most defects only appear when it is read together with the code.

## 1. Run the inventory

```
python3 scripts/inventory.py <repo> --out <out>/inventory.json
```

It lists prompt files, call sites of model APIs, template variables per file,
model IDs and lint hits (`reference/inventory.md`). It also traces each prompt
file to the code that loads it (`prompt_files[].loaded_by`), the keys each
render call fills it with (`bindings`), and the prompt files, argument names and
literal parameters of each model call (`call_sites[].prompts`, `args`,
`params`). It is a starting list, not the map: it finds prompts by pattern and
misses prompts built at runtime, stored in databases or fetched from a
registry. Search for those next.

## 2. Find what the inventory misses

- Prompt files with an empty `loaded_by`, and bindings with `traced: false`:
  their loader or render is a helper, another file or a computed path; find it
- Strings assigned to names containing `prompt`, `instruction`, `system`,
  `template`, `persona`
- Prompt text loaded at runtime: files read by path, database rows, a prompt
  registry or feature-flag service, environment variables. Record the loader's
  `path:line`; the text itself is outside the review and goes in `limitations`
- Tool and function definitions passed to the API (`tools=`, `functions=`,
  schema objects) — their descriptions are prompts
- Files an agent or skill definition tells the model to read (a skill's
  `reference/` files and templates, `@path` imports in `CLAUDE.md`): each is
  part of that prompt and gets its own row
- Agent frameworks: chains, graphs and agents whose prompts are assembled by
  the framework from pieces (LangChain, LlamaIndex, Semantic Kernel, the
  Agent SDKs). Record each piece's location and the order the framework
  assembles them in

## 3. One row per prompt

For every prompt record, in scratch and later in the `prompts` list. A traced
binding gives a first `consumer` (its render or send site), `inputs` (its
`keys`) and, through the call site whose `prompts` names the file, `model`
(`params`); confirm each by reading the code:

| Field | What to record |
|---|---|
| `id` | `P-01`, `P-02`… in the order you list them |
| `name` | A short name: what the prompt is for |
| `kind` | `system`, `template`, `few-shot`, `tool`, `agent`, `skill`, `other` |
| `location` | `path:line` of the prompt text |
| `consumer` | `path:line` of the code that sends it and handles the result |
| `model` | Model ID and the parameters that matter (temperature, max tokens), or `configured at <path:line>` |
| `inputs` | Each variable and who supplies it: developer, end user, retrieved document, tool output, another prompt |
| `output` | What consumes the output: a person, a parser (cite it), a tool call, another prompt |

## 4. Reconstruct the message as sent

For each consumer, write down the full message list in order: system text
(including any framework-added text), tools, history, the user turn with every
variable in place, and any prefill. Review that, not the template file alone.
Note every branch that sends something different (retries, fallbacks, feature
flags, A/B variants).

## 5. Mark the trust boundary

Mark each input as trusted (written by the developer) or untrusted (anything
an end user, a third party or a fetched document can influence). Then list what
the model can do on that call: tools, especially side-effecting ones; data from
other users or tenants; outputs rendered as HTML or executed. The *Untrusted
input* perspective works from this list.

## 6. Group into review units

Group prompts that share a consumer, a template or a purpose. Each group is one
review unit; the assembly code (message building, truncation, retries,
parsing) is one more, cross-cutting unit.
