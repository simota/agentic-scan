# findings.json — the record every output is rendered from

**Read when:** REPORT, before writing the first fragment; whenever a fragment
is refused by `scripts/findings.py merge`.

`render.py` validates the structure; `contract_check.py` adds the run
contract's completeness rules. `examples/findings.sample.json` (English) and
`examples/findings.sample.ja.json` (Japanese) are complete examples.

## Top level

| Key | Type | Written by |
|---|---|---|
| `schema_version` | `1` | `findings.py` (default) |
| `meta` | object | first fragment; `commit`/`dirty` only by `inventory.py --into` |
| `prompts` | list of prompt records | fragments |
| `findings` | list of finding records | fragments (`F-*`), `inventory.py --into` (`L-*`) |
| `eval_runs` | list of eval run records | fragments, only after requested evals |
| `perspectives` | list of `{name, result, note}` | fragments |
| `checked_ok`, `decisions`, `limitations`, `next_steps` | lists of strings | fragments |

## `meta`

| Field | Meaning |
|---|---|
| `target` | Repository or product name |
| `date` | Review date, `YYYY-MM-DD` |
| `assessor` | Host and model, e.g. `Claude Code (<model>)` |
| `scope` | What was reviewed, in one line |
| `lang` | Report language, `ja` or `en`; `render.py --lang` defaults to it, and to `ja` when it is absent. Any other value is a schema error, which a fragment setting `meta.lang` repairs |
| `commit` | Full Git object id of the reviewed revision, or `null` outside Git |
| `dirty` | `true` when the scanned directory differed from `commit` at scan time (uncommitted changes, untracked files, or ignored or submodule files the inventory read); `null` when Git could not tell (also when a file read is marked skip-worktree or assume-unchanged, or when the only differences are unstaged edits to files under a filter driver such as Git LFS, which only its clean command could confirm, or when a configured filter driver's name contains `=`, which keeps `inventory.py` from switching it off, so `git status` is not run). Excerpts come from `commit` only when `dirty` is `false` and the file has no `filter` attribute, otherwise from the working tree |

## Prompt record

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | `P-01`, `P-02`… |
| `name` | yes | What the prompt is for |
| `kind` | yes | `system`, `template`, `few-shot`, `tool`, `agent`, `skill`, `other` |
| `location` | yes | `path:line` of the prompt text |
| `consumer` | | `path:line` of the code that sends it and handles the output |
| `model` | | Model ID and parameters that matter, or where they are configured |
| `inputs` | | Each variable and who supplies it |
| `output` | | What consumes the output |

## Finding record

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | `F-001`… (agent) or `L-001`… (`inventory.py`) |
| `kind` | yes | `defect` or `improvement` |
| `severity` | yes | `High`, `Medium`, `Low`, `Info` (`SKILL.md`, severity table) |
| `confidence` | yes | `Confirmed`, `Model-dependent`, `Suspected` (`reference/validation.md`) |
| `category` | yes | The perspective name, exactly as in `reference/perspectives.md` |
| `title` | yes | One line |
| `location` | yes | `path:line` or `path:start-end`; extra locations go in `cause` |
| `prompt` | contract | `P-NN` or a list of them (required when `prompts` is not empty) |
| `symptom` | contract | What the model does, or would do |
| `cause` | contract | What in the text or code makes it happen |
| `impact` | contract | The effect on the consumer: user, parser, tool, cost |
| `fix` | contract | One-line direction |
| `proposal` | improvements | `{before, after}`: the current text (short quote) and the proposed text |
| `test` | contract | String or list: an eval or test assertion of the good outcome |
| `validation` | yes | `{verdict, evidence, method}` |
| `status` | | `Open` (default), `Fixed`, `Accepted` |
| `references` | | `[{title, url}]`, http(s) only |
| `source`, `rule`, `previous_validation` | | Written only by `inventory.py` on `L-*` |

*contract* = required on every `F-*` by `contract_check.py`.

`Valid`, `FalsePositive` and `NotApplicable` need nonblank
`validation.evidence`. `contract_check.py` also requires, on every High and
Medium finding (`F-*` and `L-*`), a verdict other than `Unverified` and nonblank
evidence.

## Eval run record

| Field | Meaning |
|---|---|
| `id` | `E-001`… |
| `finding` | The `F-*` finding it tests (`L-*` IDs are reassigned on every rescan) |
| `model` | Model ID and parameters used |
| `date` | Run date |
| `cases`, `passed`, `failed` | Nonnegative integers; `passed + failed ≤ cases` (the rest errored or were skipped) |
| `note` | Which prompt version (current / proposed), and anything the counts do not show |

## Fragment rules

- One to five new findings per fragment; merge each before writing the next
- A known id is updated key by key, so a later fragment can carry only
  `{"id": "F-003", "validation": {…}}`
- An `L-*` may receive only `validation`
- New `F-*` ids follow merge order; after VERIFY, `scripts/findings.py renumber
  <out>/findings.json` puts them in severity order (then path and line,
  excluded findings last) and rewrites every `F-*` reference in the record,
  except quoted `proposal` text, reference URLs, locations, paths and file
  names (a feature id such as `prompts/F-002/` or `F-002.md`), `meta`, prompt records and the
  scanner fields of `L-*` findings
- `remove` deletes exact entries from `checked_ok`, `decisions`,
  `limitations` or `next_steps`
- Literal instruction-override strings and credential-shaped values in any
  string are refused: describe the weakness, name the variable, give a
  secret's location and kind only

A minimal first fragment:

```json
{
  "meta": {"target": "acme-support-bot", "date": "2026-10-11",
           "assessor": "Claude Code (<model>)", "scope": "prompts under app/llm", "lang": "en"},
  "prompts": [{"id": "P-01", "name": "Support answer", "kind": "system",
               "location": "app/llm/prompts/support.md:1", "consumer": "app/llm/answer.py:42"}]
}
```
