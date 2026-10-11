# Validation — is each finding real, and would the fix help?

**Read when:** VERIFY, for every finding before it reaches the report; EVAL,
when the requester asked for model runs.

A finding is a hypothesis until it survives an attempt to falsify it. Keep the
verdict in `validation` (`reference/findings-schema.md`). Severity, confidence
and verdict are separate: a High finding can be `Likely`, a Low one `Valid`.

## Verdicts

| Verdict | Meaning | Evidence needed |
|---|---|---|
| `Valid` | The cause is in the text or code as cited, nothing elsewhere in the prompt as sent compensates, and the impact follows | Nonblank `evidence` naming what was re-read |
| `Likely` | Strong signals; one link not yet confirmed (often: what the model actually does) | Optional |
| `Unverified` | Not yet examined (the default for `L-*`) | — |
| `Unlikely` | Signals point away, not ruled out | Optional |
| `FalsePositive` | The cited text or code does not have the claimed problem | Nonblank `evidence` |
| `NotApplicable` | The problem is real in general but not on this path, model or configuration | Nonblank `evidence` |

`contract_check.py` also requires `evidence` on every High and Medium `F-*`.

## Falsification checks

Before setting `Valid`, try each that applies, and say in `evidence` which:

1. **Read the prompt as sent.** Rebuild the full message list from the code —
   system text, framework-added text, tools, history, filled template, prefill
   (`reference/recon.md` §4). A "missing" instruction is often in another layer
2. **Look for the compensating code.** A parser that strips prose, a
   validator that rejects bad values, a retry with a fixed prompt, a filter on
   tool calls. A prompt defect with a code guard behind it is lower severity or
   `NotApplicable`
3. **Check every call site.** A variable defect on one call site may be filled
   correctly on the others; scope the finding to the paths that break
4. **Check the model.** A feature the prompt relies on (prefill, a tool-choice
   mode) may be unsupported by the configured model, or irrelevant for it
5. **State the competing instruction.** A contradiction finding names both
   lines; an "ignored instruction" finding names what outweighs it

## Confidence

| Confidence | When |
|---|---|
| `Confirmed` | Certain from the text and code alone: a variable no call site fills, a field the parser requires that the prompt never asks for, a tag never closed, a secret in a prompt file |
| `Model-dependent` | The cause is real, but whether it changes the output depends on how the model weighs it: ambiguity, buried constraints, competing instructions, missing examples |
| `Suspected` | A signal not yet traced end to end |

A `Model-dependent` finding carries the eval case that would settle it in
`test`: the input, the expected property of the output, and how to check it
(an exact field, a regex, a rubric question). Do not run it unless asked.

## Eval runs (on request only)

Evals send prompts and test inputs to a model provider, which is outside this
skill's default boundary. Run them only when the requester asked, with their
own key, against the model they name, and say before starting what is sent and
to whom.

- Run each case on the current prompt and, when a proposal is being tested, on
  the proposed one, with the same model and parameters
- Repeat sampled cases (temperature above zero) enough times to see variance;
  record the count in `cases`
- Record every run in `eval_runs`, passed or not; never drop a failing run
- A run is evidence for that model, those cases and that date only. Do not
  extend a pass on one model to another, or a pass on synthetic cases to
  production traffic
- When `eval_runs` exist, remove the limitation "model behaviour not executed:
  static review only" and add what the runs did not cover
