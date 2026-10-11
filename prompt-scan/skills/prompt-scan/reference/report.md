# Report — output formats

**Read when:** CHECKLIST, to deliver a checklist; REPORT, to deliver findings.
Write in the requester's language.

```
python3 scripts/render.py <out>/findings.json --out <out> --lang <ja|en> --repo <repo>
python3 scripts/contract_check.py <out>
```

A second-language copy is a re-render into `<out>/<lang>/` checked with
`contract_check.py <out> --allow <lang>`, never a new review.

## Checklist deliverable

- First line: how many prompts were inventoried, how many perspectives apply,
  and that suspicions are unverified
- One section per review unit: its prompts (`P-NN`, location, consumer), then
  the applicable perspectives with the hunt steps to run, each with the
  concrete file or call site to read and an optional `initial note (unverified)`
- The perspectives judged N/A, each with a reason
- Close with the recommended starting point and one decision for the requester

## Findings report (chat summary)

1. **First line** — counts by kind (defects / improvements) and by severity,
   and the scope: static only, or with requested eval runs. Name any High
   finding not yet `Valid`
2. **Evidence line** — the reviewed revision (`meta.commit`, and whether the
   tree was dirty), how many prompts and call sites were read, what remains
   unknown (model behaviour, prompts outside the repository)
3. **Findings, by severity** — defects first within a severity, each as:

   ```
   [High|Medium|Low|Info][defect|improvement][Confirmed|Model-dependent|Suspected] title
     location: path:line   prompt: P-NN   perspective: <name>
     symptom: what the model does or would do
     cause: what in the text or code makes it happen
     impact: effect on the consumer
     fix: one line
     proposal (improvements): before → after, short
     test: the eval or test assertion of the good outcome
     verdict: Valid / Likely / … with the evidence in one line
   ```

4. **Checked and sound** — what was examined and held
5. **Decisions for a human** — intended behaviour the prompts leave open,
   model choices to confirm, accepted costs
6. **Next step** — the fix order (High defects first, then output-contract and
   variable defects, then improvements), and which findings need an eval
7. **Files** — link `dashboard.html` and `report.pdf`; name the scratch
   directory

The chat summary, dashboard and PDF show the same verdicts and counts:
`findings.json` is the record, and every finding in chat exists there.

## Required limitation lines

Kept in English, verbatim, in any report language, so `contract_check.py` can
find them:

- "model behaviour not executed: static review only" — whenever no
  `eval_runs` are recorded
- "report.pdf not produced: no PDF engine" — only with `--no-pdf`

Add, in the report language, every `not_covered` line from `inventory.json`
that applies, and any prompt in the inventory that was not read.

## Proposals

A proposal is a concrete rewrite of the smallest span that fixes the cause,
not a full new prompt. Quote the current text short in `before` (enough to
find it), and write `after` as text that can be pasted in. When the fix is in
code rather than in the prompt (escaping, truncation, parser), the proposal
shows the code-level change in words, and `fix` names the function.

Proposals never contain a working override string, and examples in proposals
use synthetic data.
