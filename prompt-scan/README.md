# prompt-scan

An agent skill for a **static, read-only review of the LLM prompts in your own
codebase**. It inventories every prompt and the code that sends and parses it,
reviews them from fourteen perspectives, verifies what it finds, and reports
**defects** (things that are broken) and **improvement proposals** (things that
work but would work better) three ways: a chat summary, an interactive
dashboard and a PDF report. It does not edit prompts or code, and does not send
anything to a model unless you explicitly ask it to run evals.

The layout and run contract follow
[security-scan](https://github.com/simota/security-scan): one `SKILL.md`,
references read per phase, scripts that own the record, a contract check every
run must pass.

## What it does

```
RECON ─► CHECKLIST ─► REVIEW ─► VERIFY ─► REPORT
 inventory  tailor      one pass   falsify    findings.json
 prompts,   perspectives per       each       ├─ dashboard.html
 call sites to these    review     finding    ├─ report.pdf
 variables  prompts     unit                  └─ chat summary
```

- **Recon**: `scripts/inventory.py` lists prompt files (prompt directories,
  `.prompt` files, `SKILL.md`, `AGENTS.md`/`CLAUDE.md`, `.claude/agents`…),
  inline prompts in code (`SYSTEM_PROMPT = """…"""`, `system="…"`), model API
  call sites, template variables, quoted model IDs and mechanical
  lint hits. It traces each prompt file to the code that loads it, the keys
  every render call (`.format`, `.render`, `.substitute`, `.invoke`,
  `.replace`…) fills it with and the model call that sends it, with that
  call's literal `model`, `max_tokens` and `temperature`. A variable a traced
  render never fills, a key it passes that the template never uses, and a key
  the code reads from the call's parsed JSON reply that no prompt asks for are
  lint hits naming both lines. The agent then reconstructs each message as
  actually sent and marks which inputs are untrusted
- **Perspectives**: task and intent; instruction consistency; structure and
  placement; variables and assembly; output contract; examples; tools and
  agents; untrusted input; safety and refusal; context budget; model and
  parameters; language and tone; evaluation; maintainability. Each is recorded
  as applied, N/A or not checked
- **Findings**: each with `file:line`, the affected prompt, symptom, cause,
  impact, fix direction, an eval or test assertion, and for improvements a
  concrete before/after proposal. Severity (High/Medium/Low/Info) and
  confidence (Confirmed / Model-dependent / Suspected) are graded separately
- **Verify**: every finding gets a verdict (`Valid`, `Likely`, `Unverified`,
  `Unlikely`, `FalsePositive`, `NotApplicable`). Claims about model behaviour
  that reading cannot settle stay `Model-dependent` with the eval case that
  would settle it
- **Eval runs** *(on explicit request only)*: with your own API access, run the
  recorded cases before and after a proposal and record every run

Ask "what should we check" and it stops after the checklist. Ask it to review
or improve prompts and it runs all phases.

## After the review

- **Re-review**: after changing prompts, run a new review and compare it with
  the earlier one: `scripts/compare.py` lists new, reopened, persisting
  (with severity and verdict changes), resolved and dismissed findings,
  matched by file, perspective and title, since IDs are renumbered. Risks
  accepted earlier (`status: Accepted`) can be carried into the new record
- **Issues**: `scripts/export.py issues` writes one issue body per finding
  from the issue template, ready for `gh issue create --body-file`
- **Code scanning and CI**: `scripts/export.py sarif` writes SARIF 2.1.0 for
  GitHub code scanning or an IDE; `export.py --fail-on High` makes the job fail
  on Open findings at that severity, `compare.py --fail-on High` only on new or
  reopened ones
- **Chat summary**: `scripts/export.py summary` prints the summary format of
  `reference/report.md` with the record's own counts and verdicts
- **Lint on every change**: `scripts/inventory.py <repo> --fail-on High`
  runs the mechanical rules alone (no agent, no model): unfilled template
  variables, keys a render passes that the template never uses, reply keys no
  prompt asks for, files an agent or skill prompt cites that do not exist,
  unbalanced templates, secrets and placeholders in prompts. `--sarif` writes
  them for code scanning, and `--baseline
  <review>/findings.json` keeps hits a review judged `FalsePositive` or
  `NotApplicable` quiet, even after the lines move

## Requirements

Python 3.9+ standard library only. The PDF needs Chrome/Chromium (or
WeasyPrint); without one, `render.py` writes the HTML and exits 3, and the run
records the limitation. Each engine gets `PROMPT_SCAN_PDF_TIMEOUT` seconds
(default: 120 plus 0.05 per finding, at most 900).

## Install

```sh
make link                 # symlink into every installed host's skills dir
make link AGENT=claude    # one host only
make status
make unlink
```

Then invoke `prompt-scan` (or `/prompt-scan`).

## Try it

`examples/sample-app` is a small synthetic app with deliberate prompt defects;
`examples/findings.sample.json` and `examples/findings.sample.ja.json` are the
review of it.

```sh
make demo                       # Japanese sample → $TMPDIR/prompt-scan-demo (PDF needs Chrome or WeasyPrint)
make demo LANG_OUT=en NO_PDF=1  # English, HTML only
make inventory TARGET=examples/sample-app
make lint TARGET=examples/sample-app FAIL_ON=High     # exits 1: the sample has two High lint hits
make compare BASE=examples/findings.sample.ja.json FINDINGS=examples/findings.sample.json
make export FORMAT=sarif FINDINGS=examples/findings.sample.json OUT=/tmp/prompt-scan.sarif
```

In CI, on every change (no review needed; the baseline is optional):

```sh
python3 skills/prompt-scan/scripts/inventory.py . --sarif prompt-lint.sarif --fail-on High \
  --baseline baseline/findings.json
```

After a review was committed or produced as an artifact:

```sh
python3 skills/prompt-scan/scripts/export.py sarif out/findings.json --out prompt-scan.sarif
python3 skills/prompt-scan/scripts/compare.py baseline/findings.json out/findings.json --fail-on High
```

## Files

| Path | What it is |
|---|---|
| `skills/prompt-scan/SKILL.md` | The skill: scope, run contract, severity, phases, decisions |
| `skills/prompt-scan/reference/` | Read per phase: recon, inventory, perspectives, validation, schema, report |
| `skills/prompt-scan/scripts/inventory.py` | Prompt inventory and lint (`L-*` findings with `--into`; `--fail-on`, `--sarif`, `--baseline` for CI) |
| `skills/prompt-scan/scripts/bindings.py` | Traces prompt files to the code that loads, renders and sends them (for `inventory.py`) |
| `skills/prompt-scan/scripts/findings.py` | Merges JSON fragments into `findings.json`; `renumber` restores severity order |
| `skills/prompt-scan/scripts/render.py` | `dashboard.html`, `report.html`, `report.pdf` |
| `skills/prompt-scan/scripts/compare.py` | What changed between two reviews; `--fail-on` gates on new findings, `--accepted-fragment` carries accepted risks forward |
| `skills/prompt-scan/scripts/export.py` | `summary` (chat), `sarif` (code scanning, IDEs), `issues` (one issue body per finding); `--fail-on` gates on Open findings |
| `skills/prompt-scan/scripts/record.py` | The `findings.json` contract every script shares: vocabulary, strict parsing, schema, atomic replacement |
| `skills/prompt-scan/scripts/excerpt.py` | What a report may quote from the reviewed repository, and the redaction applied to it |
| `skills/prompt-scan/scripts/contract_check.py` | Checks a finished output directory against the run contract |
| `skills/prompt-scan/scripts/scan_report_kit/` | Vendored [scan-report-kit](https://github.com/simota/scan-report-kit): shared stylesheets, PDF engine, safe writes |
| `skills/prompt-scan/templates/` | Issue and summary-report drafts (ja/en) |
| `docs/report-design.md` | How the report uses the shared *-scan report format |

The report and dashboard use the shared *-scan report format from the bundled
report kit (see `docs/report-design.md`): a journal-style report (numbered sections, captioned booktabs tables and
listings, one mincho face for both scripts) and a dashboard in the same system.
The copy is maintained in this repository (scan-report-kit is retired); edit it in place.

## Development

```sh
make test    # offline unit tests
make check   # tests + consistency of SKILL.md, references, and samples
```
