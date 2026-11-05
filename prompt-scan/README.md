# prompt-scan

An agent skill for a **static, read-only review of the LLM prompts in your own
codebase**. It inventories every prompt and the code that sends and parses it,
reviews them from fourteen perspectives, verifies what it finds, and reports
**defects** (things that are broken) and **improvement proposals** (things that
work but would work better) three ways: a chat summary, an interactive
dashboard and a PDF report.

> The skill reads prompts and code. It does not edit them and does not send
> anything to a model unless you explicitly ask it to run evals.

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

- **Recon** — `scripts/inventory.py` lists prompt files (prompt directories,
  `.prompt` files, `SKILL.md`, `AGENTS.md`/`CLAUDE.md`, `.claude/agents`…),
  model API call sites, template variables, quoted model IDs and mechanical
  lint hits. The agent then reconstructs each message as actually sent and
  marks which inputs are untrusted
- **Perspectives** — task and intent, instruction consistency, structure and
  placement, variables and assembly, output contract, examples, tools and
  agents, untrusted input, safety and refusal, context budget, model and
  parameters, language and tone, evaluation, maintainability. Each is recorded
  as applied, N/A or not checked
- **Findings** — each with `file:line`, the affected prompt, symptom, cause,
  impact, fix direction, an eval or test assertion, and for improvements a
  concrete before/after proposal. Severity (High/Medium/Low/Info) and
  confidence (Confirmed / Model-dependent / Suspected) are graded separately
- **Verify** — every finding gets a verdict (`Valid`, `Likely`, `Unverified`,
  `Unlikely`, `FalsePositive`, `NotApplicable`). Claims about model behaviour
  that reading cannot settle stay `Model-dependent` with the eval case that
  would settle it
- **Eval runs** *(on explicit request only)* — with your own API access, run the
  recorded cases before and after a proposal and record every run

Ask "what should we check" and it stops after the checklist. Ask it to review
or improve prompts and it runs all phases.

## Install

```sh
make link                 # symlink into every installed host's skills dir
make link AGENT=claude    # one host only
make status
make unlink
```

Then invoke `prompt-scan` (or `/prompt-scan`).

## Try it

```sh
make demo                       # Japanese sample → $TMPDIR/prompt-scan-demo (PDF needs Chrome or WeasyPrint)
make demo LANG_OUT=en NO_PDF=1  # English, HTML only
make inventory TARGET=examples/sample-app
```

`examples/sample-app` is a small synthetic app with deliberate prompt defects;
`examples/findings.sample.json` and `examples/findings.sample.ja.json` are the
review of it.

## Files

| Path | What it is |
|---|---|
| `skills/prompt-scan/SKILL.md` | The skill: scope, run contract, severity, phases, decisions |
| `skills/prompt-scan/reference/` | Read per phase: recon, inventory, perspectives, validation, schema, report |
| `skills/prompt-scan/scripts/inventory.py` | Prompt inventory and lint (`L-*` findings with `--into`) |
| `skills/prompt-scan/scripts/findings.py` | Merges JSON fragments into `findings.json`; `renumber` restores severity order |
| `skills/prompt-scan/scripts/render.py` | `dashboard.html`, `report.html`, `report.pdf` |
| `skills/prompt-scan/scripts/record.py` | The `findings.json` contract every script shares: vocabulary, strict parsing, schema, atomic replacement |
| `skills/prompt-scan/scripts/excerpt.py` | What a report may quote from the reviewed repository, and the redaction applied to it |
| `skills/prompt-scan/scripts/contract_check.py` | Checks a finished output directory against the run contract |
| `skills/prompt-scan/scripts/scan_report_kit/` | Vendored [scan-report-kit](https://github.com/simota/scan-report-kit): shared stylesheets, PDF engine, safe writes |
| `skills/prompt-scan/templates/` | Issue and summary-report drafts (ja/en) |
| `docs/report-design.md` | How the report uses the shared *-scan report format |

## Requirements

Python 3.9+ standard library only. The PDF needs Chrome/Chromium (or
WeasyPrint); without one, `render.py` writes the HTML and exits 3, and the run
records the limitation. Each engine gets `PROMPT_SCAN_PDF_TIMEOUT` seconds
(default: 120 plus 0.05 per finding, at most 900).

Report typography is the shared *-scan report format,
[scan-report-kit](https://github.com/simota/scan-report-kit) (see
`docs/report-design.md`): a journal-style report (numbered sections, captioned
booktabs tables and listings, one mincho face for both scripts) and a
dashboard in the same system. The kit is vendored in
`skills/prompt-scan/scripts/scan_report_kit/`; change it upstream and
re-vendor, never in place (`make check` verifies the copy against its
`MANIFEST`).

## Development

```sh
make test    # offline unit tests
make check   # tests + consistency of SKILL.md, references, samples and the vendored kit
```
