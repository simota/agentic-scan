# privacy-scan

An agent skill for a **static, read-only privacy review of your own
application's source code**. It maps personal data, where it flows and who
receives it, reviews the flows from several perspectives, verifies what it
finds, and delivers the result three ways: a chat summary, an interactive
dashboard and a Markdown report.

> The skill reads source only. It never reads data stores, logs or backups,
> never prints personal data values, and does not give legal advice: it
> compares the code with the application's own commitments and with the
> requirements you name.

## What it does

```
RECON ─► CHECKLIST ─► REVIEW ─► VERIFY ─► REPORT
 map      commitments  one pass   re-trace   findings.json
 personal and          per unit   High and   ├─ dashboard.html
 data,    perspectives            Medium     ├─ report.md
 flows                            findings   └─ chat summary
```

- **Recon** builds the personal data map: every element, its category and
  subjects, every store it lands in, every flow to third parties, logs,
  telemetry, other actors and copies, consent mechanisms, retention jobs, and
  deletion and export paths
- **Commitments** — what the app promises or must keep (privacy policy,
  consent texts, retention schedules, sub-processor lists, settings-screen
  copy, requirements of regulations you name), in seven families:
  minimisation, consent, retention, rights, sharing, containment and
  protection. Each is hunted on every flow that must keep it
- **Perspectives** — twelve review angles (data inventory and minimisation,
  purpose and consent, retention and deletion, data subject rights,
  third-party sharing, logs and telemetry, exposure to other actors, storage
  protection, client-side tracking, identifiers and pseudonymisation,
  non-production copies, location and transfers) with about 40 hunt steps and
  a table of sound vs look-alike constructs
- **Validation** — every finding gets a verdict (`Valid`, `Likely`,
  `Unverified`, `Unlikely`, `FalsePositive`, `NotApplicable`) with evidence,
  checked against four claims: reach, the data that actually arrives,
  controls, and whether the commitment is the app's own
- **No values** — `findings.py merge` checks report prose, including analysis
  results, commitments and coverage notes, for e-mail addresses (including
  quoted, Unicode and address-literal forms, outside reserved example domains)
  and runs of 12 or more digits, even with repeated spaces, tabs or non-breaking
  spaces. Reference URLs are also checked after decoding their components once;
  accepted URLs keep their original spelling. Use field names and placeholders
  throughout the record
- **Guards** — each finding names a check with synthetic data (redaction of a
  named field, deletion reaching every store, no SDK call before consent)

## Install

```sh
make link                 # symlink into every installed host's skills dir
make link AGENT=claude    # one host only
make status
make unlink
```

Then invoke `privacy-scan` (or `/privacy-scan`).

Install paths supplied through environment variables preserve literal dollar
signs. Command-line Make assignments retain Make's usual `$$` escaping for a
literal `$`.

## Outputs

Every output is rendered from one record, `findings.json`, which the agent
builds from JSON fragments rather than heredocs:

```sh
python3 skills/privacy-scan/scripts/findings.py merge out/findings.json frag-001.json
python3 skills/privacy-scan/scripts/render.py out/findings.json --out out --lang ja
python3 skills/privacy-scan/scripts/findings.py check out   # exit 1 lists each violation
```

| Output | What it is |
|---|---|
| Chat summary | Status and counts, findings by severity, decisions for a human |
| `findings.json` | The single source of every other output |
| `dashboard.html` | Self-contained dashboard: severity and verdict counts, findings filterable by severity, commitments, perspective coverage |
| `report.md` | The written assessment: scope, severity and verdict counts, findings, commitments, coverage, sound items, limitations, next steps |

`findings.py check` enforces the run contract: exactly these three readable,
nonempty files, gapless `PV-NNN` IDs in severity order, every perspective
recorded, nonblank reasons for unchecked commitments, and nonempty `checked_ok`
and `limitations`.
It checks shape, not whether a finding is true.

The scripts reject text that cannot be encoded as UTF-8 and stage output bytes
before replacing files, so encoding or staging failures preserve existing results.
Rendering also refuses output paths that resolve to the input record or to each
other, before writing any files. Other destination symlinks retain their links
and update their target files.
Reports retain the recorded review method even with zero findings, and the
dashboard preserves line breaks and indentation in analysis commands.

To file findings, the skill drafts from `templates/issue.{ja,en}.md` (one root
cause per issue) or `templates/report.{ja,en}.md` (one report for an owner or
DPO). An open High goes to a private tracker. Filing or sending stays with you.

## Layout

```
skills/privacy-scan/
  SKILL.md                     phases, run contract, severity, decisions, rules
  reference/recon.md           building the personal data map and flows
  reference/commitments.md     deriving the commitments ledger, flow rows, close-check
  reference/perspectives.md    the review perspectives, hunt steps and sound constructs
  reference/validation.md      verdicts, the four claims, read-only analysis, guards
  reference/findings-schema.md findings.json shape, merge semantics and render command
  reference/report.md          checklist and findings report formats
  scripts/findings.py          merges JSON fragments; refuses personal values; checks the run contract
  scripts/render.py            findings.json -> dashboard.html / report.md (stdlib only)
  scripts/output_io.py         stages UTF-8 output before replacing files
  templates/issue.{ja,en}.md   one finding as one issue
  templates/report.{ja,en}.md  findings report to an owner or DPO
examples/findings.sample.json  fictional sample for make demo / make check
tests/                         offline tests for the scripts and the documents
```

## Development

```sh
make test    # offline unit tests
make check   # tests plus citations resolve, references headed, frontmatter valid,
             # scripts parse, sample renders in ja/en and passes the run contract
make demo    # render the sample into $TMPDIR/privacy-scan-demo (LANG_OUT=en for English)
```

Requirements: Python 3.9+. No third-party packages.

The format follows the sibling `security-scan`, `performance-scan` and
`architecture-scan` skills (same phases, run contract, verdicts and report
shape), adapted to personal data protection.
