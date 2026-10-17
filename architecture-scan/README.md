# architecture-scan

An agent skill for a **static, read-only review of your own application's
design**. It maps modules, dependencies, data ownership and change hotspots,
reviews them from several perspectives, verifies what it finds, and delivers
the result three ways: a chat summary, an interactive dashboard and a Markdown
report.

> The skill reads source and, read-only, the git history; it does not refactor
> code and does not run the application. It reports defects and change costs,
> not preferences.

## What it does

```
RECON ─► CHECKLIST ─► REVIEW ─► VERIFY ─► REPORT
 map      rules and    one pass   re-trace   findings.json
 modules, perspectives per unit   High and   ├─ dashboard.html
 graph,   for this app            Medium     ├─ report.md
 history                          findings   └─ chat summary
```

- **Recon** builds the module map: deployable units, modules and declared
  layers, the import graph and its cycles, which module writes each core
  store, messaging and integration points, conventions (transactions, errors,
  config), and hotspots and co-change from `git log`
- **Design rules** — the rules this codebase states for itself (import-lint
  contracts, ADRs, structure, the majority pattern), in seven families: layer
  direction, boundaries, ownership, consistency, failure, contracts, seams.
  Each is hunted on every edge or writer that must keep it. Rules inferred
  rather than stated become questions for a human
- **Perspectives** — twelve review angles (boundaries and layering, cohesion,
  coupling, domain model and data ownership, consistency and transactions,
  failure handling, API and event contracts, configuration, testability,
  operability, duplication of patterns, dependencies and evolution) with about
  40 hunt steps and a table of sound vs look-alike constructs
- **Validation** — every finding gets a verdict (`Valid`, `Likely`,
  `Unverified`, `Unlikely`, `FalsePositive`, `NotApplicable`) with evidence,
  checked against four claims: reach, consequence, mitigations and whether the
  rule is the codebase's own. Change-cost claims need history evidence
- **Severity** — High when the structure already allows incorrect behaviour
  on a core flow (two writers with different rules, dual writes without
  recovery, non-idempotent consumers, swallowed failures), or forces lockstep
  changes in a hotspot; preference alone is never a finding
- **Guards** — each finding names a fitness function (import contract, cycle
  check, single-writer search, idempotency test) that would keep the rule

## Install

```sh
make link                 # symlink into every installed host's skills dir
make link AGENT=claude    # one host only
make status
make unlink
```

For Claude Code, `CLAUDE_CONFIG_DIR` selects the global configuration directory
(default: `~/.claude`), including its `skills` directory. `PROJECT` and
`SKILLS_DIR` take precedence when an explicit installation destination is given.
`AGENT`, `PROJECT` and `SKILLS_DIR` are read from the `make` command line only,
so a variable of the same name exported by your shell never redirects the install.
See [Claude Code's directory reference](https://code.claude.com/docs/en/claude-directory).

Then invoke `architecture-scan` (or `/architecture-scan`).

## Outputs

Every output is rendered from one record, `findings.json`, which the agent
builds from JSON fragments rather than heredocs:

```sh
python3 skills/architecture-scan/scripts/findings.py merge out/findings.json frag-001.json
python3 skills/architecture-scan/scripts/findings.py renumber out/findings.json  # severity, then path
python3 skills/architecture-scan/scripts/render.py out/findings.json --out out   # language: meta.lang
python3 skills/architecture-scan/scripts/findings.py check out --repo /path/to/assessed/checkout   # exit 1 lists each violation
python3 skills/architecture-scan/scripts/findings.py counts out/findings.json  # n_* for the report template
```

| Output | What it is |
|---|---|
| Chat summary | Status and counts, findings by severity, decisions for a human |
| `findings.json` | The single source of every other output |
| `dashboard.html` | Self-contained dashboard: severity and verdict counts, a priority queue, findings filterable by severity, confidence, perspective, status, verdict and text (excluded findings apart), design rules, perspective coverage, copy-for-LLM per finding |
| `report.md` | The written assessment: scope, findings, rules, coverage, sound items, limitations, next steps |

`findings.py check` enforces the run contract: exactly these three files,
gapless `A-NNN` IDs in severity order, then path (excluded verdicts last), every perspective recorded, nonempty
`checked_ok` and `limitations`, cited rules that exist (a `Valid` finding cites one
recorded as violated, a `Likely` one violated or partly read), every violated rule
cited by a Valid or Likely finding and no reason left on a closed rule, traced and evidenced
High and Medium findings, and a dashboard and
report that match a fresh render of the current `findings.json` in
`meta.lang`, byte for byte (re-render after the last merge). It checks shape
and consistency, not whether a finding is true.

`findings.json` is never edited by hand. A fragment corrects it: `null`
removes an optional key, `{"remove": {"next_steps": ["…"]}}` deletes a list
item, `{"remove": {"rules": ["R-05"]}}` deletes a ledger entry, and a key sent
again replaces its value. Merges may run in parallel
(each holds a lock on the output directory; on Windows, run them one at a
time).

To file findings, the skill drafts from `templates/issue.{ja,en}.md` (one root
cause per issue) or `templates/report.{ja,en}.md` (one report covering several).
Filing or sending stays with you.

## Layout

```
skills/architecture-scan/
  SKILL.md                     phases, run contract, severity, decisions, rules
  reference/recon.md           building the module map, data ownership and history
  reference/rules.md           deriving the design rules ledger, trace rows, close-check
  reference/perspectives.md    the review perspectives, hunt steps and sound constructs
  reference/validation.md      verdicts, the four claims, read-only analysis, fitness functions
  reference/findings-schema.md findings.json shape, merge semantics and render command
  reference/report.md          checklist and findings report formats
  scripts/findings.py          merges JSON fragments; renumbers; checks the run contract (stdlib only)
  scripts/render.py            findings.json -> dashboard.html / report.md (stdlib only)
  scripts/scan_report_kit/     vendored scan-report-kit: the shared dashboard stylesheet
  templates/issue.{ja,en}.md   one finding as one issue
  templates/report.{ja,en}.md  findings report to an owner or tech lead
examples/findings.sample.json  fictional sample for make demo / make check
tests/                         offline tests for the scripts and the documents
```

## Development

```sh
make test    # offline unit tests
make check   # tests plus citations resolve, references headed, frontmatter valid,
             # scripts parse, the vendored scan-report-kit matches its MANIFEST,
             # sample renders in ja/en and passes the run contract
make demo    # render the sample into a new private temp dir, or DEMO_OUT=dir (LANG_OUT=en for English)
```

Requirements: Python 3.9+. No third-party packages. `make check` also needs
`shasum` or `sha256sum`; pandoc and node are optional (the GFM parser and
dashboard script syntax tests skip without them).

The format follows the sibling `security-scan` and `performance-scan` skills
(same phases, run contract, verdicts and report shape), adapted to application
design.

The dashboard uses the shared *-scan report format,
[scan-report-kit](https://github.com/simota/scan-report-kit): its stylesheet
(light and dark themes, journal-style typography) comes first, and `render.py`
adds only the rules for architecture-scan's own records (the findings register,
coloured severity bars). The page opts into the kit's application shell: a
sticky app bar, a contents sidebar with per-severity counts that filter the
register, pinned register filters and head row, and the keys `/` (search),
`j`/`k` (next or previous finding) and Enter (show or hide details). The kit is vendored in
`skills/architecture-scan/scripts/scan_report_kit/`; change it upstream and
re-vendor, never in place (`make check` verifies the copy).
