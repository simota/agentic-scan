# performance-scan

An agent skill for a **static, read-only performance review of your own
application's source code**. It maps the hot paths, reviews them from several
perspectives, verifies what it finds, and delivers the result three ways: a
chat summary, an interactive dashboard and a Markdown report.

> The skill reads source; it does not edit code and does not send load to
> deployed systems. Benchmarks and profilers run only on request, on your own
> local or throwaway environment.

## What it does

```
RECON ─► CHECKLIST ─► REVIEW ─► VERIFY ─► REPORT
 map      budgets and  one pass   re-trace   findings.json
 hot      perspectives per unit   High and   ├─ dashboard.html
 paths,   for this app            Medium     ├─ report.md
 volumes                          findings   └─ chat summary
```

- **Recon** builds the hot-path map: stack and execution model, every entry
  point with its workload and frequency, the data model with indexes and
  expected volumes, I/O sinks, caches, pools and runtime config
- **Budgets** — the bounds this app must keep (queries per request, result and
  payload size, complexity, latency and timeouts, shared resources, front-end
  size), derived from the repository and hunted on every path that pays them.
  Bounds inferred rather than stated become questions for a human
- **Perspectives** — twelve review angles (database access, algorithms,
  memory, I/O and network, caching, concurrency and resources, payload and API
  shape, front end, background work, startup and configuration, dependencies,
  observability) with about 45 hunt steps and a table of sound vs look-alike
  constructs. Each perspective applied, not applicable, or not checked is
  recorded in the report
- **Validation** — every finding gets a verdict (`Valid`, `Likely`,
  `Unverified`, `Unlikely`, `FalsePositive`, `NotApplicable`) with evidence,
  checked against four claims: reachability, scale, mitigations and impact.
  Static cost models (`1 + N queries`) and local measurements stay distinct;
  unmeasured milliseconds are never reported
- **Severity** — High when a hot path's cost grows with an uncapped scale
  driver, or one request blocks a shared resource; each condition the code does
  not control lowers it one level

## Install

```sh
make link                 # symlink into every installed host's skills dir
make link AGENT=claude    # one host only
make status
make unlink
```

Then invoke `performance-scan` (or `/performance-scan`).

## Outputs

Every output is rendered from one record, `findings.json`, which the agent
builds from JSON fragments rather than heredocs:

```sh
python3 skills/performance-scan/scripts/findings.py merge out/findings.json frag-001.json
python3 skills/performance-scan/scripts/render.py out/findings.json --out out --lang ja
python3 skills/performance-scan/scripts/findings.py check out   # exit 1 lists each violation
```

| Output | What it is |
|---|---|
| Chat summary | Status and counts, findings by severity, decisions for a human |
| `findings.json` | The single source of every other output |
| `dashboard.html` | Self-contained dashboard: counts, findings filterable by severity, budgets, perspective coverage |
| `report.md` | The written assessment: scope, findings, budgets, coverage, sound items, limitations, next steps |

`findings.py check` enforces the run contract: exactly these three readable,
nonempty files (valid symbolic links are allowed),
gapless `P-NNN` IDs in severity order, every perspective recorded, and nonempty
`checked_ok` and `limitations`. It checks shape, not whether rendered text is
current or a finding is true.

To file findings, the skill drafts from `templates/issue.{ja,en}.md` (one root
cause per issue) or `templates/report.{ja,en}.md` (one report covering several).
Filing or sending stays with you.

## Layout

```
skills/performance-scan/
  SKILL.md                     phases, run contract, severity, decisions, rules
  reference/recon.md           building the hot-path map and workload inventory
  reference/budgets.md         deriving the budget ledger, cost-trace rows, close-check
  reference/perspectives.md    the review perspectives, hunt steps and sound constructs
  reference/validation.md      verdicts, the four claims, measurement and fix verification
  reference/findings-schema.md findings.json shape, merge semantics and render command
  reference/report.md          checklist and findings report formats
  scripts/findings.py          merges JSON fragments; checks the run contract (stdlib only)
  scripts/render.py            findings.json -> dashboard.html / report.md (stdlib only)
  templates/issue.{ja,en}.md   one finding as one issue
  templates/report.{ja,en}.md  findings report to an owner or manager
examples/findings.sample.json  fictional sample for make demo / make check
scripts/install.py             path-safe install helper used by Makefile
tests/                         offline tests for the scripts and the documents
```

## Development

```sh
make test    # offline unit tests
make check   # tests plus citations resolve, references headed, frontmatter valid,
             # scripts parse, sample renders in ja/en and passes the run contract
make demo    # render the sample into $TMPDIR/performance-scan-demo (LANG_OUT=en for English)
```

Requirements: Python 3.9+. No third-party packages.

The format follows the sibling `security-scan` skill (same phases, run
contract, verdicts and report shape), adapted from vulnerabilities to
performance.
