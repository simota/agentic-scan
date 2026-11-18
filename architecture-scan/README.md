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

During recon, one read-only script builds the Python import graph (never
importing or running the checkout):

```sh
python3 -I skills/architecture-scan/scripts/depgraph.py /path/to/checkout --out scratch/depgraph.json   # modules, edges, cycles, diagram
```

Every output is rendered from one record, `findings.json`, which the agent
builds from JSON fragments rather than heredocs:

```sh
python3 skills/architecture-scan/scripts/findings.py merge out/findings.json frag-001.json
python3 skills/architecture-scan/scripts/findings.py renumber out/findings.json  # severity, then path
python3 skills/architecture-scan/scripts/render.py out/findings.json --out out   # language: meta.lang
python3 skills/architecture-scan/scripts/findings.py check out --repo /path/to/assessed/checkout   # exit 1 lists each violation
python3 skills/architecture-scan/scripts/findings.py counts out/findings.json  # n_* for the report template
```

After the run, three tools hand the record on (each reads `findings.json`
and changes nothing in it):

```sh
python3 skills/architecture-scan/scripts/drafts.py out/findings.json --out scratch/drafts   # issue per finding + owner-report.md
python3 skills/architecture-scan/scripts/compare.py earlier/findings.json out/findings.json # new / resolved / persisting since a run
python3 skills/architecture-scan/scripts/sarif.py out/findings.json --out architecture.sarif # SARIF 2.1.0 for code scanning
```

and one command records what people decide afterwards, so the record keeps
following the work:

```sh
python3 skills/architecture-scan/scripts/findings.py triage out/findings.json A-002 \
    --status Accepted --note "Replays are rare until the Q1 rewrite"          # accept a risk, with its reason
python3 skills/architecture-scan/scripts/findings.py triage out/findings.json A-001,A-003 \
    --issue https://github.com/acme/shop/issues/12                            # link the filed issue
python3 skills/architecture-scan/scripts/compare.py earlier/findings.json out/findings.json \
    --carry scratch/carry.json --fail-on High                                 # keep that triage in a re-run; gate regressions
```

### The lifecycle of a finding

```
assess ─► drafts.py ─► file issues ─► triage --issue / --status ─► re-run ─► compare --carry ─► merge
            │                            (dashboard, report and SARIF        │
            └ skips findings already      re-rendered in place)              └ --fail-on: exit 3 on a
              tracked, Fixed or Accepted                                       new or reappeared finding
```

| Command | What it gives you |
|---|---|
| `findings.py triage` | Sets `status` (`Open`, `Fixed`, `Accepted`), `status_note` (the reason; `Accepted` needs one, reopening drops the old one) and `issue` (where the fix is tracked) on one or several findings, refuses an excluded finding or a reason naming an unknown finding, and re-renders `dashboard.html` and `report.md` in the same atomic write so `check` still passes (`--no-render` to skip). Both fields show in the dashboard, `report.md`, copy-for-LLM and SARIF (the reason becomes an Accepted result's suppression justification); `drafts.py` stops drafting a tracked finding and links its issue in the owner report |
| `compare.py --carry FILE` | A fragment for the later record holding the earlier triage of each persisting finding: `Accepted` with its reason (not when the severity rose: that decision is made again), and the `issue` URL. `Fixed` is never carried (found again, it is flagged as reappeared), nor is any verdict or severity. IDs in a carried reason are rewritten to the later record's |
| `compare.py --fail-on SEVERITY` | Exit `3` when the later record has, at or above SEVERITY, a new finding, one that reappeared after `Fixed`, one reported again after being excluded, or one whose severity rose to it; each reason on stderr, outputs still written |

| Tool | What it gives you |
|---|---|
| `drafts.py` | `templates/issue.<lang>.md` filled for every finding worth filing (one `A-NNN.md` each; excluded, `Fixed` and `Accepted` ones left out) and `templates/report.<lang>.md` filled as `owner-report.md` (counts, High/Medium findings, both Mermaid diagrams, rules, lists). Only the judgment stays for you: open questions, the conclusion, issue URLs. `--only A-001,A-003` drafts some |
| `compare.py` | An earlier assessment against a later one, paired by content because IDs are renumbered: new, resolved (not found again, with a warning when scopes differ), persisting with each change of severity, verdict, status or location, findings marked `Fixed` that reappeared, rule status and coverage changes, counts per severity. Markdown, or `--format json` |
| `sarif.py` | One SARIF result per finding to act on, at its `path:line`, levels by severity, rules by hunt step, stable fingerprints across runs, `Accepted` findings suppressed; `--min-severity` trims it. Upload it to GitHub code scanning or open it in an IDE's SARIF viewer |

| Output | What it is |
|---|---|
| Chat summary | Status and counts, findings by severity, decisions for a human |
| `findings.json` | The single source of every other output |
| `dashboard.html` | Self-contained dashboard: severity and verdict counts, a priority queue, findings filterable by severity, confidence, perspective, status, verdict and text (excluded findings apart), before and after architecture diagrams (inline SVG), design rules, perspective coverage, copy-for-LLM per finding |
| `report.md` | The written assessment: scope, findings, before and after architecture diagrams (Mermaid), rules, coverage, sound items, limitations, next steps |

`findings.py check` enforces the run contract: exactly these three files,
gapless `A-NNN` IDs in severity order, then path (excluded verdicts last), every perspective recorded, nonempty
`checked_ok` and `limitations`, cited rules that exist (a `Valid` finding cites one
recorded as violated, a `Likely` one violated or partly read), every violated rule
cited by a Valid or Likely finding and no reason left on a closed rule, traced and evidenced
High and Medium findings, locations that name a file, finding IDs in prose that
name recorded findings, both architecture diagrams (before and after), and a dashboard and report that match a fresh render of the current `findings.json` in
`meta.lang`, byte for byte (re-render after the last merge). It checks shape
and consistency, not whether a finding is true.

`findings.json` is never edited by hand. A fragment corrects it: `null`
removes an optional key, `{"remove": {"next_steps": ["…"]}}` deletes a list
item, `{"remove": {"rules": ["R-05"]}}` deletes a ledger entry, and a key sent
again replaces its value. Merges may run in parallel
(each holds a lock on the output directory; on Windows, run them one at a
time).

To file findings, the skill drafts from `templates/issue.{ja,en}.md` (one root
cause per issue) or `templates/report.{ja,en}.md` (one report covering several),
filled by `scripts/drafts.py`. Filing, sending or uploading stays with you.

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
  scripts/depgraph.py          Python import graph for recon: edges, cycles, layers, diagram (stdlib only)
  scripts/findings.py          merges JSON fragments; renumbers; records triage; checks the run contract (stdlib only)
  scripts/render.py            findings.json -> dashboard.html / report.md (stdlib only)
  scripts/drafts.py            findings.json -> issue drafts and an owner report from the templates
  scripts/compare.py           an earlier findings.json against a later one: new, resolved, persisting;
                               carries triage forward and gates regressions
  scripts/sarif.py             findings.json -> SARIF 2.1.0 for code scanning and IDE viewers
  scripts/scan_report_kit/     shared dashboard stylesheet (from the retired scan-report-kit)
  templates/issue.{ja,en}.md   one finding as one issue
  templates/report.{ja,en}.md  findings report to an owner or tech lead
examples/findings.sample.json  fictional sample for make demo / make check
tests/                         offline tests for the scripts and the documents
```

## Development

```sh
make test    # offline unit tests
make check   # tests plus citations resolve, references headed, frontmatter valid,
             # scripts parse,
             # sample renders in ja/en and passes the run contract, and
             # drafts, compare, sarif and triage run on it
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
`j`/`k` (next or previous finding) and Enter (show or hide details). The copy in `skills/architecture-scan/scripts/scan_report_kit/`
is maintained in this repository (scan-report-kit is retired); edit it in place.
