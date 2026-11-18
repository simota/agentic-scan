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
  observability) with 47 hunt steps and a table of sound vs look-alike
  constructs. Each perspective applied, not applicable, or not checked is
  recorded in the report
- **Validation** — every finding gets a verdict (`Valid`, `Likely`,
  `Unverified`, `Unlikely`, `FalsePositive`, `NotApplicable`) with evidence,
  checked against four claims: reachability, scale, mitigations and impact.
  Static cost models (`1 + N queries`) and local measurements stay distinct;
  unmeasured milliseconds are never reported. A recorded measurement always
  carries a before and an after run (without and with the fix direction), each
  with its command, result and raw log, and both outputs show them
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

JSON inputs must be regular files; symbolic links to regular files are allowed.
Named pipes (FIFOs), devices and shell process substitution are not supported.
Object member names must be unique at every nesting level. Nonstandard numeric
constants (`NaN`, `Infinity`, `-Infinity`) and numbers that overflow Python's
finite floating-point range (for example `1e400`) are refused. JSON decoding
failures, including Python's parsing limits, are reported as input errors
before any record or report is changed.

Run all merges to the same `findings.json` sequentially through one REPORT
coordinator. Parallel reviewers write draft findings in scratch; the coordinator
writes the merged fragments with final IDs. Atomic replacement does not detect
concurrent updates.

### Script behaviour

- **Inputs.** The existing record, every fragment, the render input and the
  checked record must be regular files (symbolic links to them are allowed).
  Named pipes, devices and shell process substitution are refused before
  reading. Member names are compared after decoding escapes (`"id"` and
  `"\u0069d"` collide); ordinary strings containing `NaN` or `Infinity` are
  fine.
- **Merging.** The record is validated before and after every fragment, UTF-8
  encoded in full, written to a temporary file beside the destination and then
  atomically replaced; encoding or write failures leave the record unchanged.
  Existing permission bits and symbolic links are preserved and a new record
  starts private (0600).
- **Rendering.** Both outputs are encoded, staged and backed up before either
  destination is replaced. A failed replacement restores what was already
  replaced; if that also fails, the error names the retained recovery copy.
  Permission bits and symbolic links are preserved and new outputs start
  private. This is not a transaction for concurrent writers and does not
  survive forced termination or a crash mid-replace.
- **Checking.** Required outputs must be readable, nonempty regular files;
  symbolic links to such files are allowed.
- **Untrusted text.** Record strings come from an agent that read an untrusted
  repository, so both outputs treat them as plain text: HTML is escaped, Markdown
  syntax, bare URLs, emails and emoji shortcodes are neutralised for GitHub, and
  control and bidi characters are shown as `\uXXXX`. Only `references[]` link,
  and only to absolute `http(s)` URLs, `mailto:` or relative paths (never
  `//host`, which opens a network share from `file://`). Renderers that
  linkify bare domains (markdown-it with `linkify`, used by the VS Code preview)
  may still turn names such as `example.com` into links; view `report.md` on
  GitHub or as plain text when the record's source is untrusted.

| Output | What it is |
|---|---|
| Chat summary | Status and counts, findings by severity, decisions for a human |
| `findings.json` | The single source of every other output |
| `dashboard.html` | Self-contained dashboard in the kit's application shell (app bar, contents sidebar with severity facets, j/k keys, pinned filter bar): counts, findings filterable by severity or Excluded with a live count of what the filter shows, budgets, perspective coverage (tables scroll by keyboard on narrow screens); a Copy-for-LLM button per finding whose result is announced; excluded findings badged as Excluded; light and dark themes |
| `report.md` | Severity and verification counts, scope and method, a findings index, one block per finding, excluded findings, budgets with the findings citing them, perspective coverage, checked and sound, limitations, decisions, next steps |

`findings.py check` enforces the run contract: exactly these three readable,
nonempty regular files (symbolic links allowed; more only with `--allow NAME`);
a complete, schema-valid record whose text encodes as UTF-8; gapless `P-NNN`
IDs in severity order with `FalsePositive`/`NotApplicable` last;
`Valid`/`FalsePositive`/`NotApplicable` evidence citing a `path:line`; evidence
for every High and Medium finding; each `step` a hunt step ID of the finding's
`category`; no `Suspected` finding marked `Valid`; every perspective recorded,
and `applied` when an included finding names it; each finding's `budget`
naming a ledger entry, and no `holds` budget with a `Valid`, unfixed finding
against it; a reason for every `not checked` budget; nonempty
`checked_ok` and `limitations`. It checks structure, not whether rendered text
is current or a finding is true.

Exit codes: `render.py` 0 written, 1 an output could not be written, 2 bad
input or usage; `findings.py` 0 ok, 1 merge refused or contract violated
(reasons on stderr), 2 usage.

## After the run: triage, summary, issues, re-scans and code scanning

These scripts work on a finished record. Only `findings.py set` (and merging
a `--carry` fragment) changes it; the others read it, and each escapes record
text the way `report.md` does.

```sh
S=skills/performance-scan/scripts
python3 $S/summary.py out/findings.json --scratch "$SCRATCH"      # chat summary from the record
python3 $S/issues.py  out/findings.json --out "$SCRATCH/issues"   # one issue draft per open finding
python3 $S/compare.py old/findings.json out/findings.json         # what changed since an earlier run
python3 $S/findings.py set out/findings.json P-002 --status Accepted \
  --decision "Ops accepts the export cost below 10k orders" --render  # owner triage
python3 $S/compare.py old/findings.json out/findings.json --carry "$SCRATCH/carry.json"
python3 $S/sarif.py   out/findings.json --out "$SCRATCH/perf.sarif"   # code-scanning alerts
```

- **`findings.py set`** is the owner's triage: it sets `Open`, `Fixed` or
  `Accepted` on the named findings in place (atomically, like `merge`),
  appends `--decision` to `decisions` (prefixed with the IDs when it names
  none) and with `--render` rewrites `dashboard.html` and `report.md`. A
  finding that becomes `Accepted` needs a decision, and `check` refuses an
  `Accepted` finding that no `decisions` line names. Excluded findings have no
  status to change.

- **`summary.py`** prints the chat summary of `reference/report.md` (status and
  verification counts, revision and method, one line per finding, the full
  block of each High finding, checked and sound, decisions, next steps and the
  rendered files), so the counts and IDs in chat are the record's.
  `--baseline OLD` adds one line with what changed since that run.
- **`issues.py`** writes `P-NNN.md` drafts that follow
  `templates/issue.{ja,en}.md` section by section, filled from the record:
  the budget statement, request steps one per paragraph, evidence, the
  measurement log when recorded, references, and *Open questions* built from an
  incomplete verdict, an Environment-dependent condition and the `decisions`
  and `limitations` lines that name the finding's ID. It selects every `Open`
  finding that is not excluded (`--id`, `--min-severity`,
  `--include-accepted`), keeps existing drafts unless `--force`, refuses the
  record's own run directory, and prints each file with its issue title, ready
  for e.g. `gh issue create --title ... --body-file ...`.
  `templates/report.{ja,en}.md` remains the frame for one report covering
  several findings. Filing or sending stays with you.
- **`compare.py`** compares two records of the same application. IDs are
  renumbered every run, so findings are matched by root cause: same
  perspective, then a shared location file (line numbers are ignored), the hunt
  step and title similarity. Each active finding is *new*, *resolved* (Fixed,
  excluded, or absent while the new run applied its perspective), *not
  re-checked* (absent, but its perspective was not applied this time) or
  *persisting*, with severity, confidence, verdict, status and file changes
  listed; budget and perspective status changes and a scope or same-revision
  note follow. Output is Markdown (`--lang`) or `--format json`.
  `--fail-on High` (or another severity) exits 1 when a new or escalated `Open`
  finding reaches that severity, for a CI job that compares against an
  accepted baseline.

  `--carry FRAGMENT` keeps the owner's triage across a re-scan: it writes a
  merge fragment that marks every baseline `Accepted` finding that persists,
  still `Open` and not escalated, `Accepted` again, carrying the baseline
  `decisions` lines that name it with IDs rewritten to the new run's
  (unmatched IDs become `baseline-P-NNN`). A finding whose severity rose is
  listed as not carried. Merge it with `findings.py merge` once the owner
  confirms; it is refused inside either record's directory.
- **`sarif.py`** exports the active findings as SARIF 2.1.0 for GitHub code
  scanning (`github/codeql-action/upload-sarif`) and editor SARIF viewers: one
  rule per hunt step named from `reference/perspectives.md`, High → `error`,
  Medium → `warning`, Low/Info → `note`, every location relative to
  `%SRCROOT%`, a root-cause fingerprint that survives renumbering and moved
  lines, `Accepted` findings as accepted suppressions justified by their
  decisions, and with `--baseline` a `baselineState` of `new`, `unchanged` or
  `updated`. Record text stays plain text with SARIF embedded links escaped.

A CI job can combine them: compare against the accepted baseline with
`--fail-on High`, and upload `sarif.py --baseline` output so the PR shows the
findings on their lines.

Exit codes: `summary.py` 0 printed, 2 bad input; `issues.py` 0 written, 1 a
draft could not be written, 2 bad input, an unusable `--id` or an existing
draft; `compare.py` 0 compared, 1 the `--fail-on` gate failed, 2 bad input or
a `--carry` path that could not be written; `findings.py set` 0 set, 1
refused (unknown or excluded ID, missing decision, bad record) with nothing
changed; `sarif.py` 0 written, 1 the file could not be written, 2 bad input or
an `--out` inside the record's directory.

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
  scripts/findings.py          merges JSON fragments; checks the run contract; set triages status
  scripts/citations.py         tells a path:line citation in evidence from look-alikes (used by check)
  scripts/render.py            findings.json -> dashboard.html / report.md (stdlib only)
  scripts/summary.py           findings.json -> the chat summary on stdout
  scripts/issues.py            findings.json -> one issue draft per open finding
  scripts/compare.py           two findings.json -> new / resolved / changed, a CI gate, --carry
  scripts/sarif.py             findings.json -> SARIF 2.1.0 for code scanning and editors
  scripts/scan_report_kit/     bundled report kit: the shared dashboard stylesheet
  templates/issue.{ja,en}.md   one finding as one issue
  templates/report.{ja,en}.md  findings report to an owner or manager
examples/findings.sample.json  fictional sample for make demo / make check
examples/findings.sample.baseline.json  an earlier fictional run of it, for compare.py
scripts/install.py             path-safe install helper used by Makefile
tests/                         offline tests for the scripts and the documents
```

## Development

```sh
make test    # offline unit tests
make check   # tests plus citations resolve, references headed, frontmatter valid,
             # scripts parse, description <= 400 bytes, no cited ../ paths,
             # sample renders in ja/en and passes the run contract,
             # compare (with --carry), summary, issue drafts and SARIF run on the samples
make demo    # render the sample into .demo/ in this checkout (LANG_OUT=ja for Japanese labels)
```

Requirements: Python 3.9+. No third-party packages. The `make` targets need
GNU Make 3.81+ and a POSIX shell.
The Makefile tests isolate their home, agent paths and demo settings in temporary
fixtures, so exported local configuration does not redirect test installations
or reports. Explicit per-test overrides still exercise custom paths.

The dashboard uses the report kit bundled under
`skills/performance-scan/scripts/scan_report_kit/`: its dashboard
stylesheet (light and dark themes, journal-style typography) comes first, the
page opts into its application shell (`html.app-shell`), and `render.py` adds only the rules for what this skill renders differently
(collapsible findings, severity filter buttons, budget and coverage tables).
The kit is maintained in this repository; edit it in place. `report.md` is unchanged.
