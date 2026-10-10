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

JSON inputs must be regular files; symbolic links to regular files are allowed.
Named pipes (FIFOs), devices and shell process substitution are not supported.
Object member names must be unique at every nesting level. Nonstandard numeric
constants (`NaN`, `Infinity`, `-Infinity`) and numbers that overflow Python's
finite floating-point range (for example `1e400`) are refused. JSON decoding
failures, including Python's parsing limits, are reported as input errors
before any record or report is changed.

Run all merges to the same `findings.json` sequentially through one REPORT
coordinator. Parallel reviewers write fragments in scratch for that coordinator
to merge. Atomic replacement does not detect concurrent updates.

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
| `dashboard.html` | Self-contained dashboard: counts, findings filterable by severity or Excluded, budgets, perspective coverage; light and dark themes |
| `report.md` | Severity and verification counts, scope and method, a findings index, one block per finding, excluded findings, budgets with the findings citing them, perspective coverage, checked and sound, limitations, decisions, next steps |

`findings.py check` enforces the run contract: exactly these three readable,
nonempty regular files (symbolic links allowed; more only with `--allow NAME`);
a complete, schema-valid record whose text encodes as UTF-8; gapless `P-NNN`
IDs in severity order with `FalsePositive`/`NotApplicable` last;
`Valid`/`FalsePositive`/`NotApplicable` evidence citing a `path:line`; no
`Suspected` finding marked `Valid`; every perspective recorded; each finding's
`budget` naming a ledger entry, and no `holds` budget with a `Valid`, unfixed
finding against it; a reason for every `not checked` budget; nonempty
`checked_ok` and `limitations`. It checks structure, not whether rendered text
is current or a finding is true.

Exit codes: `render.py` 0 written, 1 an output could not be written, 2 bad
input or usage; `findings.py` 0 ok, 1 merge refused or contract violated
(reasons on stderr), 2 usage.

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
             # scripts parse, description <= 400 bytes, no cited ../ paths,
             # sample renders in ja/en and passes the run contract
make demo    # render the sample into $TMPDIR/performance-scan-demo (LANG_OUT=ja for Japanese labels)
```

Requirements: Python 3.9+. No third-party packages. The `make` targets need
GNU Make 3.81+ and a POSIX shell.

The format follows the sibling `security-scan` skill (same phases, run
contract, verdicts and report shape), adapted from vulnerabilities to
performance.
