# bug-scan

An agent skill for a **static, read-only review of how bugs enter your own application**. It reads the
source and the git history, classifies past fixes, traces where they came from with graded evidence, finds
the same entry still in the code, and tracks each defect's relations, reproduction steps, risk, hazard, and
the screens, APIs and tables it reaches.

> It does not fix code, run the application or read live data, and it never ranks or names people.

```
RECON → CATALOG → HISTORY → TRIAGE → REVIEW → VERIFY → RECONCILE → REPORT
                  mine git   read      hunt     falsify  ledger      findings.json
                  history    fixes     live                          ├─ dashboard.html
                                       entries                       ├─ report.html / report.pdf
                                                                     └─ chat summary
```

## Why origins are graded

A blame edge says who last touched a line, not who caused a defect. In a hand-read sample during design,
about half of fixes closed something never written, where no introducing commit exists. So each origin is
`Traced` (both diffs read, cause explained), `Blamed` (blame only) or `Unattributable`, and only `Traced`
feeds headline numbers.

## Install

```sh
make link                 # symlink into every installed host's skills dir
make link AGENT=claude    # one host only
make status
make unlink
```

Then invoke `bug-scan` (or `/bug-scan`).

## Outputs

| Output | What it is |
|---|---|
| `findings.json` | The one source of the register and figures, built from JSON fragments |
| `surfaces.json` | Screens, APIs, jobs, tables, services and settings, with links |
| `history.json` | Fix candidates, blame edges, churn and tags. No authors, no diff bodies |
| `dashboard.html` | Self-contained register, filters and nine figures, each with a table |
| `report.html` / `report.pdf` | The printable report |
| `ledger.json` | Optional, outside the repository: tracks defects across runs |

## Figures

Related defects, surface map (screen → API → DB), risk and hazard, injection path map, pattern by module,
fix chains, hotspot quadrant, live entry points, and issues to patterns. See
`skills/bug-scan/reference/diagrams.md`.

## Tools

```sh
S=skills/bug-scan/scripts
python3 $S/surfaces.py scan <repo> --out out/surfaces.json
python3 $S/history.py <repo> --out out/history.json
python3 $S/findings.py merge out/findings.json frag.json
python3 $S/findings.py renumber out/findings.json
python3 $S/render.py out/findings.json --out out
python3 $S/contract_check.py out --repo <checkout>
python3 $S/ledger.py reconcile <ledger.json> out/findings.json --repo <repo> --fragment frag.json
python3 $S/compare.py <earlier-out> <later-out>
python3 $S/import_findings.py <other>/findings.json --scan security-scan --out frag.json
```

## Layout

```
skills/bug-scan/
  SKILL.md                 phases, run contract, severity, decisions
  reference/               recon, gates, surfaces, history, taxonomy, tracking, validation, diagrams, schema, report
  scripts/                 standard library only
  scripts/scan_report_kit/ vendored shared report format; change it upstream and re-vendor
examples/                  fictional acme-shop record, for make demo and make check
tests/                     offline tests
docs/plans/                the design and a diagram sample
docs/quality/              the SQI rubric, its measured report and the audit scripts (development only)
```

## Development

```sh
make test    # offline unit tests (needs git)
make check   # tests plus references, frontmatter, the vendored kit and a sample render in ja and en
make demo    # render the sample; DEMO_OUT=dir, LANG_OUT=en, NO_PDF=1
```

Requirements: Python 3.9+ and git. No third-party packages. The PDF needs headless Chrome, Chromium or WeasyPrint.
