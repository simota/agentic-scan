# Follow-up

**Read when:** after REPORT, when the requester asks to file the findings in a tracker, code scanning or a spreadsheet, or to compare this review with an earlier one (a re-check after fixes, a release gate).

The review stays read-only; these scripts read a finished `findings.json` and write one
derived file. Neither is a contracted output: write it into scratch or a path the requester
names. A file written inside the review directory needs `--allow <name>` on
`contract_check.py`, and the scripts refuse to replace any review output, an input, a
symlink or anything in `evidence/`. Both accept `--out -` for standard output.

## Export

```sh
python3 <skill-dir>/scripts/export.py sarif    <out>/findings.json --out ux-scan.sarif [--prefix <subdir>]
python3 <skill-dir>/scripts/export.py markdown <out>/findings.json --out issues.md [--lang ja|en]
python3 <skill-dir>/scripts/export.py csv      <out>/findings.json --out findings.csv
```

| Format | For | Holds |
|---|---|---|
| `sarif` | GitHub code scanning (`github/codeql-action/upload-sarif`), SARIF viewers in IDEs | SARIF 2.1.0: one rule per hunt step, one result per `Open` or `Accepted` finding at its `path:line` (`High` is `error`, `Medium` `warning`, `Low` and `Info` `note`), `occurrences` as related locations, `Accepted` findings suppressed, and a `uxScanFinding/v1` fingerprint from the hunt step, file and title, so a re-review that renumbers ids or moves lines updates the same alerts |
| `markdown` | Issue trackers | One issue draft per `Open` finding: the `[U-001] Title` heading is the issue title; the body holds severity, location, flow, screen, criterion, observed, expected, impact, fix, a *Done when* line, the evidence file names and references. A checklist of every draft opens the file. Tags quoted in prose are escaped outside code spans, so a tracker's HTML sanitizer does not swallow them |
| `csv` | Triage in a spreadsheet | Every finding, excluded ones too, one row each with its verdict; UTF-8 with a byte-order mark; a cell that a spreadsheet would run as a formula (`=`, `+`, `-`, `@`, tab, carriage return) is prefixed with `'` |

`FalsePositive` and `NotApplicable` findings are left out of `sarif` and `markdown`, and
`Fixed` ones out of both. `--min-severity High` keeps `High` only; `--ids U-001,U-004`
exports the findings the requester chose. When the reviewed directory sits inside a larger
Git repository (`meta.scope` names it), pass that subdirectory as `--prefix` so code
scanning resolves the paths from the repository root.

Filing the issues or uploading the SARIF publishes the findings: do it only when the
requester asks, through their own tools; the scripts write files and send nothing.

## Compare with an earlier review

Run the new review independently first (SKILL.md *Independence*): read the earlier record
only now, to compare.

```sh
python3 <skill-dir>/scripts/compare.py <earlier>/findings.json <out>/findings.json --out progress.md [--lang ja|en] [--fail-on High]
python3 <skill-dir>/scripts/compare.py <earlier>/findings.json <out>/findings.json --out progress.json --format json
```

Ids are renumbered in every review and lines move, so findings are matched by content: the
same hunt step, file and title; then the same hunt step and file with a similar title or a
start line within 3 lines; then a near-identical title anywhere, for a file that moved. Each
change is one of:

| Change | Means | Then |
|---|---|---|
| `new` | Reported now, not before, or ruled out before | Normal review output; check whether a fix introduced it |
| `regressed` | `Fixed` before, reported again | Name it first in the chat summary |
| `resolved` | Reported before, no longer reported | Not proof of a fix: confirm that the defect is gone (`after` evidence) before saying so |
| `fixed` | Marked `Fixed` now | Its `after` evidence is required already (`reference/evidence.md`) |
| `ruled_out` | Judged `FalsePositive` or `NotApplicable` now | The verdict's evidence explains the change |
| `persisting` | Reported both times | Notes name severity, status, verdict, perspective or file changes; one `Accepted` before and `Open` now is flagged so the acceptance is carried forward (as `Accepted` with its reason) or the reason it lapsed is recorded |

A match is a heuristic. A finding split into two, merged, or reworded beyond recognition
shows as `resolved` plus `new`; read both before reporting progress. `--fail-on SEVERITY`
exits 1 when a `new` or `regressed` `Open` finding, or a `persisting` one whose severity was
raised, is at or above that severity, and lists their ids: a gate for CI or a release
checklist. The comparison is written either way.

Record the outcome in the current review, not only in the derived file: add a
`next_steps` or `decisions` line for regressions and lapsed acceptances, and name the
earlier review compared (its date and commit) in `meta.method`.
