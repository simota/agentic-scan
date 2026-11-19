# SQI Improvement Report (bug-scan)

Rubric: [sqi-rubric.md](sqi-rubric.md) (fixed before the changes). Comparison: `309e1dd` and the current working tree. Measurements: [measured/](measured/).

The results are provisional. A real browser could not be launched (see “Unverified checks and remaining risks” below), and no tests with real users were conducted. There was 1 scorer, the implementer, and no independent review. The scores help describe quality and do not demonstrate gains in user satisfaction or productivity.

## Quality scores

| Metric | Before | After | Change | Assessment | Coverage | Evidence |
|---|---:|---:|---:|---|---:|---|
| DQI Design | 56.0 | 74.0 | +18.0 | Improved | 100% | Mostly E2, some E1 |
| AQI Architecture | 66.0 | 80.0 | +14.0 | Improved | 100% | Mostly E2, some E1 |
| VQI Visual quality | 49.2 | 63.1 | +13.9 | Improved (provisional) | 65% | E1 and static calculations only. Rendering unverified |
| UXQI UI/UX | 48.9 | 71.1 | +22.2 | Improved (provisional) | 90% | E2 (jsdom). Real browsers and real users unverified |
| SQI Overall | 55.0 | 72.1 | +17.0 | Improved (provisional) | 89% | Equally weighted average of 4 domains |

VQI and UXQI are normalized to 100 points using the weights of the scored criteria. Unverified criteria receive neither 0 points nor the average score. Criteria and conditions are the same before and after. The overall change is calculated from unrounded values.

## Unverified checks and remaining risks

Display in a real browser remains unverified. Chromium could not start because of Mach port restrictions in the sandbox, and the automatic mode classifier rejected execution outside the sandbox. The Chrome extension does not accept `file://`, and local servers cannot bind to a port. The Playwright Firefox download failed.

As a result, page overflow, overlapping SVG text, overflow from boxes, focus visibility, dark theme appearance, LCP/CLS, behavior while scrolling, print, and PDF remain unverified. Changes to horizontal scrolling and minimum width for `.bsf .plot`, `focus-visible`, and color tokens were adopted without checking rendered output.

`docs/quality/audit.py ui` has yet to run to completion. It failed before the browser launched, so the script itself may still contain defects. `dom_audit.mjs` was verified.

Accessibility measurements come from jsdom. jsdom has no layout, and axe contrast rules cannot run there, so 0 axe findings do not establish WCAG conformance. Screen reader checks and measurements of task success rates and completion times with real users were not performed.

The `locked` fix works only in environments with `fcntl`. Windows still runs without locking. `surfaces.py merge` and `ledger.py` have no locking.

VQI visual hierarchy and UXQI predictability remain subjective because they depend on how the rubric is interpreted.

Candidates for improvement include consolidating `TEST_PATH`, reducing C901 violations, adding CI, and contributing changes upstream to the kit.

## Quality assurance

| Check | Result |
|---|---|
| `make test` | 60 passed, 0 failures. Same result in 3 consecutive runs |
| `make check` | Passed (includes ja/en rendering, contract checks, and MANIFEST) |
| New tests against the old code | 15 failures, 16 errors |
| Lint | 0 Ruff F-series findings. The repository has no type-checking or dedicated lint configuration |
| E2E and real browser | Not run |
| `report.pdf` | Not generated (requires a browser) |

## Score breakdown

### DQI

| Criterion | Weight | Before | After | Weighted change | Evidence |
|---|---:|---:|---:|---:|---|
| Separation of responsibilities | 20 | 2 | 3 | +4 | Consolidated duplicate rules, including terminal states, in `common.py` (duplicate literals 10→0). The 2 `TEST_PATH` definitions and the mixing of data and rendering in diagrams kept the score below 4 |
| Cohesion | 15 | 3 | 4 | +3 | Removed an unused argument from `insert_once` and moved `excluded`/`closed` to the shared layer |
| Contract clarity | 15 | 3 | 4 | +3 | For 22 invalid inputs, tracebacks fell (11→0) and so did corruption cases (1→0) |
| Ease of change | 15 | 3 | 4 | +3 | Files touched when adding a status value fell (4→2) |
| Readability | 10 | 3 | 3 | 0 | C901 violations increased (14→16) with the addition of validation functions. E741 remained at 5 |
| Testability | 15 | 3 | 4 | +3 | Line coverage rose (86→87%). Added tests for invalid input and concurrency |
| Invariants and exceptions | 10 | 3 | 4 | +2 | Lost updates fell (about 135/200→0/200) |

### AQI

| Criterion | Weight | Before | After | Weighted change | Evidence |
|---|---:|---:|---:|---:|---|
| Boundaries and dependency direction | 20 | 4 | 4 | 0 | Cycles remained at 0 and the kit's MANIFEST matched |
| Layers and data flow | 15 | 3 | 4 | +3 | Replaced diagram-specific checks for unresolved records with a shared helper (D6–D9) |
| Locality of change impact | 15 | 3 | 4 | +3 | E1. Scenarios included adding a status value, adding a diagram, adding a record field, and updating the kit (maximum 4→3 files). The rubric says the scenarios would be documented in `audit.py`, but they are listed only here |
| Contracts and consistency | 15 | 3 | 4 | +3 | Restored missing table entries for D3/D4/D5 and eliminated lost updates during concurrent merges |
| Fault tolerance | 10 | 3 | 4 | +2 | `merge`, `surfaces merge`, `ledger`, `compare`, and `render` return named errors for invalid input |
| Security boundaries | 10 | 4 | 4 | 0 | Existing tests were retained and no boundaries were relaxed |
| Observability and operations | 10 | 3 | 4 | +2 | Made diagram omissions explicit and added `quality.reached_max_commits`. No CI |
| Scalability | 5 | 3 | 4 | +1 | About 1 second for 800 records. The limit is displayed in the UI |

### VQI (65% coverage)

| Criterion | Weight | Before | After | Weighted change | Evidence |
|---|---:|---:|---:|---:|---|
| Visual hierarchy | 20 | 3 | 4 | +4 | Placed the defect list before the diagrams per the design (confirmed by DOM order) |
| Consistency | 20 | 2 | 2 | 0 | Diagram cards remain rounded boxes alongside the kit's ruled style (see changes not adopted below) |
| Typography | 15 | 2 | 3 | +3 | Calculated SVG text size on mobile increased (4.2px→10.1px). Overlap was not measured, so the score stayed below 4 |
| Layout | 15 | Unverified | Unverified | - | Checking page overflow requires rendering |
| Interaction states | 10 | Unverified | Unverified | - | CSS was updated. Pixel-level checks were not performed |
| Color and contrast | 10 | 3 | 4 | +2 | AA violations for diagram token pairs fell (5→0). The kit's token pairs had 0 violations. Based solely on static token calculations |
| Spacing and density | 10 | Unverified | Unverified | - | Requires rendering |

### UXQI (90% coverage)

| Criterion | Weight | Before | After | Weighted change | Evidence |
|---|---:|---:|---:|---:|---|
| Task completion | 25 | 2 | 3 | +5 | T2 (diagram → record) now takes 1 action instead of a manual ID search. The number of screens was not measured, so the score stayed below 4 |
| Discoverability | 15 | 2 | 3 | +3 | Aligned the table of contents with page order and added a diagram index. Behavior while scrolling remains unverified |
| Predictability | 15 | 3 | 4 | +3 | Unnecessary focus stops in the report fell (130→0). Fixed separators on the English page and D4 tooltips |
| Feedback | 10 | 3 | 4 | +2 | D8 announces the selected count and diagram omissions are explicit |
| Error prevention and recovery | 10 | 2 | 4 | +4 | Every corpus entry now produces an error that identifies the field. The errors do not yet suggest fixes |
| Accessibility | 15 | 3 | 4 | +3 | Named diagram elements increased (0→134), Tab presses to reach a record decreased (168→28), and axe violations were 0. Measured in jsdom without contrast rules |
| Perceived performance | 10 | Unverified | Unverified | - | Requires rendering. See the HTML size increase below |

## Measurements

| Area | Metric | Before | After | Method |
|---|---|---:|---:|---|
| Design | Tracebacks for 22 invalid inputs in the corpus | 11 | 0 | CLI execution |
| Design | Record corruption in the same corpus (a string becomes a list with 1 character per element) | 1 | 0 | CLI execution |
| Design | Duplicate rule literals | 10 | 0 | Source count |
| Design | C901 violations | 14 | 16 (worse) | ruff |
| Design | Test count / line coverage | 45 / 86% | 60 / 87% | unittest, coverage |
| Architecture | Lost updates during concurrent merges (per 200 records, 3 runs) | 136, 137, 130 | 0, 0, 0 | 8 processes |
| Architecture | Render with broken references | KeyError, ValueError | Named errors | Script |
| Architecture | Import cycles | 0 | 0 | AST |
| Consistency | D3 table rows / all relationships | 9 / 21 | 21 / 21 | Sample |
| Consistency | D8 counts FalsePositive as unresolved | Yes | No | Test |
| Visual design | AA violations for diagram token pairs | 5 | 0 | Static calculation |
| UI | Tab presses to reach a record | 168 | 28 | jsdom |
| UI | Total Tab stops | 176 | 64 | jsdom |
| UI | Named diagram elements | 0/130 | 134/134 | jsdom |
| UI | Links that navigate to records | 0 | 20 | jsdom |
| UI | Unnecessary focus stops in the report | 130 | 0 | jsdom |
| UI | axe violations (dashboard / report) | 0 / 1 minor | 0 / 1 minor | jsdom, excluding contrast |
| Performance | Median `render.build` time (30 runs) | 13.8 ms | 10.3 ms | Treated as noise (exceeds the ±20% threshold, but no changes targeted this operation's speed) |
| Performance | Generation for 8 / 80 / 800 records | 7 / 62 / 994 ms | 7 / 38 / 1035 ms | Treated as noise |
| Performance | `dashboard.html` | 176,153 B | 191,389 B | +8.6% |
| Performance | `report.html` | 146,419 B | 158,447 B | +8.2% |

The output grew because of added accessibility attributes such as `aria-label`. For 800 records, the increase was +27%. This size regression was accepted in exchange for improved accessibility.

## Changes

| File | Change | Metrics |
|---|---|---|
| `scripts/common.py` | Centralized `excluded`, `closed`, `unresolved`, and `clean` | DQI, AQI |
| `scripts/findings.py` | Added `_check_fragment`, `_structure_errors`, and `reference_errors`. Moved key computation after validation. Fixed lock contention | DQI, AQI, UXQI |
| `scripts/diagrams.py` | Fixed miscounts of excluded records and missing table entries, made omissions explicit, added `aria-label` and record links, organized Tab order (arrow-key navigation), and addressed Esc, color tokens, and minimum width on mobile | AQI, VQI, UXQI |
| `scripts/render.py` | Moved diagrams after the defect list, aligned the table of contents with page order, added reference checks and `insert_before` | VQI, UXQI, AQI |
| `scripts/ledger.py`, `surfaces.py`, `compare.py` | Validated input and removed duplication | AQI |
| `scripts/history.py`, `import_findings.py` | Removed duplication and added `reached_max_commits` | DQI, AQI |
| `scripts/contract_check.py` | Changed the import source | DQI |
| `tests/test_bug_scan.py` | Added 15 regression tests and verified that every case failed against the old code | DQI |
| `reference/diagrams.md`, `reference/history.md`, `README.md` | Updated the behavior documentation | - |
| `docs/quality/` | Rubric, report, and measurement scripts (for development) | - |

`scan_report_kit/` and `examples/` are unchanged (MANIFEST matches).

### Compatibility impact

- Diagram placement. Diagrams now follow the defect list on the dashboard, as specified in the design. The `#figures` and `#fig-dN` anchors are unchanged.
- Re-rendering. For output from previous versions, `contract_check.py` reports that it “does not match a fresh render”. Re-rendering resolves the mismatch.
- Stricter validation. Rendering now rejects records with self-referential relations or nonexistent gates. Numeric `summary` and string `events` are also rejected.
- Contract checks. Checks stop as soon as they encounter a structural error. Previously they also reported violations of the remaining rules.
- Record format. Existing `findings.json`, `surfaces.json`, and `history.json` files remain readable as-is. `history.json` gains 1 field.

## Changes not adopted

- Align diagram cards with the kit's ruled style. Deferred because rendering could not be checked. This is why the VQI consistency score stayed at 2.
- Split `diagrams.py` and separate diagram data from rendering. Skipped because the restructuring would be excessive without solving a problem in public behavior.
- Modify `scan_report_kit`. It is vendored, and changes are made upstream.
- Add CI. Deferred as a repository operations decision and because this environment could not verify it.

## Reproduction

```sh
# Real-browser measurements (run outside the sandbox). Change --root to measure the 309e1dd checkout under the same conditions
python3 docs/quality/audit.py ui --out ui.json --shots shots --axe <axe.min.js> [--chromium <path>]

# Measurements that run in any environment
python3 docs/quality/audit.py code --out code.json
node docs/quality/dom_audit.mjs <dashboard.html> <report.html> <node_modules>
```
