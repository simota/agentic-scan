# Quality assessment (SQI)

Status: rubric and baseline fixed 2026-11-05, before any change they score.
Results after the changes are appended under "After"; the rubric, weights,
measurement conditions and tasks above that heading are not edited afterwards.

SQI is a rubric score, not a physical measurement. Scores are expert
judgements (E1) unless a row names a reproducible check (E2) or a measurement
(E3). No real-user testing was done; scripted browser runs are not user tests.

## Scope and weights

All four areas apply: the repository ships Python tooling (design,
architecture) and two generated UIs, `dashboard.html` and `report.html`
(visual, UX). The then-vendored report kit (since moved into the `report_*.py` modules)
was out of scope for changes: it is checked against its `MANIFEST` and changed
upstream only. It is in scope as the design system prompt-scan's own rules must
stay consistent with.

`SQI = 0.25 DQI + 0.25 AQI + 0.25 VQI + 0.25 UXQI`. Each area is
`Σ weight × score / 5`; items score 0–5 against the anchors below.

## Fixed measurement conditions

- Pages: `dashboard.html`, `report.html` rendered from both samples
  (`examples/findings.sample.json` en, `examples/findings.sample.ja.json` ja)
  with `--repo examples/sample-app --no-pdf`
- Viewports 1440×900 and 390×844; light and dark colour scheme; Chromium via
  Playwright; deviceScaleFactor 1 — 16 configurations
- Per configuration: axe-core 4.10.2 (tags wcag2a, wcag2aa, wcag21a, wcag21aa,
  wcag22aa, best-practice), page-level horizontal overflow
  (`scrollWidth - clientWidth`), elements past the viewport outside a scroll
  container, CLS, LCP, DOMContentLoaded, console errors
- Static: `make check`, ruff (F, E, W, B; E501 ignored), radon cyclomatic
  complexity, coverage.py branch coverage of the in-process test run, the import
  graph among `skills/prompt-scan/scripts/*.py`
- Change scenarios (AQI 3): S1 change a redaction rule; S2 add a record field;
  S3 restyle the dashboard; S4 add a lint rule; S5 change how findings.json is
  written
- Tasks (UXQI 1), scripted: T1 from the dashboard, open the first "Start here"
  finding and read its fix; T2 copy a finding for an LLM; T3 filter the register
  to one prompt; T4 read every column of the prompt inventory in `report.html`
  at 390 px

## Rubric anchors

Scores between anchors (1, 2) follow the common definitions: 0 fatal, 1 several
serious defects, 2 basic structure with recurring problems, 3 basic
requirements met, 4 high quality consistently, 5 edge cases handled with
evidence.

### DQI

| Item | Weight | 5 | 4 | 3 |
|---|---:|---|---|---|
| Separation of responsibilities | 20 | every production module has one reason to change | one module holds two reasons, documented | a module holds three or more unrelated reasons (schema, redaction, presentation…) |
| Cohesion | 15 | every public name of a module serves its stated purpose | ≤3 names serve other modules' purposes | a module exports a second purpose's API to other modules |
| Interface and contract clarity | 15 | 4 + contracts checked by tests on both sides | documented formats, exit codes, strict validation | documented but loosely validated |
| Changeability | 15 | S1–S5 each touch only modules named for the concern, no function with CC > 40 on the path | one scenario breaks that | two or more do |
| Readability | 10 | no function with CC > 30 | ≤2 such functions | 3–5 |
| Testability | 15 | offline tests for every CLI, branch coverage ≥ 90 %, external tools substitutable | coverage ≥ 80 % | coverage ≥ 60 % |
| Invariants and error handling | 10 | 4 + every boundary error typed and tested, no lint finding on exception handling | strict boundary checks, no swallowed errors | some unchecked boundaries |

### AQI

| Item | Weight | 5 | 4 | 3 |
|---|---:|---|---|---|
| Module boundaries, dependency direction | 20 | acyclic; tools depend on record/redaction modules, never on presentation | acyclic, one justified tool→tool dependency | acyclic, several tools depend on the presentation module |
| Layers and data flow | 15 | every stage exchanges only documented files, no stage reaches into another's internals | one stage reaches into another's internals | several do |
| Locality of change | 15 | S1–S5 change exactly the module named for the concern and a presentation change reaches no other tool | one scenario leaks | two or more leak |
| Contracts and data integrity | 15 | strict schema, provenance stamp, atomic and conflict-checked writes, all tested | one of these missing | two missing |
| Fault tolerance and isolation | 10 | every external call bounded and its failure reported and tested, observed failure handled | bounded and reported | some unbounded |
| Security and privacy boundary | 10 | redaction and path confinement in one module with its own tests, every consumer uses it | correct and tested but interleaved with unrelated code | gaps |
| Observability and operability | 10 | 4 + structured, machine-readable diagnostics | actionable messages, exit codes, CI | ad hoc |
| Scalability | 5 | measured at 10× sample size | explicit limits and lazy work for large inputs | none |

### VQI

| Item | Weight | 5 | 4 | 3 |
|---|---:|---|---|---|
| Visual hierarchy | 20 | 4 + verified with users | headline, counts, priority queue and register in reading order on every page | key item hard to find |
| Component and style consistency | 20 | only kit tokens, every responsive pattern the kit's | kit tokens, ≤2 local patterns differing from the kit | several |
| Typography and readability | 15 | 4 + verified at 200 % zoom | one serif/sans/mono system, comfortable measure | mixed |
| Layout and responsiveness | 15 | no page-level horizontal scroll and no clipped content in all 16 configurations | page-level horizontal scroll in ≤2 configurations, content still reachable | content clipped or unreachable |
| Interaction states | 10 | every control shows hover, focus, pressed/expanded and disabled where they apply | focus and expanded shown, one state missing | several missing |
| Colour, contrast, meaning | 10 | 0 axe contrast violations in 16 configurations and colour never the only signal | ≤2 violations | more |
| Whitespace and density | 10 | 4 + mobile density verified with users | consistent spacing scale | uneven |

### UXQI

| Item | Weight | 5 | 4 | 3 |
|---|---:|---|---|---|
| Task completion and efficiency | 25 | T1–T4 complete in scripted runs at both viewports without workaround | one task needs a workaround (horizontal page scroll) | one task fails |
| Discoverability, cognitive load | 15 | 4 + verified with users | primary actions labelled and placed first | some hidden |
| Predictability and consistency | 15 | controls behave as in sibling *-scan dashboards (the kit's runtime) in every respect | one divergence | several |
| Status and progress feedback | 10 | every action and filter result announced, verified with a screen reader | announced via live regions, not screen-reader verified | missing in places |
| Error prevention and recovery | 10 | 4 + verified with users | reset, empty states, copy fallback | partial |
| Accessibility | 15 | axe 0, keyboard paths for T1–T4, screen-reader verified | axe 0 in 16 configurations and keyboard paths for T1–T3 | violations |
| Perceived performance | 10 | CLS 0 and DOMContentLoaded < 100 ms in all configurations | CLS < 0.1 | worse |

## Baseline (commit 33c472f)

Measured:

- `make check`: 93 tests pass; ruff 3 findings (F401 unused `os` in render.py,
  B904 in findings.py, B905 in inventory.py)
- radon: 4 functions above CC 30 — `render.validate_data` 71,
  `contract_check.check` 73, `inventory.git_state` 42,
  `findings.fragment_problems` 36; render.py maintainability index C (2.0)
- Branch coverage 92 % (contract_check 89, findings 90, inventory 95, render 92)
- Import graph: acyclic; `contract_check → findings, inventory, render`;
  `inventory → findings, render`; `findings → render`. All three tools load
  render.py (1091 lines: schema, JSON parsing, redaction and Git excerpt reading,
  report HTML, dashboard template and script, PDF and CLI) for the schema and the
  redaction rules
- UI: axe 0 violations in 16/16 configurations; CLS 0; DOMContentLoaded ≤ 40 ms
  after the first load; no console errors. `report.html` (en) at 390 px scrolls
  sideways by 45 px in light and dark: the prompt inventory table runs past the
  viewport and its Model column is cut at the edge
- The dashboard forgets a chosen colour theme on reload; the kit's dashboard
  runtime remembers it (`scan-report-kit.theme`)

| Area | Item | W | Score | Evidence | Basis |
|---|---|---:|---:|---|---|
| DQI | Separation of responsibilities | 20 | 3 | E1 | render.py holds schema, redaction/excerpts, report, dashboard, PDF/CLI |
| DQI | Cohesion | 15 | 3 | E2 | findings/inventory/contract_check use render's schema and redaction API |
| DQI | Interface and contract clarity | 15 | 4 | E2 | schema doc, exit codes, strict parse; tests |
| DQI | Changeability | 15 | 3 | E1 | S2 goes through `validate_data` (CC 71); S1 and S3 edit the same file |
| DQI | Readability | 10 | 3 | E2 | 4 functions above CC 30 |
| DQI | Testability | 15 | 5 | E2 | 93 offline tests, 92 % branch, fake git and Chrome |
| DQI | Invariants and error handling | 10 | 4 | E2 | strict boundaries; B904 finding |
| AQI | Module boundaries | 20 | 3 | E2 | three tools depend on the presentation module |
| AQI | Layers and data flow | 15 | 4 | E1 | contract_check calls `inventory.lint_findings` |
| AQI | Locality of change | 15 | 3 | E2 | S1 and S3 leak: any render.py edit is loaded by every tool |
| AQI | Contracts and data integrity | 15 | 5 | E2 | schema, sha256 stamp, locked atomic writes, tests |
| AQI | Fault tolerance | 10 | 4 | E3 | Chrome timeout observed and reported with exit 3 |
| AQI | Security boundary | 10 | 4 | E2 | redaction tested, but inside render.py |
| AQI | Observability | 10 | 4 | E1 | actionable messages, exit codes, CI |
| AQI | Scalability | 5 | 4 | E1 | debounce >300 records, lazy detail, fragment and file limits |
| VQI | Visual hierarchy | 20 | 4 | E1 | screenshots |
| VQI | Consistency | 20 | 4 | E1 | kit tokens; report inventory/eval tables do not use the kit's narrow-screen pattern |
| VQI | Typography | 15 | 4 | E1 | kit type system |
| VQI | Layout and responsiveness | 15 | 4 | E2 | 2/16 configurations scroll sideways |
| VQI | Interaction states | 10 | 4 | E1 | focus-visible, aria-expanded; theme state not shown |
| VQI | Colour and contrast | 10 | 5 | E2 | axe contrast 0/16; severity always labelled |
| VQI | Whitespace and density | 10 | 4 | E1 | kit spacing |
| UXQI | Task completion | 25 | 4 | E2 | T4 needs horizontal page scroll |
| UXQI | Discoverability | 15 | 4 | E1 | "Start here" first, filters labelled |
| UXQI | Predictability | 15 | 4 | E1 | theme not remembered, unlike the kit |
| UXQI | Feedback | 10 | 4 | E1 | live result count, copy status; no screen reader run |
| UXQI | Error prevention and recovery | 10 | 4 | E1 | reset, empty states, copy fallback |
| UXQI | Accessibility | 15 | 4 | E2 | axe 0/16, keyboard toggles; no screen reader run |
| UXQI | Perceived performance | 10 | 5 | E3 | CLS 0, DCL ≤ 40 ms |

| Index | Baseline | Coverage |
|---|---:|---:|
| DQI | 71 | 100 % |
| AQI | 76 | 100 % |
| VQI | 82 | 100 % |
| UXQI | 82 | 100 % |
| **SQI** | **77.75** | |

## After (commit following 549a57c)

Same rubric, weights, pages, viewports, themes, tasks and tools as above.

Measured:

- `make check`: 98 tests pass (93 kept, 5 added: stacked tables, theme memory,
  import layout ×3); ruff (F, E, W, B) clean — the two B905 `zip()` notes are
  suppressed with a reason, since `strict=` needs Python 3.10 and CI runs 3.9
- radon: 2 functions above CC 30 (`inventory.git_state` 42,
  `findings.fragment_problems` 36; `record._validate_finding` is 30);
  average CC 9.7 → 8.3; render.py maintainability index C (2.0) → A (27.2)
- Branch coverage 92 % overall (coverage.py, as in the baseline; unchanged)
- Import graph (enforced by `tests/test_layout.py`): acyclic;
  `record → ∅`, `excerpt → record`, `render → record, excerpt`,
  `findings → record, excerpt`, `inventory → record, excerpt`,
  `contract_check → record, findings, inventory`. No module imports render.py
- Behaviour preserved: dashboard, report and inventory.json byte-identical for
  both samples; 3000 mutated records give the same schema verdict and message;
  600 mutated output directories give the same contract problems in the same
  order; printed report (Chromium `page.pdf`) pixel-identical, 13 pages each
- UI: axe 0 violations in 16/16 configurations; page-level horizontal overflow
  0/16 (was 2/16); CLS 0; no console errors. Desktop screenshots of report.html
  pixel-identical; only the 390 px layout of the inventory and eval tables
  changed
- Tasks T1–T4 complete in scripted runs (keyboard for T1–T3) at 1440 and 390 px
  in both languages; before, T4 failed at 390 px in English
- Theme choice survives a reload; with storage blocked the toggle still works
  and no error is thrown
- CLI wall time, `python3 -B`, median of 40 runs (p95):
  `findings.py --help` 73 → 50 ms (87 → 64), `render.py --no-pdf` 71 → 62 ms
  (107 → 78), `inventory.py examples/sample-app` 97 → 69 ms (113 → 94); the
  tools no longer compile the renderer

| Area | Item | W | Before | After | Δ weighted | Evidence | Basis for the change |
|---|---|---:|---:|---:|---:|---|---|
| DQI | Separation of responsibilities | 20 | 3 | 4 | +4 | E2 | render.py renders only; inventory.py still scans, lints and reads Git state |
| DQI | Cohesion | 15 | 3 | 5 | +6 | E2 | no module serves another's purpose; import graph test |
| DQI | Interface and contract clarity | 15 | 4 | 4 | 0 | E2 | unchanged |
| DQI | Changeability | 15 | 3 | 5 | +6 | E2 | S1 excerpt.py, S2 record.py (CC ≤ 30) + render.py, S3 render.py, S4 inventory.py, S5 record.py |
| DQI | Readability | 10 | 3 | 4 | +2 | E2 | 4 → 2 functions above CC 30 |
| DQI | Testability | 15 | 5 | 5 | 0 | E2 | unchanged |
| DQI | Invariants and error handling | 10 | 4 | 4 | 0 | E2 | B904 fixed (cosmetic); not every boundary error separately tested |
| AQI | Module boundaries | 20 | 3 | 4 | +4 | E2 | no tool depends on presentation; contract_check → findings, inventory remain |
| AQI | Layers and data flow | 15 | 4 | 4 | 0 | E1 | contract_check still calls `inventory.lint_findings` |
| AQI | Locality of change | 15 | 3 | 5 | +6 | E2 | a render.py change reaches no other tool (test-enforced) |
| AQI | Contracts and data integrity | 15 | 5 | 5 | 0 | E2 | unchanged |
| AQI | Fault tolerance | 10 | 4 | 4 | 0 | E3 | unchanged |
| AQI | Security boundary | 10 | 4 | 4 | 0 | E2 | redaction now one module, but inventory keeps its own walk confinement and the masking tests sit in test_render |
| AQI | Observability | 10 | 4 | 4 | 0 | E1 | unchanged |
| AQI | Scalability | 5 | 4 | 4 | 0 | E1 | unchanged |
| VQI | Visual hierarchy | 20 | 4 | 4 | 0 | E1 | unchanged |
| VQI | Consistency | 20 | 4 | 4 | 0 | E2 | tables now use the kit pattern; the proposal collapse stays local |
| VQI | Typography | 15 | 4 | 4 | 0 | E1 | unchanged |
| VQI | Layout and responsiveness | 15 | 4 | 5 | +3 | E2 | 0/16 configurations scroll sideways |
| VQI | Interaction states | 10 | 4 | 4 | 0 | E1 | theme state still not shown on the button |
| VQI | Colour and contrast | 10 | 5 | 5 | 0 | E2 | unchanged |
| VQI | Whitespace and density | 10 | 4 | 4 | 0 | E1 | unchanged |
| UXQI | Task completion | 25 | 4 | 5 | +5 | E2 | T1–T4 pass at both viewports (scripted, not users) |
| UXQI | Discoverability | 15 | 4 | 4 | 0 | E1 | unchanged |
| UXQI | Predictability | 15 | 4 | 4 | 0 | E1 | theme now as the kit; the kit's app shell (facets, shortcuts) still differs |
| UXQI | Feedback | 10 | 4 | 4 | 0 | E1 | unchanged |
| UXQI | Error prevention and recovery | 10 | 4 | 4 | 0 | E1 | unchanged |
| UXQI | Accessibility | 15 | 4 | 4 | 0 | E2 | axe 0/16, keyboard T1–T3; no screen reader run |
| UXQI | Perceived performance | 10 | 5 | 5 | 0 | E3 | unchanged |

| Index | Before | After | Δ points | Coverage |
|---|---:|---:|---:|---:|
| DQI | 71 | 89 | +18 | 100 % |
| AQI | 76 | 86 | +10 | 100 % |
| VQI | 82 | 85 | +3 | 100 % |
| UXQI | 82 | 87 | +5 | 100 % |
| **SQI** | **77.75** | **86.75** | **+9.00** | |

Not verified: screen-reader use, 200 % zoom, real-user task success, the
kit's own Chrome PDF path in this container (it timed out before and after the
changes; the printed layout was compared with Playwright instead).
