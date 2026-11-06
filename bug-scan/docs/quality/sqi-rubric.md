# SQI rubric for bug-scan

Fixed before any improvement work. Before and after are scored with this file and `audit.py` unchanged. SQI is
a rubric, not a physical measurement, and no real user took part: a score says how the artefact meets the anchors
below, not that anyone became happier or faster.

## Scope

| Item | Choice |
|---|---|
| Design and architecture targets | `skills/bug-scan/scripts/*.py`, `tests/`, `Makefile`, skill docs |
| Visual and UX targets | The generated `dashboard.html` and `report.html`: the only screens this product has |
| Vendored kit | `scripts/scan_report_kit/` is pinned by `MANIFEST` ("change it upstream and re-vendor"). The user sees it, so it is scored, but it is not edited here |
| Conditions | `examples/*.sample.json`; ja and en; viewports 1440×900, 768×1024, 390×844; light and dark; Chromium via Playwright; `file://` |
| Weights | SQI = 0.25 each for DQI, AQI, VQI, UXQI |
| Tasks | T1 open the first-priority defect; T2 go from a defect in a figure to its record; T3 reach the register; T4 filter to High; T5 read a figure's facts by keyboard only |

Evidence levels: E0 none (reported as 未検証, never scored), E1 reading code or screens, E2 reproducible script or
test, E3 real-use measurement. Measured values come from `audit.py` and are kept apart from scores.

Each item is 0 to 5. Domain score = Σ(weight × score ÷ 5). Half points are not used. A level requires everything
named in it, and a level's named defect caps the item at the level below.

## DQI: software design

| Item | Weight | 1 | 2 | 3 | 4 | 5 |
|---|---:|---|---|---|---|---|
| Responsibility split | 20 | Unrelated work mixed throughout | Layers exist; rules duplicated in 3+ modules | Each module has one purpose; at most 2 duplicated rules | No duplicated domain rule; figures separate data from drawing where it pays | Plus each rule has one owner proved by a test |
| Cohesion | 15 | Grab-bag modules | Several misplaced helpers | Misplaced helpers at most 3 | At most 1, no dead parameters | None, and public surface is minimal |
| Interface and contract clarity | 15 | Implicit shapes | Shapes checked only partly; malformed input crashes | Shapes documented and checked at merge; malformed input may still crash in places | Malformed input in the audit corpus always gives a named error | Plus the same rule set guards every entry point |
| Changeability | 15 | Any change touches most files | A scenario touches 5+ files | Scenarios touch at most 4 files | At most 3, no shotgun literals | At most 2, proved by a change scenario in a test |
| Readability | 10 | Hard to follow | Long functions with no structure | Clear names; C901 count over 10 | C901 at most 10 and no ambiguous names | At most 5 |
| Testability | 15 | No tests | Happy paths only | Pure functions and offline fixtures; error paths covered in part | Line coverage ≥ 80% of own code; malformed input and concurrency tested | ≥ 90% with mutation-style proof of key rules |
| Invariants and error handling | 10 | Errors swallowed | Tracebacks common | Atomic writes and strict JSON, but a crash or lost write can be provoked | The audit corpus gives no traceback and no lost update | Plus invariants hold under fault injection |

## AQI: architecture

| Item | Weight | 1 | 2 | 3 | 4 | 5 |
|---|---:|---|---|---|---|---|
| Module boundaries and direction | 20 | Cycles | Layering ignored in places | No cycles; one-way imports with small exceptions | No cycles; vendored kit boundary machine-checked and unbroken; no layer bypass | Plus boundary rule enforced by a test |
| Layers and data flow | 15 | Tangled | Flow readable; figures recompute record rules | One record drives all outputs; some rules re-derived in the view | No domain rule re-derived in a view | Plus every output reproducible and verified from the record |
| Change locality | 15 | Global | 5+ modules per scenario | At most 4 | At most 3 for the four scenarios in `audit.py` notes | At most 2 |
| Contracts and data integrity | 15 | None | Written but unenforced | Contract check exists; figure and table can disagree or drop facts silently | No silent drop; concurrent merge keeps every update | Plus cross-file references checked before any output |
| Failure tolerance | 10 | Partial writes | Atomic writes; crashes on bad input | Failed runs keep the previous record | Plus bad input exits with a named code at every CLI | Plus fault injection |
| Security and privacy boundary | 10 | Absent | Partial | Git hardened, outputs escaped, secrets and mail refused | Plus proved by tests | Plus independent audit |
| Observability and operability | 10 | Silent | Some messages | Exit codes and `make check` | Plus limits and truncation visible in outputs | Plus CI gate running them |
| Scalability | 5 | Fails on small inputs | Quadratic hot paths on normal input | Handles the sample; limits named in code | Limits visible to the reader, measured at 10× the sample | Measured at 100× |

## VQI: visual design

| Item | Weight | 1 | 2 | 3 | 4 | 5 |
|---|---:|---|---|---|---|---|
| Hierarchy | 20 | No order | Headings exist; primary content buried | Clear headings; primary content is below secondary | Primary content first per the design; figures subordinate | Plus verified with observers |
| Consistency | 20 | Every part differs | Two visible styles side by side | One style with a few exceptions, hard-coded colours over 3 | One style; overlay uses kit tokens; hard-coded colours at most 3 | Zero, across every state |
| Typography | 15 | Unreadable | Effective text under 8px at a target viewport | Effective minimum ≥ 8px at all viewports | ≥ 10px at all viewports and no overlap at desktop | ≥ 11px and no overlap anywhere |
| Layout and responsive | 15 | Broken | Page overflows at a target viewport | No page overflow; figures shrink until unusable | No page overflow; figures keep legible scale; tables scroll | Plus zoom 200% verified |
| Interaction states | 10 | None | Hover only | Hover and most focus | Focus shown on ≥ 95% of focusable figure parts | 100%, plus selected and error states |
| Colour and contrast | 10 | Colour alone, many failures | Over 20 contrast failures | 1 to 20 failures | No AA failures in overlay; kit failures at most 3; meaning not colour-only | None anywhere, both themes |
| Spacing and density | 10 | Cluttered | Crowded in places | Regular; boxes and rules mixed | One rhythm, text inside its box everywhere at desktop | Plus at every viewport |

## UXQI: user experience

| Item | Weight | 1 | 2 | 3 | 4 | 5 |
|---|---:|---|---|---|---|---|
| Task completion and efficiency | 25 | A task cannot complete | All complete by script, with T2 needing a manual search | T2 needs no search, or register reached within 3 screens | Both, with T1 to T5 scripted | Plus real-user success rate. Without it, 4 is the ceiling |
| Discoverability and load | 15 | Hidden | Labels clear but long unstructured page | Contents reach every section in page order | Plus figures indexed and current location always correct | Plus observed |
| Predictability | 15 | Surprises | Same element behaves differently across outputs | Mostly consistent; some inert focus stops | No inert focus stops; language consistent per page | Plus observed |
| Feedback | 10 | None | Some | Counts and copy status | Plus selection and omitted data stated | Plus observed |
| Error prevention and recovery | 10 | Tracebacks | Messages for some | Named errors for most CLI cases | Every corpus case names the field | Plus a fix hint on each |
| Accessibility | 15 | Blocking failures | axe serious or critical on overlay | Overlay names missing or tab stops over 100 | No axe serious or critical, figure parts named, tab stops to register at most 40 | Plus manual screen-reader pass. Without it, 4 is the ceiling |
| Perceived performance | 10 | Over 5 s | Over 2 s load | Under 1 s load, CLS under 0.1 | Under 300 ms load, CLS under 0.05, toggle under 100 ms | Measured on a low-end device |

## Acceptance of a change

A change stays only if: tests pass, `make check` passes, no new axe serious or critical, `render.build` and page
load do not degrade beyond noise (median of repeated runs, ±20%), the record format still loads, and the rule it
targets moved on evidence. Otherwise it is dropped and named in the report.
