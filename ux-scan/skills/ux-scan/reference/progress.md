# Progress

**Read when:** CHECKLIST (the coverage plan from the inventory), at the end of each review unit, and before REPORT — to see what the run contract and *Done when* still ask for.

```sh
python3 <skill-dir>/scripts/progress.py <out> [--lang ja|en] [--format json] [--out <scratch>/progress.md] [--strict]
```

It reads `<out>/flows.json`, `<out>/inventory.json` and `<out>/findings.json` as far as
they exist, so it runs from the first FLOWS fragment on: none is required, and merged
findings may still be unordered or `Unverified`. It writes to standard output unless `--out`
names a file, never a review output, and changes nothing. `--strict` exits 1 while a to-do
remains, for a host that loops until the review is complete.

## What it lists

Each review unit in task order (primary flows, the `shared` unit, secondary flows), with its
finding count and undecided candidates, then the to-dos by kind, then a *Next* step:

| Kind | A to-do while |
|---|---|
| `records` | `flows.json` or `inventory.json` is missing, the inventory predates the current flows (`flows_sha256`), or no finding is merged yet |
| `candidates` | An inventory candidate is undecided (below), listed under the unit that owns its file with the hunt steps it feeds (`AX2`, `FM1, FM4`…) |
| `units` | A flow has no finding and its id appears in no `perspectives` entry, `checked_ok` or `limitations` line (*Done when*: every flow reviewed, or named in `limitations`) |
| `perspectives` | A family has no `perspectives` entry with a result |
| `findings` | A verdict is `Unverified`; an included finding has no `before` evidence, a `Fixed` one no `after` evidence; a cited file is not in `evidence/`, or a file there is cited by none; a mockup has no tiers and neither its `note` nor `limitations` says why; ids are not yet in severity order (`findings.py renumber`) |

It also lists, **to confirm** rather than to do, `Valid` or `Likely` High and Medium
findings with no mockup and no mention in `limitations`: only a finding a user can see needs
one, and that is a judgement. When no to-do is left, it says so: render, then run
`contract_check.py`, which remains the only gate.

## Deciding a candidate

A candidate is a row `inventory.py` flags (`reference/inventory.md`): an orphan route, an
off-scale value, a fixed width wider than the smallest viewport, a small tap target, a removed
outline with no replacement in its rule, a zoom lock, a click handler, image, input or icon
button with something missing, a positive tabindex, a missing state branch, a destructive
action, motion with no reduced-motion path anywhere, truncation, a physical property under a
right-to-left locale, or a wide locale string. Raw `spacing`, `font_sizes`, `breakpoints` and
`z_index` rows are not candidates; their `off_scale` rows are.

Each is decided once REVIEW has read it in context and the record says so:

- a finding (any verdict, `FalsePositive` and `NotApplicable` included) whose `location` or
  `occurrences` covers its `path:line`; for `state_branches`, which are about a whole file, any
  `FB`, `PP` or `ST` finding in that file
- or a line naming that `path:line` (a trailing part of the path is enough: `app.css:12`) in a
  finding's `validation`, `observed`, `expected`, `impact` or `fix`, or in `checked_ok`,
  `limitations`, `decisions` or `next_steps`; an orphan route is also decided by naming the
  route, a wide locale string by naming its key

So a candidate that holds up is closed with a `checked_ok` line that says why, such as
`"app.css:4 .btn:focus: a :focus-visible rule in base.css restores the ring."`, not left open.
The inventory keeps at most five locations a row (`reference/inventory.md` *Caps*): a row's
other occurrences are still to be found with a search.
