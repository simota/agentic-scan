# Removal plan

**Read when:** the requester asks for a removal plan, a checklist of the work
or issues to file, or makes the later request to remove what a review found.

```sh
python3 <skill-dir>/scripts/plan.py <out>/findings.json [--unit UN-01]... \
    --out <scratch>/removal-plan.md [--json <scratch>/removal-plan.json] [--lang ja|en]
```

`<skill-dir>` is the directory holding SKILL.md (SKILL.md *Paths*).

The review never deletes anything; removal is a later, separate request. The
plan connects the two. It reads the settled record (after VERIFY and
`renumber`) and `units.json` beside it, and writes a Markdown checklist and,
with `--json`, the same plan for an agent. It changes nothing in the record or
the repository. Write it to scratch, or into the output directory and pass
`--allow removal-plan.md` (and the JSON name) to `scripts/contract_check.py`.

## What it holds

| Section | Holds |
|---|---|
| Remove now | One checkbox step per open `Valid` finding with action `remove`: what to delete, what remains, what is lost, the risk, every file it touches (`location` and `occurrences`), its unit |
| Reduce or consolidate | The same for `reduce` and `consolidate` |
| Waits for a decision | Steps whose prerequisite is still to decide, is kept (`Accepted`, `Unlikely`, ruled out) or is part of an ordering cycle, each with the reason |
| Decide with a human first | Every other open, counted finding, with the record's `decisions` lines that name it (else its risk) and the steps it unblocks |
| Files several steps touch | Files that more than one step changes, so those steps can land in one change or be ordered to avoid conflicts |
| After the removals | Commit per step, run the app's own tests, re-run the inventory, then the follow-up review (`reference/follow-up.md`) |

## How it orders

Steps follow the record's severity order, remove-now before reduce. Prose in a
finding's `risk` or `subtraction` decides the rest, read the way `renumber` reads
references (paths and filenames shaped like ids stay literal):

| Prose | Effect |
|---|---|
| `after P-010`, `once P-010`, `until P-010`; `P-010 の後`, `P-010 より後`, `P-010 を先に` | The step comes after P-010. If P-010 is still to decide, or kept, the step waits for a decision. A remove step after a reduce step moves to the later wave |
| `with P-003`, `goes with P-003`; `P-003 と併せて`, `P-024 の移行で併せて` | Shown as *coordinate with*, marked when that finding is still to decide; the order is unchanged |
| any other `P-…` reference | Shown as *see also* |

So the order you need must be in the record: when one subtraction must follow
another, say so in its `risk` ("Remove after P-010, or the old branch fails to
compile") before rendering. A `Fixed` prerequisite is satisfied.

## Use

- `--unit` plans one area at a time (one change per unit); a prerequisite in
  another unit is still named (*first, outside the selected units*)
- the header names the record's SHA-256; regenerate the plan after any merge
- in the removal request, work the plan from the top. Tick each step as it
  lands, and stop at "Waits for a decision": those steps need the human answer
  first
