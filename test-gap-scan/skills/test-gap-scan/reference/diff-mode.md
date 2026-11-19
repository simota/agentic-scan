# Diff mode — review only what a change touches

**Read when:** the requester asks to review only a diff: a branch against its
base, a pull request, a commit range or uncommitted changes. **Reader:** the
agent running the skill. **Decision it supports:** which code the review units
cover and which findings belong to the change.

A diff-scoped run is the same review on a smaller surface: the same phases,
outputs and contract, with the units cut down to what the change touches. It is
not a full assessment, and its record says so.

## 1. Resolve the change

```sh
python3 scripts/diffscope.py scope <repo> --base <base> --out <scratch>/diff.json
```

| Request | Arguments |
|---|---|
| This branch against its base | `--base <base branch>` (default: `origin/HEAD`, then `main`, then `master`) |
| A commit range `A..B` or `A...B` | `--base A --head B` (the diff is always taken from the merge base, as a pull request shows it) |
| A pull request | Its base branch as `--base` and its head commit as `--head`; fetching the head is the requester's step when it is not local |
| Uncommitted work | `--worktree` (staged, unstaged and untracked files) |
| Only part of the change | `--path <pathspec>`, repeatable |

It writes each changed file with its status (`added`, `modified`, `deleted`,
`renamed`, `copied`, `typechange`, `untracked`), the changed line ranges on the
new side (`changed`) and where lines were removed (`removed_at`), and prints the
scope line. An empty diff ends the run: say so and stop. Generated, vendored
and lock-only changes stay out of scope as in a full run.

## 2. Cut the units

- Each unit is the normal unit for this skill, restricted to the changed files
  in it; a unit with no changed file is dropped.
- Read what each changed line needs to be judged: its callers and callees, the
  module or table it belongs to, the tests and configuration that reach it.
  That context is read, not reviewed for its own sake.
- Keep the cross-cutting unit only where the diff touches it.
- Deleted and renamed files: check what still refers to the old path or the
  removed code.

## 3. Decide what counts

A finding belongs to the change when its fix location is on a changed line, or
when the change creates, exposes or worsens it elsewhere (a new caller of an
existing unbounded query, a removed guard that left an old route open). Check
each finding before merging it:

```sh
python3 scripts/diffscope.py locate <scratch>/diff.json <path:line>...
```

| Verdict | Means | Keep it when |
|---|---|---|
| `changed` | On a changed line (`--near N` allows N lines of slack) | Always |
| `file` | In a changed file, on an unchanged line | Its evidence names the changed line that causes or exposes it |
| `outside` | In a file the diff does not touch | Its evidence names the changed line that causes or exposes it |
| `deleted` | In a file the diff deletes | Never as a location: place it where the removed code is still referenced |

A pre-existing defect the change neither causes nor worsens is not a finding of
this run. Name it in the chat summary as pre-existing, at most a few lines, and
suggest a full run for it.

## 4. What the diff reaches in this skill

- Behaviour the diff changes whose tests did not change.
- Tests the diff deletes, skips, weakens or re-mocks.
- Critical flows that run through changed code, and what their tests assert there.
- CI configuration the diff changes, and whether the suite still runs.

## 5. Record it

- `meta.scope`: the scope line `diffscope.py scope` printed.
- `meta.method`: the skill's usual method, followed by "; scoped to the diff".
- `limitations`: "Diff mode: reviewed the N changed files and the code they
  reach; unchanged code was read only as context. Not a full assessment."
  Add the files left out (generated, vendored, binary) by name.
- A perspective the diff does not reach is marked the way this skill marks a
  perspective outside a requested scope, with the note "outside the diff".
- Comparison: a diff-scoped record is not a baseline for a full assessment.
  `scripts/compare.py` across the two can count findings outside the diff as
  resolved; do not compare them.
