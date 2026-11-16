# Findings file — the single source for every output

**Read when:** REVIEW, before a unit writes its first fragment; PLAN, before
recording `depends_on` and `plan`; REPORT, before producing the dashboard and
the report. **Reader:** the agent running the skill.

`findings.json` holds every recorded fact; the dashboard, `report.md` and the
chat summary are views of it. Enum values (severities, rollouts, efforts,
confidences, verdicts, statuses, perspective names, remedy names) stay in
English in both languages. Labels and headings follow `meta.lang`.

Render and check with (paths relative to this skill's directory):

```
python3 scripts/findings.py renumber <out>/findings.json
python3 scripts/render.py <out>/findings.json --out <out>
python3 scripts/findings.py check <out> --repo <checkout> [--allow NAME]
```

`render.py` writes `<out>/dashboard.html` (self-contained, offline, styled by
the vendored `scripts/scan_report_kit/`: counts, a priority queue, the plan as
ordered batches, a findings register filterable by severity, rollout, effort,
confidence, perspective, status, verdict and text, the data rule ledger,
perspective coverage, a copy-for-LLM button per finding) and `<out>/report.md`.
It refuses an `<out>` or an output file that is a symlink: a write follows the
link, so a planted one would land outside the run.
Recorded text is shown as written: locations and commands stay literal, and
prose keeps only `*emphasis*` and code spans, never Markdown blocks, links or
`_` emphasis (`__init__` stays `__init__`); bidirectional controls are shown
visibly. The record must be a regular file (render reads it twice, once
under the lock). Both files are staged, then each replaces its old one
atomically. `render.py` exits `0` when written, `1` when an output or its
closing line on stdout could not be written and `2` when the record does not
read or match the schema, or the command line is wrong.

## Writing the file

Build `findings.json` from fragments, never from a heredoc or a generated
script:

```
# file-write tool: <scratch>/frag-001.json = {"meta": {...}, "conventions": [...], "findings": [...]}
python3 scripts/findings.py merge <out>/findings.json <scratch>/frag-001.json
```

Merge semantics (merge refuses a fragment whose fields break the shapes in
*Field rules*; the rules that span fields or records, such as enforcement agreeing
with itself, `rollout_reason` on `Staged` and `Downtime` findings, `verify:` in steps, exposure, invariants and a plan batch for
Medium and above, are `check`'s, so a record may be incomplete while it is being built):

- Unknown keys in a finding, `validation`, `enforcement`, `analysis`, a reference,
  a convention, a perspective or a plan batch are refused; `meta` accepts
  extra keys
- `meta` updates key by key
- `findings` and `conventions` match by `id`: a known record updates key by
  key, a new one is appended. Nested objects (`validation`, `enforcement`,
  `analysis`) and lists (`invariants`, `steps`, `depends_on`) replace whole
- `perspectives` match by `name` and replace the whole entry
- `plan` matches by `batch` number and replaces the whole entry
- `checked_ok`, `decisions`, `limitations` and `next_steps` append without
  duplicates
- A complete finding sent with an ID that already holds a finding with a
  different `title` or `location` is refused as an ID collision, and so is a
  partial one that changes both; each unit numbers in its own block
  (`F-101`…, `F-201`…; past nine units, wait until no unit is running, merge
  and `renumber`, then hand out the free hundreds above the last ID, as
  `SKILL.md` says)
- A new ID whose `title` and `location` match a recorded finding is refused,
  unless one of the two is `NotApplicable` with evidence that is only the
  duplicate statement naming the other (`Duplicate of F-004`, `重複: F-004。`,
  as `check` reads it), or both are such duplicates of the same finding:
  it is usually a fragment written before `renumber`, which would record the
  finding twice. Rewrite the fragment with the ID `renumber` printed
- Parallel reviewers may merge at once: `merge`, `renumber`, `render.py` and
  `check` on one output directory take turns on a lock on that directory (a
  waiting one says so on stderr; render reads the record under the output
  directory's lock, so keep the record there). A directory that is writable
  but not readable cannot be locked and is refused. Windows has no such lock:
  merge one at a time there

## Correcting the record

Never edit `findings.json` by hand; every correction is a fragment. `null`
removes an optional key; `{"remove": {"next_steps": ["…"]}}` deletes a list
item (the fragment's own items take its place); `{"remove": {"conventions":
["C-05"]}}` deletes a ledger entry (a convention sent with that ID in the same
fragment must then be complete) and `{"remove": {"plan": [3]}}` a batch. A
finding is never removed: a wrong one is marked `FalsePositive`, a duplicate
`NotApplicable`. When `check` fails: correct with a fragment, `renumber` if a
finding was added, regraded, excluded or given a new first location, render,
check again.

## Numbering

`renumber` sorts findings by severity, then by the path and line of their
first location, excluded verdicts last, and renames them `F-001`… without
gaps. It rewrites every whole-word mention of an old ID in prose, in
`depends_on` and in `plan[].findings`; literal values (`meta`, `location`,
`enforcement.sites`, reference `url`, `analysis.command`, convention `source`)
keep theirs, and so does a URL in prose, up to an ID right after hiragana
(`…/issues/7でF-002を`, where Japanese prose follows the URL). After a
renumber, use only the new IDs it printed.

## Shape

```json
{
  "meta": {
    "project": "acme-shop",
    "scope": "app/ and db/; core tables: orders, customers, wallets",
    "commit": "3f2a9c1",
    "date": "2026-10-15",
    "assessor": "Claude Code (<model>)",
    "method": "Static review; git log 12 months",
    "window": "2025-10-15..2026-10-15",
    "lang": "en"
  },
  "conventions": [
    {"id": "C-01", "idiom": "Money columns are decimal(12,2), never float",
     "source": "majority: 9 of 9 money columns; db/schema.rb:40", "concern": "TYPES",
     "inferred": true, "status": "holds"}
  ],
  "findings": [
    {
      "id": "F-001",
      "title": "orders.customer_id has no foreign key, and two fixes already repaired orphaned orders",
      "severity": "High",
      "rollout": "Staged",
      "effort": "M",
      "confidence": "Confirmed",
      "category": "Schema constraints",
      "step": "SC2",
      "hazard": "Orders can reference a customer that no longer exists",
      "remedy": "Add Foreign Key",
      "location": ["app/admin/customers_controller.rb:42", "db/schema.rb:88"],
      "scenario": "An admin deletes a customer with orders; the delete skips model callbacks",
      "blast_radius": "orders and customers; invoicing reads both",
      "trace": "1. db/schema.rb:88 has no foreign key on orders.customer_id. 2. app/models/order.rb:8 checks it only on save through the model. 3. customers_controller.rb:42 calls delete_all. 4. Fixes 9c1d2e4 and 5b7a0f3 repaired orphaned orders by hand",
      "impact": "Orders whose customer is gone break invoicing and drop out of revenue reports",
      "exposure": "Core table orders; 3 writers of customer_id; fixes 9c1d2e4 and 5b7a0f3 patched orphaned rows in the window",
      "enforcement": {"net": "partial", "sites": ["app/models/order.rb:8"],
                      "gaps": "Only the model checks it; delete_all and raw SQL bypass it, and the schema has no constraint"},
      "rollout_reason": "Orphaned orders already exist, so the key cannot be validated until they are cleaned",
      "invariants": [
        "Every orders.customer_id references an existing customers.id",
        "Deleting a customer who has orders is refused by the database"
      ],
      "steps": [
        "1. List orphaned orders with a read-only query and decide their owner (verify: the count on a staging copy matches the report)",
        "2. Add the foreign key as NOT VALID (verify: the migration takes under a second on a staging copy; an order for a missing customer is refused)",
        "3. VALIDATE CONSTRAINT in a later migration (verify: validation passes on a staging copy while orders stay writable)"
      ],
      "depends_on": [],
      "fix": "Clean the orphans, then add the foreign key in two migrations: NOT VALID, then VALIDATE",
      "validation": {"verdict": "Valid", "method": "static",
                     "evidence": "db/schema.rb:88 has no add_foreign_key for orders; customers_controller.rb:42 calls delete_all; git show 9c1d2e4 5b7a0f3 updates orders with missing customers"},
      "status": "Open"
    }
  ],
  "plan": [
    {"batch": 1, "title": "Foreign key on orders.customer_id", "findings": ["F-001"],
     "prerequisite": "Decide who owns the orphaned orders",
     "pr_title": "db: foreign key from orders to customers, added NOT VALID then validated"}
  ],
  "perspectives": [
    {"name": "Schema constraints", "status": "applied", "note": "SC1-SC3 applied; SC2 found F-001"}
  ],
  "checked_ok": ["app/services/orders/place.rb:21-64: order, lines and payment are written in one transaction"],
  "decisions": ["Who owns the orders orphaned before F-001 is fixed?",
                "Confirm C-01 (money as decimal(12,2)) as the intended rule"],
  "limitations": ["No database was connected; table sizes come from docs/ops/capacity.md"],
  "next_steps": ["Batch 1 first; hand templates/plan.en.md to coding-implement"]
}
```

## Field rules

| Field | Rule |
|---|---|
| `meta.project`, `scope`, `date`, `assessor`, `lang` | Required for `check` and `render`; `lang` is `ja` or `en`. `commit` is the assessed revision (`git rev-parse --short HEAD`). `window` is the history window used for every exposure claim; both are required once a non-excluded finding is `Confirmed` |
| `findings[].id` | `F-001`…, gapless, severity order, then path and line of the first location, excluded verdicts last: the order `renumber` gives |
| `severity` | `High`, `Medium`, `Low`, `Info` — exposure (`SKILL.md`) |
| `rollout` | `Online`, `Staged`, `Downtime` (`SKILL.md`); required from the first fragment, so REVIEW records its best estimate and VERIFY corrects it (`reference/validation.md`) |
| `effort` | `S`, `M`, `L` (`reference/plan.md` §3); REVIEW estimates it and PLAN corrects it |
| `confidence` | `Confirmed`, `Environment-dependent`, `Suspected`; a non-excluded High finding is `Confirmed` |
| `category`, `step` | A perspective name from `reference/perspectives.md`, exactly; optional step ID whose two-letter prefix belongs to that perspective and exists there |
| `hazard` | Required nonblank: what can go wrong to the data, in one phrase |
| `remedy` | Required: one name from `reference/remedies.md`, exactly |
| `location` | `path:line` or `path:start-end` (no column), or a list of them; the write path, migration or schema line where the hazard lives; the path is relative to the repository root, `/`-separated, without `..`, and names a file, never a directory ending in `/` or `/.` (an absolute path would pass only on the author's machine) |
| `title`, `scenario`, `blast_radius`, `trace`, `impact`, `fix` | Required nonblank strings |
| `exposure` | Required nonblank for High and Medium: the core table, the write paths that reach it, fix commits by hash that patched its data, the table's size where the repository or a requester export records it, the deploy order |
| `enforcement` | Required for High and Medium: `{net, sites, gaps}` — what enforces the invariant today. `net` is `enforced` (a database constraint, or the single writer, enforces it), `partial` (some write paths, or only application-side checks) or `none`; `sites` a list of `path:line` (empty only when `net` is `none`; a constraint in a migration or schema file, a validation, a lock); `gaps` a nonblank string: where the invariant is not enforced (`none` when nothing is missing), never why the fix needs stages or a window |
| `rollout_reason` | Required nonblank for a non-excluded `Staged` or `Downtime` finding, optional for `Online`: what forces the staging or the window — the engine behaviour, the deploy order or the rows to clean ("rewrites audit_events under an exclusive lock; minutes at its size"). When present at any rollout it is a nonblank string |
| `invariants` | Required nonempty list for High and Medium: each item one statement of a data invariant that must hold ("every order references an existing customer", "balance never goes below zero") |
| `steps` | Required nonempty list for High and Medium; each item of a non-excluded finding, at any severity, contains `verify:` |
| `depends_on` | Optional list of finding IDs; each exists, is not excluded, and the graph has no cycle; an excluded finding has none |
| `convention` | Optional: the ledger ID(s) the finding cites (`C-01, C-03`) |
| `references` | Optional list of `{url, title}`; `url` nonblank, `title` optional. `report.md` links web URLs and relative paths, the dashboard web URLs only; any other scheme is shown as text |
| `validation` | `{verdict, method, evidence}` as in `reference/validation.md`; `analysed` requires `analysis {tool, command, result}` |
| `status` | `Open` (default), `Fixed`, `Accepted` (`reference/validation.md`, *Proving an invariant*); an `Accepted` finding's ID appears in `decisions` |
| `conventions[]` | `id` (`C-01`…), `idiom` (the rule), `source`, `status` (`holds`, `drifted`, `partly read`, `not checked`); optional `concern` from `reference/conventions.md` §2, `inferred` (an inferred entry's ID appears in `decisions`, for a person to confirm), `reason` (required for `not checked`; `check` fails it on `holds` and `drifted`) |
| `plan[]` | `batch` (1… gapless, in order), `title`, `findings` (IDs), `prerequisite`, `pr_title`. Each finding appears in at most one batch, in the same batch as each open `depends_on` or a later one; an excluded finding is in none |
| `perspectives[]` | `name`, `status` (`applied`, `N/A`, `not checked`), `note` |
| `checked_ok`, `limitations` | Required nonempty; `decisions`, `next_steps` optional |

## What `check` enforces

Exactly the three output files; the schema above; gapless `F-NNN` IDs in
`renumber`'s order; every perspective recorded; every non-excluded finding under an
`applied` perspective; and, for non-excluded findings only: High and Medium
findings with a verdict other than `Unverified`, evidence, `exposure`,
`enforcement`, `invariants` and `steps`; every High `Confirmed`; `meta.window` and
`meta.commit` once a finding is `Confirmed`; every `Accepted` finding named in
`decisions`; `verify:` in every step of a non-excluded finding; `Valid`,
`FalsePositive` and `NotApplicable` evidence citing `path:line` (a duplicate
may instead name the kept finding it repeats); `enforcement.sites` listed exactly
when `enforcement.net` is not `none`; `rollout_reason` on every `Staged` and
`Downtime` finding; cited conventions that exist (a `Valid` finding cites
only `drifted` ones, a `Likely` one only `drifted` or `partly read` ones),
every `drifted` convention cited by a `Valid` or `Likely` finding and every
`inferred` one named in `decisions`; `depends_on` acyclic and resolvable, and
absent on excluded findings; every open, non-excluded Medium-or-higher finding
in exactly one plan batch, each open dependency of a planned finding in an
earlier batch or listed before it in its own, a `Downtime` finding alone in
its batch, and no excluded finding in a batch; and `dashboard.html` and
`report.md` byte-identical to a fresh render in `meta.lang`. With `--repo`,
every `location` and `enforcement.sites` entry exists in the checkout. It checks
shape and consistency, not whether a finding is true.
