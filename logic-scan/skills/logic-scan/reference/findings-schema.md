# Findings file — the single source for every output

**Read when:** REVIEW, before a unit writes its first fragment; PLAN, before
recording `depends_on` and `plan`; REPORT, before producing the dashboard and
the report. **Reader:** the agent running the skill.

`findings.json` holds every recorded fact; the dashboard, `report.md` and the
chat summary are views of it. Enum values (severities, changes, efforts,
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
ordered batches, a findings register filterable by severity, change, effort,
confidence, perspective, status, verdict and text, the logic rule ledger,
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
with itself, `change_reason` on `Shared` and `Correction` findings, `verify:` in steps, exposure, a counterexample, invariants and a plan batch for
Medium and above, are `check`'s, so a record may be incomplete while it is being built):

- Unknown keys in a finding, `validation`, `counterexample`, `enforcement`, `analysis`, a reference,
  a convention, a perspective or a plan batch are refused; `meta` accepts
  extra keys
- `meta` updates key by key
- `findings` and `conventions` match by `id`: a known record updates key by
  key, a new one is appended. Nested objects (`validation`, `counterexample`,
  `enforcement`, `analysis`) and lists (`invariants`, `steps`, `depends_on`) replace whole
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
    "project": "acme-billing",
    "scope": "app/ and tests/; core flows: checkout, invoicing, subscription renewal",
    "commit": "3f2a9c1",
    "date": "2026-10-15",
    "assessor": "Claude Code (<model>)",
    "method": "Static review; git log 12 months",
    "window": "2025-10-15..2026-10-15",
    "lang": "en",
    "axis": "confirmed"
  },
  "conventions": [
    {"id": "C-01", "idiom": "Amounts are stored and passed between modules as integer yen",
     "source": "majority: 14 of 14 amount fields; app/billing/money.py:3", "concern": "NUMBERS",
     "inferred": true, "status": "holds"}
  ],
  "findings": [
    {
      "id": "F-001",
      "title": "The invoice rounds tax per line while the charge rounds it once, so the card is charged a different amount",
      "severity": "High",
      "change": "Shared",
      "effort": "M",
      "confidence": "Confirmed",
      "category": "Numbers and money",
      "step": "NM2",
      "hazard": "The amount charged differs from the invoice total by up to one yen per line",
      "remedy": "Centralise Rounding",
      "location": ["app/billing/invoice.py:42", "app/payments/charge.py:88"],
      "scenario": "Any order with several lines whose tax has a fraction",
      "blast_radius": "Checkout and renewal charge through charge.py; invoices read invoice.py",
      "trace": "1. invoice.py:42 rounds each line's tax down and sums. 2. charge.py:88 applies the rate to the sum and rounds with round(). 3. Fixes 9c1d2e4 and 5b7a0f3 refunded 1-yen differences by hand",
      "impact": "Customers are charged one yen more than their invoice says",
      "exposure": "Core flow checkout (money); 4 callers of charge.py; fixes 9c1d2e4 and 5b7a0f3 in the window",
      "counterexample": {
        "input": "One order: three lines of 333 yen each, tax rate 10%",
        "expected": "Invoice and charge both 1,098 yen",
        "actual": "Invoice 1,098 yen; charge 1,099 yen",
        "oracle": "docs/billing/tax.md:12: tax per line, rounded down"
      },
      "enforcement": {"net": "partial", "sites": ["tests/billing/test_invoice.py:30"],
                      "gaps": "The invoice test covers one-line orders only; nothing compares the charge with the invoice"},
      "change_reason": "charge.py:88 is shared with subscription renewal; renewals will charge one yen less on some invoices",
      "invariants": [
        "For every order, the amount charged equals the invoice total",
        "Tax is computed per line and rounded down, by one function every caller uses"
      ],
      "steps": [
        "1. Move per-line tax into one function called from invoice.py and charge.py, update the renewal tests that expected the old charge, and add a test: three lines of 333 yen at 10% give 1,098 yen on both (verify: the new test fails with the change reverted; the billing and renewal suites pass with it)"
      ],
      "depends_on": [],
      "fix": "One rounding function, per line and down, used by both the invoice and the charge",
      "validation": {"verdict": "Valid", "method": "static",
                     "evidence": "app/billing/invoice.py:42 floor per line; app/payments/charge.py:88 round(total * rate); git show 9c1d2e4 5b7a0f3 refund 1-yen differences"},
      "status": "Open"
    }
  ],
  "plan": [
    {"batch": 1, "title": "One rounding rule for invoice and charge", "findings": ["F-001"],
     "prerequisite": "Finance agrees that renewals may charge one yen less",
     "pr_title": "fix: round tax per line, the same way for invoice and charge"}
  ],
  "perspectives": [
    {"name": "Numbers and money", "status": "applied", "note": "NM1-NM3 applied; NM2 found F-001"}
  ],
  "checked_ok": ["app/billing/period.py:8-30: billing periods are half-open [start, end) in every reader"],
  "decisions": ["Whether renewals may charge one yen less once F-001 is fixed",
                "Confirm C-01 (amounts stored and passed as integer yen) as the intended rule"],
  "limitations": ["No test was run; counterexamples are traced by reading the code"],
  "next_steps": ["Batch 1 first; hand templates/plan.en.md to coding-implement"]
}
```

## Field rules

| Field | Rule |
|---|---|
| `meta.project`, `scope`, `date`, `assessor`, `lang` | Required for `check` and `render`; `lang` is `ja` or `en`. `axis` is required for `check`: `confirmed` when the requester confirmed the list severity is judged against, `assumed` when nobody answered; while it is `assumed`, every non-excluded High finding is named in `decisions`. `commit` is the assessed revision (`git rev-parse --short HEAD`). `window` is the history window used for every exposure claim; both are required once a non-excluded finding is `Confirmed` |
| `findings[].id` | `F-001`…, gapless, severity order, then path and line of the first location, excluded verdicts last: the order `renumber` gives |
| `severity` | `High`, `Medium`, `Low`, `Info` — exposure (`SKILL.md`) |
| `change` | `Local`, `Shared`, `Correction` (`SKILL.md`); required from the first fragment, so REVIEW records its best estimate and VERIFY corrects it (`reference/validation.md`) |
| `effort` | `S`, `M`, `L` (`reference/plan.md` §3); REVIEW estimates it and PLAN corrects it |
| `confidence` | `Confirmed`, `Environment-dependent`, `Suspected`; a non-excluded High finding is `Confirmed` |
| `category`, `step` | A perspective name from `reference/perspectives.md`, exactly; optional step ID whose two-letter prefix belongs to that perspective and exists there |
| `hazard` | Required nonblank: the defect — what result is wrong, in one phrase |
| `remedy` | Required: one name from `reference/remedies.md`, exactly |
| `location` | `path:line` or `path:start-end` (no column), or a list of them; the code that computes the wrong result; the path is relative to the repository root, `/`-separated, without `..`, and names a file, never a directory ending in `/` or `/.` (an absolute path would pass only on the author's machine) |
| `title`, `scenario`, `blast_radius`, `trace`, `impact`, `fix` | Required nonblank strings |
| `exposure` | Required nonblank for High and Medium: the core flow, the callers that reach the site, fix commits by hash that patched the same rule, records that the input occurs |
| `counterexample` | Required for High and Medium: `{input, expected, actual, oracle}`, each a nonblank string, no other keys. `input` is concrete values, not a class ("three lines of 333 yen at 10%"); `expected` the right result; `actual` the result the code gives, traced in `trace`; `oracle` where the expected result is stated (`path:line` of a spec, test, doc or other implementation, or the domain fact) |
| `enforcement` | Required for High and Medium: `{net, sites, gaps}` — what enforces the rule today. `net` is `enforced` (a type, a shared helper every site uses, or tests covering the counterexample's values enforce it), `partial` (some sites or some values only) or `none`; `sites` a list of `path:line` (empty only when `net` is `none`; a test, a type, a validation, a helper); `gaps` a nonblank string: where or for which values the rule is not enforced (`none` when nothing is missing), never why the fix reaches further |
| `change_reason` | Required nonblank for a non-excluded `Shared` or `Correction` finding, optional for `Local`: the callers whose results move (`Shared`), or the results already produced wrong (`Correction`: "reports since 2026-03 sent to finance overstated"). When present at any change it is a nonblank string |
| `invariants` | Required nonempty list for High and Medium: each item one rule that must hold, as an assertion a test could make ("the amount charged equals the invoice total", "a run at 01:00 JST on the billing day renews the subscription") |
| `steps` | Required nonempty list for High and Medium; each item of a non-excluded finding, at any severity, contains `verify:` |
| `depends_on` | Optional list of finding IDs; each exists, is not excluded, and the graph has no cycle; an excluded finding has none |
| `convention` | Optional: the ledger ID(s) the finding cites (`C-01, C-03`) |
| `references` | Optional list of `{url, title}`; `url` nonblank, `title` optional. `report.md` links web URLs and relative paths, the dashboard web URLs only; any other scheme is shown as text |
| `validation` | `{verdict, method, evidence}` as in `reference/validation.md`; `analysed` requires `analysis {tool, command, result}` |
| `status` | `Open` (default), `Fixed`, `Accepted` (`reference/validation.md`, *Reproducing a counterexample*); an `Accepted` finding's ID appears in `decisions` |
| `conventions[]` | `id` (`C-01`…), `idiom` (the rule), `source`, `status` (`holds`, `drifted`, `partly read`, `not checked`); optional `concern` from `reference/conventions.md` §2, `inferred` (an inferred entry's ID appears in `decisions`, for a person to confirm), `reason` (required for `not checked`; `check` fails it on `holds` and `drifted`) |
| `plan[]` | `batch` (1… gapless, in order), `title`, `findings` (IDs), `prerequisite`, `pr_title`. Each finding appears in at most one batch, in the same batch as each open `depends_on` or a later one; an excluded finding is in none |
| `perspectives[]` | `name`, `status` (`applied`, `N/A`, `not checked`), `note` |
| `checked_ok`, `limitations` | Required nonempty; `decisions`, `next_steps` optional |

## What `check` enforces

Exactly the three output files; the schema above; gapless `F-NNN` IDs in
`renumber`'s order; every perspective recorded; every non-excluded finding under an
`applied` perspective; and, for non-excluded findings only: High and Medium
findings with a verdict other than `Unverified`, evidence, `exposure`,
`counterexample`, `enforcement`, `invariants` and `steps`; every High `Confirmed`; `meta.window` and
`meta.commit` once a finding is `Confirmed`; every `Accepted` finding named in
`decisions`; `verify:` in every step of a non-excluded finding; `Valid`,
`FalsePositive` and `NotApplicable` evidence citing `path:line` (a duplicate
may instead name the kept finding it repeats); `enforcement.sites` listed exactly
when `enforcement.net` is not `none`; `change_reason` on every `Shared` and
`Correction` finding; cited conventions that exist (a `Valid` finding cites
only `drifted` ones, a `Likely` one only `drifted` or `partly read` ones),
every `drifted` convention cited by a `Valid` or `Likely` finding and every
`inferred` one named in `decisions`; `depends_on` acyclic and resolvable, and
absent on excluded findings; every open, non-excluded Medium-or-higher finding
in exactly one plan batch, each open dependency of a planned finding in an
earlier batch or listed before it in its own, a `Correction` finding alone in
its batch, and no excluded finding in a batch; and `dashboard.html` and
`report.md` byte-identical to a fresh render in `meta.lang`. With `--repo`,
every `location` and `enforcement.sites` entry exists in the checkout. It checks
shape and consistency, not whether a finding is true.
