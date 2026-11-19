# Findings file — the single source for every output

**Read when:** REVIEW, before a unit writes its first fragment; PLAN, before
recording `depends_on` and `plan`; REPORT, before producing the dashboard and
the report. **Reader:** the agent running the skill.

`findings.json` holds every recorded fact; the dashboard, `report.md` and the
chat summary are views of it. Enum values (severities, testabilities, efforts,
confidences, verdicts, statuses, perspective names, remedy names) stay in
English in both languages. Labels and headings follow `meta.lang`.

Render and check with (paths relative to this skill's directory):

```
python3 scripts/findings.py renumber <out>/findings.json
python3 scripts/render.py <out>/findings.json --out <out>
python3 scripts/findings.py check <out> --repo <checkout> [--allow NAME]
```

`render.py` writes `<out>/dashboard.html` (self-contained, offline, styled by
`scripts/report_assets/dashboard.css`: counts, a priority queue, the plan as
ordered batches, a findings register filterable by severity, testability, effort,
confidence, perspective, status, verdict and text, the test idiom ledger,
perspective coverage, a copy-for-LLM button per finding), `<out>/assessment.html`
(printable triage report) and `<out>/report.md`.
It refuses an `<out>` or an output file that is a symlink: a write follows the
link, so a planted one would land outside the run.
Recorded text is shown as written: locations and commands stay literal, and
prose keeps only `*emphasis*` and code spans, never Markdown blocks, links or
`_` emphasis (`__init__` stays `__init__`); bidirectional controls are shown
visibly. The record must be a regular file (render reads it twice, once
under the lock). All report files are staged, then each replaces its old one
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
*Field rules*; the rules that span fields or records, such as coverage agreeing
with testability, `verify:` in steps, exposure, asserts and a plan batch for
Medium and above, are `check`'s, so a record may be incomplete while it is being built):

- Unknown keys in a finding, `validation`, `coverage`, `analysis`, a reference,
  a convention, a perspective or a plan batch are refused; `meta` accepts
  extra keys
- `meta` updates key by key
- `findings` and `conventions` match by `id`: a known record updates key by
  key, a new one is appended. Nested objects (`validation`, `coverage`,
  `analysis`) and lists (`asserts`, `steps`, `depends_on`) replace whole
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
`coverage.tests`, reference `url`, `analysis.command`, convention `source`)
keep theirs, and so does a URL in prose, up to an ID right after hiragana
(`…/issues/7でF-002を`, where Japanese prose follows the URL). After a
renumber, use only the new IDs it printed.

## Shape

```json
{
  "meta": {
    "project": "acme-shop",
    "scope": "api/ and worker/; critical flows: checkout, refunds",
    "commit": "3f2a9c1",
    "date": "2026-10-15",
    "assessor": "Claude Code (<model>)",
    "method": "Static review; git log 12 months",
    "window": "2025-10-15..2026-10-15",
    "lang": "en",
    "axis": "confirmed"
  },
  "conventions": [
    {"id": "C-01", "idiom": "Time is frozen with the frozen_clock fixture",
     "source": "majority: 23 of 25 time-dependent tests; tests/conftest.py:12", "concern": "CLOCK",
     "inferred": true, "status": "holds"}
  ],
  "findings": [
    {
      "id": "F-001",
      "title": "B2B line refunds have no test, and two refund fixes shipped without one",
      "severity": "High",
      "testability": "Seam",
      "effort": "M",
      "confidence": "Confirmed",
      "category": "Untested critical paths",
      "step": "UC1",
      "gap": "Line-refund branch unreached by any test",
      "remedy": "Add Behaviour Test",
      "location": "api/refunds/b2b.py:61-104",
      "scenario": "Refunds are a named critical flow; line refunds are 30% of B2B refunds",
      "blast_radius": "1 file; every B2B line refund",
      "trace": "1. b2b.py:61 splits whole-order and line refunds. 2. tests/test_refunds.py:12 refunds a whole retail order only. 3. Fixes a1b2c3d and d4e5f6a changed b2b.py:80-97 and no test",
      "impact": "A wrong refund amount reaches customers and the ledger without a test failing",
      "exposure": "Critical flow (refunds); fixes a1b2c3d, d4e5f6a changed b2b.py with no test change; 12 commits in the window",
      "coverage": {"net": "partial", "tests": ["tests/test_refunds.py:12"],
                   "gaps": "No test reaches b2b.py; b2b.py:64 constructs PaymentGateway() inline"},
      "asserts": [
        "a refund of 2 of 5 lines refunds the sum of those lines as rounded today (half-up, b2b.py:97)",
        "the gateway receives exactly one refund call with that amount",
        "a refund above the captured amount raises RefundExceedsCapture and calls no gateway"
      ],
      "steps": [
        "1. Pass the gateway into refund_b2b() as a parameter defaulting to PaymentGateway() (verify: tests/test_refunds.py green)",
        "2. Add the line-refund tests with a fake gateway (verify: they fail when b2b.py:97 rounds half-even, green otherwise)"
      ],
      "depends_on": [],
      "fix": "Behaviour tests for B2B line refunds through refund_b2b(), after a gateway seam",
      "validation": {"verdict": "Valid", "method": "static",
                     "evidence": "b2b.py:61-104 is imported only by api/routes/refunds.py:30; no test imports either; git show --stat a1b2c3d d4e5f6a lists no test file"},
      "status": "Open"
    }
  ],
  "plan": [
    {"batch": 1, "title": "Test B2B line refunds", "findings": ["F-001"],
     "prerequisite": "none",
     "pr_title": "test: B2B line refunds through refund_b2b()"}
  ],
  "perspectives": [
    {"name": "Untested critical paths", "status": "applied", "note": "UC1-UC3 applied; UC1 found F-001"}
  ],
  "checked_ok": ["api/payments/charge.py: tests/test_charge.py:10-88 assert amount, currency and idempotency key"],
  "decisions": ["Should B2B line refunds round half-even like retail? The tests in F-001 pin today's half-up",
                "Confirm C-01 (frozen_clock fixture) as the intended idiom"],
  "limitations": ["Tests were not run; coverage is judged from reading the tests"],
  "next_steps": ["Batch 1 first; hand templates/plan.en.md to whoever writes the tests"]
}
```

## Field rules

| Field | Rule |
|---|---|
| `meta.project`, `scope`, `date`, `assessor`, `lang` | Required for `check` and `render`; `lang` is `ja` or `en`. `axis` is required for `check`: `confirmed` when the requester confirmed the list severity is judged against, `assumed` when nobody answered; while it is `assumed`, every non-excluded High finding is named in `decisions`. `commit` is the assessed revision (`git rev-parse --short HEAD`), required once a non-excluded finding is `Confirmed`. `window` is the history window used for every exposure claim, required once the `exposure` of a non-excluded `Confirmed` finding cites history: a commit hash (7 to 40 lowercase hex characters with at least one digit and one letter, `a1b2c3d`) or the word `commit`, `commits` or `コミット`. A `Confirmed` finding resting on a named critical flow and a traced skipped, flaky or empty test, with no history cited, needs no `window` |
| `findings[].id` | `F-001`…, gapless, severity order, then path and line of the first location, excluded verdicts last: the order `renumber` gives |
| `severity` | `High`, `Medium`, `Low`, `Info` — exposure (`SKILL.md`) |
| `testability` | `Direct`, `Seam`, `Restructure` (`SKILL.md`); required from the first fragment, so REVIEW records its best estimate and VERIFY corrects it (`reference/validation.md`). A `Restructure` finding is the production restructuring alone; the finding that adds the tests `depends_on` it and records the testability it has once that is done |
| `effort` | `S`, `M`, `L` (`reference/plan.md` §3); REVIEW estimates it and PLAN corrects it |
| `confidence` | `Confirmed`, `Environment-dependent`, `Suspected`; a non-excluded High finding is `Confirmed` |
| `category`, `step` | A perspective name from `reference/perspectives.md`, exactly; optional step ID whose two-letter prefix belongs to that perspective and exists there |
| `gap` | Required nonblank: the test gap's name |
| `remedy` | Required: one name from `reference/remedies.md`, exactly |
| `location` | `path:line` or `path:start-end` (no column), or a list of them; the production code the gap leaves unchecked, or the test itself for a test-quality gap; the path is relative to the repository root, `/`-separated, without `..`, and names a file, never a directory ending in `/` or `/.` (an absolute path would pass only on the author's machine) |
| `title`, `scenario`, `blast_radius`, `trace`, `impact`, `fix` | Required nonblank strings |
| `exposure` | Required nonblank for High and Medium: the critical flow, fix hashes whose change touched no test, or the window's churn on the untested code |
| `coverage` | Required for High and Medium: `{net, tests, gaps}` — the tests that reach the behaviour today. `net` is `covered` (tests reach and assert it), `partial` (tests reach it, or some of it, without asserting all that matters) or `none`; `tests` a list of `path:line` (empty only when `net` is `none`; the test function's line, or a table-driven case's row); `gaps` a nonblank string. `Restructure` requires `gaps` other than `none`: what keeps a test from reaching the behaviour |
| `asserts` | Required nonempty list for High and Medium: each item one observable outcome the new or strengthened test checks; on a `Restructure` finding, the outcomes the restructuring keeps, which the existing tests or the dependent finding's tests check |
| `steps` | Required nonempty list for High and Medium; each item of a non-excluded finding, at any severity, contains `verify:` |
| `depends_on` | Optional list of finding IDs; each exists, is not excluded, and the graph has no cycle; an excluded finding has none |
| `convention` | Optional: the ledger ID(s) the finding cites (`C-01, C-03`) |
| `references` | Optional list of `{url, title}`; `url` nonblank, `title` optional. `report.md` links web URLs and relative paths, the dashboard web URLs only; any other scheme is shown as text |
| `validation` | `{verdict, method, evidence}` as in `reference/validation.md`; `analysed` requires `analysis {tool, command, result}` |
| `status` | `Open` (default), `Fixed`, `Accepted` (`reference/validation.md`, *Proving a test*); an `Accepted` finding's ID appears in `decisions` |
| `conventions[]` | `id` (`C-01`…), `idiom`, `source`, `status` (`holds`, `drifted`, `partly read`, `not checked`); optional `concern` from `reference/conventions.md` §2, `inferred` (an inferred entry's ID appears in `decisions`, for a person to confirm), `reason` (required for `not checked`; `check` fails it on `holds` and `drifted`) |
| `plan[]` | `batch` (1… gapless, in order), `title`, `findings` (IDs), `prerequisite`, `pr_title`. Each finding appears in at most one batch, in the same batch as each open `depends_on` or a later one; an excluded finding is in none |
| `perspectives[]` | `name`, `status` (`applied`, `N/A`, `not checked`), `note` |
| `checked_ok`, `limitations` | Required nonempty; `decisions`, `next_steps` optional |

## What `check` enforces

Exactly the three output files; the schema above; gapless `F-NNN` IDs in
`renumber`'s order; every perspective recorded; every non-excluded finding under an
`applied` perspective; and, for non-excluded findings only: High and Medium
findings with a verdict other than `Unverified`, evidence, `exposure`,
`coverage`, `asserts` and `steps`; every High `Confirmed`; `meta.commit` once a
finding is `Confirmed`, and `meta.window` once a `Confirmed` finding's
`exposure` cites history (a commit hash or the word commit, as in *Field
rules*); every `Accepted` finding named in
`decisions`; `verify:` in every step of a non-excluded finding; `Valid`,
`FalsePositive` and `NotApplicable` evidence citing `path:line` (a duplicate
may instead name the kept finding it repeats); `coverage.tests` listed exactly
when `coverage.net` is not `none`, and `coverage.gaps` other than `none` on a
`Restructure` finding; cited conventions that exist (a `Valid` finding cites
only `drifted` ones, a `Likely` one only `drifted` or `partly read` ones),
every `drifted` convention cited by a `Valid` or `Likely` finding and every
`inferred` one named in `decisions`; `depends_on` acyclic and resolvable, and
absent on excluded findings; every open, non-excluded Medium-or-higher finding
in exactly one plan batch, each open dependency of a planned finding in an
earlier batch or listed before it in its own, a `Restructure` finding alone in
its batch, and no excluded finding in a batch; and `dashboard.html` and
`report.md` byte-identical to a fresh render in `meta.lang`. When present,
`assessment.html` is also checked against a fresh render. With `--repo`,
every `location` and `coverage.tests` entry exists in the checkout. It checks
shape and consistency, not whether a finding is true.
