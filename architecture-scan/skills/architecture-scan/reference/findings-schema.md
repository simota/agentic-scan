# Findings file — the single source for every output

**Read when:** REVIEW, before a unit writes its first fragment; REPORT, before
producing the dashboard and the report. Write the
results to `findings.json` once; the dashboard, `report.md` and the chat
summary use the same recorded facts. The chat summary's evidence line also
draws on scratch notes the record does not hold (what was read, what was
traced end to end, the scratch path); its counts and findings come only from
the record.

Enum values (severities, confidences, verdicts, statuses, perspective names)
stay in English in both languages: they are the record's vocabulary, the same
words a reader filters or searches by. Labels and headings follow `meta.lang`.

Render with (paths relative to this skill's directory):

```
python3 scripts/findings.py renumber <out>/findings.json
python3 scripts/render.py <out>/findings.json --out <out>
python3 scripts/findings.py check <out> --repo <checkout> [--allow NAME]
```

`render.py` writes `<out>/dashboard.html` (self-contained, works offline; the
same layout as security-scan's, styled by the vendored `scripts/scan_report_kit/`: open-risk cards, a "start here" queue, coverage
and limitations, overview charts and a findings register filterable by record
set, severity, confidence, perspective, status, verdict and text, with a
copy-for-LLM button per finding) and `<out>/report.md`. Every value is in the
HTML itself, so the dashboard reads in full without JavaScript. The dashboard preserves line breaks
in recorded text, including multiline evidence and analysis commands; its
Content-Security-Policy allows only its own inline style and script, so it
fetches nothing. Both outputs show separate counts for each validation verdict,
name the verdict and perspective (with the hunt step) of every finding,
including excluded findings, and list the perspectives in the order of
`reference/perspectives.md`, marking any not recorded. References become links
only for `http`/`https` URLs (and, in `report.md`, scheme-less relative paths,
never `//host`, `\\host` or `/\host`, which name another host);
any other scheme, or any URL containing a control or bidirectional character,
is shown as literal text (with the bidirectional character made visible). In `report.md`, recorded text keeps emphasis and code spans, but
cannot open a Markdown block (heading, list, rule, code block, link
definition) and cannot form a link, image, autolink (a bare URL, `www.` or
an e-mail address stays plain text, as in the dashboard; an `@` after a
blank, a bracket, a quote or non-ASCII punctuation, such as `@scope/pkg` or
`。@Transactional`, is left as written) or `$` math. A `>` stays
as written (`a -> b`) except where it would start a quote.
Backslashes are shown as written (`docs\adr`), so they never escape a
delimiter; the one exception in `report.md` is a backslash directly before a
backtick, the author's escape: `` \` `` shows a literal backtick and no
backslash. The dashboard shows every recorded character verbatim. A blank
optional field (including a rule's `reason`) gets no row in either output. The
dashboard keeps excluded findings in their own record set, apart from the severities, matching
the counts, lists them after the rest in either register order, says so when a
filter leaves nothing to show, and opens every finding when printed.
Bidirectional control characters (U+202A–202E, U+2066–2069) in recorded text
are shown as `[U+202E]` in both outputs, so no value can display reversed.
Both outputs are written to temporary files first; only when both are written
are they moved into place, one after the other. A write error therefore keeps
the previous pair; after any exit `1`, render again before `check`.
Exit codes: `0` written, `1` an output could not be written, `2` the record
does not match the shape or cannot be read (the field or file is named), or
the command line is wrong.

`findings.py check` exits `1` and lists every contract violation. When
`findings.json` itself fails the schema, it reports that first error (plus any
missing or unexpected files) and stops, since the other rules need a valid
record. All three
required output paths must be files, and `report.md` and `dashboard.html` must
be byte-identical to what `render.py` produces from the current
`findings.json` in `meta.lang` — re-render after the last merge. It also requires:

- every ID in a nonblank `findings[].rule` to name a `rules[].id`; a `Valid`
  finding not excluded cites rules recorded as `violated`, a `Likely` one
  rules recorded as `violated` or `partly read`
- every `violated` rule to be cited in the `rule` of a `Valid` or `Likely`
  finding; one root cause that breaks several rules lists them all
  (`"rule": "R-01, R-02"`). A rule ID in a trace cites nothing
- no `reason` on a `holds` or `violated` rule: a provisional `not checked`
  reason is sent back as `"reason": null` with the final status
- every finding not excluded to sit under a perspective recorded as `applied`
- every High and Medium finding not excluded to carry `validation.evidence`
  and a verdict other than `Unverified` (SKILL.md: an untraced High or Medium
  finding is not reported)
- `Valid`, `FalsePositive` and `NotApplicable` evidence to cite a `path:line`
  (a path with a `/` or `\`, a file with an extension, a build or project file
  such as `Makefile`, `BUILD`, `CODEOWNERS` or `README`, or a path or file name
  from the finding's own `location`, then a line from 1: `job.py:58`,
  `根拠:job.py:58`, `BUILD:12`, `server:9` beside `bin/server:9`; not
  `ABC:123`, `10:30`, `v1.2:3`, a URL's port or a host and port ending in
  `.com`, `.net`, `.io`, `.internal` or `.localhost`, such as
  `db.internal:5432`. Dotfiles and names such as `Dockerfile.dev` or
  `Makefile.local` count as files). A duplicate's `NotApplicable` evidence
  may instead be only the name of the reported finding it repeats, with
  nothing else (`Duplicate of A-004`, `重複: A-004`)
- every finding ID that prose mentions to name a recorded finding, read as
  renumber reads mentions (not in `meta`, a `location`, a URL, a command or a
  rule `source`): a fragment merged after renumber that still names an old
  block ID (`Fix A-101 first`) or a mistyped ID is named with its field
  (`next_steps[0]`, `A-002.trace`, `R-01.statement`)

With `--repo <checkout>` (a checkout of the assessed revision), `check` also
refuses a `location` whose file is missing (including a path spelled in
another letter case) or outside that checkout, or
whose line is past the file's end; it catches a path typed from memory, not a line a few rows off, so the
trace still reads each line it cites.

## Writing the file

Build `findings.json` from fragments, never from a heredoc or a generated
script:

```
# file-write tool: <scratch>/frag-001.json = {"meta": {...}, "rules": [...], "findings": [...]}
python3 scripts/findings.py merge <out>/findings.json <scratch>/frag-001.json
# file-write tool: <scratch>/frag-002.json = {"findings": [...], "perspectives": [...]}
python3 scripts/findings.py merge <out>/findings.json <scratch>/frag-002.json
```

Merge semantics:

- Every record is checked against the keys the schema knows: an unknown key
  in a finding, `validation`, `analysis`, a reference, a rule or a perspective
  (a typo such as `contrats`) is refused rather than kept and never shown.
  `meta` accepts extra keys for run context the outputs do not show,
  nested at most 32 levels deep
- `meta` updates key by key
- `findings` and `rules` match by `id`: a known record is updated key by key
  (so a later fragment can add just `validation` to `A-003`), a new one is
  appended. Nested objects (`validation`, `analysis`) replace whole, so a
  fragment that updates `validation` carries all of its fields. Duplicate IDs
  within one fragment are refused
- `perspectives` match by `name` and replace the whole entry. Duplicate names
  within one fragment are refused
- `checked_ok`, `decisions`, `limitations` and `next_steps` append without
  duplicates
- A complete finding (every required field) sent with an ID that already holds
  a finding with a different `title` or `location` is refused as an ID
  collision: two review units numbered the same ID, or a different finding at
  the same place. A partial record that changes both `title` and `location`
  is taken for another finding too. To correct a title or location, send only
  the changed field (`{"findings": [{"id": "A-003", "title": "…"}]}`); to
  correct both, send them in two fragments. Each unit numbers in its
  own block (`A-101`…, `A-201`…); `renumber` compacts them. IDs are always
  `A-` and three digits, so blocks of 100 allow nine units; with ten or
  more units, split `A-001`–`A-999` into equal blocks instead (twelve units:
  83 IDs each, unit 1 from `A-001`, unit 2 from `A-084`). A unit with more
  findings than its block continues in a free block, and a record holds at most 999

## Correcting the record

Never edit `findings.json` by hand; every correction is a fragment:

- `null` removes an optional key: `{"findings": [{"id": "A-003", "analysis":
  null}]}`, `{"meta": {"method": null}}`, `{"rules": [{"id": "R-02", "reason":
  null}]}`. A required key (including `meta.project`, `scope`, `date`,
  `assessor` and `lang`, which merge otherwise lets a fragment omit) cannot be
  removed; replace its value instead
- `remove` deletes exact items from the string lists before the fragment's own
  items are added, and those items take the earliest place an item was
  removed from (these lists are ordered: `next_steps` is the order of work), so one
  fragment replaces an item in place: `{"remove":
  {"next_steps": ["Fix A-001 first"]}, "next_steps": ["Fix A-002 first"]}`.
  It also deletes a spurious ledger entry by id: `{"remove": {"rules":
  ["R-05"]}}`; a complete rule with the same id sent in the same fragment
  takes its place in the ledger (a rule with another id is appended). An
  item that is not recorded is refused, so a typo cannot pass silently
- A finding is never removed (SKILL.md, *Never*): a wrong one is marked
  `FalsePositive`, a duplicate `NotApplicable`, each with evidence
- A wrong value is replaced by sending the key again; nested `validation` and
  `analysis` objects are replaced whole

When `check` fails: correct the record with a fragment, `renumber` if a
finding was added, regraded, relocated or excluded, render, and check again.

## Numbering

Fragments may assign IDs in the order findings are found. Before rendering,
`findings.py renumber <out>/findings.json` sorts the findings by severity, then
by the path and line of their first location, and renames them `A-001`…
without gaps. Every whole-word mention of an old ID in the record's prose
(`title`, `trace`, `evidence`, `next_steps`, `decisions`…) is rewritten in the
same pass. Literal values keep theirs: `meta`, every `location`, reference
`url`, `analysis.command` and rule `source` (an `A-001` there is a file, a
ticket or an argument). In prose, a token such as `JIRA-A-001` and a path
segment such as `docs/A-001.md` are left alone, while an ID beside Japanese
text (`A-001を`) or joined to another ID (`A-002/A-001`, `A-002-A-001`) is
rewritten. A mention of an ID that no finding holds is left as written, and
`check` names it; when renumber would give that ID to a finding, so the
mention would silently name it, renumber exits `1` and writes nothing until a
fragment corrects the mention. It prints each rename, leaves an ordered
record untouched, and writes the same way merge does. Renumber after the last
merge that adds, regrades, relocates or excludes a finding (excluded verdicts
sort last), then render.

After a renumber, use only the new IDs it printed. Merge matches findings by
ID alone, so a fragment written earlier that updates `A-002` would change
whichever finding is `A-002` now; rewrite or discard unmerged fragments before
merging them. If a finding is added, regraded, relocated or excluded later, merge it, renumber
again and re-render.

## Merge guarantees

A refused batch names the fragment that broke the record. A merge or render
killed mid-write can leave a `.findings-<hex>.tmp` file beside the record;
`check` names it; delete it once no merge or render is running.

Merge and renumber hold an exclusive lock on the record's directory from
reading the record to replacing it, so review units may merge at the same
time without losing each other's findings. Where the lock is unavailable
(Windows has no `fcntl`; a directory that can be written but not read warns
on stderr), run merges one at a time.

The existing record is validated before merging, then the combined record is
validated after each fragment. A refused batch writes nothing, even if earlier
fragments were valid. Invalid existing records must be corrected before merging.
Each finding must be complete in the fragment that first adds it.
Inputs must be UTF-8, including every string after JSON escapes are decoded;
a leading byte order mark is ignored.
JSON numbers must decode to finite values; `NaN`, `Infinity`, `-Infinity`, and
numeric overflow are rejected rather than written back as nonstandard JSON.
Duplicate keys within a JSON object are rejected, including nested objects,
so an earlier value cannot be silently discarded before validation.
Invalid text is rejected before merge or render opens an output for writing.

Merge creates the destination's directory when needed, writes the encoded
record to a temporary file beside the destination, flushes it to disk, then
replaces the destination. A write or replacement
error exits `1`, cleans up the temporary file, and preserves the previous
record. Existing permission bits and symbolic-link destinations are retained.

## Shape

```json
{
  "meta": {
    "project": "acme-shop",
    "scope": "Monorepo: api/, worker/, web/",
    "commit": "3f2a9c1",
    "date": "2026-10-09",
    "assessor": "Claude Code (<model>)",
    "method": "Static review with read-only git history",
    "lang": "en"
  },
  "rules": [
    {"id": "R-01", "statement": "Only the billing module writes invoices",
     "source": "docs/adr/0004-billing.md:12", "family": "OWN", "inferred": false,
     "status": "violated"}
  ],
  "findings": [
    {
      "id": "A-001",
      "title": "Refund job writes invoices directly, skipping billing's tax rules",
      "severity": "High",
      "confidence": "Confirmed",
      "category": "Domain model and data ownership",
      "step": "DM1",
      "location": ["worker/refunds/job.py:58", "api/billing/service.py:120"],
      "scenario": "Refund flow (core): every refund issued by support",
      "blast_radius": "invoices table; 2 writers in 2 deployable units",
      "trace": "1. worker/refunds/job.py:58 updates invoices.total directly. 2. api/billing/service.py:120 recomputes tax on every invoice change. 3. The job never calls it",
      "contrast": "api/orders/cancel.py:40 calls BillingService.adjust()",
      "impact": "Expected (R-01): every invoice change goes through billing. Actual: refunded invoices keep the pre-refund tax amount",
      "rule": "R-01",
      "fix": "Call BillingService.adjust() from the refund job instead of updating the table",
      "guard": "R-01: CI search fails on writes to invoices outside api/billing/",
      "validation": {"verdict": "Valid", "method": "static",
                     "evidence": "job.py:58 raw UPDATE; no call to billing in worker/refunds/"},
      "status": "Open"
    }
  ],
  "perspectives": [
    {"name": "Domain model and data ownership", "status": "applied", "note": "DM1 via R-01; DM2-DM5 applied"}
  ],
  "checked_ok": ["api/ has no cycles between its modules (import graph, 0 cycles)"],
  "decisions": ["Confirm that worker/ may not write billing tables"],
  "limitations": ["Broker delivery semantics in production were not observed"],
  "next_steps": ["Fix A-001, then add the single-writer check to CI"]
}
```

## Field rules

| Field | Rule |
|---|---|
| `meta.project`, `scope`, `date`, `assessor`, `lang` | May be omitted while merging fragments, but must be nonblank strings when present. All are required for `check` and `render`. `lang` is `ja` or `en`, the requester's language: render uses it unless `--lang` overrides it for a preview, and `check` requires both outputs in it. `commit` is the assessed revision (`git rev-parse --short HEAD`, read-only) |
| `meta.method` | Optional string: one phrase naming the reading and each read-only tool or history window, e.g. `Static review; git log 12 months; import-linter`. Shown verbatim in both outputs in place of the generic static/analysed note |
| `findings[].id` | `A-001`…, gapless, numbered in severity order, then path and line of the first location, excluded verdicts after the rest (`renumber` orders them) |
| `severity` | `High`, `Medium`, `Low`, `Info` (`SKILL.md` table) |
| `confidence` | `Confirmed` (follows from the code), `Environment-dependent` (needs a named runtime condition), `Suspected` |
| `category` | One perspective name from `reference/perspectives.md`, exactly |
| `step` | Optional hunt step ID (`BL1`…) from the finding's own perspective: its two-letter prefix must be the one `reference/perspectives.md` gives `category`, and the step must exist there (`DM1`–`DM5`, not `DM9`) |
| `location` | A `path:line` (or `path:start-end`) string, or a list of them. The path is relative to the repository root (the checkout given to `check --repo`), not to the review scope; an absolute path or a `..` segment is accepted only when it resolves inside that checkout, but a relative path keeps local directories out of the shared report. Lines are ASCII digits from 1, and a range does not descend. Paths may contain spaces and colons; the final colon separates the line number. CR and LF are not allowed. Each location is rendered as literal code in the Markdown report so filename punctuation is preserved |
| `title`, `scenario`, `blast_radius`, `trace`, `impact`, `fix`, `guard` | Required nonblank strings (`reference/rules.md` §5) |
| `contrast`, `rule` | Optional strings: the module or path that keeps the rule; the ledger ID, or several separated by commas (`R-01, R-02`) |
| `validation.verdict` | Required, also for an unexamined finding (`Unverified`): `Valid`, `Likely`, `Unverified`, `Unlikely`, `FalsePositive`, `NotApplicable`; the definitive three need `evidence`, and `check` requires it to cite a `path:line` |
| `meta.commit`, `validation.evidence`, `references[].title`, `rules[].reason` | Strings when present. Empty values and omission are allowed except where a nonblank value is required by the verdict or run contract |
| `validation.method` | Required: `static` or `analysed`; `analysed` requires `analysis` |
| `analysis` | When present, an object with nonblank string fields `{tool, command, result}`, from a read-only local analysis; checked even when `validation.method` is `static` |
| `status` | `Open` (default), `Fixed`, `Accepted` |
| `references[]` | Objects with a required nonblank string `url` and optional string `title`. A missing or empty title uses the URL as its label in both outputs |
| `rules[]` | `id` (`R-01`…), `statement`, `source`, `status` (`holds`, `violated`, `partly read`, `not checked`); a `not checked` rule needs `reason`, a `partly read` one may carry it, and `check` refuses it on `holds` or `violated` (send `"reason": null` with the final status). Optional `family` is one of `LAYER`, `BOUND`, `OWN`, `TX`, `FAIL`, `CONTRACT`, `SEAM` (`reference/rules.md` §2); optional `inferred` is `true` or `false` |
| `perspectives[]` | `name` (exact and unique), `status` (`applied`, `N/A`, `not checked`), `note` (required nonblank: steps applied, steps left out with reasons). A perspective is replaced by sending it again, never removed |
| `checked_ok`, `limitations` | Required nonempty for `check`; `decisions`, `next_steps` optional. Items in all four lists are nonblank strings |
