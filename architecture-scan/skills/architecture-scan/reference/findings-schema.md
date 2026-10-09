# Findings file — the single source for every output

**Read when:** REPORT, before producing the dashboard and the report. Write the
results to `findings.json` once; the dashboard, `report.md` and the chat
summary use the same recorded facts.

Render with (paths relative to this skill's directory):

```
python3 scripts/render.py <out>/findings.json --out <out> [--lang ja|en]
python3 scripts/findings.py check <out> [--allow NAME]
```

`render.py` writes `<out>/dashboard.html` (self-contained, works offline,
filter by severity) and `<out>/report.md`. The dashboard preserves line breaks
in recorded text, including multiline evidence and analysis commands; its
Content-Security-Policy allows only its own inline style and script, so it
fetches nothing. Both outputs show separate counts for each validation verdict,
name the verdict and perspective (with the hunt step) of every finding,
including excluded findings, and list the perspectives in the order of
`reference/perspectives.md`, marking any not recorded. References become links
only for `http`/`https` URLs (and, in `report.md`, scheme-less relative paths);
any other scheme is shown as literal text. Recorded text cannot open a Markdown
block (heading, list, rule, code block, link definition) in `report.md`.
Each output is replaced only once completely written.
Exit codes: `0` written, `1` an output could not be written (the previous files
are kept), `2` the record does not match the shape (the field is named).

`findings.py check` exits `1` and lists every contract violation. All three
required output paths must be files, and `report.md` and `dashboard.html` must
be byte-identical to what `render.py` produces from the current
`findings.json` (in either language, both from one rendering) — re-render after
the last merge. It also requires:

- every nonblank `findings[].rule` to name a `rules[].id`
- every finding not excluded to sit under a perspective recorded as `applied`
- every High and Medium finding not excluded to carry `validation.evidence`
- `Valid`, `FalsePositive` and `NotApplicable` evidence to cite a `path:line`

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

The existing record is validated before merging, then the combined record is
validated after each fragment. A refused batch writes nothing, even if earlier
fragments were valid. Invalid existing records must be corrected before merging.
Each finding must be complete in the fragment that first adds it.
Inputs must be UTF-8, including every string after JSON escapes are decoded.
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
      "guard": "CI search fails on writes to invoices outside api/billing/",
      "validation": {"verdict": "Valid", "method": "static",
                     "evidence": "job.py:58 raw UPDATE; no call to billing in worker/refunds/"},
      "status": "Open"
    }
  ],
  "perspectives": [
    {"name": "Domain model and data ownership", "status": "applied", "note": "DM1 via R-01; DM2-DM4 applied"}
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
| `meta.project`, `scope`, `date`, `assessor`, `lang` | May be omitted while merging fragments, but must be nonblank strings when present. All are required for `check` and `render`. `lang` is `ja` or `en`. `commit` is the assessed revision (`git rev-parse --short HEAD`, read-only) |
| `findings[].id` | `A-001`…, gapless, numbered in severity order (excluded verdicts may sit anywhere) |
| `severity` | `High`, `Medium`, `Low`, `Info` (`SKILL.md` table) |
| `confidence` | `Confirmed` (follows from the code), `Environment-dependent` (needs a named runtime condition), `Suspected` |
| `category` | One perspective name from `reference/perspectives.md`, exactly |
| `step` | Optional hunt step ID (`BL1`…) from the finding's own perspective: its two-letter prefix must be the one `reference/perspectives.md` gives `category` |
| `location` | A `path:line` (or `path:start-end`) string, or a list of them. Lines are ASCII digits from 1, and a range does not descend. Paths may contain spaces and colons; the final colon separates the line number. CR and LF are not allowed. Each location is rendered as literal code in the Markdown report so filename punctuation is preserved |
| `title`, `scenario`, `blast_radius`, `trace`, `impact`, `fix`, `guard` | Required nonblank strings (`reference/rules.md` §5) |
| `contrast`, `rule` | Optional strings: the module or path that keeps the rule; the ledger ID |
| `validation.verdict` | `Valid`, `Likely`, `Unverified`, `Unlikely`, `FalsePositive`, `NotApplicable`; the definitive three need `evidence`, and `check` requires it to cite a `path:line` |
| `meta.commit`, `validation.evidence`, `references[].title`, `rules[].reason` | Strings when present. Empty values and omission are allowed except where a nonblank value is required by the verdict or run contract |
| `validation.method` | `static` or `analysed`; `analysed` requires `analysis` |
| `analysis` | When present, an object with nonblank string fields `{tool, command, result}`, from a read-only local analysis; checked even when `validation.method` is `static` |
| `status` | `Open` (default), `Fixed`, `Accepted` |
| `references[]` | Objects with a required nonblank string `url` and optional string `title`. A missing or empty title uses the URL as its label in both outputs |
| `rules[]` | `id` (`R-01`…), `statement`, `source`, `status` (`holds`, `violated`, `partly read`, `not checked`); a `not checked` rule needs `reason`. Optional `family` is one of `LAYER`, `BOUND`, `OWN`, `TX`, `FAIL`, `CONTRACT`, `SEAM` (`reference/rules.md` §2); optional `inferred` is `true` or `false` |
| `perspectives[]` | `name` (exact and unique), `status` (`applied`, `N/A`, `not checked`), `note` (steps applied, steps left out with reasons) |
| `checked_ok`, `limitations` | Required nonempty for `check`; `decisions`, `next_steps` optional |
