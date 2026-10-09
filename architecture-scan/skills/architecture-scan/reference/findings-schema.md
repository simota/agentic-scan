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
filter by severity) and `<out>/report.md`. Exit codes: `0` written, `2` the
record does not match the shape (the field is named). `findings.py check`
exits `1` and lists every contract violation.

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
  appended. Duplicate IDs within one fragment are refused
- `perspectives` match by `name` and replace the whole entry
- `checked_ok`, `decisions`, `limitations` and `next_steps` append without
  duplicates

Every merge validates the combined record; a refused merge writes nothing.
Each finding must be complete in the fragment that first adds it.

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
| `meta.project`, `scope`, `date`, `assessor`, `lang` | Required for `check` and `render`. `lang` is `ja` or `en`. `commit` is the assessed revision (`git rev-parse --short HEAD`, read-only) |
| `findings[].id` | `A-001`…, gapless, numbered in severity order (excluded verdicts may sit anywhere) |
| `severity` | `High`, `Medium`, `Low`, `Info` (`SKILL.md` table) |
| `confidence` | `Confirmed` (follows from the code), `Environment-dependent` (needs a named runtime condition), `Suspected` |
| `category` | One perspective name from `reference/perspectives.md`, exactly |
| `step` | Optional hunt step ID (`BL1`…) |
| `location` | A `path:line` (or `path:start-end`) string, or a list of them |
| `title`, `scenario`, `blast_radius`, `trace`, `impact`, `fix`, `guard` | Required nonblank strings (`reference/rules.md` §5) |
| `contrast`, `rule` | Optional strings: the module or path that keeps the rule; the ledger ID |
| `validation.verdict` | `Valid`, `Likely`, `Unverified`, `Unlikely`, `FalsePositive`, `NotApplicable`; the definitive three need `evidence` |
| `validation.method` | `static` or `analysed`; `analysed` requires `analysis` |
| `analysis` | `{tool, command, result}`, nonblank, from a read-only local analysis |
| `status` | `Open` (default), `Fixed`, `Accepted` |
| `references[]` | `{title, url}` |
| `rules[]` | `id` (`R-01`…), `statement`, `source`, `status` (`holds`, `violated`, `partly read`, `not checked`); a `not checked` rule needs `reason`. `family` and `inferred` are optional |
| `perspectives[]` | `name` (exact), `status` (`applied`, `N/A`, `not checked`), `note` (steps applied, steps left out with reasons) |
| `checked_ok`, `limitations` | Required nonempty for `check`; `decisions`, `next_steps` optional |
