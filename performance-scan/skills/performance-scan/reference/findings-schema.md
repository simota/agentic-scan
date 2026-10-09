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
# file-write tool: <scratch>/frag-001.json = {"meta": {...}, "budgets": [...], "findings": [...]}
python3 scripts/findings.py merge <out>/findings.json <scratch>/frag-001.json
# file-write tool: <scratch>/frag-002.json = {"findings": [...], "perspectives": [...]}
python3 scripts/findings.py merge <out>/findings.json <scratch>/frag-002.json
```

Merge semantics:

- `meta` updates key by key
- `findings` and `budgets` match by `id`: a known record is updated key by key
  (so a later fragment can add just `validation` to `P-003`), a new one is
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
    "scope": "API and web front end at the repository root",
    "commit": "3f2a9c1",
    "date": "2026-10-09",
    "assessor": "Claude Code (<model>)",
    "method": "Static review",
    "lang": "en"
  },
  "budgets": [
    {"id": "B-01", "statement": "Hot list endpoints issue a constant number of queries",
     "source": "baseline; tests/test_orders.py:40 asserts 3 queries", "family": "QRY",
     "inferred": false, "status": "violated"}
  ],
  "findings": [
    {
      "id": "P-001",
      "title": "Order list loads line items per order (N+1)",
      "severity": "High",
      "confidence": "Confirmed",
      "category": "Database access",
      "step": "DB1",
      "location": ["app/orders/serializers.py:42", "app/orders/views.py:18"],
      "workload": "Every signed-in user opening the order list (hot; polled every 30 s)",
      "scale_driver": "Orders per page (max 100) × items per order (uncapped)",
      "cost_model": "1 + N queries for items, + N for products; N = orders on the page",
      "request": "1. A tenant with 100 orders, each with 20 items. 2. GET /api/orders?page=<n>",
      "contrast": "GET /api/orders/<id> prefetches items at app/orders/views.py:61",
      "impact": "Expected (B-01): constant queries. Actual: 201 queries per page; the list approaches the 30 s gateway timeout as items grow",
      "budget": "B-01",
      "fix": "Prefetch items and products on the list queryset at app/orders/views.py:18",
      "regression_test": "Query count for GET /api/orders is equal with 1 and 50 orders",
      "validation": {"verdict": "Valid", "method": "static",
                     "evidence": "views.py:18 queryset has no prefetch; serializers.py:42 iterates order.items.all()"},
      "status": "Open",
      "references": [{"title": "Django prefetch_related", "url": "https://docs.djangoproject.com/en/stable/ref/models/querysets/#prefetch-related"}]
    }
  ],
  "perspectives": [
    {"name": "Database access", "status": "applied", "note": "DB1-DB2 via B-01; DB3-DB6 applied"}
  ],
  "checked_ok": ["Product search uses a cursor and a composite index (db/migrations/0012.py:8)"],
  "decisions": ["Confirm the intended maximum items per order"],
  "limitations": ["Production data volumes and deployed indexes were not observed"],
  "next_steps": ["Fix P-001, then add the query-count test"]
}
```

## Field rules

String values are plain text, not authored Markdown or HTML. Renderers escape
them for their output context; use `references[]` for links rather than
embedding Markdown link syntax in another field.

| Field | Rule |
|---|---|
| `meta.project`, `scope`, `date`, `assessor`, `lang` | Required for `check` and `render`. `lang` is `ja` or `en`. `commit` is the assessed revision (`git rev-parse --short HEAD`, read-only) |
| `findings[].id` | `P-001`…, gapless, numbered in severity order (excluded verdicts may sit anywhere) |
| `severity` | `High`, `Medium`, `Low`, `Info` (`SKILL.md` table) |
| `confidence` | `Confirmed` (cost follows from the code), `Environment-dependent` (needs a named production condition), `Suspected` |
| `category` | One perspective name from `reference/perspectives.md`, exactly |
| `step` | Optional hunt step ID (`DB1`…) |
| `location` | A `path:line` (or `path:start-end`) string, or a nonempty list of them. The nonblank path may contain spaces or colons, but not line breaks; the final colon separates the line suffix. Line numbers are positive integers, and a range's end must not precede its start |
| `workload`, `scale_driver`, `cost_model`, `request`, `impact`, `fix`, `regression_test` | Required nonblank strings (`reference/budgets.md` §5) |
| `contrast`, `budget` | Optional strings: the sibling path that keeps the budget; the ledger ID |
| `validation.verdict` | `Valid`, `Likely`, `Unverified`, `Unlikely`, `FalsePositive`, `NotApplicable`; the definitive three need `evidence` |
| `validation.method` | `static` or `measured`; `measured` requires `measurement` |
| `measurement` | When present, an object with nonblank string fields `environment`, `command` and `result`, from an authorised local run. This shape is checked for both `static` and `measured`; `measured` requires the object |
| `status` | `Open` (default), `Fixed`, `Accepted` |
| `references[]` | `{title, url}` |
| `budgets[]` | `id` (`B-01`…), `statement`, `source`, `status` (`holds`, `violated`, `partly read`, `not checked`); a `not checked` budget needs `reason`. `family` and `inferred` are optional |
| `perspectives[]` | `name` (exact), `status` (`applied`, `N/A`, `not checked`), `note` (steps applied, steps left out with reasons) |
| `checked_ok`, `limitations` | Required nonempty for `check`; `decisions`, `next_steps` optional |
