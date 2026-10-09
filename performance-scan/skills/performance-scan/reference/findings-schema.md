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

Every merge validates the existing record before applying fragments, then
validates the combined record; a refused merge writes nothing.
Each finding must be complete in the fragment that first adds it.

Merges finish UTF-8 encoding and write a temporary file beside the destination
before replacing it. Encoding or write failures leave the existing record
unchanged. Existing file permissions and symbolic links are preserved; a new
record starts with private permissions. The destination directory must be
writable for the replacement.

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
      "title": "Order list lazy-loads items per order and products per item (N+1)",
      "severity": "High",
      "confidence": "Confirmed",
      "category": "Database access",
      "step": "DB1",
      "location": ["app/orders/serializers.py:42", "app/orders/views.py:18"],
      "workload": "Every signed-in user opening the order list (hot; polled every 30 s)",
      "scale_driver": "N = orders per page (max 100); M = items per order (uncapped)",
      "cost_model": "1 + N + N × M data queries: one for orders, N for items, N × M for lazy-loaded products; excludes fixed request overhead",
      "request": "1. The requested tenant page contains N=100 orders, each with M=20 items referencing distinct products; relation caches are empty. 2. GET /api/orders?page=<n>&page_size=100",
      "contrast": "GET /api/orders/<id> prefetches items and their products at app/orders/views.py:61",
      "impact": "Expected (B-01): constant data queries. Actual: 1 + 100 + 100 × 20 = 2101 data queries per page, growing with uncapped items per order even at a fixed page size; response latency was not measured",
      "budget": "B-01",
      "fix": "Prefetch items and products on the list queryset at app/orders/views.py:18",
      "regression_test": "After prefetching, GET /api/orders data-query counts are equal for (N,M)=(1,1), (50,1), (1,20), (50,20); each response still contains all expected orders, items and products",
      "validation": {"verdict": "Valid", "method": "static",
                     "evidence": "views.py:18 fetches orders without prefetch; serializers.py:42 evaluates order.items.all() once per order and reads item.product once per item without select_related or a shared product cache"},
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
| `meta.project`, `scope`, `date`, `assessor`, `lang` | Required for `check` and `render`. `lang` is `ja` or `en`. `commit` is an optional string for the assessed revision (`git rev-parse --short HEAD`, read-only); omission or an empty string is allowed |
| `findings`, `budgets`, `perspectives` | Optional arrays; omission and an empty array are allowed. A present value must be an array, never an object, string or `null`. `check` additionally requires every perspective to be recorded |
| `findings[].id` | `P-001`…, gapless, numbered in severity order (excluded verdicts may sit anywhere) |
| `severity` | `High`, `Medium`, `Low`, `Info` (`SKILL.md` table) |
| `confidence` | `Confirmed` (cost follows from the code), `Environment-dependent` (needs a named production condition), `Suspected` |
| `category` | One perspective name from `reference/perspectives.md`, exactly |
| `step` | Optional hunt step ID (`DB1`…) |
| `location` | A `path:line` (or `path:start-end`) string, or a nonempty list of them. The nonblank path may contain spaces or colons, but not line breaks; the final colon separates the line suffix. Line numbers are positive integers, and a range's end must not precede its start |
| `workload`, `scale_driver`, `cost_model`, `request`, `impact`, `fix`, `regression_test` | Required nonblank strings (`reference/budgets.md` §5) |
| `contrast`, `budget` | Optional strings: the sibling path that keeps the budget; the ledger ID. Omission or an empty string is allowed; a present value must be a string |
| `validation.verdict` | `Valid`, `Likely`, `Unverified`, `Unlikely`, `FalsePositive`, `NotApplicable`; the definitive three need nonblank string `evidence`. For other verdicts, `evidence` may be omitted or empty but must be a string when present |
| `validation.method` | `static` or `measured`; `measured` requires `measurement` |
| `measurement` | When present, an object with nonblank string fields `environment`, `command` and `result`, from an authorised local run. This shape is checked for both `static` and `measured`; `measured` requires the object |
| `status` | `Open` (default), `Fixed`, `Accepted` |
| `references[]` | Optional array of objects with a required nonblank string `url` and an optional string `title`. Omit `title` to use the URL as the link label; an empty title is also allowed |
| `budgets[]` | `id` (`B-01`…), `statement`, `source`, `status` (`holds`, `violated`, `partly read`, `not checked`); a `not checked` budget needs `reason`. A present `reason` must be a string (empty allowed). `family` and `inferred` are optional |
| `perspectives[]` | `name` (exact), `status` (`applied`, `N/A`, `not checked`), `note` (steps applied, steps left out with reasons) |
| `checked_ok`, `limitations` | Required nonempty for `check`; `decisions`, `next_steps` optional |
