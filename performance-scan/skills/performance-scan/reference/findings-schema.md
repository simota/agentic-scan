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
filterable) and `<out>/report.md`. Exit codes: `0` written; `1` an output could
not be encoded or written (unencodable text in the record, or a destination
problem: the destination directory must be writable); `2` the input or command
line is wrong (the message names the file and, for shape errors, the field).
`findings.py` exits `1` when a merge is refused or `check` finds violations (one
per line on stderr; a path that is not a directory is reported as such) and `2`
on a usage error. `check` requires the three outputs to be readable, nonempty
regular files (symbolic links to such files are fine) and validates structure,
not whether rendered text is current or a finding is true.

Inputs are strict UTF-8 JSON in regular files (symbolic links to them are
fine): unique member names at every level, no `NaN`/`Infinity`, no number
beyond the float range. Write piped or generated content to a regular file
first. A refused command changes no record or report; run merges and renders
one at a time. Replacements are atomic and keep existing permission bits and
symbolic links; new files start private.

## Writing the file

Build `findings.json` from fragments, never from a heredoc or a generated
script:

```
# file-write tool: <scratch>/frag-001.json = {"meta": {...}, "budgets": [...], "findings": [...]}
python3 scripts/findings.py merge <out>/findings.json <scratch>/frag-001.json
# file-write tool: <scratch>/frag-002.json = {"findings": [...], "perspectives": [...]}
python3 scripts/findings.py merge <out>/findings.json <scratch>/frag-002.json
```

- Write one to five findings per fragment; the first fragment carries `meta`.
- One REPORT coordinator runs all merges to the same `findings.json`, one at a
  time; parallel reviewers write draft findings and notes in scratch, which
  are never merged as they are.
  Merges are not safe to run concurrently: one can overwrite another's changes.
- Reviewers label findings in their scratch notes with temporary IDs
  (`U<unit>-<n>`) and never put `perspectives` in fragments. After VERIFY the
  coordinator assigns the final `P-NNN` in severity order and writes each
  finding fragment once with that ID, so no merge has to renumber.

Merge semantics:

- `meta` updates key by key
- `findings` and `budgets` match by `id`: a known record is updated key by key
  (so a later fragment can add just `validation` to `P-003`; nested objects
  such as `validation` and `measurement` are replaced whole, so send all their
  keys), a new one is
  appended. Duplicate IDs within one fragment are refused
- `perspectives` match by `name` and replace the whole entry, so parallel
  reviewers leave `perspectives` out of their fragments; the coordinator writes
  one final entry per perspective: `applied` if any unit applied it, `not
  checked` if any unit could not check it, otherwise `N/A`, with a note joining
  the unit notes (`orders: DB1–DB3 via B-01; billing: DB5 N/A …`)
- `checked_ok`, `decisions`, `limitations` and `next_steps` append without
  duplicates

A refused merge writes nothing. Each finding must be complete in the fragment
that first adds it (the record's structure is validated after every fragment;
the cross-field rules of `check`, such as evidence citations and `holds`
budgets, run only in `check`), and every entry in `findings`, `budgets` and
`perspectives` must be an object with a nonblank string `id` or `name`. The
existing and combined records need unique finding IDs, budget IDs and
perspective names; repeated perspective names within one fragment replace in
order, so the last one wins. A merge never removes a key, so an update that turns a finding into a
different one keeps its old optional fields (`measurement`, `contrast`,
`budget`, `step`, `references`): reuse an ID only for the same root cause, and
renumber by building a fresh `findings.json` from fragments with the final IDs.
While merging, `meta` may be partial, but any `project`, `scope`, `date`,
`assessor` or `lang` present must be a nonblank string (`lang`: `ja` or `en`).

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
  "checked_ok": ["Product list paginates with a cursor and prefetches images (app/products/views.py:22)"],
  "decisions": ["Confirm the intended maximum items per order"],
  "limitations": ["Production data volumes and deployed indexes were not observed"],
  "next_steps": ["Fix P-001, then add the query-count test"]
}
```

## Field rules

Findings, budgets, perspectives and the objects inside a finding (`validation`,
`measurement`, `references[]`) accept only the keys listed here; any other key
(often a typo such as `budjet`) is refused. `meta` may carry extra keys, which
nothing renders.

String values are plain text, not authored Markdown or HTML. Renderers escape
them for their output context; use `references[]` for links rather than
embedding Markdown link syntax in another field.

| Field | Rule |
|---|---|
| `meta.project`, `scope`, `date`, `assessor`, `lang` | Required for `check` and `render`. `lang` is `ja` or `en`. `commit` is an optional string for the assessed revision (`git rev-parse --short HEAD`, read-only) and `method` an optional string describing the review method (`Static review`, `Static review plus local measurement`); omission or an empty string is allowed, and an omitted or empty `commit` renders as `UNKNOWN` |
| `findings`, `budgets`, `perspectives` | Optional arrays; omission and an empty array are allowed. A present value must be an array, never an object, string or `null`. `check` additionally requires every perspective to be recorded |
| `findings[].id` | A string consisting of `P-` followed by exactly three ASCII digits (`0`–`9`), with no surrounding whitespace (`P-001`…), so one record holds at most 999 findings. Gapless, numbered in severity order; number `FalsePositive` and `NotApplicable` findings after all others (`check` enforces both; it does not rank excluded findings by severity) |
| `severity` | `High`, `Medium`, `Low`, `Info` (`SKILL.md` table) |
| `confidence` | `Confirmed` (cost follows from the code), `Environment-dependent` (needs a named production condition, stated with its threshold in `scale_driver` or `impact`), `Suspected` (the cost model itself rests on an unconfirmed code link; `check` refuses it with verdict `Valid`) |
| `category` | One perspective name from `reference/perspectives.md`, exactly |
| `step` | Optional string: the hunt step ID from `reference/perspectives.md` (`DB1`…) |
| `location` | A `path:line` (or `path:start-end`) string, or a nonempty list of them. The nonblank path may contain spaces or colons, but not line breaks; the final colon separates the line suffix. Line numbers are positive integers, and a range's end must not precede its start |
| `workload`, `scale_driver`, `cost_model`, `request`, `impact`, `fix`, `regression_test` | Required nonblank strings (`reference/budgets.md` §5) |
| `contrast`, `budget` | Optional strings: the sibling path that keeps the budget; the ledger ID. Omission or an empty string is allowed; a present value must be a string. `budget` holds exactly one ID, and `check` requires a nonblank `budget` to name an ID in `budgets[]`; name other violated budgets in `impact` |
| `validation.verdict` | `Valid`, `Likely`, `Unverified`, `Unlikely`, `FalsePositive`, `NotApplicable`; the definitive three need nonblank string `evidence`, which `check` requires to cite at least one `path:line` or `path#L42` (the path must look like a file: an extension, a directory part, or a conventional name such as `Makefile` or `BUILD`; a URL, a `host:port` such as `db.example.com:5432` or `example.org:443`, a module path such as `github.com/foo/bar:3`, a code identifier such as `time.Second:30` or `sql.DB:4`, a setting such as `TTL:300`, a time, a ratio or prose such as `timeout:30` does not count, and `check` names each rejected candidate; so write other extensionless files, and lowercase names ending in `.dev`, `.test`, `.local`, `.org` and similar, with their directory, e.g. `bin/server:12`, `config/settings.local:3`). For other verdicts, `evidence` may be omitted or empty but must be a string when present |
| `validation.method` | `static` or `measured`; `measured` requires `measurement` |
| `measurement` | When present, an object with nonblank string fields `environment`, `command` and `result`, from an authorised local run. This shape is checked for both `static` and `measured`; `measured` requires the object |
| `status` | `Open` (default), `Fixed`, `Accepted` (the owner accepts the cost, with the decision recorded in `decisions`). Every non-excluded finding is counted in the totals whatever its status |
| `references[]` | Optional array of objects with a required nonblank string `url` and an optional string `title`. Only absolute `http(s)` URLs, `mailto:` and relative paths become links; any other URL (including `//host`) is shown as text. An omitted or blank `title` uses the URL as the link label |
| `budgets[]` | `id` (a string consisting of `B-` followed by at least two ASCII digits, with no surrounding whitespace; `B-01`…), `statement`, `source`, `status` (`holds`, `violated`, `partly read`, `not checked`); a `not checked` budget needs a nonblank `reason` for `check`, and `check` refuses `holds` while a `Valid` finding that is not `Fixed` names the budget. A present `reason` must be a string (empty allowed while merging). `family` (`QRY`, `SIZE`, `CPLX`, `LAT`, `RES` or `FE`, from `reference/budgets.md` §2) and `inferred` are optional |
| `budgets[].inferred` | Optional boolean (`true` or `false`). Omission is allowed; all other types, including strings, numbers and `null`, are refused |
| `perspectives[]` | `name` (exact), `status` (`applied`, `N/A`, `not checked`), `note` (steps applied, steps left out with reasons) |
| `checked_ok`, `limitations` | Required nonempty for `check`; `decisions`, `next_steps` optional |
