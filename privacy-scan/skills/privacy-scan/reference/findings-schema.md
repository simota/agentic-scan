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

Both report contents are generated before either output file is written.

## Writing the file

Build `findings.json` from fragments, never from a heredoc or a generated
script:

```
# file-write tool: <scratch>/frag-001.json = {"meta": {...}, "commitments": [...], "findings": [...]}
python3 scripts/findings.py merge <out>/findings.json <scratch>/frag-001.json
# file-write tool: <scratch>/frag-002.json = {"findings": [...], "perspectives": [...]}
python3 scripts/findings.py merge <out>/findings.json <scratch>/frag-002.json
```

Merge semantics:

- `meta` updates key by key
- `findings` and `commitments` match by `id`: a known record is updated key by
  key (so a later fragment can add just `validation` to `PV-003`), a new one is
  appended. Duplicate IDs within one fragment are refused
- `perspectives` match by `name` and replace the whole entry. Duplicate names
  within one fragment are refused; a later fragment can still replace an entry
- `checked_ok`, `decisions`, `limitations` and `next_steps` append without
  duplicates

Every merge validates the combined record; a refused merge writes nothing.
Each finding must be complete in the fragment that first adds it. Report
prose, including analysis results, commitments, perspective notes and the
top-level text lists, is checked for e-mail addresses (other than
`example.com`, `example.org`, `example.net` or the `.example`, `.test`,
`.invalid` domains) and runs of 12 or more digits, including space- or
hyphen-separated digits and numbers next to punctuation. Name fields and use
placeholders.

Only the fields documented below are accepted, at every object level: `meta`,
findings, validation, analysis, references, commitments and perspectives.
Unknown fields are refused instead of silently retaining unexamined values in
`findings.json`. Error messages identify the object or field and its expected
shape without echoing submitted values or unknown key names.

Record collections and `references` must be JSON arrays. Finding and commitment
IDs, and perspective names, must each be unique in the combined record. Optional
text fields must be strings when present; omit an unused field rather than
setting it to `null` or an object. `inferred`, when present, must be a boolean.

Recognised hexadecimal revisions in `meta.commit` and the line-number suffix
of a validated `location` are treated as technical identifiers. The location's
path and other report prose are still checked.

Report prose is rendered as literal text in Markdown: placeholders such as
`<email>`, table punctuation and line breaks are preserved. Commands use code
spans that preserve backticks, and HTTP(S) or relative reference links are
encoded separately; other URL schemes remain visible as text.

## Shape

```json
{
  "meta": {
    "project": "acme-shop",
    "scope": "API, web front end and mobile app",
    "commit": "3f2a9c1",
    "date": "2026-10-09",
    "assessor": "Claude Code (<model>)",
    "method": "Static review",
    "lang": "en"
  },
  "commitments": [
    {"id": "C-01", "statement": "No personal field is sent to error tracking",
     "source": "web/src/legal/privacy.md:44", "family": "CONTAIN", "inferred": false,
     "status": "violated"}
  ],
  "findings": [
    {
      "id": "PV-001",
      "title": "Error tracker receives full request bodies including addresses",
      "severity": "High",
      "confidence": "Confirmed",
      "category": "Logs, telemetry and errors",
      "step": "LT2",
      "location": ["api/app.py:22", "api/checkout/views.py:40"],
      "data": "shipping_address, phone, email (contact)",
      "subjects": "Every customer who checks out and hits an error",
      "flow": "1. POST /api/checkout collects shipping_address and phone (api/checkout/views.py:40). 2. An exception is raised. 3. The error tracker is initialised with send_default_pii=True and request bodies on (api/app.py:22). 4. The body is sent to the error tracker",
      "contrast": "worker/app.py:15 initialises the tracker with PII off and a before_send scrubber",
      "impact": "Expected (C-01): no personal field reaches error tracking. Actual: addresses and phone numbers of affected customers are stored by the error tracking vendor",
      "commitment": "C-01",
      "fix": "Turn PII and request bodies off in api/app.py:22 and reuse the worker's before_send scrubber",
      "guard": "Test raises an error in checkout with synthetic data and asserts the captured event has no body or user fields",
      "validation": {"verdict": "Valid", "method": "static",
                     "evidence": "api/app.py:22 send_default_pii=True, max_request_body_size='always'"},
      "status": "Open"
    }
  ],
  "perspectives": [
    {"name": "Logs, telemetry and errors", "status": "applied", "note": "LT2 via C-01; LT1, LT3, LT4 applied"}
  ],
  "checked_ok": ["Account deletion cascades to orders, messages and files (api/accounts/delete.py:30)"],
  "decisions": ["Confirm whether the support chat vendor is a listed sub-processor"],
  "limitations": ["Not legal advice", "Vendor-side settings and contracts were not observed"],
  "next_steps": ["Fix PV-001, then add the error-capture test"]
}
```

## Field rules

| Field | Rule |
|---|---|
| `meta.project`, `scope`, `date`, `assessor`, `lang` | Required for `check` and `render`. `lang` is `ja` or `en`. `commit` is the assessed revision (`git rev-parse --short HEAD`, read-only) |
| `meta.commit`, `meta.method` | Optional strings: the assessed revision and review method |
| `findings[].id` | `PV-001`…, gapless, numbered in severity order (excluded verdicts may sit anywhere) |
| `severity` | `High`, `Medium`, `Low`, `Info` (`SKILL.md` table) |
| `confidence` | `Confirmed` (follows from the code), `Environment-dependent` (needs a named runtime setting), `Suspected` |
| `category` | One perspective name from `reference/perspectives.md`, exactly |
| `step` | Optional hunt step ID (`LT1`…) |
| `location` | A `path:line` (or `path:start-end`) string, or a list of them |
| `title`, `data`, `subjects`, `flow`, `impact`, `fix`, `guard` | Required nonblank strings (`reference/commitments.md` §5); no personal data values |
| `contrast`, `commitment` | Optional strings: the flow that keeps the commitment; the ledger ID |
| `validation.verdict` | `Valid`, `Likely`, `Unverified`, `Unlikely`, `FalsePositive`, `NotApplicable`; the definitive three need `evidence` |
| `validation.evidence` | A nonblank string for `Valid`, `FalsePositive` and `NotApplicable`; an optional string for other verdicts |
| `validation.method` | `static` or `analysed`; `analysed` requires `analysis` |
| `analysis` | `{tool, command, result}`, nonblank, from a read-only analysis of source; validated whenever present, and required for `analysed` |
| `status` | `Open` (default), `Fixed`, `Accepted` |
| `references[]` | `{title, url}`; `url` is a nonblank string, `title` is an optional string (defaults to the URL) |
| `commitments[]` | `id` (`C-01`…), `statement`, `source`, `status` (`holds`, `violated`, `partly read`, `not checked`); a `not checked` commitment needs `reason`, shown in both reports. `family` (string) and `inferred` (boolean) are optional; `inferred: true` is labelled in both reports |
| `perspectives[]` | `name` (exact), `status` (`applied`, `N/A`, `not checked`), `note` (steps applied, steps left out with reasons) |
| `checked_ok`, `limitations` | Required nonempty for `check`; `decisions`, `next_steps` optional |
