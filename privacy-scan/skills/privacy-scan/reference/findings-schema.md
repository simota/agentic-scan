# Findings file — the single source for every output

**Read when:** REPORT, before producing the dashboard and the report. Write the
results to `findings.json` once; the dashboard, `report.md` and the chat
summary use the same recorded facts.

Render with (paths relative to this skill's directory):

```
python3 scripts/findings.py renumber <out>/findings.json   # after the last merge
python3 scripts/render.py <out>/findings.json --out <out> --lang <ja|en>   # --lang defaults to meta.lang
python3 scripts/findings.py check <out> [--allow NAME]...   # one --allow per name
```

The scripts use only the standard library and also run under `python3 -I`.
`render.py` writes `<out>/dashboard.html` (self-contained, works offline,
filter by severity, styled by the vendored scan-report-kit in
`scripts/scan_report_kit/`) and `<out>/report.md`. Exit codes: `0` written, `1` an
output could not be saved, `2` the record does not match the shape (the field
is named) or the command line is invalid. `render.py` still renders a draft
that `check` would refuse, and prints each such problem on stderr as a warning. `findings.py check` exits `1`
and lists every contract violation, except that when `findings.json` fails the
schema it reports only the first schema error and skips the record checks, so
fix it and run `check` again. This is the complete list; other documents
point here. `check` refuses an output directory unless:

- it holds exactly `findings.json`, `dashboard.html` and `report.md` (plus
  `--allow` names), each a readable, nonempty file (directories and broken
  links do not qualify), and no staging file left by an interrupted write
- `findings.json` passes the schema below with every required `meta` field
  (`project`, `scope`, `date`, `assessor`, `lang`)
- IDs are `PV-001`… without gaps; reported findings (not `FalsePositive` or
  `NotApplicable`) are in severity order, then by their first location's path,
  and excluded findings follow them, by path (the order `renumber` produces)
- no two reported findings share their first `location` (one per fix location)
- a nonblank `step` is one of the hunt step IDs that `reference/perspectives.md`
  lists under `category` (`LT1`…`LT4` under Logs, telemetry and errors)
- an `Environment-dependent` reported finding names its `conditions`
- every reported High and Medium finding has nonblank `validation.evidence`,
  whatever its verdict (for `Likely` or `Unverified`, the hop not yet read)
- a `commitment` that is a ledger ID (`C-01`…) exists in `commitments`
- every perspective is recorded, and reported findings sit only under one
  recorded as `applied` or `partly applied`
- each `not checked` commitment has a nonblank `reason`
- `checked_ok` and `limitations` are nonempty
- `report.md` and `dashboard.html` are exactly what `render.py` produces from
  the current `findings.json` in one language

Run `renumber` and then `render.py` after the last merge.

Both reports include counts for every verdict, including zero counts, alongside
the severity counts. Collapsed HTML findings also show their recorded verdict.

Both report contents are generated and UTF-8 encoded before writing starts.
The scripts stage all output bytes in temporary files alongside their destinations
before replacing existing files. Encoding or staging failures preserve the previous
outputs and remove staging files. Each final replacement is atomic; replacing
multiple output files is not a single transaction.
Inputs (fragments, the record) must be regular files of at most 16 MiB; a FIFO
or device is refused instead of blocking. A command stopped by SIGTERM (for
example a tool timeout) removes its staging files; if a hard kill leaves one,
`check` names it as a stale staging file to delete rather than an extra output.
Existing destination symlinks are retained and their target files are updated.
Replaced files keep their permissions; newly created files are readable by
their owner only (`0600`), because the record and reports describe where
personal data goes.
Before staging, the renderer rejects output paths that resolve to the input
record or to each other. A rejected collision preserves the input, existing
outputs and links.

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
  key (so a later fragment can add just `validation` to `PV-003`), and its
  nested `validation` and `analysis` objects merge key by key as well (a
  fragment can change just `validation.verdict`); a new one is
  appended. Duplicate IDs within one fragment are refused
- `perspectives` match by `name` and replace the whole entry. Duplicate names
  within one fragment are refused; a later fragment can still replace an entry
- `checked_ok`, `decisions`, `limitations` and `next_steps` append without
  duplicates

Every merge validates the combined record; a refused merge writes nothing.
Validation runs once per `merge` command, after all of its fragments are
applied, so a new finding must be complete by the end of the command that first
adds it; write each new finding whole in one fragment. Strings must
be valid UTF-8 text; unpaired Unicode surrogates are refused before saving. Report
prose (every text field, including analysis results, commitments, perspective
notes, top-level lists, location paths and reference URLs) is refused when it
contains an e-mail address outside the reserved example domains (`example.com`,
`.org`, `.net`, `.example`, `.test`, `.invalid`) or a run of 12 or more digits,
including spaced, dashed, encoded and invisibly split forms. Dates, UUIDs and
hex digests are not counted. The checks run on a temporary copy; accepted text
keeps its spelling. Name fields and use placeholders; the full rules are in the
docstring of `scripts/findings.py`. A source path whose name holds a long
number, such as a timestamped migration, is accepted only in `location` and
only as a compact date-time at the start of a segment
(`db/migrate/20261009123045_add_phone.rb:3`, Flyway's `V20261009123045__…`).
In prose, and for other shapes (an epoch-millisecond prefix), write the path
with a placeholder, `db/migrate/<timestamp>_add_phone.rb:3`, and use the same
spelling in `location` when it is refused there.

To correct a finding, merge a fragment with its `id` and the changed keys.
`null` is refused, so clear an optional text field (`conditions`, `contrast`,
`step`, `commitment`) by setting it to `""`: blank fields are not shown. An
`analysis` object cannot be removed by a fragment; when it no longer applies,
rewrite its `result` to say so.

Only the fields documented below are accepted, at every object level: `meta`,
findings, validation, analysis, references, commitments and perspectives.
Unknown fields are refused instead of silently retaining unexamined values in
`findings.json`. Error messages identify the object or field and its expected
shape without echoing submitted values or unknown key names.

Record collections and `references` must be JSON arrays. Finding and commitment
IDs, and perspective names, must each be unique in the combined record.
Both reports carry a fixed line stating that the review is technical and not
legal advice. Optional
text fields must be strings when present; omit an unused field rather than
setting it to `null` or an object. `inferred`, when present, must be a boolean.

Recognised hexadecimal revisions in `meta.commit` and the line-number suffix
of a validated `location` are treated as technical identifiers. The location's
path and other report prose are still checked.

Report prose is rendered as literal text in Markdown: placeholders such as
`<email>`, table punctuation and line breaks are preserved. Both reports show
every line boundary the long-number check treats as one (CR, LF, vertical tab,
form feed, `\x1c`–`\x1e`, NEL, U+2028, U+2029) as a line break. Commands use code
spans that preserve backticks, and HTTP(S) or relative reference links are
encoded separately; other URL schemes remain visible as text. In the HTML
dashboard, commands use preformatted code blocks that preserve line breaks and
indentation. Table headers follow the report language; in Japanese reports perspective
names, perspective and commitment statuses and finding statuses are shown in
Japanese (perspective names keep the English name used in `category`), while
severity, confidence and verdict names stay as recorded. Perspectives are listed
in the order of `reference/perspectives.md`, blank optional fields add no row,
a blank reference `title` shows the URL, and a blank `meta.commit` shows
`UNKNOWN`. HTTP(S) and `www.` URLs written in prose become explicit Markdown
links (also directly after Japanese text, and with an upper-case scheme), so
renderers that link bare URLs do not keep escape characters in the target;
`ftp://` URLs, and URLs not linked this way (a `www.<placeholder>`, a dotless or
non-ASCII host), stay literal text rather than links that keep escapes. A `!`
before a URL stays text and never makes the link an image. Prose in a reference
whose URL is not linked is treated the same way. Excluded findings (`FalsePositive`,
`NotApplicable`) are labelled in both reports and have their own dashboard
filter instead of appearing under their severity; a filter that matches nothing says so. Dashboard cells wrap
long paths and keep line breaks.

## Shape

Abbreviated: `check` also needs all twelve perspectives, and a real record
usually holds several findings and commitments.

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
      "guard": "Guard for C-01: test raises an error in checkout with synthetic data and asserts the captured event has no body or user fields",
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
| `meta.project`, `scope`, `date`, `assessor`, `lang` | Required for `check` and `render`. `lang` is `ja` or `en` |
| `meta.commit`, `meta.method` | Optional strings: the assessed revision (`git rev-parse --short HEAD`, read-only) and review method. A nonblank `method` is shown in both reports, including when there are no findings; otherwise the renderer uses its default method description |
| `findings[].id` | `PV-001`…, gapless, numbered in severity order, then by first location's path (`renumber`); excluded verdicts come last, by path |
| `severity` | `High`, `Medium`, `Low`, `Info` (`SKILL.md` table) |
| `confidence` | `Confirmed` (follows from the code), `Environment-dependent` (needs a named runtime setting), `Suspected`. Confidence says how the claim follows from the code; the verdict says how far its verification got, so `Confirmed` with `Likely` means the code shows the gap but a hop was not traced. An excluded finding keeps the severity it would have had |
| `category` | One perspective name from `reference/perspectives.md`, exactly |
| `step` | Optional hunt step ID (`LT1`…), shown after the perspective in both reports. `check` requires a step listed under `category` (`LT1`…`LT4` under Logs, telemetry and errors) |
| `location` | A `path:line` (or `path:start-end`) string, or a list of them. Paths may contain spaces; colons and control characters are not allowed, so `path:line:column` is refused (drop the column) and a colon in a file name is written as a placeholder (`app/routes/<colon-name>.tsx:12`). When the fix is a file that does not exist yet, use `path:0` for the file to create and say so in `fix` |
| `title`, `data`, `subjects`, `flow`, `impact`, `fix`, `guard` | Required nonblank strings (`reference/commitments.md` §5); no personal data values. `fix` and `guard` may be omitted for `FalsePositive` and `NotApplicable` |
| `conditions` | Optional string: the runtime settings the grade assumes. `check` requires it for an `Environment-dependent` finding that is not excluded |
| `contrast`, `commitment` | Strings the schema treats as optional but `SKILL.md` expects on every finding: the flow that keeps the commitment at `path:line` (or `none`); the ledger ID. `check` reports a ledger ID that is not in `commitments` |
| `validation.verdict` | `Valid`, `Likely`, `Unverified`, `Unlikely`, `FalsePositive`, `NotApplicable`; the definitive three need `evidence` |
| `validation.evidence` | A nonblank string for `Valid`, `FalsePositive` and `NotApplicable`, and for every reported High and Medium finding (`check`); an optional string otherwise |
| `validation.method` | `static` or `analysed`; `analysed` requires `analysis` |
| `analysis` | `{tool, command, result}`, nonblank, from a read-only analysis of source; validated whenever present, and required for `analysed` |
| `status` | `Open` (default), `Fixed`, `Accepted` |
| `references[]` | `{title, url}`; `url` is a nonblank string, `title` is an optional string (defaults to the URL) |
| `commitments[]` | `id` (`C-01`…), `statement`, `source`, `status` (`holds`, `violated`, `partly read`, `not checked`); a `not checked` commitment needs a nonblank `reason` to pass `check`, shown in both reports; `reason` may also explain any other status. `family` (string, shown in both reports; name several families as `CONTAIN, SHARE` when a commitment spans them) and `inferred` (boolean) are optional; `inferred: true` is labelled in both reports |
| `perspectives[]` | `name` (exact), `status` (`applied`, `partly applied`, `N/A`, `not checked`), `note` (steps applied, steps left out with reasons; for `partly applied`, which steps were not reached) |
| `checked_ok`, `limitations` | Required nonempty for `check`; `decisions`, `next_steps` optional |
