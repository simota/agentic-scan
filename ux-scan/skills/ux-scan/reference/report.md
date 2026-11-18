# Report

**Read when:** CHECKLIST, when only a checklist was asked for; REPORT — rendering and writing the chat summary.

```sh
python3 <skill-dir>/scripts/render.py <out>/findings.json --out <out> --lang ja|en --repo <repo> [--no-pdf]
python3 <skill-dir>/scripts/contract_check.py <out> [--no-pdf] [--allow <lang>]
```

`--allow ja` or `--allow en` names a second-language render in `<out>/<lang>`
(SKILL.md *Independence*); the checker requires it to be current.

`<skill-dir>` is the directory holding SKILL.md; never run a same-named script
from the reviewed repository (SKILL.md *Paths*).

`render.py` maps `findings.json` into the bundled report kit's common format
(`scan-report/1`) and writes `dashboard.html`, `report.html` and `report.pdf`
in the shared design, plus `mockups.html` when a `Valid` or `Likely` finding carries a
before/after mockup (`reference/mockups.md`); a render without one removes a
previous `mockups.html`. When findings cite evidence, it also writes
`evidence.html` and places each finding's screenshots and log excerpts (masked
like source excerpts) in `report.html` and so in the PDF, `before` and `after`
side by side; videos are named there and play in `evidence.html`
(`reference/evidence.md`). Every page records the SHA-256 of each cited file, so
a replaced or missing file makes the pages stale. Each finding shows its flow (from `flows.json`), screen,
viewport and criterion, and both pages state the viewports and locales from
`flows.json` that the review was judged against. With `--repo`, each finding's first `path:line` is
embedded as a short excerpt: at most 40 lines and 240 characters per line,
from a UTF-8 file no larger than 2 MiB. Files outside the repository, binaries,
symlinks (including directory links), and secret-looking paths are omitted;
lines that hold a secret are masked in full (`scripts/secret_lines.py`): known
credential formats (provider token prefixes, JWTs, PEM and PGP private-key
blocks found anywhere in the file, credentials in URLs including
`redis://:password@host`, command lines including `--password value` (quoted
too, or on the next line after `\`, but not `"$PASSWORD"`) and `curl -u` or
`--user user:password`, bearer
and basic authorization values), and secret-like names (password, secret,
token, API key, credentials…, also after acronyms, inside upper-case names
and at the end of lower-case ones: `DBPassword`, `DBPASSWORD`, `mypassword`,
`SECRET_KEY_BASE`) assigned a literal that is not a label. That includes
short values, passphrases with spaces, typed declarations
(`password: string = "…"`), subscripts (`settings["password"] = "…"`), compound assignments (`||=`,
`??=`, `&&=`), the `value` or
`defaultValue` of a field whose `name` is secret-like, before or after other
attributes of its tag (a `label`, `id` or `type="password"` does not count), literals passed to a call or wrapped in
delimiters (`String("…")`, `(("…"))`, also inside `{…}`), fallbacks after a
reference (`process.env.X || "…"`, `??`, `or`; ternary branches are not read), including a lookup that names the
secret itself (`process.env.DB_PASSWORD || "…"`, `os.getenv("API_TOKEN") or "…"`; not `PASSWORD_RESET_URL`), values wrapped onto a later line after
`=` or an operator (or a secret-named field's attributes continuing there) (comment lines between are skipped), and literals left open or cut off by the 752-character limit. Labels such
as "Password", "Enter your password" or "パスワード", types, code expressions
and references (`process.env.X`, `auth.currentPassword`) and booleans stay visible,
since forms and locale files are what UX findings cite. In configuration files
(`.properties`, `.env`, `.ini`, `.cfg`, `.conf`, `.toml`, YAML) and on `NAME=value`
lines every bare value is a literal (`password = Sommer.x`), as is an upper-case `NAME=value` pair elsewhere on a
line (`ENV DB_PASSWORD=…`, `docker run -e API_TOKEN=…`; not a keyword argument or attribute inside an open
`(` or tag, such as `Client(TOKEN=auth.token)`) and a value with a
digit in its root (`Pa55.word`). A secret-named YAML block scalar (`password: |`, `>-`, also after a tag or anchor such as `!!str |`) is masked with every more
indented line of its value, even when the excerpt starts inside it. In code a digit-free bare identifier is a
reference (`password = currentPassword`), and `$VAR` / `${VAR}` stay visible as variables when they are the whole value (a `${VAR:-default}` default is
judged as a value; text joined to the variable, such as `${VAR}"x"`, or in configuration anything but a `#` comment after it, makes a literal). Each line is judged on
the shown text plus 512 characters after it, so a credential cut off at the
limit is masked too. These rules are conservative heuristics, not
a complete credential audit. Report text and
source excerpts remain escaped text in the HTML. `--out` must resolve outside
`--repo`, which must name an existing directory. The findings input must not
occupy any generated output path, including through a directory symlink or hardlink;
collisions are rejected before any output is changed.
Excerpt reads are anchored to the selected repository with descriptor-relative
no-follow operations, so a directory replacement cannot redirect them outside
that root. On platforms without these operations, excerpts are omitted;
record that limitation if source excerpts were needed.

Every HTML page (both, or all three with `mockups.html`) records the SHA-256 of the exact `findings.json` bytes and the
canonical JSON contents of `flows.json`. They also share a render identity
covering the language, rendered data including excerpts, and both generated
HTML pages before stamps are added. Renderer or style changes therefore
invalidate mixed pages even when the findings are unchanged. After PDF
generation succeeds, every page records the PDF's SHA-256. The PDF must have a
PDF header and an end-of-file trailer; this catches empty or visibly truncated
engine output, but does not validate the full PDF syntax or visual layout.
Each page also fingerprints its complete UTF-8 HTML bytes, omitting only its
single `ux-scan-page` metadata tag in the renderer's exact format. The checker
requires that tag once in the head and rejects missing, malformed or duplicate
fingerprints, truncated pages, and changes to their markup, styles or scripts.
The sealed head also contains exactly one `ux-scan-page-kind` metadata tag,
whose value must match the output filename (`dashboard.html` or `report.html`).
Copying one page over the other or swapping their filenames fails the check.

`contract_check.py` rejects stale findings or flows, mixed render versions,
replaced PDFs, and an inventory whose `flows_sha256` does not match the current
flows. Rerun the inventory after changing flows, then render after the last
record or flow change. Older outputs missing any required fingerprint or page
kind, including the complete-page fingerprint, must be regenerated. The checker reads
actual metadata in the HTML head;
stamp-like comments or report prose do not satisfy the contract. These hashes
track consistency between local outputs; they are not signatures that prove
who created the files, and they do not detect later repository edits without
a fresh review and render.

Exit 2 means invalid input or an output I/O failure. Input records and required
outputs must be regular files; symlinks, directories and FIFOs are refused.
Validation and output-target checks happen before publication. Once HTML
pages are ready, they are staged and published together with removal of the
previous PDF. A staging or publication failure restores the previous pages
and PDF together. The pages' PDF fingerprints are likewise published as a
pair after the PDF succeeds; if that publication fails, the new PDF is removed
and both current HTML pages remain ready to print without PDF metadata.
If restoring files also fails, the error names the directory containing
recovery files. An interrupted run can still leave an incomplete set of
outputs: fix the reported error, rerender and pass the contract checker before
sharing the report.

Concurrent renders to the same output directory, including directory aliases,
are refused with exit 2. An empty `.ux-scan-render.lock` directory reserves the
outputs through HTML publication, PDF generation, metadata publication and
failure cleanup. Normal returns and Python exceptions remove the lock. A
forcibly terminated process can leave it behind: verify that no renderer still
uses that directory before removing the empty lock with the diagnostic's
`rmdir` command and rerendering. The contract checker checks for the lock at
both the start and end of verification and refuses locked outputs, including
when that name is passed through `--allow`.

The renderer also publishes a new `.ux-scan-render-generation` token under the
lock before changing any report files. It keeps this file after releasing the
lock, so the checker can detect a render that both starts and finishes during
verification. The checker reads the token before its first lock check and
compares it after its last lock check. If a render overlaps verification, wait
for that render to finish and check again. Keep the generation file with the
outputs; it is permitted without `--allow`. Older output directories without
one still work, but a malformed token or non-regular generation file is refused,
even with `--allow`. A generation-publication failure leaves the reports
unchanged; later report failures keep the new token so a concurrent check must
retry. A second-language directory passed with `--allow ja|en` gets the same lock
and generation checks.

Exit 3 means no PDF: no engine found, an engine that failed, a timeout, or
output that failed the PDF envelope check —
the message says which. Engine diagnostic text is withheld because it can echo
source or report data; the engine, failure category and timeout remain visible.
An engine's undecodable process output also returns exit 3 and removes any
partial PDF; it does not publish the raw diagnostic or a traceback.
`UX_SCAN_PDF_TIMEOUT` overrides the engine's timeout in
seconds for the one retry SKILL.md allows. With `--no-pdf`, the final record
must contain `report.pdf not produced: <reason>` with a non-empty reason and
the output directory must contain no PDF; `--allow report.pdf` does not waive
this requirement. For a requester language other than
`ja` or `en`, the prose is in their language and the labels are `--lang en`
(SKILL.md *Outputs* row).

## Checklist deliverable

When only a checklist was asked for: the stack, supported viewports and
locales, the design system sources and the flows (with what is `inferred`)
first; then one section per flow listing its screens in task order and the
applicable perspectives and hunt steps, each with the concrete files to read
and any inventory candidate marked `unverified`; then the perspectives judged
N/A with a reason; last, where to start and the one decision a human must make
(usually: confirm the primary tasks and supported viewports).

## Chat summary

Satisfy SKILL.md *Done when* first. First line: status and counts, e.g. `ux-scan complete: 6 High, 12 Medium,
5 Low, 2 Info (25 open) across 5 flows; both primary flows blocked`. The
status is `complete` when every flow and perspective family was reviewed, else
`partial` (the gaps are in `limitations`). Counts are by severity over included
findings (`FalsePositive` and `NotApplicable` left out), with Info counted;
`open` counts those with status `Open`. A primary flow is blocked when an
included High finding cites it in `flow_ref`, or cites the `shared` flow
(the shell or a shared component it uses). A missing PDF is reported in the
outputs line, not in the status. Then:

- the High findings, one line each with `path:line`, the flow they block and their evidence file
- whether the UI was rendered (screenshots or video) or the evidence is logs only
- which findings carry a mockup (`mockups.html`), and which visible High and Medium findings have none
- decisions that need a human (`decisions`)
- what was not reviewed (`limitations`), in one line
- where the outputs and the scratch directory are
