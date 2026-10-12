# Report

**Read when:** CHECKLIST, when only a checklist was asked for; REPORT — rendering and writing the chat summary.

```sh
python3 <skill-dir>/scripts/render.py <out>/findings.json --out <out> --lang ja|en --repo <repo> [--no-pdf]
python3 <skill-dir>/scripts/contract_check.py <out> [--no-pdf]
```

`<skill-dir>` is the directory holding SKILL.md; never run a same-named script
from the reviewed repository (SKILL.md *Paths*).

`render.py` maps `findings.json` into scan-report-kit's common format
(`scan-report/1`) and writes `dashboard.html`, `report.html` and `report.pdf`
in the shared design. Each finding shows its flow (from `flows.json`), screen,
viewport and criterion. With `--repo`, each finding's first `path:line` is
embedded as a short excerpt: at most 40 lines and 240 characters per line,
from a UTF-8 file no larger than 2 MiB. Files outside the repository, binaries,
symlinks (including directory links), and secret-looking paths are omitted;
secret-looking assignment lines are masked in full. These name and text rules
are conservative heuristics, not a complete credential audit. Report text and
source excerpts remain escaped text in the HTML. `--out` must resolve outside
`--repo`, which must name an existing directory.
Excerpt reads are anchored to the selected repository with descriptor-relative
no-follow operations, so a directory replacement cannot redirect them outside
that root. On platforms without these operations, excerpts are omitted;
record that limitation if source excerpts were needed.

Both HTML pages record the SHA-256 of the exact `findings.json` bytes and the
canonical JSON contents of `flows.json`. They also share a render identity
covering the language, rendered data including excerpts, and both generated
HTML pages before stamps are added. Renderer or style changes therefore
invalidate mixed pages even when the findings are unchanged. After PDF
generation succeeds, both pages record the PDF's SHA-256. The PDF must have a
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
publication starts, the previous PDF is removed, so a failed run cannot leave
it beside newer HTML. An interrupted run can leave an incomplete set of
outputs: fix the reported error, rerender and pass the contract checker before
sharing the report.

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

Satisfy SKILL.md *Done when* first. First line: status and counts, e.g. `ux-scan complete: 5 High, 10 Medium,
6 Low (21 open) across 5 flows; both primary flows blocked`. Then:

- the High findings, one line each with `path:line` and the flow they block
- decisions that need a human (`decisions`)
- what was not reviewed (`limitations`), in one line
- where the outputs and the scratch directory are
