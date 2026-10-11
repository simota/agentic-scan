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
embedded as a short excerpt (never from secret-looking files; secret-looking
lines are masked). Every page is stamped with the SHA-256 of the
`findings.json` it shows; `contract_check.py` rejects stale pages.
Exit 3 means no PDF: no engine found, an engine that failed, or a timeout —
the message says which. `UX_SCAN_PDF_TIMEOUT` overrides the engine's timeout in
seconds for the one retry SKILL.md allows. For a requester language other than
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
