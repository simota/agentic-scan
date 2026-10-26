# ux-scan

An agent skill that reviews an app's **design, layout and UI/UX** by reading
its repository — navigation, layout and grid, responsive behaviour, visual
hierarchy, components, interaction states, forms, feedback, microcopy,
accessibility, motion, internationalized layout and perceived performance —
and reports every place the interface gets in the way of a user's task.

Built on the method of [security-scan](https://github.com/simota/security-scan):
a fixed run contract, phases, perspectives with hunt steps, a severity table
decided before confidence, verdicts with falsification, one finding per fix
location, JSON fragments merged by a checker, and a dashboard plus a PDF report
rendered with the shared [scan-report-kit](https://github.com/simota/scan-report-kit) format.
Its layout mirrors the sibling [brand-scan](https://github.com/simota/brand-scan).

It is read-only and judges against a stated criterion, not taste: "the cards
feel cramped" is not a finding; "`.card` uses `padding: 13px` where the spacing
scale is 4/8/12/16" is. Brand voice and palette canon are brand-scan's.

```
RECON → FLOWS → CHECKLIST → REVIEW → VERIFY → REPORT
          │                                       │
   flows.json (primary tasks, screens,     findings.json ─→ dashboard.html
   token scales, viewports, locales)                     ─→ report.html / report.pdf
                                                          ─→ mockups.html (before/after, when asked)
          │
   inventory.py --flows ─→ inventory.json (candidates, never findings)
```

## Install

```sh
make link                 # symlink skills/ux-scan into Claude Code, Codex and Antigravity
make link AGENT=claude    # one host
make status
```

Then ask the agent, e.g. "ux-scan this repository" or "review the sign-up and
checkout UI for usability and accessibility problems". Add "with before/after
mockups" to get `mockups.html`, which compares each mocked finding as it is and
as its fix proposes.

## What it checks

| Family | Examples |
|---|---|
| Information architecture | Primary flows reachable from navigation, orphan routes, current location |
| Layout and grid / Responsive | Off-scale spacing, z-index conflicts, overflow, fixed widths at the smallest viewport, tap targets, zoom locks |
| Visual hierarchy / Components | Competing primary actions, type scale, design-system bypass, duplicate components |
| Interaction states / Forms | Focus visibility, pending and disabled states, labels, validation timing, input types and autocomplete, preserved input |
| Feedback / Microcopy | Loading, empty and error states, destructive actions without undo, actionable error text |
| Accessibility / Motion | Keyboard reach, focus management, accessible names, contrast, ARIA misuse, reduced motion |
| Internationalized layout / Perceived performance | Text expansion and truncation, RTL, skeletons, layout shift from unsized media |

The full list with hunt steps is `skills/ux-scan/reference/perspectives.md`.

## Scripts (standard library only)

| Script | Does |
|---|---|
| `scripts/inventory.py REPO --out inventory.json [--flows flows.json]` | Routes and orphan routes, token sources, spacing / type / breakpoint / z-index literals, fixed widths, tap targets, focus outlines, zoom locks, click handlers on non-interactive elements, images, inputs, icon-only buttons, missing state branches, destructive actions, motion, truncation, locale expansion; with flows, values off the token scales and widths beyond the smallest viewport |
| `scripts/findings.py flows\|merge\|check\|renumber` | Validate the flows and findings; merge JSON fragments atomically; renumber findings into severity order |
| `scripts/render.py findings.json --out DIR --lang ja\|en --repo REPO` | Dashboard, report and PDF via the vendored scan-report-kit, plus `mockups.html` (before/after mockups, side by side or under a slider) when findings carry a `mockup` |
| `scripts/contract_check.py OUT [--no-pdf] [--allow NAME]…` | Contracted outputs, valid records, every perspective family recorded, no `Unverified` finding, pages stamped with the current record; `--allow` (repeatable) admits an extra file, and an allowed `ja` or `en` directory must be a current second-language render; detects concurrent renders |

## Develop

Use Python 3.10 or later and GNU Make. The scan scripts have no third-party
Python dependencies. PDF output additionally needs Chrome/Chromium or WeasyPrint.

```sh
make test       # unit tests
make check      # tests + doc refs + skill consistency + sample inventory and render
make demo       # render the sample (examples/tasklane) with PDF into $TMPDIR/ux-scan-demo
make demo NO_PDF=1 # render HTML only, recording the limitation and checking the contract
make inventory TARGET=/path/to/repo FLOWS=flows.json OUT=inventory.json
```

Checkout, install and output paths are passed literally, including spaces,
quotes and shell metacharacters. `PYTHON` remains a shell command, so options
such as `PYTHON='python3 -B'` work; quote the interpreter path inside its value
when that path contains spaces, for example `PYTHON="'/path with spaces/python3' -B"`.
In Make variable values, write a literal dollar sign as `$$` because Make
expands `$` before invoking the shell. That includes values inherited from the
environment (`HOME`, `CODEX_HOME`, `AGY_HOME`, `TMPDIR`): when one of those
paths contains `$`, pass the path explicitly on the command line with `$$`
(`CODEX_HOME=…`, `SKILLS_DIR=…` or `DEMO_OUT=…`). The demo refuses output inside its
reviewed fixture before creating or overwriting any records. Demo inputs and
inventory flow definitions must also be distinct from their outputs, including
filesystem aliases; collisions fail before publication.

`make check` validates both English and Japanese sample output contracts,
including the no-PDF limitation from `examples/no-pdf.fragment.json`. It does
not require a browser. GitHub Actions runs it on Linux and macOS with Python
3.10 and 3.14, and separately renders both sample PDFs with Chrome.

Inventory output includes `parse_warnings` for inputs that could not be fully
measured; other files still get scanned. Review those warnings and `truncated`
counts before interpreting the results. The output contract also verifies the
complete HTML bytes, so older reports need to be rendered again after an upgrade.

Concurrent renders to one output directory are refused. The renderer keeps a
`.ux-scan-render-generation` file so the contract checker also detects renders
that start and finish during verification. Keep it with the report outputs;
recovery and compatibility details are in `skills/ux-scan/reference/report.md`.

`skills/ux-scan/scripts/scan_report_kit/` is a vendored copy of
scan-report-kit; `make check` verifies it against its MANIFEST. Change it
upstream and re-vendor (`make vendor DEST=<this repo>/skills/ux-scan/scripts`
in scan-report-kit), never in place.

`examples/tasklane/` is a fictional app with deliberate UX defects; the sample
flows and findings in `examples/` describe it and are not a review of any real product.
