# Report design direction

Status: decided 2026-10-11; moved to the shared format 2026-10-12. Applies to
`report.html` / `report.pdf` and `dashboard.html` rendered by
`skills/prompt-scan/scripts/render.py`.

The visual system — security-scan's "journal of record": serif text in one
face for both scripts, sans for labels, monospace for IDs, paths and prompt
text, numbered sections, captioned booktabs tables and listings, colour only
for severity — is the shared format of every *-scan skill. It lives in the
[scan-report-kit](https://github.com/simota/scan-report-kit) repository (its
design document is `design.md` under that repository's docs directory), next
to the stylesheets it governs.

## How prompt-scan uses it

- `skills/prompt-scan/scripts/scan_report_kit/` is a vendored copy of the kit
  (stylesheets, PDF engine, safe writes). `make check` fails if it is edited in
  place; change the kit upstream, then run its
  `make vendor DEST=<this repo>/skills/prompt-scan/scripts`.
- `render.py` inlines the shared stylesheets first and appends only the rules
  for prompt-scan record types: `REPORT_CSS` (the severity-by-kind counts
  table, the prompt inventory and eval-run tables, the kind label,
  before/after proposals) and `DASH_CSS` (decisions panel, verify-first
  legend, paired counts on the closed card, earlier-validation history, and
  proposal text that wraps as in the report while source excerpts keep the
  kit's sideways scroll).
- The running footer and the report kicker are `PROMPT REVIEW` (ja
  `プロンプト診断`), passed to `document_css()` from the `running_footer` label.
- The PDF engine is the kit's (`PROMPT_SCAN_PDF_TIMEOUT` overrides its
  timeout); engine stderr is masked with `excerpt.mask` (`skills/prompt-scan/scripts/excerpt.py`)
  before it is reported.

## Readers

- **Prompt owners and engineers** fixing findings: need the location, the
  cause and a proposal they can paste
- **Product owners** deciding priority: need the counts by kind and severity
  and the decisions the review leaves to them
- **Reviewers** checking the claims: need verdicts, evidence and excerpts at
  the reviewed revision

## prompt-scan decisions on top of the shared format

- **Kind is a label, not a colour**: defect and improvement are told apart by a
  bordered label so severity keeps the only colour channel
- **Counts by severity and kind**: Table 1 crosses the two, instead of the
  kit's one-row metrics table
- **Proposals side by side**: current and proposed text in two columns, so the
  change is visible without a diff tool (one column on narrow screens)
- **Excerpts as the kit's listings**: numbered lines, the cited range
  highlighted, masked before rendering
- **Dashboard in the kit's vocabulary**: masthead, summary banner, count
  cards, "Start here" queue, coverage panel, charts, the filterable findings
  register (`table.register`) and "Copy for LLM"; defect and improvement take
  the place of security-scan's application and dependency parts
- **Self-contained and offline**: no web fonts, no remote assets; the dashboard
  embeds its data as escaped JSON and follows the system dark mode
- **Order of sections**: summary, inventory, perspectives, checked and sound,
  findings, eval runs, decisions, limitations, next steps — the reader sees
  what was looked at before what was found
