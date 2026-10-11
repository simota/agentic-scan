# Report design direction

Status: decided 2026-10-11. Applies to `report.html` / `report.pdf` and
`dashboard.html` rendered by `skills/prompt-scan/scripts/render.py`.

## Readers

- **Prompt owners and engineers** fixing findings: need the location, the
  cause and a proposal they can paste
- **Product owners** deciding priority: need the counts by kind and severity
  and the decisions the review leaves to them
- **Reviewers** checking the claims: need verdicts, evidence and excerpts at
  the reviewed revision

## Decisions

- **Same visual system as security-scan's "journal of record"**: serif text in
  one face for both scripts (`Hiragino Mincho ProN`, `Noto Serif CJK JP`), sans
  for labels, monospace for IDs, paths and prompt text; numbered sections and a
  captioned counts table; colour only for severity
- **Kind is a label, not a colour**: defect and improvement are told apart by a
  bordered label so severity keeps the only colour channel
- **Proposals side by side**: current and proposed text in two columns, so the
  change is visible without a diff tool
- **Excerpts as rows**: one flex row per source line, number and text on the
  same line, the cited range highlighted
- **Dashboard identical to security-scan's**: the same stylesheet, masthead,
  summary banner, count cards, "Start here" queue, coverage panel, charts,
  filterable findings register and "Copy for LLM" button; defect and
  improvement take the place of its application and dependency parts
- **Self-contained and offline**: no web fonts, no remote assets; the dashboard
  embeds its data as escaped JSON and follows the system dark mode
- **Order of sections**: inventory, perspectives, checked and sound, findings,
  eval runs, decisions, limitations, next steps — the reader sees what was
  looked at before what was found
