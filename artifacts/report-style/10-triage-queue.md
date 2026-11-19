# Pattern 10: Triage Queue (`10-triage-queue.html`)

## Concept
Focus the report on what readers do immediately after reviewing the results. Use a 4-lane Kanban board organized by action, with a ticket detail inspector. Automatically place all findings in 4 columns: `FIX NOW` (修正計画) / `VERIFY FIRST` (先に検証) / `CLOSED` (対応済・受容) / `EXCLUDED` (誤検知・除外). Select a card to review its evidence and copy it for an Issue or LLM from the inspector directly below.

## Why It Fits agentic-scan
- **A UI for 「決めるのは人です (`decide`)」**: The `fix_now` / `verify_first` / `excluded` classification already computed by `render.py` becomes the structure of the page itself, where it previously supported the findings table.
- **Connecting a trusted read-only scan to remediation**: The `r--` wordmark, cool gray background, and monospace IDs and paths reinforce the restraint of a scanner that leaves fixes to the user. Copying the selected ticket for an LLM or Issue takes 1 click, linking the read-only scan to the next phase of remediation.

## Adapting It to Other Skills
- **Per-skill mapping for the 4 lanes**:
  - `security-scan` / `infra-security-scan` / `privacy-scan`: `FIX NOW` / `VERIFY FIRST` / `CLOSED` / `EXCLUDED` (shared as-is)
  - `prune-scan`: `SAFE TO DELETE` (can be removed immediately) / `CHECK CALLERS` (verify call sites) / `KEEP` (retain) / `EXCLUDED`
  - `prompt-scan`: `DEFECT / FIX NOW` (defect) / `IMPROVEMENT` (improvement suggestion) / `VERIFY FIRST` / `EXCLUDED`
  - `ux-scan` / `performance-scan`: `HIGH IMPACT` / `VERIFY / MEASURE` / `ACCEPTED` / `EXCLUDED`
- **Category tags (`code` / `deps`)**: For other skills, reuse them with the target layer, screen, or module name.

## Changes and Estimated Effort for the Existing `render.py` and `dashboard.css`
- **Scope of changes**:
  - `render.py`: Split the existing `R.queue` (with `fix_now` / `verify_first` already determined) and `F` / `ALL` into 4 arrays for rendering. The Python data model needs almost no changes. Reuse the existing `action(f)` and `findingMarkdown(f)` copy function.
  - `dashboard.css`: Replace the existing `.priority-list` and `.tablewrap` with `.board` (4-column grid) and `.inspector` (detail panel), and adopt the LP's cool gray, monospace, and sans-serif styles.
- **Estimated effort**: Medium (1–1.5 days per skill). The JS copy feature and action classification already exist in `render.py`, so implementation risk is low.

## Limitations
- **Tall lanes with many findings (30 or more)**: When findings cluster in 1 lane, especially `VERIFY FIRST`, the Kanban column grows taller and takes more scanning and scrolling to reach the inspector below. For practical use, add in-lane scrolling or a search bar.
- **Card splits when printing to PDF**: The 4-column Kanban board does not fit the printed page. Fall back to 2 columns or the vertical list on the `assessment.html` side for print.
