# Pattern 09: Research Notebook and Reasoning Log (`09-research-notebook.html`)

## Concept
Present the agent's static review as a notebook of observations and experiments that readers can review, using a primarily 1-column layout. Start with run conditions styled as YAML front matter. Follow the cell numbers in the gutter from `CELL [01]` to `CELL [04]` through the summary → findings index → reasoning steps (trace, falsification, impact, and fix direction) → limits of observation.

## Why It Fits agentic-scan
- **Closest to 「読んで、反証してから、渡す」**: The design foregrounds the reasoning sequence `TRACE → VERIFICATION → IMPACT → REMEDIATION`. It follows the LP's emphasis on 「裏の取れた指摘」 and its practice of retaining `FalsePositive` entries (rejected hypotheses).
- **A scholarly tone with restrained dashboard styling**: Monospace cell labels and YAML blocks carry the brand. Japanese evidence uses a legible sans-serif with ample line spacing (1.75), making lengthy verification evidence and constraints easy to read closely.

## Adapting It to Other Skills
- **Easy to adapt the reasoning steps**: Match each cell's `<ol class="step-list">` to the skill's stages.
  - `logic-scan`: `STEP 01 業務ルール` → `STEP 02 反例（Counterexample）` → `STEP 03 影響と修正`
  - `bug-scan`: `STEP 01 履歴の起源` → `STEP 02 現行コードの同型経路` → `STEP 03 再現手順と修正`
  - `architecture-scan`: `STEP 01 期待される境界` → `STEP 02 実際の依存` → `STEP 03 改善方針`
  - `ux-scan`: `STEP 01 対象フロー・画面` → `STEP 02 阻害要因` → `STEP 03 改善案`
- **Aligning multiple reports**: The print document (`assessment.html`) and dashboard can use nearly identical visual structures by expanding all findings in `CELL [03]`.

## Changes and Estimated Effort for the Existing `render.py` and `dashboard.css`
- **Scope of changes**:
  - `dashboard.css` / `document.css`: Remove the existing 2-column layout (sidebar and main content) or replace the left sidebar with a narrow cell gutter (`7.5rem`). Adopt the LP's cool gray, monospace, and sans-serif styles.
  - `render.py`: Wrap the `location` / `evidence` / `impact` / `fix` / `previous_validation` fields from the existing `card()` (`assessment.html`) and expandable detail rows (`dashboard.html`) in `<ol class="step-list">`. The existing filter UI fits inside `CELL [02]`.
- **Estimated effort**: Small to medium (0.5–1 day per skill). It is among the lowest in total maintenance cost because it can readily share components with the print `assessment.html`.

## Limitations
- **Limited overview and side-by-side comparison**: A vertical 1-column layout requires more scrolling than multi-column designs (08 and 10) to see concentrations by severity or across categories at a glance, or to triage many findings at once.
- **Limited room for persistent search and filters**: To keep many filter criteria pinned on screen, add a collapsible filter bar at the top of `CELL [02]`.
