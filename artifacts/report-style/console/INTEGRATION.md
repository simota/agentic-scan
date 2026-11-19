# console-triage Integration Guide

`console.css` and `console.js` are shared components. This guide explains how to integrate them into the reports for 12 skills (`dashboard.html` and `assessment.html` / PDF).

- security-scan is the reference implementation.
  - `console_lane()`, `console_model()`, `console_band_html()`, and `console_tiles_html()` in `security-scan/skills/security-scan/scripts/render.py`
  - `report_assets/console.{css,js}`
  - Tests in `security-scan/tests/test_console_report.py`
- The designs come from `../03-mission-control.*` and `../10-triage-queue.*`.
- Use the token values from `site/styles.css`.

## 1. Principles

- **Each skill assigns its own lanes.** `console.js` places a card in the lane keyed by the model's `finding.lane`. Call the existing priority and action logic in each skill's render.py to assign lanes (see the table below). Do not introduce new criteria.
- **Keep the existing outputs.**
  - Retain the findings table, filters, facets, copy for LLMs, priority list, cards, and the decisions and constraints sections.
  - Add the new layer above them.
  - Prefix all new classes with `cx-` to avoid collisions with existing classes such as `.card` / `.panel` / `.copy-finding`.
- **Keep the reports self-contained.** Use no external resources. Copy `console.css` / `console.js` to each skill's `report_assets/` and embed them inline. Keep the canonical files in `artifacts/report-style/console/`. Edit the canonical files first, then copy them to each skill again.

## 2. Normalized Model

render.py embeds the following model under the `console` key in the dashboard data JSON. The assessment generates static HTML from the same model.

```jsonc
{
  "meta": {
    "skill": "security-scan",        // next to the band wordmark
    "title": "<project>",            // the band h1
    "title_id": "cx-title",
    "context": ["2026-10-06", "<commit>", "<scope>", "read-only"],  // empty items are not shown
    "headline": "<one-sentence summary>"  // optional
  },
  "counts": {"open": 4, "closed": 2, "excluded": 1, "total": 7},   // band readouts
  "severities": ["High", "Medium", "Low", "Info"],                 // tile order
  "verdicts": [                                                    // verdict bar order
    {"key": "Valid", "label": "Valid", "tone": "strong|mid|hatch|weak", "excluded": false},
    {"key": "FalsePositive", "label": "FalsePositive", "excluded": true}   // excluded gets its own accent segment
  ],
  "lanes": [                                                       // array order = display order (numbered)
    {"key": "fix_now", "label": "FIX NOW / 修正計画", "note": "...", "tone": "high|medium|low|accent|muted|ink"}
  ],
  "perspectives": [{"name": "...", "result": "...", "note": "...", "tone": "high|...|muted", "on": true}],
  "findings": [{
    "id": "F-001", "severity": "High", "status": "Open", "status_label": "Open",
    "verdict": "Valid", "title": "...", "location": "src/a.py:42",
    "lane": "fix_now",               // one of lanes[].key (required)
    "open": true,                    // filled tile cell (open)
    "excluded": false,               // left out of the tiles / dashed card
    "anchor": "finding-1",           // # target of 「一覧で開く」 (Open in register; the existing row anchor)
    "tags": ["アプリケーション", "Confirmed"],   // chips on the card and in the inspector
    "where": [{"label": "場所", "value": "...", "mono": true}],   // inspector 1: 該当箇所 (Where; empty values are not shown)
    "evidence": {"text": "...", "method": "review", "notes": ["..."]},  // inspector 2: 根拠 (Evidence)
    "fix": "...",                    // inspector 3: 修正方針 (Fix direction)
    "guidance": "..."                // optional; what to do in this lane
  }],
  "labels": {"severity_h": "...", "copy": "...", "lane_empty": "...", "...": "..."}  // the cx_* labels with the cx_ prefix removed
}
```

- Tiles count only records with `excluded=false`. Draw 1 cell per record and fill cells for `open` records.
- The verdict strip chart counts `verdict` across all records.
- The inspector order is fixed: heading → 「該当箇所」 → 「根拠」 → 「修正方針」.
- Take all displayed strings from `labels`. Store ja / en in LABELS in render.py.

## 3. Integrating into dashboard.html

1. Copy `console.css` and `console.js` to `report_assets/`. Add loader functions (`report_style.console_css()` / `console_js()` in security-scan).
2. Concatenate the CSS **after** the existing dashboard.css and any skill-specific CSS. `console.css` remaps legacy token names (`--panel --text --soft --tint --warn --warn-line --serif`) to the brand values and sets `--appbar-h:0`.
3. Update the template.
   - Replace the existing appbar with the inverted band `<header class="cx-band">`. It contains `data-cx="ident"`, `<dl data-cx="readout">`, and `.cx-tools`. Move the existing `#theme` button and assessment link into `.cx-tools`.
   - Place `<div class="cx" id="console"><div class="cx-grid">` immediately before `.shell`. Add the following 4 elements inside it.
     - `section.cx-p.cx-sev[data-cx=severity]`
     - `.cx-ver[data-cx=verdicts]`
     - `.cx-cov[data-cx=perspectives]`
     - `section.cx-triage#triage` (containing `.cx-board[data-cx=board]` and `aside.cx-insp[data-cx=inspector]`)
   - Move the findings section (filters and table) to the start of `<main>`.
   - Move the existing h1 (project name) into the band. Keep 1 h1 on the page.
   - Add `#triage` to the navigation.
4. JS: Put `console.js` **at the start of the same `<script>` element** as the existing page script. Many tests require a fixed script count. Call it at the end of the existing IIFE as follows.

   ```js
   window.AgenticConsole.mount(D.console, {root: document,
     copy: function (card) { return copyText(findingMarkdown(findById(card.id))); }});
   ```

   - Reuse the existing Markdown function for LLM copy.
   - Use `cx_copy` for the button label and give it a different name from the existing `copy_llm`. With identical names, existing tests using `get_by_role(name=...)` match 2 elements.
5. Light and dark modes use the existing `data-theme` toggle. The dark block in `console.css` matches `:root:not([data-theme=light]):not(.cx-doc)` and `:root[data-theme=dark]:not(.cx-doc)`.
6. For print (`@media print`), force light values, stack the lanes in 1 column, put the inspector after the lanes with static positioning, and hide the tools and copy button.

## 4. Integrating into assessment.html / PDF

1. Add `<html class="cx-doc">` to disable dark tokens and always print in light mode. Concatenate `console.css` after document.css and any skill-specific CSS.
2. Place `console_band_html(cm, <report type name>)` at the start of `<body>`. Remove h1 / project from the existing report-header, leaving the kicker and metadata row. Place `console_tiles_html(cm)` immediately after the band. Both generate static HTML without scripts.
3. Stack the priority queue vertically in the same 4-lane order.
   - Place open lanes (FIX NOW / VERIFY FIRST in security-scan) inside `#priority-queue`. Use the existing per-part tables within each lane. The heading id is `priority-queue-<lane>-<part>`.
   - List CLOSED / EXCLUDED immediately afterward in `#closed-lanes` as simple lists with anchors.
   - The lane element id is `lane-<key>`.
   - Keep only open items in `#priority-queue`. Existing tests require Fixed items to stay out of the priority queue and expect 0 links when there are only closed items.
4. Keep the band and tiles inverted in the PDF using `print-color-adjust: exact`. Setting `text-transform: uppercase` on the report type's `.cx-kind` uppercases the extracted PDF text. This caused a security-scan PDF test failure, so the property is omitted.

## 5. Lane Names and Assignment Logic by Skill

Based on each skill's render.py as inspected on 2026-11-19. Line numbers are from that inspection.

| Skill | Assignment Source (Existing Logic) | Open Lanes (Key → Display Name en / ja) | CLOSED / EXCLUDED Source | Copy Function | Perspective Mapping |
|---|---|---|---|---|---|
| security-scan (integrated) | Use `action_kind()` via `report_model()["queue"]` | `fix_now` FIX NOW / 修正計画, `verify_first` VERIFY FIRST / 先に検証 | `status in (Fixed, Accepted)` / `verdict in EXCLUDED` | JS `findingMarkdown` | `category == perspective.name` (for indicators) |
| architecture-scan | `action(f)` render.py:952 (Valid and Confirmed yields fix_now). The queue in `html_priority` :1489 includes Open items that are outside the exclusions | `fix_now` Plan the fix / 修正を計画, `verify_first` Verify first / 先に検証する | `STATUSES` findings.py:92, `is_excluded()` :948 | Py `finding_markdown` :973 → `copy-data` | `category` (validated against PERSPECTIVES, findings.py:284) |
| bug-scan (`scan_report_kit/assets`) | There is no fix_now / verify_first distinction. `common_finding()` :67 adds `action={label:"Fix direction"}` if a fix direction exists and `closed()` is false. The kit orders findings by (status≠Open, severity) | **Undecided**: 2 lanes for fix direction present / absent, or 1 lane (OPEN) | `KIT_STATUS` :51 (Fixed/Verified→Fixed, Accepted→Accepted), `common.excluded()` | Kit `findingMarkdown` (dashboard.js:224) | `finding.pattern` → perspective name `<pattern> <name>` |
| data-integrity-scan | `action(f)` :692 | `fix_now` Ready to ship / すぐ適用できる, `pin_first` Stage the rollout / 段階的に適用する, `verify_first` Verify first / 先に検証する | STATUSES findings.py:91, `is_excluded` :689 | Py `finding_markdown` :714 | `category` |
| infra-security-scan | No action function or priority queue. `ordered()` :762 sorts by severity, then id | **Undecided**: Findings have no status, so CLOSED is always empty. F-* (review) / I-* (baseline) and `covered_by()` :768 exist and serve other purposes than action classification | No status / `EXCLUDED` :51 | Py `finding_markdown` :846 → `#md` | `category` = perspective name |
| logic-scan | `action(f)` :700 | `fix_now` Ready to fix / すぐ直せる, `pin_first` Coordinate the change / 影響先と合意して直す, `verify_first` Verify first / 先に検証する | STATUSES findings.py:91, `is_excluded` :697 | Py `finding_markdown` :722 | `category` |
| performance-scan | No action function. `finding_group()` :171 returns only excluded or a severity | **Undecided** (no action categories) | STATUSES findings.py:59 / `is_excluded` :167 | Py `llm_finding` :652 → `data-llm` | `category` |
| privacy-scan | No action function. Only severity and excluded | **Undecided** (no action categories) | STATUSES findings.py:77 / `findings.excluded()` :716 | **None** (omit the inspector's copy control) | `category` (validated against PERSPECTIVES) |
| prompt-scan | `action(f)` :713 in `dashboard_model()`. JS applies the same logic (:470) | `fix_now` / `verify_first` (same labels as security). Add `kind` ∈ {defect, improvement} as a tag | STATUSES :18 / EXCLUDED :20 in record.py | JS `findingMarkdown` :506 | No mapping (`category` is free text) |
| prune-scan | `act_now(f)` :287 and `subtraction_groups()` :294 | `now` 引き算 - 今すぐ削除, `reduce` 縮小・統合, `decide` 人が判断 (all existing labels :81 / :113). **Note**: Existing logic leaves `Unlikely` ungrouped | STATUSES findings.py:41 / EXCLUDED :43 | Kit `findingMarkdown` | `perspective` (step ID). Names cannot be used to map perspectives |
| test-gap-scan | `action(f)` :688 | `fix_now` Ready to write / すぐ書ける, `pin_first` Change production code first / 先に本番コードを整える, `verify_first` Verify first / 先に検証する | STATUSES findings.py:89, `is_excluded` :685 | Py `finding_markdown` :710 | `category` |
| ux-scan | `to_common()` :311 (Open and Valid with a fix direction → Fix, other Open items → Verify first. Ignores confidence) | `fix` Fix / 修正, `verify` Verify first / 先に検証 | STATUSES findings.py:43 / EXCLUDED :45 | Kit `findingMarkdown` | `perspective` (step ID) |

- The 3 skills with `pin_first` (data-integrity / logic / test-gap) have 3 open lanes, for a total of 5. `console.js` is independent of the lane count. `.cx-board` has 2 columns, so the 5th lane sits alone in the 3rd row.
- Supporting `Unlikely` in prune-scan requires a placement outside the existing rules.
- Set `perspectives[].tone/on` in render.py for each skill's perspective indicator mapping. For skills without a mapping (prompt / prune / ux), the safest option is to set all indicators to `muted` and off.

## 6. Testing Notes

- **Script count**: security-scan and ux-scan require exactly 2 dashboard `<script>` elements. Concatenate `console.js` into an existing script.
- **CSP**: privacy-scan includes the sha256 hashes of the single `<script>` and `<style>` in `<meta http-equiv=Content-Security-Policy>` (render.py:640 / :686). Compute the hashes from the concatenated content.
- **Fixed templates**: ux-scan's `tests/test_page_shell.py` fails when the template changes. Update it to reflect the intended changes.
- **Navigation and ids**: The following tests check the appbar / sidebar / navigation targets / facet count. Update them for the band replacement or the addition of `#triage`.
  - architecture-scan: `test_dashboard_quality.py` (`header.appbar`, `nav.sidebar`)
  - infra-security-scan: `test_report_views.py` (`header.appbar` and the absence of `masthead`)
  - performance-scan: `test_render_layout.py`
  - data-integrity / logic / test-gap: The entire list of navigation links is matched exactly (e.g., `test_data_scan.py:1539`)
- **Priority queue count and order**: Tests cover `priority-item` counts of 4 / 12 (data-integrity / logic / test-gap) and the order within security-scan's `#priority-queue`. Keep the existing priority lists and the count tests will still pass. Ordering the assessment by lane changes the order test, so rewrite it for lane order (see security-scan's `test_priority_is_severity_first_then_readiness_then_id`).
- **No `.innerHTML`**: security-scan tests enforce this. `console.js` uses only DOM APIs, so it also satisfies the check in other skills.
- **Copy button name**: Use the `cx_copy` label for the inspector's copy button. Reusing the name of `copy_llm` makes tests using `get_by_role("button", name=..., exact=True)` match 2 elements.
- **Browser tests**: Opt in to security-scan's browser tests with `SECURITY_SCAN_BROWSER_TEST=1 CHROME=<chrome-headless-shell>`. Run outside the macOS sandbox because it denies Chrome's Mach port registration.
- **Tests to add** (see the structure of security-scan's `test_console_report.py`):
  - Lane assignment: Every record's lane matches the result of the existing function and the exclusion and closure rules
  - The model is embedded and all slots are present
  - Assessment band readout, tile cells, and lane order
  - Opt-in browser tests: Card selection → inspector order → copy, with no horizontal scrolling at 360px
