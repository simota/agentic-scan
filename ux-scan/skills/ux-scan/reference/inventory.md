# Inventory

**Read when:** RECON (first run, no flows) and after FLOWS (`--flows`), and when
deciding inventory candidates in REVIEW.

```sh
python3 <skill-dir>/scripts/inventory.py <repo> --out <out>/inventory.json [--flows <flows.json>]
```

Paths in this file are relative to the skill's directory, not the reviewed
repository (SKILL.md *Paths*).

Standard library only, read-only. It walks style, script, template and JSON
locale files under `<repo>` (skipping VCS and dependency/build directories,
symlinks, lockfiles, minified bundles, binaries and files over 2 MB) and records
**candidates** — never findings. Every row carries `path:line` locations.

| Key | What it collects | Perspective |
|---|---|---|
| `routes`, `orphan_routes`, `screens` | Router paths (`<Route path>`, `path: "/…"`, `app/**/page.*`, `routes/**/+page.svelte`); routes that no `href`, `to=` or `navigate()` / `push()` reaches (dynamic segments excluded); files under `pages/`, `screens/`, `views/`, `routes/` | IA1, IA2 |
| `token_sources` | Files named like tokens / theme / variables / `tailwind.config`, or defining three or more CSS custom properties | LG2, CC2 |
| `spacing`, `font_sizes` | `margin` / `padding` / `gap` and `font-size` literals (CSS and JS style objects), in px (rem and em at 16px); spacing of 0–2 px is ignored as hairline adjustment | LG2, VH2 |
| `breakpoints` | Media-query widths (`(max-width: …)`, `(width >= …)`), in CSS and in script strings | RS1 |
| `z_index` | `z-index` / `zIndex` values | LG3 |
| `fixed_widths` | `width` / `min-width` of 320 px or more | RS2 |
| `tap_targets` | Rules whose selector looks interactive (button, btn, icon, link, chip, tab, close…) with an explicit width or height under 44 px; `below_24` marks WCAG 2.5.8 failures | RS3 |
| `focus_outline` | `outline: none` / `0`, with whether the same rule restyles focus and whether the file has a `:focus-visible` rule | ST2 |
| `viewport_meta` | Viewport meta tags; `blocks_zoom` for `user-scalable=no` or `maximum-scale` under 2 | RS4 |
| `click_handlers` | Click handlers on non-interactive elements (`div`, `span`, `li`, `img`…) or `<a>` without `href`, with what is missing (role, tabindex, key handler) | AX2 |
| `images` | `<img>` without `alt`, or without `width` and `height` | AX4, PP2 |
| `inputs` | `input` / `select` / `textarea` without a programmatic label (no `aria-label`, `aria-labelledby`, `title`, matching `for` / `htmlFor` or wrapping `<label>`), personal-data fields without `autocomplete`, email or phone fields with the wrong `type`; `placeholder_only` when a placeholder stands in for the label | FM1, FM4 |
| `icon_buttons` | `<button>` whose content is only elements (an icon) and that has no `aria-label`, `aria-labelledby` or `title`; `*IconButton` components without a label prop | AX4 |
| `positive_tabindex` | `tabindex` greater than 0 | AX3 |
| `state_branches` | Template or component files that fetch data (`fetch`, `axios`, `useQuery`, `useSWR`…) but never mention a loading state, an error path, or — when they render a list — an empty state | FB1, PP1 |
| `destructive_actions` | Click handlers calling delete / remove / destroy / discard… in a file with no confirm, dialog or undo | FB4 |
| `motion` | Count and first locations of transitions and animations, and every `prefers-reduced-motion` / `useReducedMotion` | MO1, MO2 |
| `truncation` | `text-overflow: ellipsis`, `line-clamp`, `white-space: nowrap`, `truncate` classes | IN1, IN2 |
| `locale_expansion` | For JSON locale bundles: keys whose text in another locale is at least 1.4 × as wide as the source locale (`en` when present) and 5 columns wider; East Asian wide characters count as two | IN1 |

With `--flows`, also:

| Key | What it adds |
|---|---|
| `off_scale` | `spacing`, `font_sizes`, `breakpoints` and `z_index` rows whose value is not on the `tokens` scale (z-index 0, 1, −1 always allowed) |
| `smallest_viewport`, `fixed_widths[].wider_than_smallest_viewport` | The narrowest supported width, and which fixed widths exceed it |
| `physical_properties` | `margin-left`, `padding-right`, `left:`, `text-align: left`… — only when a shipped locale is right-to-left |

## Caps

Each row keeps its full `count` but at most 5 `locations`; find the rest with
a search for the value. `spacing`, `font_sizes` and each `off_scale` list keep
at most 200 rows (most frequent first), and each `locale_expansion` entry at
most 50 keys (widest first). `off_scale` is measured on every row before any
cap, so a rare off-scale value is never dropped from it unless `off_scale`
itself exceeds 200 rows. `limits` states the caps; `truncated` names each list
that was cut and how many rows were left out (empty when nothing was cut) —
when it is not empty, say so in `limitations` or search for the rest.

## Limits

Elements that receive props through a spread (`{...props}`) are skipped: what
they get is unknown here. Limits, to state in `limitations` when they matter:
styles computed at run time, Tailwind utility classes other than `truncate`,
native mobile UI code (SwiftUI, Compose, Flutter), components from a library
whose source is not in the repository, and rendering itself (contrast,
overlap, real text widths) are not measured. A candidate count is a lead, not a
measurement of the product.
