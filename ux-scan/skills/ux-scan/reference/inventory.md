# Inventory

**Read when:** RECON (first run, no flows) and after FLOWS (`--flows`), and when
deciding inventory candidates in REVIEW.

```sh
python3 <skill-dir>/scripts/inventory.py <repo> --out <out>/inventory.json [--flows <flows.json>]
```

Paths in this file are relative to the skill's directory, not the reviewed
repository (SKILL.md *Paths*).
The `--out` file must be outside the reviewed repository. The CLI rejects
in-repository destinations, including parent-directory symlink aliases,
before writing anything.

Standard library only, read-only. It walks style, script, template (including
MDX), JSON token and JSON locale files under `<repo>` (skipping VCS and
dependency/build directories, symlinks, lockfiles, minified bundles, binaries
and files over 2 MB) and records
**candidates** — never findings. Every row carries `path:line` locations.
Source reads use `scripts/file_io.py` to open each path component relative to
the selected repository. Replacing a checked directory with a symlink cannot
redirect the read, and the byte limit also applies when a file grows during
reading. This requires descriptor-relative no-follow reads (available on
Linux and macOS); unsupported platforms refuse source reads and record
`parse_warnings`. Refused reads and paths that cannot be represented in UTF-8
are also counted as skipped with a warning.
CSS block comments and closed HTML / JSX comments are masked without changing
source locations. JSX comment masking preserves JS strings; HTML comment
masking preserves tag attributes and raw script / style content. Ambiguous,
unclosed template comment markers leave the remaining source available for
review. In HTML, Vue, Svelte and Astro files, CSS measurements use style
blocks and literal style attributes; script style objects are measured once.
Template tag scans do not re-enter quoted attributes or raw-text elements
such as script, style and textarea. Embedded CSS uses those same boundaries,
so style examples in attribute or script strings are not measured as CSS.
Closed wrapping labels are matched to actual template tags. JSX source and
attribute expressions keep heuristic tag scanning: check their candidates
in context, including nested JSX, strings and regular expressions.
HTML template tag names are case-insensitive, while component names in JSX,
Vue, Svelte and Astro keep their case. Attribute character references are decoded.
Next.js route groups and [parallel-route slots](https://nextjs.org/docs/app/api-reference/file-conventions/parallel-routes)
(`@name`) are omitted from the inferred URL, and
[private folders](https://nextjs.org/docs/14/app/building-your-application/routing/colocation)
(`_name`) are excluded from route inference.
Interception routes are omitted with a `parse_warnings` entry for manual review.
These Next.js exclusions do not apply to Svelte route segments.

| Key | What it collects | Perspective |
|---|---|---|
| `routes`, `orphan_routes`, `screens` | Router paths (`<Route path>`, `path: "/…"`, `app/**/page.*`, `routes/**/+page.svelte`); routes that no `href`, `to=` or `navigate()` / `push()` reaches (dynamic segments excluded); files under `pages/`, `screens/`, `views/`, `routes/` | IA1, IA2 |
| `token_sources` | Files named like tokens / theme / variables / `tailwind.config` (including JSON token files), or defining three or more CSS custom properties | LG2, CC2 |
| `spacing`, `font_sizes` | `margin` / `padding` / `gap` and `font-size` literals (CSS and JS style objects), in px (rem and em at 16px); spacing of 0–2 px is ignored as hairline adjustment | LG2, VH2 |
| `breakpoints` | Media-query widths (`(max-width: …)`, `(width >= …)`), in CSS and in script strings | RS1 |
| `z_index` | `z-index` / `zIndex` values | LG3 |
| `fixed_widths` | `width` / `min-width` declarations of 320 px or more; widths in parenthesized conditions are excluded | RS2 |
| `tap_targets` | Rules whose selector looks interactive (button, btn, icon, link, chip, tab, close…) with an explicit width or height under 44 px; `below_24` flags dimensions under 24 px for review, with the actual hit area and WCAG 2.5.8 exceptions still to verify | RS3 |
| `focus_outline` | `outline: none` / `0`, with whether the same rule restyles focus and whether the file has a `:focus-visible` rule | ST2 |
| `viewport_meta` | Viewport meta tags; `blocks_zoom` for `user-scalable=no` / `0` or a nonnegative numeric `maximum-scale` under 2; names are case-insensitive and numeric prefixes are parsed without aborting on trailing text | RS4 |
| `click_handlers` | Click handlers on non-interactive elements (`div`, `span`, `li`, `img`…) or `<a>` without `href`, with what is missing (role, tabindex, key handler) | AX2 |
| `images` | `<img>` without `alt`, or without `width` and `height` | AX4, PP2 |
| `inputs` | `input` / `select` / `textarea` without a programmatic label (no nonblank `aria-label`, `aria-labelledby`, `title`, matching `for` / `htmlFor` or wrapping `<label>`), personal-data fields without `autocomplete`, email or phone fields with the wrong `type`; `placeholder_only` when a placeholder stands in for the label | FM1, FM4 |
| `icon_buttons` | `<button>` whose content is only elements (an icon) and that has no nonblank `aria-label`, `aria-labelledby` or `title`; `IconButton` and `*IconButton` components without such a name or a nonblank label prop | AX4 |
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

`flows_sha256` records a SHA-256 digest of the complete flows record using
canonical JSON (sorted object keys, compact separators, UTF-8, no non-finite
numbers), prefixed with `sha256:`. It is `null` during RECON without `--flows`.
The run contract uses it to detect an inventory that predates the current
flows, tokens or supported viewports; rerun with `--flows` after changing them.

## Caps

Each row keeps its full `count` but at most 5 `locations`; find the rest with
a search for the value. `spacing`, `font_sizes` and each `off_scale` list keep
at most 200 rows (most frequent first), `parse_warnings` keeps the first 200
warnings, and each `locale_expansion` entry at
most 50 keys (widest first). `off_scale` is measured on every row before any
cap, so a rare off-scale value is never dropped from it unless `off_scale`
itself exceeds 200 rows. `limits` states the caps; `truncated` names each list
that was cut and how many rows were left out (empty when nothing was cut) —
when it is not empty, say so in `limitations` or search for the rest.

## Limits

Elements that receive props through a spread (`{...props}`) are skipped: what
they get is unknown here. Vue object bindings (`v-bind="props"`) and bindings
with dynamic attribute names are also treated as spreads. Vue named bindings
(`:aria-label="label"`, `v-bind:aria-label="label"`) preserve the expression;
event modifiers such as `@click.stop` do not hide the event. Dynamic name
expressions are also treated as unknown;
only statically blank name attributes are rejected, and referenced label text
is not resolved. A dynamic input type is recorded as `unknown` and does not
produce a wrong-type candidate. Viewport declarations are candidates, not a browser's computed
zoom behavior. The numeric-prefix and case rules follow the
[viewport parsing algorithm](https://www.w3.org/TR/css-viewport-1/#meta-viewport),
and blank names follow the
[accessible name computation](https://www.w3.org/TR/accname-1.2/#computation-steps).
Small declared dimensions alone do not establish a failure of
[WCAG 2.5.8](https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html),
which includes spacing and other exceptions.
Invalid locale JSON, including duplicate keys, non-finite numbers and invalid
Unicode strings, is skipped and included in `files_skipped`. `parse_warnings`
records the file and reason. Locale JSON has an explicit limit of 256 nested
object / array containers, checked before decoding without recursive calls.
A root object or array counts as depth 1; all nested containers count, including
arrays and `@` metadata branches that locale expansion otherwise ignores.
Container characters inside quoted strings do not count. The limit is recorded
as `limits.locale_container_depth`; exceeding it skips the entire locale file
with a warning, regardless of the Python JSON decoder's own nesting tolerance.
Integer literals beyond 1,000 digits (or Python's lower configured conversion
limit) and lengths outside the finite numeric range are skipped individually
with a warning; the rest of the file is still scanned. Mention relevant parse
warnings in the report's `limitations`, as well as any `truncated` lists.
Limits, to state in `limitations` when they matter:
styles computed at run time, Tailwind utility classes other than `truncate`,
native mobile UI code (SwiftUI, Compose, Flutter), components from a library
whose source is not in the repository, and rendering itself (contrast,
overlap, real text widths) are not measured. A candidate count is a lead, not a
measurement of the product.
