# Inventory

**Read when:** RECON (first run, no flows) and after FLOWS (`--flows`), and when
deciding inventory candidates in REVIEW.

```sh
python3 <skill-dir>/scripts/inventory.py <repo> --out <out>/inventory.json [--flows <flows.json>]
```

`scripts/…` paths in this file are relative to the skill's directory (SKILL.md
*Paths*); route and folder patterns such as `app/**/page.*` describe the
reviewed repository.
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
Directory traversal errors also produce a warning, including a failure to
scan the repository root. They do not increase `files_skipped`, because the
number of files inside an unreadable directory is unknown.
CSS block comments, `//` line comments in Sass, Less and Stylus (files and
`<style lang="scss|sass|less|stylus">` blocks; a `//` after `:` or `(` is kept
as a URL) and closed HTML / JSX comments are masked without changing source
locations. A CSS string ends at a raw newline, so a stray quote cannot hide
later rules. JSX comment masking preserves JS strings; HTML comment
masking preserves tag attributes and raw script / style content. Ambiguous,
unclosed template comment markers leave the remaining source available for
review. In HTML, Vue, Svelte and Astro files, CSS measurements use style
blocks and literal style attributes; script style objects are measured once.
CSS rule checks keep each selector's direct declarations, including those
before and after nested rules; child declarations are not attributed to the
parent. Quoted or escaped punctuation and function values do not split rules.
Nested selectors are inspected as written: `&` inheritance, preprocessor
interpolation and the computed cascade are not expanded.
Template tag scans do not re-enter quoted attributes or raw-text elements
such as script, style and textarea. Embedded CSS uses those same boundaries,
so style examples in attribute or script strings are not measured as CSS.
Closed wrapping labels are matched to actual template tags. JSX source and
attribute expressions keep heuristic tag scanning: check their candidates
in context, including nested JSX, strings and regular expressions.
HTML template tag names are case-insensitive, while component names in JSX,
Vue, Svelte and Astro keep their case. Attribute character references are decoded.
Next.js pages include its default `.js`, `.jsx`, `.ts` and `.tsx`
[page extensions](https://nextjs.org/docs/app/api-reference/config/next-config-js/pageExtensions),
plus `.mdx`. Route groups and [parallel-route slots](https://nextjs.org/docs/app/api-reference/file-conventions/parallel-routes)
(`@name`) are omitted from the inferred URL, and
[private folders](https://nextjs.org/docs/14/app/building-your-application/routing/colocation)
(`_name`) are excluded from route inference.
Interception routes are omitted with a `parse_warnings` entry for manual review.
These Next.js exclusions do not apply to Svelte route segments.

| Key | What it collects | Perspective |
|---|---|---|
| `routes`, `orphan_routes`, `screens` | Router paths (`<Route path>`, `path: "/…"`, `app/**/page.*`, `routes/**/+page.svelte`, `+page@….svelte`); absolute routes that no `href`, `to=` or `navigate()` / `push()` reaches (dynamic segments and relative child routes, whose full path depends on their parents, excluded); files under `pages/`, `screens/`, `views/`, `routes/` | IA1, IA2 |
| `token_sources` | Files named like tokens / theme / variables / `tailwind.config` (including JSON token files), or defining three or more CSS custom properties | LG2, CC2 |
| `spacing`, `font_sizes` | `margin` / `padding` / `gap` and `font-size` literals (CSS and JS style objects), in px (rem and em at 16px); spacing of 0–2 px is ignored as hairline adjustment | LG2, VH2 |
| `breakpoints` | Media-query widths (`(max-width: …)`, `(width >= …)`, `(768px <= width)`, both ends of `(400px <= width <= 700px)`), in CSS and in script strings | RS1 |
| `z_index` | `z-index` / `zIndex` values | LG3 |
| `fixed_widths` | `width` / `min-width` declarations of 320 px or more (rem and em at 16px); widths in parenthesized conditions are excluded | RS2 |
| `tap_targets` | Rules whose selector looks interactive (button, btn, icon, link, chip, tab, close…) with an explicit width or height under 44 px; `below_24` flags dimensions under 24 px for review, with the actual hit area and WCAG 2.5.8 exceptions still to verify | RS3 |
| `focus_outline` | `outline: none` / `0` / `0px` (and `outline: 0` or `"none"` in style objects), with whether the same `:focus` rule sets a visible replacement (a box shadow, border, background, underline or outline that is not `none`, `0` or `transparent`) and whether the file has a `:focus-visible` rule | ST2 |
| `viewport_meta` | Viewport meta tags; `blocks_zoom` for `user-scalable=no` / `0` or a nonnegative numeric `maximum-scale` under 2; names are case-insensitive and numeric prefixes are parsed without aborting on trailing text | RS4 |
| `click_handlers` | Click handlers on non-interactive elements (`div`, `span`, `li`, `img`…) or `<a>` without `href`, with what is missing (role, tabindex, a keydown / keyup / keypress handler in JSX, HTML, Vue, Svelte or Angular syntax; event modifiers such as `(keyup.enter)` or `on:click|once` are ignored) | AX2 |
| `images` | `<img>` without `alt`, or without `width` and `height` | AX4, PP2 |
| `inputs` | `input` / `select` / `textarea` without a programmatic label (no nonblank `aria-label`, `aria-labelledby`, `title`, matching `for` / `htmlFor` — a literal, or an expression identical to the input's `id` expression within the same top-level component, such as `htmlFor={id}` — or wrapping `<label>`), personal-data fields without `autocomplete`, email or phone fields with the wrong `type`; `placeholder_only` when a placeholder stands in for the label | FM1, FM4 |
| `icon_buttons` | `<button>` whose content is only elements (an icon) and that has no nonblank `aria-label`, `aria-labelledby` or `title`, nor a child `<img>` with nonblank `alt` or a child `aria-label`; `IconButton` and `*IconButton` components without such a name or a nonblank label prop | AX4 |
| `positive_tabindex` | `tabindex` greater than 0, using HTML integer parsing for literal values (including leading zeros, a plus sign and numeric prefixes); unresolved template expressions remain unknown | AX3 |
| `state_branches` | Template or component files that fetch data (`fetch`, `axios`, `useQuery`, `useSWR`…) but never mention a loading state, an error path, or — when they render a list — an empty state | FB1, PP1 |
| `destructive_actions` | Parsed click / press / tap handler attributes calling delete / remove / destroy / discard… (also after a camelCase prefix: `handleDelete`, `onRemove`, `props.onDiscard`) in a file with no confirm, dialog or undo; includes block-bodied JSX handlers, Vue event modifiers and HTML `onclick` | FB4 |
| `motion` | Count and first locations of transitions and animations, and every `prefers-reduced-motion` / `useReducedMotion` | MO1, MO2 |
| `truncation` | `text-overflow: ellipsis`, `line-clamp`, `white-space: nowrap`, `truncate` classes | IN1, IN2 |
| `locale_expansion` | For JSON locale bundles: keys whose text in another locale is at least 1.4 × as wide as the source locale (`en` when present, else the first English region such as `en-US`, else the first tag) and 5 columns wider; East Asian wide characters count as two. Bundles are one file per language (`locales/de.json`) or one directory per language (`locales/de/app.json`); when both the file and its folder look like tags, an ISO 639-1 code wins, so `app.json` or `nav.json` namespaces are not read as languages | IN1 |

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

Attribute-completeness and tabindex checks skip elements that receive props
through a spread (`{...props}`): what they get is unknown here. Explicit
viewport declarations and destructive handler bodies remain candidates.
Vue object bindings (`v-bind="props"`) and bindings
with dynamic attribute names are also treated as spreads. Vue named bindings
(`:aria-label="label"`, `v-bind:aria-label="label"`) preserve the expression;
event modifiers such as `@click.stop` do not hide the event. Dynamic name
expressions are also treated as unknown;
only statically blank name attributes are rejected, and referenced label text
is not resolved. A dynamic input type is recorded as `unknown` and does not
produce a wrong-type candidate. Viewport declarations are candidates, not a browser's computed
zoom behavior. The numeric-prefix and case rules follow the
[viewport parsing algorithm](https://www.w3.org/TR/css-viewport-1/#meta-viewport).
Literal `tabindex` values follow the HTML
[integer parsing algorithm](https://html.spec.whatwg.org/multipage/common-microsyntaxes.html#rules-for-parsing-integers),
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
