# findings.json

**Read when:** REPORT — writing fragments for `scripts/findings.py merge`.

`scripts/findings.py check <out>/findings.json` (path relative to the skill's
directory, SKILL.md *Paths*) enforces this schema; `merge`
checks the record after each fragment and writes once after the entire batch
passes. A rejected fragment or failed write leaves the target unchanged. JSON
must be encodable as UTF-8, object keys must be unique, and numbers must be
finite: duplicate keys, `NaN` and `Infinity` are rejected. Commands report invalid input or unwritable output
on stderr with exit status 2. Documented text fields reject NUL and surrogate
code points before merging, so accepted text can be rendered. Output targets
must be regular files, not symlinks.

```json
{
  "schema_version": 1,
  "meta": {"project": "Tasklane", "date": "2026-10-12", "assessor": "Claude Code (<model>)",
           "scope": "web app at the recorded commit", "method": "Static review of routes, components, styles and locales",
           "commit": "0a1b2c3", "viewports": ["360x640", "1280x800"], "locales": ["en", "de"]},
  "summary": "One paragraph for the abstract: the overall state and the two or three findings that matter most.",
  "findings": [
    {"id": "U-001", "title": "Task rows open only on mouse click", "severity": "High", "confidence": "Confirmed",
     "status": "Open", "perspective": "AX2", "category": "Accessibility", "flow_ref": "FL-02",
     "screen": "Task list (/)", "criterion": "WCAG 2.2 SC 2.1.1 Keyboard",
     "location": "src/components/TaskList.tsx:15", "occurrences": ["src/components/TaskList.tsx:15"],
     "observed": "<div onClick={...}> with no role, tabindex or key handler",
     "expected": "A link or button reachable with Tab and operable with Enter",
     "impact": "Keyboard users cannot open any task.",
     "fix": "Render the title as a link to the task.",
     "validation": {"verdict": "Valid", "evidence": "inventory click_handlers; no parent handles keys.",
                    "intent_checked": "No other control on the row opens the task."},
     "references": [{"type": "standard", "title": "WCAG 2.2 Understanding 2.1.1",
                     "url": "https://www.w3.org/WAI/WCAG22/Understanding/keyboard.html"}]}
  ],
  "perspectives": [{"name": "AX Accessibility", "result": "3 findings", "note": "Keyboard walk of both primary flows."}],
  "checked_ok": ["Main navigation sets aria-current on the active item."],
  "limitations": ["Nothing was rendered; contrast was not measured."],
  "decisions": ["Confirm that /signup is reached only from the marketing site."],
  "next_steps": ["Fix U-001 to U-005, then re-run inventory.py --flows."]
}
```

Required on every finding: `id`, `title`, `severity`, `confidence`, `status`,
`perspective`, `flow_ref`, `screen`, `criterion`, `location` and
`validation.verdict` (plus `validation.evidence` unless the verdict is
`Unverified`). The first fragment carries `meta` with `project`, `date` and
`assessor`; `schema_version` is the integer `1`, and `date` is a real calendar
date in `YYYY-MM-DD` form. Optional `meta.viewports` uses the same `WIDTHxHEIGHT`
format as `flows.json`; `meta.viewports` and `meta.locales` are shown in the
pages only when `flows.json` lacks them. `commit` is the reviewed repository's `git -C <repo> rev-parse HEAD`
when `<repo>` is the top level of its own Git repository (`git -C <repo> rev-parse --show-toplevel`);
for a directory inside a larger repository, record that repository's commit and name the subdirectory in `scope`. Leave
`commit` out when the repository is not under Git or has no commit yet, and say
so in `limitations`. When `git status --porcelain` is not empty, the review
covers uncommitted changes: say so in `limitations` (which files, or how many).

| Field | Rules |
|---|---|
| `id` | `U-` and three digits; unique; new ids follow merge order. After VERIFY, `scripts/findings.py renumber` produces consecutive ids from `U-001` in severity, path and starting-line order (findings at the same location keep their previous relative order), with excluded findings last in their old id order (maximum 999 findings). `check` and rendering require this numbering and array order |
| `title` | Required, nonblank text on a single line; Unicode line separators are also rejected |
| `severity` | `High`, `Medium`, `Low`, `Info` (SKILL.md table) |
| `confidence` | `Confirmed`, `Runtime-dependent`, `Suspected` (`reference/validation.md`) |
| `status` | `Open`, `Fixed`, `Accepted` |
| `perspective` | A hunt step id from `reference/perspectives.md` (`AX2`, `FM3`…) |
| `flow_ref` | A flow id present in `flows.json` (checked when `flows.json` sits next to `findings.json`). A defect in the app shell or a shared component cites the `shared` flow; cite one primary or secondary flow instead only when that flow alone carries the impact |
| `screen` | Where the user meets it, with the route when there is one |
| `viewport` | Optional: the viewport the defect shows at (`360x640`), when it depends on one |
| `criterion` | What it fails: a WCAG 2.2 success criterion, the app's own token scale or documented pattern (with `path:line`), or a named usability heuristic. Never "looks bad" |
| `location` | `path:line` or `path:line-line`, relative to the repository, using `/` separators; the fix location must name a file, not a directory or a trailing `/.` component. Line numbers are positive and a range's end cannot precede its start |
| `occurrences` | Optional: every `path:line` the same fix covers; when present, not empty |
| `observed` / `expected` | The code or behaviour as found, and as the criterion wants it |
| `category` | Optional; defaults to the perspective family's name in the rendered pages |
| `validation.verdict` | Required; `FalsePositive` and `NotApplicable` are excluded from counts; `Unverified` is allowed while merging but `contract_check.py` rejects it |
| `mockup` | Optional before/after illustration of the fix, published in `mockups.html` (`reference/mockups.md`): one object, or a list of 2 to 4 objects that each need a `title` unique within the finding. An object has `before` and `after`, required HTML fragments of at most 64 KiB each, measured as UTF-8, with no `<link` tag text (`reference/mockups.md`), or instead `states` (2 to 4 objects of `label`, `before` and `after`, all required, and optional `note`; labels unique); optional `title`, `viewport` (`WIDTHxHEIGHT`), `note` (prose), `label` (names the `after` design; required with `alternatives`) and `alternatives` (1 to 5 objects of `label` and `after`, both required, and optional `note`; labels unique within the mockup, each `after` under the same fragment rules; with `states`, `states` of `label` and `after` per state of the mockup, in its order, instead of `after`). A finding's fragments total at most 1 MiB as UTF-8. No other keys. `"mockup": null` in a fragment removes it |
| `references` | Optional list of objects; `url` must be a valid http(s) URL with a host and no whitespace, control or invisible format characters (such as zero-width spaces and bidirectional overrides; the joiners U+200C and U+200D that Persian and Indic words use are allowed outside the host), backslashes, raw angle brackets or double quotes. Host validation also checks percent-decoded and Unicode-normalized forms using the renderer's URL rules; optional `type` and `title` are strings |

`merge` replaces a finding with the same id field by field (a list field such
as `occurrences` replaces whole; `"mockup": null` removes the mockup) and adds
new ids. It replaces `meta` and `summary` when a fragment carries them, appends
new lines to `checked_ok`,
`limitations`, `decisions` and `next_steps`, and replaces `perspectives` entries
by `name`. To drop a line, send `{"remove": {"limitations": ["exact line"]}}`.
A fragment may carry only the record's documented sections and `remove`; a
misspelled section is refused rather than kept where nothing reads it. The
same holds inside `meta`, each finding, its `validation`, each reference and each perspective:
only the fields documented here are accepted.
Every fragment section must have its documented type; findings and perspectives
must be lists of objects, with unique `id` or `name` values within that fragment.
List sections and removal lines contain strings. Use separate fragments to
update the same id more than once. `renumber` rewrites references throughout
the record's prose, including ids immediately beside Japanese text. Structured
`location`, `occurrences`, reference `url` and mockup `before`/`after` values stay unchanged: an id in a
file name or external URL does not identify a finding. Paths (including
parenthesized route-group components), routes, relative Markdown link targets,
http(s) URLs, inline code (within its paragraph), fenced code (also one opening after a list marker or `>`, with or without a space after `>`, though an ordered list not starting at 1 cannot interrupt a paragraph; each marker and the fence may sit at most three columns past the content before it, so a deeper opener is indented code, which is not protected; the fence ends at a closer repeating the marker at the opener's `>` depth, indented at most three columns past the container's content, or where its blockquote or list item ends), closed HTML comments (or an unclosed one opening a line) and HTML/JSX markup quoted
in prose also stay unchanged within their delimiters (raw HTML tags are
protected individually when they follow the CommonMark tag grammar, with JSX
`{…}` attributes read as JavaScript (nested braces, strings, template literals, comments and regular expressions; a tag longer than 8,000 characters stays prose) and Angular `(event)=`, `[prop]=`, `*ngIf=` and `#ref`, Vue `:[key]=`, Svelte `on:click|once=` and Lit
`?disabled=${…}` / `.value=${…}` attributes allowed, so comparisons such as `<640px … >1024px` or
`<sm (U-001) and >lg` remain prose). A URL, including raw Japanese text in its
path or query and balanced parentheses nested up to four levels, runs to whitespace, quotes, an
unbalanced bracket or Japanese punctuation such as `、` or `。`; write a space
between a URL and a following finding id, or that id is kept as part of the
URL. Ids inside `_emphasis_` are references; ids joined to a word or
snake_case name by any run of underscores (`a_U-001`, `foo____U-001`) are not; braces inside JSX strings and template literals, including escaped quotes, do not end an expression. Code spans close at a backtick run of the same
length; a shorter or longer run inside the span remains literal code.
Markdown destinations are preserved even for extensionless paths, query-only
URLs and reference-link definitions; link labels and titles remain prose and
their finding references are updated.
An inline code span containing only a finding id, such as `U-002`,
is a finding reference and is updated; mark other code literals as code so
their ids are not mistaken for references. Separate prose references from
source paths with whitespace, punctuation or code spans; unseparated text that
looks like one path is preserved as a source token. Ids joined only by slashes
(`U-001/U-002`), each optionally in emphasis or a code span, are a list of
references, not a path; ids with a leading or trailing slash (`/U-001`,
`U-001/`) stay a path unless that slash joins them to an id code span
(`` `U-001`/U-002 ``, `` `U-001`/U-002/U-003 ``).

When ids move, explicit finding ranges written on one line using `to`,
`through`, Japanese `から` (optionally followed by `まで`), `..`, or a hyphen or dash
(including the Unicode and full-width forms), `~`, `〜` or `～`, with optional
spaces, no-break spaces or ideographic spaces around the connector (and before `まで`), expand to a
comma-separated list of the same findings in their original range order. Ids on
different lines, such as a Markdown bullet list, are never a range: each is
renumbered on its own.
The endpoints may each be wrapped in backticks or Markdown emphasis; those
delimiters still identify finding references, and the expanded list keeps that
formatting. Spaces inside ID-only code spans are retained. Emphasis wrapping
the entire range is retained around the expanded list. References in
underscore-emphasized lists and prose are updated while underscore identifiers,
including Unicode identifiers, keep their original text.
Nested underscore emphasis is supported, including a delimiter run that closes
multiple levels, such as `_U-001 and __U-003___`. Escaped underscores and
unmatched delimiters remain literal. Underscore emphasis does not cross blank
lines or fenced-code blocks; a single line break may remain inside it.
Identifier boundary protection uses the running Python's Unicode character
categories plus all `Other_ID_Start` and `Other_ID_Continue` exceptions from
[Unicode 18.0.0](https://www.unicode.org/Public/18.0.0/ucd/PropList.txt), including
join controls. It does not normalize the text; ordinary character categories
still follow that Python version's Unicode database.
For example, if `U-001` becomes `U-003` and `U-002` becomes `U-001`,
`Fix U-001 to U-002` becomes `Fix U-003, U-001`. A range containing a missing id
is refused when any id in that range moves; replace it with an explicit list
of existing finding ids and retry. Ranges whose ids do not move stay unchanged,
unless one of their missing ids is another finding's new id, which is refused
for the same reason as the single reference below.
A single reference to an id no finding holds is likewise refused when another
finding moves to that id, since it would silently come to name that finding;
one nothing moves to stays as written.
The command also repairs the array order when the ids themselves already have
the correct values.
