# findings.json

**Read when:** REPORT — writing fragments for `scripts/findings.py merge`.

`scripts/findings.py check <out>/findings.json` (path relative to the skill's
directory, SKILL.md *Paths*) enforces this schema; `merge`
checks the record after each fragment and writes once after the entire batch
passes. A rejected fragment or failed write leaves the target unchanged. JSON
must be encodable as UTF-8, object keys must be unique, and numbers must be
finite: duplicate keys, `NaN` and `Infinity` are rejected. Commands report invalid input or unwritable output
on stderr with exit status 2. Output targets must be regular files, not symlinks.

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
format as `flows.json`. `commit` is the reviewed repository's `git rev-parse HEAD`. Leave
`commit` out when the repository is not under Git or has no commit yet, and say
so in `limitations`. When `git status --porcelain` is not empty, the review
covers uncommitted changes: say so in `limitations` (which files, or how many).

| Field | Rules |
|---|---|
| `id` | `U-` and three digits; unique; new ids follow merge order. After VERIFY, `scripts/findings.py renumber` produces consecutive ids from `U-001` in severity, path and starting-line order, with excluded findings last in their old id order (maximum 999 findings). `check` and rendering require this numbering and array order |
| `severity` | `High`, `Medium`, `Low`, `Info` (SKILL.md table) |
| `confidence` | `Confirmed`, `Runtime-dependent`, `Suspected` (`reference/validation.md`) |
| `status` | `Open`, `Fixed`, `Accepted` |
| `perspective` | A hunt step id from `reference/perspectives.md` (`AX2`, `FM3`…) |
| `flow_ref` | A flow id present in `flows.json` (checked when `flows.json` sits next to `findings.json`); for a shared component, the most important flow it breaks |
| `screen` | Where the user meets it, with the route when there is one |
| `viewport` | Optional: the viewport the defect shows at (`360x640`), when it depends on one |
| `criterion` | What it fails: a WCAG 2.2 success criterion, the app's own token scale or documented pattern (with `path:line`), or a named usability heuristic. Never "looks bad" |
| `location` | `path:line` or `path:line-line`, relative to the repository, using `/` separators; the fix location. Line numbers are positive and a range's end cannot precede its start |
| `occurrences` | Optional: every `path:line` the same fix covers |
| `observed` / `expected` | The code or behaviour as found, and as the criterion wants it |
| `category` | Optional; defaults to the perspective family's name in the rendered pages |
| `validation.verdict` | Required; `FalsePositive` and `NotApplicable` are excluded from counts; `Unverified` is allowed while merging but `contract_check.py` rejects it |
| `references` | Optional list of objects; `url` must be a valid http(s) URL with a host and no whitespace; optional `type` and `title` are strings |

`merge` replaces a finding with the same id field by field (a list field such
as `occurrences` replaces whole) and adds new ids. It replaces `meta` and
`summary` when a fragment carries them, appends new lines to `checked_ok`,
`limitations`, `decisions` and `next_steps`, and replaces `perspectives` entries
by `name`. To drop a line, send `{"remove": {"limitations": ["exact line"]}}`.
Every fragment section must have its documented type; findings and perspectives
must be lists of objects, with unique `id` or `name` values within that fragment.
List sections and removal lines contain strings. Use separate fragments to
update the same id more than once. `renumber` rewrites references throughout
the record's prose, including ids immediately beside Japanese text. Structured
`location`, `occurrences` and reference `url` values stay unchanged: an id in a
file name or external URL does not identify a finding. The command also repairs
the array order when the ids themselves already have the correct values.
