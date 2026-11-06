# Taxonomy: types, channels and patterns

**Read when:** TRIAGE, to classify a fix; CHECKLIST requests, to list what applies.

## Fix type

| `type` | Meaning | Counted as a defect |
|---|---|---|
| `commission` | Somebody wrote the wrong thing | Yes |
| `omission` | The handling was never there | Yes |
| `requirement` | The expected behaviour changed later | No |
| `not-defect` | Docs, rename, tooling, hardening with no failure | No |

An omission usually has no origin: record `Unattributable`. Do not blame the nearest line to fill the field.

## Channel

`feature`, `fix`, `refactor`, `dependency`, `config`, `migration`, `generated`, `merge`, `unknown`, and
`none` for an omission with no origin. Read the origin commit; do not trust its subject alone.

## Bug patterns

| ID | Pattern | Look for |
|---|---|---|
| BP01 | Input shape and boundaries | Empty, whitespace, unicode, zero, limits, encodings |
| BP02 | Failures that look like a value | A swallowed error returning 0, empty or a default |
| BP03 | Names and contracts across a boundary | A key, enum or type changed on one side only |
| BP04 | Duplicated rules that diverged | Two copies of a rule, or two writers applying different rules |
| BP05 | State, concurrency and ordering | Races, partial writes, retries, double execution |
| BP06 | Migrations and dependency upgrades | A silently changed default, or a renamed option |
| BP07 | Broken wiring | An event with no listener, a route without its middleware |
| BP08 | Data only some fixtures have | A branch only real data reaches |
| BP09 | Timing | Fixed timeouts, debounces, sleeps |
| BP10 | Environment and configuration | Read-only filesystems, missing optional services, differing settings |
| BP11 | Partial fix | A fix closed one case and left its siblings |
| BP12 | Docs and code disagree | Behaviour differs from what is documented |

`Unclassified` is allowed and counted. A forced pattern hides what the taxonomy is missing.

Every pattern is recorded in `perspectives` as `applied`, `N/A` or `not checked`, with a note.
