# findings.json

**Read when:** REPORT — writing fragments for `scripts/findings.py merge`.

`scripts/findings.py check <out>/findings.json` (path relative to the skill's
directory, SKILL.md *Paths*) enforces this schema; `merge` checks every
fragment before it changes anything. With `units.json` beside it, every
`unit_ref`, `entry_ref` and `purpose_ref` must exist there.

```json
{
  "schema_version": 1,
  "meta": {"project": "Larder", "date": "2026-10-12", "assessor": "Claude Code (<model>)",
           "scope": "server, web app, schema, tooling at the recorded commit",
           "method": "Static subtraction review against units.json", "commit": "0a1b2c3d4e5f60718293a4b5c6d7e8f901234567"},
  "summary": "One paragraph for the abstract: what the product is for, what does not serve it, the two or three subtractions that matter most.",
  "findings": [
    {"id": "P-007", "title": "The household leaderboard serves a documented non-goal", "severity": "Medium",
     "confidence": "Confirmed", "status": "Open", "perspective": "PX2", "unit_ref": "UN-01",
     "entry_ref": "EP-03", "purpose_ref": "PB-05",
     "element": "Household leaderboard (GET /api/leaderboard and its widget)",
     "location": "server/app.py:40", "occurrences": ["server/app.py:40", "server/leaderboard.py:5"],
     "observed": "Home renders <Leaderboard />, which ranks households",
     "basis": "README.md:11 lists comparison between households as a non-goal.",
     "impact": "A route, a module, a component and a column to maintain.",
     "subtraction": {"action": "remove", "what": "The route, server/leaderboard.py and the widget.",
                     "remains": "Home shows the household's own pantry only.",
                     "loses": "The weekly ranking of households, a non-goal."},
     "risk": "Users who liked the widget lose it.",
     "validation": {"verdict": "Valid", "evidence": "Documented non-goal; the only caller is Leaderboard.tsx.",
                    "dynamic_checked": "No other consumer in units.json calls it."}}
  ],
  "perspectives": [{"name": "PX Purpose fit", "result": "2 findings", "note": "Every used feature asked what the core jobs would lose."}],
  "checked_ok": ["/auth/callback has no caller in the repository; Google calls it."],
  "limitations": ["Static reading only: traffic and deployed settings were not seen."],
  "decisions": ["P-021: label printing rests on an inferred purpose item (PB-06); the owner decides."],
  "next_steps": ["Remove /debug/dump first, then rotate SECRET_KEY."]
}
```

Required on every finding: `id`, `title`, `severity`, `confidence`, `status`,
`perspective`, `unit_ref`, `element`, `basis`, `subtraction` (all four fields),
`risk`, `location` and `validation.verdict` (plus `validation.evidence` unless
the verdict is `Unverified`, and `validation.dynamic_checked` when it is `Valid`
or `Likely`). PX and OB findings, and every `Purpose-dependent` finding, also
need `purpose_ref`. The first fragment carries `meta` with `project`, `date` and
`assessor`; `commit` is the reviewed repository's `git rev-parse HEAD`. Leave
`commit` out when the repository is not under Git or has no commit yet, and say
so in `limitations`. When `git status --porcelain` is not empty, the review
covers uncommitted changes: say so in `limitations` (which files, or how many).

| Field | Rules |
|---|---|
| `id` | `P-` and three digits; unique; new ids follow merge order, and `scripts/findings.py renumber` puts them in severity order after VERIFY |
| `severity` | `High`, `Medium`, `Low`, `Info` (SKILL.md table: the cost of keeping) |
| `confidence` | `Confirmed`, `Externally-dependent`, `Purpose-dependent`, `Suspected` (`reference/validation.md`); `Purpose-dependent` whenever `purpose_ref` is an `inferred` item |
| `status` | `Open`, `Fixed` (removed since), `Accepted` (kept by decision) |
| `perspective` | A hunt step id from `reference/perspectives.md` (`DC1`, `OB2`…) |
| `unit_ref` | A unit id in `units.json` |
| `entry_ref` | Optional: the entry point id the element is, or hangs off |
| `purpose_ref` | The purpose item id the finding is measured against; required for PX, OB and `Purpose-dependent` |
| `element` | What is unneeded, named as a reader would find it ("Route GET /debug/dump", "Dependency moment") |
| `location` | `path:line` or `path:line-line`, relative to the repository; where the subtraction starts (a definition, an entry point, a manifest line) |
| `occurrences` | Optional: every `path:line` the same subtraction touches |
| `observed` | Optional: the code or configuration as found |
| `basis` | Why it does not earn its place: the evidence of non-use (searches, inventory keys, reference counts) or of excess (the purpose item, scale, usage, number of implementations or configurations actually used) |
| `impact` | Optional: the cost of keeping it — what the severity rests on |
| `subtraction.action` | `remove`, `reduce` (keep a smaller form) or `consolidate` (merge into another element) |
| `subtraction.what` | What to delete, reduce or merge |
| `subtraction.remains` | The simpler form that remains after the subtraction |
| `subtraction.loses` | What is lost: "Nothing…", a named capability, or named users |
| `risk` | What could break if it is removed: dynamic or external use not ruled out, data duties, ordering against other findings |
| `category` | Optional; defaults to the perspective family's name in the rendered pages |
| `validation.verdict` | Required; `FalsePositive` and `NotApplicable` are excluded from counts; `Unverified` is allowed while merging but `contract_check.py` rejects it; `Valid` needs `Confirmed` confidence |
| `validation.dynamic_checked` | The dynamic-use and external-consumer patterns searched (`reference/validation.md`) |
| `references` | Optional; `url` must be http(s) |

`merge` replaces a finding with the same id field by field (an object or list
field such as `subtraction` or `occurrences` replaces whole) and adds new ids.
It replaces `meta` and `summary` when a fragment carries them, appends new
lines to `checked_ok`, `limitations`, `decisions` and `next_steps`, and replaces
`perspectives` entries by `name`. To drop a line, send
`{"remove": {"limitations": ["exact line"]}}`.
