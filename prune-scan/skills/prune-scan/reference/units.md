# Recon and review units

**Read when:** RECON (mapping the app) and UNITS — before any finding is
written, and whenever REVIEW meets an entry point, consumer or purpose question
no unit covers yet.

`units.json` is the baseline every finding is measured against. Unused
elements are measured against the entry points and consumers; excess and purpose fit against
the purpose items.

## 1. RECON: what to map

| Item | Where to look | Record |
|---|---|---|
| Purpose | README, product docs and specs, landing or store copy, onboarding text, the requester | One statement, the target users, the core jobs, explicit non-goals and known scale, each with its source |
| Entry points | Router and route decorators, screen routes, `bin`/`console_scripts`/`package.json` `bin`, CLI commands, cron and job schedules, queue consumers, webhooks, lifecycle hooks, exported packages and public API definitions; inventory `routes`, `scripts` | Every way in, with its exposure |
| Consumers | Client code in the repository, docs naming clients, API versioning notes, partner integrations, ops runbooks, CI | Who calls the app, and whether the repository shows them |
| Manifests and config | `package.json`, `requirements*.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `.env.example`, config modules, flag definitions; inventory `dependencies_declared`, `env_*`, `feature_flags` | What is declared, so REVIEW can ask what is used |

## 2. Purpose items

| Field | Rules |
|---|---|
| `id` | `PB-` and two or three digits, unique |
| `kind` | `statement` (what the product is for), `user` (target users), `job` (a core job; at least one is required), `non_goal` (what the product deliberately does not do), `scale` (users, tenants, locales, data volume, deployment shape) |
| `text` | The item in one sentence, in the product's own words where it has them |
| `source` | `documented` (a file in the repository or a document the requester supplied), `stated` (the requester said so), `inferred` (navigation, landing copy, usage of entry points) |
| `evidence` | `path:line`, or a short reason for `stated` and `inferred` |

A finding resting on an `inferred` item must be `Purpose-dependent`
(`findings.py` refuses any other confidence); it is at most `Likely` and is
named in `decisions` so a human makes the keep or remove call.

## 3. Entry points, consumers, units

| Field | Rules |
|---|---|
| `entry_points[].id` | `EP-` and two or three digits, unique |
| `entry_points[].kind` | `endpoint`, `screen`, `cli`, `job`, `webhook`, `hook`, `package`, `other` |
| `entry_points[].exposure` | `public` (reachable from the internet without privilege), `authenticated`, `admin`, `internal` (CLI, job, in-process hook), `partner` (called by a named third party) |
| `entry_points[].name`, `location` | The entry as a reader would name it, and its `path:line` |
| `consumers[]` | `name` (unique), `kind` (`web`, `mobile`, `service`, `partner`, `ops`, `library-user`, `other`), `in_repo` (true when its code is in this repository), `evidence` |
| `units[].id` | `UN-` and two or three digits, unique |
| `units[].name` | The area as a reader would name it ("Server API"); required |
| `units[].kind` | `area` (a part of the product reviewed from its entry points) or `shared` (dependencies, configuration, data and schema, tooling, docs) |
| `units[].paths` | Repository-relative path prefixes; the most specific prefix owns a file |
| `units[].entry_points` | Entry point ids reviewed in this unit; every entry point belongs to at least one unit |

Keep units few: three to eight cover most apps.

## 4. `units.json`

Written as fragments in scratch and merged with
`scripts/findings.py units <out>/units.json <fragment>…` (run from the skill's
directory by absolute path, SKILL.md *Paths*): purpose items, entry points and
units are added or replace the one with the same id, consumers the one with the
same name; `app` is replaced when a fragment carries it. The command refuses a
change that would leave a finding in `findings.json` beside it citing a unit,
entry point or purpose item that no longer exists, or a finding other than
`Purpose-dependent` resting on a purpose item that became `inferred`.

```json
{
  "app": "Larder",
  "purpose": [
    {"id": "PB-03", "kind": "job", "text": "Add, list and remove pantry items.", "source": "documented", "evidence": "README.md:7"},
    {"id": "PB-05", "kind": "non_goal", "text": "Social or comparison features between households.", "source": "documented", "evidence": "README.md:11"}
  ],
  "entry_points": [
    {"id": "EP-06", "kind": "endpoint", "name": "GET /debug/dump", "location": "server/app.py:56", "exposure": "public"}
  ],
  "consumers": [
    {"name": "iOS app 2.x", "kind": "mobile", "in_repo": false, "evidence": "docs/clients.md:6"}
  ],
  "units": [
    {"id": "UN-01", "name": "Server API", "kind": "area", "paths": ["server/"], "entry_points": ["EP-06"]}
  ]
}
```

`scripts/inventory.py --units` tags every candidate with the unit whose paths
cover it and counts candidates per unit (`by_unit`).
