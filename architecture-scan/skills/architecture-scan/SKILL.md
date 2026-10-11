---
name: architecture-scan
description: "Read-only architecture review of your own app: maps modules, dependencies, data ownership and hotspots, then checks layering, boundaries, coupling, cohesion, consistency, failure handling, contracts, config, testability and operability. Outputs a dashboard and a report. Use for design audits, dependency cycles or structural risks. Not for security, performance or refactoring."
allowed-tools: Read, Grep, Glob, Bash, Write
---

## Owns

Finding design problems in a codebase the requester owns, **by reading it**:
places where the structure lets the application behave incorrectly, or makes
the changes it actually needs costly and risky. The output is a ranked list of
findings, each with a `file:line`, the change scenario or flow it affects, the
blast radius (which modules, files or data it reaches), a trace that shows the
problem, what goes wrong and how sure the finding is — or, when only a plan is
asked for, a checklist tailored to this application.

It does not refactor code and does not judge taste. A structure that differs
from a textbook but causes no defect and no change cost is not a finding.
Refactoring is a separate, later request.

Phases: `RECON → CHECKLIST → REVIEW → VERIFY → REPORT`.

## Before starting

- **Confirm scope in one line.** The repository is the requester's, the
  review is static, and nothing is changed. Read-only analysis (`git log`,
  a dependency-graph tool already installed) is allowed and named
- **Name the change scenarios before reading modules**: the changes this app
  must absorb — the features on the roadmap or in recent history, a new
  provider or channel, a new tenant type, a schema change, scaling out. Design
  quality is relative to these; a rigid module nobody changes costs little
- **Name the core flows**: the flows whose correctness matters most (payment,
  ordering, provisioning, permissions, billing, data sync). Severity is judged
  against these
- **Derive the design rules before hunting**: the rules this codebase states
  for itself — layer direction, module boundaries, who owns which data, where
  transactions start and end, how failures propagate, how config is read
  (`reference/rules.md`). Most real design findings are violations of the
  codebase's own rules on some path; a generic linter cannot see them because
  the rules exist only here
- **Create a new, empty output directory** outside the audited repository and
  follow the *Run contract* below

## Run contract

| Item | Fixed choice |
|---|---|
| Independence | Never read another assessment's outputs (an earlier `findings.json`, another host's report) unless the request is to merge or compare them |
| Review units | One unit per top-level module, bounded context or service, plus one cross-cutting unit (shared kernel, framework setup, config, error handling, persistence infrastructure). Each unit first hunts the rules ledger entries it owns, then sweeps every applicable perspective once. A unit closes only when its close-check matches (`reference/rules.md` §4). With subagents, one reviewer per unit; without, the same units sequentially. Each unit numbers its fragments in its own block (unit 1 `A-101`…, unit 2 `A-201`…) so no two units write the same ID; merge refuses a complete finding whose ID holds a different one. Reviewer notes stay in scratch |
| Granularity | One finding per root cause, i.e. per fix location or per design decision. The same boundary violated from ten call sites is one finding that lists them in `trace`, and a root cause that breaks several ledger rules cites them all in `rule` (`R-01, R-02`); problems needing different fixes are separate findings |
| IDs | `A-001`… numbered without gaps in severity order (then path), excluded verdicts last. No other prefixes. Number fragments in any order; `scripts/findings.py renumber` restores the order and rewrites ID mentions before rendering. After it, use only the new IDs it prints |
| Severity | The table below, decided before confidence; confidence never raises or lowers it |
| Outputs | Exactly `findings.json`, `dashboard.html`, `report.md`, in the requester's language. No extra files unless asked (`findings.py check --allow NAME`) |
| `meta.assessor` | Host and model, e.g. `Claude Code (<model>)`, `Codex (<model>)` |
| Effort | When the effort runs short, close units in risk order (core flows and change hotspots first) instead of thinning every unit. `limitations` gives the count of unreached units and ledger entries |
| Scratch | A new, empty directory for working records (module map, ledger, trace rows, fragments), outside both the audited repository and the output directory: the host's session scratch when it names one, otherwise a fresh directory under `$TMPDIR`. Name its path in the chat summary |
| Writing the record | Never build `findings.json` with a shell heredoc, `echo`/`printf` redirection or a generated script. Write each batch of one to five findings as a JSON fragment with the host's file-write tool into scratch, then `scripts/findings.py merge <out>/findings.json <fragment>…`. With parallel units, the coordinator (the agent writing the report) merges the first fragment, carrying `meta` and the ledger with provisional statuses (`not checked` with the `reason` "provisional: traced by unit N"); units merge only `findings`; after every unit closes, the coordinator merges each rule's final status (with `"reason": null` unless it stays `not checked` or `partly read`) and the `perspectives` entries, combining the units' notes, since a perspective entry is replaced whole (`reference/findings-schema.md`) |
| Read-only | Read, search, run read-only `git` commands and this skill's scripts; the file-write tool is for scratch records, fragments and read-only analysis scripts run from scratch only; write nothing inside the audited repository (the only exception is GUARD, with explicit permission) |

| Severity | When |
|---|---|
| High | The structure already allows incorrect behaviour or data damage on a core flow: two writers of the same state applying different rules, a business rule duplicated and already diverged, a dual write (database plus message, database plus external API) with no recovery, a non-idempotent consumer on an at-least-once channel, failures swallowed so a core flow reports success after partial work. Also a dependency cycle or boundary breach that forces lockstep changes across modules in an area the history shows changes often |
| Medium | A High-class consistency or failure risk that needs one condition the code does not control (concurrent requests, a retry, a partial outage), or a rule violation that measurably raises change cost on an actively changed area (co-change across boundaries, a hotspot module carrying several responsibilities), or a contract that leaks internal models to external clients |
| Low | A rule violation in stable or peripheral code, an inconsistency of patterns without demonstrated cost, a missing seam that makes one area hard to test |
| Info | A design note with no demonstrated defect or change cost |

Each further condition the code does not control lowers severity one level. An
`Environment-dependent` finding names its condition (e.g. "if the queue
delivers at least once"), and that condition counts as one the code does not
control: a High-class risk that needs it is Medium. The condition lowers the
severity; the confidence label says only how sure the finding is.

`Environment-dependent` is for deployment and delivery conditions the
repository does not state (delivery semantics, instance count, client
retries). A failure that can always happen — a crash or timeout between two
steps, a commit that fails, a broker or provider that is down — is not one: a
finding that needs it is `Confirmed` once the path is traced, and the failure
lowers severity only where the High list does not already assume it (a dual
write with no recovery is High because it fails exactly then).

Worked examples:

- Concurrent requests are not uncontrolled when the repository runs more than
  one worker or replica (gunicorn `workers`, Kubernetes `replicas`,
  autoscaling): a lost update on a balance with `replicas: 3` is High and
  `Confirmed`
- A destructive migration shipped with code that still reads the column on a
  core flow is High
- "Changes often" means top-decile churn in the history window, or at least
  three comparable changes in it
- A derived copy that a core write path leaves stale (TX5) is High when nothing
  bounds the staleness, Medium when a TTL or a periodic rebuild bounds it
- A client contract that has already drifted and renders or sends wrong data on
  a core flow (AC2) is High, like a duplicated rule that has diverged; drift
  not yet visible in behaviour is Medium

## Phases

| Phase | Do | Reference |
|---|---|---|
| RECON | Build the module map: stack, deployable units, modules and their declared layers, the import/dependency graph and its cycles, entry points per module, data stores and which modules write each table or collection, messaging and integration points, transaction and error-handling conventions, config loading, and the change history (hotspots and co-change, read-only). End by deriving the rules ledger | `reference/recon.md`, `reference/rules.md` |
| CHECKLIST | Ledger first: each rule with its source and every module or path that must keep it. Then the perspectives that apply, keeping only hunt steps no ledger entry covers; attach early suspicions marked unverified | `reference/rules.md`, `reference/perspectives.md`, `reference/report.md` |
| REVIEW | One pass (or one reviewer) per review unit. For each owned rule, trace every edge or path that must keep it with one trace row per edge: from `path:line` → to `path:line`, which rule, verdict. Every control cell names the enforcing mechanism (an import-lint contract, a module's public interface, a repository that is the only writer, a transaction wrapper) at `path:line`, or `NONE` / `N/A` / `UNKNOWN` with a reason — never "the framework separates it". Then the writer-backward pass (every write to a core table maps to a row), then sweep every applicable perspective's hunt steps | `reference/rules.md`, `reference/perspectives.md`, `reference/findings-schema.md` |
| VERIFY | Record evidence-linked reach, consequence, mitigations and change cost; try to falsify each claim (a facade that routes all calls, an outbox, an idempotency key, a test that pins the rule); keep runtime and organisational unknowns explicit | `reference/validation.md` |
| REPORT | Write `findings.json` through fragments and `scripts/findings.py merge`; `scripts/findings.py renumber <out>/findings.json`; render with `scripts/render.py <out>/findings.json --out <out>` (the language is `meta.lang`); pass `scripts/findings.py check <out> --repo <checkout>`. When check fails, correct the record with a fragment (`reference/findings-schema.md`, *Correcting the record*), renumber if a finding was added or regraded, render and check again; then give the summary in chat | `reference/findings-schema.md`, `reference/report.md`, `reference/rules.md` §5, `reference/perspectives.md` |
| GUARD *(on request)* | With explicit permission, add a fitness function to the repo's own suite that encodes a rule — an import or layer contract, a cycle check, a single-writer check, a contract test — and show it fails on the current violation. Show it passing after the fix on a scratch copy with the smallest fix applied; apply the fix in the repository itself only with separate permission for that. Record it per `reference/validation.md` (*Fitness functions*), then merge, render and check again | `reference/validation.md` |

## Outputs

| Output | What it is |
|---|---|
| Chat summary | First line status and counts, findings by severity, decisions for a human |
| `findings.json` | The single source every other output is rendered from |
| `dashboard.html` | Self-contained dashboard (security-scan layout): counts, priority queue, filterable findings, design rules, perspective coverage |
| `report.md` | The written assessment: scope, findings, rules, coverage, sound items, limitations, next steps |

Skip the files when only a checklist was asked for. Set `meta.lang` to the
requester's language (`ja` or `en`); render uses it, and `check` requires it.

## Decide first

| Situation | How to proceed |
|---|---|
| Asked "what should we check" or "list the items" | RECON and CHECKLIST only, then stop and deliver the checklist: a short form in chat, and the full ledger and perspective sections in `<scratch>/checklist.md` when they are long, named in chat |
| Asked to review, audit or scan the design or architecture | All five phases |
| Asked about one module, feature or planned change | Scope the review units to the modules the change touches, plus the cross-cutting unit; say the rest was not read in `limitations` |
| No document states the intended architecture | Infer the rules from the directory structure, import-lint config, framework conventions and the majority of modules; mark them `inferred` in the ledger, hunt them anyway, and put each rule in `decisions` |
| The intended architecture is documented (ADRs, README, diagrams) | The documents are the rules; where code and documents disagree, the disagreement is a finding or a `decisions` item, never silently resolved in either direction |
| Several deployable services in the repo | One review unit per service; check shared databases, shared libraries carrying domain logic, synchronous call chains and contract versioning between them |
| Change cost is the claim | Back it with history: co-change counts across the boundary, churn of the hotspot, or the number of files a recent comparable change touched (`git log`, read-only). Without history, confidence is at most `Suspected` |
| Consistency depends on delivery semantics or deployment | Report as `Environment-dependent` and name the condition (at-least-once delivery, more than one instance, retries in the client). When the repository itself states the condition (broker config such as Celery `task_acks_late` or Kafka `enable.auto.commit=false` with a retrying error handler, a README or ADR that says "at least once"), it is not uncontrolled: the finding is `Confirmed` and keeps its severity, citing that source |
| Authorization or tenant scoping is in question | Where it is enforced (one owner every path goes through, or a check repeated per call site) is in scope (`DM5`); whether it can be exploited is a security review, so name that in `next_steps` instead of grading it |
| A pattern is merely unfamiliar or not to taste | Not a finding. Record it only if it causes a defect, a change cost or an inconsistency the history shows |
| The requester wants a dependency graph or metrics | Run an already-installed, read-only analysis tool on the local checkout, name it before running, and record tool, command and result in `analysis`. Never install packages into the audited repository |
| Asked to lock a rule in or confirm a fix | GUARD: a fitness function in the repo's own suite, red on the current violation and green after the fix |
| The host cannot run a second, independent reviewer | Record that in `limitations`. A High finding may be `Valid` once the reporting agent has traced it end to end; until then it is not reported (see *Never*). Never invent a second reviewer |
| Asked to file findings as issues or write them up for an owner | Draft from `findings.json`: `templates/issue.<lang>.md` per finding (one root cause per issue), `templates/report.<lang>.md` for one report covering several, its `{{n_*}}` counts from `scripts/findings.py counts <out>/findings.json`. Excluded findings (`FalsePositive`, `NotApplicable`) are never filed. Write the drafts in scratch (`<scratch>/drafts/`), not in `<out>`, unless asked; then `check <out> --allow drafts`. Filing or sending is the requester's step |

## Always / Never

- Always: anchor every finding to `file:line` and name the scenario or flow it
  affects and its blast radius (modules, files, tables or clients reached)
- Always: give every finding a trace — the dependency path, the two writers, or
  the walk through a change scenario as numbered steps — the `Contrast:`
  module or path that keeps the rule, and expected vs actual naming the
  violated rule; a one-line fix direction stated as the rule restored, and at
  least one fitness function or test that would keep it (`reference/rules.md`
  §5)
- Always: grade **severity** (High / Medium / Low / Info) and **confidence**
  (Confirmed / Environment-dependent / Suspected) separately, and keep the
  verification basis (`static` or `analysed`) separate from both
- Always: list what was checked and found sound. A report with no negatives
  cannot be told apart from a report that did not look
- Always: say what static reading cannot show — runtime topology, delivery
  semantics of the deployed broker, team ownership, the roadmap, data actually
  present
- Never: edit source, configs or dependencies during the review (GUARD, after
  the review and with explicit permission, adds the fitness function; a fix
  needs its own permission, and is otherwise shown on a scratch copy)
- Never: report preference as a defect ("should use hexagonal architecture",
  "too many files") without a demonstrated defect, change cost or inconsistency
- Never: recommend a rewrite as a fix direction. Name the smallest change that
  restores the rule, and the order of steps if it is large
- Never: report a High or Medium finding you have not traced end to end yourself
- Never: delete a finding judged false — mark it `FalsePositive` or
  `NotApplicable` with evidence so the exclusion is visible

## Verify with

- Every High and Medium finding is traced by the agent writing the report,
  each hop at `path:line`
- Every "two writers" or "duplicated rule" claim lists every writer or copy
  found by search, and checks whether one delegates to the other
- Every change-cost claim cites history (co-change, churn, a recent change's
  file count) or is marked `Suspected`
- Every consistency claim names the failure point (which call can fail after
  which commit) and checks for an outbox, saga, compensation, idempotency key
  or reconciliation job before calling it unhandled
- `Unverified`, `Likely` and `Unlikely` remain verification-incomplete; recorded
  verdicts are not upgraded automatically

## Done when

`scripts/findings.py check <out> --repo <checkout>` passes, every module on a core flow or change
hotspot has been read, every rules ledger entry has a status (holds on all
paths, violated, partly read, or not checked with the reason), every review
unit's close-check matches with zero blank cells, every perspective in
`reference/perspectives.md` is recorded as applied, N/A or not checked, every
High and Medium finding has a recorded verdict and evidence, and the report
states its own blind spots.
