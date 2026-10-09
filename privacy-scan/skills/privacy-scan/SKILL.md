---
name: privacy-scan
description: "Static privacy review of an application's own source: maps personal data, where it flows and who receives it, then checks minimisation, consent, retention and deletion, data subject rights, third-party sharing, logs and telemetry, exposure, storage, tracking and copies. Outputs a dashboard and a report. Read-only; not legal advice. Use to find privacy gaps or list what to check."
allowed-tools: Read, Grep, Glob, Bash, Write
---

## Owns

Finding where an application's handling of personal data departs from what it
promises or needs, **by reading its source**. The output is a ranked list of
findings, each with a `file:line`, the personal data involved, whose data it is,
the flow from collection to the place it should not reach (or the store it is
never deleted from), what goes wrong and how sure the finding is — or, when
only a plan is asked for, a checklist tailored to this application.

It does not change code, does not read data stores, and does not decide legal
compliance. It compares the code with the application's own commitments
(privacy policy, consent texts, retention rules, contracts in the repository)
and with the requirements the requester names. Whether a gap is a legal breach
is a decision for the requester and their counsel; the report says so.

Phases: `RECON → CHECKLIST → REVIEW → VERIFY → REPORT`.

## Before starting

- **Confirm scope in one line.** The repository is the requester's, the
  review is static, no data store or production system is read, and the result
  is not legal advice. Ask which regulations or frameworks matter (e.g. GDPR,
  APPI, CCPA, HIPAA) only when the requester has not named any and the answer
  changes what to check; otherwise review against the app's own commitments
- **Name the data subjects before reading models**: end users, customers'
  customers, employees, children, visitors who never sign up, people named by
  others (contacts, invitees). Most privacy gaps are one subject's data reaching
  a place they were never told about
- **Name the sensitive categories**: health, biometrics, precise location,
  financial and government identifiers, children's data, communications
  content, special categories under the named regulation. Severity is judged
  against these
- **Derive the commitments before hunting**: what this app promises or must
  keep — purposes, retention periods, deletion and export paths, the
  processors it shares with, consent conditions (`reference/commitments.md`).
  Essential privacy gaps are violations of these on some path; a generic
  scanner cannot see them because the commitments exist only for this app
- **Create a new, empty output directory** outside the audited repository and
  follow the *Run contract* below

## Run contract

| Item | Fixed choice |
|---|---|
| Independence | Never read another assessment's outputs (an earlier `findings.json`, another host's report) unless the request is to merge or compare them |
| Review units | One unit per data domain (accounts and identity, payments, content and messages, analytics, support, HR…) plus one cross-cutting unit (logging, error tracking, analytics SDKs, backups, config, client-side scripts). Each unit first hunts the commitments ledger entries it owns, then sweeps every applicable perspective once. A unit closes only when its close-check matches (`reference/commitments.md` §4). With subagents, one reviewer per unit; without, the same units sequentially. Reviewer notes stay in scratch |
| Granularity | One finding per root cause, i.e. per fix location. The same personal field leaking through one shared logger is one finding that lists every call site in `flow`; gaps needing different fixes are separate findings |
| IDs | `PV-001`… numbered without gaps in severity order (then path); `FalsePositive` and `NotApplicable` findings may sit anywhere. No other prefixes |
| Severity | The table below, decided before confidence; confidence never raises or lowers it |
| Outputs | Exactly `findings.json`, `dashboard.html`, `report.md`, in the requester's language. No extra files unless asked (`findings.py check --allow NAME`) |
| `meta.assessor` | Host and model, e.g. `Claude Code (<model>)`, `Codex (<model>)` |
| Effort | When the effort runs short, close units in risk order (sensitive categories, third-party flows and deletion first) instead of thinning every unit. `limitations` gives the count of unreached units and ledger entries |
| Scratch | A new, empty directory for working records (data map, ledger, flow rows, fragments), outside both the audited repository and the output directory: the host's session scratch when it names one, otherwise a fresh directory under `$TMPDIR`. Name its path in the chat summary |
| Writing the record | Never build `findings.json` with a shell heredoc, `echo`/`printf` redirection or a generated script. Write each batch of one to five findings as a JSON fragment with the host's file-write tool into scratch, then `scripts/findings.py merge <out>/findings.json <fragment>…`. The first fragment carries `meta` (`reference/findings-schema.md`). The merge refuses text containing e-mail addresses or long digit runs: name fields and use placeholders |
| Read-only | Read, search, run read-only `git` commands and this skill's scripts; the file-write tool is for scratch records and fragments only; write nothing inside the audited repository |

| Severity | When |
|---|---|
| High | Personal data — any sensitive category, or broad personal data of many subjects — reaches a party or place the commitments exclude (an undisclosed third party or SDK, an external log or error service, another user or tenant, a public URL), is processed on a core flow without a consent the commitments require (tracking before opt-in, marketing without opt-in), or survives a deletion or account-closure path in a primary store |
| Medium | A High-class gap that needs one condition the code does not control (a deployment region, a setting, an SDK option, a log level in production), ordinary personal data kept beyond a stated retention period, a deletion or export path that misses a secondary store (cache, search index, analytics warehouse, file storage), or real personal data copied into non-production use |
| Low | Collection beyond need with no further exposure, missing pseudonymisation in internal analytics, identifiers in URLs inside first-party systems, defence-in-depth gaps in storage protection |
| Info | A note with no demonstrated path to a subject's harm or a broken commitment |

Grade a gap by the row it would match if every condition it needs held, then
lower it one level for each condition the code does not control (a High-class
gap behind one deployment setting is Medium). An `Environment-dependent`
finding names each such condition; confidence never changes the grade.

## Phases

| Phase | Do | Reference |
|---|---|---|
| RECON | Build the data map: stack, every personal data element and where it is collected, stored, copied, sent and displayed; data subjects and sensitive categories; consent mechanisms; retention jobs and deletion and export paths; third parties and SDKs with what they receive; logs, telemetry and error tracking; storage and backups; non-production copies; the commitments documents in the repository. End by deriving the commitments ledger | `reference/recon.md`, `reference/commitments.md` |
| CHECKLIST | Ledger first: each commitment with its source and every flow that must keep it. Then the perspectives that apply, keeping only hunt steps no ledger entry covers; attach early suspicions marked unverified | `reference/commitments.md`, `reference/perspectives.md`, `reference/report.md` |
| REVIEW | One pass (or one reviewer) per review unit. For each owned commitment, trace every flow that must keep it with one flow row per data element and sink: source `path:line` → transformations → sink `path:line`. Every control cell names the mechanism — a consent check, a redaction filter, a field allow-list, a retention job, a deletion cascade, an SDK option — at `path:line`, or `NONE` / `N/A` / `UNKNOWN` with a reason — never "the vendor handles it". Then the sink-backward pass (every log call, analytics event, outbound client and export near personal fields maps to a row), then sweep every applicable perspective's hunt steps | `reference/commitments.md`, `reference/perspectives.md` |
| VERIFY | Record evidence-linked reach, data, mitigations and impact; try to falsify each claim (a scrubber on the logger, a consent gate upstream, a retention job, a DPA listing the processor); keep deployment settings and vendor configuration outside the repository explicit | `reference/validation.md` |
| REPORT | Write `findings.json` through fragments and `scripts/findings.py merge`; render with `scripts/render.py <out>/findings.json --out <out> --lang <ja or en>` after the last merge; pass `scripts/findings.py check <out>`, which also refuses stale reports; then give the summary in chat | `reference/findings-schema.md`, `reference/report.md` |
| GUARD *(on request)* | With explicit permission, add a check to the repo's own suite that keeps a commitment — a test that the logger redacts named fields, that deletion removes the subject from every store, that an SDK is not initialised before consent, that an export contains every store — red before the fix and green after, using synthetic data only | `reference/validation.md` |

## Outputs

| Output | What it is |
|---|---|
| Chat summary | First line status and counts, findings by severity, decisions for a human |
| `findings.json` | The single source every other output is rendered from |
| `dashboard.html` | Self-contained dashboard: counts, filterable findings, commitments, perspective coverage |
| `report.md` | The written assessment: scope, findings, commitments, coverage, sound items, limitations, next steps |

Skip the files when only a checklist was asked for. Render them in the
requester's language (`--lang ja|en`).

## Decide first

| Situation | How to proceed |
|---|---|
| Asked "what should we check" or "list the items" | RECON and CHECKLIST only, then stop and deliver the checklist |
| Asked to check, audit or scan privacy or data protection | All five phases |
| Asked about one feature, SDK or data flow | Scope the review units to the flows it touches, plus the cross-cutting unit; say the rest was not read in `limitations` |
| No privacy policy or retention rule is in the repository | Infer the commitments from consent UI texts, settings screens, retention jobs and the majority of flows; mark them `inferred`, hunt them anyway, and put each in `decisions`. Ask for the published policy if the requester can share it |
| A regulation is named | Add its requirements as commitments with the regulation as source, phrased as checks on the code (e.g. "deletion reaches every store holding the subject's data"). Never state that the app is or is not compliant |
| A third party receives data | Record exactly which fields reach it, from where and when (before or after consent). Whether a contract or DPA covers it is `UNKNOWN` unless the repository says so; put it in `decisions` |
| The data reaching a sink depends on runtime values (log level, SDK options set by environment, region) | Report as `Environment-dependent` and name the setting |
| Real personal data appears in the repository (fixtures, seeds, dumps, screenshots) | Report its location and kind only. Never print the values; never copy them into scratch or the record |
| The requester asks to look at production data, logs or a database | Decline for this skill: it reviews code. Suggest which query or log search they could run themselves to confirm a finding |
| Asked to lock a commitment in or confirm a fix | GUARD: a test in the repo's own suite with synthetic data, red before and green after |
| The host cannot run a second, independent reviewer | Record that in `limitations`; High findings stay `Likely` unless the reporting agent traced them end to end. Never invent a second reviewer |
| Asked to file findings as issues or write them up for an owner or DPO | Draft from `findings.json`: `templates/issue.<lang>.md` per finding, `templates/report.<lang>.md` for one report covering several. An open High goes to a private tracker. Filing or sending is the requester's step |

## Always / Never

- Always: anchor every finding to `file:line` and name the personal data
  elements, the data subjects and the flow from source to sink
- Always: give every finding static reproduction steps — the subject and the
  data they provide, numbered steps of the flow (collection, processing, sink)
  with `path:line`, the `Contrast:` flow that keeps the commitment (or `none`), and
  expected vs actual naming the violated commitment — a one-line fix direction
  stated as the commitment restored, and at least one guard (`reference/commitments.md` §5)
- Always: grade **severity** (High / Medium / Low / Info) and **confidence**
  (Confirmed / Environment-dependent / Suspected) separately, and keep the
  verification basis (`static` or `analysed`) separate from both
- Always: list what was checked and found sound. A report with no negatives
  cannot be told apart from a report that did not look
- Always: say what static reading cannot show — data actually present,
  deployed settings, vendor-side configuration, contracts and DPAs, what the
  published policy says if it is not in the repository
- Always: state in the report that it is a technical review and not legal
  advice
- Never: read, query or export personal data from any data store, log or
  backup; never print personal data values found in the repository
- Never: edit source, configs or dependencies during the review
- Never: send source, findings or data to external services
- Never: state that the application is or is not compliant with a law
- Never: report a High or Medium finding you have not traced end to end yourself
- Never: delete a finding judged false — mark it `FalsePositive` or
  `NotApplicable` with evidence so the exclusion is visible

## Verify with

- Every High and Medium finding is traced source → sink by the agent writing
  the report, each hop at `path:line`
- Every "reaches a third party" claim names the exact fields sent, checked
  against the serializer or event payload actually built, not inferred from
  the SDK being present
- Every logging claim is checked against redaction filters, scrubbers and
  `beforeSend`-style hooks configured for that logger or SDK
- Every deletion claim lists every store holding the data element (from the
  data map) and shows which ones the deletion path reaches
- `Unverified`, `Likely` and `Unlikely` remain verification-incomplete; recorded
  verdicts are not upgraded automatically

## Done when

`scripts/findings.py check <out>` passes, every flow carrying a sensitive
category or reaching a third party has been read, every commitments ledger
entry has a status (holds on all flows, violated, partly read, or not checked
with the reason), every review unit's close-check matches with zero blank
cells, every perspective in `reference/perspectives.md` is recorded as applied,
N/A or not checked, every High and Medium finding has a recorded verdict and
evidence, and the report states its own blind spots and that it is not legal
advice.
