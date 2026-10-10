# Commitments — derive what this app promises, then hunt the flows that break it

**Read when:** end of RECON (derive the ledger), CHECKLIST (deliver it), REVIEW
(hunt each entry), REPORT (write flows and fix directions). **Reader:** the
agent running the skill, cold. **Decision it supports:** which flows to trace,
and what counts as a gap in *this* application.

The privacy gaps that matter are flows that break what this application
promises or must keep: *we delete your data within 30 days of closing your
account*, *analytics runs only after consent*, *we share your data only with
the processors listed here*, *support staff see masked card numbers*. No
generic rule knows them, so they are written down before the code is judged.

## 1. Derive commitments from where the app already states them

Strongest first:

1. **Published texts in the repository** — privacy policy, consent texts,
   cookie notices, settings-screen copy, sub-processor lists, and app-store
   privacy declarations with permission purpose strings (iOS privacy manifests,
   Google Play Data safety answers, `Info.plist` and `AndroidManifest.xml`
   usage descriptions)
2. **Regulations the requester named** — each requirement phrased as a check
   on the code, with the regulation as source
3. **Configuration and jobs** — retention TTLs, deletion jobs, consent
   manager config, redaction filters
4. **The majority of flows** — if every logger but one redacts e-mail, the
   others state the rule
5. **Tests and docs** — tests that assert redaction or deletion, data maps,
   DPIAs, records of processing
6. **Comments and issues** — "do not log", "PII", TODOs about deletion

Write each commitment with its source (`path:line`, or the named regulation).
A commitment inferred only from sources 4–6 is marked `inferred`, and the
commitment itself goes to `decisions` so a person can confirm it.

## 2. The ledger

| ID | Commitment | Source | Family | Flows that must keep it | Status |
|---|---|---|---|---|---|

Families:

- **MIN** — collect only what a stated purpose needs
- **CONSENT** — process for consent-based purposes only after a recorded,
  current consent; honour withdrawal
- **RETAIN** — keep each element no longer than its stated period, in every
  store
- **RIGHTS** — access, export, rectification and deletion reach every store
  and processor holding the subject's data
- **SHARE** — personal data reaches only the third parties, fields and
  storage or processing locations the commitments name
- **CONTAIN** — personal data stays out of logs, telemetry, URLs, errors,
  non-production copies and the view of actors who do not need it
- **PROTECT** — sensitive categories are encrypted, pseudonymised or tokenised
  where the commitments or the named regulation require

Seed the ledger with one `baseline` entry per family that applies (e.g. `C-01
CONTAIN baseline: no personal field is written to logs or error trackers
unredacted`), then add app-specific entries. *Status* is `holds`, `violated`,
`partly read` or `not checked` (with a reason).

## 3. Flow rows

For each ledger entry, one row per data element and sink:

| Entry | Element | Source (`path:line`) | Hops | Sink (`path:line`) | When | Control | Verdict |
|---|---|---|---|---|---|---|---|

- *Sink*: a store, a log or telemetry call, a third-party payload, a response
  or view seen by another actor, a copy
- *When*: relative to consent, account state (active, closed, deleted) or
  retention period, where it matters
- *Control* names the mechanism — consent check, redaction filter, field
  allow-list, retention job, deletion cascade, SDK option, encryption — at
  `path:line`, or `NONE`, `N/A` (reason) or `UNKNOWN` (what would decide it)
- *Verdict*: `holds`, `violated`, or `lead` (needs VERIFY)

For RETAIN and RIGHTS entries, add one row per store from the data map and
show whether the job or path reaches it.

## 4. Close-check per review unit

A unit closes when: every owned entry has a row for every element and sink
found by search (record the search and its hit count); every *Control* cell is
filled (zero blank); every `lead` is resolved into a finding, a `checked_ok`
line or a `limitations` line. Record the counts in scratch, one line per unit:

```
close-check <unit>: entries 6, elements 14, rows 31, blank 0, leads 3 resolved (2 findings, 1 checked_ok), searches 9
```

A unit with `blank` above zero or an unresolved lead is not closed.

## 5. From a violated row to a finding

Each finding carries:

- `data` — the personal data elements by field name, with their category
- `subjects` — whose data, and how many are affected (all users, users of one
  feature, closed accounts)
- `flow` — numbered steps: collection `path:line`, each hop, the sink
  `path:line`, and when (before consent, after deletion…)
- `contrast` — the flow that keeps the commitment, at `path:line`, or "none"
- `impact` — expected (the commitment) vs actual, and who can then see or use
  the data
- `commitment` — the ledger ID
- `fix` — one line: the commitment restored and where (add the field to the
  redaction list at `path:line`, gate SDK initialisation on consent, add the
  search index to the deletion cascade)
- `guard` — at least one deterministic check with synthetic data: the logger
  output for a request carrying a named field contains a redaction marker;
  deleting a synthetic user leaves no row in each listed store; the SDK is not
  initialised while consent is absent
