# Report — output formats

**Read when:** CHECKLIST, to deliver a checklist; REPORT, to deliver findings.
Write in the requester's language.

## Checklist deliverable

- First line: how many crown jewels, entry actors and attack-path hypotheses,
  how many perspectives apply, and that suspicions are unverified
- **Attack-path hypotheses first**: `AP-nn: actor → … → jewel`, with the first
  edge to check and the files to read
- Then one section per applicable perspective, most important first, listing
  only the hunt steps no hypothesis covers; perspectives judged N/A with a reason
- The `I-*` baseline hits from `iac_scan.py`, grouped by rule, as items to triage
- Close with the inputs that would most improve the review (a plan JSON for
  prod, the SCP / org policy export) and one decision for the requester

## Findings report (chat summary)

1. **First line** — severity counts, open attack paths, scope (accounts /
   projects / environments), and that the review was static from configuration
2. **Evidence line** — inputs read (IaC at commit, plan JSON, snapshots with
   capture time), what was re-read, what stays unknown
3. **Open attack paths** — `AP-nn` entry → jewel, with the findings that open it
4. **Findings, by severity**:

   ```
   [High|Medium|Low][Confirmed|Environment-dependent|Suspected] title
     resource: address(es)            location: path:line
     actor: entry actor and preconditions
     path: numbered edges, each with path:line
     contrast: a sibling configured soundly (path:line) or "none"
     impact: expected vs actual; what the actor can do to which jewel
     verdict: Valid / Likely / … with the evidence summary
     fix: one line — the boundary restored and where
     regression: the policy-as-code assertion
     controls: benchmark section; CWE
   ```

5. **Checked and sound** — paths that ended `blocked` and the control that
   blocked them; hits judged intended
6. **Decisions for a human** — intended public exposure to confirm, third-party
   trusts to keep or remove, guardrails to confirm outside the inputs
7. **Next step** — the fix order (open High paths first, then the edge shared by
   most paths)
8. **Files** — link `dashboard.html` and `assessment.pdf`

Keep the chat, dashboard and PDF consistent: all are views of `findings.json`.

## Limitations to state

Always, when true:

- Static review of declared configuration; deployed state may differ (unless a
  snapshot was supplied, with its capture time)
- Values from variables without defaults, remote state, data sources and
  unfetched modules were `UNKNOWN`
- Guardrails outside the inputs (SCPs, org policies, perimeters) were not read
- Resources created outside IaC are not covered (unless a snapshot was supplied)
- `iac_scan.py` `not_run` entries, verbatim
- Zero findings is not an all-clear

Never print secret values; location and kind only. Describe permission chains
and fix directions, not exploitation steps.

Source excerpts omit JSON/YAML documents with CloudFormation `NoEcho` metadata
unless its value is explicitly false (boolean or string). Unresolved values,
including opaque YAML block strings, also omit the excerpt. Parameter defaults
may be secret even when their names do not look sensitive.
