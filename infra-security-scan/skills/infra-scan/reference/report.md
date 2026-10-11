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
   capture time), what was re-read, what stays unknown, the scratch directory
   used, and any step the host refused (with what was done instead)
3. **Open attack paths** — `AP-nn` entry → jewel, with the findings that open it
4. **Findings, by severity**:

   ```
   [High|Medium|Low|Info][Confirmed|Environment-dependent|Suspected] title
     resource: address(es)            location: path:line
     attack paths: AP-nn, or "none"   perspective: category
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
8. **Files** — link `dashboard.html` and `assessment.pdf` (or say the PDF was
   not generated, as `limitations` does)

Keep the chat, dashboard and PDF consistent: all are views of `findings.json`.
Re-rendering invalidates the previous `assessment.pdf`, including with
`--no-pdf`. If PDF generation is skipped or fails, no old PDF is retained beside
the updated HTML reports; only a newly generated PDF belongs to that run.

## Limitations to state

Always, when true:

- Static review of declared configuration; deployed state may differ (unless a
  snapshot was supplied, with its capture time)
- Values from variables without defaults, remote state, data sources and
  unfetched modules were `UNKNOWN`
- Guardrails outside the inputs (SCPs, org policies, perimeters) were not read
- Resources created outside IaC are not covered (unless a snapshot was supplied)
- What `iac_scan.py` could not read: the reports show `inventory.not_run`
  under "Not run" themselves; `limitations` adds only what that list does not say
- Zero findings is not an all-clear

Never print secret values; location and kind only. Describe permission chains
and fix directions, not exploitation steps.

Source excerpts omit JSON/YAML documents with CloudFormation `NoEcho` metadata
unless its value is explicitly false (boolean or string). Unresolved values,
including opaque YAML block strings, also omit the excerpt. Parameter defaults
may be secret even when their names do not look sensitive.

Terraform excerpts are also omitted when a `variable` or `output` block in the same
module directory declares `sensitive` with a value other than the boolean
literal `false`. UTF-8 input with a leading BOM is normalized before this check,
as it is by the baseline scanner. This conservative check covers declarations
and defaults split across files, including overrides; it can omit excerpts even
when a later override makes a value public. Unreadable or symlinked sibling `.tf`
files, or the presence of a sibling `.tf.json` file whose declarations are not
evaluated, also prevent Terraform excerpts rather than leaving sensitivity unchecked. A
neighboring finding must not copy a sensitive `default` or `value` into either
HTML report.

In JSON/YAML, strings resembling Terraform references are still literal values:
secret fields containing `var.*`, `aws_*` or similar text remain redacted.
Multiline secret values must stay hidden across adjacent fields, heredocs and
YAML list entries.
