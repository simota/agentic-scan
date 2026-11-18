# infra-security-scan

An agent skill for a **static, read-only security review of cloud
infrastructure from its configuration** — Terraform / OpenTofu (`.tf`, `.tofu`), plan JSON,
CloudFormation, Kubernetes manifests, and read-only config exports — for AWS,
GCP and Kubernetes (Azure by checklist only). It maps exposure, identity and trust,
traces attack paths from entry actors to crown-jewel data, and delivers a chat
summary, an interactive dashboard and an assessment PDF.

> Use it only on infrastructure you own or are authorized to assess. The skill
> reads configuration; it never runs `terraform plan/apply`, never calls a cloud
> API, and never sends traffic to deployed resources.

It reviews infrastructure configuration only; the application's own source is
out of scope. It works in phases, records first and renders a fixed report shape.

## What it does

```
RECON ─► CHECKLIST ─► REVIEW ─► VERIFY ─► REPORT
estate    attack-path   trace     4 claims   findings.json
map,      hypotheses,   edges,    + falsify  ├─ dashboard.html
iac_scan  perspectives  sweep                ├─ assessment.pdf
baseline                perspectives         └─ chat summary
```

- **Recon** inventories providers, environments, accounts/projects, every
  resource with `path:line`, the state backend and the apply pipeline, and
  builds three maps: exposure (what the internet reaches), identity (who can
  become what) and trust (who outside can come in)
- **Attack paths** (`reference/attack-paths.md`) — the core difference from a
  rule scanner. For each crown jewel and each entry actor (internet, any cloud
  principal, organization member, CI identity, third party, compromised
  workload, cluster tenant) the path is traced edge by edge — network, assume/impersonate,
  permission, resource policy, credential, escalation — and recorded as open,
  blocked or unknown
- **Thirteen perspectives** — network exposure, identity and privilege, trust
  and federation, data protection, compute and workload, Kubernetes, serverless
  and API edge, secrets and keys, logging and detection, resilience and
  recovery, governance and guardrails, pipeline and state, coverage and drift
- **Baseline** — `scripts/iac_scan.py` parses HCL (`.tf`, `.tofu`), plan JSON,
  CloudFormation JSON, Kubernetes YAML and JSON (including `kubectl -o json`
  exports), policy JSON files (trust and resource policies directly; identity
  policies through the Terraform resource that reads them with `file()`) and
  AWS/GCP snapshot JSON (stdlib only), inventories
  resources and applies deterministic rules as `I-*` findings to triage
  — Kubernetes supports block maps/lists, single-line flow collections, comments
  and opaque block strings. Unsupported YAML, including anchors, aliases, tags
  and multiline flow values, is listed in `not_run` for manual review
  — Kubernetes and CloudFormation documents are classified individually; files
  containing both retain both inventories and count once as `mixed-yaml`
  — Terraform `override.tf` and `*_override.tf` files are merged within each
  module directory before rules run, retaining source locations for inherited
  attributes and nested blocks. Boolean resource attributes accept native and
  quoted `true` / `false`; IAM action matching recognizes `*` and `?`
  — CloudFormation YAML inventories resource definitions under `Resources`,
  excluding parameter types and embedded template text; the JSON baseline
  rules also apply when the template parses within the YAML subset
  (long-form intrinsics such as `{"Ref": X}`, and short-form tags such as `!Ref` and
  `!Sub` read as those long forms); a template outside the subset is inventoried
  and listed in `not_run`. A JSON template saved
  as `.yaml` is read as JSON; a policy document given as a JSON string is read,
  and one computed by an intrinsic (`Fn::If`, a block scalar) is listed in `not_run`
  — Terraform JSON (`*.tf.json`), unreadable, binary and deeply nested inputs
  are listed in `not_run`; UTF-16/32 exports with a BOM are read
  — on rescan, an `I-*` verdict follows its finding when the rule, file and
  resources are unchanged
  — settings elsewhere in the inputs are honoured before a rule fires:
  account defaults for IMDSv2 and EBS encryption, an org policy enforcing
  public access prevention, policies used only as permissions boundaries,
  Terragrunt-generated backends and Google-managed service agents
- **Re-assessment** — after a remediation round, `scripts/compare.py` matches
  the new record against the earlier one by content (IDs are renumbered each
  run) and lists what was resolved, what is new, reopened or regraded, and
  which attack paths opened or closed; `render.py --previous` opens both
  reports with that comparison and adds a change filter to the register, and
  `--fail-on <severity>` gates a retest on regressions
- **Issue drafts** — `scripts/issues.py` fills `templates/issue.<lang>.md` once
  per counted finding, with an index saying which drafts belong in a private
  tracker only (unfixed High and Medium); `--mask` hides account IDs and IPv4
  addresses. Drafts are written to scratch for a human to file
- **SARIF export** — `scripts/sarif.py` writes the record as one SARIF 2.1.0
  log for GitHub code scanning, GitLab, Azure DevOps or an editor's SARIF
  viewer: each finding on its `path:line` with severity, fix and evidence,
  attack paths as code flows, and a fingerprint built from the root cause (not
  the renumbered ID) so an alert keeps its identity across re-assessments.
  Excluded and covered findings are written as suppressed, closing alerts an
  earlier upload raised. Written to scratch for the requester to upload
- **Snapshots** — when deployed state matters, the skill hands the requester
  read-only export commands to run themselves (`reference/snapshots.md`); the
  exports join the baseline with `iac_scan.py --snapshots DIR`

## Install

```sh
make link                  # symlink into ~/.claude/skills, ~/.codex/skills, Antigravity
make link AGENT=claude     # one host only
make status
```

Then ask the agent, e.g. "infra-security-scan で `infra/` を診断して" or
"/infra-security-scan audit the terraform in this repo".

## Commands

```sh
make test                                  # offline unit tests
make check                                 # tests + skill self-consistency
make scan TARGET=../my-infra OUT=/tmp/infra-out   # baseline only; OUT outside TARGET
make scan TARGET=../my-infra SNAPSHOTS=/tmp/exports OUT=/tmp/infra-out  # with exports
make demo LANG_OUT=ja                      # render the sample report
python3 skills/infra-security-scan/scripts/compare.py /tmp/infra-out-oct /tmp/infra-out   # what changed
python3 skills/infra-security-scan/scripts/render.py /tmp/infra-out/findings.json --out /tmp/infra-out \
  --previous /tmp/infra-out-oct           # reports open with the comparison
python3 skills/infra-security-scan/scripts/issues.py /tmp/infra-out/findings.json --out /tmp/drafts --lang ja
python3 skills/infra-security-scan/scripts/sarif.py /tmp/infra-out/findings.json --out /tmp/infra-security-scan.sarif  # code scanning
```

Python 3.10+, standard library only. PDF output uses headless Chrome / Chromium
(`CHROME=/path/to/chrome` to override), or WeasyPrint when no Chrome is found,
and is skipped with a warning if neither works; then run
`contract_check.py OUT --no-pdf`. Each engine gets a timeout scaled to the
number of findings (`SCAN_REPORT_PDF_TIMEOUT=<seconds>` to override).

The dashboard and the assessment use the report format of the report kit
bundled under `skills/infra-security-scan/scripts/scan_report_kit/`: it sets
the journal-style assessment (numbered sections, captioned booktabs tables, one mincho face for
both scripts) and the dashboard in the same system. The kit's stylesheets, PDF
engine and safe writes live under `skills/infra-security-scan/scripts/scan_report_kit/`;
`render.py` adds only the rules for infra-security-scan's own records (attack paths,
perspective status, covered and excluded rows). The dashboard opts into the
kit's application shell: a sticky app bar, a contents sidebar with per-severity
counts that filter the register, pinned register filters and column heads, and
the keys `/` (search), `j`/`k` (next or previous finding) and Enter (show or
hide details). The kit is maintained in this repository; edit it in place.

## Layout

```
skills/infra-security-scan/
  SKILL.md                 run contract, phases, severity, decisions
  reference/               recon, attack paths, perspectives, AWS, GCP,
                           Kubernetes/Azure, snapshots, validation, schema, report
  scripts/iac_scan.py      inventory + baseline rules (I-*)
  scripts/findings.py      merge finding fragments into findings.json
  scripts/render.py        dashboard.html, assessment.html, assessment.pdf
  scripts/compare.py       what changed between two assessments (render.py --previous)
  scripts/issues.py        issue drafts from templates/issue.<lang>.md
  scripts/sarif.py         SARIF 2.1.0 log for code scanning, CI and editors
  scripts/excerpts.py      which cited lines render.py --repo may show, redacted
  scripts/contract_check.py  verify a finished run
  scripts/redaction.py     redaction and excerpt scrubbing shared by the scripts
  scripts/common.py        shared constants, JSON loading and atomic writes
  scripts/scan_report_kit/ bundled report kit: shared stylesheets, PDF engine, safe writes
  templates/               issue and report drafts (ja/en)
examples/                  sample findings.json (ja/en)
tests/                     unit tests and fixtures
```

## Limits

Configuration says what was declared, not what is deployed. Values from CI
variables, remote state and unfetched modules are unknown; guardrails outside
the inputs (SCPs, org policies, perimeters) are not seen; console-made resources
are invisible without a snapshot. A run with zero findings is not an all-clear.
