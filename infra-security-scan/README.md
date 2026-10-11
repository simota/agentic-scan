# infra-scan

An agent skill for a **static, read-only security review of cloud
infrastructure from its configuration** — Terraform / OpenTofu (`.tf`, `.tofu`), plan JSON,
CloudFormation, Kubernetes manifests, and read-only config exports — for AWS and
GCP (Kubernetes and Azure by checklist). It maps exposure, identity and trust,
traces attack paths from entry actors to crown-jewel data, and delivers a chat
summary, an interactive dashboard and an assessment PDF.

> Use it only on infrastructure you own or are authorized to assess. The skill
> reads configuration; it never runs `terraform plan/apply`, never calls a cloud
> API, and never sends traffic to deployed resources.

Sibling of [security-scan](../security-scan) (application source review): same
phases, record-first workflow and report shape, applied to infrastructure.

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
  (long-form intrinsics such as `{"Ref": X}`). Templates using short-form tags
  (`!Ref`, `!Sub`) are inventoried and listed in `not_run`
  — Terraform JSON (`*.tf.json`), unreadable, binary and deeply nested inputs
  are listed in `not_run`; UTF-16/32 exports with a BOM are read
  — on rescan, an `I-*` verdict follows its finding when the rule, file and
  resources are unchanged
  — settings elsewhere in the inputs are honoured before a rule fires:
  account defaults for IMDSv2 and EBS encryption, an org policy enforcing
  public access prevention, policies used only as permissions boundaries,
  Terragrunt-generated backends and Google-managed service agents
- **Snapshots** — when deployed state matters, the skill hands the requester
  read-only export commands to run themselves (`reference/snapshots.md`); the
  exports join the baseline with `iac_scan.py --snapshots DIR`

## Install

```sh
make link                  # symlink into ~/.claude/skills, ~/.codex/skills, Antigravity
make link AGENT=claude     # one host only
make status
```

Then ask the agent, e.g. "infra-scan で `infra/` を診断して" or
"/infra-scan audit the terraform in this repo".

## Commands

```sh
make test                                  # offline unit tests
make check                                 # tests + skill self-consistency
make scan TARGET=../my-infra OUT=/tmp/infra-out   # baseline only; OUT outside TARGET
make scan TARGET=../my-infra SNAPSHOTS=/tmp/exports OUT=/tmp/infra-out  # with exports
make demo LANG_OUT=ja                      # render the sample report
```

Python 3.10+, standard library only. PDF output uses headless Chrome / Chromium
(`CHROME=/path/to/chrome` to override), or WeasyPrint when no Chrome is found,
and is skipped with a warning if neither works; then run
`contract_check.py OUT --no-pdf`. Each engine gets a timeout scaled to the
number of findings (`SCAN_REPORT_PDF_TIMEOUT=<seconds>` to override).

The dashboard and the assessment use the shared *-scan report format,
[scan-report-kit](https://github.com/simota/scan-report-kit): its design
document (`docs/design.md` in that repository) sets the journal-style
assessment (numbered sections, captioned booktabs tables, one mincho face for
both scripts) and the dashboard in the same system. The kit's stylesheets, PDF
engine and safe writes are vendored under `skills/infra-scan/scripts/scan_report_kit/`;
`render.py` adds only the rules for infra-scan's own records (attack paths,
perspective status, covered and excluded rows). Change the kit upstream and
re-vendor, never in place: `make check` verifies the copy against
`scripts/scan_report_kit/MANIFEST`.

## Layout

```
skills/infra-scan/
  SKILL.md                 run contract, phases, severity, decisions
  reference/               recon, attack paths, perspectives, AWS, GCP,
                           Kubernetes/Azure, snapshots, validation, schema, report
  scripts/iac_scan.py      inventory + baseline rules (I-*)
  scripts/findings.py      merge finding fragments into findings.json
  scripts/render.py        dashboard.html, assessment.html, assessment.pdf
  scripts/contract_check.py  verify a finished run
  scripts/redaction.py     redaction and excerpt scrubbing shared by the scripts
  scripts/common.py        shared constants, JSON loading and atomic writes
  scripts/scan_report_kit/ vendored scan-report-kit: shared stylesheets, PDF engine, safe writes
  templates/               issue and report drafts (ja/en)
examples/                  sample findings.json (ja/en)
tests/                     unit tests and fixtures
```

## Limits

Configuration says what was declared, not what is deployed. Values from CI
variables, remote state and unfetched modules are unknown; guardrails outside
the inputs (SCPs, org policies, perimeters) are not seen; console-made resources
are invisible without a snapshot. A run with zero findings is not an all-clear.
