# infra-scan

An agent skill for a **static, read-only security review of cloud
infrastructure from its configuration** — Terraform / OpenTofu, plan JSON,
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
  workload) the path is traced edge by edge — network, assume/impersonate,
  permission, resource policy, credential, escalation — and recorded as open,
  blocked or unknown
- **Thirteen perspectives** — network exposure, identity and privilege, trust
  and federation, data protection, compute and workload, Kubernetes, serverless
  and API edge, secrets and keys, logging and detection, resilience and
  recovery, governance and guardrails, pipeline and state, coverage and drift
- **Baseline** — `scripts/iac_scan.py` parses HCL, plan JSON, CloudFormation
  JSON, Kubernetes YAML and AWS/GCP snapshot JSON (stdlib only), inventories
  resources and applies deterministic rules as `I-*` findings to triage
- **Snapshots** — when deployed state matters, the skill hands the requester
  read-only export commands to run themselves (`reference/snapshots.md`)

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
make scan TARGET=../my-infra OUT=$TMPDIR/infra-out   # baseline only
make demo LANG_OUT=ja                      # render the sample report
```

Python 3.10+, standard library only. PDF output uses headless Chrome / Chromium
(`CHROME=/path/to/chrome` to override) and is skipped with a warning if none is
found.

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
  templates/               issue and report drafts (ja/en)
examples/                  sample findings.json (ja/en)
tests/                     unit tests and fixtures
```

## Limits

Configuration says what was declared, not what is deployed. Values from CI
variables, remote state and unfetched modules are unknown; guardrails outside
the inputs (SCPs, org policies, perimeters) are not seen; console-made resources
are invisible without a snapshot. A run with zero findings is not an all-clear.
