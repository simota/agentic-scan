---
name: infra-scan
description: "Static security review of cloud infrastructure from its configuration: Terraform/OpenTofu, plan JSON, CloudFormation, Kubernetes manifests and read-only config exports for AWS and GCP. Maps exposure, identity and trust, then traces attack paths to crown-jewel data. Outputs a dashboard and a PDF report. Read-only; never calls cloud APIs."
allowed-tools: Read, Grep, Glob, Bash, Write
---

## Owns

Finding exploitable weaknesses in cloud infrastructure the requester owns or is
authorized to assess, **by reading its configuration**: infrastructure as code,
plan output, Kubernetes manifests, and config snapshots the requester exported
themselves. The output is a ranked list of findings, each anchored to a
`path:line` and a resource address, with the actor who can use it, the attack
path it opens, what goes wrong and how sure the finding is — or, when only a
plan is asked for, a checklist tailored to this estate.

It does not change infrastructure, does not authenticate to any cloud, and does
not send traffic to deployed resources. Fixing is a separate, later request.

Phases: `RECON → CHECKLIST → REVIEW → VERIFY → REPORT`.

The difference from a rule scanner: a scanner reports each resource's settings
one at a time. This skill asks **who can reach which crown jewel, through which
chain of network and identity edges** (`reference/attack-paths.md`). A public
bucket holding build logs and a role assumable from any GitHub repository are
judged by where they lead, not by the rule they break.

## Before starting

- **Confirm scope and authorization in one line**: which accounts, projects or
  clusters, which environments (prod, staging), which inputs (IaC directory,
  plan JSON, snapshots), and that the review is static. If the request implies
  calling cloud APIs or probing endpoints, see *Decide first*
- **Name the entry actors before reading resources**: the internet, any
  authenticated principal of the cloud (`allAuthenticatedUsers`, any AWS
  account), any principal in the organization, each CI/CD identity, each third
  party with a trust relationship, a compromised workload (VM, pod, function),
  and a developer with read-only console access. Most serious findings are one of
  these reaching something it should not
- **Name the crown jewels**: the data stores and capabilities whose exposure or
  takeover hurts most — customer data stores, secrets managers and KMS keys,
  organization or project admin, the IaC state and the pipeline that applies it,
  backups. Severity is judged against these
- **Create a new, empty output directory** outside the assessed repository and
  follow the *Run contract* below

## Run contract

| Item | Fixed choice |
|---|---|
| Independence | Never read another assessment's outputs unless the request is to merge or compare them |
| Inputs | IaC and manifests from the repository; plan JSON (`terraform show -json`) and config snapshots only when the requester supplies them (`reference/snapshots.md`). This skill never runs `terraform plan`, `apply`, `init`, a cloud CLI or an SDK call; the requester runs exports themselves |
| Review units | One unit per environment × provider (e.g. `prod/aws`, `prod/gcp`), plus one cross-cutting unit (organization guardrails, CI/CD and state, cross-account and cross-cloud trust). Each unit first traces the attack paths to the crown jewels it holds, then sweeps every applicable perspective once |
| Baseline | `scripts/iac_scan.py <repo> --out <out>/iac.json --into <out>/findings.json` runs first. It inventories resources and applies deterministic baseline rules, producing `I-*` findings. Never hand-write, merge or split `I-*`; review each one in its `validation` |
| Granularity | One finding per root cause, i.e. per fix location (a module, a policy document, a shared security group). The same flaw instantiated in several environments is one finding listing every resource address |
| IDs | `F-001`… for findings from review, numbered without gaps in severity order (then path); `I-*` only from `iac_scan.py`; attack paths `AP-01`… |
| Severity | The table below, decided before confidence; confidence never raises or lowers it |
| Outputs | Exactly `findings.json`, `iac.json`, `dashboard.html`, `assessment.html`, `assessment.pdf`, in the requester's language. Extra files only on request (`contract_check.py --allow NAME`) |
| `meta.assessor` | Host and model, e.g. `Claude Code (<model>)` |
| Budget | When the budget runs short, close units in risk order (production, internet-reachable paths and crown jewels first). `limitations` names the units, resources and attack paths not reached |
| Scratch | A new, empty directory outside both the repository and the output directory (Claude Code: the scratchpad directory). Name it in the chat summary |
| Writing the record | Never build `findings.json` with a heredoc, `echo` redirection, `python -c` or a generated script. Write each batch of one to five findings as a JSON fragment with the file-write tool into scratch, then `scripts/findings.py merge <out>/findings.json <fragment>…` |
| Read-only | Write nothing inside the assessed repository. Never copy a state file, a `.tfvars` with secrets or a snapshot containing secret values into the output directory |

| Severity | When |
|---|---|
| High | An entry actor that needs nothing beyond what the internet, any cloud account or any organization member already has can read or alter crown-jewel data, gain admin of an account, project, cluster or the IaC pipeline, or execute code on a workload holding a privileged identity. Also a credential with admin reach committed to the repository |
| Medium | A High-class impact that needs one condition the attacker does not control alone (a compromised workload, a specific CI repository, a setting not visible in the inputs), or direct exposure of lower-value data; missing detection on a High-class path |
| Low | Defense-in-depth gaps (encryption with provider-managed keys where customer keys are policy, missing flow logs, short log retention), or a path needing an admin or an unlikely chain |
| Info | A hardening note with no attacker path |

Each further condition the attacker does not control lowers severity one level.
An `Environment-dependent` finding is graded as if its stated condition holds,
and names that condition.

## When the host refuses an action

A refusal covers that call, not the assessment. Do not resend it or disguise it.
Switch to the sanctioned shape — a JSON fragment and `scripts/findings.py merge`;
the attack path as resource addresses and permission names with placeholders
(`<attacker-controlled AWS account>`); the fix direction instead of a
demonstration. If that is refused too, add the step to `limitations`, continue
every phase that does not depend on it, and name the blocked step in the chat
summary.

## Phases

| Phase | Do | Reference |
|---|---|---|
| RECON | Inventory: providers, environments, accounts/projects, every resource with its address and `path:line`; module and provider versions; the state backend and the pipeline that applies it. Build the exposure map (what the internet reaches), the identity map (who can assume or impersonate what, with which permissions) and the trust map (cross-account, federation, CI/CD). Run `scripts/iac_scan.py`. Name the crown jewels | `reference/recon.md`, `reference/snapshots.md` |
| CHECKLIST | Attack-path hypotheses first: for each crown jewel, each entry actor that might reach it. Then the perspectives that apply, keeping only hunt steps no path covers | `reference/attack-paths.md`, `reference/perspectives.md` |
| REVIEW | One pass per review unit. Trace every hypothesis edge by edge — network reachability, then identity, then the resource policy on the target — each edge citing the resource and `path:line` that allows or blocks it, or `UNKNOWN` with what would decide it. Then sweep every applicable perspective with the provider catalogs; triage every `I-*` | `reference/attack-paths.md`, `reference/perspectives.md`, `reference/aws.md`, `reference/gcp.md`, `reference/kubernetes.md` |
| VERIFY | For each finding: reachability, preconditions, compensating controls (org policy, SCP, permission boundary, VPC Service Controls, network policy, a WAF) and impact, each `supported` / `contradicted` / `unknown`; try to falsify it. Separate what the IaC declares from what is deployed | `reference/validation.md` |
| REPORT | Merge fragments, render with `scripts/render.py --repo <assessed-repo>`, pass `scripts/contract_check.py`, then the chat summary | `reference/findings-schema.md`, `reference/report.md` |

## Decide first

| Situation | How to proceed |
|---|---|
| Asked "what should we check" | RECON and CHECKLIST only; deliver the checklist |
| Asked to check, audit or scan | All five phases |
| Only IaC, no plan or snapshot | Review the IaC; every value from a variable, data source or remote module not in the repo is `UNKNOWN`; deployed drift goes in `limitations` |
| The requester wants live confirmation | Offer the read-only export commands in `reference/snapshots.md` for them to run with their own read-only credentials. Never run them, never probe an endpoint, never use credentials found in the repository |
| A guardrail lives outside the inputs (SCP, org policy, VPC-SC perimeter, permission boundary) | The finding is `Environment-dependent`, naming the guardrail that would block it, unless the guardrail's config is supplied |
| A module comes from a registry or another repository | Pin the version read; if its source is not available, its resources are `UNKNOWN`, listed in `limitations` |
| A state file, `.tfvars` or snapshot contains a secret | Report location and kind only. Never print the value; a state file in the repository is itself a finding |
| Asked to file findings as issues or write them up for an owner | Draft from `findings.json` with `templates/issue.<lang>.md` or `templates/report.<lang>.md`. An unfixed High or Medium goes to a private tracker, never a public issue |
| Several environments share a module | One finding at the module, listing every instance; severity from the worst environment |

## Always / Never

- Always: anchor every finding to `path:line` and a resource address, and name
  the entry actor and the attack path (`AP-*`) it belongs to
- Always: give every `F-*` an attack path as numbered edges (network, identity,
  resource policy), the contrast (a sibling resource configured soundly, or
  "none"), a one-line fix as the boundary restored, a policy-as-code assertion
  that would catch a regression, and the closest benchmark control (CIS, the
  provider's foundational benchmark) and CWE
- Always: grade severity and confidence (Confirmed / Environment-dependent /
  Suspected) separately; Confirmed means every edge was read in the inputs
- Always: list what was checked and found sound, and every perspective as
  applied, N/A or not checked
- Always: say what configuration reading cannot show — console-made resources,
  drift, runtime data, guardrails outside the inputs
- Never: run `terraform plan/apply/init/import`, a cloud CLI, an SDK, or any
  command that authenticates or sends traffic to a deployed resource
- Never: use, test or print a credential found in the inputs
- Never: write a working exploit, a privilege-escalation script, or a scanner
  that targets hosts or accounts. Describe the permission chain and the fix
- Never: paste configuration or findings into an external service
- Never: report a High or Medium finding whose path you have not traced end to end
- Never: delete a finding judged false — mark it `FalsePositive` or
  `NotApplicable` with evidence

## Verify with

- Every High and Medium finding has each attack-path edge cited at `path:line`
  by the agent writing the report
- Every "publicly reachable" claim names the route: internet gateway or
  external IP, load balancer listener, security group or firewall rule, and the
  absence of a blocking NACL, policy or perimeter in the inputs
- Every IAM claim names the exact permission (`iam:PassRole`,
  `iam.serviceAccounts.actAs`…), the principal, the resource and any condition
- `I-*` findings are triaged one by one; a rule hit is a hypothesis, not a finding

## Done when

`scripts/contract_check.py` passes, every resource in the inventory belongs to a
review unit, every crown jewel has each entry actor's path recorded as open,
blocked or unknown, every perspective in `reference/perspectives.md` is applied,
N/A or not checked, every `I-*` has a verdict, and the report states its own
blind spots.
