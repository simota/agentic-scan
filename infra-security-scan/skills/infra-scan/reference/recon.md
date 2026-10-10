# Recon — the estate map

**Read when:** RECON, before any finding is written. A security group cannot be
judged without knowing what sits behind it, and a role cannot be judged without
knowing who can assume it.

The map is a working artifact in scratch; it is not part of the output unless
asked.

## 1. Inputs and their limits

List every input and what it can and cannot tell:

| Input | Tells | Cannot tell |
|---|---|---|
| IaC source (`*.tf`, CloudFormation, CDK synth output, Pulumi, Helm, manifests) | Intended configuration, module structure, who wrote what | Variable values from CI, remote modules not in the repo, console-made resources |
| Plan JSON (`terraform show -json plan.out`) | Resolved values for one environment at one time | Resources not managed by that root module |
| Config snapshot (`reference/snapshots.md`) | What is deployed, including console-made resources | Why; and only what the export covered |
| Kubernetes manifests / rendered Helm | Workload and RBAC intent | Admission controllers and in-cluster objects created by operators |

Run `scripts/iac_scan.py <repo> --out <out>/iac.json --into <out>/findings.json`.
Its `not_run` list is kept in `inventory.not_run`, which the reports show
under "Not run" and a rescan replaces; do not copy it into `limitations`.

The baseline reads Terraform/OpenTofu (`.tf`, `.tfvars`, `.tfvars.json`), plan
JSON, CloudFormation and SAM (`.json`, `.yaml`, `.template`; a `Transform` is
not expanded), Kubernetes manifests, Terragrunt files (module source and
literal secrets only) and the exports in `reference/snapshots.md`. It names, but
does not evaluate, Terraform JSON, Kustomizations, unrendered Helm templates,
Serverless Framework and Pulumi files, other `.hcl` and export shapes without
rules: render or review those by hand (`helm template`, `kustomize build`,
`sam validate`). Tool caches (`.terraform`, `.terragrunt-cache`, `.aws-sam`,
`node_modules`) are skipped as copies and named; Serverless Framework's compiled
`.serverless/` template is read.

The Terraform baseline merges `override.tf` and `*_override.tf` after ordinary
`.tf` files, in filename order within each module directory. Attribute and
nested-block evidence retains the contributing source file; whole-resource
checks cite the final block declaration. Unsupported or ambiguous override
targets are named in `not_run`; do not treat those entries as a completed check
of the final configuration.

## 2. Estate layout

- Providers, accounts / projects / subscriptions, regions, clusters
- Environments and how they are separated: directories, workspaces,
  `*.tfvars` per environment, separate accounts or projects
- Root modules, child modules (local, registry, git) with pinned versions
- State backends per root module and who can read them
- The pipeline that runs plan and apply: CI workflow files, the identity it
  uses, the branches and events that trigger apply

## 3. Resource inventory

One row per resource: address, type, environment, `path:line`, and three
columns filled in later — *Exposure* (§4), *Identity* (§5), *Holds* (crown
jewel or not). Group rows into review units: environment × provider, plus the
cross-cutting unit.

## 4. Exposure map — what the internet reaches

For each environment, list every way in from outside:

- Public IPs and elastic IPs, instances with `associate_public_ip_address`,
  GCP `access_config`
- Load balancers and their listeners, CDN distributions and their origins,
  API gateways and their routes, function URLs, Cloud Run / Functions with
  public invokers, Kubernetes `LoadBalancer` services and ingresses
- Databases, caches, search clusters and cluster API endpoints with a public
  address
- Object storage reachable without credentials

For each entry, follow the network edges inward: listener → target group or
backend → security group / firewall rule on the target → the workload and the
identity it runs as. An edge that depends on a value the inputs do not resolve
is `UNKNOWN`.

## 5. Identity map — who can become what

- Every principal: human users and groups, SSO permission sets, roles, service
  accounts, workload identities (instance profiles, task roles, IRSA / Pod
  Identity, GKE Workload Identity), CI identities
- For each: what can assume or impersonate it (trust policy, `actAs`,
  `serviceAccountTokenCreator`, Kubernetes service account mapping) and what it
  can do (attached policies, bindings at resource, project, folder, org level)
- Mark every principal holding a privilege-escalation permission
  (`reference/perspectives.md` IP2) and every principal with admin reach

## 6. Trust map — who outside can come in

- Cross-account trust policies and the accounts they name; external IDs
- OIDC / SAML providers and the conditions on them (GitHub Actions `sub`,
  Workload Identity Federation `attribute_condition`)
- Resource policies naming other accounts or organization-wide principals
- Third-party integrations (monitoring vendors, CI SaaS, backup vendors)

## 7. Crown jewels

For each, name the resource address and where it lives:

- Customer and personal data stores (databases, buckets, warehouses)
- Secrets managers, KMS keys, parameter stores
- Organization / account / project admin capability, cluster admin
- The IaC state and the apply pipeline (admin of everything they manage)
- Backups and logs (deleting them completes an attack)

## 8. Guardrails

What sits above the account: SCPs and RCPs, GCP organization policies, VPC
Service Controls perimeters, Azure Policy, permission boundaries, Kubernetes
admission policies. If they are not in the inputs, say so once in
`limitations` and grade as if they were absent; a finding becomes
`Environment-dependent` on a guardrail only when one is known to exist and
would decide it (`SKILL.md`).
