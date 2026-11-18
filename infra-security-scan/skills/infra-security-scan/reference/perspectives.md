# Perspectives — reviewing the estate from more than one angle

**Read when:** CHECKLIST, to choose which perspectives apply; REVIEW, after the
attack-path trace (`reference/attack-paths.md`), as the coverage sweep; REPORT,
to fill `perspectives` in `findings.json`. Provider specifics are in
`reference/aws.md`, `reference/gcp.md` and `reference/kubernetes.md`.

Attack paths find what reaches the crown jewels. The perspectives make sure
nothing outside those paths is skipped. Record every perspective in the report,
including the ones that found nothing and the ones not run.

| Perspective | The question it asks |
|---|---|
| Network exposure | What can the internet, or a less trusted network, reach — and is each exposure intended? |
| Identity and privilege | Does each principal hold only what it uses, and can any principal raise its own privilege? |
| Trust and federation | Who outside the account or project can assume, impersonate or federate into it, under what conditions? |
| Data protection | Are data stores private, encrypted with keys whose policies are themselves tight, and not shared by snapshot or link? |
| Compute and workload | Does a compromised VM, container or function stay contained, or does its identity and metadata reach further? |
| Kubernetes | Are cluster API, RBAC, pod security and network policy holding the same boundaries as the cloud layer? |
| Serverless and API edge | Does every function URL, API gateway route and managed endpoint require the authentication it should? |
| Secrets and keys | Are credentials kept out of code, state, variables and environment, and are keys rotated and scoped? |
| Logging and detection | Would the attack paths found here be recorded and noticed? |
| Resilience and recovery | Can data be recovered after deletion, encryption by an attacker or a bad apply? |
| Governance and guardrails | Do organization-level controls (SCP, org policy, perimeters) block what account-level config allows? |
| Pipeline and state | Can the IaC state, the modules or the pipeline that applies them be read or altered by someone who should not? |
| Coverage and drift | What exists or is decided outside the inputs, and how much of the estate did the inputs actually describe? |

Rules:

- A perspective not applicable is recorded as `N/A` with a reason
- A perspective that could not be checked from the inputs is `Not checked`
  with what input would be needed (a plan JSON, an org policy export…)
- Every finding names the perspective that surfaced it in `category`
- A hunt step covered by an attack path cites it (`AP-…`) in the `note`
- The `note` lists the step IDs applied and each one left out with its reason
  (e.g. `NE1–NE4 via AP-01; NE5 N/A: single VPC, no peering`)
- A step is sound only when the enforcing setting is cited at `path:line`. A
  provider default counts only when the provider version that sets it is cited,
  and only for resources that do not override it

## Hunt steps

Each step says what to hunt, where, and what makes it sound — with the reason.
*Catalog* names the closest CWE; provider benchmark controls are in the
provider references.

### Network exposure (NE)

| Step | Hunt | Where | Sound when — because | Catalog |
|---|---|---|---|---|
| NE1 | Ingress open to `0.0.0.0/0` or `::/0` (or ranges that together cover it, e.g. `0.0.0.0/1` + `128.0.0.0/1`, in one rule or across rules) on admin and data ports (22, 3389, databases, caches, search, Kubernetes API, Docker) | Security groups, NACLs, GCP firewall rules, Azure NSGs, load balancer source ranges | Only intended public listeners (80/443 on an edge) are open; admin access goes through a bastion, SSM / IAP or VPN — because one open admin port is a direct path for every scanner on the internet | CWE-284 |
| NE2 | Resources with a public address: instances, databases, caches, clusters with public endpoints | `associate_public_ip_address`, `publicly_accessible`, `access_config`, `ipv4_enabled`, endpoint settings | A public address exists only where a listener is meant to be public — because an address plus a permissive rule elsewhere is an exposure | CWE-668 |
| NE3 | Load balancers and ingress: listeners, protocols, TLS policy, backends that expose internal services | ALB/NLB listeners, GCP forwarding rules and backend services, ingress resources | Every public listener terminates TLS with a current policy and routes only to intended backends — because a catch-all rule exposes everything behind it | CWE-319 |
| NE4 | Egress: unrestricted outbound from workloads holding sensitive identity or data | Egress rules, NAT, firewall egress, VPC endpoints / Private Service Connect | Sensitive workloads egress only to needed endpoints, or the risk is accepted in `decisions` — because unrestricted egress makes exfiltration a single request | CWE-284 |
| NE5 | Network segmentation between environments and tiers: peering, shared VPCs, transit gateways, routes | Peering and route resources, shared VPC host/service projects | Prod and non-prod are not routable to each other except where needed — because a breach of staging becomes a breach of prod | CWE-653 |
| NE6 | Private service access bypassed: storage or APIs reachable publicly while a private endpoint exists | Endpoint policies, VPC-SC, `restrict_public_buckets`, `private_ip_google_access` | Resource policies require the private path (source VPC/endpoint condition) — because a private endpoint does not by itself close the public one | CWE-284 |

### Identity and privilege (IP)

| Step | Hunt | Where | Sound when — because | Catalog |
|---|---|---|---|---|
| IP1 | Wildcard grants: `Action: "*"`, `service:*`, `Resource: "*"` on sensitive services; GCP basic roles `roles/owner` / `roles/editor` | IAM policy documents, managed policy attachments, `google_*_iam_*` bindings | Actions and resources are enumerated, or the wildcard is scoped by a condition — because a wildcard grants actions added later too | CWE-250 |
| IP2 | Privilege-escalation permissions held by a non-admin principal (`iam:PassRole` with `*`, `iam:CreatePolicyVersion`, `iam:AttachRolePolicy`, `iam:PutRolePolicy`, `iam:UpdateAssumeRolePolicy`, `lambda:UpdateFunctionCode` on a privileged function; GCP `iam.serviceAccounts.actAs`, `getAccessToken`, `setIamPolicy`, `iam.roles.update`) | Every policy granted to workloads, CI and human groups | No such permission, or it is scoped to resources that cannot lead to more privilege — because each of these turns a small role into admin | CWE-269 |
| IP3 | Human access: long-lived user keys, users with console + programmatic access, missing MFA enforcement, root/owner usage | IAM users, access keys, `google_service_account_key`, group bindings | Humans use SSO with short-lived credentials; no user keys in IaC — because a leaked long-lived key has no expiry | CWE-798 |
| IP4 | Service identity reuse: default service accounts, one role shared by many workloads, broad OAuth scopes | Compute default SA, `cloud-platform` scope, ECS/Lambda roles shared across services | Each workload has its own identity with its own permissions — because a shared identity makes the weakest workload's compromise everyone's | CWE-250 |
| IP5 | Permission boundaries and conditions: boundaries missing on delegated role creation; conditions that are trivially satisfiable | `permissions_boundary`, `condition` blocks, IAM Conditions | A principal that can create roles is forced to attach a boundary — because otherwise it creates its own admin | CWE-269 |

### Trust and federation (TF)

| Step | Hunt | Where | Sound when — because | Catalog |
|---|---|---|---|---|
| TF1 | Role trust policies with `Principal: "*"`, `AWS: "*"`, or an account root without conditions | `assume_role_policy`, `aws_iam_role` | Principals are named and, for third parties, `sts:ExternalId` is required — because `*` lets any AWS account assume the role | CWE-284 |
| TF2 | CI/CD OIDC trust: GitHub Actions, GitLab, Terraform Cloud, Workload Identity Federation | Trust conditions on `token.actions.githubusercontent.com:sub` / `aud`; WIF `attribute_condition` | The subject is pinned to the organization, repository and branch or environment — because a `repo:*` or missing condition lets any repository on the platform assume the role | CWE-287 |
| TF3 | Cross-account and cross-project grants: resource policies naming other accounts, organization-wide principals, `allAuthenticatedUsers` | Bucket, KMS, SNS/SQS, ECR, Secrets Manager policies; GCP bindings on members outside the organization | Every external principal is listed in `decisions` as intended — because a forgotten vendor account keeps its access | CWE-284 |
| TF4 | Service account impersonation chains | `roles/iam.serviceAccountTokenCreator`, `roles/iam.serviceAccountUser`, `sts:AssumeRole` chains | No chain ends at a more privileged identity than its start — because impersonation is privilege by another name | CWE-269 |
| TF5 | Identity providers: SAML/OIDC providers, SSO permission sets, external identity mapping | `aws_iam_saml_provider`, permission sets, `google_iam_workforce_pool` | Mapped groups and attributes are those intended; no wildcard audience — because the IdP decides who becomes admin | CWE-287 |

### Data protection (DP)

| Step | Hunt | Where | Sound when — because | Catalog |
|---|---|---|---|---|
| DP1 | Public object storage: ACLs, bucket policies with `*`, `allUsers`/`allAuthenticatedUsers`, missing public access block / public access prevention | S3, GCS, static-site buckets, CDN origins | Account- and bucket-level public access block / enforced prevention, or the bucket is a documented public asset bucket — because a single policy statement can expose everything | CWE-200 |
| DP2 | Public or shared snapshots, images and backups | EBS/RDS snapshot attributes, AMI launch permissions, GCP image IAM | Not shared outside the organization — because a snapshot is the whole disk | CWE-200 |
| DP3 | Encryption at rest and the key's own policy | `encrypted`, `kms_key_id`, CMEK settings, KMS key policies with `*` | Encryption on; key policy grants decrypt only to intended principals — because a key policy with `*` makes encryption a formality | CWE-311 |
| DP4 | Encryption in transit to data stores | `require_ssl`, `rds.force_ssl`, `aws:SecureTransport` deny, Redis `transit_encryption_enabled` | TLS required on the server side — because a client that may use TLS will sometimes not | CWE-319 |
| DP5 | Databases and caches with weak authentication | Redis without AUTH, Elasticsearch/OpenSearch without fine-grained access, `master_password` literals | Authentication is required and passwords come from a secret store — because network position is not authentication | CWE-306 |

### Compute and workload (CW)

| Step | Hunt | Where | Sound when — because | Catalog |
|---|---|---|---|---|
| CW1 | Instance metadata: IMDSv1 allowed, hop limit, GKE metadata concealment / Workload Identity | `metadata_options`, `workload_metadata_config` | IMDSv2 required; GKE uses Workload Identity — because an SSRF on the workload otherwise yields its credentials | CWE-918 |
| CW2 | Secrets in user data, startup scripts, task definitions, function environment | `user_data`, `metadata_startup_script`, `environment` blocks | Values are references to a secret store — because these fields are readable by anyone with describe permission | CWE-312 |
| CW3 | Privileged identity on internet-facing compute | Roles attached to public instances, functions, tasks | Internet-facing workloads hold only what they need — because the workload is the first thing attacked | CWE-250 |
| CW4 | Images and patching: public or unpinned images, OS login, serial port | AMI filters, `image` tags, `enable-oslogin`, `serial-port-enable` | Images are pinned to an owned source; serial port off — because an unpinned image can change under you | CWE-494 |

### Kubernetes (K8)

| Step | Hunt | Where | Sound when — because | Catalog |
|---|---|---|---|---|
| K81 | Cluster API exposure and authentication | EKS `endpoint_public_access` + CIDRs, GKE `master_authorized_networks`, private cluster, legacy ABAC, basic auth, client certs | Private endpoint or authorized networks; no legacy auth — because the API server is the cluster's admin console | CWE-284 |
| K82 | RBAC: `cluster-admin` bindings, wildcard verbs/resources, `system:authenticated` / `system:unauthenticated` subjects, `escalate`/`bind`/`impersonate` | ClusterRoleBinding, RoleBinding, aws-auth / access entries | Bindings name specific subjects with specific verbs — because `system:authenticated` includes every Google account on GKE | CWE-269 |
| K83 | Pod security: privileged, hostPath, hostNetwork/hostPID, added capabilities, root, writable root FS, no Pod Security admission | Pod specs in manifests, Helm values, `securityContext`, namespace labels | Restricted or baseline profile enforced per namespace — because a privileged pod is node root | CWE-250 |
| K84 | Network policy: default-deny absent, namespaces open to each other | NetworkPolicy, CNI settings | Default-deny with explicit allows in sensitive namespaces — because the pod network is flat by default | CWE-284 |
| K85 | Workload identity: pods mapped to cloud roles (IRSA, Pod Identity, GKE WI) and what those roles can do | ServiceAccount annotations, trust policies with `sub` conditions | Each mapping pins namespace and service account — because a missing `sub` condition gives any pod the role | CWE-287 |

### Serverless and API edge (SE)

| Step | Hunt | Where | Sound when — because | Catalog |
|---|---|---|---|---|
| SE1 | Unauthenticated invocation: Lambda function URLs with `NONE`, resource policies allowing `*`, Cloud Run / Cloud Functions `allUsers` invoker | `aws_lambda_function_url`, `aws_lambda_permission`, `google_cloud_run_*_iam_*` | Public invocation exists only for intended public endpoints, which do their own auth — because these bypass any gateway in front | CWE-306 |
| SE2 | API gateway routes without an authorizer, API keys used as authentication, missing throttling | API Gateway methods, `authorization`, usage plans; GCP API Gateway / Endpoints | Each route names its authorizer — because one route without it is the open door | CWE-306 |
| SE3 | Event sources and queues with cross-account or public publish | SNS/SQS/EventBridge/Pub/Sub policies | Only intended publishers — because a public topic lets anyone trigger the consumer | CWE-284 |
| SE4 | Edge protection: WAF, CDN origin access, origin bypass | CloudFront OAC/OAI, WAF associations, Cloud Armor, origin reachable directly | The origin accepts traffic only from the edge — because a WAF that can be bypassed is not a control | CWE-284 |

### Secrets and keys (SK)

| Step | Hunt | Where | Sound when — because | Catalog |
|---|---|---|---|---|
| SK1 | Literal secrets in IaC, `.tfvars`, Helm values, manifests, Kubernetes `Secret` objects in the repo | Every input file. `iac_scan.py` finds credential shapes in every text file, and secret-named literals (quoted strings, heredocs, secret-named variable defaults, name/value env entries) in Terraform, tfvars, Terragrunt and CloudFormation/SAM; read Helm values, Kubernetes env, and secrets inside maps, `locals` or lists by hand | Values come from a secret manager or are injected at apply time — because the repository is read by more people than prod | CWE-798 |
| SK2 | State files and plan outputs in the repository, or in a backend readable by many | `*.tfstate`, `terraform.tfstate.d`, state JSON under another name (`iac_scan.py` reads it by content), backend config | State is remote, encrypted and access-restricted — because state holds every secret in plain text | CWE-312 |
| SK3 | Secrets marked sensitive and outputs exposing them | `sensitive = true`, `output` blocks | Secret outputs are sensitive or absent — because outputs are printed in CI logs | CWE-532 |
| SK4 | KMS and secret rotation | `enable_key_rotation`, `rotation_period`, Secrets Manager rotation | Rotation on for keys and long-lived secrets — because a leaked key without rotation is leaked forever | CWE-324 |

### Logging and detection (LD)

| Step | Hunt | Where | Sound when — because | Catalog |
|---|---|---|---|---|
| LD1 | Control-plane audit logs: CloudTrail (multi-region, org trail, log validation), GCP Admin Activity and Data Access logs | `aws_cloudtrail`, `google_project_iam_audit_config`, org sinks | Every account/project logs, to a store the workload accounts cannot delete — because attackers delete what they can | CWE-778 |
| LD2 | Network and data-access logs: VPC flow logs, S3 access logs, load balancer logs, Cloud SQL logs | Flow log resources, `logging` blocks | Enabled where a High-class path exists — because without them the incident cannot be scoped | CWE-778 |
| LD3 | Threat detection: GuardDuty, Security Hub, Security Command Center, Config rules | Detector resources, org-level enablement | Enabled org-wide, findings routed to someone — because detection off means a breach is found by a customer | CWE-778 |
| LD4 | Log retention and integrity | Retention days, bucket lock / object lock, sink destinations | Retention meets the requester's policy; logs immutable — because short retention ends the investigation early | CWE-779 |

### Resilience and recovery (RR)

| Step | Hunt | Where | Sound when — because | Catalog |
|---|---|---|---|---|
| RR1 | Backups: enabled, retention, cross-account or locked copies (the baseline flags only backups switched off literally, `AWS-RDS-003` / `GCP-SQL-002`; an omitted Cloud SQL `backup_configuration` also leaves them off and is this step's to find) | `backup_retention_period`, AWS Backup plans, Cloud SQL backups, vault lock | Backups exist in a place the production identity cannot delete — because ransomware deletes backups first | CWE-693 |
| RR2 | Deletion protection on crown-jewel stores | `deletion_protection`, `prevent_destroy`, `force_destroy` | On for crown jewels — because one bad apply or one stolen credential deletes the data | CWE-693 |
| RR3 | Versioning and object lock on buckets holding critical data or state | `versioning`, `object_lock_configuration`, GCS retention policy | On for state and critical data — because overwrite equals deletion without them | CWE-693 |

### Governance and guardrails (GV)

| Step | Hunt | Where | Sound when — because | Catalog |
|---|---|---|---|---|
| GV1 | Organization policies: SCPs, GCP org policy constraints, Azure Policy | `aws_organizations_policy`, `google_org_policy_policy` | Guardrails deny the High-class paths found (public buckets, SA key creation, regions, leaving the org) — because account-level config drifts | CWE-693 |
| GV2 | Account and project structure: prod separated, management account unused for workloads | Organization resources, account factory, folder structure | Workloads never run in the management account — because SCPs do not apply there | CWE-653 |
| GV3 | Perimeters: VPC Service Controls, resource control policies | `google_access_context_manager_*`, RCPs | Perimeters cover the crown-jewel services, with dry-run results reviewed — because they block exfiltration with valid credentials | CWE-284 |

### Pipeline and state (PS)

| Step | Hunt | Where | Sound when — because | Catalog |
|---|---|---|---|---|
| PS1 | State backend: encryption, locking, access, versioning | `backend` blocks, the state bucket's own resources | Encrypted, locked, versioned, readable only by the pipeline — because state is the estate's secret store and its blueprint | CWE-312 |
| PS2 | Pipeline credentials: static keys in CI, apply identity scope, plan vs apply separation | CI workflow files, OIDC roles, `provider` blocks with `access_key` | CI uses OIDC; plan runs read-only; apply only from a protected branch — because the apply identity is admin of everything it manages | CWE-798 |
| PS3 | Module and provider pinning and sources | `source`, `version`, `.terraform.lock.hcl`, git refs | Modules pinned to a version or commit; providers locked — because an unpinned module is code someone else can change | CWE-829 |
| PS4 | Who can change IaC that changes prod: branch protection, CODEOWNERS, `pull_request_target` on apply workflows | `.github/workflows`, CODEOWNERS | Apply requires review and runs only from protected refs — because the pipeline turns a merged PR into prod access | CWE-284 |

### Coverage and drift (CD)

| Step | Hunt | Where | Sound when — because | Catalog |
|---|---|---|---|---|
| CD1 | Values not resolvable from the inputs: variables without defaults, data sources, remote state, unfetched modules | `variable`, `data`, `terraform_remote_state`, module sources | Each is listed in `limitations` with its effect on findings — because an unknown value is not a safe value | — |
| CD2 | Resources outside IaC: snapshot entries not matched by any IaC resource | Snapshot vs inventory comparison | Every unmatched resource is listed — because console-made resources skip review | — |
| CD3 | Environments in the repo not in scope, or in scope but absent | Directory layout, workspaces, `*.tfvars` per env | Scope statement matches the inputs read — because a silent gap reads as an all-clear | — |
