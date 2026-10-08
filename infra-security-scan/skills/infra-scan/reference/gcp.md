# GCP — where each perspective looks

**Read when:** REVIEW of a unit with Google Cloud resources. Terraform
`google` / `google-beta` resource types are listed.

Benchmark citations name the benchmark, its edition and the section title (e.g.
`CIS Google Cloud Platform Foundation v3.0 — Ensure that Cloud Storage bucket is
not anonymously or publicly accessible`). Copy control numbers only from the
edition the requester uses.

## IAM model reminders

- Bindings inherit downward: organization → folder → project → resource. A
  role granted on a folder applies to every project in it — read bindings at
  every level present in the inputs
- `google_*_iam_policy` is authoritative (replaces all bindings);
  `*_iam_binding` is authoritative for one role; `*_iam_member` is additive.
  Bindings made outside Terraform survive `_member` but not `_policy`
- Members: `allUsers` (anyone), `allAuthenticatedUsers` (any Google account),
  `domain:`, `group:`, `serviceAccount:`, `principalSet://` (federated)

## Network exposure

| Look at | Attribute | Unsound |
|---|---|---|
| `google_compute_firewall` | `direction` (default INGRESS), `source_ranges`, `allow { protocol ports }`, `target_tags` / `target_service_accounts`, `disabled` | `0.0.0.0/0` on 22, 3389, database ports, or all; no targets (applies to every instance in the network) |
| `google_compute_instance` | `network_interface.access_config` | External IP on a non-edge VM |
| `google_sql_database_instance` | `settings.ip_configuration.ipv4_enabled`, `authorized_networks`, `ssl_mode` / `require_ssl`, `private_network` | `0.0.0.0/0` authorized; public IP without SSL enforcement |
| `google_container_cluster` | `private_cluster_config`, `master_authorized_networks_config`, `enable_private_endpoint` | Public endpoint without authorized networks |
| `google_compute_subnetwork` | `private_ip_google_access`, `log_config` | No `log_config` on subnets carrying a High-class path (no flow logs) |
| Default network | `google_compute_network` named `default`, or project without `compute.skipDefaultNetworkCreation` | Default network with its permissive default rules |

## Identity and privilege

- Basic roles `roles/owner`, `roles/editor` (and `roles/viewer` on sensitive
  projects) on users, groups or service accounts
- Escalation permissions (perspectives IP2): `iam.serviceAccounts.actAs`
  (`roles/iam.serviceAccountUser`), `iam.serviceAccounts.getAccessToken` /
  `signBlob` / `signJwt` / `implicitDelegation`
  (`roles/iam.serviceAccountTokenCreator`), `iam.serviceAccountKeys.create`,
  `resourcemanager.projects.setIamPolicy`, `iam.roles.update` on a custom role
  the principal holds, `deploymentmanager.deployments.create`,
  `cloudfunctions.functions.create` / `run.services.create` + actAs,
  `compute.instances.setMetadata` (SSH keys) on privileged VMs
- Project-level `serviceAccountUser` / `serviceAccountTokenCreator` lets the
  holder act as **every** service account in the project
- `google_service_account_key` resources: long-lived keys; prefer Workload
  Identity Federation or attached service accounts
- Compute default service account (`<number>-compute@developer.gserviceaccount.com`)
  with `scopes = ["cloud-platform"]` — Editor by default on older projects

## Trust and federation

- `google_iam_workload_identity_pool_provider`: `attribute_condition` must pin
  the repository / organization (e.g. `assertion.repository_owner`); a
  provider for GitHub with no condition accepts any repository
- `principalSet://…/attribute.repository/…` bindings on service accounts —
  check the attribute matched is the one intended
- Members outside the organization's domain; `domain:` bindings for partner
  domains (record intended ones in `decisions`)
- `google_iam_workforce_pool` mappings

## Data protection

- `google_storage_bucket`: `uniform_bucket_level_access`,
  `public_access_prevention = "enforced"`, `encryption.default_kms_key_name`,
  `retention_policy`, `versioning`; bucket IAM with `allUsers` /
  `allAuthenticatedUsers`; `google_storage_bucket_acl` / `_object_acl`
- BigQuery: `google_bigquery_dataset_iam_*`, `access` blocks with
  `special_group = "allAuthenticatedUsers"`, `default_encryption_configuration`
- Images, snapshots and disks shared via IAM; `google_compute_disk`
  `disk_encryption_key`
- KMS: `google_kms_crypto_key` `rotation_period`, IAM on keys
  (`roles/cloudkms.cryptoKeyEncrypterDecrypter` broadly granted)
- Secret Manager: `google_secret_manager_secret_iam_*` scope

## Compute and workload

- `metadata`: `enable-oslogin = "TRUE"`, `block-project-ssh-keys`,
  `serial-port-enable` (must not be true), startup scripts with secrets
- `shielded_instance_config`, `confidential_instance_config` where required
- GKE: `workload_identity_config` on the cluster, `workload_metadata_config {
  mode = "GKE_METADATA" }` on node pools, `enable_legacy_abac = false`,
  `master_auth.client_certificate_config`, node service account (not the
  compute default), `enable_shielded_nodes`, Binary Authorization

## Serverless and API edge

- `google_cloud_run_service_iam_*` / `google_cloud_run_v2_service_iam_*` with
  `allUsers` on `roles/run.invoker`; `ingress` setting
  (`INGRESS_TRAFFIC_ALL` vs internal / internal-and-cloud-load-balancing)
- `google_cloudfunctions_function_iam_*`, `google_cloudfunctions2_function`
  `service_config.ingress_settings`
- API Gateway / Endpoints security definitions; Cloud Armor policies on
  backend services; IAP (`google_iap_*`) for internal tools
- Pub/Sub topic IAM with `allUsers` / `allAuthenticatedUsers`

## Logging and detection

- `google_project_iam_audit_config` / `google_organization_iam_audit_config`:
  Data Access logs (`DATA_READ`, `DATA_WRITE`) for crown-jewel services;
  exempted members
- `google_logging_organization_sink` / `_project_sink` to a locked bucket
  (`google_logging_project_bucket_config` `locked`, `retention_days`)
- Subnet `log_config` (VPC flow logs), firewall `log_config`, Cloud SQL
  database flags for logging
- Security Command Center enablement and notifications (often outside the
  inputs: `Not checked` with the reason)

## Resilience and recovery

- Cloud SQL `backup_configuration.enabled`, `point_in_time_recovery_enabled`,
  `deletion_protection`; GCS `versioning`, `retention_policy.is_locked`,
  `soft_delete_policy`; `google_container_cluster` `deletion_protection`

## Governance and pipeline

- `google_org_policy_policy` / `google_organization_policy` /
  `google_project_organization_policy` — constraints worth expecting:
  `iam.allowedPolicyMemberDomains`, `iam.disableServiceAccountKeyCreation`,
  `storage.publicAccessPrevention`, `storage.uniformBucketLevelAccess`,
  `compute.vmExternalIpAccess`, `compute.requireOsLogin`,
  `sql.restrictPublicIp`, `compute.skipDefaultNetworkCreation`,
  `iam.automaticIamGrantsForDefaultServiceAccounts`
- VPC Service Controls: `google_access_context_manager_service_perimeter`
  resources, restricted services, dry-run vs enforced
- State backend `backend "gcs"`: bucket IAM, versioning,
  `encryption_key` / `kms_encryption_key`
- `provider "google"` with `credentials` pointing at a key file in the repo
