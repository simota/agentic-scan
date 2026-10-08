# Kubernetes and other platforms — where each perspective looks

**Read when:** REVIEW of a unit with Kubernetes manifests, Helm charts or
managed clusters; or when the estate includes Azure.

## Kubernetes manifests and Helm

Review rendered manifests where possible. If only a chart is present, read
templates together with `values.yaml` and each environment's values file; a
value set only at install time is `UNKNOWN`.

| Perspective | Look at | Unsound |
|---|---|---|
| Kubernetes — RBAC | `ClusterRoleBinding`, `RoleBinding`, `ClusterRole` | `cluster-admin` to a broad subject; subjects `system:authenticated`, `system:unauthenticated`, `system:anonymous`; verbs `*`, `escalate`, `bind`, `impersonate`; `secrets` `get`/`list` cluster-wide; `pods/exec` broadly |
| Kubernetes — pod security | `securityContext`, pod spec | `privileged: true`, `allowPrivilegeEscalation` not false, `hostPath` (especially `/`, `/var/run/docker.sock`, `/var/run/containerd`), `hostNetwork`, `hostPID`, `hostIPC`, added `SYS_ADMIN` / `NET_ADMIN`, `runAsUser: 0`, no `readOnlyRootFilesystem` |
| Kubernetes — admission | Namespace labels `pod-security.kubernetes.io/enforce`, Kyverno / Gatekeeper policies | No enforce label on workload namespaces, or `privileged` level |
| Kubernetes — network | `NetworkPolicy` | No default-deny in namespaces holding crown jewels; `ingress: [{}]` (allow all) |
| Serverless and API edge | `Service` type `LoadBalancer` / `NodePort`, `Ingress`, Gateway API | Admin or internal service exposed; missing TLS; annotations making an internal LB public |
| Secrets and keys | `kind: Secret` with `data` / `stringData` in the repo; env values; mounted service-account tokens | Committed secret material (base64 is not encryption); `automountServiceAccountToken` left on for pods that do not call the API |
| Trust and federation | ServiceAccount annotations `eks.amazonaws.com/role-arn`, `iam.gke.io/gcp-service-account` | Mapping to a privileged cloud role; trust not pinned to namespace and service account |
| Compute and workload | Image references | `:latest` or no digest for production workloads; images from unowned registries |

Managed-cluster settings (endpoint exposure, legacy auth, workload identity,
node identity) are in `reference/aws.md` (EKS) and `reference/gcp.md` (GKE).

## Azure (when present)

The perspectives apply unchanged; the places to look:

- Network: `azurerm_network_security_group` / `_rule` (`source_address_prefix`
  `*` / `Internet` / `0.0.0.0/0` on admin and data ports), public IPs,
  `public_network_access_enabled` on data services
- Identity: role assignments with `Owner` / `Contributor` / `User Access
  Administrator` at subscription or management-group scope; managed identities
  of internet-facing workloads; federated identity credentials (`subject`
  pinning for GitHub)
- Data: storage `allow_nested_items_to_be_public`, `public_network_access_enabled`,
  `min_tls_version`, `shared_access_key_enabled`; Key Vault
  `purge_protection_enabled`, `network_acls`
- Logging: diagnostic settings, Defender for Cloud plans, activity log export
- Governance: `azurerm_policy_assignment` at management-group scope

`iac_scan.py` has no Azure baseline rules; say so in `limitations` when Azure
resources are in scope, and review them by hand with this list.
