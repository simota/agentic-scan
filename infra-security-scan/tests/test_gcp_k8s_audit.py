"""GCP and Kubernetes rules on realistic module and chart shapes."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-security-scan" / "scripts"))
import iac_scan  # noqa: E402


def scan(files):
    with tempfile.TemporaryDirectory() as tmp:
        for name, text in files.items():
            path = Path(tmp) / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text if isinstance(text, str) else json.dumps(text, indent=1), encoding="utf-8")
        return iac_scan.run(tmp)


def found(result):
    return sorted({(h["rule"], h["address"]) for h in result.hits})


class GcpIamTest(unittest.TestCase):
    def test_templated_cloudservices_editor_is_the_default(self):
        result = scan({"iam.tf": '''resource "google_project_iam_member" "apis" {
  role   = "roles/editor"
  member = "serviceAccount:${data.google_project.p.number}@cloudservices.gserviceaccount.com"
}
resource "google_project_iam_member" "human" {
  role   = "roles/editor"
  member = "user:${var.user}"
}
'''})
        self.assertEqual(found(result), [("GCP-IAM-002", "google_project_iam_member.human")])

    def test_data_policy_scope_and_for_each_roles(self):
        result = scan({"iam.tf": '''data "google_iam_policy" "project" {
  binding {
    role    = "roles/iam.serviceAccountTokenCreator"
    members = ["group:devs@example.com"]
  }
}
resource "google_project_iam_policy" "p" {
  project     = "p"
  policy_data = data.google_iam_policy.project.policy_data
}
resource "google_project_iam_member" "each" {
  for_each = toset(["roles/owner", "roles/viewer"])
  role     = each.value
  member   = "group:ops@example.com"
}
resource "google_project_iam_member" "var" {
  role   = var.role
  member = "group:ops@example.com"
}
'''})
        self.assertEqual(found(result), [("GCP-IAM-002", "google_project_iam_member.each"),
                                         ("GCP-IAM-004", "google_project_iam_policy.p")])
        self.assertTrue([n for n in result.not_run if "google_project_iam_member.var" in n])

    def test_cloud_run_without_invoker_iam(self):
        result = scan({"run.tf": 'resource "google_cloud_run_v2_service" "s" {\n  invoker_iam_disabled = true\n}\n'})
        self.assertEqual(found(result), [("GCP-IAM-001", "google_cloud_run_v2_service.s")])


class GcpComputeTest(unittest.TestCase):
    def test_default_service_account_written_or_referenced(self):
        result = scan({"vm.tf": '''resource "google_compute_instance" "data" {
  service_account {
    email  = data.google_compute_default_service_account.default.email
    scopes = ["cloud-platform"]
  }
}
resource "google_compute_instance" "templated" {
  service_account {
    email = "${data.google_project.p.number}-compute@developer.gserviceaccount.com"
  }
}
resource "google_compute_region_instance_template" "t" {
  service_account {
    email = "default"
  }
}
resource "google_container_node_pool" "np" {
  cluster = "c"
}
resource "google_container_node_pool" "own" {
  node_config {
    service_account = "nodes@p.iam.gserviceaccount.com"
    workload_metadata_config {
      mode = "GCE_METADATA"
    }
  }
}
'''})
        self.assertEqual(found(result), [
            ("GCP-GCE-001", "google_compute_instance.data"), ("GCP-GCE-001", "google_compute_instance.templated"),
            ("GCP-GCE-001", "google_compute_region_instance_template.t"),
            ("GCP-GCE-001", "google_container_node_pool.np"), ("GCP-GKE-001", "google_container_node_pool.own")])

    def test_project_metadata_and_client_certificates(self):
        result = scan({"p.tf": '''resource "google_compute_project_metadata" "m" {
  metadata = {
    serial-port-enable = "true"
  }
}
resource "google_compute_project_metadata_item" "i" {
  key   = "serial-port-enable"
  value = "true"
}
resource "google_container_cluster" "c" {
  private_cluster_config {
    enable_private_endpoint = true
  }
  workload_identity_config {
    workload_pool = "p.svc.id.goog"
  }
  remove_default_node_pool = true
  master_auth {
    client_certificate_config {
      issue_client_certificate = true
    }
  }
}
resource "google_container_cluster" "unknown" {
  private_cluster_config {
    enable_private_endpoint = var.private
  }
  workload_identity_config {
    workload_pool = "p.svc.id.goog"
  }
}
'''})
        self.assertEqual(found(result), [("GCP-GCE-002", "google_compute_project_metadata.m"),
                                         ("GCP-GCE-002", "google_compute_project_metadata_item.i"),
                                         ("GCP-GKE-001", "google_container_cluster.c")])
        self.assertTrue([n for n in result.not_run if "google_container_cluster.unknown" in n])


class GcpNetworkAndStorageTest(unittest.TestCase):
    def test_firewall_policy_rules_and_sources(self):
        result = scan({"fw.tf": '''resource "google_compute_network_firewall_policy_rule" "ssh" {
  action    = "allow"
  direction = "INGRESS"
  match {
    src_ip_ranges = ["0.0.0.0/0"]
    layer4_configs {
      ip_protocol = "tcp"
      ports       = ["22"]
    }
  }
}
resource "google_compute_firewall_policy_rule" "deny" {
  action = "deny"
  match {
    src_ip_ranges = ["0.0.0.0/0"]
    layer4_configs {
      ip_protocol = "tcp"
    }
  }
}
resource "google_compute_firewall" "empty" {
  source_ranges = []
  allow {
    protocol = "tcp"
    ports    = ["3389", "22"]
  }
}
resource "google_compute_firewall" "var" {
  source_ranges = var.ranges
  allow {
    protocol = "tcp"
  }
}
'''})
        self.assertEqual(found(result), [("GCP-NET-001", "google_compute_firewall.empty"),
                                         ("GCP-NET-001", "google_compute_network_firewall_policy_rule.ssh")])
        detail = next(h["detail"] for h in result.hits if h["address"] == "google_compute_firewall.empty")
        self.assertEqual(detail, "ingress from 0.0.0.0/0 to 22/SSH, 3389/RDP")
        self.assertTrue([n for n in result.not_run if "google_compute_firewall.var" in n])

    def test_bucket_access_controls(self):
        result = scan({"gcs.tf": '''resource "google_storage_bucket_access_control" "a" {
  role   = "READER"
  entity = "allUsers"
}
resource "google_storage_default_object_access_control" "b" {
  role   = "READER"
  entity = "user-x@example.com"
}
'''})
        self.assertEqual(found(result), [("GCP-GCS-002", "google_storage_bucket_access_control.a")])

    def test_org_policies_scope_and_dry_run(self):
        bucket = '''resource "google_storage_bucket" "b" {
  project = "proj-b"
  uniform_bucket_level_access = true
}
'''
        dry_run = '''resource "google_org_policy_policy" "pap" {
  name   = "projects/proj-b/policies/storage.publicAccessPrevention"
  parent = "projects/proj-b"
  dry_run_spec {
    rules {
      enforce = "TRUE"
    }
  }
}
'''
        other_project = '''resource "google_project_organization_policy" "pap" {
  project    = "proj-a"
  constraint = "storage.publicAccessPrevention"
  boolean_policy {
    enforced = true
  }
}
'''
        same_project = other_project.replace("proj-a", "proj-b")
        ubla = '''resource "google_project_organization_policy" "ubla" {
  project    = "proj-b"
  constraint = "storage.uniformBucketLevelAccess"
  boolean_policy {
    enforced = true
  }
}
resource "google_storage_bucket" "legacy" {
  project = "proj-b"
  public_access_prevention = "enforced"
}
'''
        self.assertEqual(found(scan({"a.tf": bucket + dry_run})), [("GCP-GCS-001", "google_storage_bucket.b")])
        self.assertEqual(found(scan({"a.tf": bucket + other_project})), [("GCP-GCS-001", "google_storage_bucket.b")])
        self.assertEqual(found(scan({"a.tf": bucket + same_project})), [])
        self.assertEqual(found(scan({"a.tf": ubla})), [])


POD = "  template:\n    spec:\n      containers:\n        - name: c\n          securityContext:\n            privileged: true\n"


class KubernetesTest(unittest.TestCase):
    def test_a_literal_secret_in_a_container_env_is_sec_001(self):
        manifest = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      initContainers:
      - name: migrate
        image: app
        env:
        - name: DB_PASSWORD
          value: "VALUE"
      containers:
      - name: app
        image: app
        env:
        - name: LOG_LEVEL
          value: debug
        - name: API_TOKEN
          valueFrom:
            secretKeyRef: {name: app, key: token}
        - name: DB_PASSWORD_REF
          value: "$(DB_PASSWORD)"
        - name: TLS_ENABLED
          value: "true"
"""
        value = "Literal" + "Pw" * 6
        result = scan({"deploy.yaml": manifest.replace("VALUE", value)})
        hits = [h for h in result.hits if h["rule"] == "SEC-001"]
        self.assertEqual([(h["file"], h["line"]) for h in hits], [("deploy.yaml", 13)])
        self.assertIn("DB_PASSWORD", hits[0]["detail"])
        self.assertNotIn(value, json.dumps(result.hits))
        # A key file path under a credentials name is no secret, as in Terraform.
        path = manifest.replace("DB_PASSWORD", "GOOGLE_APPLICATION_CREDENTIALS", 1).replace(
            '"VALUE"', "/var/secrets/google/key.json")
        self.assertEqual([h for h in scan({"deploy.yaml": path}).hits if h["rule"] == "SEC-001"], [])
        # The same container in kubectl JSON.
        doc = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "p"},
               "spec": {"containers": [{"name": "c", "image": "x",
                                        "env": [{"name": "CLIENT_SECRET", "value": value}]}]}}
        self.assertEqual([h["rule"] for h in scan({"pod.json": doc}).hits], ["SEC-001"])
        for placeholder in ("", "<set-me>", "{{ .Values.password }}", "${DB_PASSWORD}", "$DB_PASSWORD"):
            with self.subTest(placeholder=placeholder):
                result = scan({"deploy.yaml": manifest.replace('"VALUE"', json.dumps(placeholder))})
                self.assertEqual([h for h in result.hits if h["rule"] == "SEC-001"], [])

    def test_more_workload_kinds(self):
        for name, text in {
            "knative.yaml": "apiVersion: serving.knative.dev/v1\nkind: Service\nmetadata:\n  name: k\nspec:\n" + POD,
            "dc.yaml": "apiVersion: apps.openshift.io/v1\nkind: DeploymentConfig\nmetadata:\n  name: d\nspec:\n" + POD,
            "keda.yaml": "apiVersion: keda.sh/v1alpha1\nkind: ScaledJob\nmetadata:\n  name: j\nspec:\n"
                         "  jobTargetRef:\n" + POD.replace("\n  ", "\n    ").replace("  template", "    template", 1),
            "wf.yaml": "apiVersion: argoproj.io/v1alpha1\nkind: Workflow\nmetadata:\n  name: w\nspec:\n"
                       "  templates:\n    - name: t\n      container:\n        image: x\n"
                       "        securityContext:\n          capabilities:\n            add: [SYS_MODULE]\n",
        }.items():
            with self.subTest(name=name):
                result = scan({name: text})
                self.assertEqual([h["rule"] for h in result.hits], ["K8S-001"], (result.hits, result.not_run))

    def test_unmodelled_workload_is_named(self):
        result = scan({"p.yaml": "apiVersion: monitoring.coreos.com/v1\nkind: Prometheus\nmetadata:\n  name: p\n"
                                 "spec:\n  containers:\n    - name: c\n"})
        self.assertTrue([n for n in result.not_run if "workload kind Prometheus" in n])

    def test_rbac_platform_bindings_namespaces_and_wildcards(self):
        docs = [
            "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: kubeadm:cluster-admins\n"
            "roleRef:\n  kind: ClusterRole\n  name: cluster-admin\nsubjects:\n  - kind: Group\n    name: kubeadm:cluster-admins\n",
            "apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  name: team\n  namespace: team-a\n"
            "roleRef:\n  kind: ClusterRole\n  name: cluster-admin\nsubjects:\n  - kind: User\n    name: alice\n",
            "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: argocd-application-controller\n"
            "rules:\n  - apiGroups: ['*']\n    resources: ['*']\n    verbs: ['*']\n",
            "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: argocd\n"
            "roleRef:\n  kind: ClusterRole\n  name: argocd-application-controller\nsubjects:\n"
            "  - kind: ServiceAccount\n    name: argocd\n    namespace: argocd\n",
            "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: all-sa\n"
            "roleRef:\n  kind: ClusterRole\n  name: view\nsubjects:\n  - kind: Group\n    name: system:serviceaccounts\n",
        ]
        result = scan({"rbac.yaml": "---\n".join(docs)})
        self.assertEqual(sorted((h["address"], h["severity"]) for h in result.hits),
                         [("k8s:ClusterRoleBinding/all-sa", "High"), ("k8s:ClusterRoleBinding/argocd", "High"),
                          ("k8s:RoleBinding/team-a/team", "Medium")])
        self.assertTrue([n for n in result.not_run if "kubeadm:cluster-admins" in n])

    def test_omitted_namespace_pairs_with_an_explicit_one_both_ways(self):
        # An omitted namespace is the apply context's; it was taken as
        # "default" on the role/account side only, so the pair was dropped.
        role = ("apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: all{ns}\n"
                "rules:\n  - apiGroups: ['*']\n    resources: ['*']\n    verbs: ['*']\n")
        binding = ("apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  name: b{ns}\n"
                   "roleRef:\n  kind: Role\n  name: all\nsubjects:\n  - kind: User\n    name: bob\n")
        sa = "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: app{ns}\nautomountServiceAccountToken: true\n"
        pod = ("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p{ns}\nspec:\n  serviceAccountName: app\n"
               "  containers:\n    - name: c\n      image: x\n")
        prod, none, other = "\n  namespace: prod", "", "\n  namespace: dev"
        for first, second, expected in ((none, prod, True), (prod, none, True), (prod, prod, True),
                                        (other, prod, False)):
            with self.subTest(first=first, second=second):
                rbac = scan({"rbac.yaml": role.format(ns=first) + "---\n" + binding.format(ns=second)})
                self.assertEqual(any(h["rule"] == "K8S-002" for h in rbac.hits), expected, rbac.hits)
                pods = scan({"pod.yaml": sa.format(ns=first) + "---\n" + pod.format(ns=second)})
                self.assertEqual(any(h["rule"] == "K8S-001" for h in pods.hits), expected, pods.hits)

    def test_empty_secrets_and_export_shapes(self):
        pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "p"}, "spec": {"hostPID": True}}
        result = scan({
            "secret.yaml": "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\nstringData:\n  tls.crt: ''\n",
            "items.json": [pod],
            "list.yaml": "- apiVersion: v1\n  kind: Pod\n  metadata:\n    name: q\n  spec:\n    hostIPC: true\n",
            "ndjson.json": json.dumps(pod) + "\n" + json.dumps(pod) + "\n",
        })
        self.assertEqual(found(result), [("K8S-001", "k8s:Pod/p"), ("K8S-001", "k8s:Pod/q")])
        self.assertTrue([n for n in result.not_run if "ndjson.json" in n])


if __name__ == "__main__":
    unittest.main()
