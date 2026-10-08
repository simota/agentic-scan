"""Kubernetes rules use YAML structure and retain evidence line numbers."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "infra-scan" / "scripts"))
import iac_scan  # noqa: E402


class KubernetesParseTest(unittest.TestCase):
    def scan(self, text):
        with tempfile.TemporaryDirectory(prefix="k8s-parse-test-") as tmp:
            path = Path(tmp) / "manifest.yaml"
            path.write_text(text, encoding="utf-8")
            return iac_scan.run(tmp)

    def test_metadata_and_service_account_names_do_not_grant_admin(self):
        scan = self.scan("""apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cluster-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: cluster-admin
  namespace: default
- kind: User
  name: system:authenticated
""")
        self.assertEqual(scan.hits, [])
        self.assertEqual(scan.not_run, [])
        self.assertEqual(scan.resources[0]["address"], "k8s:RoleBinding/cluster-admin")

    def test_rbac_comments_quotes_and_subject_kinds(self):
        text = """'apiVersion': rbac.authorization.k8s.io/v1
"kind": ClusterRoleBinding
metadata: {name: administrators}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: "cluster-admin" # administrator permissions
subjects:
- kind: Group
  name: 'system:authenticated' # all signed-in users
- kind: User
  name: system:anonymous # anonymous requests
"""
        scan = self.scan(text)
        self.assertEqual([(h["rule"], h["line"]) for h in scan.hits],
                         [("K8S-002", 7), ("K8S-002", 10), ("K8S-002", 12)])
        self.assertEqual(scan.not_run, [])

    def test_hash_and_apostrophe_inside_strings_are_not_comments(self):
        scan = self.scan("""apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: readers
  annotations:
    description: Reader's permissions, with explanatory text
roleRef: {kind: ClusterRole, name: "cluster-admin # different role"}
subjects: [{kind: Group, name: 'system:authenticated # different group'}]
""")
        self.assertEqual(scan.hits, [])
        self.assertEqual(scan.not_run, [])

    def test_configmap_block_strings_are_not_workloads(self):
        scan = self.scan("""apiVersion: v1
kind: ConfigMap
metadata:
  name: documentation
data:
  example.yaml: |-
    privileged: true
    hostNetwork: true
    hostPath: {path: /}
    roleRef: {kind: ClusterRole, name: cluster-admin}
    ---
    kind: Secret
    data: {setting: placeholder}
  notes: > # folding does not make the contents Kubernetes fields
    hostPID: true
""")
        self.assertEqual(scan.hits, [])
        self.assertEqual(scan.not_run, [])
        self.assertEqual([r["address"] for r in scan.resources], ["k8s:ConfigMap/documentation"])

    def test_indentless_containers_and_volumes_keep_field_lines(self):
        scan = self.scan("""apiVersion: v1
kind: Pod
metadata: {name: agent}
spec:
  hostNetwork: true # public host network
  containers:
  - name: agent
    image: example/agent:1.0
    securityContext: {privileged: true}
  volumes:
  - name: root
    hostPath:
      path: /
""")
        self.assertEqual([(h["detail"], h["line"]) for h in scan.hits],
                         [("hostNetwork: true", 5), ("privileged: true", 9),
                          ("hostPath volume", 12)])
        self.assertEqual(scan.not_run, [])

    def test_standard_workload_podspec_paths_and_container_types(self):
        paths = {
            "Pod": ["spec"],
            "PodTemplate": ["template", "spec"],
            "Deployment": ["spec", "template", "spec"],
            "StatefulSet": ["spec", "template", "spec"],
            "DaemonSet": ["spec", "template", "spec"],
            "ReplicaSet": ["spec", "template", "spec"],
            "ReplicationController": ["spec", "template", "spec"],
            "Job": ["spec", "template", "spec"],
            "CronJob": ["spec", "jobTemplate", "spec", "template", "spec"],
        }
        for kind, path in paths.items():
            with self.subTest(kind=kind):
                doc = {"apiVersion": "v1", "kind": kind, "metadata": {"name": "agent"}}
                cursor = doc
                for key in path:
                    cursor[key] = {}
                    cursor = cursor[key]
                cursor.update({"hostPID": True, "hostIPC": True,
                               "initContainers": [{"securityContext": {"privileged": True}}],
                               "ephemeralContainers": [{"securityContext": {"privileged": True}}]})
                scan = self.scan(json.dumps(doc))
                self.assertEqual({h["detail"] for h in scan.hits},
                                 {"hostPID: true", "hostIPC: true", "privileged: true"})
                self.assertEqual(len(scan.hits), 3)
                self.assertEqual(scan.not_run, [])

    def test_single_line_yaml_flow_collections(self):
        scan = self.scan("""{metadata: {name: agent}, apiVersion: v1, kind: Pod, spec: {containers: [{name: agent, image: example/agent:1.0, securityContext: {privileged: true}}]}}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: admins}
roleRef: {kind: ClusterRole, name: cluster-admin} # standard role
subjects: [{kind: Group, name: system:authenticated}]
""")
        self.assertEqual([(h["rule"], h["line"]) for h in scan.hits],
                         [("K8S-001", 1), ("K8S-002", 6), ("K8S-002", 7)])
        self.assertEqual(scan.not_run, [])

    def test_secret_data_is_structural_and_empty_maps_are_silent(self):
        scan = self.scan("""apiVersion: v1
kind: Secret
metadata: {name: empty}
data: {} # no committed data
stringData:
---
apiVersion: v1
kind: Secret
metadata: {name: populated}
data: {setting: ZXhhbXBsZQ==}
stringData:
  notes: |
    placeholder
""")
        self.assertEqual([(h["rule"], h["line"]) for h in scan.hits],
                         [("K8S-003", 10), ("K8S-003", 11)])
        self.assertEqual(scan.not_run, [])

    def test_lists_inventory_and_check_each_resource(self):
        scan = self.scan("""apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: Pod
  metadata: {name: agent}
  spec: {hostNetwork: true}
- apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRoleBinding
  metadata: {name: administrators}
  roleRef: {kind: ClusterRole, name: cluster-admin}
""")
        self.assertEqual([r["address"] for r in scan.resources],
                         ["k8s:Pod/agent", "k8s:ClusterRoleBinding/administrators"])
        self.assertEqual([h["line"] for h in scan.hits], [7, 11])
        self.assertEqual(scan.not_run, [])

    def test_unsupported_syntax_is_explicitly_not_run(self):
        cases = [
            "spec: &pod\n  hostNetwork: true\n",
            "spec: *pod\n",
            "spec: !!map {hostNetwork: true}\n",
            "spec: {hostNetwork: true,\n       hostPID: true}\n",
            "spec: {hostNetwork:true}\n",
            "spec:\n  <<: *pod\n",
            "kind: Deployment\n",
            "metadata:\n  name: agent\n  description: a multiline\n    plain string\n",
            "metadata:\n  name: \"multiline\n    string\"\n",
            "spec:\n\thostNetwork: true\n",
        ]
        for suffix in cases:
            with self.subTest(suffix=suffix):
                scan = self.scan("apiVersion: v1\nkind: Pod\n" + suffix)
                self.assertEqual(scan.hits, [])
                self.assertEqual(len(scan.not_run), 1)
                self.assertIn("kubernetes YAML rules not applied", scan.not_run[0])

    def test_unsupported_document_does_not_hide_later_valid_documents(self):
        scan = self.scan("""apiVersion: v1
kind: Pod
spec: &unsupported {hostNetwork: true}
---
apiVersion: v1
kind: Pod
metadata: {name: valid}
spec: {hostNetwork: true}
""")
        self.assertEqual([h["line"] for h in scan.hits], [8])
        self.assertEqual(len(scan.not_run), 1)
        self.assertTrue(scan.not_run[0].endswith("manifest.yaml:3"))

    def test_opaque_rbac_identity_requires_manual_review(self):
        scan = self.scan("""apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: admins}
roleRef:
  kind: ClusterRole
  name: |-
    cluster-admin
""")
        self.assertEqual(scan.hits, [])
        self.assertEqual(len(scan.not_run), 1)
        self.assertIn("opaque identity needs manual review", scan.not_run[0])


if __name__ == "__main__":
    unittest.main()
