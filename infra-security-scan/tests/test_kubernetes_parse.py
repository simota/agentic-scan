"""Kubernetes rules use YAML structure and retain evidence line numbers."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "infra-security-scan" / "scripts"))
import iac_scan  # noqa: E402


class KubernetesParseTest(unittest.TestCase):
    def scan(self, text):
        with tempfile.TemporaryDirectory(prefix="k8s-parse-test-") as tmp:
            path = Path(tmp) / "manifest.yaml"
            path.write_text(text, encoding="utf-8")
            return iac_scan.run(tmp)

    def test_utf8_bom_does_not_hide_a_manifest(self):
        pod = """apiVersion: v1
kind: Pod
metadata: {name: agent}
spec:
  hostNetwork: true
  containers:
  - name: agent
    image: example/agent:1.0
    securityContext: {privileged: true}
"""
        for prefix in ("", "---\n", "# workload\n"):
            with self.subTest(prefix=prefix):
                expected = self.scan(prefix + pod)
                scan = self.scan("\ufeff" + prefix + pod)
                self.assertEqual(scan.files, expected.files)
                self.assertEqual(scan.resources, expected.resources)
                self.assertEqual(scan.hits, expected.hits)
                self.assertEqual(len(scan.hits), 2)
                self.assertEqual(scan.not_run, [])

    def test_bom_at_later_document_start_preserves_inventory_and_lines(self):
        scan = self.scan("""apiVersion: v1
kind: ConfigMap
metadata: {name: config}
---
\ufeffapiVersion: v1
kind: Pod
metadata: {name: agent}
spec: {hostNetwork: true}
""")
        self.assertEqual(scan.files, [{"path": "manifest.yaml", "kind": "kubernetes"}])
        self.assertEqual([(r["address"], r["line"]) for r in scan.resources],
                         [("k8s:ConfigMap/config", 2), ("k8s:Pod/agent", 6)])
        self.assertEqual([(h["rule"], h["line"]) for h in scan.hits], [("K8S-001", 8)])
        self.assertEqual(scan.not_run, [])

    def test_yaml_boolean_spellings_match_kubernetes(self):
        for value in ("y", "Y", "yes", "Yes", "YES", "on", "On", "ON",
                      "true", "True", "TRUE"):
            with self.subTest(value=value):
                scan = self.scan(f"""apiVersion: v1
kind: Pod
metadata: {{name: agent}}
spec:
  hostNetwork: {value}
  containers:
  - name: agent
    image: example/agent:1.0
    securityContext: {{privileged: {value}}}
""")
                self.assertEqual([(h["detail"], h["line"]) for h in scan.hits],
                                 [("hostNetwork: true", 5), ("privileged: true", 9)])
                self.assertEqual(scan.not_run, [])
        for value in ("n", "N", "no", "No", "NO", "off", "Off", "OFF",
                      "false", "False", "FALSE"):
            with self.subTest(value=value):
                doc = iac_scan._YamlSubset([(1, f"hostNetwork: {value}")]).parse()
                self.assertIs(doc["hostNetwork"], False)
        for value in ("y", "Y", "n", "N", "true", "false"):
            with self.subTest(quoted=value):
                doc = iac_scan._YamlSubset([(1, f'hostNetwork: "{value}"')]).parse()
                self.assertEqual(doc["hostNetwork"], value)

    def test_cloudformation_markers_in_comments_do_not_hide_kubernetes(self):
        scan = self.scan("""# AWSTemplateFormatVersion belongs to CloudFormation, not this workload.
apiVersion: v1
kind: Pod
metadata:
  name: agent
  annotations:
    example.com/note: AWSTemplateFormatVersion
spec: {hostNetwork: true}
""")
        self.assertEqual(scan.files, [{"path": "manifest.yaml", "kind": "kubernetes"}])
        self.assertEqual([r["address"] for r in scan.resources], ["k8s:Pod/agent"])
        self.assertEqual([(h["rule"], h["line"]) for h in scan.hits], [("K8S-001", 8)])
        self.assertEqual(scan.not_run, [])

    def test_cloudformation_block_strings_do_not_hide_later_workloads(self):
        scan = self.scan("""apiVersion: v1
kind: ConfigMap
metadata: {name: templates}
data:
  stack.yaml: |
    AWSTemplateFormatVersion: '2010-09-09'
    Resources:
      Example:
        Type: AWS::S3::Bucket
---
apiVersion: v1
kind: Pod
metadata: {name: agent}
spec: {hostNetwork: true}
""")
        self.assertEqual(scan.files, [{"path": "manifest.yaml", "kind": "kubernetes"}])
        self.assertEqual([r["address"] for r in scan.resources],
                         ["k8s:ConfigMap/templates", "k8s:Pod/agent"])
        self.assertEqual([(h["rule"], h["line"]) for h in scan.hits], [("K8S-001", 14)])
        self.assertEqual(scan.not_run, [])

    def test_mixed_yaml_documents_preserve_inventory_and_evidence_lines(self):
        cfn = """Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Custom BucketName
"""
        pod = """apiVersion: v1
kind: Pod
metadata: {name: agent}
spec: {hostNetwork: true}
"""
        for docs in ((cfn, pod), (pod, cfn)):
            with self.subTest(first=docs[0].splitlines()[0]):
                text = "---\n".join(docs)
                scan = self.scan(text)
                lines = text.splitlines()
                self.assertEqual(scan.files, [{"path": "manifest.yaml", "kind": "mixed-yaml"}])
                self.assertEqual({r["address"]: r["line"] for r in scan.resources},
                                 {"cfn:Bucket": lines.index("    Type: AWS::S3::Bucket") + 1,
                                  "k8s:Pod/agent": lines.index("kind: Pod") + 1})
                self.assertEqual([(h["rule"], h["line"]) for h in scan.hits],
                                 [("K8S-001", lines.index("spec: {hostNetwork: true}") + 1)])
                self.assertEqual(scan.not_run,
                                 ["cloudformation yaml: rules not applied (tags or syntax outside the YAML subset): "
                                  "manifest.yaml"])

    def test_cloudformation_text_in_non_infrastructure_yaml_is_not_inventory(self):
        scan = self.scan("""# AWSTemplateFormatVersion
documentation: |
  Resources:
    Bucket:
      Type: AWS::S3::Bucket
""")
        self.assertEqual(scan.files, [])
        self.assertEqual(scan.resources, [])
        self.assertEqual(scan.hits, [])
        self.assertEqual(scan.not_run, [])

    def test_unsupported_kubernetes_keeps_its_not_run_despite_cfn_comment(self):
        scan = self.scan("""# AWSTemplateFormatVersion
apiVersion: v1
kind: Pod
metadata: {name: agent}
spec: &unsupported {hostNetwork: true}
""")
        self.assertEqual(scan.files, [{"path": "manifest.yaml", "kind": "kubernetes"}])
        # Inventoried from its headers so it still belongs to a review unit.
        self.assertEqual([(r["address"], r["line"]) for r in scan.resources], [("k8s:Pod/agent", 3)])
        self.assertEqual(scan.hits, [])
        self.assertEqual(len(scan.not_run), 1)
        self.assertIn("kubernetes YAML rules not applied", scan.not_run[0])
        self.assertTrue(scan.not_run[0].endswith("manifest.yaml:5"))

    def test_tagged_or_anchored_root_flow_maps_are_explicitly_not_run(self):
        for prefix in ("!!map", "&root"):
            with self.subTest(prefix=prefix):
                scan = self.scan(prefix + " {apiVersion: v1, kind: Pod, "
                                 "metadata: {name: agent}, spec: {hostNetwork: true}}\n")
                self.assertEqual(scan.files, [{"path": "manifest.yaml", "kind": "kubernetes"}])
                self.assertEqual(scan.resources, [])
                self.assertEqual(scan.hits, [])
                self.assertEqual(len(scan.not_run), 1)
                self.assertIn("kubernetes YAML rules not applied", scan.not_run[0])
                self.assertTrue(scan.not_run[0].endswith("manifest.yaml:1"))

    def test_inline_document_start_flow_map_is_explicitly_not_run(self):
        scan = self.scan("--- {apiVersion: v1, kind: Pod, metadata: {name: agent}, "
                         "spec: {hostNetwork: true}}\n")
        self.assertEqual(scan.files, [{"path": "manifest.yaml", "kind": "kubernetes"}])
        self.assertEqual(scan.resources, [])
        self.assertEqual(scan.hits, [])
        self.assertEqual(len(scan.not_run), 1)
        self.assertIn("kubernetes YAML rules not applied", scan.not_run[0])
        self.assertTrue(scan.not_run[0].endswith("manifest.yaml:1"))

    def test_indented_root_is_scanned_like_an_unindented_manifest(self):
        text = """apiVersion: v1
kind: Pod
metadata: {name: agent}
spec:
  hostNetwork: true
  containers:
  - name: agent
    image: example/agent:1.0
"""
        expected = self.scan(text)
        scan = self.scan("\n".join("  " + line for line in text.splitlines()) + "\n")
        self.assertEqual(scan.files, [{"path": "manifest.yaml", "kind": "kubernetes"}])
        self.assertEqual(scan.resources, expected.resources)
        self.assertEqual(scan.hits, expected.hits)
        self.assertEqual([h["rule"] for h in scan.hits], ["K8S-001"])
        self.assertEqual(scan.not_run, [])

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

    def namespaced_pod(self, namespace):
        return f'''apiVersion: v1
kind: Pod
metadata: {{name: worker, namespace: {namespace}}}
spec:
  hostNetwork: true
  containers: [{{name: worker, image: example/worker:1.0}}]
'''

    def test_same_named_pods_in_different_namespaces_keep_distinct_identities(self):
        scan = self.scan(self.namespaced_pod("alpha") + "---\n" + self.namespaced_pod("beta"))
        addresses = ["k8s:Pod/alpha/worker", "k8s:Pod/beta/worker"]
        self.assertEqual([r["address"] for r in scan.resources], addresses)
        self.assertEqual(iac_scan.build_findings(scan.hits)[0]["resources"], addresses)
        self.assertEqual(scan.not_run, [])

    def test_removing_a_namespace_resource_invalidates_its_attack_path(self):
        alpha, beta = self.namespaced_pod("alpha"), self.namespaced_pod("beta")
        old = iac_scan.build_findings(self.scan(alpha + "---\n" + beta).hits)
        new = iac_scan.build_findings(self.scan(beta).hits)
        data = {"attack_paths": [{"id": "AP-01", "status": "open", "target": "alpha/worker",
                                  "findings": [old[0]["id"]]}], "limitations": []}
        iac_scan.remap_baseline_references(data, old, new)
        self.assertEqual(data["attack_paths"][0]["status"], "unknown")
        self.assertEqual(data["attack_paths"][0]["findings"], [])

    def test_legacy_ambiguous_namespace_address_requires_fresh_review(self):
        new = iac_scan.build_findings(self.scan(self.namespaced_pod("alpha")).hits)
        old = [{**new[0], "resources": ["k8s:Pod/worker"]}]
        data = {"attack_paths": [{"id": "AP-01", "status": "open", "findings": [old[0]["id"]]}],
                "limitations": []}
        iac_scan.remap_baseline_references(data, old, new)
        self.assertEqual(data["attack_paths"][0]["status"], "unknown")
        self.assertEqual(data["attack_paths"][0]["findings"], [])

    def test_missing_namespace_and_cluster_scope_keep_legacy_addresses(self):
        scan = self.scan('''apiVersion: v1
kind: Pod
metadata: {name: worker}
spec: {hostNetwork: true}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: admins}
roleRef: {kind: ClusterRole, name: cluster-admin}
''')
        self.assertEqual([r["address"] for r in scan.resources],
                         ["k8s:Pod/worker", "k8s:ClusterRoleBinding/admins"])
        self.assertEqual(scan.not_run, [])

    def test_opaque_namespace_is_an_explicit_unknown_identity(self):
        scan = self.scan('''apiVersion: v1
kind: Pod
metadata:
  name: worker
  namespace: |-
    alpha
spec: {hostNetwork: true}
''')
        self.assertEqual(scan.resources[0]["address"], "k8s:Pod/?/worker")
        self.assertEqual([h["rule"] for h in scan.hits], ["K8S-001"])
        self.assertEqual(len(scan.not_run), 1)
        self.assertIn("opaque identity needs manual review", scan.not_run[0])


if __name__ == "__main__":
    unittest.main()
