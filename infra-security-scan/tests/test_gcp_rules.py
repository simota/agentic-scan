"""GCP service defaults and firewall exports retain their security meaning."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "infra-scan" / "scripts"))
import iac_scan  # noqa: E402


class ScanCase(unittest.TestCase):
    def scan(self, text, name="main.tf"):
        with tempfile.TemporaryDirectory(prefix="iac-gcp-rules-") as tmp:
            (Path(tmp) / name).write_text(text, encoding="utf-8")
            return iac_scan.run(tmp)


class CloudSqlDefaultsTest(ScanCase):
    def database(self, ipv4=None, ssl='"ALLOW_UNENCRYPTED_AND_ENCRYPTED"'):
        public_ip = f"      ipv4_enabled = {ipv4}\n" if ipv4 is not None else ""
        return self.scan('''resource "google_sql_database_instance" "app" {
  name = "example-db"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
''' + public_ip + f"      ssl_mode = {ssl}\n" + '''      authorized_networks {
        name = "office"
        value = "203.0.113.4/32"
      }
    }
  }
}
''')

    def test_omitted_and_null_public_ip_match_the_enabled_default(self):
        for ipv4 in (None, "null", "true", '"true"'):
            with self.subTest(ipv4=ipv4):
                scan = self.database(ipv4)
                self.assertEqual([(h["rule"], h["detail"]) for h in scan.hits],
                                 [("GCP-SQL-001", "public IP without required TLS")])
                self.assertEqual(scan.not_run, [])

    def test_disabled_or_unknown_public_ip_does_not_use_the_default(self):
        for ipv4 in ("false", '"false"', "var.public_ip", '"invalid"'):
            with self.subTest(ipv4=ipv4):
                self.assertEqual(self.database(ipv4).hits, [])

    def test_enforced_or_unknown_tls_does_not_prove_plaintext_access(self):
        for ssl in ('"ENCRYPTED_ONLY"', '"TRUSTED_CLIENT_CERTIFICATE_REQUIRED"',
                    "var.ssl_mode"):
            with self.subTest(ssl=ssl):
                self.assertEqual(self.database(ssl=ssl).hits, [])

    def test_unknown_public_ip_in_a_plan_does_not_use_the_default(self):
        resource = {"address": "google_sql_database_instance.app", "mode": "managed",
                    "type": "google_sql_database_instance", "values": {"settings": [{
                        "ip_configuration": [{"ssl_mode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED"}],
                    }]}}
        doc = {"planned_values": {"root_module": {"resources": [resource]}},
               "resource_changes": [{"address": resource["address"], "change": {
                   "after_unknown": {"settings": [{"ip_configuration": [{"ipv4_enabled": True}]}]},
               }}]}
        scan = self.scan(json.dumps(doc), "plan.json")
        self.assertEqual(scan.hits, [])
        self.assertTrue(any("plan contains unknown" in note for note in scan.not_run))


class GkeAutopilotTest(ScanCase):
    def cluster(self, autopilot=None, identity=False, private=True):
        mode = f"  enable_autopilot = {autopilot}\n" if autopilot is not None else ""
        endpoint = '''  private_cluster_config {
    enable_private_nodes = true
    enable_private_endpoint = true
    master_ipv4_cidr_block = "172.16.0.0/28"
  }
''' if private else ""
        workload = '''  workload_identity_config {
    workload_pool = "example-project.svc.id.goog"
  }
''' if identity else ""
        return self.scan('resource "google_container_cluster" "app" {\n' +
                         '  name = "example-cluster"\n  location = "us-central1"\n' +
                         mode + endpoint + workload + '}\n')

    def test_autopilot_has_workload_identity_without_an_explicit_block(self):
        for autopilot in ("true", '"true"'):
            with self.subTest(autopilot=autopilot):
                scan = self.cluster(autopilot)
                self.assertEqual(scan.hits, [])
                self.assertEqual(scan.not_run, [])

    def test_standard_and_default_modes_still_require_workload_identity(self):
        for autopilot in (None, "null", "false", '"false"'):
            with self.subTest(autopilot=autopilot):
                scan = self.cluster(autopilot)
                self.assertEqual([(h["rule"], h["detail"]) for h in scan.hits],
                                 [("GCP-GKE-001", "no workload_identity_config")])
                self.assertEqual(scan.not_run, [])

    def test_unknown_autopilot_mode_requires_review_without_a_finding(self):
        scan = self.cluster("var.autopilot")
        self.assertEqual(scan.hits, [])
        self.assertTrue(any("GCP-GKE-001" in note and "Autopilot" in note and
                            "main.tf:4" in note for note in scan.not_run))

    def test_explicit_identity_is_safe_even_when_autopilot_is_unknown(self):
        scan = self.cluster("var.autopilot", identity=True)
        self.assertEqual(scan.hits, [])
        self.assertEqual(scan.not_run, [])

    def test_autopilot_does_not_hide_an_unrestricted_control_plane(self):
        scan = self.cluster("true", private=False)
        self.assertEqual([(h["rule"], h["detail"]) for h in scan.hits],
                         [("GCP-GKE-001", "no master authorized networks and no private endpoint")])


class FirewallSnapshotTest(ScanCase):
    def firewall(self, name="internal-ssh", **fields):
        return {"kind": "compute#firewall", "name": name, "direction": "INGRESS",
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}], **fields}

    def snapshot(self, resources):
        return self.scan(json.dumps(resources), "gcp-firewall.json")

    def test_tag_service_account_and_egress_exports_are_inventoried_alone(self):
        for fields in ({"sourceTags": ["bastion"]},
                       {"sourceServiceAccounts": ["bastion@example.iam.gserviceaccount.com"]},
                       {"direction": "EGRESS", "destinationRanges": ["0.0.0.0/0"]}):
            with self.subTest(fields=fields):
                scan = self.snapshot([self.firewall(**fields)])
                self.assertEqual(scan.files, [{"path": "gcp-firewall.json", "kind": "snapshot"}])
                self.assertEqual([r["address"] for r in scan.resources], ["snapshot:internal-ssh"])
                self.assertEqual(scan.hits, [])
                self.assertEqual(scan.not_run, [])

    def test_world_range_rule_does_not_change_other_firewall_inventory(self):
        private = self.firewall(sourceTags=["bastion"])
        public = self.firewall("public-ssh", sourceRanges=["0.0.0.0/0"])
        alone = self.snapshot([private])
        together = self.snapshot([private, public])
        self.assertEqual(alone.resources, together.resources[:1])
        self.assertEqual([(h["rule"], h["address"]) for h in together.hits],
                         [("GCP-NET-001", "snapshot:public-ssh")])

    def test_concise_firewall_snapshots_without_kind_remain_supported(self):
        for rule in ("allowed", "denied"):
            with self.subTest(rule=rule):
                scan = self.snapshot([{"name": "ssh", "sourceRanges": ["0.0.0.0/0"],
                                       rule: [{"IPProtocol": "tcp", "ports": ["22"]}]}])
                self.assertEqual([r["address"] for r in scan.resources], ["snapshot:ssh"])
                self.assertEqual([h["rule"] for h in scan.hits],
                                 ["GCP-NET-001"] if rule == "allowed" else [])

    def test_unrelated_json_lists_are_not_classified_as_firewalls(self):
        unrelated = (
            [],
            [{"name": "notes", "sourceRanges": ["0.0.0.0/0"]}],
            [{"name": "notes", "sourceRanges": ["0.0.0.0/0"], "allowed": ["anything"]}],
            [self.firewall(kind="compute#instance", sourceRanges=["0.0.0.0/0"])],
            [self.firewall(sourceRanges=["0.0.0.0/0"]), {"kind": "unrelated"}],
        )
        for doc in unrelated:
            with self.subTest(doc=doc):
                scan = self.snapshot(doc)
                self.assertEqual(scan.files, [])
                self.assertEqual(scan.resources, [])
                self.assertEqual(scan.hits, [])


if __name__ == "__main__":
    unittest.main()
