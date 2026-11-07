"""Baseline rules for the Resilience and recovery perspective: backups switched off."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "infra-scan" / "scripts"))
import iac_scan  # noqa: E402

RULES = {"AWS-RDS-003", "GCP-SQL-002"}


def hits(files, snapshots=None):
    with tempfile.TemporaryDirectory(prefix="iac-resilience-") as tmp:
        root = Path(tmp) / "repo"
        for name, text in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        dirs = []
        for name, text in (snapshots or {}).items():
            path = Path(tmp) / "exports" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            dirs = [str(Path(tmp) / "exports")]
        root.mkdir(exist_ok=True)
        scan = iac_scan.run(str(root), dirs)
        return sorted((h["rule"], h["address"], h["line"]) for h in scan.hits if h["rule"] in RULES)


def rds(name, retention, extra=""):
    line = f"  backup_retention_period = {retention}\n" if retention is not None else ""
    return (f'resource "aws_db_instance" "{name}" {{\n  engine = "postgres"\n  storage_encrypted = true\n'
            f'{line}{extra}}}\n')


def sql(name, enabled, extra=""):
    backup = f"    backup_configuration {{\n      enabled = {enabled}\n    }}\n" if enabled is not None else ""
    return (f'resource "google_sql_database_instance" "{name}" {{\n  database_version = "POSTGRES_15"\n{extra}'
            f'  settings {{\n    tier = "db-f1-micro"\n{backup}    ip_configuration {{\n'
            f'      ipv4_enabled = false\n    }}\n  }}\n}}\n')


class AwsBackupTest(unittest.TestCase):
    def test_literal_zero_retention_fires_at_its_line(self):
        self.assertEqual(hits({"main.tf": rds("off", 0)}), [("AWS-RDS-003", "aws_db_instance.off", 4)])
        self.assertEqual(hits({"main.tf": rds("quoted", '"0"')}), [("AWS-RDS-003", "aws_db_instance.quoted", 4)])

    def test_retention_kept_omitted_or_unresolved_is_silent(self):
        for value in (7, '"1"', None, "var.retention", "local.days"):
            with self.subTest(value=value):
                self.assertEqual(hits({"main.tf": rds("db", value)}), [])

    def test_a_read_replica_takes_its_source_backups(self):
        text = rds("replica", 0, '  replicate_source_db = aws_db_instance.main.identifier\n')
        self.assertEqual(hits({"main.tf": text}), [])

    def test_cloudformation_json_and_yaml(self):
        props = {"Engine": "postgres", "StorageEncrypted": True, "BackupRetentionPeriod": 0}
        template = {"AWSTemplateFormatVersion": "2010-09-09",
                    "Resources": {"Db": {"Type": "AWS::RDS::DBInstance", "Properties": props}}}
        self.assertEqual([h[0] for h in hits({"t.json": json.dumps(template, indent=2)})], ["AWS-RDS-003"])
        yaml = ("AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Db:\n    Type: AWS::RDS::DBInstance\n"
                "    Properties:\n      Engine: postgres\n      StorageEncrypted: true\n"
                "      BackupRetentionPeriod: '0'\n")
        self.assertEqual([h[0] for h in hits({"t.yaml": yaml})], ["AWS-RDS-003"])
        props["BackupRetentionPeriod"] = {"Ref": "Retention"}
        self.assertEqual(hits({"t.json": json.dumps(template)}), [])
        props["BackupRetentionPeriod"] = 0
        props["SourceDBInstanceIdentifier"] = "primary"
        self.assertEqual(hits({"t.json": json.dumps(template)}), [])

    def test_describe_db_instances_snapshot(self):
        export = {"DBInstances": [
            {"DBInstanceIdentifier": "off", "BackupRetentionPeriod": 0, "StorageEncrypted": True},
            {"DBInstanceIdentifier": "kept", "BackupRetentionPeriod": 7, "StorageEncrypted": True},
            {"DBInstanceIdentifier": "replica", "BackupRetentionPeriod": 0, "StorageEncrypted": True,
             "ReadReplicaSourceDBInstanceIdentifier": "off"}]}
        found = hits({}, {"rds.json": json.dumps(export, indent=2)})
        self.assertEqual([(r, a) for r, a, _ in found], [("AWS-RDS-003", "snapshot:aws_db_instance.off")])

    def test_plan_json(self):
        plan = {"format_version": "1.2", "planned_values": {"root_module": {"resources": [
            {"address": "aws_db_instance.off", "mode": "managed", "type": "aws_db_instance", "name": "off",
             "values": {"engine": "postgres", "storage_encrypted": True, "backup_retention_period": 0}},
            {"address": "aws_db_instance.kept", "mode": "managed", "type": "aws_db_instance", "name": "kept",
             "values": {"engine": "postgres", "storage_encrypted": True, "backup_retention_period": 7}}]}}}
        self.assertEqual([(r, a) for r, a, _ in hits({"plan.json": json.dumps(plan, indent=2)})],
                         [("AWS-RDS-003", "aws_db_instance.off")])


class GcpBackupTest(unittest.TestCase):
    def test_explicitly_disabled_backups_fire_at_the_enabled_line(self):
        self.assertEqual(hits({"main.tf": sql("off", "false")}),
                         [("GCP-SQL-002", "google_sql_database_instance.off", 6)])
        self.assertEqual(hits({"main.tf": sql("quoted", '"false"')}),
                         [("GCP-SQL-002", "google_sql_database_instance.quoted", 6)])

    def test_enabled_omitted_or_unresolved_is_silent(self):
        for value in ("true", None, "var.backups"):
            with self.subTest(value=value):
                self.assertEqual(hits({"main.tf": sql("db", value)}), [])

    def test_a_replica_takes_its_primary_backups(self):
        text = sql("replica", "false", '  master_instance_name = google_sql_database_instance.main.name\n')
        self.assertEqual(hits({"main.tf": text}), [])

    def test_dynamic_backup_block_is_not_read_as_disabled(self):
        text = ('resource "google_sql_database_instance" "dyn" {\n  settings {\n    tier = "db-f1-micro"\n'
                '    dynamic "backup_configuration" {\n      for_each = var.backups\n      content {\n'
                '        enabled = false\n      }\n    }\n  }\n}\n')
        # for_each may be empty: whether the block exists is unknown until apply.
        self.assertEqual(hits({"main.tf": text}), [])


class CatalogTest(unittest.TestCase):
    def test_rules_name_the_resilience_perspective(self):
        for rule in RULES:
            self.assertEqual(iac_scan.RULES[rule][2], "Resilience and recovery")
            self.assertEqual(iac_scan.RULES[rule][1], "Low")


if __name__ == "__main__":
    unittest.main()
