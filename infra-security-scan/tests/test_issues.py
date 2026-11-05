"""issues.py: one issue draft per counted finding, filled from templates/issue.<lang>.md."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills" / "infra-scan" / "scripts"))
import issues  # noqa: E402

SAMPLE = REPO / "examples" / "findings.sample.json"
SAMPLE_JA = REPO / "examples" / "findings.sample.ja.json"


def sample(path=SAMPLE):
    return json.loads(path.read_text(encoding="utf-8"))


def by_id(data, fid):
    return next(f for f in data["findings"] if f["id"] == fid)


class DraftTest(unittest.TestCase):
    def test_one_draft_per_counted_finding_and_an_index(self):
        texts = issues.drafts(sample(), "en")
        # F-003 is a FalsePositive: excluded findings need no issue.
        self.assertEqual(sorted(texts), ["F-001.md", "F-002.md", "F-004.md", "F-005.md", "F-006.md",
                                         "I-001.md", "I-002.md", "I-003.md", "index.md"])
        index = texts["index.md"]
        self.assertIn("| [F-001](F-001.md) | High | Customer export bucket is readable by allUsers | "
                      "private tracker only |", index)
        self.assertIn("| [F-006](F-006.md) | Low | Production VPC has no flow logs | any tracker", index)

    def test_fields_come_from_the_finding_and_the_record(self):
        data = sample()
        text = issues.drafts(data, "en", ids=["F-002"])["F-002.md"]
        f = by_id(data, "F-002")
        self.assertIn(f"**Title:** [High] {f['title']} (F-002)", text)
        self.assertIn("| Resources | `aws_iam_role.terraform_deploy`, `aws_iam_openid_connect_provider.github` |", text)
        self.assertIn(f"| Revision | {data['meta']['commit']} |", text)
        self.assertIn(f["path"], text)
        self.assertIn(f"- **Policy-as-code regression guard:** {f['regression']}", text)
        for ref in f.get("references", []):
            self.assertIn(f"- [{ref['title']}]({ref['url']})", text)
        self.assertNotIn("{{", text.split("-->", 1)[1])  # the kept checklist quotes {{field}} itself
        # The filing checklist stays for whoever files it; the private banner comes first.
        self.assertTrue(text.startswith("> **Private tracker only.** An unfixed High finding"))
        self.assertIn("Before filing:", text)

    def test_empty_optional_rows_and_sections_are_dropped(self):
        data = sample()
        f = by_id(data, "F-006")
        for key in ("controls", "cwe", "references", "attack_paths"):
            f.pop(key, None)
        text = issues.drafts(data, "en", ids=["F-006"])["F-006.md"]
        self.assertNotIn("| Benchmark / CWE |", text)
        self.assertNotIn("| Attack paths |", text)
        self.assertNotIn("## References", text)
        self.assertIn("> Check the masking before filing", text)

    def test_a_condition_comment_becomes_its_line(self):
        data = sample()
        f = by_id(data, "F-004")
        text = issues.drafts(data, "en", ids=["F-004"])["F-004.md"]
        self.assertIn(f"**Assumed condition:** {f['condition']}", text)
        self.assertNotIn("If Environment-dependent", text)
        f.pop("condition")
        f["confidence"] = "Suspected"
        text = issues.drafts(data, "en", ids=["F-004"])["F-004.md"]
        self.assertNotIn("Assumed condition", text)
        # A comment naming no field is guidance and stays.
        self.assertIn("<!-- Conditions configuration cannot show", text)

    def test_table_values_cannot_break_the_row(self):
        data = sample()
        by_id(data, "F-001")["resources"] = ["google_storage_bucket_iam_member.a|b"]
        text = issues.drafts(data, "en", ids=["F-001"])["F-001.md"]
        self.assertIn("| Resources | `google_storage_bucket_iam_member.a\\|b` |", text)

    def test_japanese_template_and_display_values(self):
        texts = issues.drafts(sample(SAMPLE_JA), "ja")
        text = texts["F-004.md"]
        self.assertTrue(text.startswith("> **非公開トラッカー専用。**"))
        self.assertIn("| 深刻度 / 確度 | 中 / 環境依存 |", text)
        self.assertIn("**前提条件:**", text)
        self.assertIn("非公開トラッカーのみ", texts["index.md"])

    def test_selection(self):
        texts = issues.drafts(sample(), "en", min_severity="Medium")
        self.assertNotIn("F-006.md", texts)
        self.assertIn("I-003.md", texts)
        with self.assertRaisesRegex(issues.Refused, "excluded after triage"):
            issues.drafts(sample(), "en", ids=["F-003"])
        with self.assertRaisesRegex(issues.Refused, "no such finding: F-404"):
            issues.drafts(sample(), "en", ids=["F-404"])
        data = sample()
        by_id(data, "F-005")["validation"]["evidence"] += " Root cause of I-003."
        with self.assertRaisesRegex(issues.Refused, r"I-003 \(covered by F-005\)"):
            issues.drafts(data, "en", ids=["I-003"])
        self.assertNotIn("I-003.md", issues.drafts(data, "en"))

    def test_mask_hides_account_ids_and_addresses(self):
        data = sample()
        account = "1234" * 3
        f = by_id(data, "F-002")
        f["impact"] = f"Role arn:aws:iam::{account}:role/deploy reachable; bastion 203.0.113.7 and 0.0.0.0/0 ingress"
        text = issues.drafts(data, "en", ids=["F-002"], masked=True)["F-002.md"]
        self.assertNotIn(account, text)
        self.assertNotIn("203.0.113.7", text)
        self.assertIn("arn:aws:iam::<account-id>:role/deploy", text)
        self.assertIn("bastion <ip>", text)
        self.assertIn("0.0.0.0/0", text)
        self.assertIn(data["meta"]["commit"], text)  # a hex digest is not an account ID
        unmasked = issues.drafts(data, "en", ids=["F-002"])["F-002.md"]
        self.assertIn(account, unmasked)

    def test_credential_shapes_are_never_repeated(self):
        data = sample()
        key = "AKIA" + "Z" * 16  # built at runtime
        by_id(data, "F-005")["fix"] = f"Rotate {key}"
        text = issues.drafts(data, "en", ids=["F-005"])["F-005.md"]
        self.assertNotIn(key, text)


class CliTest(unittest.TestCase):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = issues.main([str(a) for a in args])
        return code, out.getvalue(), err.getvalue()

    def test_writes_drafts_to_scratch(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "drafts"
            code, out, _ = self.run_cli(SAMPLE, "--out", target, "--min-severity", "High")
            self.assertEqual(code, 0)
            self.assertIn("wrote 3 draft(s)", out)
            self.assertEqual(sorted(p.name for p in target.iterdir()), ["F-001.md", "F-002.md", "I-001.md", "index.md"])

    def test_refuses_the_output_directory_and_bad_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = Path(tmp) / "findings.json"
            record.write_text(SAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
            code, _, err = self.run_cli(record, "--out", tmp)
            self.assertEqual(code, 1)
            self.assertIn("holds findings.json", err)
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ["findings.json"])
            code, _, err = self.run_cli(record, "--out", Path(tmp) / "d", "--ids", "F-003")
            self.assertEqual(code, 1)
            self.assertFalse((Path(tmp) / "d").exists())

    def test_refuses_writing_through_a_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "drafts"
            target.mkdir()
            elsewhere = Path(tmp) / "elsewhere.md"
            elsewhere.write_text("keep", encoding="utf-8")
            (target / "F-001.md").symlink_to(elsewhere)
            code, _, err = self.run_cli(SAMPLE, "--out", target)
            self.assertEqual(code, 1)
            self.assertEqual(elsewhere.read_text(encoding="utf-8"), "keep")

    def test_schema_errors_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "findings.json"
            data = copy.deepcopy(sample())
            data["findings"] = 3
            bad.write_text(json.dumps(data), encoding="utf-8")
            code, _, err = self.run_cli(bad, "--out", Path(tmp) / "d")
            self.assertEqual(code, 2)
            self.assertIn("schema:", err)


if __name__ == "__main__":
    unittest.main()
