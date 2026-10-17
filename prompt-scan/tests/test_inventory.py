import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from helpers import SAMPLE_APP, inventory, run, sample, write_json


def make_repo(files):
    root = Path(tempfile.mkdtemp())
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


class InventoryTest(unittest.TestCase):
    def test_sample_app(self):
        result = inventory.scan(SAMPLE_APP)
        files = {f["path"]: f for f in result["prompt_files"]}
        self.assertEqual(files["app/llm/prompts/answer.prompt"]["variables"], ["context", "question"])
        self.assertEqual(files["app/llm/prompts/support_system.md"]["variables"], ["ticket_body"])
        self.assertEqual([(c["path"], c["line"], c["api"]) for c in result["call_sites"]],
                         [("app/llm/answer.py", 15, "anthropic.messages")])
        self.assertEqual(result["models"], [{"id": "claude-haiku-5-5", "locations": ["app/llm/answer.py:16"]}])
        self.assertEqual([(h["rule"], h["location"]) for h in result["lint"]],
                         [("unclosed-tag", "app/llm/prompts/support_system.md:3"),
                          ("placeholder", "app/llm/prompts/support_system.md:7")])

    def test_prompt_file_detection(self):
        root = make_repo({
            "skills/x/SKILL.md": "---\nname: x\n---\nDo it.\n",
            ".claude/agents/reviewer.md": "Review.\n",
            "AGENTS.md": "Rules.\n",
            "docs/guide.md": "Not a prompt.\n",
            "src/templates/page.html": "{{ title }}\n",
        })
        kinds = {f["path"]: f["kind"] for f in inventory.scan(root)["prompt_files"]}
        self.assertEqual(kinds, {"skills/x/SKILL.md": "skill", ".claude/agents/reviewer.md": "agent",
                                 "AGENTS.md": "agent"})

    def test_lint_rules(self):
        token = "ghp_" + "A" * 36
        root = make_repo({
            "prompts/a.md": "{{ name }\n<rules>\nkeep it\n" + ("Always cite the title of the source document you used.\n" * 2),
            "prompts/b.md": f"Use key {token}\n",
            "prompts/c.md": "```\n<example>\nTODO\n{\"user\": {\"id\": 1}}\n```\n<b>bold</b> <other tenant's id>\n",
            # Inline code holds examples, not markup; the same tag outside it still counts.
            "skills/x/SKILL.md": "Run `render.py <out> --lang <lang>` and `{{ name` then `TODO`.\n",
            "skills/y/SKILL.md": "Use `<rules>` here.\n<rules>\nkeep it\n",
        })
        hits = {(h["rule"], h["location"]) for h in inventory.scan(root)["lint"]}
        self.assertIn(("unbalanced-template", "prompts/a.md:1"), hits)
        self.assertIn(("unclosed-tag", "prompts/a.md:2"), hits)
        self.assertIn(("duplicate-line", "prompts/a.md:5"), hits)
        self.assertIn(("secret-literal", "prompts/b.md:1"), hits)
        self.assertFalse([h for h in hits if h[1].startswith("prompts/c.md")], hits)
        self.assertFalse([h for h in hits if h[1].startswith("skills/x/SKILL.md")], hits)
        self.assertIn(("unclosed-tag", "skills/y/SKILL.md:2"), hits)
        text = json.dumps(inventory.scan(root))
        self.assertNotIn(token, text)

    def test_skips_env_and_vendor(self):
        root = make_repo({"prompts/.env": "x\n", "node_modules/p/prompts/a.md": "TODO\n", "prompts/ok.md": "Hi\n"})
        self.assertEqual([f["path"] for f in inventory.scan(root)["prompt_files"]], ["prompts/ok.md"])

    def test_model_ids_in_cloud_forms(self):
        root = make_repo({"cfg.py": "\n".join([
            'BEDROCK = "us.anthropic.claude-sonnet-4-20250514-v1:0"',
            'VERTEX = "claude-3-5-sonnet@20240620"',
            'GEMINI = ["models/gemini-1.5-pro", "gemini-pro"]',
            'OPENAI = ["o1-preview", "o3-mini-2025-01-31", "chatgpt-4o-latest"]',
            'SHORT = ["gpt-4", "claude-2", "llama3", "gemini-flash-latest"]',
            'GLOBAL = "global.anthropic.claude-sonnet-4-5-20250929-v1:0"',
            'NOT_A_MODEL = ["gemini-cli", "claude-", "o3x"]',
        ]) + "\n"})
        self.assertEqual([m["id"] for m in inventory.scan(root)["models"]], [
            "chatgpt-4o-latest", "claude-2", "claude-3-5-sonnet@20240620", "gemini-flash-latest", "gemini-pro",
            "global.anthropic.claude-sonnet-4-5-20250929-v1:0", "gpt-4", "llama3", "models/gemini-1.5-pro",
            "o1-preview", "o3-mini-2025-01-31", "us.anthropic.claude-sonnet-4-20250514-v1:0"])

    def test_variable_forms(self):
        self.assertEqual(inventory.variables("{{- user }} {{~ name}} {amount:.2f} {who!r} {a: 1} {{ x }}"),
                         ["user", "name", "x", "amount", "who"])

    def test_literal_braces_and_format_masks_are_not_template_or_placeholder_hits(self):
        rules = lambda text: [h["rule"] for h in inventory.lint_file("p.md", text, 1)]  # noqa: E731
        self.assertEqual(rules('Reply as {"user": {"id": 1}}\nPhone: XXX-XXX-XXXX, code AXXXB\n'), [])
        # In a file that uses the template engine, a stray closer and a bare XXX still count.
        self.assertEqual(rules("{{ a }}\nstray }}\nXXX: decide later\n"), ["unbalanced-template", "placeholder"])

    def test_fences_and_first_template_line(self):
        self.assertEqual(inventory.fenced_lines(["````", "```", "<x>", "````", "<y>"]), {1, 2, 3, 4})
        self.assertEqual(inventory.lint_template(["{{ name", "", "stray %}"], set()),
                         [(1, "{{ opened and never closed")])

    def test_rescan_keeps_each_tag_review_on_a_shared_line(self):
        root = make_repo({"prompts/a.md": "<rules><context>\n"})
        out = Path(tempfile.mkdtemp())
        data = sample()
        data["findings"] = [f for f in data["findings"] if f["id"].startswith("F-")]
        write_json(out / "findings.json", data)
        args = (root, "--out", out / "inventory.json", "--into", out / "findings.json")
        self.assertEqual(run(inventory.main, *args)[0], 0)
        merged = json.loads((out / "findings.json").read_text(encoding="utf-8"))
        verdicts = {}
        for f in merged["findings"]:
            if f["id"].startswith("L-"):
                verdicts[f["id"]] = "FalsePositive" if "<rules>" in f["cause"] else "Valid"
                f["validation"] = {"verdict": verdicts[f["id"]], "evidence": f["cause"], "method": "static"}
        write_json(out / "findings.json", merged)
        self.assertEqual(run(inventory.main, *args)[0], 0)
        merged = json.loads((out / "findings.json").read_text(encoding="utf-8"))
        kept = {f["cause"]: f["previous_validation"]["verdict"] for f in merged["findings"] if f["id"].startswith("L-")}
        self.assertEqual(sorted(kept.values()), ["FalsePositive", "Valid"])
        for cause, verdict in kept.items():
            self.assertEqual(verdict, "FalsePositive" if "<rules>" in cause else "Valid")

    def test_lint_order_compares_line_numbers(self):
        root = make_repo({"prompts/a.md": "x\n" * 8 + "TODO\n<rules>\n"})
        self.assertEqual([h["location"] for h in inventory.scan(root)["lint"]], ["prompts/a.md:9", "prompts/a.md:10"])

    def test_dirty_is_scoped_to_the_scanned_tree(self):
        root = make_repo({"svc/prompts/a.md": "one\n", "other/b.md": "two\n"})
        git = ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.com"]
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run([*git, "add", "."], check=True)
        subprocess.run([*git, "commit", "-qm", "init"], check=True)
        (root / "other" / "b.md").write_text("changed\n", encoding="utf-8")
        index = root / ".git" / "index"
        before = index.stat().st_mtime_ns
        commit, dirty = inventory.git_state(root / "svc")
        self.assertRegex(commit, r"^[0-9a-f]{40}$")
        self.assertIs(dirty, False)
        self.assertIs(inventory.git_state(root)[1], True)
        self.assertEqual(index.stat().st_mtime_ns, before, "git status rewrote the reviewed repository's index")
        # An untracked prompt is part of the scan but not of HEAD, whatever the repository's status config says.
        subprocess.run(["git", "-C", str(root), "config", "status.showUntrackedFiles", "no"], check=True)
        (root / "svc" / "prompts" / "new.md").write_text("new\n", encoding="utf-8")
        self.assertIs(inventory.git_state(root / "svc")[1], True)

    def test_dirty_is_unknown_when_git_status_fails(self):
        def fake(cmd, **kwargs):
            ok = "rev-parse" in cmd
            return subprocess.CompletedProcess(cmd, 0 if ok else 128, stdout="0" * 40 if ok else "", stderr="")
        with mock.patch.object(inventory.subprocess, "run", side_effect=fake):
            self.assertEqual(inventory.git_state(Path(".")), ("0" * 40, None))

    def test_rescans_keep_the_latest_review(self):
        out = Path(tempfile.mkdtemp())
        write_json(out / "findings.json", sample())
        for _ in range(2):  # The second rescan comes before anyone re-reviewed the hit.
            code, _, err = run(inventory.main, SAMPLE_APP, "--out", out / "inventory.json",
                               "--into", out / "findings.json")
            self.assertEqual(code, 0, err)
        merged = json.loads((out / "findings.json").read_text(encoding="utf-8"))
        lint = [f for f in merged["findings"] if f["id"].startswith("L-")]
        self.assertEqual([f["previous_validation"]["verdict"] for f in lint], ["Valid", "Valid"])

    def test_into_replaces_lint_findings_and_keeps_review(self):
        out = Path(tempfile.mkdtemp())
        data = sample()
        write_json(out / "findings.json", data)
        code, _, err = run(inventory.main, SAMPLE_APP, "--out", out / "inventory.json", "--into", out / "findings.json")
        self.assertEqual(code, 0, err)
        merged = json.loads((out / "findings.json").read_text(encoding="utf-8"))
        lint = [f for f in merged["findings"] if f["id"].startswith("L-")]
        self.assertEqual([f["id"] for f in lint], ["L-001", "L-002"])
        self.assertTrue(all(f["validation"]["verdict"] == "Unverified" for f in lint))
        self.assertEqual(lint[0]["previous_validation"]["verdict"], "Valid")
        self.assertEqual(len([f for f in merged["findings"] if f["id"].startswith("F-")]), 8)
        self.assertIn("commit", merged["meta"])


if __name__ == "__main__":
    unittest.main()
