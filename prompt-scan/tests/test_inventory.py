import json
from pathlib import Path
import tempfile
import unittest

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
