import json
import os
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
                         [("unfilled-variable", "app/llm/prompts/answer.prompt:4"),
                          ("unclosed-tag", "app/llm/prompts/support_system.md:3"),
                          ("placeholder", "app/llm/prompts/support_system.md:7")])

    def test_unreferenced_variable(self):
        root = make_repo({
            "prompts/a.prompt": "Hi {{ user.name }}, {{ missing }}\n{% for doc in docs %}{{ doc }}{% endfor %}\n"
                                "{{ loop.index }} `{{ example }}`\n",
            "prompts/b.md": "Ticket: {ticket}\n```\n{fenced}\n```\n",
            "AGENTS.md": "Use {never_filled} here\n",
            "app.py": "render(user=u, docs=d)\nfmt(ticket=t)\n",
        })
        hits = [(h["rule"], h["location"], h["detail"]) for h in inventory.scan(root)["lint"]]
        self.assertEqual(hits, [("unreferenced-variable", "prompts/a.prompt:1", "1 variable(s) no code file names: missing")])

    def test_unreferenced_variable_needs_code_to_check_against(self):
        root = make_repo({"prompts/a.prompt": "{{ only_prompts }}\n"})
        self.assertEqual(inventory.scan(root)["lint"], [])

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
        # An engine template file whose only delimiter is a stray closer (a forgotten opener) still counts.
        for name in ("reply.j2", "reply.mustache"):
            self.assertEqual([h["rule"] for h in inventory.lint_file(name, "Hello }}\n", 1)], ["unbalanced-template"])
        # In JSON, YAML and TOML a }} closes nested objects even when a value holds a {{variable}}; an
        # opener left open is still a hit.
        data_rules = lambda name, text: [h["rule"] for h in inventory.lint_file(name, text, 1)]  # noqa: E731
        self.assertEqual(data_rules("chat.json", '{"messages": [{"content": "Help {{customer}}."}], "p": {"t": 0}}\n'), [])
        self.assertEqual(data_rules("sum.yaml", "system: Hi {{name}}\nformat: {type: object, schema: {a: b}}\n"), [])
        self.assertEqual(data_rules("sum.yml", "system: Hi {{name}\n"), ["unbalanced-template"])

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

    def git_repo(self, files):
        root = make_repo(files)
        git = ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.com"]
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run([*git, "add", "."], check=True)
        subprocess.run([*git, "commit", "-qm", "init"], check=True)
        return root

    def test_index_flags_that_hide_edits_leave_dirty_undetermined(self):
        for flag in ("--skip-worktree", "--assume-unchanged"):
            root = self.git_repo({"prompts/a.md": "hi\n", "prompts/b.md": "hi\n"})
            self.assertIs(inventory.scan(root)["dirty"], False)
            subprocess.run(["git", "-C", str(root), "update-index", flag, "prompts/a.md"], check=True)
            (root / "prompts" / "a.md").write_text("edited, but git status does not say so\n", encoding="utf-8")
            self.assertIsNone(inventory.scan(root)["dirty"], flag)

    def test_no_filter_driver_from_the_repository_runs(self):
        root = self.git_repo({".gitattributes": "*.md filter=x\n*.txt filter=my\\ x\n*.prompt filter=a=b\n",
                              "prompts/a.md": "hi\n", "prompts/b.txt": "hi\n", "prompts/c.prompt": "hi\n"})
        marker = Path(tempfile.mkdtemp()) / "ran"
        # A driver name may contain a space, or an "=", which -c would take for the end of the key.
        for driver in ("x", "my x", "a=b"):
            for key in ("clean", "process"):
                subprocess.run(["git", "-C", str(root), "config", f"filter.{driver}.{key}",
                                f"sh -c 'touch {marker}; cat'"], check=True)
        # A newer mtime makes git status re-hash the file through the filter driver.
        for name in ("a.md", "b.txt", "c.prompt"):
            os.utime(root / "prompts" / name, (2_000_000_000, 2_000_000_000))
        dirty = inventory.scan(root)["dirty"]
        self.assertFalse(marker.exists(), "a filter command configured in the reviewed repository ran")
        self.assertIsNone(dirty)  # Git cannot tell without the command an "=" keeps -c from blanking.

    def test_a_required_transforming_filter_leaves_dirty_undetermined(self):
        # As git lfs install sets it up: HEAD holds what the clean command makes of the file (a pointer). Without
        # running that command, git cannot compare a stat-dirty file, so the answer is unknown, never "changed".
        root = make_repo({".gitattributes": "*.md filter=x\n", "prompts/a.md": "expanded\n"})
        marker = Path(tempfile.mkdtemp()) / "ran"
        git = ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.com"]
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run([*git, "config", "filter.x.clean", f"sh -c 'touch {marker}; sed s/expanded/pointer/'"], check=True)
        subprocess.run([*git, "config", "filter.x.required", "true"], check=True)
        # An mtime older than the index keeps the file out of git's racy-clean re-hash right after the commit.
        os.utime(root / "prompts" / "a.md", (1_000_000_000, 1_000_000_000))
        subprocess.run([*git, "add", "."], check=True)
        subprocess.run([*git, "commit", "-qm", "init"], check=True)
        marker.unlink()
        self.assertIs(inventory.scan(root)["dirty"], False)
        os.utime(root / "prompts" / "a.md", (2_000_000_000, 2_000_000_000))
        dirty = inventory.scan(root)["dirty"]
        self.assertFalse(marker.exists(), "a filter command configured in the reviewed repository ran")
        self.assertIsNone(dirty)  # Git cannot tell without the command an "=" keeps -c from blanking.

    def test_a_transforming_filter_leaves_an_unstaged_edit_undetermined(self):
        # nbstripout-style: not required, but HEAD holds the cleaned text, so a stat-dirty file may be no change.
        root = make_repo({".gitattributes": "*.md filter=x\n", "svc/prompts/a.md": "expanded\n",
                          "svc/prompts/b.txt": "plain\n"})
        git = ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.com"]
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run([*git, "config", "filter.x.clean", "sed s/expanded/pointer/"], check=True)
        for name in ("a.md", "b.txt"):
            os.utime(root / "svc" / "prompts" / name, (1_000_000_000, 1_000_000_000))
        subprocess.run([*git, "add", "."], check=True)
        subprocess.run([*git, "commit", "-qm", "init"], check=True)
        os.utime(root / "svc" / "prompts" / "a.md", (2_000_000_000, 2_000_000_000))
        for scanned in (root, root / "svc"):  # Status paths are relative to the top of the work tree.
            self.assertIsNone(inventory.git_state(scanned, ["prompts/a.md"])[1], scanned)
        # An edit to an unfiltered file, or a staged one, is a change whatever the filtered file holds.
        (root / "svc" / "prompts" / "b.txt").write_text("edited\n", encoding="utf-8")
        self.assertIs(inventory.git_state(root / "svc", ["prompts/a.md"])[1], True)
        subprocess.run([*git, "checkout", "-q", "--", "svc/prompts/b.txt"], check=True)
        (root / "svc" / "prompts" / "a.md").write_text("edited\n", encoding="utf-8")
        subprocess.run([*git, "-c", "filter.x.clean=cat", "add", "svc/prompts/a.md"], check=True)
        self.assertIs(inventory.git_state(root / "svc", ["prompts/a.md"])[1], True)

    def test_no_filter_driver_from_a_submodule_runs(self):
        sub = self.git_repo({".gitattributes": "*.md filter=x\n", "p.md": "hi\n"})
        top = self.git_repo({"a.md": "x\n"})
        git = ["git", "-C", str(top), "-c", "user.name=t", "-c", "user.email=t@example.com",
               "-c", "protocol.file.allow=always"]
        subprocess.run([*git, "submodule", "add", "-q", str(sub), "prompts"], check=True, capture_output=True)
        subprocess.run([*git, "commit", "-qm", "submodule"], check=True)
        marker = Path(tempfile.mkdtemp()) / "ran"
        subprocess.run(["git", "-C", str(top / "prompts"), "config", "filter.x.clean", f"sh -c 'touch {marker}; cat'"],
                       check=True)
        os.utime(top / "prompts" / "p.md", (2_000_000_000, 2_000_000_000))
        result = inventory.scan(top)
        self.assertFalse(marker.exists(), "a filter command configured in a submodule ran")
        # The submodule's files are not in the superproject's commit, so the scan read more than HEAD holds.
        self.assertIs(result["dirty"], True)

    def test_ignored_files_the_scan_read_make_it_dirty(self):
        root = self.git_repo({".gitignore": "prompts/local.md\n*.log\n", "prompts/a.md": "hi\n"})
        (root / "debug.log").write_text("ignored, never read\n", encoding="utf-8")
        self.assertIs(inventory.scan(root)["dirty"], False)
        (root / "prompts" / "local.md").write_text("TODO\n", encoding="utf-8")
        self.assertIs(inventory.scan(root)["dirty"], True)

    def test_non_utf8_file_name_is_reported_escaped(self):
        root = make_repo({"prompts/ok.md": "hi\n"})
        try:
            (root / os.fsdecode(b"prompts/\xff.md")).write_text("hi\n", encoding="utf-8")
        except (OSError, UnicodeError):
            self.skipTest("this file system refuses non-UTF-8 names")
        out = Path(tempfile.mkdtemp()) / "inventory.json"
        code, _, err = run(inventory.main, root, "--out", out)
        self.assertEqual(code, 0, err)
        paths = [f["path"] for f in json.loads(out.read_text(encoding="utf-8"))["prompt_files"]]
        self.assertEqual(paths, ["prompts/ok.md", "prompts/\\xff.md"])

    def test_skipped_directories_are_named(self):
        root = make_repo({".claude/skills/build/SKILL.md": "Build.\n", ".claude/skills/review/SKILL.md": "Review.\n",
                          "node_modules/x/prompts/a.md": "hi\n", "prompts/a.md": "hi\n"})
        result = inventory.scan(root)
        self.assertEqual([f["path"] for f in result["prompt_files"]], [".claude/skills/review/SKILL.md", "prompts/a.md"])
        self.assertEqual(result["skipped_dirs"], [".claude/skills/build", "node_modules"])
        self.assertIn(inventory.SKIPPED_NOTE, result["not_covered"])
        clean = inventory.scan(make_repo({"prompts/a.md": "hi\n"}))
        self.assertEqual((clean["skipped_dirs"], inventory.SKIPPED_NOTE in clean["not_covered"]), ([], False))
        self.assertEqual((clean["skipped_files"], inventory.UNREAD_NOTE in clean["not_covered"]), ([], False))

    def test_symlinked_directories_are_named(self):
        # The walk does not follow a directory symlink, so a symlinked prompts/ used to vanish without a trace.
        root = make_repo({"shared/sys.md": "You are a bot.\n", "app/prompts/a.md": "hi\n"})
        outside = Path(tempfile.mkdtemp())
        (outside / "b.md").write_text("hi\n", encoding="utf-8")
        (root / "prompts").symlink_to(root / "shared")
        (root / "app" / "prompts" / "linked").symlink_to(outside)
        (root / "prompts.md").symlink_to(root / "shared" / "sys.md")  # A file symlink stays in skipped_files.
        result = inventory.scan(root)
        self.assertEqual([f["path"] for f in result["prompt_files"]], ["app/prompts/a.md"])
        self.assertEqual(result["skipped_dirs"], ["app/prompts/linked", "prompts"])
        self.assertIn(inventory.SKIPPED_NOTE, result["not_covered"])
        self.assertEqual(result["skipped_files"], [])

    def test_prompt_files_that_are_not_read_are_named(self):
        # The largest prompts, the ones large-prompt exists for, used to vanish without a trace.
        root = make_repo({"prompts/big.md": "x" * (inventory.MAX_FILE_BYTES + 1), "notes.md": "hi\n"})
        (root / "prompts" / "bin.md").write_bytes(b"a\x00b")
        (root / "docs").mkdir()
        (root / "docs" / "image.bin").write_bytes(b"\x00")  # Not a prompt file: not listed.
        (root / "prompts" / "link.md").symlink_to(root / "notes.md")
        (root / "CLAUDE.md").symlink_to(root / "notes.md")
        result = inventory.scan(root)
        self.assertEqual(result["skipped_files"], [
            {"path": "CLAUDE.md", "reason": "symlink"}, {"path": "prompts/big.md", "reason": "over 1 MiB"},
            {"path": "prompts/bin.md", "reason": "binary"}, {"path": "prompts/link.md", "reason": "symlink"}])
        self.assertIn(inventory.UNREAD_NOTE, result["not_covered"])

    def test_fences_follow_commonmark(self):
        root = make_repo({
            # A backtick line with backticks after the opener is inline code, not a fence.
            "prompts/a.md": "```json``` blocks are the only accepted output.\n<instructions>\nTODO\n",
            "prompts/b.md": "```json``` is inline.\n```\n<example>\n```\n",
            # A fence nested in a list item is indented by the item, often four spaces or more.
            "prompts/c.md": "1. Step\n   - Output:\n\n     ```xml\n     <verdict>ok\n     ```\n",
        })
        hits = {(h["rule"], h["location"]) for h in inventory.scan(root)["lint"]}
        self.assertEqual(hits, {("unclosed-tag", "prompts/a.md:2"), ("placeholder", "prompts/a.md:3")})
        root = make_repo({
            # An indented ``` inside a fence is content: it closes nothing.
            "prompts/d.md": "```python\nEXAMPLE = '''\n    ```json\n    {}\n    ```\n'''\n```\n<rules>\n",
            # Outside a list item, a line indented four spaces is an indented code block, not a fence.
            "prompts/e.md": "Start like this:\n\n    ```json\n\n<rules>\n",
        })
        hits = {(h["rule"], h["location"]) for h in inventory.scan(root)["lint"]}
        self.assertEqual(hits, {("unclosed-tag", "prompts/d.md:8"), ("unclosed-tag", "prompts/e.md:5")})

    def test_out_refuses_a_symlink_and_reports_write_errors(self):
        root = make_repo({"prompts/a.md": "hi\n", "victim.txt": "keep\n"})
        out = Path(tempfile.mkdtemp())
        (out / "inventory.json").symlink_to(root / "victim.txt")
        code, _, err = run(inventory.main, root, "--out", out / "inventory.json")
        self.assertEqual(code, 2)
        self.assertIn("symlink", err)
        self.assertEqual((root / "victim.txt").read_text(encoding="utf-8"), "keep\n")
        (out / "dir.json").mkdir()
        code, _, err = run(inventory.main, root, "--out", out / "dir.json")
        self.assertEqual((code, err.startswith("inventory.py: ")), (2, True), err)

    def test_out_never_replaces_findings_json(self):
        out = Path(tempfile.mkdtemp())
        write_json(out / "findings.json", sample())
        before = (out / "findings.json").read_bytes()
        for args in (("--out", out / "findings.json", "--into", out / "findings.json"),
                     ("--out", out / "findings.json")):
            code, _, err = run(inventory.main, SAMPLE_APP, *args)
            self.assertEqual(code, 2, args)
            self.assertIn("not an inventory.json", err)
            self.assertEqual((out / "findings.json").read_bytes(), before)
        # A previous run's inventory.json is replaced as before.
        for _ in range(2):
            self.assertEqual(run(inventory.main, SAMPLE_APP, "--out", out / "inventory.json")[0], 0)

    def test_non_utf8_root_name_is_reported_escaped(self):
        parent = Path(tempfile.mkdtemp())
        try:
            root = parent / os.fsdecode(b"repo-\xff")
            (root / "prompts").mkdir(parents=True)
        except (OSError, UnicodeError):
            self.skipTest("this file system refuses non-UTF-8 names")
        (root / "prompts" / "a.md").write_text("hi\n", encoding="utf-8")
        out = parent / "inventory.json"
        code, _, err = run(inventory.main, root, "--out", out)
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["root"], "repo-\\xff")

    def test_git_sees_a_non_utf8_name_as_it_is_on_disk(self):
        root = self.git_repo({"prompts/ok.md": "hi\n"})
        (root / ".gitignore").write_bytes(b"prompts/\xff.md\n")
        try:
            (root / os.fsdecode(b"prompts/\xff.md")).write_text("TODO\n", encoding="utf-8")
        except (OSError, UnicodeError):
            self.skipTest("this file system refuses non-UTF-8 names")
        # .gitignore is untracked, so clear that signal: only the ignored read should count.
        (root / ".git" / "info" / "exclude").write_text(".gitignore\n", encoding="utf-8")
        self.assertIs(inventory.scan(root)["dirty"], True)

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
        self.assertEqual([f["previous_validation"]["verdict"] for f in lint], ["Valid", "Valid", "Valid"])

    def test_into_replaces_lint_findings_and_keeps_review(self):
        out = Path(tempfile.mkdtemp())
        data = sample()
        write_json(out / "findings.json", data)
        code, _, err = run(inventory.main, SAMPLE_APP, "--out", out / "inventory.json", "--into", out / "findings.json")
        self.assertEqual(code, 0, err)
        merged = json.loads((out / "findings.json").read_text(encoding="utf-8"))
        lint = [f for f in merged["findings"] if f["id"].startswith("L-")]
        self.assertEqual([f["id"] for f in lint], ["L-001", "L-002", "L-003"])
        self.assertTrue(all(f["validation"]["verdict"] == "Unverified" for f in lint))
        self.assertEqual(lint[0]["previous_validation"]["verdict"], "Valid")
        self.assertEqual(len([f for f in merged["findings"] if f["id"].startswith("F-")]), 8)
        self.assertIn("commit", merged["meta"])


if __name__ == "__main__":
    unittest.main()
