"""missing-file-reference: agent and skill prompts that point the model at files that are not there."""
import unittest

from helpers import REPO, inventory
from test_inventory import make_repo


def hits(files):
    return [(h["location"], h["detail"]) for h in inventory.scan(make_repo(files))["lint"]
            if h["rule"] == "missing-file-reference"]


class ReferenceTest(unittest.TestCase):
    def test_stale_references(self):
        found = hits({
            "skills/x/SKILL.md": "Read `reference/recon.md` then `reference/gone.md`.\n"
                                 "Run `scripts/run.py <repo>` and write `out/new.md`.\n"
                                 "See [guide](docs/guide.md), [ok](reference/recon.md#top), [web](https://e.com/a.md).\n"
                                 "```\n`reference/fenced-gone.md`\n```\n"
                                 "Not paths: `.claude/agents/*.md`, `github.com/a/b.md`, `../../../../etc/x.md`.\n",
            "skills/x/reference/recon.md": "x\n", "skills/x/scripts/run.py": "x = 1\n",
            "CLAUDE.md": "See @docs/style.md and @README.md, mail a@b.com, ping @alice.\n"
                         "Also `skills/x/reference/recon.md` and `skills/x/reference/old.md`.\n",
            "README.md": "hi\n",
            # A template is not an instruction to read files.
            "prompts/a.md": "See [x](missing.md)\n",
        })
        self.assertEqual(found, [
            ("CLAUDE.md:1", "2 reference(s) to files that do not exist: docs/style.md, skills/x/reference/old.md"),
            ("skills/x/SKILL.md:1", "2 reference(s) to files that do not exist: reference/gone.md, docs/guide.md")])

    def test_this_skill_cites_only_files_it_has(self):
        self.assertEqual([h for h in inventory.scan(REPO)["lint"] if h["rule"] == "missing-file-reference"], [])


if __name__ == "__main__":
    unittest.main()
