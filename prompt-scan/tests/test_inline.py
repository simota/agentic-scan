"""Inline prompts: string literals in code assigned to, or passed as, a prompt-named name."""
import unittest

from helpers import inventory
from test_inventory import make_repo

PY = '''import textwrap
SYSTEM_PROMPT = textwrap.dedent("""
    You are a support bot.
    <rules>
    TODO: add refund rules
    Return {{"answer": "..."}} for {question}.
""")
PROMPT_PATH = "prompts/system.md"
def go(client, q, system=None):
    # the system call
    user_prompt = (f"Answer {q} briefly. "
                   "Use the docs.")
    return client.messages.create(model="m", system="You are terse and exact, never chatty.", messages=[
        {"role": "system", "content": "Always cite <source> tags."},
        {"role": "user", "content": "Not a system prompt at all, just user text."}])
x = "a b c d e f g h i j k l m n o p"
'''
TS = 'export const systemPrompt = `You are a reviewer.\nTBD: scope\n<instructions>\nBe kind.`;\nconst instructions = "short";\n'


class InlineTest(unittest.TestCase):
    def test_found_and_linted_at_their_code_lines(self):
        result = inventory.scan(make_repo({"app.py": PY, "src/a.ts": TS}))
        self.assertEqual([(e["path"], e["line"], e["name"], e["lines"], e["variables"]) for e in result["inline_prompts"]], [
            ("app.py", 2, "SYSTEM_PROMPT", 6, ["question"]),
            ("app.py", 11, "user_prompt", 2, ["q"]),
            ("app.py", 13, "system", 1, []),
            ("app.py", 14, "system", 1, []),
            ("src/a.ts", 1, "systemPrompt", 4, []),
        ])
        # An f-string's {{ is a literal brace: no unbalanced-template; <source> is HTML.
        self.assertEqual([(h["rule"], h["location"]) for h in result["lint"]], [
            ("unclosed-tag", "app.py:4"), ("placeholder", "app.py:5"),
            ("placeholder", "src/a.ts:2"), ("unclosed-tag", "src/a.ts:3")])

    def test_call_sites_name_the_inline_prompts_they_send(self):
        code = PY + "def h(c):\n    return c.messages.create(model='m', system=SYSTEM_PROMPT, messages=[])\n"
        calls = {c["line"]: c.get("inline_prompts") for c in inventory.scan(make_repo({"app.py": code}))["call_sites"]
                 if c["api"] == "anthropic.messages"}
        # Written in the call, or passed by name; the keyword system= is not a use of a prompt named system.
        self.assertEqual(calls, {13: ["app.py:13", "app.py:14"], 18: ["app.py:2"]})

    def test_candidates_need_a_quote_after_a_prompt_name(self):
        text = 'def f(system=None):\n    # the system\n    s = "value with spaces"\n'
        self.assertEqual(inventory.binding_tool.inline_candidates(text), set())
        # Offsets stay aligned when lower-casing would lengthen the text.
        text = 'x = "İ"\nPROMPT = "Answer in one short line."\n'
        start = text.index('"Answer')
        self.assertEqual(inventory.binding_tool.inline_candidates(text), {start})


if __name__ == "__main__":
    unittest.main()
