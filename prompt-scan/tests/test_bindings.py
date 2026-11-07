"""Where code loads a prompt file, what it fills it with, and the lint rules built on that trace."""
import unittest

from helpers import SAMPLE_APP, inventory
from test_inventory import make_repo


def scan(files):
    return inventory.scan(make_repo(files))


def lint(result):
    return [(h["rule"], h["location"], h["detail"]) for h in result["lint"]]


def renders(result, prompt):
    return [(b["traced"], [(s["location"], s["via"], s["keys"], s["complete"]) for s in b["renders"]])
            for b in result["bindings"] if b["prompt"] == prompt]


class TraceTest(unittest.TestCase):
    def test_sample_app(self):
        result = inventory.scan(SAMPLE_APP)
        files = {f["path"]: f["loaded_by"] for f in result["prompt_files"]}
        self.assertEqual(files, {"app/llm/prompts/answer.prompt": ["app/llm/answer.py:14"],
                                 "app/llm/prompts/support_system.md": ["app/llm/answer.py:13"]})
        self.assertEqual(renders(result, "app/llm/prompts/answer.prompt"),
                         [(True, [("app/llm/answer.py:14", "render", ["question"], True)])])
        self.assertEqual(renders(result, "app/llm/prompts/support_system.md"),
                         [(True, [("app/llm/answer.py:13", "format", ["ticket_body"], True)])])
        site = result["call_sites"][0]
        self.assertEqual(site["params"], {"model": "claude-haiku-5-5", "max_tokens": 200, "temperature": 1.0})
        self.assertEqual(site["args"], ["model", "max_tokens", "temperature", "system", "messages"])
        self.assertEqual(site["prompts"], ["app/llm/prompts/answer.prompt", "app/llm/prompts/support_system.md"])
        self.assertEqual(lint(result)[0], ("unfilled-variable", "app/llm/prompts/answer.prompt:4",
                                           "1 variable(s) not filled where app/llm/answer.py:14 renders it: context"))

    def test_module_constant_rendered_in_a_function(self):
        result = scan({
            "prompts/sys.md": "Hi {name}, about {topic}.\n",
            "app.py": 'from pathlib import Path\nSYSTEM = (Path(__file__).parent / "prompts" / "sys.md").read_text()\n\n'
                      'def go(client, n):\n    text = SYSTEM.format(name=n)\n'
                      '    return client.messages.create(model=MODEL, system=text, messages=[])\n'})
        self.assertEqual(renders(result, "prompts/sys.md"), [(True, [("app.py:5", "format", ["name"], True)])])
        # The unfilled name is reported once, by the rule that names the call; unreferenced-variable leaves it.
        self.assertEqual(lint(result), [("unfilled-variable", "prompts/sys.md:1",
                                         "1 variable(s) not filled where app.py:5 renders it: topic")])
        site = result["call_sites"][0]
        self.assertEqual((site["params"], site["prompts"]), ({}, ["prompts/sys.md"]))

    def test_open_or_untraced_renders_are_not_judged(self):
        cases = {
            "splat": 'S = open("prompts/sys.md").read()\ndef go(**kw):\n    return S.format(**kw)\n',
            "positional dict": 'S = open("prompts/sys.md").read()\nS.format_map(values)\n',
            "helper": 'def go():\n    return render_prompt(load("sys.md"), name=1)\n',
            "collection": 'PROMPTS = {"sys": open("prompts/sys.md").read()}\n',
            "returned": 'def load():\n    return open("prompts/sys.md").read()\n',
            "piped": 'p = ChatPromptTemplate.from_template(Path("prompts/sys.md").read_text())\nchain = p | llm\n',
            "other file": 'SYSTEM = open("prompts/sys.md").read()\n',
        }
        for name, code in cases.items():
            with self.subTest(name):
                result = scan({"prompts/sys.md": "Hi {name} {topic}\n", "app.py": code + "name = topic = 1\n"})
                self.assertEqual(lint(result), [])
                self.assertEqual(result["prompt_files"][0]["loaded_by"], ["app.py:" + str(
                    1 + code.split("sys.md")[0].count("\n"))])

    def test_jinja_template_object_rendered_across_lines(self):
        result = scan({
            "prompts/a.j2": "{% if docs %}{{ docs }}{% endif %} {{ question }} {{ user.name }} "
                            "{{ tone | default('plain') }} {{ missing }}\n",
            "app.py": 'env = Environment()\ntpl = env.get_template("a.j2")\n\ndef go(q, u):\n'
                      '    out = tpl.render(\n        question=q,\n        user=u,\n    )\n    return out\n'
                      'docs = tone = missing = None\n'})
        self.assertEqual(renders(result, "prompts/a.j2"), [(True, [("app.py:5", "render", ["question", "user"], True)])])
        # docs and tone are tested before use (if, default): optional by design.
        self.assertEqual(lint(result), [("unfilled-variable", "prompts/a.j2:1",
                                         "1 variable(s) not filled where app.py:5 renders it: missing")])

    def test_renamed_variable_is_one_finding(self):
        result = scan({
            "prompts/a.prompt": "Ticket: {{ ticket }}\n",
            "app.py": 'from jinja2 import Template\nT = Template(open("prompts/a.prompt").read())\n'
                      'x = T.render(ticket_body=1)\nticket = 0\n'})
        self.assertEqual(lint(result), [(
            "unfilled-variable", "prompts/a.prompt:1", "1 variable(s) not filled where app.py:3 renders it: ticket; "
            "that call passes ticket_body, which the template never uses")])

    def test_unused_render_key(self):
        result = scan({
            "prompts/a.prompt": "Ticket: {{ ticket }}\n```\n{{ fenced }}\n```\n",
            "app.py": 'T = Template(open("prompts/a.prompt").read())\n'
                      'x = T.render({"ticket": 1, "extra": 2, "fenced": 3})\n'
                      'y = T.render(dict(ticket=1, **more), stray=4)\n'})
        # A name used only inside a code fence is still filled by the engine, so passing it is not unused.
        self.assertEqual(lint(result), [
            ("unused-render-key", "app.py:2", "renders prompts/a.prompt with 1 key(s) the template never uses: extra"),
            ("unused-render-key", "app.py:3", "renders prompts/a.prompt with 1 key(s) the template never uses: stray")])

    def test_each_render_style_fills_its_own_syntax(self):
        cases = [
            # string.Template: $name and ${name}.
            ({"prompts/a.txt": "Hi $name and ${place}\n",
              "app.py": 't = Template(Path("prompts/a.txt").read_text())\ns = t.substitute(name="x")\n'},
             ["1 variable(s) not filled where app.py:2 renders it: place"]),
            # str.format: {{literal}} is an escaped brace, not a variable.
            ({"prompts/a.md": "Return {{\"answer\": ...}} for {question} and {{ context }}\n",
              "app.py": 'p = open("prompts/a.md").read().format(question=q)\n'}, []),
            # Jinja: single-brace text is literal, and unreferenced-variable is settled for it too.
            ({"prompts/a.prompt": 'Return {"answer": ...} and {{ q }}. Use {example} literally.\n',
              "app.py": 'x = Template(open("prompts/a.prompt").read()).render(q=1)\n'}, []),
            # LangChain invoke with a dict literal.
            ({"prompts/a.txt": "Q: {question} C: {context}\n",
              "app.py": 'p = PromptTemplate.from_template(Path("prompts/a.txt").read_text())\n'
                        'r = p.invoke({"question": q})\n'},
             ["1 variable(s) not filled where app.py:2 renders it: context"]),
        ]
        for files, details in cases:
            with self.subTest(files["app.py"]):
                self.assertEqual([d for _, _, d in lint(scan(files))], details)

    def test_javascript_replace_and_unrendered_send(self):
        result = scan({
            "prompts/a.md": "Hello {{name}} on {{site}}\n",
            "prompts/b.md": "Hello {{name}}\n",
            "src/a.ts": 'import fs from "fs";\n'
                        'const tpl = fs.readFileSync(path.join(__dirname, "prompts/a.md"), "utf8");\n'
                        'export function build(name: string) {\n'
                        '  const prompt = tpl.replace("{{name}}", name).replace(/\\{\\{date\\}\\}/g, today);\n'
                        '  return generateText({ model: openai("gpt-4o"), prompt, maxTokens: 300, temperature: 0 });\n'
                        '}\n'
                        'const system = await readFile("prompts/b.md", "utf8");\n'
                        'const r = await client.messages.create({ model: "claude-x", system, max_tokens: 100, messages });\n'})
        # A regex replace may fill any name, so the a.md site is open and only unreferenced-variable, which
        # needs no call, reports site; b.md is sent with its placeholder.
        self.assertEqual(renders(result, "prompts/a.md"), [(True, [("src/a.ts:4", "replace", ["name"], False)])])
        self.assertEqual(lint(result), [
            ("unfilled-variable", "prompts/b.md:1", "1 variable(s) not filled where src/a.ts:8 sends it without rendering: name"),
            ("unreferenced-variable", "prompts/a.md:1", "1 variable(s) no code file names: site")])
        calls = {c["line"]: c for c in result["call_sites"]}
        self.assertEqual((calls[5]["params"], calls[5]["prompts"]),
                         ({"maxTokens": 300, "temperature": 0}, ["prompts/a.md"]))
        self.assertEqual((calls[8]["params"], calls[8]["prompts"]),
                         ({"model": "claude-x", "max_tokens": 100}, ["prompts/b.md"]))

    def test_paths_that_name_several_files_or_none(self):
        result = scan({
            "prompts/en/sys.md": "Hi {name}\n", "prompts/ja/sys.md": "Hi {name}\n",
            "app.py": '"""Loads sys.md and fills it."""\n# open("prompts/en/sys.md")\n'
                      'S = open(f"prompts/{lang}/sys.md").read()\nS.format()\nname = 1\n'})
        self.assertEqual({b["prompt"]: (b["loaded_at"], b.get("ambiguous")) for b in result["bindings"]},
                         {"prompts/en/sys.md": ("app.py:3", True), "prompts/ja/sys.md": ("app.py:3", True)})
        self.assertEqual(lint(result), [])

    def test_includes_and_reassignment(self):
        result = scan({
            "prompts/a.j2": "{% include 'b.j2' %}{{ q }}\n",
            "prompts/b.md": "{a}\n",
            "app.py": 'x = env.get_template("a.j2").render()\n'
                      'p = open("prompts/b.md").read()\nq = p.format(a=1)\np = "other"\np.format(b=2)\n'})
        self.assertEqual(renders(result, "prompts/b.md"), [(True, [("app.py:3", "format", ["a"], True)])])
        self.assertEqual(lint(result), [])

    def test_rescan_keeps_review_per_template_at_one_call(self):
        hits = [dict(rule="unused-render-key", location="app.py:2", detail=f"renders {t} with 1 key(s) the "
                     "template never uses: x", kind="defect", severity="Medium", confidence="Suspected",
                     category="Variables and assembly") for t in ("prompts/a.md", "prompts/b.md")]
        keys = {inventory.hit_key(f["rule"], f["location"], f["cause"]) for f in inventory.lint_findings(hits)}
        self.assertEqual(len(keys), 2)

    def test_masking_ignores_comments_and_strings(self):
        src = inventory.binding_tool.Source('a = "x(" # )\nb = (1, \'\'\'\n)\'\'\')\n', ".py")
        self.assertEqual(src.masked, 'a = "  "    \nb = (1, \'\'\'\n \'\'\')\n')
        self.assertEqual(len(src.match), 1)
        self.assertEqual(src.line(src.masked.index("b")), 2)


if __name__ == "__main__":
    unittest.main()
