"""The before/after architecture diagrams every report carries."""
import copy
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from test_architecture_scan import SKILL, architecture, complete_doc, finding, findings, render


def diagram(nodes, edges):
    return {"nodes": [{"id": n, "label": n} for n in nodes],
            "edges": [{"from": a, "to": b} for a, b in edges]}


class SchemaTests(unittest.TestCase):
    def refused(self, change, message):
        doc = complete_doc()
        change(doc["architecture"]["before"])
        with self.assertRaisesRegex(findings.SchemaError, message):
            findings.validate(doc, complete=True)

    def test_the_fixture_is_valid(self):
        findings.validate(complete_doc(), complete=True)

    def test_malformed_diagrams_are_refused(self):
        cases = [
            (lambda d: d.update(nodes=[]), r"before\.nodes: at least one node"),
            (lambda d: d["nodes"][0].update(colour="red"), r"nodes\[0\]: unknown keys"),
            (lambda d: d["nodes"][1].update(id="refunds"), "duplicate refunds"),
            (lambda d: d["nodes"][0].update(id="1st"), "must look like"),
            (lambda d: d["nodes"][0].update(id="A-001"), "looks like a finding ID"),
            (lambda d: d["nodes"][0].update(label=" ​"), "label: must be a nonblank"),
            (lambda d: d["nodes"][0].update(kind="queue"), "kind: 'queue' is not one of"),
            (lambda d: d["edges"][0].update(to="ghost"), r"edges\[0\]\.to: 'ghost' is not a node id"),
            (lambda d: d["edges"][0].update(to="refunds"), "joins two different nodes"),
            (lambda d: d["edges"][0].update(to=["invoices"]), r"edges\[0\]\.to: \['invoices'\] is not"),
            (lambda d: d["edges"].append({"from": "refunds", "to": "invoices"}), "duplicate edge"),
            (lambda d: d["edges"][0].update(finding="R-01"), "finding IDs such as"),
            (lambda d: d["edges"][0].update(finding=""), "finding IDs such as"),
            (lambda d: d.update(nodes=[{"id": f"n{i}", "label": "x"} for i in range(61)], edges=[]),
             "more than 60"),
        ]
        for change, message in cases:
            with self.subTest(message=message):
                self.refused(change, message)

    def test_an_unknown_diagram_name_is_refused(self):
        doc = complete_doc()
        doc["architecture"]["target"] = doc["architecture"]["after"]
        with self.assertRaisesRegex(findings.SchemaError, r"architecture: unknown keys \['target'\]"):
            findings.validate(doc)


class MergeAndCheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def check(self, doc):
        (self.tmp / "findings.json").write_text(json.dumps(doc), encoding="utf-8")
        for name, data in render.rendered_outputs(doc, doc["meta"]["lang"]).items():
            (self.tmp / name).write_bytes(data)
        return findings.contract_problems(self.tmp)

    def test_check_requires_both_diagrams(self):
        self.assertEqual(self.check(complete_doc()), [])
        for missing in ("before", "after"):
            with self.subTest(missing=missing):
                doc = complete_doc()
                del doc["architecture"][missing]
                self.assertEqual([p for p in self.check(doc) if p.startswith("architecture")],
                                 [f"architecture.{missing}: draw the {missing} diagram (module graph "
                                  + ("at the assessed revision)" if missing == "before" else
                                     "with the recorded fix directions applied)")])

    def test_a_fragment_replaces_one_diagram_whole_and_null_removes_it(self):
        doc = complete_doc()
        replacement = diagram(["a", "b"], [("a", "b")])
        findings.merge(doc, {"architecture": {"after": replacement}}, "f")
        self.assertEqual(doc["architecture"]["after"], replacement)
        self.assertEqual(doc["architecture"]["before"], architecture()["before"])
        findings.merge(doc, {"architecture": {"after": None, "before": None}}, "f")
        self.assertNotIn("architecture", doc)

    def test_an_edge_citing_an_unrecorded_finding_fails_check(self):
        doc = complete_doc()
        doc["architecture"]["before"]["edges"][0]["finding"] = "A-001, A-009"
        self.assertIn("architecture.before.edges[0].finding: mentions A-009, which no finding "
                      "holds; name a recorded finding (after renumber, only the new IDs)",
                      self.check(doc))

    def test_renumber_rewrites_edge_findings_but_never_node_ids(self):
        doc = complete_doc()
        doc["findings"] = [finding("A-201", "Low"), finding("A-101", rule="R-01")]
        doc["architecture"] = architecture("A-101, A-201")
        renamed, mapping = findings.renumber(doc)
        self.assertEqual(mapping, {"A-101": "A-001", "A-201": "A-002"})
        edge = renamed["architecture"]["before"]["edges"][0]
        self.assertEqual((edge["from"], edge["to"], edge["finding"]),
                         ("refunds", "invoices", "A-001, A-002"))

    def test_the_cli_merges_a_diagram_fragment(self):
        target, fragment = self.tmp / "findings.json", self.tmp / "frag.json"
        doc = complete_doc()
        del doc["architecture"]
        target.write_text(json.dumps(doc), encoding="utf-8")
        fragment.write_text(json.dumps({"architecture": architecture()}), encoding="utf-8")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(findings.main(["merge", str(target), str(fragment)]), 0)
        self.assertEqual(findings.read_json(target)["architecture"], architecture())


HOSTILE_LABEL = 'a"] --> evil["x`;<script>alert(1)</script> #35; | ```'


class MarkdownTests(unittest.TestCase):
    def section(self, doc, lang="en"):
        markdown = render.render_markdown(doc, lang)
        start = markdown.index(f"## {render.LABELS[lang]['architecture']}")
        return markdown[start:markdown.index("\n## ", start + 1)]

    def test_both_diagrams_are_mermaid_with_changes_in_words(self):
        section = self.section(complete_doc())
        self.assertEqual(section.count("```mermaid\nflowchart LR\n"), 2)
        self.assertIn('n1 -->|"writes · A-001"| n3', section)
        self.assertIn("linkStyle 0 stroke:#c0392b,stroke-width:2.5px,stroke-dasharray:6 4", section)
        self.assertIn("- Removed edge: worker/refunds → invoices (writes · A-001)", section)
        self.assertIn("- Added edge: worker/refunds → api/billing (adjust())", section)
        self.assertIn('n3[("invoices")]', section)

    def test_a_label_cannot_leave_its_quotes_or_the_fence(self):
        doc = complete_doc()
        doc["architecture"]["before"]["nodes"][0]["label"] = HOSTILE_LABEL
        doc["architecture"]["before"]["edges"][1]["label"] = HOSTILE_LABEL
        section = self.section(doc)
        blocks = re.findall(r"```mermaid\n(.*?)\n```", section, re.S)
        self.assertEqual(len(blocks), 2)
        escaped = ("a#34;] --#62; evil[#34;x#96;#59;#60;script#62;alert(1)#60;/script#62; "
                   "#35;35#59; #124; #96;#96;#96;")
        self.assertIn(f'  n1["{escaped}"]', blocks[0].splitlines())
        self.assertIn(f'  n2 -->|"{escaped}"| n3', blocks[0].splitlines())
        # Every quote left is one that opens or closes a generated label.
        labels = sum(line.startswith("  n") for line in blocks[0].splitlines())
        self.assertEqual(blocks[0].count('"'), 2 * labels)

    def test_after_equal_to_before_says_nothing_changes(self):
        doc = complete_doc()
        doc["architecture"]["after"] = copy.deepcopy(doc["architecture"]["before"])
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                self.assertIn(render.LABELS[lang]["no_changes"], self.section(doc, lang))

    def test_a_missing_diagram_renders_as_not_recorded(self):
        doc = complete_doc()
        del doc["architecture"]
        section = self.section(doc)
        self.assertEqual(section.count(render.LABELS["en"]["not_drawn"]), 2)
        self.assertNotIn("```mermaid", section)


class DashboardTests(unittest.TestCase):
    def section(self, doc, lang="en"):
        html = render.render_html(doc, lang)
        start = html.index("<section class='panel arch' id='architecture'")
        return html[start:html.index("</section>", start)]

    def test_two_svgs_without_style_attributes_and_a_nav_entry(self):
        html = render.render_html(complete_doc(), "en")
        section = self.section(complete_doc())
        self.assertEqual(section.count("<svg class='arch-svg'"), 2)
        # The CSP allows only the hashed stylesheet: an inline style attribute would be dropped.
        self.assertNotRegex(section, r"\sstyle=")
        self.assertIn("marker-end='url(#before-arrow-violation)'", section)
        self.assertIn("<g class='edge violation removed'>", section)
        self.assertIn("<g class='edge added'>", section)
        self.assertIn('<a href="#architecture">Architecture</a>', html)
        # A diagram wider than the screen scrolls in a frame a keyboard can reach.
        self.assertEqual(section.count("<div class='arch-scroll' tabindex='0' role='region' "), 2)
        # Arrowheads keep one size on a thin and a bold edge.
        self.assertEqual(section.count("markerUnits='userSpaceOnUse'"), 6)

    def test_recorded_text_is_escaped_and_listed_in_full(self):
        doc = complete_doc()
        doc["architecture"]["before"]["nodes"][0]["label"] = HOSTILE_LABEL + " " + "x" * 40
        section = self.section(doc)
        self.assertNotIn("<script>", section)
        self.assertIn(render.html_text(HOSTILE_LABEL + " " + "x" * 40), section)  # the text list
        self.assertIn("…</text>", section)  # the drawing cuts it

    def test_a_cut_edge_label_keeps_its_finding_ids(self):
        edge = {"from": "a", "to": "b", "label": "a very long label naming many calls",
                "finding": "A-001, A-002"}
        lines = render.fit_caption(edge)
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].endswith(" · A-001, A-002"))
        self.assertLessEqual(render.text_units(lines[0]), render.LABEL_UNITS)

    def test_many_finding_ids_wrap_onto_lines_and_none_is_cut(self):
        ids = ", ".join(f"A-{i:03d}" for i in range(1, 8))
        for edge in ({"from": "a", "to": "b", "finding": ids},
                     {"from": "a", "to": "b", "label": "writes", "finding": ids}):
            with self.subTest(label="label" in edge):
                lines = render.fit_caption(edge)
                self.assertNotIn("…", "".join(lines))
                self.assertEqual(re.findall(r"A-[0-9]{3}", " ".join(lines)),
                                 [f"A-{i:03d}" for i in range(1, 8)])
                self.assertTrue(all(render.text_units(line) <= render.LABEL_UNITS for line in lines))
                self.assertEqual(lines[0] == "writes", "label" in edge)
        doc = complete_doc()
        doc["findings"] = [finding(f"A-{i:03d}", "Low") for i in range(1, 5)]
        doc["architecture"]["before"]["edges"][0]["finding"] = "A-001, A-002, A-003, A-004"
        svg = render.render_html(doc, "en")
        self.assertIn("<tspan x='", svg)
        self.assertIn(">A-004</tspan>", svg)

    def test_a_module_keeps_its_place_in_both_diagrams(self):
        section = self.section(complete_doc())
        before, after = section.split("<svg class='arch-svg'")[1:]
        for label in ("worker/refunds", "api/billing", "invoices"):
            place = re.compile(rf"<title>{re.escape(label)}</title><rect x='([0-9.]+)' y='([0-9.]+)'")
            self.assertEqual(place.search(before).groups(), place.search(after).groups())

    def test_a_long_edge_never_runs_under_a_node_it_does_not_touch(self):
        # a -> b -> c -> d puts d three columns right of a; a -> d crosses b's and c's columns.
        arch = {"before": diagram("abcd", [("a", "b"), ("b", "c"), ("c", "d"), ("a", "d")])}
        arch["after"] = copy.deepcopy(arch["before"])
        positions, routes, _, _ = render.arch_layout(arch)
        kind, points, reverse, _ = routes[("a", "d")]
        self.assertEqual((kind, reverse, len(points)), ("chain", False, 6))
        for node in "bc":
            x, y = positions[node]
            for px, py in points:
                inside = x <= px <= x + render.NODE_W and y <= py <= y + render.NODE_H
                self.assertFalse(inside, (node, px, py))

    def test_a_cycle_is_drawn_with_the_back_edge_reversed(self):
        arch = {"before": diagram("ab", [("a", "b"), ("b", "a")])}
        arch["after"] = diagram("ab", [("a", "b")])
        _, routes, _, _ = render.arch_layout(arch)
        self.assertFalse(routes[("a", "b")][2])
        self.assertTrue(routes[("b", "a")][2])
        # The two directions run apart rather than on one line.
        self.assertNotEqual(routes[("a", "b")][1][0][1], routes[("b", "a")][1][0][1])
        svg = render.svg_diagram(arch["before"], "before", render.diagram_changes(arch),
                                 render.arch_layout(arch), "t")
        self.assertIn("marker-start='url(#before-arrow-plain)'", svg)

    def test_a_label_moves_off_a_node_box(self):
        # The middle of the edge lies on a node box; another spot on the edge is clear.
        segment = ((0, 50), (50, 50), (150, 50), (200, 50))
        taken = [(70, 30, 60, 30, 10)]
        x, y = render.label_spot([segment], 40, taken)
        self.assertFalse(70 < x + 20 and x - 20 < 130 and 30 < y and y - render.LABEL_H < 60)

    def test_layout_does_not_depend_on_hash_order(self):
        # check compares bytes with a fresh render, which runs in another process.
        script = ("import json, sys; sys.path.insert(0, sys.argv[1]); sys.dont_write_bytecode = True\n"
                  "import render\n"
                  "nodes = [{'id': f'm{i}', 'label': f'm{i}'} for i in range(12)]\n"
                  "edges = [{'from': f'm{i}', 'to': f'm{(i * 5 + 3) % 12}'} for i in range(12)]\n"
                  "d = {'nodes': nodes, 'edges': edges}\n"
                  "print(repr(render.arch_layout({'before': d, 'after': d})))\n")
        layouts = {subprocess.run([sys.executable, "-c", script, str(SKILL / "scripts")],
                                  env={**os.environ, "PYTHONHASHSEED": seed}, capture_output=True,
                                  text=True, check=True, timeout=60).stdout
                   for seed in ("1", "2", "3")}
        self.assertEqual(len(layouts), 1)


if __name__ == "__main__":
    unittest.main()
