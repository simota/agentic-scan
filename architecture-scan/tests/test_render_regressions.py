"""Regression checks for information retained in generated report tables."""
import re
from html.parser import HTMLParser
import unittest

from test_architecture_scan import complete_doc, render


def table_rows(markdown, heading):
    section = markdown.split(f"## {heading}\n", 1)[1].split("\n## ", 1)[0]
    rows = []
    for line in section.splitlines():
        if not line.startswith("|"):
            continue
        cells, start = [], 1
        for index in range(1, len(line)):
            if line[index] != "|":
                continue
            preceding = len(line[:index]) - len(line[:index].rstrip("\\"))
            if preceding % 2 == 0:
                cells.append(line[start:index].strip())
                start = index + 1
        rows.append(cells)
    return rows[2:]  # Header and separator are not data rows.


class CellText(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.text = ""
        self.codes = []
        self.in_code = False
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        if tag == "br":
            self.text += "\n"
        elif tag == "code":
            self.in_code = True
            self.codes.append("")

    def handle_endtag(self, tag):
        if tag == "code":
            self.in_code = False

    def handle_data(self, value):
        self.text += value
        if self.in_code:
            self.codes[-1] += value


def plain_cell(source):
    # Accept either GFM backslash escapes or HTML character references.
    return CellText(re.sub(r"\\([\\|])", r"\1", source)).text


class RenderRegressionTests(unittest.TestCase):
    def test_markdown_tables_keep_columns_and_cell_text(self):
        doc = complete_doc()
        doc["meta"].update(project="demo | package", scope="api/ | worker/\r\nmore\rfinal",
                           commit="abc|123", assessor="owner | reviewer")
        doc["rules"][0].update(statement="Created | Deleted\r\nthen Reviewed",
                                source=r"docs\adr\|boundary.md:12")
        doc["perspectives"][0]["note"] = "api/ | worker/\r\ncoverage\rremaining"
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                markdown = render.render_markdown(doc, lang)
                labels = render.LABELS[lang]
                scope = table_rows(markdown, labels["scope"])
                self.assertEqual([len(row) for row in scope], [2] * 4)
                self.assertEqual([plain_cell(row[1]) for row in scope], [
                    "demo | package", "api/ | worker/\nmore\nfinal", "abc|123",
                    "2026-10-09 / owner | reviewer",
                ])
                rules = table_rows(markdown, labels["rules"])
                self.assertEqual(len(rules), 1)
                self.assertEqual(len(rules[0]), 4)
                self.assertEqual([plain_cell(cell) for cell in rules[0]], [
                    "R-01", "Created | Deleted\nthen Reviewed",
                    r"docs\adr\|boundary.md:12", "violated",
                ])
                perspectives = table_rows(markdown, labels["perspectives"])
                self.assertTrue(all(len(row) == 3 for row in perspectives))
                self.assertEqual(plain_cell(perspectives[0][2]),
                                 "api/ | worker/\ncoverage\nremaining")

    def test_markdown_code_spans_keep_literal_content(self):
        doc = complete_doc()
        doc["rules"][0]["statement"] = (
            r"Use ``a`b\|c`` and `C:\src\pkg` and "
            + "`first\r\nsecond` and ` *a*_[link](url)~ ` and `a  b`"
        )
        markdown = render.render_markdown(doc, "en")
        row = table_rows(markdown, render.LABELS["en"]["rules"])[0]
        self.assertEqual(len(row), 4)
        self.assertEqual(CellText(row[1]).codes,
                         [r"a`b\|c", r"C:\src\pkg", "first second", "*a*_[link](url)~", "a  b"])
        self.assertIn("&#32;&#32;", row[1])  # Raw HTML spaces collapse during GFM parsing.
        self.assertEqual(row[3], "violated")

    def test_not_checked_reason_is_visible_in_both_formats_and_languages(self):
        doc = complete_doc()
        reason = "Deployment <manifest> | access denied"
        doc["rules"][0].update(status="not checked", reason=reason)
        for lang, label in (("en", "Reason"), ("ja", "理由")):
            with self.subTest(lang=lang):
                markdown = render.render_markdown(doc, lang)
                row = table_rows(markdown, render.LABELS[lang]["rules"])[0]
                self.assertEqual(len(row), 4)
                self.assertEqual(plain_cell(row[3]), f"not checked\n{label}: {reason}")
                html = render.render_html(doc, lang)
                html_row = re.search(r"<tr><td class='nowrap'[^>]*>R-01</td>.*?</tr>", html).group(0)
                self.assertIn(f"not checked\n{label}: {reason}", CellText(html_row).text)
                self.assertNotIn("<manifest>", html_row)

    def test_escaped_backticks_stay_literal(self):
        doc = complete_doc()
        doc["rules"][0]["statement"] = r"Use \`literal\` and `a|b`"
        markdown = render.render_markdown(doc, "en")
        row = table_rows(markdown, render.LABELS["en"]["rules"])[0]
        self.assertEqual(len(row), 4)
        parsed = CellText(row[1])
        self.assertEqual(parsed.text, "Use `literal` and a|b")
        self.assertEqual(parsed.codes, ["a|b"])

    def test_rule_without_reason_keeps_its_status(self):
        doc = complete_doc()
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                markdown = render.render_markdown(doc, lang)
                row = table_rows(markdown, render.LABELS[lang]["rules"])[0]
                self.assertEqual(row[3], "violated")
                html = render.render_html(doc, lang)
                self.assertRegex(html, r"<td[^>]*>violated</td></tr>")


if __name__ == "__main__":
    unittest.main()


class CellLabels(HTMLParser):
    """Each table's column headers and the data-label of each of its body cells."""

    def __init__(self, source):
        super().__init__()
        self.tables, self.in_th = {}, False
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "table":
            self.current = self.tables.setdefault(attrs.get("class"), {"heads": [], "rows": []})
        elif tag == "th":
            self.in_th = True
            self.current["heads"].append("")
        elif tag == "tr" and self.current["heads"]:
            self.current["rows"].append([])
        elif tag == "td":
            self.current["rows"][-1].append(attrs.get("data-label"))

    def handle_endtag(self, tag):
        if tag == "th":
            self.in_th = False

    def handle_data(self, data):
        if self.in_th:
            self.current["heads"][-1] += data


class LedgerTableLayoutTests(unittest.TestCase):
    """The rules and coverage tables stack on narrow screens, as the register does.

    A path in a rule's source is one unbreakable word, so as a table the ledger
    pushed its status column out of a phone-width view.
    """

    def test_every_ledger_cell_is_labelled_with_its_column(self):
        doc = complete_doc()
        doc["rules"][0].update(family="OWN", status="not checked", reason="out of scope")
        doc["perspectives"] = [{"name": "Coupling", "status": "applied", "note": "CP1-CP4"}]
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                tables = CellLabels(render.render_html(doc, lang)).tables
                for name in ("rules", "coverage-table"):
                    table = tables[name]
                    self.assertTrue(table["rows"])
                    for row in table["rows"]:
                        self.assertEqual(row, table["heads"])

    def test_ledger_tables_stack_where_the_register_does_and_break_long_paths(self):
        css = render.CSS
        breakpoint = re.search(r"@media\(max-width:(\d+)px\)\{\.reg-head\{display:none\}", css)[1]
        block = re.search(r"@media\(max-width:" + breakpoint + r"px\)\{(table\.rules,.*?\})\}", css)[1]
        declared = {}
        for selectors, body in re.findall(r"([^{}]+)\{([^{}]*)\}", block):
            for selector in selectors.split(","):
                declared.setdefault(selector, "")
                declared[selector] += body + ";"
        for table in ("table.rules", "table.coverage-table"):
            with self.subTest(table=table):
                self.assertIn("display:grid", declared[f"{table}>tbody>tr"])
                self.assertIn("clip-path:inset(50%)", declared[f"{table}>thead"])
                self.assertIn("content:attr(data-label)", declared[f"{table}>tbody>tr>td:before"])
        # Half a phone's width cannot hold `R-04 · CONTRACT` on one line; it wraps at the blank.
        self.assertIn("white-space:normal", declared["table.rules>tbody>tr>td.nowrap"])
        self.assertRegex(css, r"table\.rules td,table\.coverage-table td\{overflow-wrap:anywhere\}")
