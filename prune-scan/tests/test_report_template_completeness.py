"""Template contents cannot supply the generated document's closing envelope."""

import hashlib
import unittest

from test_report_regressions import ReportFixture
import contract_check


class ReportTemplateCompletenessTests(ReportFixture):
    def setUp(self):
        super().setUp()
        stamps = "".join(
            f'<meta name="{stamp}" content="sha256:{hashlib.sha256((self.out / name).read_bytes()).hexdigest()}">'
            for stamp, name in ((contract_check.STAMP, "findings.json"),
                                (contract_check.UNITS_STAMP, "units.json"))
        )
        self.opening = f'<html lang="en"><head>{stamps}</head><body>'
        self.closing = "</body></html>"
        self.page = self.opening + "Report" + self.closing
        for name in ("dashboard.html", "report.html"):
            (self.out / name).write_text(self.page, encoding="utf-8")
        self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])

    def assert_rejected(self, page):
        for name in ("dashboard.html", "report.html"):
            with self.subTest(artifact=name):
                path = self.out / name
                path.write_text(page, encoding="utf-8")
                try:
                    errors = list(contract_check.problems(self.out, no_pdf=True))
                    self.assertTrue(any(error.startswith(f"{name}: invalid or incomplete HTML")
                                        for error in errors), errors)
                finally:
                    path.write_text(self.page, encoding="utf-8")

    def assert_accepted(self, page):
        for name in ("dashboard.html", "report.html"):
            (self.out / name).write_text(page, encoding="utf-8")
        self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])

    def test_unclosed_body_templates_cannot_supply_document_closing_tags(self):
        for content in ("<template>unfinished", "<TEMPLATE>unfinished",
                        "<template><template>unfinished</template>",
                        "<template><div>unfinished</div>"):
            with self.subTest(content=content):
                self.assert_rejected(self.opening + content + self.closing)

    def test_closing_templates_after_inert_end_tags_does_not_finish_the_document(self):
        for depth in (1, 2):
            with self.subTest(depth=depth):
                self.assert_rejected(self.opening + "<template>" * depth + "Report"
                                     + self.closing + "</template>" * depth)

    def test_closed_nested_templates_preserve_real_document_boundaries(self):
        content = '<template><section><template><p>Nested</p></template></section></template>'
        for position in ("<head>", "<body>"):
            with self.subTest(position=position):
                self.assert_accepted(self.page.replace(position, position + content, 1))

    def test_template_text_in_raw_text_elements_and_comments_is_not_markup(self):
        for content in ('<!-- <template> -->',
                        '<script>const example = "<template>";</script>',
                        '<style>body::before { content: "<template>"; }</style>',
                        '<textarea>Example: <template></textarea>'):
            with self.subTest(content=content):
                self.assert_accepted(self.opening + content + "Report" + self.closing)

    def test_rendered_reports_in_both_languages_remain_valid_with_closed_templates(self):
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                code, _, error = self.render("--lang", lang, "--no-pdf")
                self.assertEqual(code, 0, error)
                self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])
                for name in ("dashboard.html", "report.html"):
                    path = self.out / name
                    page = path.read_text(encoding="utf-8")
                    page = page.replace("</body>", "<template><p>Optional content</p></template></body>", 1)
                    path.write_text(page, encoding="utf-8")
                self.assertEqual(list(contract_check.problems(self.out, no_pdf=True)), [])


if __name__ == "__main__":
    unittest.main()
