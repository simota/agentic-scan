"""Optional source excerpts must not guess where a secret expression ends."""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import findings  # noqa: E402
import render  # noqa: E402


class SecretContinuationTests(unittest.TestCase):
    def test_member_index_call_and_operator_continuations_are_not_excerpted(self):
        continuations = (
            '.concat("DO_NOT_PUBLISH");',
            '["concat"]("DO_NOT_PUBLISH");',
            '?.concat("DO_NOT_PUBLISH");',
            '.replace("first",\n  "DO_NOT_PUBLISH");',
            '&& "DO_NOT_PUBLISH";',
            '|| "DO_NOT_PUBLISH";',
            '?? "DO_NOT_PUBLISH";',
            '? "DO_NOT_PUBLISH" : "fallback";',
            '("DO_NOT_PUBLISH");',
            '`DO_NOT_PUBLISH`;',
            '+ "DO_NOT_PUBLISH";',
        )
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            for continuation in continuations:
                with self.subTest(continuation=continuation):
                    source = 'const API_TOKEN = "first"\n' + '\n' * 5 + continuation + '\n'
                    (repo / "settings.ts").write_text(source, encoding="utf-8")
                    self.assertIsNone(render.snippet(repo, "settings.ts:7"))

    def test_comments_and_other_language_boundaries_do_not_make_values_safe(self):
        sources = {
            "line-comment.ts": 'const apiKey = "first"\n// continue below\n.concat("DO_NOT_PUBLISH");\n',
            "block-comment.ts": 'const apiKey = "first"\n/* continue below */\n.concat("DO_NOT_PUBLISH");\n',
            "binding.ts": 'const API_TOKEN\n = "DO_NOT_PUBLISH";\n',
            "annotation.ts": 'const apiKey\n : string = "DO_NOT_PUBLISH";\n',
            "setter.ts": 'configure.apiToken(\n "DO_NOT_PUBLISH"\n);\n',
            "property.ts": 'configure["api_key"](\n "DO_NOT_PUBLISH"\n);\n',
            "settings.php": '$api_key = "first"\n . "DO_NOT_PUBLISH";\n',
            "settings.lua": 'api_key = "first"\n .. "DO_NOT_PUBLISH"\n',
            "settings.yaml": '? api_key\n: "DO_NOT_PUBLISH"\n',
        }
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            for name, source in sources.items():
                with self.subTest(source=name):
                    (repo / name).write_text(source, encoding="utf-8")
                    self.assertIsNone(render.snippet(repo, f"{name}:2"))

    def test_secret_names_anywhere_in_the_source_suppress_the_excerpt(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            for marker in ('const API_TOKEN = "value";', '// password is configured elsewhere',
                           'settings.setPrivateKey(value)', 'const clientSecret = provider();'):
                for before in (False, True):
                    with self.subTest(marker=marker, before=before):
                        public = 'console.log("public");'
                        source = marker + '\n' * 12 + public if before else public + '\n' * 12 + marker
                        (repo / "source.ts").write_text(source + '\n', encoding="utf-8")
                        self.assertIsNone(render.snippet(repo, f"source.ts:{13 if before else 1}"))

    def test_secret_free_continuations_keep_their_excerpt(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            lines = ['const label = "public"', '/* display formatting */', '.concat("SHAREABLE");']
            (repo / "source.ts").write_text('\n'.join(lines) + '\n', encoding="utf-8")
            self.assertEqual(render.snippet(repo, "source.ts:3"),
                             {"start": 1, "hit": [3, 3], "lines": lines})

    def test_published_pages_omit_the_value_and_keep_the_finding_and_public_excerpt(self):
        for language in ("en", "ja"):
            with self.subTest(language=language), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                repo, out = base / "repo", base / "out"
                repo.mkdir()
                (repo / "settings.ts").write_text(
                    'const API_TOKEN = "first"\n.concat("DO_NOT_PUBLISH");\n', encoding="utf-8")
                (repo / "public.ts").write_text('console.log("SHAREABLE");\n', encoding="utf-8")
                data = json.loads((ROOT / "examples" / "findings.sample.json").read_text(encoding="utf-8"))
                data["findings"][0]["location"] = "settings.ts:2"
                data["findings"][0]["title"] = "Unused service configuration"
                data["findings"][1]["location"] = "public.ts:1"
                data = findings.renumber(data, findings.renumber_map(data["findings"]))
                source = base / "findings.json"
                source.write_text(json.dumps(data), encoding="utf-8")
                errors = io.StringIO()
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors):
                    status = render.main([str(source), "--out", str(out), "--repo", str(repo),
                                          "--lang", language, "--no-pdf"])
                self.assertEqual(status, 0, errors.getvalue())
                for name in ("dashboard.html", "report.html"):
                    with self.subTest(page=name):
                        page = (out / name).read_text(encoding="utf-8")
                        self.assertFalse("DO_NOT_PUBLISH" in page, f"{name} exposed the continued source value")
                        self.assertTrue("SHAREABLE" in page, f"{name} lost the ordinary source excerpt")
                        self.assertTrue("settings.ts:2" in page, f"{name} lost the finding's location")
                        self.assertTrue("Unused service configuration" in page,
                                        f"{name} lost the finding's description")


if __name__ == "__main__":
    unittest.main()
