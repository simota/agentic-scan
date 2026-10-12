"""A report must not select a different repository between finding excerpts."""

import contextlib
import copy
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from test_findings_regressions import record
import render


class RepositorySelectionTests(unittest.TestCase):
    @contextlib.contextmanager
    def repositories(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            repo = base / "checkout" / "repo"
            replacement = base / "replacement" / "repo"
            for directory, prefix in ((repo, "ORIGINAL"), (replacement, "OUTSIDE")):
                directory.mkdir(parents=True)
                for name in ("alpha", "beta"):
                    (directory / f"{name}.py").write_text(f"{prefix}_{name.upper()} = 1\n", encoding="utf-8")
            data = record()
            first = data["findings"][0]
            first["location"] = "alpha.py:1"
            second = copy.deepcopy(first)
            second.update(id="P-002", location="beta.py:1")
            data["findings"].append(second)
            yield base, repo, replacement, data

    @contextlib.contextmanager
    def after_first_excerpt(self, callback):
        original = render.snippet
        calls = []

        def read_then_change(*args, **kwargs):
            result = original(*args, **kwargs)
            calls.append(args[1])
            if len(calls) == 1:
                callback()
            return result

        with mock.patch.object(render, "snippet", side_effect=read_then_change):
            yield calls
        self.assertEqual(calls, ["alpha.py:1", "beta.py:1"])

    def assert_original_only(self, common):
        self.assertEqual(common["findings"][0]["snippet"]["lines"], ["ORIGINAL_ALPHA = 1"])
        self.assertNotIn("OUTSIDE_", json.dumps(common))
        second = common["findings"][1].get("snippet")
        if second is not None:
            self.assertEqual(second["lines"], ["ORIGINAL_BETA = 1"])

    def test_repository_or_ancestor_replacement_between_findings_is_not_read(self):
        for ancestor in (False, True):
            for symlink in (False, True):
                for fallback in (False, True):
                    with self.subTest(ancestor=ancestor, symlink=symlink, fallback=fallback), self.repositories() as fixture:
                        base, repo, replacement, data = fixture
                        target = repo.parent if ancestor else repo
                        substitute = replacement.parent if ancestor else replacement

                        def replace():
                            target.rename(base / "selected")
                            if symlink:
                                target.symlink_to(substitute, target_is_directory=True)
                            else:
                                substitute.rename(target)

                        with self.after_first_excerpt(replace), mock.patch.object(
                                render, "NOFOLLOW_DIR_FD", False if fallback else render.NOFOLLOW_DIR_FD):
                            common = render.to_common(data, "en", repo=repo)
                        self.assert_original_only(common)

    def test_requested_repository_alias_is_not_reselected_between_findings(self):
        for ancestor in (False, True):
            for fallback in (False, True):
                with self.subTest(ancestor=ancestor, fallback=fallback), self.repositories() as fixture:
                    base, repo, replacement, data = fixture
                    alias = base / "alias"
                    alias.symlink_to(repo.parent if ancestor else repo, target_is_directory=True)
                    requested = alias / "repo" if ancestor else alias

                    def retarget():
                        alias.unlink()
                        alias.symlink_to(replacement.parent if ancestor else replacement, target_is_directory=True)

                    with self.after_first_excerpt(retarget), mock.patch.object(
                            render, "NOFOLLOW_DIR_FD", False if fallback else render.NOFOLLOW_DIR_FD):
                        common = render.to_common(data, "en", repo=requested)
                    self.assert_original_only(common)

    def test_replacement_links_cannot_redirect_an_original_excerpt(self):
        for ancestor in (False, True):
            for symlink in (False, True):
                for fallback in (False, True):
                    with self.subTest(ancestor=ancestor, symlink=symlink, fallback=fallback), self.repositories() as fixture:
                        base, repo, replacement, data = fixture
                        (replacement / "beta.py").unlink()
                        (replacement / "beta.py").symlink_to("alpha.py")
                        target = repo.parent if ancestor else repo
                        substitute = replacement.parent if ancestor else replacement

                        def replace():
                            target.rename(base / "selected")
                            if symlink:
                                target.symlink_to(substitute, target_is_directory=True)
                            else:
                                substitute.rename(target)

                        with self.after_first_excerpt(replace), mock.patch.object(
                                render, "NOFOLLOW_DIR_FD", False if fallback else render.NOFOLLOW_DIR_FD):
                            common = render.to_common(data, "en", repo=repo)
                        self.assert_original_only(common)
                        self.assertNotIn("snippet", common["findings"][1])

    def test_replacement_during_excerpt_resolution_omits_the_excerpt(self):
        for after_resolve in (False, True):
            for fallback in (False, True):
                with self.subTest(after_resolve=after_resolve, fallback=fallback), self.repositories() as fixture:
                    base, repo, replacement, data = fixture
                    (replacement / "beta.py").unlink()
                    (replacement / "beta.py").symlink_to("alpha.py")
                    resolve = Path.resolve
                    replaced = False

                    def replace_during_resolve(path, *args, **kwargs):
                        nonlocal replaced
                        if path != repo / "beta.py" or replaced:
                            return resolve(path, *args, **kwargs)
                        resolved = resolve(path, *args, **kwargs) if after_resolve else None
                        repo.rename(base / "selected")
                        replacement.rename(repo)
                        replaced = True
                        return resolved if after_resolve else resolve(path, *args, **kwargs)

                    with mock.patch.object(Path, "resolve", replace_during_resolve), mock.patch.object(
                            render, "NOFOLLOW_DIR_FD", False if fallback else render.NOFOLLOW_DIR_FD):
                        common = render.to_common(data, "en", repo=repo)
                    self.assertTrue(replaced)
                    self.assert_original_only(common)
                    self.assertNotIn("snippet", common["findings"][1])

    def test_invalid_initial_selection_cannot_become_an_outside_repository(self):
        for fallback in (False, True):
            with self.subTest(fallback=fallback), self.repositories() as fixture:
                base, repo, replacement, data = fixture
                requested = base / "missing"
                with self.after_first_excerpt(lambda: requested.symlink_to(replacement, target_is_directory=True)), \
                        mock.patch.object(render, "NOFOLLOW_DIR_FD", False if fallback else render.NOFOLLOW_DIR_FD):
                    common = render.to_common(data, "en", repo=requested)
                self.assertTrue(all("snippet" not in finding for finding in common["findings"]))

    def test_replacement_during_initial_selection_disables_all_excerpts(self):
        for fallback in (False, True):
            with self.subTest(fallback=fallback), self.repositories() as fixture:
                base, repo, replacement, data = fixture
                resolve = Path.resolve
                replaced = False

                def replace_before_resolve(path, *args, **kwargs):
                    nonlocal replaced
                    if path == repo and not replaced:
                        repo.rename(base / "selected")
                        replacement.rename(repo)
                        replaced = True
                    return resolve(path, *args, **kwargs)

                with mock.patch.object(Path, "resolve", replace_before_resolve), mock.patch.object(
                        render, "NOFOLLOW_DIR_FD", False if fallback else render.NOFOLLOW_DIR_FD):
                    common = render.to_common(data, "en", repo=repo)
                self.assertTrue(replaced)
                self.assertTrue(all("snippet" not in finding for finding in common["findings"]))

    def test_relative_repository_survives_a_working_directory_change(self):
        with self.repositories() as fixture:
            _, repo, replacement, data = fixture
            previous = Path.cwd()
            try:
                os.chdir(repo.parent)
                with self.after_first_excerpt(lambda: os.chdir(replacement.parent)):
                    common = render.to_common(data, "en", repo="repo")
            finally:
                os.chdir(previous)
            self.assert_original_only(common)

    def test_normal_repository_aliases_and_internal_links_remain_readable(self):
        for ancestor in (False, True):
            for fallback in (False, True):
                with self.subTest(ancestor=ancestor, fallback=fallback), self.repositories() as fixture:
                    base, repo, _, data = fixture
                    (repo / "actual.py").write_text("ORIGINAL_ALPHA = 1\n", encoding="utf-8")
                    (repo / "alpha.py").unlink()
                    (repo / "alpha.py").symlink_to("actual.py")
                    alias = base / "alias"
                    alias.symlink_to(repo.parent if ancestor else repo, target_is_directory=True)
                    requested = alias / "repo" if ancestor else alias
                    with mock.patch.object(render, "NOFOLLOW_DIR_FD", False if fallback else render.NOFOLLOW_DIR_FD):
                        common = render.to_common(data, "en", repo=requested)
                    self.assert_original_only(common)
                    self.assertEqual(common["findings"][1]["snippet"]["lines"], ["ORIGINAL_BETA = 1"])

    @unittest.skipUnless(render.NOFOLLOW_DIR_FD, "requires descriptor-relative directory opens")
    def test_repository_descriptors_close_on_success_and_conversion_errors(self):
        for interrupted in (False, True):
            with self.subTest(interrupted=interrupted), self.repositories() as fixture:
                _, repo, _, data = fixture
                open_file, duplicate, snippet = os.open, os.dup, render.snippet
                descriptors = []
                calls = 0

                def track(operation, *args, **kwargs):
                    descriptor = operation(*args, **kwargs)
                    descriptors.append(descriptor)
                    return descriptor

                def read_or_fail(*args, **kwargs):
                    nonlocal calls
                    calls += 1
                    if interrupted and calls == 2:
                        raise RuntimeError("interrupted conversion")
                    return snippet(*args, **kwargs)

                with mock.patch.object(os, "open", side_effect=lambda *a, **k: track(open_file, *a, **k)), \
                        mock.patch.object(os, "dup", side_effect=lambda *a, **k: track(duplicate, *a, **k)), \
                        mock.patch.object(render, "snippet", side_effect=read_or_fail):
                    if interrupted:
                        with self.assertRaisesRegex(RuntimeError, "interrupted conversion"):
                            render.to_common(data, "en", repo=repo)
                    else:
                        self.assert_original_only(render.to_common(data, "en", repo=repo))
                self.assertTrue(descriptors)
                for descriptor in set(descriptors):
                    with self.assertRaises(OSError, msg=f"descriptor {descriptor} leaked"):
                        os.fstat(descriptor)

    @unittest.skipUnless(render.SAFE_OUTPUT, "rendering requires descriptor-relative output support")
    def test_both_languages_html_keep_the_original_repository(self):
        for lang in ("en", "ja"):
            with self.subTest(lang=lang), self.repositories() as fixture:
                base, repo, replacement, data = fixture
                source = base / "findings.json"
                source.write_text(json.dumps(data), encoding="utf-8")
                out = base / "out"

                def replace():
                    repo.rename(base / "selected")
                    replacement.rename(repo)

                errors = io.StringIO()
                with self.after_first_excerpt(replace), contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(errors):
                    status = render.main([str(source), "--out", str(out), "--repo", str(repo),
                                          "--lang", lang, "--no-pdf"])
                self.assertEqual(status, 0, errors.getvalue())
                for name in ("dashboard.html", "report.html"):
                    text = (out / name).read_text(encoding="utf-8")
                    self.assertIn("ORIGINAL_ALPHA", text)
                    self.assertNotIn("OUTSIDE_", text)
                    self.assertIn("P-001", text)
                    self.assertIn("P-002", text)


if __name__ == "__main__":
    unittest.main()
