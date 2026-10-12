"""Repository-boundary and size-limit regressions for shared input reads."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "ux-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import file_io  # noqa: E402


class FileReadRegressions(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / "repo"
        self.source_dir = self.repo / "src"
        self.source_dir.mkdir(parents=True)
        self.source = self.source_dir / "entry.ts"
        self.source.write_bytes(b"safe source")
        self.outside = self.root / "outside"
        self.outside.mkdir()
        (self.outside / "entry.ts").write_bytes(b"DO_NOT_READ_OUTSIDE_SOURCE")

    def test_growth_after_fstat_is_rejected_by_the_byte_limit(self):
        get_info = os.fstat
        roots = (None, self.repo) if file_io.SUPPORTS_ROOT_READS else (None,)
        for root in roots:
            with self.subTest(root=root):
                self.source.write_bytes(b"safe")

                def grow_after_size_check(descriptor):
                    info = get_info(descriptor)
                    with self.source.open("ab") as handle:
                        handle.write(b"x" * 100_000)
                    return info

                with mock.patch.object(file_io.os, "fstat", side_effect=grow_after_size_check):
                    with self.assertRaisesRegex(ValueError, "exceeds 4 bytes"):
                        file_io.read_regular(self.source, max_bytes=4, root=root)

    def test_unsupported_root_reads_are_refused_before_opening(self):
        with mock.patch.object(file_io, "SUPPORTS_ROOT_READS", False), \
                mock.patch.object(file_io.os, "open") as open_file:
            with self.assertRaisesRegex(ValueError, "safe repository reads require"):
                file_io.read_regular(self.source, root=self.repo)
            open_file.assert_not_called()

    @unittest.skipUnless(file_io.SUPPORTS_ROOT_READS, "requires descriptor-relative no-follow reads")
    def test_root_reads_reject_outside_and_parent_traversal(self):
        for path in (self.outside / "entry.ts", self.repo / ".." / "outside" / "entry.ts", self.repo):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    file_io.read_regular(path, root=self.repo)

    @unittest.skipUnless(file_io.SUPPORTS_ROOT_READS, "requires descriptor-relative no-follow reads")
    def test_directory_replaced_before_open_is_not_followed(self):
        open_file = os.open

        def replace_directory(path, flags, **kwargs):
            if path == "src":
                self.source_dir.rename(self.repo / "saved-src")
                self.source_dir.symlink_to(self.outside, target_is_directory=True)
            return open_file(path, flags, **kwargs)

        with mock.patch.object(file_io.os, "open", side_effect=replace_directory):
            with self.assertRaises(OSError):
                file_io.read_regular(self.source, root=self.repo)

    @unittest.skipUnless(file_io.SUPPORTS_ROOT_READS, "requires descriptor-relative no-follow reads")
    def test_directory_replaced_after_open_cannot_redirect_the_read(self):
        open_file = os.open

        def replace_directory(path, flags, **kwargs):
            if path == "entry.ts":
                self.source_dir.rename(self.repo / "saved-src")
                self.source_dir.symlink_to(self.outside, target_is_directory=True)
            return open_file(path, flags, **kwargs)

        with mock.patch.object(file_io.os, "open", side_effect=replace_directory):
            self.assertEqual(file_io.read_regular(self.source, root=self.repo), b"safe source")

    @unittest.skipUnless(file_io.SUPPORTS_ROOT_READS, "requires descriptor-relative no-follow reads")
    def test_file_replaced_with_a_symlink_is_not_followed(self):
        open_file = os.open

        def replace_file(path, flags, **kwargs):
            if path == "entry.ts":
                self.source.unlink()
                self.source.symlink_to(self.outside / "entry.ts")
            return open_file(path, flags, **kwargs)

        with mock.patch.object(file_io.os, "open", side_effect=replace_file):
            with self.assertRaises(OSError):
                file_io.read_regular(self.source, root=self.repo)

    @unittest.skipUnless(file_io.SUPPORTS_ROOT_READS and hasattr(os, "mkfifo"), "requires POSIX FIFOs")
    def test_root_reads_refuse_fifo_without_waiting_for_a_writer(self):
        self.source.unlink()
        os.mkfifo(self.source)
        script = (
            "import sys\nsys.path.insert(0, sys.argv[1])\nfrom file_io import read_regular\n"
            "try:\n    read_regular(sys.argv[2], root=sys.argv[3])\n"
            "except ValueError:\n    sys.exit(0)\nsys.exit(1)\n"
        )
        result = subprocess.run([sys.executable, "-c", script, str(SCRIPTS), str(self.source), str(self.repo)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
