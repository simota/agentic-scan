"""Bounded regular-file reads, optionally anchored inside a repository, and console output
that cannot fail on a path the console's encoding lacks.

Repository reads require descriptor-relative, no-follow directory traversal.
Platforms without those primitives refuse them instead of following a path
that can change after a symlink check. Standard library only.
"""

import os
import stat
import sys
from pathlib import Path

SUPPORTS_ROOT_READS = (os.open in os.supports_dir_fd
                      and all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")))


def _open_in_root(path, root, flags):
    """Open each component relative to a directory that is already held open."""
    if not SUPPORTS_ROOT_READS:
        raise ValueError("safe repository reads require dir_fd, O_DIRECTORY, O_NOFOLLOW and O_NONBLOCK")
    # Do not resolve the file path: resolving would follow the very symlinks
    # this operation refuses. Callers supply their already chosen repo root.
    path, root = path.absolute(), Path(root).absolute()
    try:
        relative = path.relative_to(root)
    except ValueError:
        raise ValueError(f"{path}: outside repository root {root}") from None
    if not relative.parts or ".." in relative.parts:
        raise ValueError(f"{path}: expected a file inside repository root {root}")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    directory = os.open(root, directory_flags)
    try:
        for part in relative.parts[:-1]:
            child = os.open(part, directory_flags, dir_fd=directory)
            previous, directory = directory, child
            os.close(previous)
        return os.open(relative.name, flags, dir_fd=directory)
    finally:
        os.close(directory)


def read_regular(path, max_bytes=None, root=None):
    """Read bytes from a regular file, without following a final symlink or FIFO.

When root is given, path must be lexically inside that directory (both may be
absolute or cwd-relative). Every component below root is opened with
O_NOFOLLOW and dir_fd, so replacing an ancestor with a symlink cannot redirect
the read. Root's final component must also be a real directory. Root's parent
directories belong to the caller's trusted path, not the reviewed repository.

Non-regular files, an exceeded byte limit, an out-of-root path and unsupported
root traversal raise ValueError; filesystem errors raise OSError. The byte
limit is checked on the opened descriptor and on the bounded read, including
when a file grows after its size was checked.
"""
    if max_bytes is not None and (type(max_bytes) is not int or max_bytes < 0):
        raise ValueError("max_bytes must be a non-negative integer or None")
    path = Path(path)
    flags = (os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    if root is not None:
        descriptor = _open_in_root(path, root, flags)
    else:
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError(f"{path}: must be a regular file (not a symlink)")
        descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{path}: must be a regular file")
        if max_bytes is not None and info.st_size > max_bytes:
            raise ValueError(f"{path}: exceeds {max_bytes} bytes")
        source = handle.read() if max_bytes is None else handle.read(max_bytes + 1)
        if max_bytes is not None and len(source) > max_bytes:
            raise ValueError(f"{path}: exceeds {max_bytes} bytes")
        return source


def within(path, root):
    """Whether absolute path is root or lies under it.

Directories are compared by identity, not spelling, so a differently cased
name on a case-insensitive filesystem or another alias of root still counts.
Ancestors that do not exist yet, or cannot be inspected, are skipped.
"""
    target = os.stat(root)
    for directory in (path, *path.parents):
        try:
            info = os.stat(directory)
        except OSError:  # Missing or not inspectable: nothing to compare.
            continue
        if (info.st_dev, info.st_ino) == (target.st_dev, target.st_ino):
            return True
    return False


def tolerant_console():
    """Escape characters stdout and stderr cannot encode (a Japanese output path on a cp1252
    pipe), so a success message never turns finished work into a failure exit."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
