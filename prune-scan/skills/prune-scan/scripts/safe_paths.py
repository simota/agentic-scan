"""Descriptor-relative directory opens for paths already selected by a caller.

Callers gate this helper on POSIX descriptor-relative and O_NOFOLLOW support.
Every component, including ancestors of a repository or artifact directory,
is opened from a pinned parent. The returned descriptor belongs to the caller.
"""

import os
from pathlib import Path


def open_directory(path, *, readable=True, expected_stat=None):
    """Pin an absolute directory without following symlinks in any component.

    Resolve intentional aliases in the caller after capturing the selected
    identity, not here: resolving again could accept a newly planted symlink.
    Relative paths are anchored to the current directory without dereferencing
    links or discarding '..' components.

    Ancestors need only search permission when O_PATH or O_SEARCH is available.
    Set readable=False when the final directory is only a parent for openat;
    runtimes without search-only flags require directory read permission.

    Pass the stat captured before resolving or inspecting a selected directory
    to reject normal-directory replacements as well as symlinks. The returned
    descriptor retains that identity if the pathname changes afterward.
    """
    path = Path(path).absolute()
    protection = os.O_DIRECTORY | os.O_NOFOLLOW
    search = getattr(os, "O_PATH", getattr(os, "O_SEARCH", os.O_RDONLY)) | protection
    final = (os.O_RDONLY | protection) if readable else search
    descriptor = os.open(path.anchor, final if len(path.parts) == 1 else search)
    try:
        for index, part in enumerate(path.parts[1:], 1):
            flags = final if index == len(path.parts) - 1 else search
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        if expected_stat is not None and not os.path.samestat(expected_stat, os.fstat(descriptor)):
            raise OSError(f"{path}: directory changed since it was selected")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise
