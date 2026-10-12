"""Descriptor-relative directory opens for paths already selected by a caller.

Callers gate this helper on POSIX descriptor-relative and O_NOFOLLOW support.
Every component, including ancestors of a repository or artifact directory,
is opened from a pinned parent. The returned descriptor belongs to the caller.
"""

import os
from pathlib import Path


def open_directory(path, *, readable=True):
    """Pin an absolute directory without following symlinks in any component.

    Resolve intentional aliases before selecting/inspecting a directory, not
    here: resolving again could accept a symlink planted after that inspection.
    Relative paths are anchored to the current directory without dereferencing
    links or discarding '..' components.

    Ancestors need only search permission when O_PATH or O_SEARCH is available.
    Set readable=False when the final directory is only a parent for openat;
    runtimes without search-only flags require directory read permission.
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
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise
