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


def within(path, root):
    """True when path is root or lies below it, matching directories by identity.

    Comparing stat identities instead of spellings also catches symlinked,
    bind-mounted and case-insensitive aliases of root. Components that do not
    exist yet are skipped, so a directory that would be created counts too.
    Links are resolved first, so '..' after a link names the link target's parent.
    """
    try:
        root_stat = os.stat(root)
    except OSError:
        return False
    current = Path(os.path.realpath(path))
    for candidate in (current, *current.parents):
        try:
            if os.path.samestat(os.stat(candidate), root_stat):
                return True
        except OSError:
            continue
    return False


def descriptor_within(descriptor, root):
    """True when the pinned directory is root or lies below it, walking '..' from the descriptor.

    A pathname check alone leaves a window: a symlinked output parent retargeted
    into root after the check but before pinning would pass. The descriptor
    names the directory that receives the writes, so its ancestry is what counts.
    An ancestor that cannot be opened ends the walk; callers keep the pathname check.
    """
    try:
        root_stat = os.stat(root)
        current = os.open(".", getattr(os, "O_PATH", getattr(os, "O_SEARCH", os.O_RDONLY)) | os.O_DIRECTORY,
                          dir_fd=descriptor)
    except OSError:
        return False
    search = getattr(os, "O_PATH", getattr(os, "O_SEARCH", os.O_RDONLY)) | os.O_DIRECTORY
    try:
        while True:
            info = os.fstat(current)
            if os.path.samestat(info, root_stat):
                return True
            parent = os.open("..", search, dir_fd=current)
            os.close(current)
            current = parent
            if os.path.samestat(os.fstat(current), info):
                return False  # The filesystem root is its own parent.
    except OSError:
        return False
    finally:
        os.close(current)
