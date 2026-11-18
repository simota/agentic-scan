"""Publish regular files relative to a directory descriptor retained by the caller.

Directory selection belongs to callers: capture its stat before resolving any
intentional alias, then use safe_paths.open_directory(expected_stat=...). These
writers never resolve that pathname again. Protected input stats must come from
open input descriptors held until publication finishes, preventing inode reuse.
"""

import os
import secrets
import shutil
import stat
import sys
from pathlib import Path

SAFE_OUTPUT = (os.open in os.supports_dir_fd and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW")
               and all(fn in os.supports_dir_fd for fn in (os.stat, os.rename, os.unlink, os.mkdir, os.rmdir))
               and os.stat in os.supports_follow_symlinks and hasattr(os, "fchmod"))


def tolerant_stdout():
    """Escape what the terminal cannot encode (a non-UTF-8 directory name) in status lines.

    The scripts print a path after their work is done; a strict stdout would
    otherwise turn a completed write into a traceback and exit status 1.
    """
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(errors="backslashreplace")


def _basename(name):
    if (not isinstance(name, str) or not name or name in {".", ".."}
            or "\0" in name or Path(name).name != name):
        raise OSError("output must name a file within the selected directory")


def checked_target(directory, name, *, protected=(), regular=False):
    """Return a no-follow stat, refusing an actual input or an unsafe report target."""
    _basename(name)
    try:
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if any(os.path.samestat(info, source) for source in protected):
        raise OSError(f"output would overwrite an input source: {name}")
    if regular and not stat.S_ISREG(info.st_mode):
        raise OSError(f"refusing to write {name}: symlink or non-regular file")
    return info


def _unlink(directory, name):
    try:
        os.unlink(name, dir_fd=directory)
    except FileNotFoundError:
        pass


def _temporary(directory):
    for _ in range(100):
        name = ".scan-output-" + secrets.token_hex(12) + ".tmp"
        try:
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
            return descriptor, name
        except FileExistsError:
            continue
    raise OSError("could not create an output temporary file")


def write_output_at(directory, name, text, *, protected=()):
    """Atomically replace one basename, preserving regular-file permission bits.

    The final entry may be a symlink: replacement removes the link, without writing
    through it. Newly created files are private to their owner. The caller retains
    the directory descriptor through temporary-file removal on every error path.
    """
    existing = checked_target(directory, name, protected=protected)
    mode = stat.S_IMODE(existing.st_mode) & 0o777 if existing and stat.S_ISREG(existing.st_mode) else None
    descriptor, temporary = None, None
    try:
        descriptor, temporary = _temporary(directory)
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as handle:
            handle.write(text)
        if mode is not None:
            os.fchmod(descriptor, mode)
        checked_target(directory, name, protected=protected)
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        temporary = None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            _unlink(directory, temporary)


def publish_outputs_at(directory, files, *, remove=(), protected=()):
    """Copy private staged files, then commit a report set with rollback.

    Every public operation, backup, restore and cleanup stays relative to the same
    selected directory. Each rename is atomic; the set as a whole is not. Previous
    regular files keep their permissions, and recovery files remain if restoration
    fails. Unlike the single-file writer, reports refuse final symlinks.
    """
    files, remove = dict(files), tuple(remove)
    names = tuple(files) + remove
    for name in names:
        checked_target(directory, name, protected=protected, regular=True)
    if len(set(names)) != len(names):
        raise ValueError("output and removal names must be distinct")
    if not names:
        return
    work = None
    for _ in range(100):
        candidate = ".scan-report-output-" + secrets.token_hex(12)
        try:
            os.mkdir(candidate, mode=0o700, dir_fd=directory)
            work = candidate
            break
        except FileExistsError:
            continue
    if work is None:
        raise OSError("could not create an output transaction directory")
    workspace, prepared = None, {}
    installing, keep_recovery = set(), False
    try:
        workspace = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
        # Reserving every name also rejects aliases on case-insensitive volumes.
        for name in names:
            descriptor = os.open("new-" + name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=workspace)
            prepared[name] = descriptor
            if name in files:
                source = os.open(files[name], os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
                with os.fdopen(source, "rb") as reader:
                    if not stat.S_ISREG(os.fstat(reader.fileno()).st_mode):
                        raise OSError(f"staged output must be a regular file: {name}")
                    with os.fdopen(descriptor, "wb", closefd=False) as writer:
                        shutil.copyfileobj(reader, writer)
        try:
            for name in names:
                info = checked_target(directory, name, protected=protected, regular=True)
                if info is None:
                    continue
                if name in files:
                    os.fchmod(prepared[name], stat.S_IMODE(info.st_mode) & 0o777)
                os.replace(name, "old-" + name, src_dir_fd=directory, dst_dir_fd=workspace)
            for name in files:
                checked_target(directory, name, protected=protected, regular=True)
                installing.add(name)
                os.replace("new-" + name, name, src_dir_fd=workspace, dst_dir_fd=directory)
        except BaseException as error:
            rollback_errors = []
            for name in reversed(names):
                try:
                    saved = checked_target(workspace, "old-" + name)
                    if saved is not None:
                        checked_target(directory, name, protected=protected)
                        os.replace("old-" + name, name, src_dir_fd=workspace, dst_dir_fd=directory)
                    elif name in installing:
                        checked_target(directory, name, protected=protected)
                        _unlink(directory, name)
                except BaseException as rollback:
                    rollback_errors.append(f"{name}: {rollback or type(rollback).__name__}")
            if rollback_errors:
                keep_recovery = True
                raise OSError(f"could not update outputs: {error or type(error).__name__}; recovery files "
                              f"are preserved in the selected output directory at {work}; could not restore "
                              + "; ".join(rollback_errors)) from error
            raise
    finally:
        for descriptor in prepared.values():
            os.close(descriptor)
        try:
            if not keep_recovery and workspace is not None:
                for name in names:
                    _unlink(workspace, "new-" + name)
                    _unlink(workspace, "old-" + name)
        finally:
            if workspace is not None:
                os.close(workspace)
        if not keep_recovery:
            os.rmdir(work, dir_fd=directory)
