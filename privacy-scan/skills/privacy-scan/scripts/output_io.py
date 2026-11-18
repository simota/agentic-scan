"""Stage UTF-8 outputs before replacing existing files.

Encoding and temporary-file write failures leave every destination unchanged.
Each final replacement is atomic; multiple replacements are not a transaction.
"""
from pathlib import Path
import stat
from tempfile import NamedTemporaryFile


def write_utf8_files(outputs, *, protected_paths=()):
    """Stage text outputs, refusing aliases of other outputs or protected files."""
    # Encode every output before opening any file, including temporary files.
    encoded = [(Path(path), text.encode("utf-8")) for path, text in outputs.items()]
    try:
        used_paths = {Path(path).resolve() for path in protected_paths}
    except RuntimeError:
        raise OSError("protected file cannot be resolved") from None
    destinations = []
    for path, content in encoded:
        # Match write_text's symlink behavior while replacing the target atomically.
        try:
            path = path.resolve()
        except RuntimeError:
            raise OSError("output destination cannot be resolved") from None
        if path in used_paths:
            raise OSError("output destination aliases another output or protected file")
        used_paths.add(path)
        try:
            metadata = path.stat()
        except FileNotFoundError:
            mode = None
        else:
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError("output destination must be a regular file")
            mode = stat.S_IMODE(metadata.st_mode)
        destinations.append((path, content, mode))

    staged = []
    try:
        for path, content, mode in destinations:
            with NamedTemporaryFile(mode="wb", dir=path.parent,
                                    prefix=f".{path.name}.", suffix=".tmp",
                                    delete=False) as stream:
                temporary = Path(stream.name)
                staged.append((temporary, path))
                stream.write(content)
            if mode is not None:
                temporary.chmod(mode)
        # Do not start replacing files until every staged write has succeeded.
        for temporary, destination in staged:
            temporary.replace(destination)
    finally:
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)
