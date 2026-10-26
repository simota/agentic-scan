#!/usr/bin/env python3
"""Capture evidence files for findings (reference/evidence.md).

    python3 capture.py screenshot URL --out FILE.png --viewport 360x640 [--wait MS] [--timeout S]
    python3 capture.py log --out FILE.log [--cwd DIR] [--timeout S] -- COMMAND [ARG...]

screenshot loads URL in headless Chrome (CHROME picks the binary) at the
viewport and saves a PNG. log runs COMMAND without a shell and saves the
command line, working directory, exit status, capture time and its combined
output, with secret-looking lines masked. Save into <out>/evidence/ and cite
the file in the finding's evidence. Standard library only.
Exit status: 0 written, 2 invalid arguments or capture failed.
"""

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evidence import FILE, KINDS, MAX_BYTES  # noqa: E402
from file_io import tolerant_console  # noqa: E402
from scan_report_kit.pdf import CHROME_CANDIDATES  # noqa: E402
from secret_lines import SHOWN_CHARACTERS, continued_secret_lines, private_key_lines, secret_line  # noqa: E402

VIEWPORT = re.compile(r"^([1-9][0-9]{2,3})x([1-9][0-9]{2,3})\Z")
MASKED = "[masked: looks like a secret]"
# Room under the renderer's log limit for the header and the truncation note.
MAX_OUTPUT = MAX_BYTES["log"] - 64 * 1024


def secret_anywhere(line):
    """secret_line judges a window from the line's start; the file keeps whole lines, so judge
    overlapping windows across all of it (each window reaches well past the next one's start)."""
    return any(secret_line(line[i:]) for i in range(0, max(len(line), 1), SHOWN_CHARACTERS))


def target(path, kind):
    """The output path, refused when its name cannot be cited or it is not a regular file."""
    path = Path(path)
    m = FILE.match(path.name)
    if not m or m["ext"] not in KINDS[kind]:
        raise ValueError(f"{path.name}: a {kind} file is named like U-001-before-360.{KINDS[kind][0]} "
                         f"(.{', .'.join(KINDS[kind])})")
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(f"{path}: must be a regular file, not a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def chrome():
    for candidate in [os.environ["CHROME"]] if os.environ.get("CHROME") else CHROME_CANDIDATES:
        exe = candidate if os.path.isabs(candidate) and os.path.exists(candidate) else shutil.which(candidate)
        if exe:
            return exe
    raise ValueError("no Chrome or Chromium found; set CHROME to its binary")


def screenshot(url, out, viewport, wait, timeout):
    m = VIEWPORT.match(viewport)
    if not m:
        raise ValueError(f"--viewport: expected WIDTHxHEIGHT such as 360x640, got {viewport!r}")
    if not re.match(r"(?i)^(?:https?|file):", url):
        raise ValueError("URL: expected an http(s) or file URL")
    out = target(out, "screenshot")
    if out.suffix.lower() != ".png":
        raise ValueError(f"{out.name}: Chrome saves PNG; name the file .png")
    sandbox = ["--no-sandbox"] if hasattr(os, "geteuid") and os.geteuid() == 0 else []
    with tempfile.TemporaryDirectory(prefix=".ux-scan-capture-", dir=out.parent) as staging:
        shot = Path(staging) / "shot.png"
        try:
            subprocess.run([chrome(), "--headless=new", "--disable-gpu", "--hide-scrollbars", *sandbox,
                            "--no-first-run", f"--user-data-dir={Path(staging) / 'profile'}",
                            f"--window-size={m[1]},{m[2]}", f"--virtual-time-budget={wait}",
                            f"--screenshot={shot}", url],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            raise ValueError(f"Chrome timed out after {timeout:g} s") from None
        if not shot.exists() or not shot.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"):
            raise ValueError("Chrome produced no screenshot (is the URL reachable from here?)")
        os.replace(shot, out)
    return out


def log(command, out, cwd, timeout):
    if not command:
        raise ValueError("log: give the command after --")
    out = target(out, "log")
    try:
        done = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              stdin=subprocess.DEVNULL, timeout=timeout, check=False)
        output, status = done.stdout, str(done.returncode)
    except subprocess.TimeoutExpired as e:
        output, status = e.stdout or b"", f"timed out after {timeout:g} s"
    except OSError as e:
        raise ValueError(f"cannot run {command[0]}: {e.strerror or e}") from None
    lines = output[:MAX_BYTES["log"]].decode("utf-8", errors="replace").splitlines()
    hidden = private_key_lines(lines) | continued_secret_lines(lines, 0, len(lines))
    lines = [MASKED if i in hidden or secret_anywhere(line) else line for i, line in enumerate(lines)]
    # A command line can carry a credential too (curl -u, --password).
    shown = f"$ {shlex.join(command)}"
    header = [MASKED if secret_anywhere(shown) else shown, f"cwd: {cwd or '.'}", f"exit: {status}",
              f"captured: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}", "---"]
    # Masks and replacement characters can grow the text: bound what is written, not what was read,
    # so the renderer never refuses the log. Keep the head and say so.
    kept, size = [], len("\n".join(header).encode("utf-8")) + 1
    for line in lines:
        size += len(line.encode("utf-8")) + 1
        if size > MAX_OUTPUT:
            kept.append(f"[output truncated: {len(output)} bytes of output, the first {len(kept)} lines kept]")
            break
        kept.append(line)
    out.write_text("\n".join(header + kept) + "\n", encoding="utf-8")
    return out


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("screenshot", help="PNG of a URL at a viewport, from headless Chrome")
    s.add_argument("url")
    s.add_argument("--out", required=True)
    s.add_argument("--viewport", default="360x640")
    s.add_argument("--wait", type=int, default=3000, help="virtual milliseconds to let the page settle")
    s.add_argument("--timeout", type=float, default=60.0)
    g = sub.add_parser("log", help="a command's output, with its command line and exit status")
    g.add_argument("--out", required=True)
    g.add_argument("--cwd")
    g.add_argument("--timeout", type=float, default=120.0)
    g.add_argument("command", nargs=argparse.REMAINDER)
    a = p.parse_args(argv)
    try:
        if a.mode == "screenshot":
            written = screenshot(a.url, a.out, a.viewport, a.wait, a.timeout)
        else:
            command = a.command[1:] if a.command[:1] == ["--"] else a.command
            written = log(command, a.out, a.cwd, a.timeout)
    except (OSError, ValueError) as e:
        print(f"capture.py: {e}", file=sys.stderr)
        return 2
    print(f"wrote {written}")
    return 0


if __name__ == "__main__":
    tolerant_console()
    sys.exit(main())
