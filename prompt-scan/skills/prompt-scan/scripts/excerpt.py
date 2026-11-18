"""What a report may quote from the reviewed repository, and how it is redacted.

Excerpts are read from the blob at `meta.commit` when the record names one and the tree was known clean
at scan time (never from later working-tree edits), otherwise from the working tree. A file with a
`filter` attribute (git-crypt, Git LFS) is always read from the working tree: its blob holds what the
clean command stored, and no repository command is run to undo that. Credential-shaped values are masked,
private-key blocks whole, and so are single-token values (quoted ones without spaces) assigned to
credential-named keys (`password=`, `SECRET_KEY:`, `"api_key" =>`, `const DB_PASSWORD =`,
`API_KEY: str =`, `password :=`, `ENV API_TOKEN=`) and URL passwords; `.env*`, `*.env`, key files (.pem,
.key, .p12, .pfx, .jks, .keystore) and login files (.npmrc, .pypirc, .netrc, id_rsa...) are never quoted.
inventory.py applies the same file rules and never reads those files; findings.py refuses report prose
holding a credential-shaped value.
"""
from pathlib import Path
import re
import subprocess

from record import LOC_RE

SECRET_RE = re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}|\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|"
                       r"\bgh[pousr]_[A-Za-z0-9]{36,}|\bgithub_pat_[A-Za-z0-9_]{22,}|\bglpat-[A-Za-z0-9_-]{20,}|"
                       r"\bhf_[A-Za-z0-9]{30,}|\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}|"
                       r"\bxox[abprs]-[A-Za-z0-9-]{10,}|\bAIza[0-9A-Za-z_-]{35}|"
                       r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")
# Every match of SECRET_RE contains one of these, so a text holding none has no credential-shaped value
# and is passed over without SECRET_RE's word-boundary tests at each character. Keep the two in step;
# tests/test_inventory.py checks that the needles cover the pattern.
SECRET_NEEDLES = ("sk-", "AKIA", "ASIA", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "hf_",
                  "k_live_", "k_test_", "xox", "AIza", "-----BEGIN ")
# Values with no recognisable format sit next to ones that have one (an AWS secret key under its key id):
# an excerpt masks the value assigned to a credential-named key, and the password in a URL. A key starts a
# line (after indent, `- ` or declaration keywords such as `export const`, `private static final String`,
# `ENV`) or follows { ( [ , ; & ?, so prose ("asks for the password: no") is left alone. It is assigned
# with =, :, =>, := or a type annotation (`API_KEY: str =`). The value is one token or a quoted string
# without spaces; a number, None/null/true/false, a template variable or an unquoted call is not a secret.
# Every run is bounded, so long lines stay linear.
DECLARATION = r"(?:export|const|let|var|val|final|static|readonly|private|public|protected|internal|ENV|String|string|str)"
ASSIGNED_SECRET_RE = re.compile(
    r"""(?im)((?:^[ \t]{0,64}(?P<decl>(?:-[ \t]+|(?-i:""" + DECLARATION + r""")[ \t]+){0,4})|[{(\[,;&?][ \t]{0,8})["']?"""
    r"""[\w.-]{0,64}?"""
    r"""(?:secret|passw(?:or)?d|passwd|pwd|token|api[_-]?key|access[_-]?key|private[_-]?key|credentials?)"""
    r"""(?:[_-][A-Za-z0-9]{1,16}){0,2}["']?\]?[ \t]{0,8}"""
    r"""(?P<op>=>|:=|[:=]|:[ \t]{0,8}[A-Za-z_][\w.\[\]]{0,40}[ \t]{0,8}=)[ \t]{0,8})"""
    r"""(?!(?:-?[0-9]+(?:\.[0-9]+)?|None|null|nil|true|false|undefined)[ \t]*(?:[,;#&)\]}]|$)|["']?[{$<%])"""
    r"""(?P<value>"[^"\s]{1,256}"|'[^'\s]{1,256}'|[^\s"',;#&)\]}]{1,256})(?=[ \t]*(?:[,;#&)\]}]|$))""")
# The password runs to the last @ before the host, so one that holds an @ or a / is masked whole.
URL_PASSWORD_RE = re.compile(r"((?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,31}://[^\s:/@]{0,256}:)(\S{1,256})"
                             r"(?=@[^\s@/]{0,256}(?:[/?#\s]|$))")
# Files that hold credentials by convention: inventory.py never reads them, and no excerpt quotes them.
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}
SENSITIVE_NAMES = {".npmrc", ".pypirc", ".netrc", "_netrc", ".pgpass", ".htpasswd", ".git-credentials",
                   "credentials", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
# A whole private-key block, so masking it also hides the key body lines (an unterminated block runs to the end).
KEY_BLOCK_RE = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\Z)",
                          re.S)


def has_secret_needle(text):
    """False when SECRET_RE cannot match anywhere in text; True when it may."""
    return any(needle in text for needle in SECRET_NEEDLES)


def mask(text):
    # A text without a needle has nothing to replace: sub() would return it unchanged.
    return SECRET_RE.sub("[REDACTED]", text) if has_secret_needle(text) else text


def mask_excerpt(line):
    """mask(), plus the values an excerpt's context lines carry without a recognisable format."""
    # Before mask(): its [REDACTED] would otherwise read as a value assigned to the key.
    def assigned(m):
        value = m["value"]
        # An unquoted value holding "(" is a call, a quoted one a literal whatever it holds; after a
        # declaration keyword a bare ":" starts a type (`let password: string`), not a value.
        if "(" in value and value[0] not in "\"'" or m["op"] == ":" and m["decl"] and m["decl"].strip("- \t"):
            return m.group(0)
        return m.group(1) + "[REDACTED]"
    line = ASSIGNED_SECRET_RE.sub(assigned, line)
    return mask(URL_PASSWORD_RE.sub(lambda m: m.group(1) + "[REDACTED]", line))


def mask_key_blocks(text):
    """Replace each private-key block line by line, so line numbers stay put."""
    return KEY_BLOCK_RE.sub(lambda m: "\n".join("[REDACTED]" for _ in m.group(0).split("\n")), text)


def source_lines(text):
    """Lines as editors and `path:line` count them: split on newline only.

    str.splitlines() also breaks at form feeds, U+2028 and other separators, which
    would shift every later line number.
    """
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [line[:-1] if line.endswith("\r") else line for line in lines]


def sensitive(name):
    """Whether a file name is one that holds credentials by convention (.env*, *.env, key and login files)."""
    lower = name.lower()
    return (lower.startswith(".env") or lower.endswith(".env") or lower in SENSITIVE_NAMES
            or Path(lower).suffix in SENSITIVE_SUFFIXES)


def git_in(repo):
    """git in the reviewed repository, never running its fsmonitor command (check-attr reads the index) and
    never writing its index, as inventory.py runs it."""
    return ["git", "--no-optional-locks", "-C", str(repo), "-c", "core.fsmonitor=false"]


def _source(repo, commit, rel):
    if Path(rel).is_absolute() or ".." in Path(rel).parts or sensitive(Path(rel).name):
        return None
    if commit:
        try:
            # A blob under a filter driver (git-crypt, LFS) is what the clean command stored, not the text the
            # scan read; the tree was clean, so the working-tree file is that text. check-attr runs no driver.
            attr = subprocess.run([*git_in(repo), "check-attr", "-z", "filter", "--", f"./{rel}"],
                                  capture_output=True, timeout=20)
            if attr.returncode != 0:
                return None
            if attr.stdout.split(b"\0")[2:3] in ([b"unspecified"], [b"unset"]):
                # "./" resolves the path against --repo, which may be a subdirectory of the Git work tree.
                r = subprocess.run([*git_in(repo), "show", f"{commit}:./{rel}"], capture_output=True,
                                   timeout=20)
                return r.stdout.decode("utf-8", errors="replace") if r.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            return None
    root = Path(repo).resolve()
    path = (root / rel).resolve()
    if root not in path.parents or sensitive(path.name) or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def attach_sources(data, repo, context=3, limit=40):
    """Excerpts keyed by finding id: (first line number, lines, highlighted range)."""
    excerpts = {}
    if repo is None:
        return excerpts
    meta = data.get("meta", {})
    # Only a scan known to be clean reviewed the commit's blob; a dirty or undetermined one read the working tree.
    commit = meta.get("commit") if meta.get("dirty") is False else None
    cache = {}
    for f in data.get("findings", []):
        m = LOC_RE.match(f["location"])
        if not m:
            continue
        rel = m["path"]
        if rel not in cache:
            cache[rel] = _source(repo, commit, rel)
        text = cache[rel]
        if text is None:
            continue
        lines = source_lines(mask_key_blocks(text))
        start = int(m["start"])
        end = max(start, int(m["end"] or start))
        if start < 1 or start > len(lines):
            continue
        first = max(1, start - context)
        last = min(len(lines), end + context, first + limit - 1)
        excerpts[f["id"]] = (first, [mask_excerpt(line) for line in lines[first - 1:last]], (start, end))
    return excerpts

