"""Shared helpers for the bug-scan scripts. Standard library only."""
import json
import os
import re
import subprocess
import tempfile
import unicodedata
from pathlib import Path

PATTERNS = {
    "BP01": ("入力の形・境界値", "Input shape and boundaries"),
    "BP02": ("値に見える失敗", "Failures that look like a value"),
    "BP03": ("境界をまたぐ名前や契約のずれ", "Names and contracts across a boundary"),
    "BP04": ("重複したルールの乖離", "Duplicated rules that diverged"),
    "BP05": ("状態・並行・順序", "State, concurrency and ordering"),
    "BP06": ("移行や依存更新の変化", "Migrations and dependency upgrades"),
    "BP07": ("配線切れ", "Broken wiring"),
    "BP08": ("一部のデータでのみ再現", "Data only some fixtures have"),
    "BP09": ("タイミング依存", "Timing"),
    "BP10": ("環境・設定の差", "Environment and configuration"),
    "BP11": ("部分修正", "Partial fix"),
    "BP12": ("文書と実装のずれ", "Docs and code disagree"),
    "Unclassified": ("未分類", "Unclassified"),
}
PERSPECTIVES = [k for k in PATTERNS if k != "Unclassified"]
EVENT_TYPES = ("commission", "omission", "requirement", "not-defect")
DEFECT_TYPES = ("commission", "omission")
CHANNELS = ("feature", "fix", "refactor", "dependency", "config", "migration", "generated", "merge", "unknown", "none")
STRENGTHS = ("Traced", "Blamed", "Unattributable")
STAGES = ("dev", "ci", "release", "unknown")
SEVERITIES = ("High", "Medium", "Low", "Info")
CONFIDENCES = ("Confirmed", "Environment-dependent", "Suspected")
VERDICTS = ("Valid", "Likely", "Unverified", "Unlikely", "FalsePositive", "NotApplicable")
EXCLUDED = ("FalsePositive", "NotApplicable")
STATUSES = ("Open", "Triaged", "Reopened", "Unverified", "Accepted", "Fixed", "Verified")
CLOSED = ("Fixed", "Verified")
LEVELS = ("Low", "Medium", "High")
RISK_TABLE = {("Low", "Low"): "Low", ("Medium", "Low"): "Low", ("High", "Low"): "Medium",
              ("Low", "Medium"): "Low", ("Medium", "Medium"): "Medium", ("High", "Medium"): "High",
              ("Low", "High"): "Medium", ("Medium", "High"): "High", ("High", "High"): "High"}
YES_NO = ("yes", "no", "unknown")
RELATION_TYPES = ("regression_of", "caused_by", "same_root_cause", "blocks", "duplicate_of")
REPRO_STATES = ("static", "test", "verified", "not-reproduced", "unknown")
SURFACE_KINDS = ("screen", "api", "job", "db", "ext", "cfg")
LINK_BASES = ("traced", "inferred", "UNKNOWN")
PATH_STATES = ("allowed", "blocked", "unknown")
SIBLING_STATES = ("affected", "safe", "unknown")

LOCATION = re.compile(r"^(?P<path>[^\r\n]+):(?P<line>[1-9][0-9]*)(?:-(?P<end>[1-9][0-9]*))?$")
ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
HEX_REF = re.compile(r"^[0-9a-f]{4,64}$")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
RESERVED_MAIL = ("example.com", "example.org", "example.net", "test", "invalid", "example")
SECRET = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|\b(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{16,}"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\bsk-[A-Za-z0-9_-]{20,}"
    r"|\bxox[abprs]-[A-Za-z0-9-]{10,}"
    r"|\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+"
    r"|\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@"
    r"|(?i:\b(?:password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*[\"']?[^\s\"'<>{}$]{6,})"
)


class RecordError(ValueError):
    """A record, fragment or input file that the contract refuses."""


def _reject_constant(value):
    raise ValueError(f"nonstandard JSON constant {value}")


def _unique_keys(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key {key!r}")
        out[key] = value
    return out


def load_json(path):
    """Read strict JSON: duplicate keys and NaN/Infinity would silently change recorded evidence."""
    try:
        with open(path, encoding="utf-8-sig") as handle:
            return json.load(handle, object_pairs_hook=_unique_keys, parse_constant=_reject_constant)
    except (OSError, ValueError, RecursionError) as error:
        raise RecordError(f"{path}: {error}") from None


def write_json(path, data):
    """Replace a JSON file atomically so a failed run keeps the previous record."""
    write_text(path, json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + "\n")


def write_text(path, text):
    """Replace a text file atomically, keeping its mode, so a failed write leaves the previous file whole."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, tmp = tempfile.mkstemp(prefix=f".{path.name}-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
        if path.exists():
            os.chmod(tmp, path.stat().st_mode & 0o777)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def redact(text):
    return SECRET.sub("[redacted]", text)


def clean(text):
    """Recorded text taken from outside the review: no secrets, no addresses."""
    return EMAIL.sub("[email]", redact(str(text)))


def excluded(finding):
    return (finding.get("validation") or {}).get("verdict") in EXCLUDED


def closed(finding):
    return finding.get("status") in CLOSED


def unresolved(finding):
    """Still needs someone: neither judged false nor fixed."""
    return not excluded(finding) and not closed(finding)


def personal_email(text):
    """The first address in text that is not on a domain reserved for examples."""
    for match in EMAIL.finditer(text):
        domain = match.group(1).lower()
        if not any(domain == r or domain.endswith("." + r) for r in RESERVED_MAIL):
            return match.group(0)
    return None


def walk_strings(value, where=""):
    if isinstance(value, str):
        yield where, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from walk_strings(item, f"{where}.{key}" if where else str(key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from walk_strings(item, f"{where}[{index}]")


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def location_path(location):
    match = LOCATION.match(location)
    return match.group("path") if match else location


def display_width(text):
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)


def clip(text, width):
    """Cut text to a display width for a drawing; the table beside the drawing keeps it whole."""
    if display_width(text) <= width:
        return text
    out, used = [], 0
    for char in text:
        used += display_width(char)
        if used > width - 1:
            break
        out.append(char)
    return "".join(out) + "…"


def clip_left(text, width):
    """Cut the start of a path, so a location still shows its file and line."""
    if display_width(text) <= width:
        return text
    out, used = [], 0
    for char in reversed(text):
        used += display_width(char)
        if used > width - 1:
            break
        out.append(char)
    return "…" + "".join(reversed(out))


def pattern_name(pattern, lang):
    names = PATTERNS.get(pattern)
    return (names[0] if lang == "ja" else names[1]) if names else str(pattern)


def git(repo, *args, check=True):
    """Run read-only git against a repository whose configuration is not trusted.

    Hooks, fsmonitor, external diff drivers and pagers are all ways a repository's
    config could execute code during an audit, so each is switched off here.
    """
    command = ["git", "-C", str(repo), "--no-pager", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
               "-c", "core.quotepath=off", "-c", "diff.external=", "-c", "core.pager=cat", *args]
    env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat"}
    env.pop("GIT_DIR", None)
    env.pop("GIT_WORK_TREE", None)
    done = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)
    if check and done.returncode != 0:
        raise RecordError(f"git {' '.join(args[:2])} failed: {done.stderr.strip()[:300]}")
    return done.stdout
