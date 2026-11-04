#!/usr/bin/env python3
"""Merge finding fragments into findings.json and check a run's output directory.

    python3 findings.py merge FINDINGS FRAGMENT [FRAGMENT ...]
    python3 findings.py check OUT_DIR [--allow NAME ...]

A fragment is a JSON file written with the host's file-write tool (never a
shell heredoc or a generated script). It holds any of these top-level keys:
`meta` is merged key by key; `findings` and `budgets` records are matched by
`id`, a known record updated key by key and a new one appended; `perspectives`
are matched by `name` and replaced whole; the string lists (`checked_ok`,
`decisions`, `limitations`, `next_steps`) are appended without duplicates.
FINDINGS is created when absent. The record must pass the schema check
(`reference/findings-schema.md`) after every fragment before anything is
written. A merge never removes a key.
Run merges to the same FINDINGS sequentially; atomic replacement does not
detect concurrent updates.

`check` is the run contract: the output directory holds exactly
`findings.json`, `dashboard.html` and `report.md` (plus `--allow` names), the
required outputs are readable nonempty regular files, the record is complete,
IDs are gapless in severity order and every perspective in
`reference/perspectives.md` is recorded.

Exit codes: 0 ok, 1 a fragment was refused, the input was unreadable or the
contract failed (reasons on stderr), 2 a command-line usage error.
"""
import argparse
import contextlib
import errno
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

SEVERITIES = ("High", "Medium", "Low", "Info")
CONFIDENCES = ("Confirmed", "Environment-dependent", "Suspected")
VERDICTS = ("Valid", "Likely", "Unverified", "Unlikely", "FalsePositive", "NotApplicable")
DEFINITIVE = ("Valid", "FalsePositive", "NotApplicable")
EXCLUDED = ("FalsePositive", "NotApplicable")
METHODS = ("static", "measured")
STATUSES = ("Open", "Fixed", "Accepted")
BUDGET_FAMILIES = ("QRY", "SIZE", "CPLX", "LAT", "RES", "FE")
BUDGET_STATUSES = ("holds", "violated", "partly read", "not checked")
PERSPECTIVE_STATUSES = ("applied", "N/A", "not checked")
PERSPECTIVES = (
    "Database access", "Algorithms and data structures", "Memory", "I/O and network",
    "Caching", "Concurrency and resources", "Payload and API shape", "Front end",
    "Background work", "Startup and configuration", "Dependencies and platform",
    "Observability",
)
# The hunt-step IDs of reference/perspectives.md, per perspective in its order,
# mapped to the perspective they belong to.
STEP_PERSPECTIVES = {f"{prefix}{n}": name for name, (prefix, count) in zip(PERSPECTIVES, (
    ("DB", 6), ("AL", 4), ("ME", 4), ("IO", 6), ("CA", 4), ("CC", 5), ("PA", 4),
    ("FE", 5), ("BG", 3), ("SC", 3), ("DP", 2), ("OB", 1))) for n in range(1, count + 1)}
HUNT_STEPS = frozenset(STEP_PERSPECTIVES)
LISTS = ("checked_ok", "decisions", "limitations", "next_steps")
TOP_KEYS = {"meta", "findings", "budgets", "perspectives", *LISTS}
META_REQUIRED = ("project", "scope", "date", "assessor", "lang")
FINDING_REQUIRED = ("id", "title", "severity", "confidence", "category", "location",
                    "workload", "scale_driver", "cost_model", "request", "impact",
                    "fix", "regression_test", "validation")
# Records accept only their documented keys, so a typo (budjet, measurment) is
# refused instead of silently escaping check's rules and both outputs. meta stays
# open for host-specific notes; only its documented keys are rendered.
FINDING_KEYS = frozenset(FINDING_REQUIRED + ("contrast", "budget", "step", "status",
                                             "measurement", "references"))
VALIDATION_KEYS = frozenset(("verdict", "method", "evidence"))
MEASUREMENT_KEYS = frozenset(("environment", "before", "after"))
# A measurement is a comparison: the same harness on the code as it is and with
# the fix direction applied, each with the raw output it printed.
MEASUREMENT_RUNS = ("before", "after")
RUN_KEYS = ("command", "result", "log")
REFERENCE_KEYS = frozenset(("url", "title"))
BUDGET_KEYS = frozenset(("id", "statement", "source", "family", "inferred", "status", "reason"))
PERSPECTIVE_KEYS = frozenset(("name", "status", "note"))
OUTPUTS = {"findings.json", "dashboard.html", "report.md"}
FINDING_ID = re.compile(r"P-[0-9]{3}")
BUDGET_ID = re.compile(r"B-[0-9]{2,}")
# Budget IDs are ASCII, so only ASCII identifier characters bound a mention;
# kana or kanji right next to an ID (予算B-02を超過) do not hide it.
BUDGET_MENTION = re.compile(r"(?<![A-Za-z0-9_-])B-[0-9]{2,}(?![A-Za-z0-9_-])")
# Evidence for a definitive verdict cites at least one path:line (or path#L42).
# The lookbehind starts a match only at the beginning of a run: without it a long
# run with no colon is retried from every position (quadratic time). CJK
# punctuation separates too: unspaced prose (比は2:1、app/views.py:18) has no
# other boundary before a path.
CITATION = re.compile(r"(?<![^\s:：#()\[\]'\"`,;<>、。，；（）「」『』【】])"
                      r"([^\s:：#()\[\]'\"`,;<>、。，；（）「」『』【】]+)(?:[:：]|#L)[1-9１-９][0-9０-９]*")
# The path holds no line break of any kind str.splitlines() knows.
LOCATION = re.compile(r"(?P<path>[^\r\n\x0b\x0c\x1c-\x1e\x85\u2028\u2029]+)"
                      r":(?P<start>[0-9]+)(?:-(?P<end>[0-9]+))?")


class SchemaError(ValueError):
    pass


# Final labels that mark a dotted name as a host rather than a file name.
# Hostnames are case-insensitive, so HOST_SUFFIXES apply in any case
# (DB.EXAMPLE.COM). The ambiguous ones are also common file suffixes
# (README.org, Dockerfile.dev, Service.svc, .env.local): they mark a host in a
# name of three or more labels (api.corp.dev, postgres.default.svc) or in an
# all-lowercase two-label name (example.org, db.dev); a leading dot always
# means a file.
HOST_SUFFIXES = frozenset(("com", "net", "io", "cloud", "jp", "uk", "de", "fr", "eu", "us",
                           "localdomain", "internal", "lan", "invalid", "arpa"))
AMBIGUOUS_HOST_SUFFIXES = frozenset(("org", "co", "dev", "app", "local", "example", "test",
                                     "svc"))
# Two single capital letters around a slash (N/A, I/O, R/W) are an
# abbreviation; ./a, /a, a/b and src/a are files.
ABBREVIATION = re.compile(r"[A-Z][/\\][A-Z]")
IPV4 = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}")
# A citation names a file by shape, deliberately loosely: a directory part
# (src/a, fixtures/123, ./NOTES), a dot with something after it (views.py,
# foo.1, Dockerfile.22.04, .env) or a conventional extensionless root name.
# Refused: numbers, versions, ratios and times (12:30, 1.5:1, v1.2.3:4, 1/2:3),
# protocol versions (HTTP/1.1), URLs, hosts and bare words (timeout:30, TTL:300).
# Checked with string operations and single-class patterns only: nested
# unbounded patterns backtrack quadratically on long candidates (aaa…aaa:1).
# Digits only, in any script and with signs (1/2, １/２, -1/2): a v-prefixed root name is a version (VERSION_START below), but
# under a directory it is a path (v8/123, V1/2).
NUMERIC = re.compile(r"[-+]?\d(?:[\d.]|[/\\][-+]?)*")
# A root-level name that starts with a digit, or with v or V and a digit
# (1!2.3, 1.2.3.post1, 2.0b3, 5.0.0.BUILD-SNAPSHOT, v1!2.3, v2rc1.post2), is a
# number or version, whatever follows: version syntaxes cannot be listed
# exhaustively, so a file named like that is cited with its directory or ./
# (./2.0.txt:3, ./v8.json:2, db/001_init.sql:4). Under a directory, such names count.
LETTER = re.compile(r"[^\W\d_]")
# Range operators may lead (~v1.2.3, ^v2.0.0, >=v1.2.3).
VERSION_START = re.compile(r"[~^=<>!]*[vV]?\d")
# A package spec puts a dotted version after @ or an operator (react@18.2.0,
# pkg@v1.2.3, python==1.2.3); a scale suffix such as icon@2x.png is a file.
PACKAGE_VERSION = re.compile(r"[@=<>~^!][vV]?[0-9]+\.[0-9]")
# A dotted version qualifier is not a file extension (Python-3.12.1.post1,
# Spring-5.3.20.RELEASE, 1.0.Final).
# Short ones that are also real extensions (.m, .a, .el, .deb) need a number.
QUALIFIER = re.compile(r"(?:post|dev|rc|pre|alpha|beta|preview|final|release|ga|snapshot"
                       r"|build-snapshot|milestone|amzn|ubuntu|sles|mga|svn)[0-9_]*"
                       r"|(?:m|a|b|sr|cr|sp|hf|ea|u|p|r|el|fc|deb|git)[0-9][0-9_]*", re.IGNORECASE)
EXTENSION = re.compile(r"[^\W\d_][^\W_]{0,4}")
# Before the - or _ that precedes the number, the name may hold digits, . + #
# and further - or _ (log4j-2.17.1, Node.js-20.11.0, .NET-8.0.0,
# python-dateutil-2.8.2), and a v may mark the number (Python-v3.12.1).
# Without a separator the name is letters only, so python3.11 splits as
# python + 3.11.
PRODUCT_VERSION = re.compile(r"(?:\.?[^\W\d_](?:[^\W_]|[.+#]|[-_](?![vV]?\d))*([-_])[vV]?"
                             r"|[^\W\d_]+)([0-9]+(?:\.[0-9]+)+)")
# Flyway's versioned migrations (V3__add_index.sql, V1_1__init.sql) are files.
MIGRATION = re.compile(r"V[0-9][0-9._]*__[^_]")
# Named protocols, in any case and spelling (HTTP/1.1, tls/1.3, TLSv1.3,
# SSH-2.0, HTTP2), and any capitalised name with a slash and a dotted number
# (SMB/3.1.1, RDP/10.0, OData/4.0, CoAP/1.0). Other directories holding
# numbered files (DB/123, SQL/001, db/1.5) are paths: a lowercase protocol is
# told from a directory only by this list (stomp/1.2 vs db/1.5).
PROTOCOL = re.compile(r"(?:HTTPS?|TLS|SSL|DTLS|QUIC|SPDY|S?FTPS?|SMTPS?|IMAPS?|POP3?|SIP|RTSP"
                      r"|AMQP|MQTT|SOCKS|SSH|SNMP|LDAPS?|SMB|CIFS|NFS|RDP|NNTP|XMPP|IRC|WEBDAV"
                      r"|GRPC|STOMP|COAPS?|ODATA|RTMPS?|AMQPS|MQTTS|WAMP|XML-?RPC|JSON-?RPC)(?:[/\\]|[-_]?v?)[0-9]+(?:\.[0-9]+)*",
                      re.IGNORECASE)
CAPS_PROTOCOL = re.compile(r"[A-Z][A-Za-z]+(?:-[A-Za-z]+)*[/\\][0-9]+(?:\.[0-9]+)+")
ROOT_FILE = re.compile(r"(?:GNU)?makefile|[A-Z][a-z]*file"
                        r"|BUILD|WORKSPACE|OWNERS|CODEOWNERS|LICENSE|LICENCE|README|VERSION|BUCK"
                        r"|CHANGELOG|CHANGES|HISTORY|NEWS|AUTHORS|CONTRIBUTORS|CONTRIBUTING"
                        r"|MAINTAINERS|NOTICE|COPYING|INSTALL|SECURITY|TODO")
# Capitalised words ending in "file" that are prose, not files.
NOT_FILES = frozenset(("Profile", "Ffile"))
# Kana, kanji and hangul: scripts written without spaces between words, so a
# number in the prose (比率は1.5:1, 約２.５：１) is glued to the word before it.
CJK = re.compile(r"[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uac00-\ud7af\uf900-\ufaff"
                 r"\uff66-\uff9f]")


def _is_host(name):
    """True for localhost, an IPv4 address or a dotted name ending in a host suffix."""
    if "/" in name or "\\" in name or name.startswith("."):
        return False
    if name.lower() == "localhost" or IPV4.fullmatch(name):
        return True
    labels = name.lower().split(".")
    if len(labels) < 2:
        return False
    if labels[-1] in HOST_SUFFIXES:
        return True
    return labels[-1] in AMBIGUOUS_HOST_SUFFIXES and (len(labels) > 2 or name == name.lower())


def _product_version(name):
    """True for a word followed by a version, whatever qualifier follows:
    Python-3.12.1rc1, OpenSSL_3.0.0-alpha, version1.2.3+build.5. Without a
    separator the number needs three or more parts (python3.11 is a file), and
    a name that ends in a letter-led extension is a file (jquery-3.6.0.min.js)."""
    match = PRODUCT_VERSION.match(name)
    if not match:
        return False
    separator, number = match.group(1), match.group(2)
    if not separator and number.count(".") < 2:
        return False
    return not _has_extension(name[match.end():])


def _has_extension(name):
    """True when name ends in an extension-shaped suffix: up to five letters
    and digits, letter first (.js, .gz, .bz2), and not a version, platform or
    distribution qualifier (.post1, .RELEASE, .el9, .win_amd64)."""
    _, dot, extension = name.rpartition(".")
    return bool(dot and EXTENSION.fullmatch(extension)
                and not QUALIFIER.fullmatch(extension))


def _protocol_version(path):
    """True for a protocol version, bare or with a draft or implementation tag
    (TLSv1.3, SMB/3.1.1, HTTP/3-draft-29, SSH-2.0-OpenSSH_9.6); a tagged name
    that ends in a letter-led extension is a file (http2-server.go)."""
    if CAPS_PROTOCOL.fullmatch(path):
        return True
    match = PROTOCOL.match(path)
    if not match:
        return False
    rest = path[match.end():]
    if not rest:
        return True
    # A tag stays within one component: http2-tests/README is a path.
    if rest[0] not in "-+_" or "/" in rest or "\\" in rest:
        return False
    _, dot, extension = rest.rpartition(".")
    return not (dot and extension[:1].isalpha())


def _number_after_prose(name):
    """True for a number written straight after kana, kanji or hangul (約2.5,
    TLSは1.3): unspaced prose, not a file name. A string walk, not a pattern, so
    a long run of digits and dots stays linear."""
    start = len(name)
    while start and (name[start - 1].isdecimal() or name[start - 1] == "."):
        start -= 1
    return (start < len(name) and start > 0 and name[start].isdecimal()
            and bool(CJK.fullmatch(name[start - 1])))


def _file_shaped(path):
    """True when path has a directory part, a dotted suffix or a root-file name."""
    if NUMERIC.fullmatch(path) or _protocol_version(path):
        return False
    directory, slash, last = path.replace("\\", "/").rpartition("/")
    if slash:
        # A package or module spec (@scope/pkg@1.2.3, golang.org/x/sync@v0.17.0)
        # is not a file unless it ends in an extension (vendor/lodash@4.17.21.tgz).
        if PACKAGE_VERSION.search(last) and not _has_extension(last):
            return False
        # . and .. name directories, not files (src/..:3).
        return last not in ("", ".", "..")
    # A root-level name needs a letter (.5, ~1.5 and 1/2-like tokens are numbers).
    if (VERSION_START.match(last) and not MIGRATION.match(last)) or not LETTER.search(last):
        return False
    if PACKAGE_VERSION.search(last) or _product_version(last) or _number_after_prose(last):
        return False
    _, dot, suffix = last.rpartition(".")
    return bool(dot and suffix) or bool(ROOT_FILE.fullmatch(last))


def _rejection(path):
    """Why a path:line candidate is not a file position, or None when it is one."""
    if "//" in path:
        return "a URL"
    if _is_host(path):
        return "a host:port"
    if "/" in path.replace("\\", "/") and path.replace("\\", "/").rsplit("/", 1)[-1] in ("", ".", ".."):
        return "a directory, not a file"
    if not _file_shaped(path) or path in NOT_FILES:
        return ("not a file name (a setting, number, version or word; write an "
                "extensionless file with its directory or ./)")
    if ABBREVIATION.fullmatch(path):
        return "an abbreviation such as N/A or I/O, not a file"
    first, _, rest = path.replace("\\", "/").partition("/")
    last = path.replace("\\", "/").rsplit("/", 1)[-1]
    if rest and "." not in last and _is_host(first):
        return "a module or host path, not a file"
    # A code member such as time.Second:30 has the same shape as a file with a
    # capitalised extension (analysis.Rmd, project.Rproj, schema.PROTO), so it is
    # not refused; the evidence rule asks for a citation, not proof of one.
    return None


def citation_rejections(text):
    """The path:line candidates in text that do not name a file, with the reason."""
    return [(match.group(0), reason) for match in CITATION.finditer(text)
            for reason in [_rejection(match.group(1))] if reason]


def cites_location(text):
    """True when text names a file position, not a URL, a host:port, a time or a ratio.

    The path must look like a file (see _file_shaped), so prose such as
    "timeout:30" or "上限：100" does not count. A service name such as
    redis:6379 does not either; an extensionless file must be written with its
    directory (src/main:40) unless its name is conventional (BUILD:10).
    """
    return any(_rejection(match.group(1)) is None for match in CITATION.finditer(text))


def resolve_path(path):
    """Resolve symbolic links, reporting a loop as an I/O error on every Python version.

    Python 3.12 and earlier raise RuntimeError; 3.13+ return the looping link
    itself, which would otherwise look like an absent file and be replaced.
    """
    try:
        resolved = Path(path).resolve()
    except RuntimeError as exc:
        raise OSError(f"cannot resolve {path}: {exc}") from exc
    if resolved.is_symlink():
        raise OSError(errno.ELOOP, f"cannot resolve {path}: symbolic link loop")
    return resolved


def file_mode(path):
    """Return st_mode, or None when the path does not exist; other errors propagate."""
    try:
        return path.stat().st_mode
    except FileNotFoundError:
        return None


def _unique_object(pairs):
    """Reject ambiguous members before the decoder can discard earlier values."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object member: {key!r}")
        result[key] = value
    return result


def _reject_constant(token):
    raise ValueError(f"non-finite JSON numeric constant: {token}")


# Exact: float() rounds integers just above the bound down instead of raising.
FLOAT_MAX_INT = int(sys.float_info.max)


def _finite_int(token):
    value = int(token)
    if abs(value) > FLOAT_MAX_INT:
        raise ValueError(f"JSON number exceeds the finite floating-point range: "
                         f"{token[:20]}...")
    return value


def _finite_float(token):
    value = float(token)
    if not math.isfinite(value):
        raise ValueError(f"JSON number exceeds the finite floating-point range: {token}")
    return value


def read_json(path):
    """Read unambiguous UTF-8 JSON from a regular file, following symbolic links."""
    try:
        source = Path(path)
        if not stat.S_ISREG(source.stat().st_mode):
            raise ValueError("input must be a regular file")
        return json.loads(source.read_text(encoding="utf-8"),
                          object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant, parse_float=_finite_float,
                          parse_int=_finite_int)
    except (OSError, ValueError, RecursionError) as exc:
        raise SchemaError(f"{path}: {exc}") from exc


def _text(value, where):
    if not isinstance(value, str) or not value.strip():
        raise SchemaError(f"{where}: must be a nonblank string")


def _optional_strings(record, keys, where):
    for key in keys:
        if key in record and not isinstance(record[key], str):
            raise SchemaError(f"{where}.{key}: must be a string")


def _show(value, limit=80):
    """Quote a value for an error message without dumping a huge or nested input."""
    text = repr(value)
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _choice(value, allowed, where):
    if value not in allowed:
        raise SchemaError(f"{where}: {_show(value)} is not one of {', '.join(allowed)}")


def _known_keys(record, allowed, where):
    unknown = set(record) - allowed
    if unknown:
        raise SchemaError(f"{where}: unknown keys {sorted(unknown)}")


def validate_finding(f, where):
    if not isinstance(f, dict):
        raise SchemaError(f"{where}: must be an object")
    _known_keys(f, FINDING_KEYS, where)
    for key in FINDING_REQUIRED:
        if key not in f:
            raise SchemaError(f"{where}: missing {key}")
    if not isinstance(f["id"], str) or not FINDING_ID.fullmatch(f["id"]):
        raise SchemaError(f"{where}.id: {_show(f['id'])} must look like P-001")
    for key in ("title", "workload", "scale_driver", "cost_model", "request",
                "impact", "fix", "regression_test"):
        _text(f[key], f"{where}.{key}")
    _optional_strings(f, ("contrast", "budget", "step"), where)
    _choice(f["severity"], SEVERITIES, f"{where}.severity")
    _choice(f["confidence"], CONFIDENCES, f"{where}.confidence")
    _choice(f["category"], PERSPECTIVES, f"{where}.category")
    _choice(f.get("status", "Open"), STATUSES, f"{where}.status")
    locations = f["location"] if isinstance(f["location"], list) else [f["location"]]
    if not locations:
        raise SchemaError(f"{where}.location: at least one path:line")
    for loc in locations:
        match = LOCATION.fullmatch(loc) if isinstance(loc, str) else None
        if match is None or not match["path"].strip():
            raise SchemaError(f"{where}.location: {_show(loc)} must be path:line")
        # Compare decimal strings without Python's integer-conversion digit limit.
        start = match["start"].lstrip("0") or "0"
        end = (match["end"] or match["start"]).lstrip("0") or "0"
        if start == "0" or (len(end), end) < (len(start), start):
            raise SchemaError(f"{where}.location: {_show(loc)} needs positive line numbers "
                              "and a range end not before its start")
    v = f["validation"]
    if not isinstance(v, dict):
        raise SchemaError(f"{where}.validation: must be an object")
    _known_keys(v, VALIDATION_KEYS, f"{where}.validation")
    _choice(v.get("verdict"), VERDICTS, f"{where}.validation.verdict")
    _choice(v.get("method"), METHODS, f"{where}.validation.method")
    if v["verdict"] in DEFINITIVE:
        _text(v.get("evidence"), f"{where}.validation.evidence ({v['verdict']} needs evidence)")
    else:
        _optional_strings(v, ("evidence",), f"{where}.validation")
    if v["method"] == "measured" and "measurement" not in f:
        raise SchemaError(f"{where}.measurement: required when validation.method is measured")
    if "measurement" in f:
        m = f["measurement"]
        if not isinstance(m, dict):
            raise SchemaError(f"{where}.measurement: must be an object")
        _known_keys(m, MEASUREMENT_KEYS, f"{where}.measurement")
        _text(m.get("environment"), f"{where}.measurement.environment")
        for run in MEASUREMENT_RUNS:
            r = m.get(run)
            if not isinstance(r, dict):
                raise SchemaError(f"{where}.measurement.{run}: must be an object "
                                  "(a measurement records both the before and the after run)")
            _known_keys(r, frozenset(RUN_KEYS), f"{where}.measurement.{run}")
            for key in RUN_KEYS:
                _text(r.get(key), f"{where}.measurement.{run}.{key}")
    references = f.get("references", [])
    if not isinstance(references, list):
        raise SchemaError(f"{where}.references: must be a list")
    for i, ref in enumerate(references):
        if not isinstance(ref, dict):
            raise SchemaError(f"{where}.references[{i}]: must be an object")
        _known_keys(ref, REFERENCE_KEYS, f"{where}.references[{i}]")
        _text(ref.get("url"), f"{where}.references[{i}].url")
        _optional_strings(ref, ("title",), f"{where}.references[{i}]")


def validate_budget(b, where, seen):
    """Check one budget; seen collects the IDs of the budgets before it."""
    if (not isinstance(b, dict) or not isinstance(b.get("id"), str)
            or not BUDGET_ID.fullmatch(b["id"])):
        raise SchemaError(f"{where}.id: must look like B-01")
    _known_keys(b, BUDGET_KEYS, where)
    if b["id"] in seen:
        raise SchemaError(f"{where}.id: duplicate {b['id']}")
    seen.add(b["id"])
    for key in ("statement", "source"):
        _text(b.get(key), f"{where}.{key}")
    if "inferred" in b and not isinstance(b["inferred"], bool):
        raise SchemaError(f"{where}.inferred: must be a boolean")
    _optional_strings(b, ("reason",), where)
    if "family" in b:
        _choice(b["family"], BUDGET_FAMILIES, f"{where}.family")
    _choice(b.get("status"), BUDGET_STATUSES, f"{where}.status")


def validate_perspective(p, where, seen):
    """Check one perspective; seen collects the names of the perspectives before it."""
    if not isinstance(p, dict):
        raise SchemaError(f"{where}: must be an object")
    _known_keys(p, PERSPECTIVE_KEYS, where)
    _choice(p.get("name"), PERSPECTIVES, f"{where}.name")
    if p["name"] in seen:
        raise SchemaError(f"{where}.name: duplicate {p['name']}")
    seen.add(p["name"])
    _choice(p.get("status"), PERSPECTIVE_STATUSES, f"{where}.status")
    _text(p.get("note"), f"{where}.note")


def validate(doc, complete=False):
    """Raise SchemaError when doc does not match reference/findings-schema.md."""
    if not isinstance(doc, dict):
        raise SchemaError("top level: must be an object")
    unknown = set(doc) - TOP_KEYS
    if unknown:
        raise SchemaError(f"top level: unknown keys {sorted(unknown)}")
    meta = doc.get("meta", {})
    if not isinstance(meta, dict):
        raise SchemaError("meta: must be an object")
    for key in META_REQUIRED:
        if complete or key in meta:
            _text(meta.get(key), f"meta.{key}")
    if "lang" in meta:
        _choice(meta["lang"], ("ja", "en"), "meta.lang")
    _optional_strings(meta, ("commit", "method"), "meta")
    for key in ("findings", "budgets", "perspectives"):
        if not isinstance(doc.get(key, []), list):
            raise SchemaError(f"{key}: must be a list")
    seen = set()
    for i, f in enumerate(doc.get("findings", [])):
        try:
            validate_finding(f, f"findings[{i}]")
        except SchemaError as exc:
            # After a merge the index is the combined record's, not the fragment's.
            if (isinstance(f, dict) and isinstance(f.get("id"), str)
                    and not str(exc).startswith(f"findings[{i}].id:")):
                raise SchemaError(f"{exc} (finding {_show(f['id'])})") from exc
            raise
        if f["id"] in seen:
            raise SchemaError(f"findings[{i}].id: duplicate {f['id']}")
        seen.add(f["id"])
    seen = set()
    for i, b in enumerate(doc.get("budgets", [])):
        with _named(b, "id", "budget"):
            validate_budget(b, f"budgets[{i}]", seen)
    seen = set()
    for i, p in enumerate(doc.get("perspectives", [])):
        with _named(p, "name", "perspective"):
            validate_perspective(p, f"perspectives[{i}]", seen)
    for key in LISTS:
        values = doc.get(key, [])
        if not isinstance(values, list):
            raise SchemaError(f"{key}: must be a list")
        for i, value in enumerate(values):
            _text(value, f"{key}[{i}]")


@contextlib.contextmanager
def _named(record, key, kind):
    """Name the record in an error: after a merge the index is the combined
    record's, not the fragment's."""
    try:
        yield
    except SchemaError as exc:
        name = record.get(key) if isinstance(record, dict) else None
        if isinstance(name, str) and f".{key}:" not in str(exc):
            raise SchemaError(f"{exc} ({kind} {_show(name)})") from exc
        raise


def _record_identity(record, key, where):
    if not isinstance(record, dict):
        raise SchemaError(f"{where}: must be an object")
    value = record.get(key)
    _text(value, f"{where}.{key}")
    return value


def _merge_records(current, incoming, key, where):
    ids = [_record_identity(record, key, f"{where}[{i}]")
           for i, record in enumerate(incoming)]
    if len(set(ids)) != len(ids):
        raise SchemaError(f"{where}: every record needs a unique {key}")
    index = {r[key]: r for r in current}
    for record in incoming:
        if record[key] in index:
            index[record[key]].update(record)
        else:
            current.append(dict(record))
            index[record[key]] = current[-1]


def _replace_perspectives(doc, incoming, where):
    """A perspective is replaced whole: drop the recorded one of that name, then append."""
    for i, p in enumerate(incoming):
        name = _record_identity(p, "name", f"{where}[{i}]")
        doc.setdefault("perspectives", [])
        doc["perspectives"] = [q for q in doc["perspectives"] if q.get("name") != name]
        doc["perspectives"].append(p)


def merge(doc, fragment, where):
    if not isinstance(fragment, dict):
        raise SchemaError(f"{where}: must be an object")
    unknown = set(fragment) - TOP_KEYS
    if unknown:
        raise SchemaError(f"{where}: unknown keys {sorted(unknown)}")
    if "meta" in fragment:
        if not isinstance(fragment["meta"], dict):
            raise SchemaError(f"{where}.meta: must be an object")
        doc.setdefault("meta", {}).update(fragment["meta"])
    for key in ("findings", "budgets", "perspectives"):
        if key in fragment:
            if not isinstance(fragment[key], list):
                raise SchemaError(f"{where}.{key}: must be a list")
            if key == "perspectives":
                _replace_perspectives(doc, fragment[key], f"{where}.{key}")
            else:
                _merge_records(doc.setdefault(key, []), fragment[key], "id", f"{where}.{key}")
    for key in LISTS:
        if key in fragment:
            if not isinstance(fragment[key], list):
                raise SchemaError(f"{where}.{key}: must be a list")
            target = doc.setdefault(key, [])
            seen = set(target)  # A list scan per item made large merges quadratic.
            for i, value in enumerate(fragment[key]):
                _text(value, f"{where}.{key}[{i}]")
                if value not in seen:
                    seen.add(value)
                    target.append(value)
    return doc


def write_atomic(target, content):
    """Replace a resolved target only after all bytes have been written and closed."""
    mode = file_mode(target)
    mode = None if mode is None else stat.S_IMODE(mode)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=target.parent,
                                         prefix=f".{target.name}.", suffix=".tmp",
                                         delete=False) as output:
            temporary = Path(output.name)
            output.write(content)
            # Durable before the rename: after a crash the record is the old
            # bytes or the new ones, never an empty file.
            output.flush()
            os.fsync(output.fileno())
        if mode is not None:
            temporary.chmod(mode)
        os.replace(temporary, target)
        temporary = None
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError as exc:
                print(f"cleanup: {temporary}: {exc}", file=sys.stderr)


def cmd_merge(args):
    target = Path(args.findings)
    try:
        # Keep the existing behavior of reading and updating a symlink's destination.
        destination = resolve_path(target)
        doc = read_json(destination) if file_mode(destination) is not None else {}
        try:
            validate(doc)
        except SchemaError as exc:
            raise SchemaError(f"{target}: {exc}") from exc
        for path in args.fragments:
            merge(doc, read_json(path), path)
            # Validate per fragment: a finding must be complete where it first appears.
            try:
                validate(doc)
            except SchemaError as exc:
                raise SchemaError(f"{path}: {exc}") from exc
        content = (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        # FINDINGS is created when absent, together with its directory.
        destination.parent.mkdir(parents=True, exist_ok=True)
        write_atomic(destination, content)
    except (SchemaError, OSError, UnicodeError, RecursionError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    print(f"merged {len(args.fragments)} fragment(s) into {target}: "
          f"{len(doc.get('findings', []))} finding(s)")
    return 0


def _output_problems(out, present, allow):
    """Return the problems with the directory's entries and the readable outputs."""
    problems = []
    for name in sorted(OUTPUTS - present):
        problems.append(f"missing output: {name}")
    for name in sorted(present - OUTPUTS - set(allow)):
        if name.isprintable():
            problems.append(f"unexpected output: {name} (pass --allow {name} if requested)")
        else:
            # One line per problem: quote a name holding a line break or another
            # unprintable character. Its escaped form is not a usable --allow value.
            problems.append(f"unexpected output: {name!r} (rename or remove it)")
    readable = set()
    for name in sorted(OUTPUTS & present):
        path = out / name
        try:
            # Follow valid symlinks, but never open a FIFO or device as a report.
            if not stat.S_ISREG(path.stat().st_mode):
                problems.append(f"invalid output: {name} (must be a regular file)")
                continue
            with path.open("rb") as source:
                if not source.read(1):
                    problems.append(f"empty output: {name}")
                    continue
        except OSError as exc:
            problems.append(f"unreadable output: {name}: {exc}")
            continue
        readable.add(name)
    return problems, readable


def _order_problems(findings):
    """IDs are gapless, included findings run High first and excluded ones come last."""
    problems = []
    expected = [f"P-{i:03d}" for i in range(1, len(findings) + 1)]
    if [f["id"] for f in findings] != expected:
        problems.append(f"IDs must be gapless in order: expected {', '.join(expected) or 'none'}"
                        " (rebuild findings.json from fragments that carry the final IDs)")
    included = [f for f in findings if f["validation"]["verdict"] not in EXCLUDED]
    for before, after in zip(included, included[1:]):
        if SEVERITIES.index(after["severity"]) < SEVERITIES.index(before["severity"]):
            problems.append("findings must be numbered in severity order (High first): "
                            f"{after['id']} ({after['severity']}) follows "
                            f"{before['id']} ({before['severity']})")
            break
    seen_excluded = None
    for f in findings:
        if f["validation"]["verdict"] in EXCLUDED:
            seen_excluded = seen_excluded or f["id"]
        elif seen_excluded:
            problems.append(f"{f['id']}: excluded findings ({seen_excluded}) must be numbered "
                            "after all others")
            break
    return problems


def _record_problems(doc):
    """Evidence, perspective coverage, budget cross-references and required lists."""
    problems = []
    findings = doc.get("findings", [])
    statuses = {p["name"]: p["status"] for p in doc.get("perspectives", [])}
    for f in findings:
        v = f["validation"]
        if v["verdict"] in DEFINITIVE and not cites_location(v["evidence"]):
            rejected = "; ".join(f"{_show(candidate, 40)} is {reason}" for candidate, reason
                                 in citation_rejections(v["evidence"])[:3])
            problems.append(f"{f['id']}.validation.evidence: {v['verdict']} evidence must "
                            "cite a path:line" + (f" ({rejected})" if rejected else ""))
        # A Likely High or Medium names its unconfirmed link here (SKILL.md "Done when").
        elif f["severity"] in ("High", "Medium") and not v.get("evidence", "").strip():
            problems.append(f"{f['id']}.validation.evidence: a {f['severity']} finding needs "
                            f"evidence, even when {v['verdict']}")
        step = f.get("step", "")
        if step.strip() and step not in HUNT_STEPS:
            problems.append(f"{f['id']}.step: {_show(step)} is not a hunt step in "
                            "reference/perspectives.md")
        elif step in HUNT_STEPS and STEP_PERSPECTIVES[step] != f["category"]:
            problems.append(f"{f['id']}.step: {step} is a hunt step of "
                            f"{STEP_PERSPECTIVES[step]}, not of the category {f['category']}")
        # The perspective that surfaced an included finding was applied.
        status = statuses.get(f["category"], "applied")
        if status != "applied" and v["verdict"] not in EXCLUDED:
            problems.append(f"{f['id']}.category: {f['category']} is recorded {status}, but "
                            "this finding came from it; record the perspective applied")
        if f["confidence"] == "Suspected" and v["verdict"] == "Valid":
            problems.append(f"{f['id']}: a Suspected finding cannot be Valid; confirm the "
                            "code link (Confirmed or Environment-dependent) or record Likely")
    recorded = {p["name"] for p in doc.get("perspectives", [])}
    for name in PERSPECTIVES:
        if name not in recorded:
            problems.append(f"perspective not recorded: {name}")
    budget_ids = set()
    for b in doc.get("budgets", []):
        budget_ids.add(b["id"])
        if b["status"] == "not checked" and not b.get("reason", "").strip():
            problems.append(f"{b['id']}: a not-checked budget needs a reason")
    holding = {b["id"] for b in doc.get("budgets", []) if b["status"] == "holds"}
    for f in findings:
        # Further violated budgets are named in impact; they must exist too.
        mentioned = set(BUDGET_MENTION.findall(f["impact"]))
        for named in sorted(mentioned - budget_ids):
            problems.append(f"{f['id']}.impact: {named} is not in budgets")
        budget = f.get("budget", "")
        if budget.strip() and budget not in budget_ids:
            problems.append(f"{f['id']}.budget: {_show(budget)} is not in budgets")
        # Every budget the finding violates, in budget or named in impact.
        violated = sorted(({budget} if budget in budget_ids else set())
                          | (mentioned & budget_ids))
        if f.get("status", "Open") != "Fixed" and f["validation"]["verdict"] == "Valid":
            for held in (b for b in violated if b in holding):
                problems.append(f"{held}: status holds, but {f['id']} is a Valid, unfixed "
                                "violation of it")
    if not doc.get("limitations"):
        problems.append("limitations: state what static reading cannot show")
    if not doc.get("checked_ok"):
        problems.append("checked_ok: list what was examined and held")
    return problems


def contract_problems(out, allow=()):
    """Return the run-contract violations for an output directory."""
    out = Path(out)
    try:
        if not out.is_dir():
            return [f"not a directory: {out}"]
        present = {p.name for p in out.iterdir()}
    except OSError as exc:
        return [f"cannot inspect output directory: {out}: {exc}"]
    problems, readable = _output_problems(out, present, allow)
    if "findings.json" not in readable:
        return problems
    try:
        doc = read_json(out / "findings.json")
        validate(doc, complete=True)
        # A "\ud800" escape decodes to a lone surrogate that render cannot encode.
        json.dumps(doc, ensure_ascii=False).encode("utf-8")
    except (SchemaError, UnicodeError) as exc:
        return problems + [f"findings.json: {exc}"]
    return problems + _order_problems(doc.get("findings", [])) + _record_problems(doc)


def cmd_check(args):
    problems = contract_problems(args.out, args.allow)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    print(f"contract ok: {args.out}")
    return 0


def escape_unencodable_console():
    """A path the console encoding cannot show must not turn a completed command
    into a traceback and exit 1."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("merge", help="merge fragments into findings.json")
    m.add_argument("findings")
    m.add_argument("fragments", nargs="+")
    m.set_defaults(func=cmd_merge)
    c = sub.add_parser("check", help="check the run contract of an output directory")
    c.add_argument("out")
    c.add_argument("--allow", action="append", default=[])
    c.set_defaults(func=cmd_check)
    args = parser.parse_args(argv)
    escape_unencodable_console()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
