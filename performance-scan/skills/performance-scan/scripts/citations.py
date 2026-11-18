"""Tell a path:line citation from look-alikes in validation evidence.

`findings.py check` requires the evidence of a definitive verdict to cite a
file position. This module decides, by shape alone, whether a `name:42` or
`name#L42` candidate names a file, and when not, says why (a URL, a host:port,
a number, a version, a protocol, a word). The rules are listed for authors in
`reference/findings-schema.md` (`validation.verdict`).

Standard library only; no I/O.
"""
import re

# Evidence for a definitive verdict cites at least one path:line (or path#L42).
# The lookbehind starts a match only at the beginning of a run: without it a long
# run with no colon is retried from every position (quadratic time). CJK
# punctuation separates too: unspaced prose (比は2:1、app/views.py:18) has no
# other boundary before a path.
CITATION = re.compile(r"(?<![^\s:：#()\[\]'\"`,;<>、。，；（）「」『』【】])"
                      r"([^\s:：#()\[\]'\"`,;<>、。，；（）「」『』【】]+)(?:[:：]|#L)[1-9１-９][0-9０-９]*")

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
