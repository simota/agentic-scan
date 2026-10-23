#!/usr/bin/env python3
"""Inventory removal candidates in a repository: candidates for review, never findings.

    python3 inventory.py REPO --out inventory.json [--units units.json] [--today YYYY-MM-DD]

Collects, best effort and by name only: top-level symbols (Python, JS/TS, Go,
Rust) with no reference outside their definition, source files nothing imports
or names, declared dependencies never imported (package.json, requirements*.txt,
pyproject.toml, go.mod, Cargo.toml), dependencies sharing a purpose or
replaceable by the platform, environment variables read versus declared,
feature flags with their values and checks, locale keys never referenced,
asset files and CSS classes never named, routes nothing names, Makefile targets
and package scripts nothing invokes, unreferenced scripts, SQL and docs,
skipped tests, commented-out code blocks, deprecation and removal markers with
dates, and SQL tables and columns no code names. With --units, every row is
tagged with the review unit whose path covers it. Never prints the value of an
environment variable. Read-only, standard library only (reference/inventory.md).
Exit status: 0 written, 2 bad arguments (including --out inside the repository) or unreadable
repository/units, 1 output not written.
"""

import argparse
import ast
import datetime
import json
import os
import re
import stat
import sys
from array import array
from bisect import bisect_left
from collections import Counter, defaultdict
from contextlib import ExitStack, contextmanager
from functools import lru_cache
from itertools import islice
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import RecordError, check_units, parse_json  # noqa: E402
from safe_output import SAFE_OUTPUT, tolerant_stdout, write_output_at  # noqa: E402
from safe_paths import open_directory, within  # noqa: E402
from safe_source import physical_lines, sensitive_source  # noqa: E402
from scan_report_kit.output import write_output  # noqa: E402

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "out", ".next", ".nuxt",
             ".svelte-kit", "coverage", ".venv", "venv", "__pycache__", "Pods", ".gradle", "target",
             ".turbo", ".cache", "bower_components", ".idea", ".vscode", "DerivedData", ".dart_tool",
             "storybook-static", ".output", ".tox", ".mypy_cache", ".pytest_cache", "site-packages"}
# `env` is a common virtualenv name and an equally common source directory
# (src/env/schema.mjs); it is skipped only when it holds a virtualenv.
VENV_DIRS = {"env"}
VENV_MARKERS = ("pyvenv.cfg", "bin/activate", "Scripts/activate", "conda-meta")
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock", "poetry.lock", "Gemfile.lock",
              "go.sum", "composer.lock", "Podfile.lock", "pubspec.lock", "bun.lockb", "bun.lock", "uv.lock",
              "npm-shrinkwrap.json", "Pipfile.lock"}
SECRET_FILE = re.compile(r"(?i)^(?:\.env(?:\.(?!example$|sample$|template$|dist$)[\w.-]+)?|.*\.(?:pem|key|p12|pfx|jks|"
                         r"keystore)|id_(?:[rd]sa|ecdsa|ed25519|xmss).*|\.netrc|\.npmrc|\.pypirc|"
                         r"\.htpasswd|\.pgpass|\.dockercfg|.*\.tfstate(?:\..*)?|.*\.kdbx)$")
# Credential files known by their directory: the rest of .docker/ (a Dockerfile) is ordinary.
SECRET_PATH = re.compile(r"(?i)(?:^|/)(?:\.docker/config\.json[^/]*|\.kube/.*)$")
# Data files named like this hold secrets. Source code named like this
# (useCredentials.ts, client_secret.py) is read for imports and identifiers
# so its dependencies are not reported unused, but none of its literal text is
# exported: no excerpts, flag names, routes or dynamic key and class prefixes.
SECRET_NAMED = re.compile(r"(?i)^(?:.*credentials.*|.*secrets?(?:\..*)?|kubeconfig.*)$")
ENV_DECL_FILE = re.compile(r"(?i)^(?:\.env\.(?:example|sample|template|dist)|example\.env|env\.example)$")
MAX_BYTES = 2 * 1024 * 1024
MAX_LOCATIONS = 5
MAX_ROWS = 200
SAFE_DIR_OPEN = os.open in os.supports_dir_fd and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW")

PY_EXT = {".py"}
JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".mjs", ".cjs", ".vue", ".svelte"}
GO_EXT = {".go"}
RS_EXT = {".rs"}
SOURCE_EXT = PY_EXT | JS_EXT | GO_EXT | RS_EXT | {".rb", ".java", ".kt", ".swift", ".php", ".cs", ".scala"}
CSS_EXT = {".css", ".scss", ".sass", ".less", ".styl", ".pcss"}
PROSE_EXT = {".md", ".rst", ".txt", ".adoc"}
ASSET_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".bmp", ".svg", ".woff", ".woff2", ".ttf",
             ".otf", ".eot", ".mp4", ".webm", ".mov", ".mp3", ".wav", ".ogg", ".pdf"}
LOOSE_EXT = {".sh", ".bash", ".zsh", ".ps1", ".sql", ".md", ".rst", ".txt"}
LOOSE_DIRS = {"scripts", "bin", "tools", "docs", "doc", "db", "seeds", "seed", "fixtures", "sql"}
ROOT_DOCS = {"readme", "changelog", "license", "licence", "contributing", "security", "claude", "agents",
             "code_of_conduct", "notice", "authors", "history", "requirements", "codeowners"}
ENTRY_STEMS = {"main", "index", "app", "__init__", "__main__", "setup", "manage", "conftest", "wsgi", "asgi",
               "server", "cli", "lib", "mod", "build", "worker"}
# Include extensionless .mts/.cts imports accepted by some bundlers, beyond tsc's resolver.
JS_RESOLVE_EXT = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte", ".json", ".mts", ".cts")
# Keep extensionless file and directory imports consistent for every supported source type.
JS_RESOLVE = ("", *JS_RESOLVE_EXT, *("/index" + ext for ext in JS_RESOLVE_EXT))
# TypeScript source imports name the emitted JavaScript files in Node's ESM modes.
JS_SUBSTITUTIONS = {".js": (".ts", ".tsx", ".d.ts", ".js", ".jsx"),
                    ".jsx": (".tsx", ".d.ts", ".jsx"),
                    ".mjs": (".mts", ".d.mts", ".mjs"), ".cjs": (".cts", ".d.cts", ".cjs")}
TEST_PATH = re.compile(r"(?i)(?:^|/)(?:tests?|__tests__|spec|e2e)/|(?:^|/)test_[^/]+$|_test\.\w+$|"
                       r"\.(?:test|spec)\.\w+$")
LOCALE_DIR = re.compile(r"(?i)(?:^|/)(?:locales?|i18n|l10n|lang|langs|languages|translations|messages)(?:/|$)")
LANG = re.compile(r"^[a-z]{2,3}(?:[-_][A-Za-z]{2,4})?$")

IDENT = re.compile(r"[A-Za-z_$][\w$]*")
CSS_TOKEN = re.compile(r"[A-Za-z_][\w-]*")
# A failed extension match must not retry at every suffix of a long token.
FILE_TOKEN = re.compile(r"(?<![\w.@+~-])[\w.@+~-]+\.\w+")  # logo@2x.png, icon~dark.svg
QUOTED = re.compile(r"[\"'`]([A-Za-z0-9_][\w.-]*)[\"'`]")
# Any short single-line literal: natural-language keys ("Delete item") and
# namespaced lookups ("common:save") are locale keys too.
STRING_LITERAL = re.compile(r"\"([^\"\\\n]{1,200})\"|'([^'\\\n]{1,200})'|`([^`\\$\n]{1,200})`")
PYTHON_MODULE_RUN = re.compile(r"\bpython[\d.]*\s+(?:-\w+\s+)*-m\s+([A-Za-z_]\w*(?:\.\w+)*)")
# Dotted module paths loaded by name: "mysite.urls" (ROOT_URLCONF), "polls.apps.PollsConfig"
# (INSTALLED_APPS), "pkg.mod:app" and an unquoted gunicorn/uvicorn pkg.mod:app.
PYTHON_MODULE_STRING = re.compile(r"[\"']([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)(?::[A-Za-z_]\w*)?[\"']|"
                                  r"(?<![\w.:/-])([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+):[A-Za-z_]\w*(?![\w.:/-])")
# "config.json" and "logo.png" name files, not modules (named_in covers those).
NOT_MODULE_SUFFIX = {"json", "yaml", "yml", "toml", "ini", "cfg", "conf", "txt", "md", "rst", "html", "htm", "css",
                     "scss", "less", "js", "jsx", "mjs", "cjs", "ts", "tsx", "vue", "py", "pyi", "sh", "sql", "csv",
                     "xml", "lock", "log", "env", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "woff", "woff2",
                     "ttf", "pdf", "zip", "gz", "tar", "example", "sample", "local"}
CSS_IMPORT = re.compile(r"@(?:import|use|forward)\s+(?:url\(\s*)?[\"']~?([^\"'()\s]+)[\"']")
DYNAMIC_KEY = re.compile(r"`([\w-]+(?:\.[\w-]+)*\.)\$\{")
DYNAMIC_CLASS = re.compile(r"(?<![\w-])([A-Za-z_][\w-]*-)\$\{")
CONCAT_CLASS = re.compile(r"[\"']([A-Za-z_][\w-]*-)[\"']\s*\+")

PY_DEF = re.compile(r"^(?:async\s+)?def\s+([A-Za-z_]\w*)|^class\s+([A-Za-z_]\w*)|^([A-Z][A-Z0-9_]+)\s*(?::[^=\n]+)?=(?!=)",
                    re.M)
JS_DEF = re.compile(r"^export\s+(?:declare\s+)?(?:async\s+)?(?:function\*?|class|const|let|var|type|interface|enum|"
                    r"abstract\s+class)\s+([A-Za-z_$][\w$]*)|^(?:async\s+)?function\*?\s+([A-Za-z_$][\w$]*)|"
                    r"^(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=", re.M)
# Methods (func (h *handler) ServeHTTP) satisfy interfaces and are called through them, not by name.
GO_DEF = re.compile(r"^func\s+([A-Za-z_]\w*)|^type\s+([A-Za-z_]\w*)", re.M)
RS_DEF = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:fn|struct|enum|trait)\s+([A-Za-z_]\w*)", re.M)
MODIFIERS = {"export", "default", "declare", "async", "abstract"}
ENTRY_SYMBOLS = {"main", "init", "setup", "teardown", "handler", "default", "__all__", "__version__"}

PY_IMPORT = re.compile(r"^[^\S\r\n]*import\s+([\w.]+(?:\s+as\s+\w+)?(?:\s*,\s*[\w.]+(?:\s+as\s+\w+)?)*)", re.M)
PY_FROM = re.compile(r"^[^\S\r\n]*from\s+(\.*)([\w.]*)\s+import\s+(\((?:#[^\n]*(?:\n|$)|[^)#])*\)|[^\n#]+)", re.M)
JS_IMPORT_START = re.compile(r"\b(?:import|export|require)\b")
# Non-ASCII binding names remain opaque; ASCII operators delimit separate tokens.
JS_BINDING_NAME = re.compile(r"(?:[$\w]+|[^\x00-\x7f\s\ufeff]+|\\u(?:[0-9a-fA-F]{4}|\{[0-9a-fA-F]+\}))+")
JS_QUOTE_OR_ESCAPE = re.compile(r"\\[\s\S]|['\"]")
JS_SPACE = re.compile(r"[\s\ufeff]+")
JS_LINE_END = re.compile(r"[\r\n\u2028\u2029]")
GO_PATH = re.compile(r"[\w.+~\-/]+\Z")
GO_ESCAPE = re.compile(r"\\([0-7]{3}|x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|.)")
GO_SIMPLE_ESCAPES = dict(zip("abfnrtv\\\"'", (b"\a", b"\b", b"\f", b"\n", b"\r", b"\t", b"\v", b"\\", b'"', b"'")))
RS_USE = re.compile(r"\b(?:use|extern\s+crate)\s+([A-Za-z_]\w*)|\b([A-Za-z_]\w*)::")

ENV_READ = re.compile(
    r"process\.env\.([A-Z_][A-Z0-9_]*)|process\.env\[\s*[\"']([A-Z_][A-Z0-9_]*)[\"']\s*\]|"
    r"import\.meta\.env\.([A-Z_][A-Z0-9_]*)|(?:\bos\.|(?<![\w.]))environ\[\s*[\"']([A-Z_][A-Z0-9_]*)[\"']\s*\]|"
    r"(?:\bos\.|(?<![\w.]))environ\.get\(\s*[\"']([A-Z_][A-Z0-9_]*)[\"']|"
    r"(?:\bos\.|(?<![\w.]))getenv\(\s*[\"']([A-Z_][A-Z0-9_]*)[\"']|"
    r"Deno\.env\.get\(\s*[\"']([A-Z_][A-Z0-9_]*)[\"']|os\.(?:Getenv|LookupEnv)\(\s*\"([A-Z_][A-Z0-9_]*)\"|"
    r"env::var(?:_os)?\(\s*\"([A-Z_][A-Z0-9_]*)\"|ENV(?:\.fetch\(|\[)\s*[\"']([A-Z_][A-Z0-9_]*)[\"']|"
    r"System\.getenv\(\s*\"([A-Z_][A-Z0-9_]*)\"")
# const { PORT = 3000, DATABASE_URL: url } = process.env reads each key it names.
ENV_DESTRUCTURE = re.compile(r"\{([^{}]*)\}\s*=\s*(?:process|import\.meta)\.env\b(?!\s*[.\[])")
ENV_DESTRUCTURED_KEY = re.compile(r"(?:^|,)\s*([A-Z_][A-Z0-9_]*)\s*(?=[=:,]|\Z)")
ENV_DECL = re.compile(r"^[^\S\r\n]*(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*=", re.M)
FLAG_CHECK = re.compile(r"\b(?:isEnabled|is_enabled|isFeatureEnabled|is_feature_enabled|featureEnabled|"
                        r"feature_enabled|flag_enabled|useFlag|useFeature|useFeatureFlag|useFeatureIsOn|getFlag|"
                        r"get_flag|variation|boolVariation|isOn|is_on|active\?)\(\s*[\"'`:]([\w.-]+)[\"'`]?")
FLAG_FILE = re.compile(r"(?i)(?:^|/)(?:feature[-_]?)?(?:flags?|features|toggles|experiments)\.(?:py|ts|tsx|js|mjs|"
                       r"json|ya?ml|toml)$")
FLAG_DEF = re.compile(r"^[^\S\r\n]*(?:(?:export\s+)?(?:const|let|var)\s+)?[\"']?([A-Za-z][\w.-]*)[\"']?"
                      r"\s*(?::\s*boolean\s*)?[:=]\s*(true|false|True|False|on|off)\b", re.M)
ENV_FLAG = re.compile(r"^(?:FEATURE|FF|ENABLE|FLAG)_[A-Z0-9_]+$")
ROUTE_DEFS = (
    ("server", re.compile(r"@\w+(?:\.\w+)*\.(route|get|post|put|patch|delete|api_route|websocket)\(\s*[\"']([^\"']*)[\"']")),
    ("server", re.compile(r"\b(?:app|router|server|api|routes)\.(get|post|put|patch|delete|all|head|options)\(\s*"
                          r"[\"'`](/[^\"'`]*)[\"'`]")),
    ("server", re.compile(r"\b(re_path|path)\(\s*r?[\"']([^\"']*)[\"']\s*,")),
    ("client", re.compile(r"<(Route)\b[^>]*?\bpath\s*=\s*[\"']([^\"']+)[\"']")),
    ("client", re.compile(r"\b(path)\s*:\s*[\"'](/[^\"']*)[\"']")),
)
PARAM = re.compile(r"<[^>]+>|:[A-Za-z_]\w*\??|\{[^}]+\}|\[[^\]]+\]|\*\w*|\(\?P<[^>]+>[^)]*\)")
# A rule may name several targets (clean distclean:); each is a target.
# Directive lines (export CC ::= gcc, override X: y) and ::= assignments are not rules.
MAKE_TARGET = re.compile(r"^(?!(?:export|unexport|override|private|undefine|vpath)[^\S\n])"
                         r"([A-Za-z0-9][\w.-]*(?:[^\S\n]+[\w.-]+)*)[^\S\n]*:(?!:*=)", re.M)
# A define ... endef body is a variable's text, not rules.
MAKE_DEFINE = re.compile(r"^[^\S\n]*(?:override[^\S\n]+)?define\b[\s\S]*?(?:^[^\S\n]*endef\b|\Z)", re.M)
# Targets end on a non-space character, so trailing blanks are matched once.
MAKE_INCLUDE = re.compile(r"^[^\S\n]*-?s?include[^\S\n]+([^#\n]+)", re.M)
MAKE_RULE = re.compile(r"^([^\s#:=](?:[^:=\n]*[^\s:=])?)[^\S\n]*::?(?!=)[^\S\n]*([^;#\n]*)", re.M)
NPM_LIFECYCLES = {"preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare",
                  "prepublishOnly", "prepack", "postpack", "publish", "postpublish", "dependencies",
                  "preversion", "version", "postversion"}
SKIPPED_TEST = re.compile(r"@pytest\.mark\.skip(?:if)?\b|@unittest\.skip\w*|\bpytest\.skip\(|"
                          r"\b(?:it|test|describe|context)\.(?:skip|todo)\(|\bx(?:it|describe|test)\(|#\[ignore\]|"
                          r"\bt\.Skip(?:f|Now)?\(|@Disabled\b|@Ignore\b|\bskip\(\s*[\"']")
# Line comments per language: `#` starts a Rust attribute, a JS private field
# or a CSS id selector, so each extension only gets its own comment syntax.
HASH_COMMENT = re.compile(r"^\s*#\s?(.*)$")
SLASH_COMMENT = re.compile(r"^\s*//\s?(.*)$")
COMMENT_LINE = {
    **dict.fromkeys((".py", ".rb", ".sh", ".yml", ".yaml", ".toml"), HASH_COMMENT),
    **dict.fromkeys(JS_EXT | GO_EXT | RS_EXT | {".java", ".kt", ".swift", ".cs", ".scala", ".scss", ".sass",
                                                 ".less", ".styl"}, SLASH_COMMENT),
    ".php": re.compile(r"^\s*(?:#(?!\[)|//)\s?(.*)$"),  # #[...] is a PHP 8 attribute.
    ".sql": re.compile(r"^\s*(?:--|#)\s?(.*)$"),  # # is MySQL's line comment.
}
CODE_LIKE = re.compile(r"[;{}()=\[\]]|^\s*(?:def|return|import|from|if|elif|else|for|while|class|const|let|var|"
                       r"function|await|async|try|except|raise|throw|SELECT|INSERT|UPDATE)\b")
MARKER = re.compile(r"(?i)\b(TODO|FIXME|HACK|XXX|deprecated|remove (?:after|by|once|when|in)|temporary|sunset|ended|"
                    r"until)\b")
ALWAYS_MARKERS = {"deprecated", "sunset"}
DATE = re.compile(r"\b(20[0-9]{2}-(?:0[1-9]|1[0-2])(?:-(?:0[1-9]|[12][0-9]|3[01]))?)\b")
CREATE_TABLE_START = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:[`\"\[]?\w+[`\"\]]?\.)?"
                                r"[`\"\[]?(\w+)[`\"\]]?\s*\(", re.I)
# Fallback end of a body: ")" then table options without parentheses or quotes, then ";".
CREATE_TABLE_END = re.compile(r"\)[^;()'\"]*;")
# Inside a table body: quoted text, comments and the parentheses that nest or end it.
# Strings take MySQL's backslash escapes (DEFAULT 'can\'t)') as well as '', and
# end at their line: where a backslash is literal (PostgreSQL's 'C:\'), a misread
# string costs the rest of one line, not every table after it. An unfinished
# block comment runs to the end, so no suffix is searched twice.
SQL_BODY_TOKEN = re.compile(r"'(?:[^'\\\n]|\\.?|'')*(?:'|$)|\"[^\"\n]*(?:\"|$)|`[^`\n]*(?:`|$)|(?:--|#)[^\n]*|"
                            r"/\*[\s\S]*?(?:\*/|\Z)|[()]", re.M)
# Quoted identifiers ("it's", `o'clock`) are passed over; strings and comments are blanked.
SQL_BLANK_TOKEN = re.compile(r"\"[^\"\n]*\"|`[^`\n]*`|'|(?:--|#)[^\n]*|/\*[\s\S]*?(?:\*/|\Z)")
SQL_ESCAPED_STRING = re.compile(r"'(?:[^'\\\n]|\\[^\n]|'')*'")
SQL_LITERAL_STRING = re.compile(r"'(?:[^'\n]|'')*'")
SQL_CONSTRAINT = {"primary", "foreign", "unique", "constraint", "check", "key", "index"}

DUPLICATE_GROUPS = {
    "javascript": {
        "dates": {"moment", "dayjs", "date-fns", "luxon", "moment-timezone"},
        "http client (JS)": {"axios", "node-fetch", "got", "superagent", "request", "ky", "cross-fetch",
                             "isomorphic-fetch", "undici"},
        "utility belt": {"lodash", "lodash-es", "underscore", "ramda"},
        "test runner (JS)": {"jest", "vitest", "mocha", "ava", "jasmine"},
        "uuid": {"uuid", "nanoid", "shortid"},
        "class names": {"classnames", "clsx"},
    },
    "python": {
        "http client (Python)": {"requests", "httpx", "urllib3", "aiohttp"},
        "json (Python)": {"simplejson", "ujson", "orjson", "rapidjson"},
        "test runner (Python)": {"pytest", "nose", "nose2"},
    },
}
PLATFORM_REPLACEABLE = {
    "javascript": {
        "node-fetch": "global fetch (Node 18+)", "cross-fetch": "global fetch", "isomorphic-fetch": "global fetch",
        "left-pad": "String.prototype.padStart", "object-assign": "Object.assign", "es6-promise": "native Promise",
        "uuid": "crypto.randomUUID()", "array-includes": "Array.prototype.includes",
        "abort-controller": "global AbortController",
    },
    "python": {
        "six": "Python 3 only code", "mock": "unittest.mock", "futures": "concurrent.futures", "enum34": "enum",
        "pathlib2": "pathlib", "typing": "typing (stdlib)", "dataclasses": "dataclasses (stdlib, 3.7+)",
        "simplejson": "json", "importlib-metadata": "importlib.metadata (3.8+)", "backports.zoneinfo": "zoneinfo (3.9+)",
        "pytz": "zoneinfo (3.9+)",
    },
}
PY_MODULE_NAMES = {"pyyaml": "yaml", "beautifulsoup4": "bs4", "pillow": "PIL", "python-dateutil": "dateutil",
                   "scikit-learn": "sklearn", "opencv-python": "cv2", "opencv-python-headless": "cv2",
                   "attrs": "attr", "psycopg2-binary": "psycopg2", "python-dotenv": "dotenv", "protobuf": "google",
                   "python-jose": "jose", "pyjwt": "jwt", "python-multipart": "multipart", "msgpack-python": "msgpack",
                   "mysqlclient": "MySQLdb", "pymongo": "pymongo", "google-cloud-storage": "google",
                   "djangorestframework": "rest_framework", "typing-extensions": "typing_extensions",
                   "importlib-metadata": "importlib_metadata", "backports.zoneinfo": "backports",
                   "opentelemetry-api": "opentelemetry"}
IMPLICIT_TOOLS = re.compile(r"^(?:typescript|tslib|ts-node|prettier|postcss|autoprefixer|tailwindcss|eslint(?:-.*)?|"
                            r"@types/.*|@babel/.*|babel-.*|@eslint/.*|@typescript-eslint/.*|eslint-plugin-.*|"
                            r"eslint-config-.*|stylelint.*|husky|lint-staged|mypy|ruff|black|flake8|isort|pylint|"
                            r"types-.*|coverage|pre-commit|wheel|setuptools|pip)$")
TOOL_FILES = re.compile(r"(?i)(?:^|/)(?:Makefile|Dockerfile[\w.-]*|Procfile|justfile|Taskfile\.ya?ml|tox\.ini|setup\.cfg|"
                        r"pyproject\.toml|package\.json|[\w.-]*\.config\.(?:js|cjs|mjs|ts)|\.[\w-]*rc(?:\.\w+)?|"
                        r"[\w.-]+\.ya?ml|[\w.-]+\.sh|noxfile\.py|conftest\.py|setup\.py)$")


def is_virtualenv(name, exists):
    return name in VENV_DIRS and any(exists(f"{name}/{marker}") for marker in VENV_MARKERS)


def iter_files(root, *, directory=None):
    if directory is not None:
        # Walk the same pinned repository used by open_source, even if its pathname is replaced.
        for dirpath, dirnames, filenames, dir_fd in os.fwalk(".", dir_fd=directory, follow_symlinks=False):
            def exists(rel):
                try:
                    os.stat(rel, dir_fd=dir_fd, follow_symlinks=False)
                except OSError:
                    return False
                return True
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not is_virtualenv(d, exists))
            for name in sorted(filenames):
                if name in SKIP_FILES:
                    continue
                try:
                    info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISREG(info.st_mode):
                    yield root / dirpath / name
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d))
                             and not is_virtualenv(d, lambda rel: os.path.lexists(os.path.join(dirpath, rel))))
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if name in SKIP_FILES or path.is_symlink() or not path.is_file():
                continue
            yield path


def check_root_identity(root, expected):
    """Refuse a changed repository when descriptor-relative discovery is unavailable."""
    current = root.lstat()
    if not stat.S_ISDIR(current.st_mode) or not os.path.samestat(current, expected):
        raise OSError("repository root changed during the scan")


@contextmanager
def open_source(path, root, *, root_fd=None, root_stat=None):
    """Open a regular repository file without following replaced files or parent directories."""
    parts = path.relative_to(root).parts
    if not parts or ".." in parts:
        raise OSError("expected a file inside the repository")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    dir_fd = None
    if SAFE_DIR_OPEN:
        directory_flags = (getattr(os, "O_PATH", getattr(os, "O_SEARCH", os.O_RDONLY))
                           | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            dir_fd = (os.dup(root_fd) if root_fd is not None
                      else open_directory(root, readable=False, expected_stat=root_stat))
            for part in parts[:-1]:
                child_fd = os.open(part, directory_flags, dir_fd=dir_fd)
                os.close(dir_fd)
                dir_fd = child_fd
            fd = os.open(parts[-1], flags, dir_fd=dir_fd)
        finally:
            if dir_fd is not None:
                os.close(dir_fd)
    else:
        # Platforms without descriptor-relative opens get path and inode checks before any read.
        # The POSIX branch above additionally closes races in ancestor-directory resolution.
        current, snapshots = root, []
        if root_stat is not None:
            check_root_identity(root, root_stat)
        for part in ("", *parts):
            current = current / part
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise OSError("repository symlinks are not scanned")
            snapshots.append((current, info))
        expected = snapshots[-1][1]
        if not stat.S_ISREG(expected.st_mode):
            raise OSError("expected a regular repository file")
        fd = os.open(path, flags)
        try:
            actual = os.fstat(fd)
            if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
                raise OSError("repository file changed before it could be read")
            for current, previous in snapshots:
                latest = current.lstat()
                if (stat.S_ISLNK(latest.st_mode)
                        or (latest.st_dev, latest.st_ino) != (previous.st_dev, previous.st_ino)):
                    raise OSError("repository path changed before it could be read")
        except BaseException:
            os.close(fd)
            raise
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise OSError("expected a regular repository file")
        yield handle


def secret_named(parts):
    return any(SECRET_NAMED.match(part) for part in parts)


def read_file(path, root, *, root_fd=None, root_stat=None):
    """Return (text or None, size or None), checking the opened file and bounding the read."""
    parts = path.relative_to(root).parts
    if any(SECRET_FILE.match(part) for part in parts) or SECRET_PATH.search("/".join(parts)) or (
            secret_named(parts) and path.suffix.lower() not in SOURCE_EXT | CSS_EXT):
        return None, None
    with open_source(path, root, root_fd=root_fd, root_stat=root_stat) as handle:
        size = os.fstat(handle.fileno()).st_size
        if size > MAX_BYTES or re.search(r"\.min\.(?:js|css)$", path.name):
            return None, size
        data = handle.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        return None, size
    if b"\0" in data:
        return None, size
    try:
        # A byte order mark (Windows editors) would hide a JSON or env file's first key.
        text = data.decode("utf-8").removeprefix("\ufeff")
    except UnicodeDecodeError:
        return None, size
    return (env_names_only(text) if ENV_DECL_FILE.match(path.name) else text), size


def read_text(path):
    """The file's text, or None for binaries, minified bundles, oversized and secret-looking files."""
    path = Path(path)
    return read_file(path, path.parent)[0]


def go_lexemes(text):
    """Keep comments and literals opaque, consuming even unterminated tokens only once."""
    index, length = 0, len(text)
    while index < length:
        start, char = index, text[index]
        if text.startswith(("//", "/*"), index):
            block = text[index + 1] == "*"
            end = text.find("*/" if block else "\n", index + 2)
            index = length if end < 0 else end + (2 if block else 0)
            kind = "comment"
        elif char in "\"'`":
            index += 1
            kind = "invalid"
            while index < length:
                if text[index] == char:
                    index += 1
                    kind = "rune" if char == "'" else "string"
                    break
                index += 2 if char != "`" and text[index] == "\\" else 1
            index = min(index, length)
        elif char in " \t\r\n":
            index += 1
            while index < length and text[index] in " \t\r\n":
                index += 1
            kind = "space"
        elif char.isalnum() or char == "_":
            index += 1
            while index < length and (text[index].isalnum() or text[index] == "_"):
                index += 1
            kind = "word"
        else:
            index += 1
            kind = "punctuation"
        yield kind, text[start:index]


def go_string_value(token):
    """Decode Go import strings, including byte escapes and raw-string carriage returns."""
    value = token[1:-1]
    if token.startswith("`"):
        return value.replace("\r", "")
    if "\\" not in value:
        return value
    parts, position = [], 0
    try:
        for match in GO_ESCAPE.finditer(value):
            plain = value[position:match.start()]
            if "\\" in plain:
                return None
            parts.append(plain.encode("utf-8"))
            escape = match.group(1)
            if escape[0] in "01234567":
                parts.append(bytes([int(escape, 8)]))
            elif escape[0] == "x":
                parts.append(bytes([int(escape[1:], 16)]))
            elif escape[0] in "uU":
                parts.append(chr(int(escape[1:], 16)).encode("utf-8"))
            else:
                parts.append(GO_SIMPLE_ESCAPES[escape])
            position = match.end()
        if "\\" in value[position:]:
            return None
        parts.append(value[position:].encode("utf-8"))
        return b"".join(parts).decode("utf-8")
    except (KeyError, ValueError, UnicodeError, OverflowError):
        return None


def go_import_paths(text):
    """Read only import declarations; strings elsewhere cannot invent dependency uses."""
    importing, grouped = False, False
    for kind, token in go_lexemes(text):
        if kind in {"space", "comment"}:
            continue
        if kind == "word" and token == "import":
            importing, grouped = True, False
        elif importing:
            if token == "(" and not grouped:
                grouped = True
            elif kind == "string":
                path = go_string_value(token)
                if path and GO_PATH.fullmatch(path):
                    yield path
                importing = grouped
            elif token == ")" or (token == ";" and not grouped):
                importing = False
            elif kind != "word" and token not in {".", ";"}:
                importing = False


def env_names_only(text):
    """Discard env example values before any collector sees them; retain line numbers."""
    lines, quote = [], None
    assignment = re.compile(r"^\s*(?:export\s+)?(?:[\w.-]+|'[^']+')\s*=")
    for line in text.split("\n"):
        binding = assignment.match(line) if quote is None else None
        declaration = ENV_DECL.match(line) if binding else None
        lines.append(declaration.group(0) if declaration else "")
        value = line[binding.end():].lstrip() if binding else (line if quote else "")
        if quote is None and value.startswith(("'", '"', "`")):
            quote, value = value[0], value[1:]
        if quote:
            escaped = False
            for char in value:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                    break
    return "\n".join(lines)


@lru_cache(maxsize=1)
def line_breaks(text):
    """Index one source at a time; fixed-width offsets keep even newline-heavy files bounded."""
    return array("I", (m.start() for m in re.finditer("\n", text)))


def line_of(text, index):
    return bisect_left(line_breaks(text), index) + 1


def is_test(rel):
    return bool(TEST_PATH.search(rel))


def locale_bundle(rel):
    """(bundle, lang) for a JSON locale file, else None."""
    p = Path(rel)
    if p.suffix != ".json":
        return None
    if LANG.match(p.stem) and (LOCALE_DIR.search(rel) or p.parent.name.lower() in ("i18n", "locales", "lang")):
        return (p.parent / "{lang}.json").as_posix(), p.stem.replace("_", "-")
    if LANG.match(p.parent.name) and LOCALE_DIR.search(rel):
        return (p.parent.parent / "{lang}" / p.name).as_posix(), p.parent.name.replace("_", "-")
    return None


def flatten(value, prefix=""):
    if isinstance(value, dict):
        for k, v in value.items():
            if not str(k).startswith("@"):
                yield from flatten(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(value, (str, list)):
        yield prefix


def json_key_lines(text):
    """Index the first occurrence of each decoded key in an already validated JSON file."""
    lines = {}
    # Consume values as well as keys so escaped quotes inside a value stay opaque.
    for token in re.finditer(r'"(?:[^"\\]|\\.)*"', text):
        end = token.end()
        while end < len(text) and text[end] in " \t\r\n":
            end += 1
        if end < len(text) and text[end] == ":":
            key = json.loads(token.group())
            lines.setdefault(key, line_of(text, token.start()))
    return lines


def section_key_lines(text):
    """Line of each key directly inside a top-level object, by (section, key), in a validated JSON file.

    A dependency named like a script or a top-level setting (storybook, jest)
    then points at its own section, not at the first key spelled the same."""
    lines, stack, key = {}, [], None
    for token in re.finditer(r'"(?:[^"\\]|\\.)*"|[{}\[\]]', text):
        value = token.group()
        if value in "{[":
            stack.append(key)
            key = None
        elif value in "}]":
            if stack:
                stack.pop()
            key = None
        else:
            end = token.end()
            while end < len(text) and text[end] in " \t\r\n":
                end += 1
            if end < len(text) and text[end] == ":":
                key = json.loads(value)
                if len(stack) == 2:
                    lines.setdefault((stack[1], key), line_of(text, token.start()))
    return lines


def key_line(text, key, *, lines=None):
    """Line of the last segment of key in a JSON locale file (first match)."""
    if lines is None:
        lines = json_key_lines(text)
    return lines.get(key.rsplit(".", 1)[-1], 1)


# Strings first, so comment markers and commas inside them are kept.
# The lookahead's comment cannot run past its own */, so each comma scans only
# the comments directly after it.
JSONC_DROP = re.compile(r'"(?:\\.|[^"\\\n])*"|(//[^\n]*|/\*[\s\S]*?(?:\*/|\Z)|'
                        r',(?=\s*(?:(?://[^\n]*|/\*(?:[^*]|\*(?!/))*\*/)\s*)*[}\]]))')
TS_CONFIG = re.compile(r"(?:^|/)(?:tsconfig(?:\.[\w-]+)?|jsconfig)\.json$")


def jsonc_object(text):
    """tsconfig.json allows comments and trailing commas; drop them outside strings."""
    cleaned = JSONC_DROP.sub(lambda m: "" if m.group(1) else m.group(0), text)
    try:
        data = parse_json(cleaned, "tsconfig")
    except (RecordError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def ts_config_options(rel, texts, cache, in_progress=None):
    """(paths, directory paths resolve from, baseUrl directory) for one config, following relative extends.

    Results are cached per config, so a diamond of extends is walked once. A
    config already being resolved (a cycle, which tsc rejects) contributes
    nothing; only finished results are cached, so an interrupted walk leaves
    no partial entry behind.
    """
    if rel in cache:
        return cache[rel]
    in_progress = set() if in_progress is None else in_progress
    if rel in in_progress:
        return None, None, None
    in_progress.add(rel)
    try:
        cache[rel] = ts_config_resolve(rel, texts, cache, in_progress)
    finally:
        in_progress.discard(rel)
    return cache[rel]


def ts_config_resolve(rel, texts, cache, in_progress):
    data = jsonc_object(texts[rel]) or {}
    paths, paths_root, base = None, None, None
    extends = data.get("extends")
    for parent in (extends if isinstance(extends, list) else [extends]):
        # Package configs (@tsconfig/node20) live outside the repository.
        if not isinstance(parent, str) or not parent.startswith("."):
            continue
        target = os.path.normpath((Path(rel).parent / parent).as_posix()).replace(os.sep, "/")
        target = next((t for t in (target, target + ".json", target + "/tsconfig.json") if t in texts), None)
        if target:
            inherited_paths, inherited_root, inherited_base = ts_config_options(target, texts, cache, in_progress)
            if inherited_paths is not None:
                paths, paths_root = inherited_paths, inherited_root
            if inherited_base is not None:
                base = inherited_base
    options = data.get("compilerOptions")
    if isinstance(options, dict):
        root = Path(rel).parent
        if isinstance(options.get("baseUrl"), str):
            base = root / options["baseUrl"]
        if isinstance(options.get("paths"), dict):
            paths, paths_root = options["paths"], root
    return paths, paths_root, base


def js_alias_rules(texts):
    """{config directory: [(prefix, wildcard, [target paths])]} from compilerOptions.paths and baseUrl.

    A config inherits paths and baseUrl through relative extends; paths resolve
    from baseUrl when one is set, else from the config that declares them.
    """
    by_directory, cache = {}, {}
    for rel in sorted(texts):
        if not TS_CONFIG.search(rel):
            continue
        try:
            paths, paths_root, base = ts_config_options(rel, texts, cache)
        except RecursionError:
            paths, paths_root, base = None, None, None  # An absurdly deep extends chain.
        root = Path(rel).parent
        # Every config governs its directory, even with no aliases: a package
        # config with only strict must not fall through to the root's paths.
        rules = by_directory.setdefault("" if root.as_posix() == "." else root.as_posix(), [])
        for key, targets in (paths or {}).items():
            if not isinstance(targets, list):
                continue
            wildcard = key.endswith("*")
            resolved = [os.path.normpath(((base or paths_root) / t.rstrip("*")).as_posix()).replace(os.sep, "/")
                        for t in targets if isinstance(t, str)]
            rules.append((key.rstrip("*"), wildcard, [("" if r == "." else r) for r in resolved]))
        if base is not None:
            target = os.path.normpath(base.as_posix()).replace(os.sep, "/")
            rules.append(("", True, ["" if target == "." else target]))
    return by_directory


def js_package(spec):
    if spec.startswith((".", "/", "~", "#", "@/", "node:")) or ":" in spec:
        return None
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec.startswith("@") else parts[0]


def js_import_specs(text):
    """Read import clauses without letting a spurious candidate hide a later one.

    This remains a conservative text scan, including template expressions. Comment
    and quote boundaries are indexed once; shared gaps and named clauses are cached
    so repeated candidates cannot repeatedly scan the remaining source.
    """
    if not JS_IMPORT_START.search(text):
        return
    length = len(text)
    names, candidates = {}, []
    for match in JS_BINDING_NAME.finditer(text):
        names[match.start()] = match.end()
        if match.end() - match.start() in (6, 7):
            kind = match.group(0)
            if kind in ("import", "export", "require"):
                candidates.append((kind, match.end()))
    if not candidates:
        return
    comments = {}
    close = -1
    for match in re.finditer(r"/\*", text):
        if close < match.end():
            close = text.find("*/", match.end())
            if close < 0:
                close = length
        comments[match.start()] = min(close + 2, length)
    close = -1
    for match in re.finditer(r"//", text):
        if close < match.end():
            newline = JS_LINE_END.search(text, match.end())
            close = newline.start() if newline else length
        comments[match.start()] = close
    quotes, previous = {}, {}
    for match in JS_QUOTE_OR_ESCAPE.finditer(text):
        quote = match.group(0)
        if quote in ("'", '"'):
            if quote in previous:
                quotes[previous[quote]] = match.start()
            previous[quote] = match.start()
    gaps = {length: length}

    def gap(pos):
        visited = []
        while pos not in gaps:
            visited.append(pos)
            space = JS_SPACE.match(text, pos)
            if space:
                pos = space.end()
            elif pos in comments:
                pos = comments[pos]
            else:
                break
        end = gaps.get(pos, pos)
        for start in visited:
            gaps[start] = end
        return end

    @lru_cache(maxsize=None)
    def token_at(pos):
        if pos >= length:
            return "end", "", length
        if text[pos] in ("'", '"'):
            end = quotes.get(pos)
            if end is None:
                return "invalid", "", length
            value = text[pos + 1:end]
            # A quoted binding may continue after an escaped line ending.
            if ("\n" in value or "\r" in value) and any(
                    match.group(1) for match in re.finditer(r"\\(?:\r\n|[\s\S])|([\r\n])", value)):
                return "invalid", "", end + 1
            return "string", value, end + 1
        end = names.get(pos)
        if end is not None:
            # Only contextual keywords affect the grammar; never copy a long name.
            value = text[pos:end] if end - pos <= 6 else ""
            return "name", value, end
        return "punct", text[pos], pos + 1

    def token(pos):
        return token_at(gap(pos))

    clauses = {}

    def named_clause(pos):
        visited = []
        end = None
        while True:
            pos = gap(pos)
            if pos in clauses:
                end = clauses[pos]
                break
            visited.append(pos)
            binding = token(pos)
            if binding[:2] == ("punct", "}"):
                end = binding[2]
                break
            if binding[0] not in ("name", "string"):
                break
            following = token(binding[2])
            if (binding[0] == "name" and binding[1] in ("type", "typeof")
                    and following[0] in ("name", "string")):
                after = token(following[2])
                # `as` may be the imported name, or introduce an ordinary alias.
                if (following[:2] != ("name", "as")
                        or after[:2] in (("punct", "}"), ("punct", ","))
                        or (after[:2] == ("name", "as")
                            and token(after[2])[0] in ("name", "string"))):
                    following = after
            if following[:2] == ("name", "as"):
                alias = token(following[2])
                if alias[0] not in ("name", "string"):
                    break
                following = token(alias[2])
            if following[:2] == ("punct", "}"):
                end = following[2]
                break
            if following[:2] != ("punct", ","):
                break
            pos = following[2]
        for start in visited:
            clauses[start] = end
        return end

    # The keyword scan advances independently of the candidate-local parser. Text
    # such as "import /*" in a string or line comment must not swallow real code.
    seen, emitted = set(), set()

    def specifier_value(value):
        """Decode a module's StringLiteral once, without reinterpreting produced backslashes."""
        if "\\" not in value:
            return None if re.search(r"[\x00\ud800-\udfff]", value) else value
        parts, position = [], 0
        escapes = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}
        while position < len(value):
            slash = value.find("\\", position)
            if slash < 0:
                parts.append(value[position:])
                break
            parts.append(value[position:slash])
            position = slash + 1
            if position == len(value):
                return None
            escape = value[position]
            position += 1
            if escape in "\r\n\u2028\u2029":
                if escape == "\r" and value.startswith("\n", position):
                    position += 1
                continue
            if escape in "xu":
                if escape == "u" and value.startswith("{", position):
                    end = value.find("}", position + 1)
                    if end < 0:
                        return None
                    digits = value[position + 1:end]
                    if not re.fullmatch(r"[0-9a-fA-F]+", digits):
                        return None
                    # Leading zeroes are permitted; never construct an unbounded integer.
                    digits = digits.lstrip("0") or "0"
                    position = end + 1
                    if len(digits) > 6 or int(digits, 16) > 0x10ffff:
                        return None
                else:
                    count = 2 if escape == "x" else 4
                    digits = value[position:position + count]
                    if len(digits) != count or not re.fullmatch(r"[0-9a-fA-F]+", digits):
                        return None
                    position += count
                parts.append(chr(int(digits, 16)))
            elif escape in "01234567":
                # CommonJS and other non-strict scripts also admit legacy octal escapes.
                digits, count = escape, 3 if escape in "0123" else 2
                while len(digits) < count and position < len(value) and value[position] in "01234567":
                    digits += value[position]
                    position += 1
                parts.append(chr(int(digits, 8)))
            else:
                parts.append(escapes.get(escape, escape))
        try:
            # JavaScript strings use UTF-16. Join escaped surrogate pairs, rejecting lone halves.
            decoded = "".join(parts).encode("utf-16-le", "surrogatepass").decode("utf-16-le")
        except UnicodeError:
            return None
        return None if "\0" in decoded else decoded

    def unseen(module):
        if module[0] != "string" or not module[1] or module[2] in emitted:
            return None
        # Mark before decoding: overlapping candidates must never decode the same long literal again.
        emitted.add(module[2])
        return specifier_value(module[1])

    for kind, start in candidates:
        pos = gap(start)
        if (kind, pos) in seen:
            continue
        seen.add((kind, pos))
        following = token_at(pos)
        if kind in ("import", "require"):
            source_call = False
            if kind == "import" and following[:2] == ("punct", "."):
                phase = token(following[2])
                if phase[:2] not in (("name", "source"), ("name", "defer")):
                    continue
                source_call = phase[1] == "source"
                following = token(phase[2])
                if following[:2] != ("punct", "("):
                    continue
            if kind == "import" and following[0] == "string":
                if spec := unseen(following):
                    yield spec
                continue
            if following[:2] == ("punct", "("):
                module = token(following[2])
                after = token(module[2])
                # Source-phase calls take one argument; defer permits import options.
                literal_end = (after[:2] == ("punct", ")") or
                               (not source_call and after[:2] == ("punct", ",")))
                if literal_end and (spec := unseen(module)):
                    yield spec
                continue
            if kind == "require":
                continue
            if following[:2] == ("name", "source"):
                binding = token(following[2])
                after = token(binding[2])
                # Keep `import source from ...` as an ordinary default binding.
                if binding[0] == "name" and after[:2] == ("name", "from"):
                    module = token(after[2])
                    if spec := unseen(module):
                        yield spec
                    continue
        if kind == "import" and following[:2] == ("name", "typeof"):
            # Flow's reserved modifier may precede a binding named `from` or `type`.
            following = token(following[2])
        elif following[:2] == ("name", "type"):
            after = token(following[2])
            if kind == "export" or after[:2] not in (("name", "from"), ("punct", ",")):
                following = after
        if kind == "import" and following[0] == "name":
            following = token(following[2])
            if following[:2] == ("punct", ","):
                following = token(following[2])
        if following[:2] == ("punct", "{"):
            end = named_clause(following[2])
            if end is None:
                continue
            following = token(end)
        elif following[:2] == ("punct", "*"):
            following = token(following[2])
            if following[:2] == ("name", "as"):
                alias = token(following[2])
                if alias[0] not in ("name", "string"):
                    continue
                following = token(alias[2])
            elif kind == "import":
                continue
        if following[:2] == ("name", "from"):
            module = token(following[2])
            if spec := unseen(module):
                yield spec


def py_dist_module(name):
    lower = name.lower()
    return PY_MODULE_NAMES.get(lower, re.sub(r"[-.]", "_", lower))


def dynamic_class_prefixes(text):
    """Retain every literal class prefix, including several in one template."""
    # Treat each backtick as a possible opening, conservatively including nested templates.
    # Segments are disjoint, and prefixes cannot restart inside the same hyphenated token.
    for template in re.finditer(r"`[^`]*", text):
        for match in DYNAMIC_CLASS.finditer(text, template.start() + 1, template.end()):
            yield match.group(1)
    for match in CONCAT_CLASS.finditer(text):
        yield match.group(1)


def py_import_specs(text, *, tree=None):
    """Keep valid Python imports in inline suites and continued statements; fall back for newer syntax."""
    if tree is not None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    yield "", alias.name, []
            elif isinstance(node, ast.ImportFrom):
                yield "." * node.level, node.module or "", [alias.name for alias in node.names if alias.name != "*"]
        return
    for match in PY_IMPORT.finditer(text):
        for part in match.group(1).split(","):
            module = re.split(r"\s+as\s+", part, maxsplit=1)[0].strip()
            yield "", module, []
    for match in PY_FROM.finditer(text):
        imported = re.sub(r"#[^\n]*", "", match.group(3)).strip("()").replace("\n", " ")
        names = [re.split(r"\s+as\s+", name, maxsplit=1)[0].strip() for name in imported.split(",")]
        yield match.group(1), match.group(2), [name for name in names if name and name != "*"]


def blank_sql_body(body):
    """body with strings closed on their line and comments blanked in place.

    A comma inside one then cannot start a column. A string read with
    backslash escapes (can\\'t) is tried before one where a backslash is
    literal (C:\\), so a misread string never swallows the comma
    that ends its line. Once the escaped reading fails, the rest of that line
    uses the literal reading only, so no line is rescanned per quote.
    """
    out, position, written, literal_until = [], 0, 0, -1
    while match := SQL_BLANK_TOKEN.search(body, position):
        start, end, token = match.start(), match.end(), match.group()
        if token[0] in "\"`":
            position = end
            continue
        if token == "'":
            string = SQL_ESCAPED_STRING.match(body, start) if start >= literal_until else None
            if string is None and start >= literal_until:
                line_end = body.find("\n", start)
                literal_until = len(body) if line_end < 0 else line_end
            string = string or SQL_LITERAL_STRING.match(body, start)
            if string is None:
                position = start + 1
                continue
            end = string.end()
        out.append(body[written:start])
        out.append(re.sub(r"[^\n]", " ", body[start:end]))
        position = written = end
    out.append(body[written:])
    return "".join(out)


def parse_requirements(rel, text):
    for i, line in enumerate(physical_lines(text), 1):
        line = line.split("#", 1)[0].strip()
        if not line or line.lower().startswith(("-", "git+", "http://", "https://")):
            continue
        m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if m:
            yield m.group(1), "requirements", f"{rel}:{i}"


CARGO_DEPENDENCY_TABLE = re.compile(
    r"^((?:target\..+\.|workspace\.)?(?:dev-|build-)?dependencies)\.([A-Za-z0-9][A-Za-z0-9_-]*)$")


def parse_toml_lists(rel, text):
    """pyproject.toml dependencies (PEP 621 and Poetry) and Cargo.toml dependency tables, by regex."""
    section = None
    in_list = None
    list_depth = inline_depth = 0
    # Keep punctuation inside strings out of the structural scan (extras, markers, URLs).
    tokens = re.compile(r'"(?:\\.|[^"\\])*"|\'[^\']*\'|\#.*$|[\[\]{}]')
    for i, line in enumerate(physical_lines(text), 1):
        comment = next((m.start() for m in tokens.finditer(line) if m.group(0).startswith("#")), len(line))
        stripped = line[:comment].strip()
        if not in_list:
            header = re.match(r"^\[+([^\]]+)\]+$", stripped)
            if header:
                section = header.group(1).strip()
                table = CARGO_DEPENDENCY_TABLE.match(section)
                if table:  # [dependencies.serde] declares one dependency.
                    yield table.group(2), table.group(1), f"{rel}:{i}"
                continue
            m = re.match(r"^([\w-]+)\s*=\s*\[(.*)$", stripped)
            if m and ((section == "project" and m.group(1) == "dependencies") or section in (
                    "project.optional-dependencies", "dependency-groups")):
                in_list, list_depth, inline_depth = section, 1, 0
                stripped = m.group(2)
            elif section and (section.endswith("dependencies") and ("poetry" in section or section.startswith(
                    ("dependencies", "dev-dependencies", "build-dependencies", "workspace.dependencies",
                     "target.")))):
                m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=", stripped)
                if m and m.group(1) != "python":
                    yield m.group(1), section, f"{rel}:{i}"
                continue
        if in_list:
            for token in tokens.finditer(stripped):
                value = token.group(0)
                if value == "[":
                    list_depth += 1
                elif value == "]":
                    list_depth -= 1
                    if list_depth == 0:
                        in_list = None
                        break
                elif value == "{":
                    inline_depth += 1
                elif value == "}":
                    inline_depth = max(0, inline_depth - 1)
                elif value.startswith(('"', "'")) and list_depth == 1 and inline_depth == 0:
                    dependency = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", value[1:-1])
                    if dependency:
                        yield dependency.group(0), in_list, f"{rel}:{i}"


def package_sections(text):
    """Return usable package.json maps; invalid shapes cannot abort a best-effort scan."""
    try:
        value = parse_json(text)
    except RecordError:
        return {}
    if not isinstance(value, dict):
        return {}
    return {key: {name: entry for name, entry in section.items() if isinstance(entry, str)}
            for key, section in value.items() if isinstance(section, dict)}


def parse_go_mod(rel, text):
    block = False
    for i, line in enumerate(physical_lines(text), 1):
        if re.search(r"//\s*indirect\b", line):
            continue  # Transitive by definition; go mod tidy adds it back.
        s = line.split("//", 1)[0].strip()
        if s.startswith("require ("):
            block = True
            continue
        if block and s == ")":
            block = False
            continue
        m = re.match(r"^(?:require\s+)?([\w.\-]+\.[\w.\-]+/[\w.\-/]+)\s+v", s) if (block or s.startswith("require")) else None
        if m:
            yield m.group(1), "require", f"{rel}:{i}"


def sql_table_specs(text):
    """Find table bodies once; repeated starts cannot rescan a missing terminator."""
    position, balanced = 0, True
    while True:
        opening = CREATE_TABLE_START.search(text, position)
        if opening is None:
            return
        # The body ends at the parenthesis balancing the opening one, so table
        # options (MySQL's ENGINE=...) and nested types or checks cannot end it early.
        depth, closing = 1, None
        for token in SQL_BODY_TOKEN.finditer(text, opening.end()) if balanced else ():
            depth += {"(": 1, ")": -1}.get(token.group(0), 0)
            if depth == 0:
                closing = token
                break
        if closing is None:
            # Unbalanced (quoting this scan misreads): the rest of the file ends
            # bodies at the first ")...;" as before, so one odd body cannot drop every
            # table after it, and no later table rescans the same unbalanced tail.
            balanced = False
            closing = CREATE_TABLE_END.search(text, opening.end())
        if closing is None:
            return
        yield opening.group(1), opening.start(), opening.end(), text[opening.end():closing.start()]
        position = closing.end()


MAKE_CALL = re.compile(r"(?:\bmake|\$\(MAKE\)|\$\{MAKE\})(?=[^\S\n])")
NPM_CALL = re.compile(r"\b(?:npm|pnpm|yarn|bun)(?=[^\S\n])")
MAKE_VALUE_OPTIONS = {"-C", "-f", "-I", "-o", "-W"}
# Long spellings of the options above, whose value is the next word.
MAKE_LONG_OPTIONS = {"--directory": "-C", "--file": "-f", "--makefile": "-f", "--include-dir": "-I",
                     "--old-file": "-o", "--assume-old": "-o", "--new-file": "-W", "--assume-new": "-W",
                     "--what-if": "-W"}
# -j and -l take an optional value: a number or a variable (make -j 4, make -j $(nproc)).
MAKE_OPTIONAL_VALUE_OPTIONS = {"-j", "-l", "--jobs", "--load-average", "--max-load"}
MAKE_OPTIONAL_VALUE = re.compile(r"[\"']?(?:[0-9][0-9.]*|\$)\S*")
MAKE_VARIABLE = re.compile(r"[\w.][\w.-]*=\S*")
NPM_OPTION = re.compile(r"--?\w[\w-]*(?:=\S*)?")
# Package manager options whose value is the next word.
NPM_VALUE_OPTIONS = {"--prefix", "-C", "--dir", "--cwd", "-w", "--workspace", "--filter", "-F", "--registry",
                     "--loglevel", "--userconfig", "--cache", "--tag", "--scope"}
PACKAGE_MANAGERS = {"npm", "pnpm", "yarn", "bun"}
MAX_COMMAND_TOKENS = 64
COMMAND_TOKEN = re.compile(r"\S+")
MAKE_NAME = re.compile(r"[A-Za-z0-9_.:=-]*")
NPM_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:.-")


def command_tokens(text, end):
    """Lazily, at most MAX_COMMAND_TOKENS whitespace tokens of the rest of one line.

    The line end comes from the cached newline index and callers stop reading
    at the first token that ends the command, so many command starts on one
    long line stay linear.
    """
    breaks = line_breaks(text)
    index = bisect_left(breaks, end)
    line_end = breaks[index] if index < len(breaks) else len(text)
    return (m.group() for m in islice(COMMAND_TOKEN.finditer(text, end, line_end), MAX_COMMAND_TOKENS))


def script_names_in(token, scripts, lengths):
    """Known script names that token starts with, ending where a name could end."""
    found = set()
    for length in lengths:
        if length <= len(token) and (length == len(token) or token[length] not in NPM_NAME_CHARS):
            if token[:length] in scripts:
                found.add(token[:length])
    return found


def npm_script(tokens):
    """The script one package manager command runs, or None.

    Options that take a separate value (npm --prefix web, pnpm --filter web,
    yarn --cwd web) skip it; run/run-script and yarn workspace NAME name the
    script after them; otherwise the first word is the script (npm test,
    yarn build).
    """
    tokens = iter(tokens)
    for token in tokens:
        if token in NPM_VALUE_OPTIONS:
            next(tokens, None)
            continue
        if NPM_OPTION.fullmatch(token):
            continue
        if token.startswith("-"):
            return None
        if token in ("run", "run-script"):
            for token in tokens:
                if token in NPM_VALUE_OPTIONS:
                    next(tokens, None)
                elif not NPM_OPTION.fullmatch(token):
                    return token
            return None
        if token == "workspace":
            next(tokens, None)
            return next(tokens, None)
        return token
    return None


def make_targets(text):
    """(target, rule start) for every target a Makefile's rules name, in order; .PHONY-style names are skipped."""
    text = MAKE_DEFINE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
    for m in MAKE_TARGET.finditer(text):
        for target in m.group(1).split():
            if not target.startswith("."):
                yield target, m.start()


def make_command(tokens, known):
    """(targets in order, whether each is exact, -C directories, -f files) of one make command.

    Options (-C dir), variables and known targets may come before a target; any
    other word ends the command, and so does trailing punctuation (make build.).
    """
    tokens = iter(tokens)
    sequence, directories, files = [], [], []
    for token in tokens:
        if token in MAKE_OPTIONAL_VALUE_OPTIONS:
            token = next(tokens, None)
            if token is None:
                break
            if MAKE_OPTIONAL_VALUE.fullmatch(token):
                continue
        token = MAKE_LONG_OPTIONS.get(token, token)
        if token in MAKE_VALUE_OPTIONS:
            value = next(tokens, None)
            if value is None or value.startswith("-"):
                break
            (directories if token == "-C" else files if token == "-f" else []).append(value)
            continue
        if (token.startswith("-") and len(token) > 1) or MAKE_VARIABLE.fullmatch(token):
            continue
        name = MAKE_NAME.match(token).group()
        if not name or name not in known:
            break
        sequence.append((name, name == token))
        if name != token:
            break
    return sequence, directories, files


def invocation_counts(texts, project_targets, scripts=frozenset(),
                      select_project=lambda rel, directories, files: None):
    """Count make <target> per Makefile project and npm|pnpm|yarn|bun [run] <script> in one pass.

    A make command line may hold options (-C dir), variables and other targets
    of the same project before the target; prose words between make and a
    target name end it. When -C or -f selects a known Makefile project
    (select_project), only that project's targets count.
    """
    make_calls, npm_calls = defaultdict(Counter), Counter()
    lengths = sorted({len(name) for name in scripts})
    known = frozenset().union(*project_targets.values())
    for rel, text in texts.items():
        for start in MAKE_CALL.finditer(text):
            sequence, directories, files = make_command(command_tokens(text, start.end()), known)
            if not sequence:
                continue
            selected = select_project(rel, directories, files) if directories or files else None
            for project, targets in project_targets.items():
                if selected is not None and project != selected:
                    continue
                called = set()  # A command runs each named target once.
                for name, exact in sequence:
                    if name not in targets:
                        break
                    called.add(name)
                    if not exact:
                        break
                make_calls[project].update(called)
        for start in NPM_CALL.finditer(text):
            script = npm_script(command_tokens(text, start.end()))
            if script:
                npm_calls.update(script_names_in(script, scripts, lengths))
    return make_calls, npm_calls


class Collector:
    """Per-file signals gathered in one pass, resolved across files at the end."""

    def __init__(self, root, today, *, root_fd=None, root_stat=None):
        self.root, self.today = root, today
        self.root_fd, self.root_stat = root_fd, root_stat
        self.texts = {}            # rel -> text, for every readable file
        self.assets = []           # (rel, bytes)
        self.skipped = 0
        self.locales = defaultdict(dict)

    def add(self, path):
        if self.root_fd is None and self.root_stat is not None:
            check_root_identity(self.root, self.root_stat)
        rel = path.relative_to(self.root).as_posix()
        try:
            rel.encode("utf-8")
        except UnicodeEncodeError:
            self.skipped += 1
            return  # Filesystem surrogateescape names cannot form valid UTF-8 JSON locations.
        try:
            text, size = read_file(path, self.root, root_fd=self.root_fd, root_stat=self.root_stat)
        except OSError:
            self.skipped += 1
            return
        if path.suffix.lower() in ASSET_EXT and size is not None:
            self.assets.append((rel, size))
        if text is None:
            if path.suffix.lower() not in ASSET_EXT or size is None:
                self.skipped += 1
            return
        self.texts[rel] = text
        bundle = locale_bundle(rel)
        if bundle:
            try:
                self.locales[bundle[0]][bundle[1]] = (rel, list(flatten(parse_json(text))))
            except (RecordError, RecursionError):
                pass


def loc_key(location):
    path, _, line = location.rpartition(":")
    return path, int(line.split("-")[0])


def suffix(rel):
    return Path(rel).suffix.lower()


def inventory(root, units=None, today=None):
    root = Path(root)
    root_stat = root.stat()  # Capture the caller's selected repository before resolving any aliases.
    root = root.resolve()
    today = today or datetime.date.today().isoformat()
    root_fd = None
    try:
        if SAFE_DIR_OPEN and hasattr(os, "fwalk"):
            root_fd = open_directory(root, readable=False, expected_stat=root_stat)
        else:
            check_root_identity(root, root_stat)
        col = Collector(root, today, root_fd=root_fd, root_stat=root_stat)
        for path in iter_files(root, directory=root_fd):
            col.add(path)
        if root_fd is None:
            check_root_identity(root, root_stat)
    finally:
        if root_fd is not None:
            os.close(root_fd)
    texts = col.texts
    locale_files = {rel for langs in col.locales.values() for rel, _ in langs.values()}
    code_files = [r for r in texts if suffix(r) not in PROSE_EXT | {".sql"} and r not in locale_files]
    # Read only for imports and identifiers: no literal from these reaches the output.
    secret_sources = {r for r in texts if secret_named(Path(r).parts)}

    # Identifier counts over code and config (string contents included: names built from strings count as uses).
    idents = Counter()
    for rel in code_files:
        idents.update(IDENT.findall(texts[rel]))

    # File names mentioned anywhere: a file named elsewhere (HTML script src, Makefile, config) is referenced.
    named_in, module_runs = defaultdict(set), defaultdict(set)
    for rel, text in texts.items():
        for tok in set(FILE_TOKEN.findall(text)):
            named_in[tok].add(rel)
        # python -m server.nightly runs server/nightly.py (or a package's __main__).
        for module in set(PYTHON_MODULE_RUN.findall(text)):
            stem = module.replace(".", "/")
            for path in (stem + ".py", stem + "/__main__.py"):
                module_runs[path].add(rel)
        # A dotted name loads every package on its path and the module inside one; a trailing
        # attribute (a class) names no file. A lone first part names only a package, so a host
        # such as "api.example.com" leaves api.py a candidate.
        # Tests patch modules by name (monkeypatch.setattr("pkg.mod.fn")); that keeps nothing in use.
        for quoted, served in set() if is_test(rel) else set(PYTHON_MODULE_STRING.findall(text)):
            parts = (quoted or served).split(".")
            if parts[-1].lower() in NOT_MODULE_SUFFIX:
                continue
            for end in range(1, len(parts) + 1):
                stem = "/".join(parts[:end])
                module_runs[stem + "/__init__.py"].add(rel)
                if end > 1:
                    module_runs[stem + ".py"].add(rel)

    def named_elsewhere(rel):
        parts = rel.split("/")
        if any(module_runs.get("/".join(parts[i:]), set()) - {rel} for i in range(len(parts))):
            return True
        return bool(named_in.get(Path(rel).name, set()) - {rel})

    rows = {}

    # Symbols.
    defs = defaultdict(list)
    python_imports = {}
    decorated_skipped = 0
    for rel in code_files:
        ext = suffix(rel)
        text = texts[rel]
        python_defs = None
        if ext in PY_EXT:
            try:
                tree = ast.parse(text)
                python_defs = {node.lineno: bool(getattr(node, "decorator_list", []))
                               for node in tree.body
                               if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                                    ast.Assign, ast.AnnAssign))}
                python_imports[rel] = list(py_import_specs(text, tree=tree))
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                pass  # Unsupported syntax and parser resource limits retain the best-effort scan.
        if is_test(rel):
            continue
        regex = {**{e: PY_DEF for e in PY_EXT}, **{e: JS_DEF for e in JS_EXT}, **{e: GO_DEF for e in GO_EXT},
                 **{e: RS_DEF for e in RS_EXT}}.get(ext)
        if not regex:
            continue
        lang = {".py": "python", ".go": "go", ".rs": "rust"}.get(ext, "javascript")
        for m in regex.finditer(text):
            name = next(g for g in m.groups() if g)
            if name in ENTRY_SYMBOLS or name.startswith("__"):
                continue
            line = line_of(text, m.start())
            if python_defs is not None and line not in python_defs:
                continue  # A definition-shaped line in a docstring is not executable code.
            end = m.start()
            while end and text[end - 1] == "\n":
                end -= 1
            before = text[text.rfind("\n", 0, end) + 1:end].strip()
            if (python_defs is not None and python_defs[line]) or before.startswith(("@", "#[")):
                decorated_skipped += 1
                continue
            words = [w for w in re.split(r"[\s(]+", m.group(0)) if w and w not in MODIFIERS and not w.startswith("pub")]
            kind = words[0].rstrip("*") if words and words[0] != name else "constant"
            defs[name].append({"name": name, "kind": kind, "language": lang,
                               "location": f"{rel}:{line}",
                               "exported": m.group(0).startswith(("export", "pub")) or (lang == "go" and name[0].isupper())})
    rows["unreferenced_symbols"] = sorted(
        (d for name, ds in defs.items() if idents[name] - len(ds) <= 0 for d in ds),
        key=lambda d: loc_key(d["location"]))

    # Imports and orphan files.
    files = set(texts)
    inbound = defaultdict(set)
    js_packages, py_modules, go_imports, rs_crates = Counter(), Counter(), Counter(), Counter()

    def resolve_js(rel, spec):
        base = (Path(rel).parent / spec).as_posix() if spec.startswith(".") else spec.lstrip("/")
        base = os.path.normpath(base).replace(os.sep, "/")
        ext = Path(base).suffix
        candidates = ([base[:-len(ext)] + replacement for replacement in JS_SUBSTITUTIONS[ext]]
                      if ext in JS_SUBSTITUTIONS else [base + ending for ending in JS_RESOLVE])
        # A dotted stem such as helper.client can still omit its source extension.
        single_target = ext in JS_EXT or ext == ".json" or (bool(ext) and base in files)
        targets = []
        for candidate in candidates:
            if candidate in files:
                targets.append(candidate)
                if single_target:
                    break  # Preserve known-extension substitution and existing exact-file imports.
        # Extensionless resolution depends on the bundler; each possible target is a reference.
        return targets

    alias_rules = js_alias_rules(texts)

    def resolve_alias(rel, spec):
        """tsconfig/jsconfig paths and baseUrl; else @/ ~/ #/ from an enclosing root or src/."""
        targets = []
        # Only the nearest enclosing config governs a file: in a monorepo each
        # package's @/* maps to its own src/, and a config without aliases
        # keeps an ancestor's from applying.
        parent = Path(rel).parent
        ancestors = ["" if a.as_posix() == "." else a.as_posix() for a in (parent, *parent.parents)]
        config_dir = next((d for d in ancestors if d in alias_rules), None)
        for prefix, wildcard, destinations in alias_rules.get(config_dir, ()):
            if spec.startswith(prefix) if wildcard else spec == prefix:
                rest = spec[len(prefix):] if wildcard else ""
                for destination in destinations:
                    joined = "/".join(x for x in (destination, rest) if x)
                    if joined:
                        targets.extend(resolve_js(rel, "/" + joined))
        # Bundler aliases (Vite, webpack) are often not in the config; try the
        # conventional ones, but never beyond the governing config's directory.
        if not targets and spec[:2] in ("@/", "~/", "#/") and len(spec) > 2:
            scope = ancestors if config_dir is None else ancestors[:ancestors.index(config_dir) + 1]
            for base in scope:
                for root in (base, f"{base}/src" if base else "src"):
                    targets.extend(resolve_js(rel, "/" + "/".join(x for x in (root, spec[2:]) if x)))
        return targets

    def resolve_py(rel, dots, module, names):
        if dots:
            pkg = Path(rel).parent
            for _ in range(len(dots) - 1):
                pkg = pkg.parent
            bases = [pkg.as_posix() if pkg.as_posix() != "." else ""]
        else:
            # A file run as a script adds its own directory to Python's import path,
            # and an application package can sit below the repository root
            # (backend/app/main.py importing app.models): try every ancestor.
            parent = Path(rel).parent
            bases = list(dict.fromkeys(["", "src", *("" if a.as_posix() == "." else a.as_posix()
                                                     for a in (parent, *parent.parents))]))
        targets = []
        for base in bases:
            stem = "/".join(x for x in [base, module.replace(".", "/")] if x)
            for cand in (stem + ".py", stem + "/__init__.py"):
                if cand in files:
                    targets.append(cand)
            for name in names:
                for cand in (f"{stem}/{name}.py" if stem else f"{name}.py", f"{stem}/{name}/__init__.py"):
                    if cand in files:
                        targets.append(cand)
        return targets

    for rel in code_files:
        ext, text = suffix(rel), texts[rel]
        if ext in JS_EXT or ext in (".html", ".htm"):
            for spec in js_import_specs(text):
                if spec.startswith((".", "/")):
                    for target in resolve_js(rel, spec):
                        inbound[target].add(rel)
                else:
                    for target in resolve_alias(rel, spec):
                        inbound[target].add(rel)
                    pkg = js_package(spec)
                    if pkg:
                        js_packages[pkg] += 1
        elif ext in PY_EXT:
            imports = python_imports[rel] if rel in python_imports else py_import_specs(text)
            for dots, module, names in imports:
                if not dots and module:
                    # Distribution names compare case-insensitively (PyQt5, MySQLdb).
                    py_modules[module.split(".")[0].lower()] += 1
                    # Namespace distributions (azure-storage-blob, ruamel.yaml)
                    # are imported by their dotted path, not one top-level name.
                    parts = module.lower().split(".")
                    for n in range(2, len(parts) + 1):
                        py_modules[".".join(parts[:n])] += 1
                for target in resolve_py(rel, dots, module, names):
                    inbound[target].add(rel)
        elif ext in CSS_EXT:
            # @import "normalize.css" and @use "bootstrap/scss/..." load packages.
            for spec in CSS_IMPORT.findall(text):
                if not spec.startswith((".", "/")) and "://" not in spec:
                    pkg = js_package(spec)
                    if pkg:
                        js_packages[pkg] += 1
        elif ext in GO_EXT:
            for module in go_import_paths(text):
                go_imports[module] += 1
        elif ext in RS_EXT:
            for m in RS_USE.finditer(text):
                rs_crates[m.group(1) or m.group(2)] += 1
    orphans = []
    for rel in sorted(code_files):
        if suffix(rel) not in PY_EXT | JS_EXT or is_test(rel) or Path(rel).stem in ENTRY_STEMS:
            continue
        if re.search(r"\.config\.\w+$|\.d\.(?:ts|mts|cts)$", rel) or named_elsewhere(rel):
            continue
        importers = inbound.get(rel, set()) - {rel}
        if any(not is_test(i) for i in importers):
            continue
        orphans.append({"path": rel, "test_importers": sorted(importers)[:MAX_LOCATIONS]})
    rows["orphan_files"] = orphans

    # Dependencies.
    tool_text = "\n".join(t for r, t in texts.items() if TOOL_FILES.search(r))
    declared, unimported, dup_rows, platform_rows = [], [], [], []
    for rel, text in sorted(texts.items()):
        name = Path(rel).name
        deps = []
        ecosystem = None
        if name == "package.json":
            ecosystem = "javascript"
            pkg = package_sections(text)
            key_lines = section_key_lines(text) if pkg else {}
            scripts = " ".join(v for v in pkg.get("scripts", {}).values() if isinstance(v, str))
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                for dep in pkg.get(section, {}):
                    loc = f"{rel}:{key_lines.get((section, dep), 1)}"
                    deps.append((dep, section, loc, js_packages[dep],
                                 len(re.findall(r"(?<![\w@/-])%s(?![\w-])" % re.escape(dep.split("/")[-1]),
                                                scripts + "\n" + tool_text.replace(text, "")))))
        elif re.match(r"requirements[\w.-]*\.(?:txt|in)$", name) or name == "pyproject.toml":
            ecosystem = "python"
            parsed = parse_requirements(rel, text) if name != "pyproject.toml" else parse_toml_lists(rel, text)
            for dep, section, loc in parsed:
                modules = {py_dist_module(dep).lower(), re.sub(r"[-.]", "_", dep.lower())}
                if re.search(r"[-.]", dep):
                    modules.add(re.sub(r"[-.]", ".", dep.lower()))
                deps.append((dep, section, loc, sum(py_modules[module] for module in modules),
                             len(re.findall(r"(?<![\w-])%s(?![\w-])" % re.escape(dep), tool_text.replace(text, "")))))
        elif name == "go.mod":
            for dep, section, loc in parse_go_mod(rel, text):
                deps.append((dep, section, loc, sum(n for p, n in go_imports.items() if p == dep or p.startswith(dep + "/")),
                             0))
        elif name == "Cargo.toml":
            for dep, section, loc in parse_toml_lists(rel, text):
                deps.append((dep, section, loc, rs_crates[dep.replace("-", "_")], 0))
        if not deps:
            continue
        declared.append({"manifest": rel, "count": len(deps)})
        names = {d[0].lower() for d in deps}
        for group, members in DUPLICATE_GROUPS.get(ecosystem, {}).items():
            hit = sorted(names & members)
            if len(hit) > 1:
                dup_rows.append({"group": group, "manifest": rel, "names": hit})
        replacements = PLATFORM_REPLACEABLE.get(ecosystem, {})
        for dep, section, loc, imports, mentions in deps:
            if dep.lower() in replacements:
                platform_rows.append({"name": dep, "manifest": rel, "replacement": replacements[dep.lower()],
                                      "imports": imports, "location": loc})
            if imports == 0:
                unimported.append({"name": dep, "manifest": rel, "section": section, "location": loc,
                                   "mentions": mentions, "status": "script_only" if mentions else "unreferenced",
                                   "implicit_tool": bool(IMPLICIT_TOOLS.match(dep.lower()))})
    rows["dependencies_declared"] = declared
    rows["unimported_dependencies"] = unimported
    rows["duplicate_purpose"] = dup_rows
    rows["platform_replaceable"] = platform_rows

    # Environment variables: names only, never values.
    reads = defaultdict(list)
    decl, decl_files = {}, []
    for rel, text in sorted(texts.items()):
        if ENV_DECL_FILE.match(Path(rel).name):
            decl_files.append(rel)
            for m in ENV_DECL.finditer(text):
                decl.setdefault(m.group(1), f"{rel}:{line_of(text, m.start(1))}")
            continue
        if rel in code_files:
            found = [(next(g for g in m.groups() if g), m.start()) for m in ENV_READ.finditer(text)]
            if suffix(rel) in JS_EXT:
                found.extend((key.group(1), m.start(1) + key.start(1)) for m in ENV_DESTRUCTURE.finditer(text)
                             for key in ENV_DESTRUCTURED_KEY.finditer(m.group(1)))
            for name, start in sorted(found, key=lambda item: item[1]):
                reads[name].append(f"{rel}:{line_of(text, start)}")
    rows["env_read"] = [{"name": n, "count": len(locs), "locations": locs[:MAX_LOCATIONS]} for n, locs in sorted(reads.items())]
    rows["env_declared_not_read"] = [{"name": n, "location": loc} for n, loc in sorted(decl.items()) if n not in reads]
    rows["env_read_not_declared"] = ([{"name": n, "locations": reads[n][:MAX_LOCATIONS]}
                                      for n in sorted(reads) if n not in decl] if decl_files else [])

    # Feature flags.
    flags = defaultdict(lambda: {"definitions": [], "values": set(), "checks": []})
    secret_checks = []
    for rel in code_files:
        text = texts[rel]
        if rel in secret_sources:
            # Their checks count for flags named elsewhere; their names never become rows.
            secret_checks.extend((m.group(1), f"{rel}:{line_of(text, m.start())}") for m in FLAG_CHECK.finditer(text))
            continue
        if FLAG_FILE.search(rel):
            for m in FLAG_DEF.finditer(text):
                f = flags[m.group(1)]
                f["definitions"].append(f"{rel}:{line_of(text, m.start(1))}")
                f["values"].add(m.group(2).lower() in ("true", "on"))
        for m in FLAG_CHECK.finditer(text):
            flags[m.group(1)]["checks"].append(f"{rel}:{line_of(text, m.start())}")
    for name, location in secret_checks:
        if name in flags:
            flags[name]["checks"].append(location)
    for name, locs in reads.items():
        # Only reads outside secret-named sources make an env var a flag row.
        public = [loc for loc in locs if loc.rpartition(":")[0] not in secret_sources]
        if ENV_FLAG.match(name) and (public or name in flags):
            flags[name]["checks"].extend(locs)
            flags[name]["source"] = "env"
    rows["feature_flags"] = [
        {"name": n, "value": (next(iter(f["values"])) if len(f["values"]) == 1 else ("mixed" if f["values"] else None)),
         "source": f.get("source", "code"), "definitions": f["definitions"][:MAX_LOCATIONS],
         "checks": len(f["checks"]), "locations": f["checks"][:MAX_LOCATIONS]}
        for n, f in sorted(flags.items())]

    # Locale keys.
    # Prefixes from secret-named sources suppress candidates but are never listed.
    quoted, prefixes, secret_prefixes = set(), set(), set()
    for rel in code_files:
        if suffix(rel) == ".json":
            continue
        quoted.update(QUOTED.findall(texts[rel]))
        for literal in STRING_LITERAL.finditer(texts[rel]):
            value = next(g for g in literal.groups() if g is not None)
            quoted.add(value)
            if ":" in value:
                quoted.add(value.split(":", 1)[1])  # i18next namespace: common:save
        (secret_prefixes if rel in secret_sources else prefixes).update(DYNAMIC_KEY.findall(texts[rel]))
    i18n = []
    locale_lines = {}
    for bundle, langs in sorted(col.locales.items()):
        keys = defaultdict(list)
        for lang, (rel, flat) in sorted(langs.items()):
            for key in flat:
                keys[key].append((lang, rel))
        for key, where in sorted(keys.items()):
            if key in quoted or any(key.startswith(p) for p in prefixes | secret_prefixes):
                continue
            first = where[0][1]
            if first not in locale_lines:
                locale_lines[first] = json_key_lines(texts[first])
            i18n.append({"key": key, "bundle": bundle, "langs": [lang for lang, _ in where],
                         "location": f"{first}:{key_line(texts[first], key, lines=locale_lines[first])}"})
    rows["i18n_unreferenced"] = i18n
    rows["i18n_dynamic_prefixes"] = sorted(prefixes)

    # Assets.
    rows["assets_unreferenced"] = [
        {"path": rel, "bytes": size, "public": bool(re.match(r"(?:.*/)?(?:public|static|www)/", rel))}
        for rel, size in sorted(col.assets) if not named_elsewhere(rel)]

    # CSS classes.
    css_tokens, class_prefixes, secret_class_prefixes = set(), set(), set()
    for rel in code_files:
        if suffix(rel) in CSS_EXT:
            continue
        css_tokens.update(CSS_TOKEN.findall(texts[rel]))
        (secret_class_prefixes if rel in secret_sources else class_prefixes).update(
            dynamic_class_prefixes(texts[rel]))
    css_rows, seen_classes = [], set()
    for rel in sorted(r for r in texts if suffix(r) in CSS_EXT):
        if Path(rel).stem.endswith(".module"):
            continue
        # An unclosed comment runs through EOF; never retry its nested opening markers.
        text = re.sub(r"/\*.*?(?:\*/|\Z)", lambda m: re.sub(r"[^\n]", " ", m.group(0)), texts[rel], flags=re.S)
        # Start after a delimiter, without consuming it: nested selectors still get a turn.
        # Retrying every suffix of a long brace-free segment would take quadratic time.
        for m in re.finditer(r"(?:\A|(?<=[{};]))([^{};]+)\{", text):
            selector = m.group(1)
            if selector.strip().startswith("@"):
                continue
            # a[href$=".pdf"] has no class; blank attribute selectors and strings in place.
            selector = re.sub(r"\[[^\]]*\]|\"[^\"]*\"|'[^']*'", lambda s: " " * len(s.group(0)), selector)
            for c in re.finditer(r"(?<![\w-])\.(-?[A-Za-z_][\w-]*)", selector):
                name = c.group(1)
                if (name in seen_classes or name in css_tokens
                        or any(name.startswith(p) for p in class_prefixes | secret_class_prefixes)):
                    continue
                seen_classes.add(name)
                css_rows.append({"class": name, "location": f"{rel}:{line_of(text, m.start(1) + c.start())}"})
    rows["css_unreferenced"] = css_rows
    rows["css_dynamic_prefixes"] = sorted(class_prefixes)

    # Routes.
    route_rows, seen_routes, definition_spans = [], set(), defaultdict(list)
    for rel in code_files:
        text = texts[rel]
        # api.get("/users/me") on an axios, ky or ofetch instance is a client
        # call, not a route; an express router named api in the same file is not.
        http_client = bool(re.search(r"\b(?:const|let|var)\s+api\s*=\s*(?:axios|ky|ofetch)\b", text))
        for kind, regex in ROUTE_DEFS:
            for m in regex.finditer(text):
                route = m.group(2)
                where = f"{rel}:{line_of(text, m.start())}"
                if (kind == "client" and suffix(rel) not in JS_EXT) or (where, route) in seen_routes:
                    continue
                if http_client and m.group(0).startswith("api."):
                    continue
                seen_routes.add((where, route))
                definition_spans[rel].append(m.span(2))
                if rel in secret_sources:
                    continue  # Its definitions are not mentions, but its literals are never output.
                route_rows.append({"route": route, "method": m.group(1).upper() if kind == "server" else "",
                                   "kind": kind, "location": where})
    for row in route_rows:
        # Strip Django's regex anchors (^api/items/$) here, before escaping: the
        # joiner below holds a literal \$ for ${...} that must stay intact.
        route = row["route"].removeprefix("^")
        route = route[:-1] if route.endswith("$") and not route.endswith("\\$") else route
        route = route if route.startswith("/") or row["kind"] == "client" else "/" + route
        parts = [re.escape(p) for p in PARAM.split(route)]
        # A bounded ${...} on one line keeps an unclosed one from rescanning the file.
        pattern = r"(?:\$\{[^}\n]{0,200}\}|[^/\"'`\s?#]+)".join(parts)
        static = PARAM.sub("", route).strip("/^$")
        row["dynamic"] = bool(PARAM.search(route))
        if not static:
            row["mentions"], row["mentioned_in"] = None, []
            continue
        # A host still names the route (https://host/api/items). For a server
        # route, so does a preceding path segment: a router mounted under /api
        # serves /items as /api/items. A client route is the page's own path.
        # Route path literals in definitions are not mentions (below).
        # Every character a mount segment can hold ($VERSION included) is
        # excluded before the match, so a match starts once per path;
        # @/pages/users is an import, not a URL.
        mount = r"(?:/[\w.$-]+)*?" if row["kind"] == "server" else ""
        # A trailing slash is optional on either side (/api/items/ names /api/items),
        # but only where the path ends there: /api/items/${id} and "/api/items/" + id
        # are another route.
        route_pattern = pattern.rstrip("/").rstrip("\\/")
        # Every match holds the route's longest literal piece; skip files without it.
        needle = max((piece.strip("/") for piece in PARAM.split(route)), key=len)
        rx = re.compile(r"(?<![\w/.:@~$-])(?:(?:https?:)?//[\w.:@-]+)?%s%s"
                        r"(?:/(?=[\s?#)\]}>,;<]|\Z|[\x22\x27`](?!\s*\+))|(?![\w/-]))" % (mount, route_pattern))
        where = []
        for rel, text in texts.items():
            if needle not in text:
                continue
            hits = [m for m in rx.finditer(text)]
            # A route's own path literal, or another route's (/api/items holds
            # /items), is not a mention; a redirect on a definition line is.
            spans = definition_spans.get(rel, ())
            hits = [m for m in hits if not any(m.start() < end and start < m.end() for start, end in spans)]
            if hits:
                where.append(rel)
        row["mentions"], row["mentioned_in"] = len(where), sorted(where)[:MAX_LOCATIONS]
    route_rows.sort(key=lambda r: loc_key(r["location"]))
    rows["routes"] = route_rows
    rows["unreferenced_routes"] = [r for r in route_rows if r["mentions"] == 0]

    # Make targets and package scripts.
    script_rows = []
    # A Makefile and the files it includes (or that include it) form one
    # project: their targets share command lines (make deps build) and
    # prerequisite lists. Unrelated Makefiles do not.
    make_files = sorted(rel for rel in texts
                        if Path(rel).name in ("Makefile", "makefile", "GNUmakefile") or rel.endswith(".mk"))
    project = {rel: rel for rel in make_files}

    def project_of(rel):
        while project[rel] != rel:
            project[rel] = project[project[rel]]
            rel = project[rel]
        return rel
    for rel in make_files:
        for line in MAKE_INCLUDE.findall(texts[rel]):
            for included in line.split():
                if "$" in included:
                    continue
                target = os.path.normpath((Path(rel).parent / included).as_posix()).replace(os.sep, "/")
                if target in project:
                    project[project_of(target)] = project_of(rel)
    project_targets, project_prerequisites = defaultdict(set), defaultdict(Counter)
    for rel in make_files:
        text = texts[rel]
        project_targets[project_of(rel)].update(name for name, _ in make_targets(text))
        # Another rule's prerequisite list runs the target too (all: build).
        for rule in MAKE_RULE.finditer(text):
            owners = set(rule.group(1).split())
            if any(owner.startswith(".") for owner in owners):
                continue  # .PHONY: build declares, it does not run.
            for prerequisite in set(rule.group(2).replace("|", " ").split()) - owners:
                project_prerequisites[project_of(rel)][prerequisite] += 1
    make_dirs = defaultdict(list)
    for make_file in make_files:
        make_dirs[Path(make_file).parent.as_posix()].append(make_file)

    def select_project(rel, directories, makefiles):
        """The project a command's -C and -f options name, from the repository root or the file's directory."""
        for base in (Path(rel).parent, Path(".")):
            directory = base
            for name in directories:
                directory = directory / name
            if makefiles:
                target = os.path.normpath((directory / makefiles[-1]).as_posix()).replace(os.sep, "/")
                if target in project:
                    return project_of(target)
                continue
            found = make_dirs.get(os.path.normpath(directory.as_posix()).replace(os.sep, "/"))
            if found:
                return project_of(sorted(found)[0])
        return None
    all_scripts = frozenset(name for rel, text in texts.items() if Path(rel).name == "package.json"
                            for name in package_sections(text).get("scripts", {}))
    make_calls, npm_calls = invocation_counts(texts, {p: frozenset(t) for p, t in project_targets.items()},
                                              all_scripts, select_project)
    for rel, text in sorted(texts.items()):
        name = Path(rel).name
        if name in ("Makefile", "makefile", "GNUmakefile") or rel.endswith(".mk"):
            prerequisites = project_prerequisites[project_of(rel)]
            calls = make_calls[project_of(rel)]
            for n, (target, start) in enumerate(make_targets(text)):
                hits = calls[target] + prerequisites[target]
                script_rows.append({"source": rel, "name": target, "location": f"{rel}:{line_of(text, start)}",
                                    "invocations": hits, "default": n == 0})
        elif name == "package.json":
            scripts = package_sections(text).get("scripts", {})
            key_lines = section_key_lines(text) if scripts else {}
            implicit_start = (Path(rel).parent / "server.js").as_posix() in files
            for script in scripts:
                hits = npm_calls[script]
                hook = re.match(r"^(?:pre|post)(.+)$", script)
                lifecycle = bool(script in NPM_LIFECYCLES or hook and (
                    hook.group(1) in scripts or hook.group(1) == "start" and implicit_start))
                script_rows.append({"source": rel, "name": script,
                                    "location": f"{rel}:{key_lines.get(('scripts', script), 1)}",
                                    "invocations": hits, "default": lifecycle})
    rows["scripts"] = script_rows
    rows["uninvoked_scripts"] = [r for r in script_rows if r["invocations"] == 0 and not r["default"]]

    # Loose files: scripts, SQL and docs nothing names.
    loose = []
    for rel in sorted(texts):
        p = Path(rel)
        if p.suffix.lower() not in LOOSE_EXT or "migrations" in p.parts or p.stem.lower() in ROOT_DOCS:
            continue
        if not (set(x.lower() for x in p.parts[:-1]) & LOOSE_DIRS) or named_elsewhere(rel):
            continue
        loose.append({"path": rel, "kind": {".sql": "sql", ".md": "doc", ".rst": "doc", ".txt": "doc"}.get(
            p.suffix.lower(), "script")})
    rows["unreferenced_files"] = loose

    # Skipped tests, commented-out code, dated markers.
    skipped, commented, markers = [], [], []
    for rel, text in sorted(texts.items()):
        ext = suffix(rel)
        # Preserve candidates and their metadata, but do not export arbitrary
        # source text when a value elsewhere in the file may continue here.
        omitted_text = ("[omitted: source may contain secrets]"
                        if sensitive_source(text) or secret_named(Path(rel).parts) else None)
        if rel in code_files and is_test(rel):
            for m in SKIPPED_TEST.finditer(text):
                line = text[text.rfind("\n", 0, m.start()) + 1:].split("\n", 1)[0].strip()
                skipped.append({"location": f"{rel}:{line_of(text, m.start())}", "text": omitted_text or line[:120]})
        comment_line = COMMENT_LINE.get(ext)
        if comment_line:
            run = []
            for n, line in enumerate(physical_lines(text) + [""], 1):
                m = comment_line.match(line)
                if m and not line.lstrip().startswith(("#!", "# -*-")):
                    run.append((n, m.group(1)))
                    continue
                if len(run) >= 4:
                    code = sum(1 for _, body in run if CODE_LIKE.search(body))
                    if code / len(run) >= 0.6:
                        commented.append({"location": f"{rel}:{run[0][0]}-{run[-1][0]}", "lines": len(run)})
                run = []
        if ext in PROSE_EXT or rel in locale_files or ext == ".json":
            continue
        for n, line in enumerate(physical_lines(text), 1):
            m = MARKER.search(line)
            if not m:
                continue
            word = m.group(1).lower()
            date = DATE.search(line)
            if not date and word not in ALWAYS_MARKERS and not word.startswith("remove"):
                continue
            row = {"marker": word, "location": f"{rel}:{n}", "text": omitted_text or line.strip()[:120]}
            if date:
                row["date"] = date.group(1)
                row["overdue"] = date.group(1) < today[:len(date.group(1))]
            markers.append(row)
    rows["skipped_tests"] = skipped
    rows["commented_code"] = commented
    rows["markers"] = markers

    # SQL schema: tables and columns no non-SQL code names.
    # Unquoted SQL identifiers are case-insensitive, so names are compared folded.
    tables, columns = [], []
    sql_files = sorted(r for r in texts if suffix(r) == ".sql")
    folded = Counter()
    for name, count in (idents.items() if sql_files else ()):
        folded[name.lower()] += count
    for rel in sql_files:
        text = texts[rel]
        for table, start, body_start, body in sql_table_specs(text):
            if folded[table.lower()] == 0:
                tables.append({"table": table, "location": f"{rel}:{line_of(text, start)}"})
                continue
            body = blank_sql_body(body)
            for c in re.finditer(r"(?:^|,)\s*[`\"\[]?(\w+)[`\"\]]?\s+\w", body):
                col_name = c.group(1)
                if col_name.lower() in SQL_CONSTRAINT or folded[col_name.lower()]:
                    continue
                columns.append({"table": table, "column": col_name,
                                "location": f"{rel}:{line_of(text, body_start + c.start(1))}"})
    rows["sql_tables_unreferenced"] = tables
    rows["sql_columns_unreferenced"] = columns

    if units:
        tag_units(rows, units)

    # Caps apply only after every list was measured; each cut is counted.
    truncated = {}
    for key, value in rows.items():
        if isinstance(value, list) and len(value) > MAX_ROWS:
            truncated[key] = len(value) - MAX_ROWS
            rows[key] = value[:MAX_ROWS]
    line_breaks.cache_clear()
    return {
        "tool": "inventory.py", "version": 1,
        "repository": root.name.encode("utf-8", "backslashreplace").decode("utf-8"), "today": today,
        "files_scanned": len(texts), "files_skipped": col.skipped,
        "env_declaration_files": decl_files, "decorated_symbols_skipped": decorated_skipped,
        **rows,
        "limits": {"rows": MAX_ROWS, "locations_per_row": MAX_LOCATIONS, "file_bytes": MAX_BYTES},
        "truncated": truncated,
    }


# Complete listings, not candidates: their candidates are listed again
# (unreferenced_routes, uninvoked_scripts, env_*_not_*, unimported_dependencies).
INVENTORY_ONLY = ("routes", "scripts", "env_read", "dependencies_declared")


def tag_units(rows, units):
    """Tag every row that has a path with the most specific unit whose paths cover it; count candidates per unit."""
    prefixes = []
    for unit in units["units"]:
        for path in unit["paths"]:
            prefix = Path(path).as_posix()
            prefixes.append(("" if prefix == "." else prefix, unit["id"]))
    prefixes.sort(key=lambda item: -len(item[0]))

    def unit_of(rel):
        for prefix, uid in prefixes:
            if not prefix or rel == prefix or rel.startswith(prefix + "/"):
                return uid
        return None
    counts = Counter()
    for name, value in rows.items():
        if not isinstance(value, list):
            continue
        for row in value:
            if not isinstance(row, dict):
                continue
            # Env and flag rows keep their paths in locations or definitions.
            listed = row.get("definitions") or row.get("locations") or [""]
            location = row.get("location") or (listed[0] if isinstance(listed[0], str) else "")
            where = row.get("path") or location.rsplit(":", 1)[0] or row.get("manifest")
            if where:
                row["unit"] = unit_of(where)
                if name not in INVENTORY_ONLY:
                    counts[row["unit"] or "none"] += 1
    rows["by_unit"] = dict(sorted(counts.items()))


@contextmanager
def selected_units(path):
    """Keep the identity of the regular file actually parsed until its output is committed."""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise RecordError(f"{path}: expected a regular JSON file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            units = check_units(parse_json(handle.read(), where=str(path)))
        yield units, info
    finally:
        os.close(descriptor)


def output_is_source(directory, name, source):
    """Compare actual entries, including case aliases; a final output symlink is replaced safely."""
    try:
        existing = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return os.path.samestat(existing, source)


def main(argv=None):
    tolerant_stdout()
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("repo")
    p.add_argument("--out", required=True)
    p.add_argument("--units")
    p.add_argument("--today", help="date that markers are judged overdue against (default: today)")
    a = p.parse_args(argv)
    if not Path(a.repo).is_dir():
        print(f"inventory.py: {a.repo} is not a directory", file=sys.stderr)
        return 2
    if a.today:
        try:
            if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", a.today):
                raise ValueError
            datetime.date.fromisoformat(a.today)
        except ValueError:
            print("inventory.py: --today expects a valid calendar date (YYYY-MM-DD)", file=sys.stderr)
            return 2
    if a.units and not SAFE_OUTPUT:
        print("inventory.py: --units requires descriptor-relative output support to preserve its source",
              file=sys.stderr)
        return 2
    output, directory, units, source = Path(a.out), None, None, None
    if within(output.parent, a.repo):
        # SKILL.md: nothing is written inside the reviewed repository.
        print(f"inventory.py: --out must be outside the reviewed repository; {a.out} is inside {a.repo}",
              file=sys.stderr)
        return 2
    with ExitStack() as resources:
        if SAFE_OUTPUT:
            try:
                selected = output.parent.stat()
                directory = open_directory(output.parent.resolve(strict=True), readable=False, expected_stat=selected)
                resources.callback(os.close, directory)
            except (OSError, ValueError, RuntimeError) as e:
                print(f"inventory.py: --out: {e}", file=sys.stderr)
                return 2 if a.units else 1
        if a.units:
            try:
                units, source = resources.enter_context(selected_units(a.units))
                if output_is_source(directory, output.name, source):
                    print("inventory.py: output would overwrite the units source; choose a different --out file",
                          file=sys.stderr)
                    return 2
            except (OSError, ValueError, RecordError) as e:
                print(f"inventory.py: units: {e}", file=sys.stderr)
                return 2
        try:
            result = inventory(a.repo, units, a.today)
        except (OSError, RuntimeError) as e:
            print(f"inventory.py: cannot read repository: {e}", file=sys.stderr)
            return 2
        try:
            text = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
            if directory is None:
                # Preserve untagged scans on runtimes without descriptor-relative writes.
                write_output(output, text)
            else:
                write_output_at(directory, output.name, text, protected=(source,) if source is not None else ())
        except (OSError, ValueError) as e:
            print(f"inventory.py: cannot write {a.out}: {e}", file=sys.stderr)
            return 1
    counts = ", ".join(f"{len(result[k])} {k.replace('_', ' ')}" for k in (
        "unreferenced_symbols", "orphan_files", "unimported_dependencies", "feature_flags", "unreferenced_routes",
        "i18n_unreferenced", "assets_unreferenced", "css_unreferenced"))
    print(f"wrote {a.out}: {result['files_scanned']} files, {counts}"
          + (f"; truncated {', '.join(result['truncated'])}" if result["truncated"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
