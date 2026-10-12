#!/usr/bin/env python3
"""Inventory UI/UX signals in a repository: candidates for review, never findings.

    python3 inventory.py REPO --out inventory.json [--flows flows.json]

Collects routes and links, token sources, spacing / font-size / breakpoint /
z-index literals, fixed widths, small tap targets, removed focus outlines,
viewport zoom locks, click handlers on non-interactive elements, images,
form inputs, icon-only buttons, positive tabindex, data views missing loading /
empty / error branches, destructive actions without confirmation or undo,
motion without reduced-motion handling, truncation and locale text expansion;
with --flows, also literals off the token scales, widths wider than the
smallest supported viewport and, when an RTL locale ships, physical direction
properties (reference/inventory.md). Read-only, standard library only.
Exit status: 0 written, 2 bad arguments or unreadable flows, 1 output not written.
"""

import argparse
import html
import json
import math
import os
import re
import sys
import unicodedata
from bisect import bisect_left, bisect_right
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import RecordError, canonical_digest, check_flows, load_json, loads_json  # noqa: E402
from scan_report_kit.output import write_output  # noqa: E402

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "out", ".next", ".nuxt",
             ".svelte-kit", "coverage", ".venv", "venv", "__pycache__", "Pods", ".gradle", "target",
             ".turbo", ".cache", "bower_components", ".idea", ".vscode", "DerivedData", ".dart_tool",
             "storybook-static", ".output"}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock", "poetry.lock", "Gemfile.lock",
              "go.sum", "composer.lock", "Podfile.lock", "pubspec.lock", "bun.lockb", "uv.lock"}
MAX_BYTES = 2 * 1024 * 1024
MAX_LOCATIONS = 5
MAX_ROWS = 200
MAX_KEYS = 50
MAX_INTEGER_DIGITS = 1000
MAX_LOCALE_DEPTH = 256

CSS_EXT = {".css", ".scss", ".sass", ".less", ".styl", ".pcss"}
EMBED_CSS_EXT = {".html", ".htm", ".vue", ".svelte", ".astro"}
JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro"}
MARKUP_EXT = {".js", ".jsx", ".tsx", ".mjs", ".vue", ".svelte", ".astro", ".html", ".htm", ".erb", ".hbs",
              ".handlebars", ".ejs", ".php", ".njk", ".liquid", ".twig", ".mustache", ".jinja", ".j2", ".mdx"}
HTML_EXT = {".html", ".htm", ".erb", ".hbs", ".handlebars", ".ejs", ".php", ".njk", ".liquid",
            ".twig", ".mustache", ".jinja", ".j2"}
JSX_EXT = {".js", ".jsx", ".tsx", ".mjs", ".mdx"}
LOCALE_DIR = re.compile(r"(?i)(?:^|/)(?:locales?|i18n|l10n|lang|langs|languages|translations|messages)(?:/|$)")
LANG = re.compile(r"^[a-z]{2,3}(?:[-_][A-Za-z]{2,4})?$")
RTL_LANGS = {"ar", "he", "iw", "fa", "ur", "yi", "ps", "sd", "ug", "dv", "ckb"}

LENGTH = re.compile(r"(?<![\w.#-])(-?(?:\d+(?:\.\d+)?|\.\d+))(px|rem|em)\b")
CSS_SPACING = re.compile(r"(?<![\w-])(?:margin|padding|gap|row-gap|column-gap)"
                         r"(?:-(?:top|right|bottom|left|inline|block)(?:-start|-end)?)?\s*:\s*([^;{}\n]+)")
JS_SPACING = re.compile(r"\b(?:margin|padding|gap|rowGap|columnGap)(?:Top|Right|Bottom|Left|Inline|Block|X|Y)?"
                        r"(?:Start|End)?\s*:\s*(?:(-?\d+(?:\.\d+)?)\s*(?=[,}\n])|[\"'`]([^\"'`\n]{1,60})[\"'`])")
CSS_FONT_SIZE = re.compile(r"(?<![\w-])font-size\s*:\s*([^;{}\n]+)")
JS_FONT_SIZE = re.compile(r"\bfontSize\s*:\s*(?:(\d+(?:\.\d+)?)\s*(?=[,}\n])|[\"'`]([^\"'`\n]{1,40})[\"'`])")
MEDIA = re.compile(r"\(\s*(?:(?:min|max)-width\s*:|width\s*[<>]=?)\s*(\d+(?:\.\d+)?)(px|em|rem)\s*\)")
CSS_Z = re.compile(r"(?<![\w-])z-index\s*:\s*(-?\d+)")
JS_Z = re.compile(r"\bzIndex\s*:\s*[\"']?(-?\d+)")
# A parenthesized condition tests a width; it does not set an element's width.
CSS_WIDTH = re.compile(r"(?<![\w-])(width|min-width)\s*:\s*(\d+(?:\.\d+)?)(px|rem)\b"
                       r"(?!\s*(?:(?i:!important)\s*)?\))")
JS_WIDTH = re.compile(r"\b(width|minWidth)\s*:\s*(?:(\d+(?:\.\d+)?)\s*(?=[,}\n])|[\"'](\d+(?:\.\d+)?)px[\"'])")
# Start at a selector boundary, not every character of a brace-free segment.
# Otherwise even a long CSS comment causes quadratic failed matches.
BLOCK = re.compile(r"(?<![^{};])([^{};]+)\{([^{}]*)\}")
SIZE_DECL = re.compile(r"(?<![\w-])(width|height|min-width|min-height)\s*:\s*(\d+(?:\.\d+)?)(px|rem)\b")
TAP_SELECTOR = re.compile(r"(?i)btn|button|icon|close|chip|toggle|\btab\b|link|(?:^|[\s,>+~])a(?=$|[\s.:#\[,>+~])|checkbox|radio")
OUTLINE_NONE = re.compile(r"(?<![\w-])outline\s*:\s*(?:none|0)\b")
JS_OUTLINE_NONE = re.compile(r"\boutline\s*:\s*[\"'](?:none|0)[\"']")
FOCUS_REPLACEMENT = re.compile(r"box-shadow\s*:|border[\w-]*\s*:|background[\w-]*\s*:|text-decoration\s*:|"
                               r"outline(?:-color|-style|-width)?\s*:\s*(?!none|0\b)")
CSS_MOTION = re.compile(r"(?<![\w-])(transition|animation)(?:-duration|-name)?\s*:\s*(?!\s*none\b)([^;{}\n]+)")
JS_MOTION = re.compile(r"\b(transition|animation)\s*:\s*[\"'`](?!none)")
REDUCED_MOTION = re.compile(r"prefers-reduced-motion|useReducedMotion|reducedMotion|ReducedMotion")
TRUNCATION = re.compile(r"text-overflow\s*:\s*ellipsis|line-clamp\s*:|white-space\s*:\s*nowrap|"
                        r"textOverflow\s*:\s*[\"']ellipsis|WebkitLineClamp|whiteSpace\s*:\s*[\"']nowrap|"
                        r"class(?:Name)?\s*=\s*[\"'][^\"']*\b(?:truncate|line-clamp-\d)\b")
PHYSICAL = re.compile(r"(?<![\w-])(margin-left|margin-right|padding-left|padding-right|border-left|border-right|"
                      r"text-align\s*:\s*(?:left|right)|float\s*:\s*(?:left|right)|(?<![\w-])(?:left|right)(?=\s*:))|"
                      r"\b(marginLeft|marginRight|paddingLeft|paddingRight|borderLeft|borderRight)\s*:")
CUSTOM_PROPERTY = re.compile(r"(?<![\w-])--[\w-]+\s*:")
TOKEN_FILE = re.compile(r"(?i)(?:^|[/_.-])(?:tokens?|theme|variables|design-system)\.|tailwind\.config\.")
FETCH = re.compile(r"\bfetch\(|\baxios[.(]|\buse(?:Query|SWR|InfiniteQuery|Fetch|LoaderData)\b|\$fetch\(|"
                   r"\bcreateResource\b|\buseAsyncData\b")
LOADING = re.compile(r"(?i)\b(?:is)?loading\b|\bis_?pending\b|\bpending\b|\bisFetching\b|Skeleton|Spinner|<Suspense|"
                     r"\bstatus\s*===?\s*[\"'](?:loading|pending)")
ERROR = re.compile(r"(?i)\b(?:is)?error\b|\.catch\(|\bcatch\s*[({]|ErrorBoundary|onError\b|\bfailed\b")
LIST_RENDER = re.compile(r"\.map\(|\bv-for=|\{#each\b|\*ngFor=")
EMPTY = re.compile(r"(?i)\.length\s*===?\s*0|!\s*[\w.?]+\.length\b|\.length\s*<\s*1|\bEmpty\w*|\bisEmpty\b|"
                   r"\bno \w+ yet\b|\bnothing\b")
DESTRUCTIVE = re.compile(r"(?i)(?:on(?:click|press|tap)\s*=\s*\{[^{}]*?|@click\s*=\s*\"[^\"]*?|on:click\s*=\s*\{[^{}]*?)"
                         r"\b((?:\w+\.)?(?:delete|remove|destroy|discard|erase|purge|drop)\w*)\s*\(")
CONFIRM = re.compile(r"(?i)\bconfirm\w*\b|\bundo\b|Dialog|\bModal\b|AlertDialog|\bare you sure\b")
ROUTE = re.compile(r"<Route\b[^>]*?\bpath\s*=\s*[\"']([^\"']+)[\"']|\bpath\s*:\s*[\"'](/[^\"']*)[\"']")
LINK = re.compile(r"(?<![\w-])(?:to|href)\s*=\s*\{?\s*[\"'`](/[^\"'`?#]*)|"
                  r"\b(?:navigate|push|replace|redirect)\(\s*[\"'`](/[^\"'`?#]*)")
FILE_ROUTE = re.compile(r"(?:^|/)app/((?:[^/]+/)*)page\.(?:tsx|jsx|js|mdx)$|(?:^|/)routes/((?:[^/]+/)*)\+page\.svelte$")
SCREEN_DIR = re.compile(r"(?i)(?:^|/)(?:pages|screens|views|routes)/")
PERSONAL = re.compile(r"(?i)e-?mail|passw|\btel\b|phone|mobile|(?:first|last|full|given|family|user)[-_ ]?name|^name$|"
                      r"address|street|postal|zip|city|country|cc-|card|\botp\b|one-time")
NON_INTERACTIVE = {"div", "span", "li", "td", "tr", "p", "img", "section", "article", "header", "footer", "main",
                   "i", "svg", "ul", "ol", "h1", "h2", "h3", "h4", "h5", "h6"}
CLICK_ATTRS = ("onclick", "@click", "v-on:click", "on:click", "(click)")
KEY_ATTRS = ("onkeydown", "onkeyup", "onkeypress", "@keydown", "@keyup", "v-on:keydown", "on:keydown", "(keydown)")
NAME_ATTRS = ("aria-label", "aria-labelledby", "title")
VIEWPORT_SCALE = re.compile(r"(?<![\w-])maximum-scale\s*=\s*"
                            r"([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?)", re.I)
VIEWPORT_ZOOM_LOCK = re.compile(r"(?<![\w-])user-scalable\s*=\s*(?:no|0)\b", re.I)
TAG_START = re.compile(r"<([A-Za-z][\w.:-]*)(?=[\s/>])")
ATTR_NAME = re.compile(r"[^\s=>/{}\"']+")
CSS_COMMENTS = re.compile(r"""/\*.*?(?:\*/|$)|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'""", re.S)
MARKUP_TOKEN = re.compile(r"<!--|\{/\*|<([A-Za-z][\w.:-]*)(?=[\s/>])")
JSX_TOKEN = re.compile(r"""\{/\*|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`""", re.S)
STYLE_BLOCK = re.compile(r"(<style\b[^>]*>)(.*?)(</style\s*>|$)", re.S | re.I)
SCRIPT_BLOCK = re.compile(r"(<script\b[^>]*>)(.*?)(</script\s*>|$)", re.S | re.I)
STYLE_ATTRIBUTE = re.compile(r"(?<![\w:-])style\s*=\s*([\"'])(.*?)\1", re.S | re.I)


def iter_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d)))
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if name in SKIP_FILES or path.is_symlink() or not path.is_file():
                continue
            yield path


def read_text(path):
    """The file's text, or None for binaries, minified bundles and oversized files."""
    if path.stat().st_size > MAX_BYTES or re.search(r"\.min\.(?:js|css)$", path.name):
        return None
    data = path.read_bytes()
    if b"\0" in data[:8192]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


class SourceLines:
    """Map offsets to lines without rescanning a file for every candidate."""

    def __init__(self, text):
        self.newlines = [m.start() for m in re.finditer("\n", text)]

    def __call__(self, index):
        return bisect_left(self.newlines, index) + 1


def blank_comment(match):
    """Mask a comment while preserving every source offset and newline."""
    return re.sub(r"[^\n]", " ", match.group(0))


def mask_css_comments(text):
    # Quoted strings may legitimately contain /* and */ as visible content.
    return CSS_COMMENTS.sub(lambda m: blank_comment(m) if m.group(0).startswith("/*") else m.group(0), text)


def mask_markup_comments(text, *, jsx=False):
    """Mask template comments, protecting quoted attributes and raw-text blocks."""
    parts, end, cursor = [], 0, 0
    token = JSX_TOKEN if jsx else MARKUP_TOKEN
    while match := token.search(text, cursor):
        if jsx and match.group(0) != "{/*":
            cursor = match.end()  # A JS string, not a comment or an HTML fragment.
            continue
        name = None if jsx else match.group(1)
        if name:
            tag = parse_tag(text, match.end())
            cursor = tag[2] if tag else match.end()
            if tag and not tag[3] and name.lower() in ("style", "script"):
                close = re.compile(r"</" + name + r"\s*>", re.I).search(text, cursor)
                cursor = close.end() if close else len(text)
        else:
            marker = "-->" if match.group(0) == "<!--" else "*/}"
            close = text.find(marker, match.end())
            if close < 0:
                break  # Do not erase the remaining source on ambiguous syntax.
            cursor = close + len(marker)
            parts.extend((text[end:match.start()], re.sub(r"[^\n]", " ", text[match.start():cursor])))
            end = cursor
    parts.append(text[end:])
    return "".join(parts)


def keep_regions(text, regions):
    """Mask text outside nonoverlapping regions without shifting their offsets."""
    parts, end = [], 0
    for start, stop, body in sorted(regions):
        if start < end:
            continue
        parts.extend((re.sub(r"[^\n]", " ", text[end:start]), body))
        end = stop
    parts.append(re.sub(r"[^\n]", " ", text[end:]))
    return "".join(parts)


def embedded_css(text):
    """Keep style blocks and literal style attributes at their source offsets."""
    regions = [(m.start(2), m.end(2), mask_css_comments(m.group(2))) for m in STYLE_BLOCK.finditer(text)]
    # Replacing the closing attribute quote with a delimiter prevents one inline
    # declaration from becoming part of the next style block's first selector.
    regions.extend((m.start(2), m.end(2) + 1, mask_css_comments(m.group(2)) + ";")
                   for m in STYLE_ATTRIBUTE.finditer(text))
    return keep_regions(text, regions)


def parse_warning(acc, location, reason):
    acc["parse_warnings"].append({"location": location, "reason": reason})


def integer(value, warn):
    """Bound work independently of Python's configurable integer-string limit."""
    try:
        if len(value.lstrip("+-")) > MAX_INTEGER_DIGITS:
            raise ValueError("too many digits")
        return int(value)
    except ValueError:
        warn("integer literal exceeds the supported conversion limit; candidate skipped")
        return None


class Tally:
    """value -> count and the first locations it was seen at."""

    def __init__(self):
        self.count, self.where = defaultdict(int), defaultdict(list)

    def add(self, value, loc):
        self.count[value] += 1
        if len(self.where[value]) < MAX_LOCATIONS:
            self.where[value].append(loc)

    def rows(self, key="value"):
        return [{key: v, "count": self.count[v], "locations": self.where[v]}
                for v in sorted(self.count, key=lambda v: (-self.count[v], str(v)))]


def px(number, unit, warn=None):
    """A CSS length in px (rem and em at 16px), formatted without trailing zeros."""
    value = float(number) * (16 if unit in ("rem", "em") else 1)
    if not math.isfinite(value):
        if warn:
            warn("length literal exceeds the finite numeric range; candidate skipped")
        return None
    return round(value, 2)


def fmt(value):
    return f"{value:g}px"


def lengths(value, warn=None):
    """px values of the lengths in a CSS value; bare numbers are not lengths in CSS."""
    return [v for m in LENGTH.finditer(value) if (v := px(m.group(1), m.group(2), warn)) is not None]


def js_lengths(bare, quoted, warn=None):
    if bare is not None:
        value = px(bare, "px", warn)
        return [value] if value is not None else []
    return lengths(quoted or "", warn)


def skip_braces(text, i, limit):
    """Index just past the brace group opening at text[i], or None when it does not close within limit."""
    depth, quote, n = 0, None, min(len(text), i + limit)
    while i < n:
        c = text[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "\"'`":
            quote = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def parse_tag(text, i, limit=4000, vue=False):
    """Parse an opening tag's attributes from i (just past its name).

    Returns (attrs, spread, end, self_closing) with attribute names lower-cased and
    values as written (True for a bare attribute), or None when the tag does not close.
    """
    attrs, spread, n, stop = {}, False, len(text), min(len(text), i + limit)
    while i < stop:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == ">":
            return attrs, spread, i + 1, False
        elif text.startswith("/>", i):
            return attrs, spread, i + 2, True
        elif c == "{":
            j = skip_braces(text, i, limit)
            if j is None:
                return None
            spread = spread or text[i + 1:j].lstrip().startswith("...")
            i = j
        else:
            m = ATTR_NAME.match(text, i)
            if not m:
                return None
            name, i = m.group(0).lower(), m.end()
            k = i
            while k < n and text[k].isspace():
                k += 1
            value = True
            if k < n and text[k] == "=":
                k += 1
                while k < n and text[k].isspace():
                    k += 1
                if k < n and text[k] in "\"'":
                    end = text.find(text[k], k + 1)
                    if end < 0:
                        return None
                    value, i = html.unescape(text[k + 1:end]), end + 1
                elif k < n and text[k] == "{":
                    end = skip_braces(text, k, limit)
                    if end is None:
                        return None
                    value, i = text[k:end], end
                else:
                    m = re.compile(r"[^\s>]+").match(text, k)
                    if not m:
                        return None
                    value, i = html.unescape(m.group(0)), m.end()
            if vue:
                if name == "v-bind" or name.startswith("v-bind.") or name.startswith((":[", "v-bind:[")):
                    spread = True  # An object or dynamic key can supply any missing attribute.
                elif name.startswith((":", "v-bind:")):
                    name = name.removeprefix("v-bind:").removeprefix(":").split(".", 1)[0]
                    value = "{" + (value if isinstance(value, str) else name) + "}"
                elif name.startswith(("@", "v-on:")):
                    name = name.split(".", 1)[0]
            attrs[name] = value
    return None


def literal(value):
    """The string an attribute value names: "x", {"x"} or {'x'}; None for expressions."""
    if not isinstance(value, str):
        return None
    m = re.fullmatch(r"\{\s*([\"'`])([^\"'`]*)\1\s*\}", value)
    if m:
        return m.group(2)
    return None if value.startswith("{") else value


def has_name(attrs, names=NAME_ATTRS):
    """A nonblank name attribute, or an expression whose value is unknown."""
    for name in names:
        value = attrs.get(name)
        if isinstance(value, str):
            static = literal(value)
            if static is None or static.strip():
                return True
    return False


def tags(text, *, vue=False, html_names=False):
    """(name, attrs, spread, start, end, self_closing) for every parseable opening tag."""
    for m in TAG_START.finditer(text):
        parsed = parse_tag(text, m.end(), vue=vue)
        if parsed:
            attrs, spread, end, closing = parsed
            name = m.group(1).lower() if html_names else m.group(1)
            yield name, attrs, spread, m.start(), end, closing


def display_width(s):
    return sum(2 if unicodedata.east_asian_width(c) in ("W", "F") else 1 for c in s)


def check_locale_depth(text, where):
    """Bound all JSON containers before decoding, independently of Python's parser."""
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "{[":
            depth += 1
            if depth > MAX_LOCALE_DEPTH:
                raise RecordError(f"{where}: locale JSON exceeds {MAX_LOCALE_DEPTH} nested object/array containers")
        elif char in "}]":
            depth -= 1
    # Syntax, matching delimiters and valid escapes are checked by loads_json.


def flatten(value, prefix=""):
    pending = [(prefix, value)]
    while pending:
        key, item = pending.pop()
        if isinstance(item, dict):
            for k, v in reversed(item.items()):
                if not str(k).startswith("@"):
                    pending.append((f"{key}.{k}" if key else str(k), v))
        elif isinstance(item, str):
            yield key, item


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


def scan_css(rel, text, acc, source_lines=None):
    """Rule-level checks on CSS: tap targets and removed focus outlines."""
    source_lines = source_lines or SourceLines(text)
    focus_visible = ":focus-visible" in text
    for m in BLOCK.finditer(text):
        selector = re.sub(r"/\*.*?\*/", "", m.group(1), flags=re.S).strip()
        body = m.group(2)
        if not selector or selector.startswith("@"):
            continue
        loc = f"{rel}:{source_lines(m.start(1) + len(m.group(1)) - len(m.group(1).lstrip()))}"
        warn = lambda reason: parse_warning(acc, loc, reason)  # noqa: E731
        if OUTLINE_NONE.search(body):
            acc["focus_outline"].append({"selector": selector[:120], "location": loc,
                                         "replacement_in_rule": bool(FOCUS_REPLACEMENT.search(OUTLINE_NONE.sub("", body))),
                                         "focus_visible_rule_in_file": focus_visible})
        if TAP_SELECTOR.search(selector):
            sizes = {d.group(1): v for d in SIZE_DECL.finditer(body)
                     if (v := px(d.group(2), d.group(3), warn)) is not None}
            small = {k: v for k, v in sizes.items() if 0 < v < 44}
            if small:
                acc["tap_targets"].append({"selector": selector[:120], "sizes": {k: fmt(v) for k, v in sizes.items()},
                                           "below_24": any(v < 24 for v in small.values()), "location": loc})


def scan_markup(rel, text, acc, source_lines=None):
    """Element-level checks on templates and JSX."""
    clean = mask_markup_comments(text, jsx=Path(rel).suffix.lower() in JSX_EXT)
    source_lines = source_lines or SourceLines(clean)
    html_names = Path(rel).suffix.lower() in HTML_EXT
    labels_for = set()
    label_spans = [(m.start(), m.end()) for m in re.finditer(r"<label\b.*?</label\s*>", clean,
                                                           re.S | (re.I if html_names else 0))]
    label_starts = [s for s, _ in label_spans]
    parsed = list(tags(clean, vue=Path(rel).suffix.lower() == ".vue", html_names=html_names))
    for name, attrs, _, _, _, _ in parsed:
        if name == "label":
            target = literal(attrs.get("for") or attrs.get("htmlfor"))
            if target:
                labels_for.add(target)
    for name, attrs, spread, start, end, closing in parsed:
        loc = f"{rel}:{source_lines(start)}"
        lname = name.lower()
        if name == "meta" and (literal(attrs.get("name")) or "").lower() == "viewport":
            content = literal(attrs.get("content")) or ""
            # Viewport numbers use a numeric prefix; extra dots must not abort
            # the whole scan. Negative scales are ignored by the viewport rules.
            scale = VIEWPORT_SCALE.search(content)
            blocks = bool(VIEWPORT_ZOOM_LOCK.search(content)) or bool(scale and 0 <= float(scale.group(1)) < 2)
            acc["viewport_meta"].append({"content": content, "blocks_zoom": blocks, "location": loc})
        if spread:
            continue  # Props passed through a spread are unknown here.
        tabindex = attrs.get("tabindex")
        tabindex = tabindex.strip("{}\"' ") if isinstance(tabindex, str) else ""
        if re.fullmatch(r"[1-9]\d*", tabindex):
            value = integer(tabindex, lambda reason: parse_warning(acc, loc, reason))
            if value is not None:
                acc["positive_tabindex"].append({"element": name, "value": value, "location": loc})
        if any(a in attrs for a in CLICK_ATTRS) and (
                (lname in NON_INTERACTIVE and name == lname) or (name == "a" and "href" not in attrs)):
            missing = [label for label, keys in (("role", ("role",)), ("tabindex", ("tabindex",)), ("key handler", KEY_ATTRS))
                       if not any(k in attrs for k in keys)]
            if missing:
                acc["click_handlers"].append({"element": name, "missing": missing, "location": loc})
        if name == "img":
            missing = ([] if "alt" in attrs else ["alt"]) + (
                [] if ("width" in attrs and "height" in attrs) or "fill" in attrs else ["dimensions"])
            if missing:
                acc["images"].append({"missing": missing, "location": loc})
        if name in ("input", "select", "textarea"):
            type_attr = attrs.get("type")
            dynamic_type = isinstance(type_attr, str) and literal(type_attr) is None
            kind = ("unknown" if dynamic_type else (literal(type_attr) or "text").lower()) if name == "input" else name
            if kind in ("hidden", "submit", "button", "reset", "image"):
                continue
            ident = " ".join(x for x in (literal(attrs.get("name")), literal(attrs.get("id"))) if x)
            label_index = bisect_right(label_starts, start) - 1
            in_label = label_index >= 0 and start < label_spans[label_index][1]
            labelled = has_name(attrs) or literal(attrs.get("id")) in labels_for or in_label
            missing = [] if labelled else ["label"]
            if (PERSONAL.search(ident) or kind in ("email", "password", "tel")) and "autocomplete" not in attrs:
                missing.append("autocomplete")
            if name == "input" and not dynamic_type and re.search(r"(?i)e-?mail", ident) and kind != "email":
                missing.append("type=email")
            if name == "input" and not dynamic_type and re.search(r"(?i)\btel\b|phone|mobile", ident) and kind != "tel":
                missing.append("type=tel")
            if missing:
                acc["inputs"].append({"element": name, "type": kind, "name": ident, "missing": missing,
                                      "placeholder_only": not labelled and "placeholder" in attrs, "location": loc})
        named = has_name(attrs)
        if name == "button" and not closing and not named:
            close = re.compile(r"</button\s*>", re.I if html_names else 0).search(clean, end, end + 1200)
            inner = clean[end:close.start()] if close else ""
            if "<" in inner and not re.sub(r"<[^<>]*>", "", inner).strip():
                acc["icon_buttons"].append({"element": name, "location": loc})
        elif re.fullmatch(r"(?:[A-Z]\w*)?IconButton", name) and not named and not has_name(attrs, ("label",)):
            acc["icon_buttons"].append({"element": name, "location": loc})


def inventory(root, flows=None):
    root = Path(root).resolve()
    spacing, font_sizes, breakpoints, z_index = Tally(), Tally(), Tally(), Tally()
    widths, truncation, physical = Tally(), Tally(), Tally()
    acc = defaultdict(list)
    routes, links, screens, tokens, motion, reduced, locales = [], set(), [], [], [], [], defaultdict(dict)
    scanned = skipped = 0
    for path in iter_files(root):
        rel = path.relative_to(root).as_posix()
        suffix = path.suffix.lower()
        if suffix not in CSS_EXT | EMBED_CSS_EXT | JS_EXT | MARKUP_EXT | {".json"}:
            continue
        try:
            text = read_text(path)
        except OSError:
            text = None
        if text is None:
            skipped += 1
            continue
        scanned += 1
        bundle = locale_bundle(rel)
        if bundle:
            try:
                check_locale_depth(text, rel)
                locales[bundle[0]][bundle[1]] = (rel, dict(flatten(loads_json(text, rel))))
            except (ValueError, RecordError, RecursionError) as e:
                scanned -= 1
                skipped += 1
                parse_warning(acc, f"{rel}:1", f"locale JSON could not be parsed; file skipped: {str(e)[:200]}")
            continue
        if suffix == ".json":
            if TOKEN_FILE.search("/" + rel):
                tokens.append({"path": rel, "custom_properties": 0})
            continue
        css = suffix in CSS_EXT | EMBED_CSS_EXT
        js = suffix in JS_EXT or suffix in EMBED_CSS_EXT
        if suffix in MARKUP_EXT:
            text = mask_markup_comments(text, jsx=suffix in JSX_EXT)
        if suffix in CSS_EXT:
            text = mask_css_comments(text)
        elif suffix in EMBED_CSS_EXT:
            text = STYLE_BLOCK.sub(lambda m: m.group(1) + mask_css_comments(m.group(2)) + m.group(3), text)
        css_text = embedded_css(text) if suffix in EMBED_CSS_EXT else text
        js_text = (keep_regions(text, [(m.start(2), m.end(2), m.group(2)) for m in SCRIPT_BLOCK.finditer(text)])
                   if suffix in EMBED_CSS_EXT - JS_EXT else text)
        source_lines = SourceLines(text)
        at = lambda i: f"{rel}:{source_lines(i)}"  # noqa: E731
        warn_at = lambda i: lambda reason: parse_warning(acc, at(i), reason)  # noqa: E731
        props = len(CUSTOM_PROPERTY.findall(css_text if css else text))
        if TOKEN_FILE.search("/" + rel) or props >= 3:
            tokens.append({"path": rel, "custom_properties": props})
        if css:
            for m in CSS_SPACING.finditer(css_text):
                for v in lengths(m.group(1), warn_at(m.start())):
                    if abs(v) > 2:
                        spacing.add(fmt(v), at(m.start()))
            for m in CSS_FONT_SIZE.finditer(css_text):
                for v in lengths(m.group(1), warn_at(m.start())):
                    font_sizes.add(fmt(v), at(m.start()))
            for m in CSS_Z.finditer(css_text):
                value = integer(m.group(1), warn_at(m.start()))
                if value is not None:
                    z_index.add(value, at(m.start()))
            for m in CSS_WIDTH.finditer(css_text):
                v = px(m.group(2), m.group(3), warn_at(m.start()))
                if v is not None and v >= 320:
                    widths.add(fmt(v), at(m.start()))
            for m in CSS_MOTION.finditer(css_text):
                motion.append(at(m.start()))
            scan_css(rel, css_text, acc, source_lines)
        if js:
            for m in JS_SPACING.finditer(js_text):
                for v in js_lengths(m.group(1), m.group(2), warn_at(m.start())):
                    if abs(v) > 2:
                        spacing.add(fmt(v), at(m.start()))
            for m in JS_FONT_SIZE.finditer(js_text):
                for v in js_lengths(m.group(1), m.group(2), warn_at(m.start())):
                    font_sizes.add(fmt(v), at(m.start()))
            for m in JS_Z.finditer(js_text):
                value = integer(m.group(1), warn_at(m.start()))
                if value is not None:
                    z_index.add(value, at(m.start()))
            for m in JS_WIDTH.finditer(js_text):
                v = px(m.group(2) or m.group(3), "px", warn_at(m.start()))
                if v is not None and v >= 320:
                    widths.add(fmt(v), at(m.start()))
            for m in JS_MOTION.finditer(js_text):
                motion.append(at(m.start()))
            for m in JS_OUTLINE_NONE.finditer(js_text):
                acc["focus_outline"].append({"selector": "(style object)", "location": at(m.start()),
                                             "replacement_in_rule": None, "focus_visible_rule_in_file": None})
        for m in MEDIA.finditer(text):
            value = px(m.group(1), m.group(2), warn_at(m.start()))
            if value is not None:
                breakpoints.add(fmt(value), at(m.start()))
        for m in REDUCED_MOTION.finditer(text):
            reduced.append(at(m.start()))
        for m in TRUNCATION.finditer(text):
            truncation.add(re.sub(r"\s+", " ", m.group(0))[:40], at(m.start()))
        for m in PHYSICAL.finditer(text):
            physical.add(re.sub(r"\s+", " ", (m.group(1) or m.group(2)))[:30], at(m.start()))
        for m in ROUTE.finditer(text):
            routes.append({"route": m.group(1) or m.group(2), "location": at(m.start())})
        for m in LINK.finditer(text):
            links.add((m.group(1) or m.group(2)).rstrip("/") or "/")
        fr = FILE_ROUTE.search(rel)
        if fr:
            next_app = fr.group(1) is not None
            segments = (fr.group(1) if next_app else fr.group(2)).split("/")
            private = next_app and any(s.startswith("_") for s in segments)
            intercepted = next_app and any(re.match(r"^\(\.{1,3}\)", s) for s in segments)
            if intercepted and not private:
                parse_warning(acc, f"{rel}:1", "Next.js interception route is not inferred; inspect routing manually")
            elif not private:
                segs = [s for s in segments if s and not s.startswith("(")
                        and not (next_app and s.startswith("@"))]
                routes.append({"route": "/" + "/".join(segs), "location": f"{rel}:1"})
        if SCREEN_DIR.search(rel) and suffix in MARKUP_EXT | JS_EXT:
            screens.append(rel)
        if suffix in MARKUP_EXT:
            scan_markup(rel, text, acc, source_lines)
            if FETCH.search(text):
                missing = [k for k, rx in (("loading", LOADING), ("error", ERROR)) if not rx.search(text)]
                if LIST_RENDER.search(text) and not EMPTY.search(text):
                    missing.append("empty")
                if missing:
                    acc["state_branches"].append({"file": rel, "missing": missing,
                                                  "location": at(FETCH.search(text).start())})
            if not CONFIRM.search(text):
                for m in DESTRUCTIVE.finditer(text):
                    acc["destructive_actions"].append({"call": m.group(1), "location": at(m.start(1))})

    expansion = []
    for bundle, langs in sorted(locales.items()):
        if len(langs) < 2:
            continue
        base = "en" if "en" in langs else sorted(langs)[0]
        base_strings = langs[base][1]
        for lang, (rel, strings) in sorted(langs.items()):
            if lang == base:
                continue
            rows = []
            for key, src in base_strings.items():
                if key in strings and src.strip():
                    a, b = display_width(src), display_width(strings[key])
                    if b >= a * 1.4 and b - a >= 5:
                        rows.append({"key": key, "base_width": a, "width": b, "ratio": round(b / a, 2)})
            if rows:
                rows.sort(key=lambda r: (-r["ratio"], r["key"]))
                expansion.append({"bundle": bundle, "base": base, "lang": lang, "file": rel, "keys": rows})

    linked = {r["route"] for r in routes if r["route"].rstrip("/") in links or r["route"] in links}
    result = {
        "tool": "inventory.py", "version": 1, "repository": root.name,
        "flows_sha256": canonical_digest(flows) if flows is not None else None,
        "files_scanned": scanned, "files_skipped": skipped,
        "parse_warnings": acc["parse_warnings"],
        "routes": routes,
        "orphan_routes": [r for r in routes if r["route"] not in linked and r["route"] not in ("/", "*")
                          and not re.search(r"[:\[*]", r["route"])],
        "screens": screens, "token_sources": tokens,
        "spacing": spacing.rows(), "font_sizes": font_sizes.rows(),
        "breakpoints": breakpoints.rows(), "z_index": z_index.rows(), "fixed_widths": widths.rows(),
        "tap_targets": acc["tap_targets"], "focus_outline": acc["focus_outline"],
        "viewport_meta": acc["viewport_meta"], "click_handlers": acc["click_handlers"],
        "images": acc["images"], "inputs": acc["inputs"], "icon_buttons": acc["icon_buttons"],
        "positive_tabindex": acc["positive_tabindex"], "state_branches": acc["state_branches"],
        "destructive_actions": acc["destructive_actions"],
        "motion": {"declarations": len(motion), "locations": motion[:MAX_LOCATIONS],
                   "reduced_motion": reduced[:MAX_LOCATIONS]},
        "truncation": truncation.rows("pattern"),
        "locale_expansion": expansion,
    }
    if flows:
        scales = flows.get("tokens", {})
        off = {}
        for key, tally in (("spacing", result["spacing"]), ("font_sizes", result["font_sizes"]),
                           ("breakpoints", result["breakpoints"])):
            if key in scales:
                allowed = {float(x) for x in scales[key]}
                off[key] = [row for row in tally if abs(float(row["value"][:-2])) not in allowed]
        if "z_index" in scales:
            allowed = set(scales["z_index"]) | {0, -1, 1}
            off["z_index"] = [row for row in result["z_index"] if row["value"] not in allowed]
        result["off_scale"] = off
        viewports = [int(v.split("x")[0]) for v in flows.get("viewports", [])]
        if viewports:
            smallest = min(viewports)
            result["smallest_viewport"] = smallest
            for row in result["fixed_widths"]:
                row["wider_than_smallest_viewport"] = float(row["value"][:-2]) > smallest
        if {loc.split("-")[0].split("_")[0].lower() for loc in flows.get("locales", [])} & RTL_LANGS:
            result["physical_properties"] = physical.rows("property")
    # Caps apply only after off_scale was measured on every row; each cut is counted.
    truncated = {}

    def cap(rows, limit, name):
        if len(rows) > limit:
            truncated[name] = len(rows) - limit
        return rows[:limit]
    for key in ("spacing", "font_sizes", "parse_warnings"):
        result[key] = cap(result[key], MAX_ROWS, key)
    for key, rows in result.get("off_scale", {}).items():
        result["off_scale"][key] = cap(rows, MAX_ROWS, f"off_scale.{key}")
    for entry in result["locale_expansion"]:
        entry["keys"] = cap(entry["keys"], MAX_KEYS, f"locale_expansion {entry['bundle']} {entry['lang']}")
    result["limits"] = {"rows": MAX_ROWS, "locations_per_row": MAX_LOCATIONS, "expansion_keys": MAX_KEYS,
                        "locale_container_depth": MAX_LOCALE_DEPTH}
    result["truncated"] = truncated
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("repo")
    p.add_argument("--out", required=True)
    p.add_argument("--flows")
    a = p.parse_args(argv)
    if not Path(a.repo).is_dir():
        print(f"inventory.py: {a.repo} is not a directory", file=sys.stderr)
        return 2
    root = Path(a.repo).resolve()
    out = Path(a.out)
    try:
        # write_output replaces a final symlink rather than following it. Resolve
        # only its parent so this check covers the entry that will be changed.
        out = out.parent.resolve() / out.name
    except (OSError, RuntimeError) as e:
        print(f"inventory.py: cannot write {a.out}: {e}", file=sys.stderr)
        return 1
    if out == root or root in out.parents:
        print(f"inventory.py: --out must be outside the reviewed repository: {a.out}", file=sys.stderr)
        return 2
    flows = None
    if a.flows:
        try:
            flows = check_flows(load_json(a.flows))
        except (OSError, ValueError, RecordError) as e:
            print(f"inventory.py: flows: {e}", file=sys.stderr)
            return 2
    result = inventory(root, flows)
    try:
        write_output(out, json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    except OSError as e:
        print(f"inventory.py: cannot write {a.out}: {e.strerror or e}", file=sys.stderr)
        return 1
    counts = ", ".join(f"{len(result[k])} {k.replace('_', ' ')}" for k in (
        "routes", "click_handlers", "inputs", "images", "icon_buttons", "state_branches"))
    print(f"wrote {a.out}: {result['files_scanned']} files, {counts}"
          + (f", {sum(len(v) for v in result['off_scale'].values())} off-scale values" if flows else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
