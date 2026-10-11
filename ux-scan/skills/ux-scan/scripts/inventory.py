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
import json
import os
import re
import sys
import unicodedata
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import RecordError, check_flows  # noqa: E402
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

CSS_EXT = {".css", ".scss", ".sass", ".less", ".styl", ".pcss"}
EMBED_CSS_EXT = {".html", ".htm", ".vue", ".svelte", ".astro"}
JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro"}
MARKUP_EXT = {".js", ".jsx", ".tsx", ".mjs", ".vue", ".svelte", ".astro", ".html", ".htm", ".erb", ".hbs",
              ".handlebars", ".ejs", ".php", ".njk", ".liquid", ".twig", ".mustache", ".jinja", ".j2"}
LOCALE_DIR = re.compile(r"(?i)(?:^|/)(?:locales?|i18n|l10n|lang|langs|languages|translations|messages)(?:/|$)")
LANG = re.compile(r"^[a-z]{2,3}(?:[-_][A-Za-z]{2,4})?$")
RTL_LANGS = {"ar", "he", "iw", "fa", "ur", "yi", "ps", "sd", "ug", "dv", "ckb"}

LENGTH = re.compile(r"(?<![\w.#-])(-?\d*\.?\d+)(px|rem|em)\b")
CSS_SPACING = re.compile(r"(?<![\w-])(?:margin|padding|gap|row-gap|column-gap)"
                         r"(?:-(?:top|right|bottom|left|inline|block)(?:-start|-end)?)?\s*:\s*([^;{}\n]+)")
JS_SPACING = re.compile(r"\b(?:margin|padding|gap|rowGap|columnGap)(?:Top|Right|Bottom|Left|Inline|Block|X|Y)?"
                        r"(?:Start|End)?\s*:\s*(?:(-?\d+(?:\.\d+)?)\s*(?=[,}\n])|[\"'`]([^\"'`\n]{1,60})[\"'`])")
CSS_FONT_SIZE = re.compile(r"(?<![\w-])font-size\s*:\s*([^;{}\n]+)")
JS_FONT_SIZE = re.compile(r"\bfontSize\s*:\s*(?:(\d+(?:\.\d+)?)\s*(?=[,}\n])|[\"'`]([^\"'`\n]{1,40})[\"'`])")
MEDIA = re.compile(r"\(\s*(?:(?:min|max)-width\s*:|width\s*[<>]=?)\s*(\d+(?:\.\d+)?)(px|em|rem)\s*\)")
CSS_Z = re.compile(r"(?<![\w-])z-index\s*:\s*(-?\d+)")
JS_Z = re.compile(r"\bzIndex\s*:\s*[\"']?(-?\d+)")
CSS_WIDTH = re.compile(r"(?<![\w-])(width|min-width)\s*:\s*(\d+(?:\.\d+)?)(px|rem)\b")
JS_WIDTH = re.compile(r"\b(width|minWidth)\s*:\s*(?:(\d+(?:\.\d+)?)\s*(?=[,}\n])|[\"'](\d+(?:\.\d+)?)px[\"'])")
BLOCK = re.compile(r"([^{};]+)\{([^{}]*)\}")
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
TAG_START = re.compile(r"<([A-Za-z][\w.:-]*)(?=[\s/>])")
ATTR_NAME = re.compile(r"[^\s=>/{}\"']+")


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


def line_of(text, index):
    return text.count("\n", 0, index) + 1


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


def px(number, unit):
    """A CSS length in px (rem and em at 16px), formatted without trailing zeros."""
    value = float(number) * (16 if unit in ("rem", "em") else 1)
    return round(value, 2)


def fmt(value):
    return f"{value:g}px"


def lengths(value):
    """px values of the lengths in a CSS value; bare numbers are not lengths in CSS."""
    return [px(m.group(1), m.group(2)) for m in LENGTH.finditer(value)]


def js_lengths(bare, quoted):
    if bare is not None:
        return [px(bare, "px")]
    return lengths(quoted or "")


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


def parse_tag(text, i, limit=4000):
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
                    value, i = text[k + 1:end], end + 1
                elif k < n and text[k] == "{":
                    end = skip_braces(text, k, limit)
                    if end is None:
                        return None
                    value, i = text[k:end], end
                else:
                    m = re.compile(r"[^\s>]+").match(text, k)
                    if not m:
                        return None
                    value, i = m.group(0), m.end()
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


def tags(text):
    """(name, attrs, spread, start, end, self_closing) for every parseable opening tag."""
    for m in TAG_START.finditer(text):
        parsed = parse_tag(text, m.end())
        if parsed:
            attrs, spread, end, closing = parsed
            yield m.group(1), attrs, spread, m.start(), end, closing


def display_width(s):
    return sum(2 if unicodedata.east_asian_width(c) in ("W", "F") else 1 for c in s)


def flatten(value, prefix=""):
    if isinstance(value, dict):
        for k, v in value.items():
            if not str(k).startswith("@"):
                yield from flatten(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(value, str):
        yield prefix, value


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


def scan_css(rel, text, acc):
    """Rule-level checks on CSS: tap targets and removed focus outlines."""
    focus_visible = ":focus-visible" in text
    for m in BLOCK.finditer(text):
        selector = re.sub(r"/\*.*?\*/", "", m.group(1), flags=re.S).strip()
        body = m.group(2)
        if not selector or selector.startswith("@"):
            continue
        loc = f"{rel}:{line_of(text, m.start(1) + len(m.group(1)) - len(m.group(1).lstrip()))}"
        if OUTLINE_NONE.search(body):
            acc["focus_outline"].append({"selector": selector[:120], "location": loc,
                                         "replacement_in_rule": bool(FOCUS_REPLACEMENT.search(OUTLINE_NONE.sub("", body))),
                                         "focus_visible_rule_in_file": focus_visible})
        if TAP_SELECTOR.search(selector):
            sizes = {d.group(1): px(d.group(2), d.group(3)) for d in SIZE_DECL.finditer(body)}
            small = {k: v for k, v in sizes.items() if 0 < v < 44}
            if small:
                acc["tap_targets"].append({"selector": selector[:120], "sizes": {k: fmt(v) for k, v in sizes.items()},
                                           "below_24": any(v < 24 for v in small.values()), "location": loc})


def scan_markup(rel, text, acc):
    """Element-level checks on templates and JSX."""
    clean = re.sub(r"\{/\*.*?\*/\}|<!--.*?-->", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text, flags=re.S)
    labels_for = set()
    label_spans = [(m.start(), m.end()) for m in re.finditer(r"<label\b.*?</label>", clean, re.S)]
    parsed = list(tags(clean))
    for name, attrs, _, _, _, _ in parsed:
        if name == "label":
            target = literal(attrs.get("for") or attrs.get("htmlfor"))
            if target:
                labels_for.add(target)
    for name, attrs, spread, start, end, closing in parsed:
        loc = f"{rel}:{line_of(clean, start)}"
        lname = name.lower()
        if name == "meta" and literal(attrs.get("name")) == "viewport":
            content = literal(attrs.get("content")) or ""
            scale = re.search(r"maximum-scale\s*=\s*([\d.]+)", content)
            blocks = bool(re.search(r"user-scalable\s*=\s*(?:no|0)\b", content)) or bool(scale and float(scale.group(1)) < 2)
            acc["viewport_meta"].append({"content": content, "blocks_zoom": blocks, "location": loc})
        if spread:
            continue  # Props passed through a spread are unknown here.
        tabindex = attrs.get("tabindex")
        tabindex = tabindex.strip("{}\"' ") if isinstance(tabindex, str) else ""
        if re.fullmatch(r"[1-9]\d*", tabindex):
            acc["positive_tabindex"].append({"element": name, "value": int(tabindex), "location": loc})
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
            kind = (literal(attrs.get("type")) or "text").lower() if name == "input" else name
            if kind in ("hidden", "submit", "button", "reset", "image"):
                continue
            ident = " ".join(x for x in (literal(attrs.get("name")), literal(attrs.get("id"))) if x)
            labelled = (any(a in attrs for a in NAME_ATTRS) or literal(attrs.get("id")) in labels_for
                        or any(s <= start < e for s, e in label_spans))
            missing = [] if labelled else ["label"]
            if (PERSONAL.search(ident) or kind in ("email", "password", "tel")) and "autocomplete" not in attrs:
                missing.append("autocomplete")
            if name == "input" and re.search(r"(?i)e-?mail", ident) and kind != "email":
                missing.append("type=email")
            if name == "input" and re.search(r"(?i)\btel\b|phone|mobile", ident) and kind != "tel":
                missing.append("type=tel")
            if missing:
                acc["inputs"].append({"element": name, "type": kind, "name": ident, "missing": missing,
                                      "placeholder_only": not labelled and "placeholder" in attrs, "location": loc})
        named = any(a in attrs for a in NAME_ATTRS)
        if name == "button" and not closing and not named:
            close = clean.find("</button>", end, end + 1200)
            inner = clean[end:close] if close >= 0 else ""
            if "<" in inner and not re.sub(r"<[^<>]*>", "", inner).strip():
                acc["icon_buttons"].append({"element": name, "location": loc})
        elif re.fullmatch(r"[A-Z]\w*IconButton", name) and not named and "label" not in attrs:
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
                locales[bundle[0]][bundle[1]] = (rel, dict(flatten(json.loads(text))))
            except ValueError:
                pass
            continue
        if suffix == ".json":
            continue
        at = lambda i: f"{rel}:{line_of(text, i)}"  # noqa: E731
        css = suffix in CSS_EXT | EMBED_CSS_EXT
        js = suffix in JS_EXT
        props = len(CUSTOM_PROPERTY.findall(text))
        if TOKEN_FILE.search("/" + rel) or props >= 3:
            tokens.append({"path": rel, "custom_properties": props})
        if css:
            for m in CSS_SPACING.finditer(text):
                for v in lengths(m.group(1)):
                    if abs(v) > 2:
                        spacing.add(fmt(v), at(m.start()))
            for m in CSS_FONT_SIZE.finditer(text):
                for v in lengths(m.group(1)):
                    font_sizes.add(fmt(v), at(m.start()))
            for m in CSS_Z.finditer(text):
                z_index.add(int(m.group(1)), at(m.start()))
            for m in CSS_WIDTH.finditer(text):
                v = px(m.group(2), m.group(3))
                if v >= 320:
                    widths.add(fmt(v), at(m.start()))
            for m in CSS_MOTION.finditer(text):
                motion.append(at(m.start()))
            scan_css(rel, text, acc)
        if js:
            for m in JS_SPACING.finditer(text):
                for v in js_lengths(m.group(1), m.group(2)):
                    if abs(v) > 2:
                        spacing.add(fmt(v), at(m.start()))
            for m in JS_FONT_SIZE.finditer(text):
                for v in js_lengths(m.group(1), m.group(2)):
                    font_sizes.add(fmt(v), at(m.start()))
            for m in JS_Z.finditer(text):
                z_index.add(int(m.group(1)), at(m.start()))
            for m in JS_WIDTH.finditer(text):
                v = px(m.group(2) or m.group(3), "px")
                if v >= 320:
                    widths.add(fmt(v), at(m.start()))
            for m in JS_MOTION.finditer(text):
                motion.append(at(m.start()))
            for m in JS_OUTLINE_NONE.finditer(text):
                acc["focus_outline"].append({"selector": "(style object)", "location": at(m.start()),
                                             "replacement_in_rule": None, "focus_visible_rule_in_file": None})
        for m in MEDIA.finditer(text):
            breakpoints.add(fmt(px(m.group(1), m.group(2))), at(m.start()))
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
            segs = [s for s in (fr.group(1) or fr.group(2) or "").split("/") if s and not s.startswith("(")]
            routes.append({"route": "/" + "/".join(segs), "location": f"{rel}:1"})
        if SCREEN_DIR.search(rel) and suffix in MARKUP_EXT | JS_EXT:
            screens.append(rel)
        if suffix in MARKUP_EXT:
            scan_markup(rel, text, acc)
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
        "files_scanned": scanned, "files_skipped": skipped,
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
    for key in ("spacing", "font_sizes"):
        result[key] = cap(result[key], MAX_ROWS, key)
    for key, rows in result.get("off_scale", {}).items():
        result["off_scale"][key] = cap(rows, MAX_ROWS, f"off_scale.{key}")
    for entry in result["locale_expansion"]:
        entry["keys"] = cap(entry["keys"], MAX_KEYS, f"locale_expansion {entry['bundle']} {entry['lang']}")
    result["limits"] = {"rows": MAX_ROWS, "locations_per_row": MAX_LOCATIONS, "expansion_keys": MAX_KEYS}
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
    flows = None
    if a.flows:
        try:
            flows = check_flows(json.loads(Path(a.flows).read_text(encoding="utf-8")))
        except (OSError, ValueError, RecordError) as e:
            print(f"inventory.py: flows: {e}", file=sys.stderr)
            return 2
    result = inventory(a.repo, flows)
    try:
        write_output(Path(a.out), json.dumps(result, ensure_ascii=False, indent=2) + "\n")
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
