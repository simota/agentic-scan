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
import stat
import sys
import unicodedata
from bisect import bisect_left, bisect_right
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from file_io import read_regular, tolerant_console, within  # noqa: E402
from findings import RecordError, canonical_digest, check_flows, load_json, loads_json  # noqa: E402
from scan_report_kit.output import write_output  # noqa: E402

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "out", ".next", ".nuxt",
             ".svelte-kit", "coverage", ".venv", "venv", "__pycache__", "Pods", ".gradle", "target",
             ".turbo", ".cache", "bower_components", ".idea", ".vscode", "DerivedData", ".dart_tool",
             "storybook-static", ".output"}
# Inside a file-route tree these names can be URL segments (app/coverage/page.tsx is /coverage).
# A package named app still keeps its build output there, so only a subtree holding page sources counts.
ROUTE_SEGMENT_DIRS = {"vendor", "dist", "build", "out", "coverage", "target"}
ROUTE_TREES = {"app", "pages", "routes"}
PAGE_SOURCE = re.compile(r"(?i)\.(?:tsx|jsx|vue|svelte|astro|mdx)$")
MAX_SEGMENT_PROBE = 2000
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock", "poetry.lock", "Gemfile.lock",
              "go.sum", "composer.lock", "Podfile.lock", "pubspec.lock", "bun.lockb", "uv.lock"}
MAX_BYTES = 2 * 1024 * 1024
MAX_LOCATIONS = 5
MAX_ROWS = 200
MAX_KEYS = 50
MAX_INTEGER_DIGITS = 1000
MAX_LOCALE_DEPTH = 256
MAX_EXPRESSION_FAILURES = 64

CSS_EXT = {".css", ".scss", ".sass", ".less", ".styl", ".pcss"}
# Files whose <style> blocks and style attributes are measured as CSS, including server templates.
EMBED_CSS_EXT = {".html", ".htm", ".vue", ".svelte", ".astro", ".erb", ".hbs", ".handlebars", ".ejs", ".php",
                 ".njk", ".liquid", ".twig", ".mustache", ".jinja", ".jinja2", ".j2"}
JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte", ".astro"}
MARKUP_EXT = {".js", ".jsx", ".tsx", ".mjs", ".vue", ".svelte", ".astro", ".html", ".htm", ".erb", ".hbs",
              ".handlebars", ".ejs", ".php", ".njk", ".liquid", ".twig", ".mustache", ".jinja", ".jinja2", ".j2", ".mdx"}
HTML_EXT = {".html", ".htm", ".erb", ".hbs", ".handlebars", ".ejs", ".php", ".njk", ".liquid",
            ".twig", ".mustache", ".jinja", ".jinja2", ".j2"}
JSX_EXT = {".js", ".jsx", ".tsx", ".mjs", ".mdx"}
# Unions tested once per file, built once here.
STYLE_EXT = CSS_EXT | EMBED_CSS_EXT
RAW_TEXT_EXT = HTML_EXT | EMBED_CSS_EXT
SOURCE_EXT = MARKUP_EXT | JS_EXT
SCANNED_EXT = STYLE_EXT | JS_EXT | MARKUP_EXT | {".json"}
LOCALE_DIR = re.compile(r"(?i)(?:^|/)(?:locales?|i18n|l10n|lang|langs|languages|translations|messages)(?:/|$)")
LANG = re.compile(r"^[a-z]{2,3}(?:[-_](?:[A-Za-z]{2,4}|\d{3}))?$")
# ISO 639-1 codes: a two-letter name in this set is preferred as the language
# when both a locale file's name and its directory look like language tags.
ISO_639_1 = set("aa ab ae af ak am an ar as av ay az ba be bg bh bi bm bn bo br bs ca ce ch co cr cs cu cv cy "
                "da de dv dz ee el en eo es et eu fa ff fi fj fo fr fy ga gd gl gn gu gv ha he hi ho hr ht hu hy "
                "hz ia id ie ig ii ik io is it iu ja jv ka kg ki kj kk kl km kn ko kr ks ku kv kw ky la lb lg li "
                "ln lo lt lu lv mg mh mi mk ml mn mr ms mt my na nb nd ne ng nl nn no nr nv ny oc oj om or os pa "
                "pi pl ps pt qu rm rn ro ru rw sa sc sd se sg si sk sl sm sn so sq sr ss st su sv sw ta te tg th "
                "ti tk tl tn to tr ts tt tw ty ug uk ur uz ve vi vo wa wo xh yi yo za zh zu".split())
RTL_LANGS = {"ar", "he", "iw", "fa", "ur", "yi", "ps", "sd", "ug", "dv", "ckb"}


def leading(chars, pattern):
    """Compile pattern behind a lookahead for the characters every one of its matches starts with.

    The lookahead never changes what matches or where. It lets the search reject other
    positions at once, which the engine cannot do by itself for a pattern that opens with a
    lookbehind or \\b. A global flag group such as (?i) stays first and applies to chars too.
    """
    flags = re.match(r"\(\?[aiLmsux]+\)", pattern)
    head = flags.group(0) if flags else ""
    return re.compile(f"{head}(?={chars})(?:{pattern[len(head):]})")


def words(boundary, *alternatives):
    """Alternatives of literal words, each matched only where no boundary character precedes it.

    (?:word(?<!Bword)|…) matches what (?<!B)(?:word|…) matches, at the same places and in
    the same order: the lookbehind reads the one character before the word once the word
    is read. Opening with literal letters lets the engine scan for a word's first character,
    which it cannot do past a lookbehind, \\b or lookahead. \\b before a word that starts
    with a word character is boundary \\w.
    """
    return "(?:" + "|".join(f"{re.escape(w)}(?<!{boundary}{re.escape(w)})" for w in alternatives) + ")"


LENGTH = re.compile(r"(?<![\w.#-])(-?(?:\d+(?:\.\d+)?|\.\d+))((?i:px|rem|em))\b")
# A declaration's value may wrap onto whole later lines; it ends at ";", a brace,
# or a line with a colon, which starts another declaration (also across masked
# regions). Indented Sass and Stylus end a declaration at the line break.
_CSS_CONTINUATION = r"(?:[^;{}:\n]|#\{[^{}\n]*\})*"  # Sass #{…} interpolation is part of a value.
_CSS_VALUE = r"([^;{}\n]+(?:\n(?=" + _CSS_CONTINUATION + r"(?:[\n;}]|\Z))" + _CSS_CONTINUATION + r")*)"
_CSS_LINE_VALUE = r"([^;{}\n]+)"
INDENTED_CSS_EXT = {".sass", ".styl"}
INDENTED_STYLE_LANGS = {"sass", "stylus", "styl"}
_CSS_SPACING_NAME = (words(r"[\w-]", "margin", "padding", "gap", "row-gap", "column-gap", "grid-gap",
                           "grid-row-gap", "grid-column-gap")
                     + r"(?:-(?:top|right|bottom|left|inline|block)(?:-start|-end)?)?\s*:\s*")
CSS_SPACING = re.compile(_CSS_SPACING_NAME + _CSS_VALUE)
CSS_SPACING_LINE = re.compile(_CSS_SPACING_NAME.replace(r"\s*:\s*", r"[^\S\n]*:[^\S\n]*") + _CSS_LINE_VALUE)
# Style-object keys may be quoted, and Vue style bindings use kebab-case names.
JS_SPACING = re.compile(words(r"[\w$-]", "margin", "padding", "gap", "rowGap", "columnGap", "row-gap", "column-gap")
                        + r"(?:Top|Right|Bottom|Left|Inline|Block|X|Y|-top|-right|-bottom|-left|-inline|-block)?"
                        r"(?:Start|End|-start|-end)?[\"']?\s*:\s*"
                        r"(?:(-?\d+(?:\.\d+)?)\s*(?=[,}\n])|[\"'`]([^\"'`\n]{1,60})[\"'`])")
CSS_FONT_SIZE = re.compile(words(r"[\w-]", "font-size") + r"\s*:\s*" + _CSS_VALUE)
CSS_FONT_SIZE_LINE = re.compile(words(r"[\w-]", "font-size") + r"[^\S\n]*:[^\S\n]*" + _CSS_LINE_VALUE)
JS_FONT_SIZE = re.compile(words(r"[\w$-]", "fontSize", "font-size") + r"[\"']?\s*:\s*"
                          r"(?:(\d+(?:\.\d+)?)\s*(?=[,}\n])|[\"'`]([^\"'`\n]{1,40})[\"'`])")
# Width conditions, including Media Queries 4 ranges written from either side.
_MQ = r"(\d+(?:\.\d+)?)((?i:px|em|rem))"
MEDIA = re.compile(r"\(\s*(?:(?:(?:min|max)-width\s*:|width\s*[<>]=?)\s*" + _MQ + r"|"
                   + _MQ + r"\s*[<>]=?\s*width(?:\s*[<>]=?\s*" + _MQ + r")?)\s*\)")
CSS_Z = re.compile(words(r"[\w-]", "z-index") + r"\s*:\s*(-?\d+)")
JS_Z = re.compile(words(r"[\w$-]", "zIndex", "z-index") + r"[\"']?\s*:\s*[\"']?(-?\d+)")
# A parenthesized condition tests a width; it does not set an element's width.
CSS_WIDTH = re.compile("(" + words(r"[\w-]", "width", "min-width") + r")\s*:\s*(\d+(?:\.\d+)?)((?i:px|rem|em))\b"
                       r"(?!\s*(?:(?i:!important)\s*)?\))")
JS_WIDTH = re.compile("(" + words(r"[\w$-]", "width", "minWidth", "min-width") + r")[\"']?\s*:\s*(?:(\d+(?:\.\d+)?)\s*(?=[,}\n])|[\"'](\d+(?:\.\d+)?)((?i:px|rem|em))[\"'])")
# A script object that describes a viewport or an image rather than styling an element:
# use: { viewport: { width: 1280 } } (test runners), openGraph: { images: [{ width: 1200 }] }.
NOT_ELEMENT_WIDTH = re.compile(r"(?<![\w$-])[\"']?(?:viewport|images)[\"']?\s*:\s*"
                               r"(?:\[(?:\s*\{[^{}]*\}\s*,)*)?\s*\{[^{}]*\Z")
# Rule boundaries ignore quoted text and escaped punctuation. Parenthesized
# and bracketed regions are tracked by css_rules, including unquoted data URLs.
# A CSS string ends at a raw newline, so one stray quote cannot swallow later rules.
# Sass #{…} and Less @{…} interpolation are part of a selector, not a rule's braces.
CSS_RULE_TOKEN = re.compile(r'''\\.|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|#\{[^{}]*\}|@\{[\w-]*\}|[{};()[\]]''', re.S)
SIZE_DECL = re.compile(r"(?<![\w-])(width|height|min-width|min-height)\s*:\s*(\d+(?:\.\d+)?)((?i:px|rem|em))\b")
TAP_SELECTOR = re.compile(r"(?i)btn|button|icon|close|chip|toggle|\btab\b|link|(?:^|[\s,>+~])a(?=$|[\s.:#\[,>+~])|checkbox|radio")
_NO_OUTLINE = r"(?:none|0(?:\.0+)?(?:px|em|rem)?)(?![\w.%-])"
OUTLINE_NONE = re.compile(r"(?<![\w-])outline\s*:\s*" + _NO_OUTLINE)
JS_OUTLINE_NONE = re.compile(words(r"\w", "outline") + r"\s*:\s*(?:[\"']" + _NO_OUTLINE + r"[\"']|0(?=\s*[,}\n]))")
# A visible replacement sets a box shadow, border, background, underline or
# outline to something other than nothing.
FOCUS_REPLACEMENT = re.compile(r"(?<![\w-])(?:box-shadow|border(?:-(?:top|right|bottom|left|block|inline)"
                               r"(?:-(?:start|end))?)?(?:-(?:color|style|width))?|background(?:-color|-image)?|"
                               r"text-decoration(?:-line|-color|-style|-thickness)?|outline(?:-color|-style|-width)?)"
                               r"\s*:(?!\s*(?:(?:none|0(?:\.0+)?(?![\d.])(?:px|em|rem)?|transparent|inherit|initial|unset|revert)"
                               r"\s*)+(?:!important\s*)?(?:;|$))",
                               re.M)
CSS_MOTION = re.compile("(" + words(r"[\w-]", "transition", "animation") + r")(?:-duration|-name)?\s*:\s*(?!\s*none\b)([^;{}\n]+)")
JS_MOTION = re.compile("(" + words(r"\w", "transition", "animation") + r")\s*:\s*[\"'`](?!none)")
REDUCED_MOTION = re.compile(r"prefers-reduced-motion|useReducedMotion|reducedMotion|ReducedMotion")
TRUNCATION = re.compile(r"text-overflow\s*:\s*ellipsis|line-clamp\s*:|white-space\s*:\s*nowrap|"
                        r"textOverflow\s*:\s*[\"']ellipsis|WebkitLineClamp|whiteSpace\s*:\s*[\"']nowrap|"
                        r"class(?:Name)?\s*=\s*(?:\{[^}]{0,200}?)?[\"'`][^\"'`]*\b(?:truncate|line-clamp-\d)\b|"
                        # Vue :class="['truncate', …]" or "{ 'line-clamp-2': on }"; Svelte class:truncate={on}.
                        + "|".join(words(r"[\w-]", bind) + r"class\s*=\s*\"[^\"]{0,200}?\b(?:truncate|line-clamp-\d)\b"
                                   for bind in ("v-bind:", ":")) + "|"
                        + words(r"\w", "class:") + r"(?:truncate|line-clamp-\d)\b")
PHYSICAL = leading(r"[mpbtflr]", r"(?<![\w-])(margin-left|margin-right|padding-left|padding-right|border-left|border-right|"
                      r"text-align\s*:\s*(?:left|right)|float\s*:\s*(?:left|right)|(?<![\w.#-])(?:left|right)(?=\s*:))|"
                      r"\b(marginLeft|marginRight|paddingLeft|paddingRight|borderLeft|borderRight)\s*:")
CUSTOM_PROPERTY = re.compile(words(r"[\w-]", "--") + r"[\w-]+\s*:")
# A token file is named for its role (theme.ts) or sits in a folder named for it (theme/index.ts).
TOKEN_FILE = re.compile(r"(?i)(?:^|[/_.-])(?:tokens?|theme|variables|design-system)\.|tailwind\.config\.|"
                        # Below such a folder, style and data files and index modules; below a
                        # theme or design-system folder also script modules (palette.ts), not
                        # components (.tsx) and not auth/tokens/*.ts.
                        r"/(?:tokens|design-tokens|theme|design-system)/(?:[^/]+/)*"
                        r"(?:index\.[cm]?[jt]sx?|[^/]+\.(?:css|scss|sass|less|styl|pcss|json))$|"
                        r"/(?:design-tokens|theme|design-system)/(?:[^/]+/)*[^/]+\.[cm]?[jt]s$")
FETCH = re.compile(words(r"\w", "fetch") + r"\(|" + words(r"\w", "axios") + r"[.(]|"
                   + words(r"\w", "use") + r"(?:Query|SWR|InfiniteQuery|Fetch|LoaderData)\b|\$fetch\(|"
                   + words(r"\w", "createResource") + r"\b|" + words(r"\w", "useAsyncData") + r"\b")
LOADING = leading(r"[ilps<{]", r"(?i)\b(?:is)?loading\b|\bis_?pending\b|\bpending\b|\bisFetching\b|Skeleton|Spinner|<Suspense|"
                     r"\bstatus\s*===?\s*[\"'](?:loading|pending)|"
                     # A Svelte {#await p} block whose pending branch comes before {:then}.
                     r"\{#await\b(?![^{}]*\bthen\b)")
ERROR = leading(r"[ie.cof{]", r"(?i)\b(?:is)?error\b|\.catch\(|\bcatch\s*[({]|ErrorBoundary|onError\b|\bfailed\b|\{:catch\b")
LIST_RENDER = leading(r"[.v{*]", r"\.map\(|\bv-for=|\{#each\b|\*ngFor=")
EMPTY = leading(r"[.!ein]", r"(?i)\.length\s*===?\s*0|!\s*[\w.?]+\.length\b|\.length\s*<\s*1|\bEmpty\w*|\bisEmpty\b|"
                   r"\bno \w+ yet\b|\bnothing\b")
# A destructive verb leads the callee (deleteTask, Remove) or follows a camelCase
# prefix (handleDelete, onRemove, props.onDiscard). "dropdown", drag-and-drop
# handlers (onDrop) and past-tense predicates (isDeleted) are not destructive.
_DESTRUCTIVE_NAME = (r"(?:\w+\.)*(?:(?i:delete|remove|destroy|discard|erase|purge|drop(?!down))|"
                     r"[a-z_]\w*?(?:(?:Delete|Remove|Discard|Erase|Purge)(?!d)|Destroy(?!ed)))\w*")
# A call inside a handler, or the handler passed by name (onClick={handleDelete}, @click="deleteTask").
# A callee starts a name or follows a call, index or optional chain: getState().removeTask(…), api?.delete(…).
# A method after the name (deleteMutation.mutate) and optional calls (onDelete?.()) count too.
# Only the methods that run the action count after the name: deleteModal.onOpen
# opens a confirmation, and removeToast.dismiss removes nothing the user made.
_RUN = r"(?:\.(?:mutate|mutateAsync|call|apply|execute|run|trigger))?"
DESTRUCTIVE = re.compile(r"(?:(?<![\w.])|(?<=[)\]?]\.))(" + _DESTRUCTIVE_NAME + _RUN + r")\s*(?:\?\.)?\(")
DESTRUCTIVE_REFERENCE = re.compile(r"\s*\{?\s*(" + _DESTRUCTIVE_NAME + _RUN + r")\s*\}?\s*")
# DOM and URL housekeeping that removes nothing the user made.
NOT_DESTRUCTIVE = re.compile(r"(?:^|\.)(?:classList|searchParams|params|headers|style|dataset|attributes)\."
                             r"|(?:^|\.)(?:removeEventListener|removeAttribute|removeProperty|removeChild|"
                             r"removeClass|removeListener)\b")
MAX_HANDLER_SCAN = 4000
MAX_HANDLER_REFERENCE = 200
# A field that confirms an entry (confirmPassword, confirm_email) is not a confirmation step.
CONFIRM = leading(r"[cudma]", r"(?i)\bconfirm(?![\s_-]?(?:new[\s_-]?)?(?:password|passwd|pass|pw|email|e-mail|pin|code)\w*\b)\w*\b|\bundo\b|Dialog|\bModal\b|AlertDialog|\bare you sure\b")
# Attributes before path may hold an element (element={<Home />}) or an arrow function.
ROUTE = re.compile(r"<Route\b(?:=>|<[^<>]*>|[^<>]){0,2000}?\bpath\s*=\s*(?:\{\s*(?=[\"'`](?:(?!\$\{)[^\"'`])+[\"'`]\s*\}))?[\"'`]((?:(?!\$\{)[^\"'`])+)[\"'`]|"
                   + words(r"\w", "path") + r"\s*:\s*[\"'](/[^\"']*)[\"']")
# to="/x", href="/x", :to="'/x'", routerLink="/x", [routerLink]="'/x'" or "['/x']".
# Nav arrays ({ name: "Settings", href: "/settings" }) also name link targets.
# A location object ({ path: "/x" }) passed to to=, href= or push() is a link, not a route.
LINK = leading(r"(?i:[\[:thr])|[np]", r"(?<![\w-])\[?(?i:to|href|routerlink)\]?\s*[=:]\s*\{?\s*[\"'`]\[?\s*[\"'`]?(/[^\"'`?#]*)|"
                  r"\b(?:navigate|push|replace|redirect)\(\s*[\"'`](/[^\"'`?#]*)|"
                  r"(?:(?<![\w-]):?(?i:to|href)\s*=\s*[\"']?\{\{?|\b(?:navigate|push|replace|redirect)\(\s*\{)"
                  r"[^{}]{0,200}?\bpath(?:name)?\s*:\s*[\"'`](/[^\"'`?#]*)")
# Every LINK match holds a quote, then at most "[", spaces and a second quote, before its "/".
# A file without that has no link, and this search is far cheaper than LINK's own.
LINK_TARGET = re.compile(r"[\"'`]\[?\s*[\"'`]?/")
FRONTMATTER = re.compile(r"---[^\S\n]*\n(.*?)(?:\n---[^\S\n]*(?:\n|$))", re.S)
FILE_ROUTE = re.compile(r"(?:^|/)app/((?:[^/]+/)*)page\.(?:tsx|ts|jsx|js|mdx)$|"
                        r"(?:^|/)routes/((?:[^/]+/)*)\+page(?:@[^/]*)?\.svelte$")
SCREEN_DIR = re.compile(r"(?i)(?:^|/)(?:pages|screens|views|routes)/")
# Matched against a field name split into words (user_email, firstName, cc-number).
# Distinctive stems match inside a word (useremail, telephone, billingaddress);
# short ones must be whole words, so capacity, wildcard and microphone are not personal.
PERSONAL = re.compile(r"e_?mail|passw|(?<!micro)(?<!micro_)phone|tele?phone|(?<!auto)(?<!auto_)mobile|address|street|postal|post_?code|zip_?code|_zip_|"
                      r"country|(?:first|last|full|given|family|user)_?name|one_?time|"
                      r"_(?:tel|name|city|card|otp|cc_\w+)_")
EMAIL_WORD = re.compile(r"e_?mail")
# microPhone and autoMobile split into micro_phone and auto_mobile, so the exceptions cover both forms.
PHONE_WORD = re.compile(r"(?<!micro)(?<!micro_)phone|_tel_|(?<!auto)(?<!auto_)mobile")


def field_words(name):
    """'user_emailAddress' -> '_user_email_address_' for whole-word matching."""
    return "_" + "_".join(w.lower() for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", name)) + "_"
NON_INTERACTIVE = {"div", "span", "li", "td", "tr", "p", "img", "section", "article", "header", "footer", "main",
                   "i", "svg", "ul", "ol", "h1", "h2", "h3", "h4", "h5", "h6"}
LABELABLE = {"button", "input", "meter", "output", "progress", "select", "textarea"}
CLICK_ATTRS = ("onclick", "@click", "v-on:click", "on:click", "(click)", "x-on:click")
DESTRUCTIVE_ATTRS = (*CLICK_ATTRS, "onpress", "ontap")
KEY_ATTRS = tuple(prefix + event for prefix, event in (
    (p, e) for p in ("on", "@", "v-on:", "on:", "x-on:") for e in ("keydown", "keyup", "keypress"))) + (
    "(keydown)", "(keyup)", "(keypress)")
NAME_ATTRS = ("aria-label", "aria-labelledby", "title")
# Native labels and the common component wrappers that render one (shadcn, MUI).
LABEL_TAGS = {"label", "Label", "FormLabel", "InputLabel"}
VIEWPORT_SCALE = re.compile(r"(?<![\w-])maximum-scale\s*=\s*"
                            r"([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?)", re.I)
# Next.js App Router: export const viewport = { maximumScale: 1, userScalable: false },
# also around one level of nested objects (themeColor: [{ media, color }]).
NEXT_VIEWPORT = re.compile(words(r"\w", "export") + r"\s+const\s+viewport\b[^=\n]*=\s*\{((?:[^{}]|\{[^{}]{0,200}\}){0,1000})\}")
# The whole value of maximumScale, when it is a lone numeric literal (not an expression).
NEXT_MAXIMUM_SCALE = re.compile(r"\bmaximumScale\s*:\s*([0-9.][\w.]*(?:(?<=[eE])[+-][\w]+)?)(?=\s*(?:,|//|/\*|$))")
JS_DECIMAL = re.compile(r"(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")
JS_INTEGER = {"0x": (16, re.compile(r"[0-9a-fA-F]+")), "0o": (8, re.compile(r"[0-7]+")), "0b": (2, re.compile(r"[01]+"))}


def js_number(literal):
    """The value of a JavaScript numeric literal (1, .5, 1e5, 1_000, 0x10), or None if it is not one."""
    if re.search(r"(?<![0-9a-fA-F])_|_(?![0-9a-fA-F])", literal):
        return None  # A separator must sit between digits.
    literal = literal.replace("_", "")
    base = JS_INTEGER.get(literal[:2].lower())
    if base:
        return int(literal[2:], base[0]) if base[1].fullmatch(literal[2:]) else None
    return float(literal) if JS_DECIMAL.fullmatch(literal) else None

VIEWPORT_ZOOM_LOCK = re.compile(r"(?<![\w-])user-scalable\s*=\s*(?:no|0)\b", re.I)
TAG_TOKEN = re.compile(r"<(/?)([A-Za-z][\w.:-]*)(?=[\s/>])")
ATTR_NAME = re.compile(r"[^\s=<>/{}\"']+")
CSS_COMMENTS = re.compile(r"""/\*.*?(?:\*/|$)|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'""", re.S)
# Sass, Less and Stylus also have line comments; "//" inside an unquoted url(…)
# or after ":" or "(" is part of a URL.
LINE_CSS_COMMENTS = re.compile(r"""/\*.*?(?:\*/|$)|(?i:url)\([^()'"\n]*\)|(?<![:(/\\])//[^\n]*|"""
                               r""""(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'""", re.S)
LINE_COMMENT_EXT = {".scss", ".sass", ".less", ".styl"}
LINE_COMMENT_LANGS = {"scss", "sass", "less", "stylus", "styl"}
MARKUP_TOKEN = re.compile(r"<!--|\{/\*|<([A-Za-z][\w.:-]*)(?=[\s/>])")
# Server templates also comment markup out with {# #}, {% comment %}, {{!-- --}}, {{! }} and <%# %>.
TEMPLATE_TOKEN = re.compile(r"<!--|\{/\*|(?<!\{)\{#(?![#/])|\{\{!--|\{\{!|<%#|\{%-?\s*comment\s*-?%\}|<([A-Za-z][\w.:-]*)(?=[\s/>])")
TEMPLATE_CLOSE = {"{#": "#}", "{{!--": "--}}", "{{!": "}}", "<%#": "%>", "<!--": "-->", "{/*": "*/}"}
ENDCOMMENT = re.compile(r"\{%-?\s*endcomment\s*-?%\}")
# JSX files: {/* */}, a // comment line (commented-out markup) and a /* */ comment, beside JS strings.
JSX_TOKEN = re.compile(r"""\{/\*|^[ \t]*//[^\n]*|/\*|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`""",
                       re.S | re.M)
# Plain script: the JSX tokens without {/*, so "{/* note */ a: 1}" ends its comment at "*/".
SCRIPT_TOKEN = re.compile(JSX_TOKEN.pattern.removeprefix(r"\{/\*|"), re.S | re.M)
# A child that names an icon-only button: an image's alt text or a child's aria-label.
# A blank value, quoted or as a {""} expression, names nothing.
INNER_NAME = re.compile(r"""(?i)(?:<img\b[^<>]*?\salt|\saria-label(?:ledby)?)\s*=\s*"""
                        r"""(?:"\s*[^"\s]|'\s*[^'\s]|\{(?!\s*(["'`])\s*\1\s*\}))""")
# A tag inside a button's content. A JSX {…} attribute may hold ">" (onMouseEnter={() => go()});
# one holding "<" is left to the plain form, keeping the scan linear.
MARKUP_TAG = re.compile(r"<(?:[^<>{}]|\{(?:[^{}<]|\{[^{}<]*\})*\})*>|<[^<>]*>")
RAW_TEXT_TAGS = {"script", "style", "textarea", "title", "xmp", "iframe", "noembed", "noframes"}
RAW_TEXT_CLOSE = {name: re.compile(r"</" + name + r"\s*>", re.I) for name in RAW_TEXT_TAGS}


def holds_page_sources(directory):
    """Whether a bounded, no-follow walk below directory finds a page source file."""
    seen = 0
    for dirpath, dirnames, filenames in os.walk(directory):
        # A segment name can hold a deeper one (app/build/out/page.tsx is /build/out), as iter_files reads it.
        dirnames[:] = [d for d in dirnames if (d not in SKIP_DIRS or d in ROUTE_SEGMENT_DIRS)
                       and not os.path.islink(os.path.join(dirpath, d))]
        if any(PAGE_SOURCE.search(name) for name in filenames):
            return True
        seen += len(dirnames) + len(filenames)
        if seen > MAX_SEGMENT_PROBE:
            return False
    return False


def iter_files(root, onerror=None):
    for dirpath, dirnames, filenames in os.walk(root, onerror=onerror):
        in_routes = not ROUTE_TREES.isdisjoint(Path(dirpath).relative_to(root).parts)
        dirnames[:] = sorted(d for d in dirnames
                             if not os.path.islink(os.path.join(dirpath, d))
                             and (d not in SKIP_DIRS
                                  or (in_routes and d in ROUTE_SEGMENT_DIRS
                                      and holds_page_sources(os.path.join(dirpath, d)))))
        for name in sorted(filenames):
            if name in SKIP_FILES:
                continue
            path = Path(dirpath) / name
            # One lstat answers both Path.is_symlink() and Path.is_file(): a path that is not a
            # link stats the same either way. A failed lookup takes the Path methods' own answer.
            try:
                regular = stat.S_ISREG(os.lstat(path).st_mode)
            except (OSError, ValueError):
                regular = not path.is_symlink() and path.is_file()
            if regular:
                yield path


def read_text(path, root=None):
    """Text or None for binaries and minified bundles.

    Unsafe, unreadable, oversized and invalid UTF-8 files raise so the caller
    can record why they were skipped.
    """
    if re.search(r"(?i)\.min\.(?:[cm]?js|css)$", path.name):
        return None
    data = read_regular(path, max_bytes=MAX_BYTES, root=root)
    # UTF-16 and UTF-32 text holds NUL bytes too, but it is text that is not UTF-8.
    if data.startswith((b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff")):
        raise ValueError("UTF-16 or UTF-32 text, not UTF-8")
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"not valid UTF-8 at byte {e.start}") from None


LONE_CR = re.compile(r"\r(?!\n)")


class SourceLines:
    """Map offsets to lines without rescanning a file for every candidate."""

    def __init__(self, text):
        self.newlines = [m.start() for m in re.finditer("\n", text)]

    def __call__(self, index):
        return bisect_left(self.newlines, index) + 1


def blank_comment(match):
    """Mask a comment while preserving every source offset and newline."""
    return re.sub(r"[^\n]", " ", match.group(0))


def mask_css_comments(text, line_comments=False):
    # Quoted strings may legitimately contain /* and */ as visible content.
    pattern = LINE_CSS_COMMENTS if line_comments else CSS_COMMENTS
    return pattern.sub(lambda m: blank_comment(m) if m.group(0).startswith("/") else m.group(0), text)


def style_line_comments(tag):
    """Whether an embedded style block's lang attribute names a preprocessor with // comments."""
    return (literal(tag.attrs.get("lang")) or "").lower() in LINE_COMMENT_LANGS


# Characters jsx_text_line may read back over a whole file: a fixed allowance
# plus this many per character of the file, keeping the scan linear.
JSX_TEXT_BUDGET = (100_000, 8)
LINE_COMMENT = re.compile(r"[ \t]*//")
# A line that reads as JSX child text rather than code: no JS keyword first and
# no operator, bracket or statement punctuation outside {expressions}. Such a
# line inside code leads back to more code, never to a tag's ">".
JSX_TEXT = re.compile(r"[ \t]*(?!(?:return|const|let|var|import|export|if|else|case|default|throw|yield|await|"
                      r"type|interface|function|class)\b)(?:[^=;(){}\[\]<>`\n]|\{[^{}\n]*\})*")


def jsx_text_line(text, start, budget):
    """Whether the line at start continues JSX child text: the code before it ends with a tag's ">".

    Earlier // lines, child text lines and {expression} children are skipped
    ("<div>{x}\\n// text", "<div>\\nhello\\n// text"),
    at most 50 steps back; "=>" is an arrow function, so what follows is code.
    budget is a one-item list of characters left to read back in this file;
    once it is spent, // lines are comments again.
    """
    i = start
    for _ in range(50):
        floor = max(0, i - budget[0])
        k = i - 1
        while k >= floor and text[k].isspace():
            k -= 1
        if k < floor:
            budget[0] -= i - floor
            return False
        line_start = text.rfind("\n", floor, k) + 1
        budget[0] -= i - line_start
        if line_start == 0 and floor > 0:
            return False  # The line starts beyond the budget.
        if LINE_COMMENT.match(text, line_start, k + 1):
            i = line_start  # Another comment line: look further back.
            continue
        if text[k] not in "}>" and JSX_TEXT.fullmatch(text, line_start, k + 1):
            i = line_start  # Child text such as "Hello": look further back for its element.
            continue
        if text[k] != "}":
            return text[k] == ">" and _ends_tag(text, k, floor)
        j = _open_brace(text, k, floor)
        budget[0] -= max(0, line_start - max(j, floor))
        if j < floor:
            return False
        i = j
    return False


def jsx_child_text(text, i, budget, memo=None):
    """Whether text[i] lies in JSX child text: inside an element opened earlier on its line
    ("<p>Requests to /api/* …", "<p><b>x</b>/* …"), or on a line that continues child text.

    The tags before i on its line are read right to left, each closing tag matching an opening one;
    after a complete element (const A = <div /> /* … */) or code, "/*" opens a comment. Reading
    back draws on budget, as jsx_text_line does; once it is spent, "/*" is a comment again.
    memo, a dict kept for one text, holds the answer from each tag start an earlier call passed
    with no element left to match, so "<p><b>x</b> /* … /*" does not re-read the line per "/*".
    """
    line_start = text.rfind("\n", 0, i) + 1
    if i - line_start > budget[0]:
        budget[0] = 0
        return False
    budget[0] -= i - line_start
    depth, end, level = 0, i, []
    while (close := text.rfind(">", line_start, end)) >= 0:
        opening = text.rfind("<", line_start, close)
        if (JSX_TEXT.fullmatch(text, close + 1, end) is None or opening < 0
                or not TAG_BEFORE.match(text, opening, close + 1)
                or text.count("{", opening, close) != text.count("}", opening, close)):
            # Code, a tag that started on an earlier line, or a ">" inside {…} (=>, a > b).
            return _remember(memo, level, False)
        if text.startswith("</", opening):
            depth += 1
        elif text[close - 1] != "/":
            if not depth:
                return _remember(memo, level, True)  # The element this text belongs to.
            depth -= 1
        end = opening
        if not depth and memo is not None:
            if end in memo:
                return _remember(memo, level, memo[end])
            level.append(end)
    # A "/*" that starts its line opens a comment: after "() => <Icon />" the next line is code again.
    # Not remembered: this answer also depends on the budget left.
    return (not depth and bool(text[line_start:i].strip()) and JSX_TEXT.fullmatch(text, line_start, end) is not None
            and jsx_text_line(text, line_start, budget))


def _remember(memo, starts, answer):
    """Record answer for each tag start in starts, as jsx_child_text found it; return answer."""
    if memo is not None:
        memo.update(dict.fromkeys(starts, answer))
    return answer


# An open, closing or fragment tag ending at the ">" found: a name and attributes
# (arrow functions in {…} included), with no other "<" or ">" in between.
TAG_BEFORE = re.compile(r"<(?:/?[A-Za-z][\w.:-]*(?:\s(?:[^<>]|=>)*?)?/?)?>\Z")


def _ends_tag(text, k, floor):
    """Whether the ">" at text[k] closes a JSX tag, not a comparison (foo >\\n bar) or an arrow."""
    start = text.rfind("<", max(floor, k - 2000), k)
    return start >= 0 and TAG_BEFORE.match(text[start:k + 1]) is not None


def _escaped(text, i):
    """Whether text[i] follows an odd number of backslashes."""
    n = 0
    while i - n - 1 >= 0 and text[i - n - 1] == "\\":
        n += 1
    return n % 2 == 1


def _open_brace(text, k, floor):
    """Index of the "{" matching the "}" at text[k], reading back no further than floor; -1 if not found.

    Quoted strings, template literals, /* */ comments and regular-expression
    literals are skipped, so braces inside them do not count.
    """
    depth, j = 0, k
    while j >= floor:
        c = text[j]
        if c in "\"'`" and not _escaped(text, j):
            # Back to the opening quote; " and ' strings stay on one line.
            lo = floor if c == "`" else max(floor, text.rfind("\n", floor, j) + 1)
            j = text.rfind(c, lo, j)
            while j >= lo and _escaped(text, j):
                j = text.rfind(c, lo, j)
            if j < lo:
                return -1
        elif c == "/" and j > floor and text[j - 1] == "*":
            j = text.rfind("/*", floor, j - 1)  # A block comment.
            if j < 0:
                return -1
        elif c == "/" and not _escaped(text, j):
            # A regular-expression literal when its opening "/" follows an operator or "(".
            line = max(floor, text.rfind("\n", floor, j) + 1)
            opening = text.rfind("/", line, j)
            before = text[line:opening].rstrip()[-1:] if opening >= 0 else ""
            if opening >= 0 and (before == "" or before in "(,=:[!&|?{};"):
                j = opening
        elif c == "}":
            depth += 1
        elif c == "{":
            depth -= 1
            if depth == 0:
                return j
        j -= 1
    return -1


def mask_markup_comments(text, *, jsx=False, template=False, child_text=True):
    """Mask template comments, protecting quoted attributes and raw-text blocks.

    With jsx, child_text=False reads every // line as a comment: plain script
    (.ts, .cjs, <script> blocks) has no JSX child text.
    """
    parts, end, cursor, resumes = [], 0, 0, MAX_BRACE_RESUMES
    token = (JSX_TOKEN if child_text else SCRIPT_TOKEN) if jsx else TEMPLATE_TOKEN if template else MARKUP_TOKEN
    budget = [JSX_TEXT_BUDGET[0] + JSX_TEXT_BUDGET[1] * len(text)]
    child_memo = {}
    while match := token.search(text, cursor):
        found = match.group(0)
        if jsx and found.lstrip().startswith("//"):
            if child_text and jsx_text_line(text, match.start(), budget):
                cursor = match.end()  # "//" in JSX child text is visible text, not a comment.
                continue
            parts.extend((text[end:match.start()], re.sub(r"[^\n]", " ", found)))
            cursor = end = match.end()
            continue
        if jsx and found == "/*" and inside_regex(text, match.start(), budget):
            cursor = match.end()  # Inside or at the end of a regular expression (/a/*2, /[/*]/), not a comment.
            continue
        if jsx and found == "/*" and child_text and jsx_child_text(text, match.start(), budget, child_memo):
            cursor = match.end()  # Visible text such as <p>Requests to /api/* …</p>, not a comment.
            continue
        if jsx and found not in ("{/*", "/*"):
            cursor = match.end()  # A JS string, not a comment or an HTML fragment.
            continue
        name = None if jsx else match.group(1)
        if name:
            tag, cursor, spans = read_tag(text, match.end())
            resumed = tag is None and spans is None and resumes
            if resumed:
                # As in tags(): a brace that never closes is text, so later comments are still comments.
                cursor, resumes = tag_end(text, match.end()), resumes - 1
            if (resumed or (tag and not tag[3])) and name.lower() in RAW_TEXT_TAGS:
                close = RAW_TEXT_CLOSE[name.lower()].search(text, cursor)
                cursor = close.end() if close else len(text)
        else:
            if found.startswith("{%"):
                close_match = ENDCOMMENT.search(text, match.end())
                close, marker = (close_match.start(), close_match.group(0)) if close_match else (-1, "")
            else:
                marker = "*/" if found == "/*" else TEMPLATE_CLOSE[found]
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


def replace_regions(text, regions):
    """Replace disjoint regions in one pass, retaining all other source text."""
    parts, end = [], 0
    for start, stop, body in sorted(regions):
        parts.extend((text[end:start], body))
        end = stop
    parts.append(text[end:])
    return "".join(parts)


def embedded_regions(text, parsed):
    """Extract actual style/script regions, never markup-looking attribute text."""
    css, js = [], []
    for tag in parsed:
        if tag.body is not None and tag.name in ("style", "script"):
            start, stop = tag.body
            target = css if tag.name == "style" else js
            body = (mask_css_comments(text[start:stop], style_line_comments(tag)) if target is css
                    else mask_markup_comments(text[start:stop], jsx=True, child_text=False))
            target.append((start, stop, body))
        for name, (start, stop, expression) in tag.attribute_spans.items():
            if expression:
                js.append((start, stop, text[start:stop]))
            elif name == "style":
                # Braces over the delimiters make the declarations one rule of their own, so a
                # max-width beside a width caps it, without shifting source offsets.
                css.append((start - 1, stop + 1, "{" + mask_css_comments(text[start:stop]) + "}"))
    return css, js


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
    value = float(number) * (16 if unit.lower() in ("rem", "em") else 1)
    if not math.isfinite(value):
        if warn:
            warn("length literal exceeds the finite numeric range; candidate skipped")
        return None
    return round(value, 2)


def fmt(value):
    return f"{value:g}px"


SIZING_FUNCTION = re.compile(r"(?i)(?<![\w-])(?:-webkit-|-moz-)?(calc|clamp)\Z")


def literal_terms(value):
    """A CSS value without the terms that are not sizes in their own right.

    calc() mixes units, and the preferred (middle) term of clamp() is a fluid
    formula: their numbers are an intercept or an addend, not a size. The
    bounds of clamp() and the arguments of min() and max() are kept. One pass,
    without recursion, so nesting depth costs nothing.
    """
    if "(" not in value:
        return value
    out, frames, hidden, last = [], [], 0, 0
    for m in re.finditer(r"[(),]", value):
        if not hidden:
            out.append(value[last:m.start()])
        last = m.end()
        token = m.group()
        if token == "(":
            name = SIZING_FUNCTION.search(value, max(0, m.start() - 16), m.start())
            kind = name.group(1).lower() if name else ""
            frames.append([kind, 0, kind == "calc"])
            hidden += kind == "calc"
        elif token == "," and frames and frames[-1][0] == "clamp":
            frame = frames[-1]
            hidden -= frame[2]
            frame[1] += 1
            frame[2] = frame[1] == 1
            hidden += frame[2]
        elif token == ")" and frames:
            hidden -= frames.pop()[2]
        if not hidden:
            out.append(" ")
    if not hidden:
        out.append(value[last:])
    return "".join(out)


def lengths(value, warn=None):
    """px values of the lengths in a CSS value; bare numbers are not lengths in CSS."""
    return [v for m in LENGTH.finditer(literal_terms(value)) if (v := px(m.group(1), m.group(2), warn)) is not None]


def js_lengths(bare, quoted, warn=None):
    if bare is not None:
        value = px(bare, "px", warn)
        return [value] if value is not None else []
    return lengths(quoted or "", warn)


def comment_start(text, i):
    """A JavaScript comment follows whitespace or a delimiter; "/" after anything else is a regex or division."""
    return i == 0 or text[i - 1] in " \t\r\n{}(),;"


REGEX_BEFORE = set("(,=:[!&|?{};+-*%<>~^")
CONTROL_WORDS = {"if", "while", "for", "with"}
REGEX_WORDS = {"return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void", "throw", "yield", "await"}


def inside_regex(text, i, budget=None):
    """Whether the "/" at text[i] lies inside a regular-expression literal opened earlier on its line.

    The line is read forward from its start (at most 2000 characters back),
    skipping quoted strings and regex literals with their [character classes],
    so /a/*2 and /[/*]/ hold no comment, while x=/* … */1 starts one.
    budget, a one-item list shared across a file, caps the characters read;
    once it is spent, every "/*" starts a comment.
    """
    floor = max(0, i - 2000)
    if budget is not None:
        floor = max(floor, i - max(budget[0], 0))
        budget[0] -= i - floor
    newline = text.rfind("\n", floor, i)
    j = newline + 1 if newline >= 0 else floor
    previous = ""  # The last significant token: a character, or "a" for an operand.
    word_before = ""  # The identifier just before the last token, to spot if ( … ) and while ( … ).
    parens = []  # For each open "(": whether it opened a control condition.
    while j < i:
        c = text[j]
        if c in "\"'`":
            close = j + 1
            while close < i and text[close] != c:
                close += 2 if text[close] == "\\" else 1
            if close >= i:
                return False  # Inside a string, which the caller's scanner already handles.
            j, previous = close + 1, "a"
            continue
        if c == "/" and text.startswith("/*", j):
            close = text.find("*/", j + 2, i)
            if close < 0:
                return False
            j = close + 2
            continue
        if c == "/" and text.startswith("//", j):
            return False
        if c == "/" and previous in REGEX_BEFORE | {""} and text[j - 1:j] != "<":  # "</" closes a JSX tag.
            j += 1
            in_class = False
            while j < len(text) and text[j] != "\n" and (in_class or text[j] != "/"):
                if text[j] == "\\":
                    j += 1
                elif text[j] == "[":
                    in_class = True
                elif text[j] == "]":
                    in_class = False
                if j >= i:
                    return True  # i is inside this literal.
                j += 1
            if j >= i:
                return True  # i is the literal's closing "/".
            j, previous = j + 1, "a"
            continue
        word = re.match(r"[A-Za-z_$][\w$]*", text[j:j + 64])
        if word:
            dotted = previous == "."  # obj.return is a property, not the keyword.
            previous = "" if word.group(0) in REGEX_WORDS and not dotted else "a"
            word_before = "" if dotted else word.group(0)
            j += len(word.group(0))
            continue
        if c in "+-" and text.startswith(c, j + 1):
            previous, word_before = "a", ""  # i++ and i-- end an operand, so a following "/" divides.
            j += 2
            continue
        if c == "(":
            parens.append(word_before in CONTROL_WORDS)
        elif c == ")":
            # After if ( … ), while ( … ) or for ( … ) a statement starts, so "/" opens a regex.
            previous = "" if parens and parens.pop() else ")"
            word_before = ""
            j += 1
            continue
        if not c.isspace():
            previous, word_before = c, ""
        j += 1
    return False


def skip_braces(text, i, limit):
    """Index just past the brace group opening at text[i], or None when it does not close within limit."""
    depth, quote, n = 0, None, min(len(text), i + limit)
    while i < n:
        c = text[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote or (c == "\n" and quote != "`"):  # Only template literals span lines.
                quote = None
        elif c in "\"'`":
            quote = c
        elif text.startswith("//", i) and comment_start(text, i):
            # A line comment's apostrophe opens no string; "//" in JSX text ("Type // to search}") is not one.
            newline = text.find("\n", i, n)
            line_end = n if newline < 0 else newline
            if text.find("}", i, line_end) < 0:
                i = line_end
                continue
            i += 1
        elif text.startswith("/*", i) and not inside_regex(text, i):
            close = text.find("*/", i + 2, n)
            i = n if close < 0 else close + 2
            continue
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


BUTTON_OPEN = re.compile(r"<button\b")
BUTTON_OPEN_I = re.compile(r"<button\b", re.I)
BUTTON_CLOSE = re.compile(r"</button\s*>")
BUTTON_CLOSE_I = re.compile(r"</button\s*>", re.I)
VOID_ELEMENTS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}
# An open tag whose attributes are read quote-aware, so "1 > 0" or title="aria-hidden='true'"
# inside a value neither ends the tag nor counts as an attribute.
# {…} values may nest three levels deep: style={{ fontSize: 20 }}, cn("a", { b: c }).
_BRACES = r"\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}"
_TAG_ATTRS = r"""((?:"[^"]*"|'[^']*'|""" + _BRACES + r"""|[^<>"'{}])*?)"""
OPEN_TAG = re.compile(r"(?s)<([A-Za-z][\w.:-]*)(?=[\s/>])" + _TAG_ATTRS + r"(/?)>")
ANY_TAG = re.compile(r"(?s)<(/?)([A-Za-z][\w.:-]*)(?=[\s/>])" + _TAG_ATTRS + r"(/?)>")
TAG_ATTRIBUTE = re.compile(r"""\s([^\s=/>"'{}]+)(?:\s*=\s*("[^"]*"|'[^']*'|""" + _BRACES + r"""|[^\s>"']+))?""")


def aria_hidden(attributes):
    """Whether an attribute string sets aria-hidden to true ("true", 'true', true or {true})."""
    return any(name.lower() == "aria-hidden" and re.fullmatch(r"""["']?true["']?|\{\s*true\s*\}""", value or "")
               for name, value in TAG_ATTRIBUTE.findall(attributes))


def strip_aria_hidden(markup):
    """markup with each aria-hidden="true" element, content included, replaced by <i></i>.

    Same-name descendants are counted, so <span aria-hidden><span>×</span>close</span>
    hides "close" too; an unclosed element hides the rest, and a void element only
    itself. Linear in len(markup).
    """
    parts, cursor, scan = [], 0, 0
    while opening := OPEN_TAG.search(markup, scan):
        scan = opening.end()
        if not aria_hidden(opening.group(2)):
            continue
        parts.append(markup[cursor:opening.start()])
        cursor = opening.end()
        name = opening.group(1)
        if not opening.group(3) and name.lower() not in VOID_ELEMENTS:  # Find the matching close tag.
            depth = 1
            # Every tag is read whole, so "<span>" inside another tag's attribute is not a tag.
            while depth and (tag := ANY_TAG.search(markup, cursor)):
                cursor = tag.end()
                if tag.group(2).lower() == name.lower():
                    depth += -1 if tag.group(1) else 0 if tag.group(4) else 1
            if depth:
                cursor = len(markup)
        parts.append("<i></i>")
        scan = cursor
    parts.append(markup[cursor:])
    return "".join(parts)


# An icon element never holds another of its own opening tags: an unclosed one stops there
# instead of scanning to the end of the button for every repeat, keeping the scan linear.
ICON_ELEMENT = re.compile(r"(?is)<(mat-icon|v-icon|ion-icon|fa-icon|q-icon)\b[^>]*>(?:(?!<\1\b).)*?</\1\s*>")
# Bindings that set a button's text, so an empty element still has a name unless the value is blank.
TEXT_BINDINGS = ("v-text", "v-html", "innertext", "textcontent", "innerhtml", "dangerouslysetinnerhtml",
                 "x-text", "x-html", "children")
SHORTHAND = re.compile(r"[A-Za-z_$][\w$]*")


def read_tag(text, i, limit=None, vue=False):
    """Read attributes once, returning the consumed offset even on malformed tags.

    Returns (parsed or None, offset, spans); spans is None when an attribute
    expression never closes. Attribute spans let embedded-language scans preserve source offsets. A raw
    '<' outside a quoted value or expression begins the next token; malformed
    prefixes therefore cannot repeatedly rescan the rest of the file.
    """
    attrs, spans, spread = {}, {}, False
    stop = len(text) if limit is None else min(len(text), i + limit)
    while i < stop:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == ">":
            return (attrs, spread, i + 1, False), i + 1, spans
        elif text.startswith("/>", i):
            return (attrs, spread, i + 2, True), i + 2, spans
        elif text.startswith(("<%", "<?"), i):
            # An ERB or PHP tag inside the element can add any attribute.
            close = text.find("%>" if c == "<" and text[i + 1] == "%" else "?>", i + 2, stop)
            if close < 0:
                return None, stop, {}
            spread, i = True, close + 2
        elif c == "{":
            j = skip_braces(text, i, stop - i)
            if j is None:
                return None, stop, None  # None spans: an expression that never closes.
            inner = text[i + 1:j - 1].strip()
            if inner.startswith(("...", "{", "%")):
                spread = True  # A JSX spread, or Jinja/Django {{ attrs }} / {% include %}.
            elif SHORTHAND.fullmatch(inner):
                attrs[inner.lower()] = "{" + inner + "}"  # Svelte and Astro {href} shorthand.
            i = j
        else:
            m = ATTR_NAME.match(text, i, stop)
            if not m:
                return None, i, {}
            name, i = m.group(0).lower(), m.end()
            k = i
            while k < stop and text[k].isspace():
                k += 1
            value, span = True, None
            if k < stop and text[k] == "=":
                k += 1
                while k < stop and text[k].isspace():
                    k += 1
                if k < stop and text[k] in "\"'":
                    end = text.find(text[k], k + 1, stop)
                    if end < 0:
                        return None, stop, {}
                    value, i = html.unescape(text[k + 1:end]), end + 1
                    span = (k + 1, end, False)
                elif k < stop and text[k] == "{":
                    end = skip_braces(text, k, stop - k)
                    if end is None:
                        return None, stop, None
                    value, i = text[k:end], end
                    span = (k, end, True)
                else:
                    m = re.compile(r"[^\s<>]+").match(text, k, stop)
                    if not m:
                        return None, k, {}
                    value, i = html.unescape(m.group(0)), m.end()
                    span = (k, i, False)
            if name.startswith("[") and name.endswith("]") and len(name) > 2:
                # Angular property bindings: [attr.aria-label]="label" supplies aria-label.
                name = name[1:-1].removeprefix("attr.")
                value = "{" + (value if isinstance(value, str) else name) + "}"
                if span:
                    span = (*span[:2], True)
            if vue:
                if name == "v-bind" or name.startswith("v-bind.") or name.startswith((":[", "v-bind:[")):
                    spread = True  # An object or dynamic key can supply any missing attribute.
                elif name.startswith((":", "v-bind:")):
                    name = name.removeprefix("v-bind:").removeprefix(":").split(".", 1)[0]
                    value = "{" + (value if isinstance(value, str) else name) + "}"
                    if span:
                        span = (*span[:2], True)
                elif name.startswith(("@", "v-on:")):
                    name = name.split(".", 1)[0]
                    if span:
                        span = (*span[:2], True)
            attrs[name] = value
            if span:
                spans[name] = span
    return None, stop, {}


def parse_tag(text, i, limit=4000, vue=False):
    """Return (attrs, spread, end, self_closing), or None within a bounded tag."""
    return read_tag(text, i, limit=limit, vue=vue)[0]


def literal(value):
    """The string an attribute value names: "x", {"x"} or {'x'}; None for expressions."""
    if not isinstance(value, str):
        return None
    m = re.fullmatch(r"\{\s*([\"'`])([^\"'`]*)\1\s*\}", value)
    if m:
        return None if m.group(1) == "`" and "${" in m.group(2) else m.group(2)
    return None if value.startswith("{") else value


def tabindex_integer(value, expression, warn):
    """HTML integer prefix, after resolving only simple literal expressions."""
    if not isinstance(value, str):
        return None
    if expression:
        number = re.fullmatch(r"\{\s*([+-]?[0-9]+)\s*\}", value)
        value = number.group(1) if number else literal(value)
        if value is None:
            return None
    match = re.match(r"[\t\n\f\r ]*([+-]?[0-9]+)", value)
    return integer(match.group(1), warn) if match else None


def label_expression(value):
    """A dynamic for/id expression with whitespace normalized, distinct from any literal id."""
    return ("expression", re.sub(r"\s+", "", value))


def dynamic_label_pairs(parsed):
    """Dynamic for/id expressions that pair exactly one label with exactly one field.

    Component boundaries are not parsed, and two components may pass different
    values through one prop name, so any repeated expression stays unresolved.
    """
    labels, fields = defaultdict(int), defaultdict(int)
    for tag in parsed:
        if tag.closing:
            continue
        if tag.name in LABEL_TAGS:
            target, counts = tag.attrs.get("for") or tag.attrs.get("htmlfor"), labels
        elif tag.name in ("input", "select", "textarea"):
            target, counts = tag.attrs.get("id"), fields
        else:
            continue
        if isinstance(target, str) and literal(target) is None:
            counts[label_expression(target)] += 1
    return {key for key, count in labels.items() if count == 1 and fields.get(key) == 1}


def event_name(attr):
    """An event attribute without modifiers: (keyup.enter) -> (keyup), on:click|once -> on:click."""
    return re.sub(r"[.|][^)]*", "", attr)


def has_name(attrs, names=NAME_ATTRS):
    """A nonblank name attribute, or an expression whose value is unknown."""
    for name in names:
        value = attrs.get(name)
        if isinstance(value, str):
            static = literal(value)
            if static is None or static.strip():
                return True
    return False


class Record:
    """Equality and repr by field, as a dataclass gives them, for classes that list their fields
    in __slots__. Importing dataclasses loads inspect, which costs every run more than these need."""

    __slots__ = ()
    __hash__ = None

    def _fields(self):
        return tuple(getattr(self, name) for name in self.__slots__)

    def __eq__(self, other):
        return self._fields() == other._fields() if other.__class__ is self.__class__ else NotImplemented

    def __repr__(self):
        fields = ", ".join(f"{name}={getattr(self, name)!r}" for name in self.__slots__)
        return f"{type(self).__qualname__}({fields})"


class MarkupTag(Record):
    # Declaration order, as the dataclass had it: positional arguments and repr follow it.
    __slots__ = ("name", "attrs", "spread", "start", "end", "self_closing", "closing", "attribute_spans", "body")  # noqa: RUF023

    def __init__(self, name: str, attrs: dict, spread: bool, start: int, end: int, self_closing: bool,
                 closing: bool, attribute_spans: dict, body: tuple | None = None):
        self.name, self.attrs, self.spread, self.start, self.end = name, attrs, spread, start, end
        self.self_closing, self.closing, self.attribute_spans, self.body = self_closing, closing, attribute_spans, body


def expression_tags(text, start, stop, *, html_names=False, vue=False):
    """Keep existing JSX candidate coverage without pretending to parse JavaScript.

    Expressions may contain actual JSX in fallback/render props. Independently
    inspect their tag candidates; a full JavaScript grammar is outside this
    lightweight inventory's scope.
    """
    skip, failures = start, 0
    for match in TAG_TOKEN.finditer(text, start, stop):
        if match.start() < skip:
            continue  # Inside a brace group that already failed to close; do not rescan it.
        parsed, cursor, spans = read_tag(text, match.end(), limit=min(4000, stop - match.end()), vue=vue)
        if parsed is None:
            if spans is None:  # Later tags on an unclosed expression's line would rescan it.
                failures += 1
                line_end = text.find("\n", match.end(), cursor)
                # Past a few failures, skip the whole unclosed window so scanning stays linear.
                skip = max(skip, cursor if line_end < 0 or failures > MAX_EXPRESSION_FAILURES else line_end)
        else:
            attrs, spread, end, self_closing = parsed
            name = match.group(2).lower() if html_names else match.group(2)
            yield MarkupTag(name, attrs, spread, match.start(), end, self_closing,
                            bool(match.group(1)), spans)


MAX_BRACE_RESUMES = 8


def _after_equals(text, i):
    """Whether only whitespace separates offset i from a preceding =."""
    j = i - 1
    while j >= 0 and text[j] in " \t\r\n\f":
        j -= 1
    return j >= 0 and text[j] == "="


def tag_end(text, i):
    """The offset after the > that ends the tag continuing at i, as a browser reads it: braces are plain
    text and quoted attribute values may hold >. The end of the text when there is none."""
    while i < len(text):
        c = text[i]
        if c in "\"'" and _after_equals(text, i):
            close = text.find(c, i + 1)
            i = len(text) if close < 0 else close
        elif c == ">":
            return i + 1
        i += 1
    return len(text)


def tags(text, *, vue=False, html_names=False, raw_text=False, jsx=False):
    """Walk HTML template boundaries while preserving existing JSX coverage."""
    if jsx:
        yield from expression_tags(text, 0, len(text), html_names=html_names, vue=vue)
        return
    cursor, resumes = 0, MAX_BRACE_RESUMES
    while m := TAG_TOKEN.search(text, cursor):
        parsed, cursor, spans = read_tag(text, m.end(), vue=vue)
        if parsed is None:
            if spans is None and resumes:
                # A brace that never closes is text to a browser: read on after the tag's >. Each
                # retry can scan to the end of the file, so a few keep stray braces from going quadratic.
                cursor, resumes = tag_end(text, m.end()), resumes - 1
                name = m.group(2).lower() if html_names else m.group(2)
                if raw_text and not m.group(1) and name in RAW_TEXT_TAGS:
                    # <script {x> still opens raw text: markup inside it is not markup.
                    close = RAW_TEXT_CLOSE[name].search(text, cursor)
                    cursor = close.end() if close else len(text)
            continue
        attrs, spread, end, self_closing = parsed
        name = m.group(2).lower() if html_names else m.group(2)
        closing = bool(m.group(1))
        body = None
        if raw_text and not closing and not self_closing and name in RAW_TEXT_TAGS:
            close = RAW_TEXT_CLOSE[name].search(text, end)
            body = (end, close.start() if close else len(text))
            cursor = close.end() if close else len(text)
        yield MarkupTag(name, attrs, spread, m.start(), end, self_closing, closing, spans, body)
        for start, stop, expression in spans.values():
            if expression:
                yield from expression_tags(text, start, stop, html_names=html_names, vue=vue)


def label_regions(parsed):
    """Ranges of potentially associated controls in complete wrapping labels."""
    controls = [tag for tag in parsed if not tag.closing and tag.name in LABELABLE
                and not (tag.name == "input" and (literal(tag.attrs.get("type")) or "").lower() == "hidden")]
    control_starts = [tag.start for tag in controls]
    definite = [tag for tag in controls if tag.name != "input" or not (tag.spread or (
        isinstance(tag.attrs.get("type"), str) and literal(tag.attrs["type"]) is None))]
    definite_starts = [tag.start for tag in definite]
    stack, regions = [], []
    for tag in parsed:
        if tag.name not in LABEL_TAGS:
            continue
        if tag.closing and stack:
            opening = stack.pop()
            target = opening.attrs.get("for", opening.attrs.get("htmlfor"))
            if opening.spread or (isinstance(target, str) and literal(target) is None):
                # Unknown targets can associate any wrapped control at runtime.
                regions.append((opening.end, tag.start))
                continue
            if target is not None:
                continue  # A static explicit target overrides implicit association.
            index = bisect_left(control_starts, opening.end)
            if index < len(controls) and controls[index].start < tag.start:
                first_definite = bisect_left(definite_starts, opening.end)
                stop = definite[first_definite].end if first_definite < len(definite) else tag.start
                # An unresolved input type could be hidden, so every candidate
                # through the first definitely labelable control remains possible.
                regions.append((controls[index].start, min(stop, tag.start)))
        elif not tag.closing and not tag.self_closing:
            stack.append(tag)
    merged = []
    for start, stop in sorted(regions):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], stop))
        else:
            merged.append((start, stop))
    return merged


def display_width(s):
    # Combining marks and format characters (ZWJ, ZWSP) take no column of their own.
    return sum(0 if unicodedata.category(c) in ("Mn", "Me", "Cf") else
               2 if unicodedata.east_asian_width(c) in ("W", "F") else 1 for c in s)


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


# Three-letter codes for languages without an ISO 639-1 code that apps commonly ship.
THREE_LETTER_LANGUAGES = {"fil", "haw", "ckb", "yue", "ast", "kab", "gsw", "nds", "sah", "chr", "ceb", "hmn", "kok",
                          "mai", "mni", "sat", "sco", "szl", "zgh", "nqo", "arn", "moh", "quc", "sma", "smj", "smn"}


def iso_language(name):
    primary = re.split(r"[-_]", name)[0]
    return bool(LANG.match(name)) and (primary in ISO_639_1 or primary in THREE_LETTER_LANGUAGES)


def locale_bundle(rel):
    """(bundle, lang) for a JSON locale file, else None.

    A file named for its language (locales/de.json) and a directory per
    language (locales/de/app.json) are both recognised; when both names look
    like tags, an ISO 639-1 name wins, so namespaces such as app.json or
    nav.json are not mistaken for languages.
    """
    if not str(rel).endswith(".json"):  # Cheaper than a Path for the many other files.
        return None
    p = Path(rel)
    if p.suffix != ".json":
        return None
    by_stem = (p.parent / "{lang}.json").as_posix(), p.stem.replace("_", "-")
    by_dir = (p.parent.parent / "{lang}" / p.name).as_posix(), p.parent.name.replace("_", "-")
    stem_ok = LANG.match(p.stem) and (LOCALE_DIR.search(rel) or p.parent.name.lower() in ("i18n", "locales", "lang"))
    dir_ok = LANG.match(p.parent.name) and LOCALE_DIR.search(rel)
    if stem_ok and dir_ok and not iso_language(p.stem) and iso_language(p.parent.name):
        return by_dir
    if stem_ok:
        return by_stem
    if dir_ok:
        return by_dir
    return None


class CssRule(Record):
    __slots__ = ("start", "selector", "declarations", "closed", "body_start", "end")  # noqa: RUF023

    def __init__(self, start: int, selector: str, declarations: list, closed: bool = False,
                 body_start: int = 0, end: int | None = None):
        self.start, self.selector, self.declarations = start, selector, declarations
        self.closed, self.body_start, self.end = closed, body_start, end


def css_blocks(text):
    """Every rule in source order, with its body's extent.

    A brace stack keeps child declarations out of their parent while retaining
    declarations on either side of a nested rule. No selector expansion or CSS
    cascade is attempted, and every source segment is visited only once.
    """
    stack, rules, brackets = [], [], []
    boundary = 0
    for match in CSS_RULE_TOKEN.finditer(text):
        token = match.group(0)
        if len(token) != 1:
            continue
        if token in "([":
            brackets.append(token)
        elif token in ")]":
            if brackets:
                brackets.pop()
        elif brackets:
            continue
        elif token == "{":
            header = text[boundary:match.start()]
            start = boundary + len(header) - len(header.lstrip())
            rule = CssRule(start, header.strip(), [], body_start=match.end())
            stack.append(rule)
            rules.append(rule)
            boundary = match.end()
        elif token == ";":
            if stack:
                stack[-1].declarations.append(text[boundary:match.end()])
            boundary = match.end()
        else:  # A closing brace.
            if stack:
                rule = stack.pop()
                rule.declarations.append(text[boundary:match.start()])
                rule.closed, rule.end = True, match.start()
            boundary = match.end()
    return rules


def css_rules(text):
    """Closed rules in source order, with only their own direct declarations."""
    for rule in css_blocks(text):
        if rule.closed:
            yield rule.start, rule.selector, "".join(rule.declarations)


# The narrowest viewport a media query admits: min-width, or a range's lower end.
MEDIA_FLOOR = re.compile(r"(?i)\(\s*min-width\s*:\s*" + _MQ + r"\s*\)|\bwidth\s*>=?\s*" + _MQ
                         + r"|" + _MQ + r"\s*<=?\s*width\b")
# A width capped by its container or the viewport cannot overflow it (min-width can).
# Only a whole value counts: N% or Nvw, or calc() of one less a length (calc(100% - 2rem)).
WIDTH_CAP = re.compile(r"(?i)(?<![\w-])max-width\s*:\s*(?:(\d+(?:\.\d+)?)(?:%|[sdl]?vw)|"
                       r"calc\(\s*(\d+(?:\.\d+)?)(?:%|[sdl]?vw)\s+-\s+\d*\.?\d+(?:px|r?em|%|[sdl]?vw)\s*\))"
                       r"\s*(?:!\s*important\s*)?(?=;|$)")


def own_media_floor(selector):
    """The narrowest viewport width an @media rule admits, in px (0 for any other rule).

    A query list (comma or "or") applies when any of its queries does, so it
    admits the smallest of their minimums; a negated query is not judged.
    """
    if selector[:6].lower() != "@media":
        return 0
    return min((0 if re.search(r"(?i)\bnot\b", query) else
                max((px(m.group(i), m.group(i + 1)) or 0
                     for m in MEDIA_FLOOR.finditer(query) for i in (1, 3, 5) if m.group(i)), default=0))
               for query in re.split(r"(?i),|\bor\b", selector[6:]))


def width_conditions(text, offsets):
    """offset -> (media floor, capped) for width declarations at those offsets.

    The floor is the widest minimum any enclosing @media rule requires; capped
    means the innermost rule also limits max-width to its container or the
    viewport. Rules are swept once in source order against the sorted offsets,
    and the stack holds only the chain of rules around the current position.
    """
    rules, stack, floors, caps, result, i = css_blocks(text), [], [], {}, {}, 0
    for offset in sorted(offsets):
        while i < len(rules) and rules[i].body_start <= offset:
            rule = rules[i]
            while stack and stack[-1].end is not None and stack[-1].end < rule.body_start:
                stack.pop()
                floors.pop()
            floors.append(max(own_media_floor(rule.selector), floors[-1] if floors else 0))
            stack.append(rule)
            i += 1
        while stack and stack[-1].end is not None and stack[-1].end <= offset:
            stack.pop()
            floors.pop()
        inner = stack[-1] if stack else None
        if inner is not None and id(inner) not in caps:
            caps[id(inner)] = any(float(m.group(1) or m.group(2)) <= 100
                                  for d in inner.declarations if (m := WIDTH_CAP.search(d.strip().rstrip(";"))))
        result[offset] = (floors[-1] if floors else 0, inner is not None and caps[id(inner)])
    return result


def scan_css(rel, text, acc, source_lines=None):
    """Rule-level checks on CSS: tap targets and removed focus outlines."""
    source_lines = source_lines or SourceLines(text)
    focus_visible = ":focus-visible" in text
    for start, selector, body in css_rules(text):
        if not selector or selector.startswith("@"):
            continue
        loc = f"{rel}:{source_lines(start)}"
        warn = lambda reason: parse_warning(acc, loc, reason)  # noqa: E731
        if OUTLINE_NONE.search(body):
            acc["focus_outline"].append({"selector": selector[:120], "location": loc,
                                         "replacement_in_rule": ":focus" in selector
                                         and bool(FOCUS_REPLACEMENT.search(OUTLINE_NONE.sub("", body))),
                                         "focus_visible_rule_in_file": focus_visible})
        if TAP_SELECTOR.search(selector):
            sizes = {d.group(1): v for d in SIZE_DECL.finditer(body)
                     if (v := px(d.group(2), d.group(3), warn)) is not None}
            small = {k: v for k, v in sizes.items() if 0 < v < 44}
            if small:
                acc["tap_targets"].append({"selector": selector[:120], "sizes": {k: fmt(v) for k, v in sizes.items()},
                                           "below_24": any(v < 24 for v in small.values()), "location": loc})


def scan_markup(rel, text, acc, source_lines=None, parsed=None):
    """Element-level checks on templates and JSX."""
    suffix = Path(rel).suffix.lower()
    clean = (mask_markup_comments(text, jsx=suffix in JSX_EXT, template=suffix in HTML_EXT)
             if parsed is None else text)
    source_lines = source_lines or SourceLines(clean)
    html_names = suffix in HTML_EXT
    if parsed is None:
        parsed = list(tags(clean, vue=suffix == ".vue", html_names=html_names,
                           raw_text=suffix in RAW_TEXT_EXT, jsx=suffix in JSX_EXT))
    labels_for = dynamic_label_pairs(parsed)  # htmlFor={id} names its one id={id}.
    # Searched once, and only for a file with a destructive handler attribute to judge.
    has_confirmation = None
    destructive_offsets = set()
    label_spans = label_regions(parsed)
    label_starts = [s for s, _ in label_spans]

    for tag in parsed:
        if tag.name in LABEL_TAGS and not tag.closing:
            target = tag.attrs.get("for") or tag.attrs.get("htmlfor")
            if literal(target):
                labels_for.add(literal(target))
    for tag in parsed:
        if tag.closing:
            continue
        name, attrs, spread, start, end, closing = (
            tag.name, tag.attrs, tag.spread, tag.start, tag.end, tag.self_closing)
        loc = f"{rel}:{source_lines(start)}"
        lname = name.lower()
        if name == "meta" and (literal(attrs.get("name")) or "").lower() == "viewport":
            content = literal(attrs.get("content")) or ""
            # Viewport numbers use a numeric prefix; extra dots must not abort
            # the whole scan. Negative scales are ignored by the viewport rules.
            scale = VIEWPORT_SCALE.search(content)
            blocks = bool(VIEWPORT_ZOOM_LOCK.search(content)) or bool(scale and 0 <= float(scale.group(1)) < 2)
            acc["viewport_meta"].append({"content": content, "blocks_zoom": blocks, "location": loc})
        if not has_confirmation:
            for attr, (handler_start, handler_end, _) in tag.attribute_spans.items():
                if event_name(attr) in DESTRUCTIVE_ATTRS:
                    if has_confirmation is None:
                        has_confirmation = bool(CONFIRM.search(clean))
                    if has_confirmation:
                        break
                    scan_end = min(handler_end, handler_start + MAX_HANDLER_SCAN)
                    matches = list(DESTRUCTIVE.finditer(clean, handler_start, scan_end))
                    reference = (DESTRUCTIVE_REFERENCE.fullmatch(clean, handler_start, handler_end)
                                 if handler_end - handler_start <= MAX_HANDLER_REFERENCE else None)
                    for start_, call in ([(m.start(1), m.group(1)) for m in matches] if matches
                                         else [(reference.start(1), reference.group(1))] if reference else []):
                        if NOT_DESTRUCTIVE.search(call):
                            continue
                        if start_ not in destructive_offsets:
                            destructive_offsets.add(start_)
                            acc["destructive_actions"].append({"call": call,
                                                               "location": f"{rel}:{source_lines(start_)}"})
        style = literal(attrs.get("style"))
        if style and OUTLINE_NONE.search(style):
            acc["focus_outline"].append({"selector": "(inline style)", "location": loc,
                                         "replacement_in_rule": None, "focus_visible_rule_in_file": None})
        if spread:
            continue  # Props passed through a spread are unknown here.
        tabindex_span = tag.attribute_spans.get("tabindex")
        value = tabindex_integer(attrs.get("tabindex"), bool(tabindex_span and tabindex_span[2]),
                                 lambda reason: parse_warning(acc, loc, reason))
        if value is not None and value > 0:
            acc["positive_tabindex"].append({"element": name, "value": value, "location": loc})
        events = {event_name(a) for a in attrs}
        if any(a in events for a in CLICK_ATTRS) and (
                (lname in NON_INTERACTIVE and name == lname) or (name == "a" and "href" not in attrs and "routerlink" not in attrs)):
            missing = [label for label, keys in (("role", ("role",)), ("tabindex", ("tabindex",)), ("key handler", KEY_ATTRS))
                       if not any(k in attrs or k in events for k in keys)]
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
            names = [x for x in (literal(attrs.get("name")), literal(attrs.get("id"))) if x]
            ident = " ".join(names)
            # A checkbox or radio about email (email_notifications) is not an email address field.
            entry = kind not in ("checkbox", "radio", "range", "color", "file")
            label_index = bisect_right(label_starts, start) - 1
            in_label = label_index >= 0 and start < label_spans[label_index][1]
            ident_attr = attrs.get("id")
            labelled = (has_name(attrs) or in_label or literal(ident_attr) in labels_for
                        or (isinstance(ident_attr, str) and literal(ident_attr) is None
                            and label_expression(ident_attr) in labels_for))
            missing = [] if labelled else ["label"]
            words = [field_words(x) for x in names]
            if (entry and (any(PERSONAL.search(w) for w in words) or kind in ("email", "password", "tel"))
                    and "autocomplete" not in attrs):
                missing.append("autocomplete")
            if entry and name == "input" and not dynamic_type and any(EMAIL_WORD.search(w) for w in words) and kind != "email":
                missing.append("type=email")
            if (entry and name == "input" and not dynamic_type and any(PHONE_WORD.search(w) for w in words)
                    and kind != "tel"):
                missing.append("type=tel")
            if missing:
                acc["inputs"].append({"element": name, "type": kind, "name": ident, "missing": missing,
                                      "placeholder_only": not labelled and "placeholder" in attrs, "location": loc})
        named = has_name(attrs)
        if name == "button" and closing and not html_names and not named and not has_name(attrs, TEXT_BINDINGS):
            acc["icon_buttons"].append({"element": name, "location": loc})  # <button />: no content to name it.
        elif name == "button" and not closing and not named and not has_name(attrs, TEXT_BINDINGS):
            # A following <button> ends the search: buttons do not nest, and it keeps unclosed ones cheap.
            following = (BUTTON_OPEN_I if html_names else BUTTON_OPEN).search(clean, end, end + 20000)
            close = (BUTTON_CLOSE_I if html_names else BUTTON_CLOSE).search(
                clean, end, following.start() if following else end + 20000)
            if close:
                # Icon-font ligatures (<mat-icon>delete</mat-icon>) are hidden from assistive technology.
                inner = ICON_ELEMENT.sub("<i></i>", clean[end:close.start()])
                # Content hidden from assistive technology (<span aria-hidden="true">×</span>) names nothing.
                inner = strip_aria_hidden(inner)
                if not MARKUP_TAG.sub("", inner).strip() and not INNER_NAME.search(inner):
                    acc["icon_buttons"].append({"element": name, "location": loc})
        elif re.fullmatch(r"(?:[A-Z]\w*)?IconButton", name) and not named and not has_name(attrs, ("label",)):
            acc["icon_buttons"].append({"element": name, "location": loc})


def rtl_locales(flows):
    return {loc.split("-")[0].split("_")[0].lower() for loc in flows.get("locales", [])} & RTL_LANGS


def inventory(root, flows=None):
    root = Path(root).resolve()
    spacing, font_sizes, breakpoints, z_index = Tally(), Tally(), Tally(), Tally()
    widths, truncation, physical = Tally(), Tally(), Tally()
    width_conditions_by_value = defaultdict(list)  # value -> (media floor, capped) per declaration
    lower_breakpoints = set()  # breakpoint values used at least once as a lower bound
    acc = defaultdict(list)
    routes, links, screens, tokens, motion, reduced, locales = [], set(), [], [], [], [], defaultdict(dict)
    scanned = skipped = 0
    try:  # Physical properties are reported only for an RTL locale; others need no scan for them.
        scan_physical = bool(flows) and bool(rtl_locales(flows))
    except Exception:  # Scan anyway; the report step below raises as it always did.
        scan_physical = True

    def directory_warning(error):
        relative = Path(error.filename or root).relative_to(root).as_posix()
        location = relative.encode("utf-8", errors="backslashreplace").decode("utf-8") + ":1"
        reason = str(error.strerror or error).encode("utf-8", errors="backslashreplace").decode("utf-8")
        parse_warning(acc, location, f"directory could not be scanned; contents skipped: {reason[:200]}")

    for path in iter_files(root, onerror=directory_warning):
        rel = path.relative_to(root).as_posix()
        suffix = path.suffix.lower()
        if suffix not in SCANNED_EXT:
            continue
        try:
            rel.encode("utf-8")
        except UnicodeEncodeError:
            skipped += 1
            safe_rel = rel.encode("utf-8", errors="backslashreplace").decode("utf-8")
            parse_warning(acc, f"{safe_rel}:1", "filename is not valid Unicode; file skipped")
            continue
        try:
            text = read_text(path, root=root)
        except (OSError, ValueError) as e:
            # The warning names rel already; the reader's absolute path would leak the
            # reviewer's directories and crowd the reason out of the 200 characters.
            reason = str(e).replace(f"{path.absolute()}: ", "").replace(f"{path}: ", "")
            parse_warning(acc, f"{rel}:1", f"file could not be read; file skipped: {reason[:200]}")
            text = None
        if text is None:
            skipped += 1
            continue
        scanned += 1
        # A lone CR ends a line, as in the report excerpts; turning it into LF keeps
        # every offset while line counting and line-based patterns see the break.
        text = LONE_CR.sub("\n", text)
        # Editors may save any text file with a byte order mark; a space keeps every
        # offset while selectors, at-rules and tags in the first line still match.
        bom = text.startswith("\ufeff")
        if bom:
            text = " " + text[1:]
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
        css = suffix in STYLE_EXT
        js = suffix in JS_EXT or suffix in EMBED_CSS_EXT
        if suffix in MARKUP_EXT:
            text = mask_markup_comments(text, jsx=suffix in JSX_EXT, template=suffix in HTML_EXT)
        elif suffix in JS_EXT:  # .ts, .cjs, .mts and .cts: script without markup.
            text = mask_markup_comments(text, jsx=True, child_text=False)
        if suffix in CSS_EXT:
            text = mask_css_comments(text, suffix in LINE_COMMENT_EXT)
        parsed = (list(tags(text, vue=suffix == ".vue", html_names=suffix in HTML_EXT,
                            raw_text=suffix in RAW_TEXT_EXT, jsx=suffix in JSX_EXT))
                  if suffix in MARKUP_EXT else None)
        css_text, js_text = text, text
        if suffix in EMBED_CSS_EXT:
            css_regions, js_regions = embedded_regions(text, parsed)
            css_text = keep_regions(text, css_regions)
            # Astro frontmatter is JavaScript outside any script tag.
            if suffix == ".astro":
                frontmatter = FRONTMATTER.match(text, 1 if bom else 0)
                if frontmatter:
                    js_regions.append((frontmatter.start(1), frontmatter.end(1), frontmatter.group(1)))
            js_text = keep_regions(text, js_regions)
            # Whole-file heuristics also need CSS comments masked, while script
            # strings and literal attributes retain their original contents.
            style_regions = [(*tag.body, mask_css_comments(text[slice(*tag.body)], style_line_comments(tag)))
                             for tag in parsed if tag.name == "style" and tag.body is not None]
            script_regions = [(*tag.body, mask_markup_comments(text[slice(*tag.body)], jsx=True, child_text=False))
                              for tag in parsed if tag.name == "script" and tag.body is not None]
            text = replace_regions(text, style_regions + script_regions)
        source_lines = SourceLines(text)
        at = lambda i: f"{rel}:{source_lines(i)}"  # noqa: E731
        warn_at = lambda i: lambda reason: parse_warning(acc, at(i), reason)  # noqa: E731
        props = len(CUSTOM_PROPERTY.findall(css_text if css else text))
        if TOKEN_FILE.search("/" + rel) or props >= 3:
            tokens.append({"path": rel, "custom_properties": props})
        if css:
            # Indented Sass and Stylus, as files or <style lang="sass|stylus"> blocks, are read by line.
            if suffix in INDENTED_CSS_EXT:
                by_syntax = [(css_text, True)]
            else:
                blocks = [(start, stop, css_text[start:stop]) for tag in parsed or ()
                          if tag.name == "style" and tag.body is not None
                          and (literal(tag.attrs.get("lang")) or "").lower() in INDENTED_STYLE_LANGS
                          for start, stop in [tag.body]]
                by_syntax = [(replace_regions(css_text, [(a, b, re.sub(r"[^\n]", " ", t)) for a, b, t in blocks]), False)]
                if blocks:
                    by_syntax.append((keep_regions(css_text, blocks), True))
            for measured, indented in by_syntax:
                for m in (CSS_SPACING_LINE if indented else CSS_SPACING).finditer(measured):
                    for v in lengths(m.group(1), warn_at(m.start())):
                        if abs(v) > 2:
                            spacing.add(fmt(v), at(m.start()))
                for m in (CSS_FONT_SIZE_LINE if indented else CSS_FONT_SIZE).finditer(measured):
                    for v in lengths(m.group(1), warn_at(m.start())):
                        font_sizes.add(fmt(v), at(m.start()))
            for m in CSS_Z.finditer(css_text):
                value = integer(m.group(1), warn_at(m.start()))
                if value is not None:
                    z_index.add(value, at(m.start()))
            found = [(m, v) for m in CSS_WIDTH.finditer(css_text)
                     if (v := px(m.group(2), m.group(3), warn_at(m.start()))) is not None and v >= 320]
            conditions = width_conditions(css_text, [m.start() for m, _ in found]) if found else {}
            for m, v in found:
                floor, capped = conditions[m.start()]
                widths.add(fmt(v), at(m.start()))
                width_conditions_by_value[fmt(v)].append((floor, capped and m.group(1) == "width"))
            for m in CSS_MOTION.finditer(css_text):
                motion.append(at(m.start()))
            scan_css(rel, css_text, acc, source_lines)
        if js:
            # A bare number in an MUI sx prop is a multiple of the theme's spacing unit, not px.
            sx = sorted(span[:2] for tag in parsed or () if (span := tag.attribute_spans.get("sx")) and span[2])
            sx_starts = [start for start, _ in sx]
            for m in JS_SPACING.finditer(js_text):
                if m.group(1) is not None and sx:
                    k = bisect_right(sx_starts, m.start()) - 1
                    if k >= 0 and m.start() < sx[k][1]:
                        continue
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
                if NOT_ELEMENT_WIDTH.search(js_text, max(0, m.start() - 400), m.start()):
                    continue
                v = px(m.group(2) or m.group(3), m.group(4) or "px", warn_at(m.start()))
                if v is not None and v >= 320:
                    widths.add(fmt(v), at(m.start()))
                    width_conditions_by_value[fmt(v)].append((0, False))
            for m in JS_MOTION.finditer(js_text):
                motion.append(at(m.start()))
            for m in JS_OUTLINE_NONE.finditer(js_text):
                acc["focus_outline"].append({"selector": "(style object)", "location": at(m.start()),
                                             "replacement_in_rule": None, "focus_visible_rule_in_file": None})
            for m in NEXT_VIEWPORT.finditer(js_text):
                body = m.group(1)
                scale = NEXT_MAXIMUM_SCALE.search(body)
                value = js_number(scale.group(1)) if scale else None
                blocks = bool(re.search(r"\buserScalable\s*:\s*false\b", body)) or (value is not None and value < 2)
                acc["viewport_meta"].append({"content": re.sub(r"\s+", " ", body).strip()[:200],
                                             "blocks_zoom": blocks, "location": at(m.start())})
        for m in MEDIA.finditer(text):
            window = max(0, m.start() - 300)  # A bounded look back keeps the scan linear.
            rule_start = max(window, *(text.rfind(c, window, m.start()) + 1 for c in "{};"))
            if "@container" in text[rule_start:m.start()]:
                continue  # A container query tests a component's width, not the viewport.
            # Which end each width bounds: max-width, width < N and N > width are upper bounds.
            if m.group(1):
                uppers = [bool(re.search(r"(?i)max-width|width\s*<", m.group(0)))]
            else:
                ops = re.findall(r"[<>]", m.group(0))
                uppers = [ops[0] == ">"] + ([ops[1] == "<"] if len(ops) > 1 else [])
            numbers = [(n, u) for n, u in zip(m.groups()[::2], m.groups()[1::2]) if n]
            for (number, unit), upper in zip(numbers, uppers):
                value = px(number, unit, warn_at(m.start()))
                if value is not None:
                    breakpoints.add(fmt(value), at(m.start()))
                    if not upper:
                        lower_breakpoints.add(fmt(value))
        for m in REDUCED_MOTION.finditer(text):
            reduced.append(at(m.start()))
        for m in TRUNCATION.finditer(text):
            truncation.add(re.sub(r"\s+", " ", m.group(0))[:40], at(m.start()))
        for m in PHYSICAL.finditer(text) if scan_physical else ():
            physical.add(re.sub(r"\s+", " ", (m.group(1) or m.group(2)))[:30], at(m.start()))
        link_spans = []
        for m in LINK.finditer(text) if LINK_TARGET.search(text) else ():
            links.add((m.group(1) or m.group(2) or m.group(3)).rstrip("/") or "/")
            link_spans.append(m.span())
        for m in ROUTE.finditer(text):
            if not any(start <= m.start() < end for start, end in link_spans):
                routes.append({"route": m.group(1) or m.group(2), "location": at(m.start())})
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
        if SCREEN_DIR.search(rel) and suffix in SOURCE_EXT:
            screens.append(rel)
        if suffix in MARKUP_EXT:
            scan_markup(rel, text, acc, source_lines, parsed)
            fetch = FETCH.search(text)
            if fetch:
                missing = [k for k, rx in (("loading", LOADING), ("error", ERROR)) if not rx.search(text)]
                if LIST_RENDER.search(text) and not EMPTY.search(text):
                    missing.append("empty")
                if missing:
                    acc["state_branches"].append({"file": rel, "missing": missing,
                                                  "location": at(fetch.start())})

    linked = {r["route"] for r in routes if r["route"].rstrip("/") in links or r["route"] in links}
    result = {
        "tool": "inventory.py", "version": 1, "repository": root.name,
        "flows_sha256": canonical_digest(flows) if flows is not None else None,
        "files_scanned": scanned, "files_skipped": skipped,
        "parse_warnings": acc["parse_warnings"],
        "routes": routes,
        # A relative child route's full path depends on its parents; links are absolute.
        "orphan_routes": [r for r in routes if r["route"] not in linked and r["route"].startswith("/")
                          and r["route"] != "/" and not re.search(r"[:\[*]", r["route"])],
        "screens": screens, "token_sources": tokens,
        "spacing": spacing.rows(), "font_sizes": font_sizes.rows(),
        "breakpoints": breakpoints.rows(), "z_index": z_index.rows(), "fixed_widths": widths.rows(),
        "tap_targets": acc["tap_targets"], "focus_outline": acc["focus_outline"],
        "viewport_meta": acc["viewport_meta"], "click_handlers": acc["click_handlers"],
        "images": acc["images"], "inputs": acc["inputs"], "icon_buttons": acc["icon_buttons"],
        "positive_tabindex": acc["positive_tabindex"], "state_branches": acc["state_branches"],
        "destructive_actions": acc["destructive_actions"],
        "motion": {"declarations": len(motion), "locations": motion[:MAX_LOCATIONS],
                   "reduced_motion": reduced},
        "truncation": truncation.rows("pattern"),
        "locale_expansion": locale_expansion(locales),
    }
    if flows:
        result.update(against_flows(result, flows, lower_breakpoints, width_conditions_by_value))
        if rtl_locales(flows):
            result["physical_properties"] = physical.rows("property")
    # Caps apply only after off_scale was measured on every row.
    return cap_rows(result)


def locale_expansion(locales):
    """Keys whose translation is much wider than the base locale's, per bundle and language.

    locales maps bundle -> lang -> (file, flattened strings). The base is en, else
    the first English variant, else the first language in sort order.
    """
    expansion = []
    for bundle, langs in sorted(locales.items()):
        if len(langs) < 2:
            continue
        english = sorted(lang for lang in langs if re.split(r"[-_]", lang)[0].lower() == "en")
        base = "en" if "en" in langs else (english or sorted(langs))[0]
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
    return expansion


def off_scale(rows, key, scale, lower_breakpoints):
    """The rows of one measured property whose value is not on its token scale."""
    if key == "z_index":
        allowed = set(scale) | {0, -1, 1}
        return [row for row in rows if row["value"] not in allowed]
    allowed = {float(x) for x in scale}

    # An upper bound written just below a breakpoint (max-width: 767.98px or 767px) is
    # that breakpoint; a value also used as a lower bound gets no tolerance.
    def near(row):
        v = float(row["value"][:-2])
        return (key == "breakpoints" and row["value"] not in lower_breakpoints
                and any(0 < t - v <= 1 for t in allowed))
    return [row for row in rows if abs(float(row["value"][:-2])) not in allowed and not near(row)]


def against_flows(result, flows, lower_breakpoints, width_conditions):
    """off_scale and smallest_viewport for result; also marks fixed widths wider than that viewport.

    width_conditions maps a width value to (media floor, capped) for every declaration of it.
    """
    scales = flows.get("tokens", {})
    measured = {"off_scale": {key: off_scale(result[key], key, scales[key], lower_breakpoints)
                              for key in ("spacing", "font_sizes", "breakpoints", "z_index") if key in scales}}
    viewports = [int(v.split("x")[0]) for v in flows.get("viewports", [])]
    if viewports:
        smallest = min(viewports)
        measured["smallest_viewport"] = smallest
        # Wider only where a declaration applies at that viewport and is not capped.
        for row in result["fixed_widths"]:
            row["wider_than_smallest_viewport"] = float(row["value"][:-2]) > smallest and any(
                floor <= smallest and not capped for floor, capped in width_conditions[row["value"]])
    return measured


def cap_rows(result):
    """result with its long row lists cut to the limits, each cut counted in truncated."""
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
    if out == root or root in out.parents or within(out.parent, root):
        print(f"inventory.py: --out must be outside the reviewed repository: {a.out}", file=sys.stderr)
        return 2
    flows = None
    if a.flows:
        try:
            source_path = Path(a.flows).resolve()
            if source_path == out.resolve() or (out.exists() and source_path.samefile(out)):
                raise ValueError("--flows input must be different from --out")
            flows = check_flows(load_json(a.flows))
        except (OSError, RuntimeError, ValueError, RecordError) as e:
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
    tolerant_console()
    sys.exit(main())
