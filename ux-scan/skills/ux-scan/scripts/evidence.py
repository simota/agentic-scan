"""Evidence attached to findings: screenshots, videos and logs (reference/evidence.md).

Each finding lists its evidence files, kept in the evidence/ directory next to
findings.json, each marked as showing the defect (before) or the fix (after).
render.py embeds screenshots and log excerpts in report.html (so the PDF
carries them, before and after side by side) and writes evidence.html, which
also plays videos from the evidence directory. Every page records the SHA-256
of every referenced file, so a replaced screenshot makes the pages stale.
Standard library only.
"""

import base64
import hashlib
import html
import os
import re
import stat
from pathlib import Path

from scan_report_kit import style
from secret_lines import SHOWN_CHARACTERS, continued_secret_lines, private_key_lines, secret_line

DIRECTORY = "evidence"
PAGE = "evidence.html"
STAMP = "ux-scan-evidence"
KINDS = {"screenshot": ("png", "jpg", "jpeg", "webp", "gif"),
         "video": ("webm", "mp4", "gif"),
         "log": ("txt", "log", "json")}
STAGES = ("before", "after")
KEYS = ("kind", "file", "caption", "stage", "viewport", "url", "captured")
MAX_ITEMS = 12
# A plain file name inside evidence/: no directories, no hidden files, a known extension.
FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}\.(?P<ext>[a-z0-9]{2,4})\Z")
MAX_BYTES = {"screenshot": 5 * 1024 * 1024, "video": 200 * 1024 * 1024, "log": 1024 * 1024}
MAX_LOG_LINES = 60
MIME = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "webp": "image/webp", "gif": "image/gif",
        "webm": "video/webm", "mp4": "video/mp4", "txt": "text/plain", "log": "text/plain", "json": "application/json"}
# Images are embedded; videos load from the evidence directory beside the page.
PAGE_POLICY = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; "
               "media-src 'self' file:; base-uri 'none'; form-action 'none'")
DASHBOARD_REPORT_LINK = '<a class="button" href="report.html" data-l="report_link"></a>'
ARTICLE = re.compile(r"<article class='[^']*' id='[^']*'><div class='finding-header'><span class='finding-id'>"
                     r"(?P<id>U-[0-9]{3})</span>.*?</article>", re.S)

LABELS = {
    "en": {"title": "Evidence", "field": "Evidence", "before": "Before (as found)", "after": "After (fixed)",
           "screenshot": "Screenshot", "video": "Video", "log": "Log", "dashboard": "Dashboard",
           "viewport": "Viewport", "url": "URL", "captured": "Captured", "open": "Open the file",
           "video_print": "Video: play it in evidence.html or open the file", "contents": "Findings",
           "excerpt": "First {n} of {total} lines", "masked": "[masked: looks like a secret]",
           "lead": "Screenshots, videos and logs captured for each finding: Before shows the defect as found, "
                   "After shows the fix. Files are kept in the evidence directory next to findings.json."},
    "ja": {"title": "エビデンス", "field": "エビデンス", "before": "Before（現状）", "after": "After（修正後）",
           "screenshot": "スクリーンショット", "video": "動画", "log": "ログ", "dashboard": "ダッシュボード",
           "viewport": "ビューポート", "url": "URL", "captured": "取得日時", "open": "ファイルを開く",
           "video_print": "動画: evidence.html で再生するか、ファイルを開いてください", "contents": "指摘一覧",
           "excerpt": "全 {total} 行中、先頭 {n} 行", "masked": "[秘密情報らしき行のため非表示]",
           "lead": "各指摘について取得したスクリーンショット・動画・ログです。Before は見つかった状態、"
                   "After は修正後の状態を示します。ファイルは findings.json と同じ場所の evidence ディレクトリにあります。"},
}

REPORT_CSS = """
.evidence{margin:0 0 3mm}
.evidence-stages{display:grid;grid-template-columns:repeat(var(--stages,1),minmax(0,1fr));gap:3mm}
.evidence-stage h5{font:700 7.4pt/1.4 var(--sans);letter-spacing:.06em;color:var(--muted);margin:1mm 0}
.evidence-stage.after h5{color:var(--accent,#0b6)}
.evidence figure{margin:0 0 2.5mm;break-inside:avoid;page-break-inside:avoid}
.evidence img{display:block;max-width:100%;max-height:110mm;height:auto;border:.6pt solid var(--rule,#ccc)}
.evidence video{display:block;max-width:100%;max-height:110mm}
.evidence figcaption{font-size:7.4pt;color:var(--muted);margin-top:1mm;overflow-wrap:anywhere}
.evidence pre{margin:0;padding:2mm 0 2mm 3mm;border-left:.6pt solid var(--rule,#ccc);font:7.2pt/1.5 var(--mono,monospace);white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-all}
"""
PAGE_CSS = """
.evidence-lead{color:var(--muted);max-width:72ch}
.evidence-toc{margin:0 0 28px;padding-left:20px}
.evidence-finding{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:20px;margin:0 0 28px;scroll-margin-top:calc(var(--appbar-h) + 16px)}
.evidence-finding h2{margin:4px 0 6px;font-size:18px}
.evidence-stages{display:grid;grid-template-columns:repeat(var(--stages,1),minmax(0,1fr));gap:16px}
.evidence-stage h3{font:700 12px/1.4 var(--sans);letter-spacing:.06em;color:var(--muted);margin:8px 0}
.evidence-stage.after h3{color:var(--accent)}
.evidence figure{margin:0 0 16px}
.evidence img,.evidence video{display:block;max-width:100%;height:auto;border:1px solid var(--line);border-radius:6px;background:#fff}
.evidence figcaption{font-size:12px;color:var(--muted);margin-top:4px;overflow-wrap:anywhere}
.evidence pre{margin:0;padding:10px;border:1px solid var(--line);border-radius:6px;font:12px/1.5 var(--mono);white-space:pre-wrap;overflow-wrap:anywhere;max-height:480px;overflow:auto}
@media(max-width:700px){.evidence-stages{grid-template-columns:minmax(0,1fr)}}
"""
THEME_JS = """
(function () {
  'use strict';
  var root = document.documentElement, THEME_KEY = 'scan-report-kit.theme';
  try {
    var saved = window.localStorage.getItem(THEME_KEY);
    if (saved === 'light' || saved === 'dark') root.dataset.theme = saved;
  } catch (e) { /* follow the OS theme */ }
  document.getElementById('theme').onclick = function () {
    var dark = root.dataset.theme ? root.dataset.theme === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches;
    root.dataset.theme = dark ? 'light' : 'dark';
    try { window.localStorage.setItem(THEME_KEY, root.dataset.theme); } catch (e) { /* not remembered */ }
  };
})();
"""


def esc(text):
    return html.escape(str(text or ""))


def items(finding):
    return finding.get("evidence", [])


def stage(item):
    return item.get("stage", "before")


def with_evidence(data):
    """The findings that carry evidence, in record order."""
    return [f for f in data["findings"] if items(f)]


def referenced(data):
    """Every referenced file name with its kind; one name has one kind across the record."""
    kinds = {}
    for f in data["findings"]:
        for item in items(f):
            if kinds.setdefault(item["file"], item["kind"]) != item["kind"]:
                raise ValueError(f"{DIRECTORY}/{item['file']}: cited as both {kinds[item['file']]} and {item['kind']}")
    return kinds


def _magic(kind, ext, head):
    if ext == "png":
        return head.startswith(b"\x89PNG\r\n\x1a\n")
    if ext in ("jpg", "jpeg"):
        return head.startswith(b"\xff\xd8\xff")
    if ext == "gif":
        return head[:6] in (b"GIF87a", b"GIF89a")
    if ext == "webp":
        return head[:4] == b"RIFF" and head[8:12] == b"WEBP"
    if ext == "webm":
        return head.startswith(b"\x1a\x45\xdf\xa3")
    if ext == "mp4":
        return head[4:8] == b"ftyp"
    return True  # Logs are checked as UTF-8 text instead.


def _read(path, limit, keep):
    """SHA-256 of a regular file read without following a final symlink, and its bytes when keep."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError(f"{path}: must be a regular file (not a symlink)")
    with os.fdopen(os.open(path, flags), "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError(f"{path}: must be a regular file")
        digest, kept, size = hashlib.sha256(), [], 0
        while chunk := handle.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                raise ValueError(f"{path}: exceeds {limit} bytes")
            digest.update(chunk)
            if keep or not kept:
                kept.append(chunk)
    return digest.hexdigest(), b"".join(kept) if keep else (kept[0] if kept else b"")


def load(record_dir, data):
    """Read every referenced evidence file: {name: {kind, ext, sha256, data?, text?}}.

    Raises ValueError for a missing, non-regular, oversized or mistyped file.
    """
    kinds = referenced(data)
    if not kinds:
        return {}
    directory = Path(record_dir) / DIRECTORY
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError(f"{directory}: expected the evidence directory holding {len(kinds)} referenced files")
    files = {}
    for name, kind in sorted(kinds.items()):
        ext = FILE.match(name)["ext"]
        path = directory / name
        try:
            digest, source = _read(path, MAX_BYTES[kind], keep=kind != "video")
        except FileNotFoundError:
            raise ValueError(f"{DIRECTORY}/{name}: missing; save the {kind} there or drop it from the finding") from None
        if not source:
            raise ValueError(f"{DIRECTORY}/{name}: empty file")
        if not _magic(kind, ext, source[:16]):
            raise ValueError(f"{DIRECTORY}/{name}: content is not a .{ext} file")
        entry = {"kind": kind, "ext": ext, "sha256": digest}
        if kind == "screenshot":
            entry["data"] = source
        elif kind == "log":
            try:
                entry["text"] = source.decode("utf-8")
            except UnicodeDecodeError:
                raise ValueError(f"{DIRECTORY}/{name}: a log must be UTF-8 text") from None
        files[name] = entry
    return files


def digest(files):
    """The pages' evidence stamp: the SHA-256 of every referenced file, or 'absent'."""
    if not files:
        return "absent"
    listing = "".join(f"{name}\0{entry['sha256']}\n" for name, entry in sorted(files.items()))
    return "sha256:" + hashlib.sha256(listing.encode("utf-8")).hexdigest()


def log_excerpt(text, masked):
    """The first lines of a log, cut to the shown width, secret-looking lines masked."""
    lines = re.split(r"\r\n|\r|\n", text)
    if lines and lines[-1] == "":
        lines.pop()
    shown = lines[:MAX_LOG_LINES]
    hidden = private_key_lines(lines) | continued_secret_lines(lines, 0, len(shown), False)
    return [masked if i in hidden or secret_line(line, False) else line[:SHOWN_CHARACTERS]
            for i, line in enumerate(shown)], len(lines)


def field(finding, lang):
    """The finding field naming its evidence, or None."""
    if not items(finding):
        return None
    L = LABELS[lang]
    lines = [f"{L[stage(i)]} · {L[i['kind']]} · {DIRECTORY}/{i['file']} — {i['caption']}" for i in items(finding)]
    return L["field"], "\n".join([*lines, f"{PAGE}#{finding['id']}"])


def _meta(item, L):
    parts = [f"{L[item['kind']]}: {item['caption']}"]
    for key in ("viewport", "url", "captured"):
        if item.get(key):
            parts.append(f"{L[key]} {item[key]}")
    return " · ".join(parts)


def _figure(item, files, href, L, printable):
    entry = files[item["file"]]
    link = f"{href}/{item['file']}"
    caption = f"<figcaption>{esc(_meta(item, L))} — <a href=\"{esc(link)}\">{esc(item['file'])}</a></figcaption>"
    if item["kind"] == "screenshot":
        uri = f"data:{MIME[entry['ext']]};base64,{base64.b64encode(entry['data']).decode('ascii')}"
        body = f"<img src=\"{uri}\" alt=\"{esc(item['caption'])}\">"
    elif item["kind"] == "video":
        body = (f"<p>{esc(L['video_print'])}</p>" if printable else
                f"<video controls preload=\"metadata\" src=\"{esc(link)}\"></video>")
    else:
        lines, total = log_excerpt(entry["text"], L["masked"])
        note = f"<p>{esc(L['excerpt'].format(n=len(lines), total=total))}</p>" if total > len(lines) else ""
        body = f"<pre>{esc(chr(10).join(lines))}</pre>{note}"
    return f"<figure>{body}{caption}</figure>"


def _stages(finding, files, href, L, printable, heading):
    """Before and after in aligned columns: screenshots and videos in one row, logs in the next,
    so a long log never pushes its stage's screenshot away from the other stage's."""
    present = [s for s in STAGES if any(stage(i) == s for i in items(finding))]
    rows = [[i for i in items(finding) if i["kind"] != "log"], [i for i in items(finding) if i["kind"] == "log"]]
    out, first = [], True
    for row in rows:
        if not row:
            continue
        cells = "".join(f"<div class=\"evidence-stage {s}\">"
                        + (f"<{heading}>{esc(L[s])}</{heading}>" if first else "")
                        + "".join(_figure(i, files, href, L, printable) for i in row if stage(i) == s) + "</div>"
                        for s in present)
        out.append(f"<div class=\"evidence-stages\" style=\"--stages:{len(present)}\">{cells}</div>")
        first = False
    return "".join(out)


def inject_report(page, data, files, lang, href):
    """report.html with each finding's evidence placed at the end of its card."""
    L = LABELS[lang]
    by_id = {f["id"]: f for f in with_evidence(data)}
    placed = set()

    def place(m):
        f = by_id.get(m["id"])
        if f is None:
            return m[0]
        placed.add(f["id"])
        block = (f"<div class='finding-field evidence'><h4>{esc(L['field'])}</h4>"
                 f"{_stages(f, files, href, L, True, 'h5')}</div>")
        return m[0][:-len("</article>")] + block + "</article>"

    page = ARTICLE.sub(place, page)
    missing = [fid for fid in by_id if fid not in placed and by_id[fid]["validation"]["verdict"] not in
               ("FalsePositive", "NotApplicable")]
    if missing:
        raise RuntimeError(f"report template changed: cannot place the evidence of {', '.join(missing)}")
    if page.count("</head>") != 1:
        raise RuntimeError("report template changed: cannot place the evidence styles")
    return page.replace("</head>", f"<style>{REPORT_CSS}</style></head>", 1)


def link_dashboard(page, lang):
    """The dashboard with a link to evidence.html beside its report link."""
    if page.count(DASHBOARD_REPORT_LINK) != 1:
        raise RuntimeError("dashboard template changed: cannot place the evidence link")
    link = f'<a class="button" href="{PAGE}">{esc(LABELS[lang]["title"])}</a>'
    return page.replace(DASHBOARD_REPORT_LINK, DASHBOARD_REPORT_LINK + link, 1)


def render_page(data, files, lang, chrome, href):
    """evidence.html: every finding's evidence, before and after side by side, videos playable."""
    L = LABELS[lang]
    project = data["meta"]["project"]
    findings = with_evidence(data)
    toc = "".join(f'<li><a href="#{esc(f["id"])}">{esc(f["id"])} {esc(f["title"])}</a></li>' for f in findings)
    sections = "".join(
        f'<section class="evidence-finding evidence" id="{esc(f["id"])}"><h2>{esc(f["id"])} {esc(f["title"])}</h2>'
        f'<p class="evidence-lead">{esc(f["screen"])} · <code>{esc(f["location"])}</code></p>'
        f'{_stages(f, files, href, L, False, "h3")}</section>' for f in findings)
    return f"""<!doctype html>
<html lang="{esc(lang)}" class="app-shell">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{esc(PAGE_POLICY)}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(f"{L['title']} - {project}")}</title>
<style>
{style.dashboard_css()}
{PAGE_CSS}
</style>
</head>
<body>
<header class="appbar"><div class="appbar-in"><span class="brand"><span>{esc(chrome["kind"])}</span> <span class="appbar-project">{esc(project)}</span></span><div class="tools"><a class="button" href="dashboard.html">{esc(L["dashboard"])}</a><a class="button" href="report.html">{esc(chrome["report_link"])}</a><button id="theme" type="button">{esc(chrome["theme"])}</button></div></div></header>
<main>
<h1>{esc(L["title"])}</h1>
<p class="evidence-lead">{esc(L["lead"])}</p>
<nav aria-label="{esc(L["contents"])}"><ol class="evidence-toc">{toc}</ol></nav>
{sections}
</main>
<script>
{THEME_JS}
</script>
</body>
</html>
"""
