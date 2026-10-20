"""The before/after mockup page (mockups.html) for findings that carry a mockup.

Each mockup side is an HTML fragment written by the reviewer. It is shown in a
sandboxed iframe (no scripts, no same-origin access, no network fetches), at
the mockup's viewport, side by side, under a slider, or one side at a time.
The page is self-contained and offline; it is not part of the PDF.
Standard library only.
"""

import html

from findings import EXCLUDED
from scan_report_kit import style

PAGE = "mockups.html"
DEFAULT_VIEWPORT = "360x640"
# Applies inside every frame; the page's own policy is inherited as well.
FRAME_POLICY = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:"
PAGE_POLICY = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; "
               "font-src data:; frame-src 'self'; base-uri 'none'; form-action 'none'")
DASHBOARD_REPORT_LINK = '<a class="button" href="report.html" data-l="report_link"></a>'

LABELS = {
    "en": {"kind": "UX review", "title": "Before / After", "dashboard": "Dashboard", "report": "Report",
           "theme": "Theme", "before": "Before", "after": "After", "side": "Side by side", "slider": "Slider",
           "view": "View", "viewport": "Viewport", "split": "Before / After split",
           "contents": "Mockups", "screen": "Screen", "location": "Location", "flow": "Flow",
           "observed": "Observed", "expected": "Expected", "fix": "Fix", "field": "Before/After",
           "lead": "Mockups illustrate each finding as it is and as its fix proposes. They are drawn for the "
                   "review, not rendered from the app, and are not part of the PDF report.",
           "no_script": "Scripts are off: both sides are shown at full size."},
    "ja": {"kind": "UX診断", "title": "Before / After", "dashboard": "ダッシュボード", "report": "診断書",
           "theme": "テーマ", "before": "Before（現状）", "after": "After（修正案）", "side": "並べて表示",
           "slider": "スライダー", "view": "表示", "viewport": "ビューポート", "split": "Before / After の境界",
           "contents": "モック一覧", "screen": "画面", "location": "箇所", "flow": "フロー",
           "observed": "現状", "expected": "あるべき状態", "fix": "修正", "field": "Before/After",
           "lead": "各指摘の現状と修正案をモックで示します。モックは診断のために描いたもので、アプリを実際に"
                   "描画したものではありません。PDF の診断書には含まれません。",
           "no_script": "スクリプトが無効のため、両方を原寸で表示しています。"},
}

CSS = """
.mockups-lead{color:var(--muted);max-width:72ch}
.mockup-toc{margin:0 0 28px;padding-left:20px}
.mockup{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:20px;margin:0 0 28px;scroll-margin-top:calc(var(--appbar-h) + 16px)}
.mockup h2{margin:4px 0 6px;font-size:18px}
.mockup-meta{display:flex;flex-wrap:wrap;gap:4px 16px;margin:0 0 10px;font-size:12px;color:var(--muted)}
.mockup-note{margin:0 0 12px;white-space:pre-wrap}
.mockup-controls{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center;margin:0 0 14px;font-size:12px}
.mockup-controls[hidden]{display:none}
.mockup-controls .group{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.mockup-controls button{padding:5px 10px}
.mockup-controls button[aria-pressed="true"]{background:var(--text);color:var(--bg);border-color:var(--text)}
.compare{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
.pane{margin:0;min-width:0}
.pane figcaption{font:700 12px/1.4 var(--sans);letter-spacing:.06em;color:var(--muted);margin:0 0 6px}
.pane.after figcaption{color:var(--accent)}
.stage{overflow:auto;border:1px solid var(--line);border-radius:6px;background:#fff;max-width:100%}
.stage iframe{display:block;border:0;background:#fff;transform-origin:0 0}
.compare.scaled .stage{overflow:hidden}
.compare[data-mode="before"],.compare[data-mode="after"]{grid-template-columns:minmax(0,1fr)}
.compare[data-mode="before"] .pane.after,.compare[data-mode="after"] .pane.before{display:none}
.compare[data-mode="slider"]{display:block;position:relative}
.compare[data-mode="slider"] .pane{position:absolute;top:0;left:0}
.compare[data-mode="slider"] .pane.before{position:relative}
.compare[data-mode="slider"] .pane.after{clip-path:inset(0 0 0 var(--split,50%))}
.compare[data-mode="slider"] .pane.after figcaption{text-align:right}
.compare[data-mode="slider"] .pane.before .stage{position:relative}
.compare[data-mode="slider"] .pane.before .stage::after{content:"";position:absolute;top:0;bottom:0;left:calc(var(--split,50%) - 2px);border-left:2px solid var(--accent);pointer-events:none}
.split{display:none;width:100%;margin:10px 0 0}
.compare[data-mode="slider"] + .split{display:block}
.mockup dl{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:4px 14px;margin:16px 0 0;font-size:13px}
.mockup dt{color:var(--muted);font-family:var(--sans)}
.mockup dd{margin:0;white-space:pre-wrap}
@media(max-width:700px){.compare{grid-template-columns:minmax(0,1fr)}.mockup dl{grid-template-columns:minmax(0,1fr)}}
"""

JS = """
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
  var sections = Array.prototype.slice.call(document.querySelectorAll('.mockup'));
  // Below this, side-by-side text is too small to read (15px becomes 7px); open under the slider instead.
  var MIN_SIDE_SCALE = 0.5;
  function scaleFor(section) {
    var compare = section.querySelector('.compare');
    var avail = compare.clientWidth, w = +section.dataset.viewport.split('x')[0];
    if (compare.dataset.mode === 'side' && window.getComputedStyle(compare).gridTemplateColumns.split(' ').length > 1) avail = (avail - 16) / 2;
    return Math.min(1, (avail - 2) / w);
  }
  function size(section) {
    var compare = section.querySelector('.compare'), scale = scaleFor(section);
    var vp = section.dataset.viewport.split('x'), w = +vp[0], h = +vp[1];
    compare.classList.add('scaled');
    Array.prototype.forEach.call(compare.querySelectorAll('.stage'), function (stage) {
      stage.style.width = Math.floor(w * scale + 2) + 'px';
      stage.style.height = Math.floor(h * scale + 2) + 'px';
      var frame = stage.querySelector('iframe');
      frame.width = w; frame.height = h;
      frame.style.transform = 'scale(' + scale + ')';
    });
  }
  function press(group, value) {
    Array.prototype.forEach.call(group.querySelectorAll('button'), function (b) {
      b.setAttribute('aria-pressed', String(b.value === value));
    });
  }
  sections.forEach(function (section) {
    var compare = section.querySelector('.compare'), controls = section.querySelector('.mockup-controls');
    var split = section.querySelector('.split'), modes = controls.querySelector('.modes');
    controls.hidden = false;
    function mode(value) { compare.dataset.mode = value; press(modes, value); size(section); }
    modes.onclick = function (e) { if (e.target.value) mode(e.target.value); };
    controls.querySelector('.viewports').onclick = function (e) {
      if (!e.target.value) return;
      section.dataset.viewport = e.target.value; press(e.currentTarget, e.target.value); size(section);
    };
    split.oninput = function () { compare.style.setProperty('--split', split.value + '%'); };
    if (scaleFor(section) < MIN_SIDE_SCALE) mode('slider'); else size(section);
  });
  window.addEventListener('resize', function () { sections.forEach(size); });
})();
"""


def esc(text):
    return html.escape(str(text or ""))


def with_mockups(data):
    """Included findings that carry a mockup, in record order."""
    return [f for f in data["findings"] if f.get("mockup") and f["validation"]["verdict"] not in EXCLUDED]


def frame_document(fragment, lang):
    """A complete document for one mockup side; its policy forbids every fetch but inline styles and data URLs."""
    return (f'<!doctype html><html lang="{esc(lang)}"><head><meta charset="utf-8">'
            f'<meta http-equiv="Content-Security-Policy" content="{esc(FRAME_POLICY)}">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f"</head><body>{fragment}</body></html>")


def viewport_of(finding, flows):
    mockup = finding["mockup"]
    return mockup.get("viewport") or finding.get("viewport") or ((flows or {}).get("viewports") or [DEFAULT_VIEWPORT])[0]


def _section(f, flows, lang, L):
    mockup, fid = f["mockup"], f["id"]
    viewport = viewport_of(f, flows)
    choices = list(dict.fromkeys([viewport, *((flows or {}).get("viewports") or [])]))
    by_flow = {fl["id"]: fl["name"] for fl in (flows or {}).get("flows", [])}
    meta = [(L["screen"], f["screen"]), (L["viewport"], viewport), (L["location"], f["location"]),
            (L["flow"], f"{f['flow_ref']}: {by_flow[f['flow_ref']]}" if f["flow_ref"] in by_flow else f["flow_ref"])]
    panes = "".join(
        f'<figure class="pane {side}"><figcaption>{esc(L[side])}</figcaption><div class="stage">'
        f'<iframe sandbox="" referrerpolicy="no-referrer" title="{esc(f"{fid} {L[side]}")}" '
        f'width="{viewport.split("x")[0]}" height="{viewport.split("x")[1]}" '
        f'srcdoc="{html.escape(frame_document(mockup[side], lang), quote=True)}"></iframe></div></figure>'
        for side in ("before", "after"))
    modes = "".join(f'<button type="button" value="{m}" aria-pressed="{str(m == "side").lower()}">{esc(L[m])}</button>'
                    for m in ("side", "slider", "before", "after"))
    sizes = "".join(f'<button type="button" value="{v}" aria-pressed="{str(v == viewport).lower()}">{v}</button>'
                    for v in choices)
    details = "".join(f"<dt>{esc(L[k])}</dt><dd>{esc(f[k])}</dd>" for k in ("observed", "expected", "fix") if f.get(k))
    return (f'<section class="mockup" id="{esc(fid)}" data-viewport="{viewport}" aria-labelledby="{esc(fid)}-h">'
            f'<span class="badge {esc(f["severity"])}">{esc(f["severity"])}</span>'
            f'<h2 id="{esc(fid)}-h">{esc(fid)} {esc(f["title"])}</h2>'
            f'<p class="mockup-meta">{"".join(f"<span>{esc(k)}: {esc(v)}</span>" for k, v in meta)}</p>'
            + (f'<p class="mockup-note">{esc(mockup["note"])}</p>' if mockup.get("note", "").strip() else "")
            + f'<div class="mockup-controls" hidden>'
            f'<div class="group modes" role="group" aria-label="{esc(L["view"])}">{modes}</div>'
            f'<div class="group viewports" role="group" aria-label="{esc(L["viewport"])}">{sizes}</div></div>'
            f'<div class="compare" data-mode="side">{panes}</div>'
            f'<input class="split" type="range" min="0" max="100" value="50" aria-label="{esc(L["split"])}">'
            f"<dl>{details}</dl></section>")


def render_page(data, flows, lang):
    """mockups.html for the included findings with a mockup."""
    L = LABELS[lang]
    items = with_mockups(data)
    project = data["meta"]["project"]
    toc = "".join(f'<li><a href="#{esc(f["id"])}">{esc(f["id"])} {esc(f["title"])}</a></li>' for f in items)
    sections = "".join(_section(f, flows, lang, L) for f in items)
    return f"""<!doctype html>
<html lang="{esc(lang)}" class="app-shell">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{esc(PAGE_POLICY)}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(f"{L['title']} - {project}")}</title>
<style>
{style.dashboard_css()}
{CSS}
</style>
</head>
<body>
<header class="appbar"><div class="appbar-in"><span class="brand"><span>{esc(L["kind"])}</span> <span class="appbar-project">{esc(project)}</span></span><div class="tools"><a class="button" href="dashboard.html">{esc(L["dashboard"])}</a><a class="button" href="report.html">{esc(L["report"])}</a><button id="theme" type="button">{esc(L["theme"])}</button></div></div></header>
<main>
<h1>{esc(L["title"])}</h1>
<p class="mockups-lead">{esc(L["lead"])}</p>
<noscript><p class="mockups-lead">{esc(L["no_script"])}</p></noscript>
<nav aria-label="{esc(L["contents"])}"><ol class="mockup-toc">{toc}</ol></nav>
{sections}
</main>
<script>
{JS}
</script>
</body>
</html>
"""


def link_dashboard(page, lang):
    """The dashboard with a link to mockups.html beside its report link."""
    if page.count(DASHBOARD_REPORT_LINK) != 1:
        raise RuntimeError("dashboard template changed: cannot place the mockups link")
    link = f'<a class="button" href="{PAGE}">{esc(LABELS[lang]["title"])}</a>'
    return page.replace(DASHBOARD_REPORT_LINK, DASHBOARD_REPORT_LINK + link, 1)


def field(finding, lang):
    """The finding field that points at its mockup, or None."""
    if not finding.get("mockup") or finding["validation"]["verdict"] in EXCLUDED:
        return None
    return LABELS[lang]["field"], f"{PAGE}#{finding['id']}"
