"""The before/after mockup page (mockups.html) for findings that carry a mockup.

Each mockup side is an HTML fragment written by the reviewer. It is shown in a
sandboxed iframe (no scripts, no same-origin access, no network fetches), at
the mockup's viewport, side by side, under a slider, or one side at a time.
A mockup with alternatives offers each proposal as an after side, one at a time
or all together; a mockup with states compares each state in turn. A finding can
carry several mockups, one section each.
The page is self-contained and offline; it is not part of the PDF.
Standard library only.
"""

import html

from scan_report_kit import style

PAGE = "mockups.html"
DEFAULT_VIEWPORT = "360x640"
# Mockups illustrate settled defects; on any other verdict they stay in the record unpublished.
PUBLISHED = ("Valid", "Likely")
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
           "proposal": "Proposal", "alternative": "Alternative", "state": "State", "all": "All proposals",
           "lead": "Mockups illustrate each finding as it is and as its fix proposes. They are drawn for the "
                   "review, not rendered from the app, and are not part of the PDF report.",
           "no_script": "Scripts are off: every side is shown at full size."},
    "ja": {"kind": "UX診断", "title": "Before / After", "dashboard": "ダッシュボード", "report": "診断書",
           "theme": "テーマ", "before": "Before（現状）", "after": "After（修正案）", "side": "並べて表示",
           "slider": "スライダー", "view": "表示", "viewport": "ビューポート", "split": "Before / After の境界",
           "contents": "モック一覧", "screen": "画面", "location": "箇所", "flow": "フロー",
           "observed": "現状", "expected": "あるべき状態", "fix": "修正", "field": "Before/After",
           "proposal": "案", "alternative": "別案", "state": "状態", "all": "全案を並べる",
           "lead": "各指摘の現状と修正案をモックで示します。モックは診断のために描いたもので、アプリを実際に"
                   "描画したものではありません。PDF の診断書には含まれません。",
           "no_script": "スクリプトが無効のため、すべての面を原寸で表示しています。"},
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
.pane[hidden],.mockup-note[hidden],.mockup-controls .group[hidden]{display:none}
.pane figcaption{font:700 12px/1.4 var(--sans);letter-spacing:.06em;color:var(--muted);margin:0 0 6px}
.pane.after figcaption{color:var(--accent)}
.stage{overflow:auto;border:1px solid var(--line);border-radius:6px;background:#fff;max-width:100%}
.stage iframe{display:block;border:0;background:#fff;transform-origin:0 0}
.compare.scaled .stage{overflow:hidden}
.compare[data-mode="before"],.compare[data-mode="after"]{grid-template-columns:minmax(0,1fr)}
.compare[data-mode="before"] .pane.after,.compare[data-mode="after"] .pane.before{display:none}
.compare[data-mode="all"]{grid-template-columns:repeat(var(--columns,2),minmax(0,1fr))}
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
  // Below this, side-by-side text is too small to read (15px becomes 7px); use the slider instead.
  var MIN_SIDE_SCALE = 0.5, ONE_COLUMN = window.matchMedia('(max-width: 700px)');
  function scaleFor(section, columns) {
    var avail = section.querySelector('.compare').clientWidth, w = +section.dataset.viewport.split('x')[0];
    return Math.min(1, ((avail - 16 * (columns - 1)) / columns - 2) / w);
  }
  // All proposals: as many columns as stay readable, down to one.
  function columnsFor(section, mode) {
    if (ONE_COLUMN.matches || (mode !== 'side' && mode !== 'all')) return 1;
    if (mode === 'side') return 2;
    var columns = +section.dataset.options + 1;
    while (columns > 1 && scaleFor(section, columns) < MIN_SIDE_SCALE) columns--;
    return columns;
  }
  function size(section) {
    var compare = section.querySelector('.compare'), columns = columnsFor(section, compare.dataset.mode);
    var scale = scaleFor(section, columns);
    compare.style.setProperty('--columns', columns);
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
    var proposals = controls.querySelector('.proposals'), states = controls.querySelector('.states');
    var chosen = {proposal: '0', state: '0'};
    controls.hidden = false;
    // One state at a time; one after side at a time, or every proposal under "all".
    function show() {
      var all = compare.dataset.mode === 'all';
      Array.prototype.forEach.call(section.querySelectorAll('[data-proposal], [data-state]'), function (el) {
        el.hidden = (el.dataset.state !== undefined && el.dataset.state !== chosen.state) ||
          (el.dataset.proposal !== undefined && !all && el.dataset.proposal !== chosen.proposal);
      });
      if (proposals) { press(proposals, chosen.proposal); proposals.hidden = all; }
      if (states) press(states, chosen.state);
    }
    function mode(value) { compare.dataset.mode = value; press(modes, value); show(); size(section); }
    function picker(group, key) {
      if (group) group.onclick = function (e) { if (e.target.value) { chosen[key] = e.target.value; show(); } };
    }
    picker(proposals, 'proposal');
    picker(states, 'state');
    // Until the viewer picks a view, choose the readable one whenever the size changes.
    section.fit = function () {
      if (section.dataset.chosen) size(section);
      else mode(scaleFor(section, columnsFor(section, 'side')) < MIN_SIDE_SCALE ? 'slider' : 'side');
    };
    modes.onclick = function (e) {
      if (!e.target.value) return;
      section.dataset.chosen = 'true'; mode(e.target.value);
    };
    controls.querySelector('.viewports').onclick = function (e) {
      if (!e.target.value) return;
      section.dataset.viewport = e.target.value; press(e.currentTarget, e.target.value); section.fit();
    };
    split.oninput = function () { compare.style.setProperty('--split', split.value + '%'); };
    section.fit();
  });
  window.addEventListener('resize', function () { sections.forEach(function (section) { section.fit(); }); });
})();
"""


def esc(text):
    return html.escape(str(text or ""))


def with_mockups(data):
    """Valid and Likely findings that carry a mockup, in record order."""
    return [f for f in data["findings"] if f.get("mockup") and f["validation"]["verdict"] in PUBLISHED]


def frame_document(fragment, lang):
    """A complete document for one mockup side; its policy forbids every fetch but inline styles and data URLs."""
    return (f'<!doctype html><html lang="{esc(lang)}"><head><meta charset="utf-8">'
            f'<meta http-equiv="Content-Security-Policy" content="{esc(FRAME_POLICY)}">'
            '<meta http-equiv="x-dns-prefetch-control" content="off">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f"</head><body>{fragment}</body></html>")


def viewport_of(finding, flows, mockup=None):
    """The viewport a mockup (by default the finding's first) opens at."""
    if mockup is None:
        mockup = finding["mockup"][0] if isinstance(finding["mockup"], list) else finding["mockup"]
    return mockup.get("viewport") or finding.get("viewport") or ((flows or {}).get("viewports") or [DEFAULT_VIEWPORT])[0]


def mockups_of(finding):
    """(anchor, mockup) per mockup of the finding: the first keeps the finding's id as its anchor."""
    mockup, fid = finding["mockup"], finding["id"]
    items = mockup if isinstance(mockup, list) else [mockup]
    return [(fid if i == 0 else f"{fid}-{i + 1}", m) for i, m in enumerate(items)]


def states(mockup):
    """(label, before, after, note) per state; a mockup without states is one unlabelled state."""
    if "states" not in mockup:
        return [("", mockup["before"], mockup["after"], "")]
    return [(s["label"].strip(), s["before"], s["after"], s.get("note", "")) for s in mockup["states"]]


def proposals(mockup, L):
    """(label, caption, afters, note) per proposal, one after per state: the fix first, then each alternative."""
    label = mockup.get("label", "").strip()
    first = (label, f'{L["after"]} — {label}' if label else L["after"], [s[2] for s in states(mockup)], "")
    return [first, *((a["label"].strip(), f'{L["alternative"]} — {a["label"].strip()}',
                      [s["after"] for s in a["states"]] if "states" in a else [a["after"]], a.get("note", ""))
                     for a in mockup.get("alternatives", []))]


def _pane(side, caption, fragment, name, viewport, lang, proposal=None, state=None):
    data = "".join(f' data-{k}="{v}"' for k, v in (("proposal", proposal), ("state", state)) if v is not None)
    # Lazy, since a mockup with states and alternatives can hold dozens of hidden frames.
    return (f'<figure class="pane {side}"{data}><figcaption>{esc(caption)}</figcaption><div class="stage">'
            f'<iframe sandbox="" referrerpolicy="no-referrer" loading="lazy" title="{esc(f"{name} {caption}")}" '
            f'width="{viewport.split("x")[0]}" height="{viewport.split("x")[1]}" '
            f'srcdoc="{html.escape(frame_document(fragment, lang), quote=True)}"></iframe></div></figure>')


def _buttons(label, values, cls, first="0"):
    buttons = "".join(f'<button type="button" value="{v}" aria-pressed="{str(v == first).lower()}">{esc(text)}</button>'
                      for v, text in values)
    return f'<div class="group {cls}" role="group" aria-label="{esc(label)}">{buttons}</div>'


def _section(f, anchor, mockup, flows, lang, L):
    fid = f["id"]
    title = mockup.get("title", "").strip()
    name = f"{fid} {title}" if title else fid
    viewport = viewport_of(f, flows, mockup)
    choices = list(dict.fromkeys([viewport, *((flows or {}).get("viewports") or [])]))
    by_flow = {fl["id"]: fl["name"] for fl in (flows or {}).get("flows", [])}
    meta = [(L["screen"], f["screen"]), (L["viewport"], viewport), (L["location"], f["location"]),
            (L["flow"], f"{f['flow_ref']}: {by_flow[f['flow_ref']]}" if f["flow_ref"] in by_flow else f["flow_ref"])]
    options, sides = proposals(mockup, L), states(mockup)
    several, staged = len(options) > 1, len(sides) > 1

    def mark(i):
        return i if staged else None

    def captioned(caption, j):
        return f"{caption} · {sides[j][0]}" if staged else caption

    panes = "".join(_pane("before", captioned(L["before"], j), before, name, viewport, lang, state=mark(j))
                    for j, (_, before, _, _) in enumerate(sides))
    panes += "".join(_pane("after", captioned(caption, j), after, name, viewport, lang,
                           i if several else None, mark(j))
                     for i, (_, caption, afters, _) in enumerate(options) for j, after in enumerate(afters))
    # Labelled, since without scripts every state's and proposal's note is shown at once.
    notes = "".join(f'<p class="mockup-note" data-state="{j}"><strong>{esc(label)}:</strong> {esc(note)}</p>'
                    for j, (label, _, _, note) in enumerate(sides) if note.strip())
    notes += "".join(f'<p class="mockup-note" data-proposal="{i}"><strong>{esc(label)}:</strong> {esc(note)}</p>'
                     for i, (label, _, _, note) in enumerate(options) if note.strip())
    pickers = _buttons(L["state"], [(j, s[0]) for j, s in enumerate(sides)], "states", 0) if staged else ""
    pickers += _buttons(L["proposal"], [(i, o[0]) for i, o in enumerate(options)], "proposals", 0) if several else ""
    modes = _buttons(L["view"], [(m, L[m]) for m in ("side", "slider", "before", "after", *(("all",) if several else ()))],
                     "modes", "side")
    sizes = _buttons(L["viewport"], [(v, v) for v in choices], "viewports", viewport)
    details = "".join(f"<dt>{esc(L[k])}</dt><dd>{esc(f[k])}</dd>" for k in ("observed", "expected", "fix") if f.get(k))
    heading = f"{fid} {f['title']}" + (f" — {title}" if title else "")
    return (f'<section class="mockup" id="{esc(anchor)}" data-viewport="{viewport}" data-options="{len(options)}" '
            f'aria-labelledby="{esc(anchor)}-h">'
            f'<span class="badge {esc(f["severity"])}">{esc(f["severity"])}</span>'
            f'<h2 id="{esc(anchor)}-h">{esc(heading)}</h2>'
            f'<p class="mockup-meta">{"".join(f"<span>{esc(k)}: {esc(v)}</span>" for k, v in meta)}</p>'
            + (f'<p class="mockup-note">{esc(mockup["note"])}</p>' if mockup.get("note", "").strip() else "")
            + notes
            + f'<div class="mockup-controls" hidden>{pickers}{modes}{sizes}</div>'
            f'<div class="compare" data-mode="side">{panes}</div>'
            f'<input class="split" type="range" min="0" max="100" value="50" aria-label="{esc(L["split"])}">'
            f"<dl>{details}</dl></section>")


def render_page(data, flows, lang):
    """mockups.html for the included findings with a mockup."""
    L = LABELS[lang]
    items = with_mockups(data)
    project = data["meta"]["project"]
    entries = [(f, anchor, m) for f in items for anchor, m in mockups_of(f)]
    toc = "".join(f'<li><a href="#{esc(anchor)}">{esc(f["id"])} {esc(f["title"])}'
                  f'{esc(" — " + m["title"].strip()) if m.get("title", "").strip() else ""}</a></li>'
                  for f, anchor, m in entries)
    sections = "".join(_section(f, anchor, m, flows, lang, L) for f, anchor, m in entries)
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
    if not finding.get("mockup") or finding["validation"]["verdict"] not in PUBLISHED:
        return None
    return LABELS[lang]["field"], f"{PAGE}#{finding['id']}"
