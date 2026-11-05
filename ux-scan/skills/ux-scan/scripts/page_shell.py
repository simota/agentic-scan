"""The app shell of the pages render.py writes beside the dashboard.

evidence.html and mockups.html share the dashboard's look (scan-report-kit's
dashboard CSS), its app bar and its theme toggle, and the dashboard links to
each of them from its app bar. One shell keeps those pages and links alike.
Standard library only.
"""

import html

from scan_report_kit import style

DASHBOARD_REPORT_LINK = '<a class="button" href="report.html" data-l="report_link"></a>'
# The dashboard's app bar is one 56px row, and with these links its tools no longer
# fit at a phone's width: the theme toggle ran off screen and the page scrolled
# sideways. Up to the kit's own phone breakpoint the tools wrap onto a second row
# of a taller bar; --appbar-h also sets every sticky offset below the bar. The
# tools leave room for the kit's 10px gap after the brand, which shrinks to nothing.
NARROW_TOOLBAR_CSS = ("@media(max-width:480px){html.app-shell{--appbar-h:80px}"
                      ".app-shell .appbar .tools{flex-wrap:wrap;justify-content:flex-end;row-gap:6px;"
                      "max-width:calc(100% - 10px)}}")
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


def page(*, lang, title, policy, css, chrome, project, dashboard, body, script=""):
    """A complete page: the dashboard's CSS and app bar, then body inside main.

    chrome holds the dashboard's own labels (scan_report_kit.report.labels_for), so
    the app bar names the report link and the theme toggle exactly as the dashboard
    does; dashboard is this page's label for the link back to it.
    """
    return f"""<!doctype html>
<html lang="{esc(lang)}" class="app-shell">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{esc(policy)}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>
{style.dashboard_css()}
{css}
</style>
</head>
<body>
<header class="appbar"><div class="appbar-in"><span class="brand"><span>{esc(chrome["kind"])}</span> <span class="appbar-project">{esc(project)}</span></span><div class="tools"><a class="button" href="dashboard.html">{esc(dashboard)}</a><a class="button" href="report.html">{esc(chrome["report_link"])}</a><button id="theme" type="button">{esc(chrome["theme"])}</button></div></div></header>
<main>
{body}
</main>
<script>
{THEME_JS}{script}
</script>
</body>
</html>
"""


def link_dashboard(page, links):
    """The dashboard with links to the pages in links ((href, label) pairs) after its report link."""
    if not links:
        return page
    if page.count(DASHBOARD_REPORT_LINK) != 1 or "</head>" not in page:
        raise RuntimeError("dashboard template changed: cannot place the links to its companion pages")
    anchors = "".join(f'<a class="button" href="{esc(href)}">{esc(label)}</a>' for href, label in links)
    page = page.replace(DASHBOARD_REPORT_LINK, DASHBOARD_REPORT_LINK + anchors, 1)
    # The first </head> closes the head: record text comes later, in the body.
    return page.replace("</head>", f"<style>{NARROW_TOOLBAR_CSS}</style></head>", 1)
